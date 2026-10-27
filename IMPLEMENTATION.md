# Auth Server — Implementation Document

Complement to `DESIGN.md`. This document is for the engineer who has to maintain or extend the code: it explains the Go idioms in use, the non-obvious wiring, the edge cases each piece guards against, and the tradeoffs taken at the line level.

Sections:
1. Go concepts in use (in depth)
2. Layer-by-layer code tour
3. Persistence: pgx, transactions, the `Executor` trick
4. HTTP request lifecycle
5. Concurrency primitives we rely on
6. Error model
7. Testing implementation deep-dive
8. Common pitfalls + how the code prevents them
9. Conventions to keep when adding code

---

## 1. Go concepts in use (in depth)

### 1.1 Typed context keys

Why: `context.WithValue(ctx, "tx", tx)` is fragile. Two unrelated packages might both use the string `"tx"` and silently collide. The recommended idiom (used since Go 1.5) is an unexported zero-size struct as the key type.

```go
// internal/platform/postgres/tx/tx.go
type contextKey struct{}

func (m *Manager) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
    tx, err := m.db.Begin(ctx)
    if err != nil { return err }
    txCtx := context.WithValue(ctx, contextKey{}, tx)
    // ...
}

func FromContext(ctx context.Context) (pgx.Tx, bool) {
    tx, ok := ctx.Value(contextKey{}).(pgx.Tx)
    return tx, ok
}
```

- `contextKey` is unexported, so no external package can construct a value of the same type.
- The struct is empty (`struct{}`) — zero allocation; the address-of-type is the identity.
- Asserting `.(pgx.Tx)` returns `(zero, false)` on a miss rather than panicking, because we use the two-return-value form.

We use the same pattern for `principalKey` in `internal/shared/context/principal.go`.

### 1.2 Interface segregation

Each domain has a `Repository` (or `XRepository`) interface in `domain/` that lists exactly the methods the use case needs — nothing more. The postgres implementation lives in `infra/postgres/`. No code outside `infra` imports `infra` types.

```go
// internal/identity/domain/repository.go
type Repository interface {
    GetByID(ctx context.Context, id string) (*Identity, error)
    GetByEmail(ctx context.Context, email string) (*Identity, error)
    Create(ctx context.Context, identity *Identity) error
}
```

A unit test for a use case constructs an `in-memory` repo that satisfies that interface — no DB needed. See `internal/token/app/jwt_service_test.go` (`memKeyRepo`) for an example.

### 1.3 Shared executor interface (the "Executor trick")

Repositories must support both pool-backed queries and in-transaction queries. We don't want to write two versions of every method. Solution:

```go
// internal/platform/postgres/tx/tx.go
type Executor interface {
    Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
    QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
    Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}
```

Both `*pgxpool.Pool` and `pgx.Tx` satisfy this interface (no `implements` declaration; structural typing).

```go
// every repo has:
func (r *Repository) executor(ctx context.Context) pgtx.Executor {
    if tx, ok := pgtx.FromContext(ctx); ok {
        return tx       // we're inside a transaction
    }
    return r.db         // we're not
}
```

A use case wraps multi-step writes with `txManager.WithinTransaction(ctx, fn)`; everything inside `fn` calls `r.executor(ctx)` and gets the transaction. Outside, the same method calls go straight to the pool. Same code, two execution modes — pure structural typing.

### 1.4 Functional options for use case input

Long parameter lists are bug-prone (order errors, mandatory-vs-optional confusion). We use an `Input` struct per use case instead:

```go
type LoginInput struct {
    Email, Password, IPAddress, UserAgent string
}
func (u *LoginUseCase) Execute(ctx context.Context, input LoginInput) (*LoginOutput, error)
```

Callers do `u.Execute(ctx, LoginInput{Email: ..., Password: ...})`. Adding a new field doesn't break callers (zero value is the default).

### 1.5 Sentinel errors + comparison via `errors.Is`

```go
// internal/shared/errors/errors.go
var (
    ErrNotFound           = errors.New("not found")
    ErrUnauthorized       = errors.New("unauthorized")
    ErrInvalidCredentials = errors.New("invalid credentials")
    // ...
)
```

Handlers map these to HTTP statuses:
```go
if err == sharederrors.ErrInvalidCredentials { writeError(w, "...", 401); return }
```

When use cases want to wrap a sentinel with context, they use `fmt.Errorf("...: %w", err)`. Callers then use `errors.Is(err, sharederrors.ErrXxx)`.

### 1.6 Constructor-injected dependencies, no `init()`

All wiring happens in `cmd/iam-server/main.go`. No package has an `init()` that opens a DB connection. No package uses a package-level mutable variable. This makes the program:
- testable (you can construct alternate wiring in tests)
- deterministic (startup order is line order)
- debuggable (no hidden state)

### 1.7 `slog` (Go 1.21+ structured logging)

```go
slog.LogAttrs(r.Context(), slog.LevelInfo, "http_request",
    slog.String("method", r.Method),
    slog.Int("status", status),
    slog.Duration("dur", dur),
)
```

- JSON handler in production, attaches fields atomically (no `fmt.Sprintf` string-mashing).
- `LogAttrs` is the zero-allocation form when all attrs are typed (`slog.String`, `slog.Int`, etc.).
- The handler is set once with `slog.SetDefault(...)` — every package uses the package-level functions and gets the same handler.

### 1.8 Goroutines + channels for background work

`cmd/worker/main.go` runs two background loops:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// audit consumer is callback-based via nats.go
sub, err := consumer.Subscribe(ctx)

// cleanup loop on a goroutine
go runSessionCleanup(ctx, sessionRepo)

// block until signal
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
sig := <-sigCh
cancel()   // tells the cleanup loop to exit
```

The `select { case <-ctx.Done(): return ... }` pattern in `runSessionCleanup` is the standard Go cancellation idiom; the goroutine cannot leak across shutdown.

### 1.9 `sync.WaitGroup`, `sync.Mutex`, `atomic`

In the stress, soak, spike, and A/B harnesses we run N workers in parallel.

```go
var wg sync.WaitGroup
for i := 0; i < workers; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        for { select { case <-done: return; default: }
            // ...
        }
    }()
}
// later
close(done)
wg.Wait()
```

- `sync.Mutex` protects the shared `[]time.Duration` of samples.
- `atomic.AddInt64(&counter, 1)` for hot counters where a mutex would be overkill.
- `atomic.Pointer[T]` (Go 1.19+) in the spike test to switch the "current phase" atomically across all workers without a mutex.

### 1.10 Native fuzzing (`testing.F`, Go 1.18+)

```go
func FuzzVerifyPKCE(f *testing.F) {
    f.Add("dBjftJeZ4CVP-...", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    f.Add("", "")
    f.Fuzz(func(t *testing.T, verifier, challenge string) {
        ok := verifyPKCE(verifier, challenge)
        if ok {
            // soundness invariant: ok=true implies a specific challenge
            sum := sha256.Sum256([]byte(verifier))
            want := base64.RawURLEncoding.EncodeToString(sum[:])
            if want != challenge { t.Fatal("...") }
        }
    })
}
```

- Seed corpus via `f.Add(...)`.
- Mutator mutates seeds; minimiser shrinks failing inputs to the smallest reproducer.
- Discovered inputs are saved under `testdata/fuzz/<Func>/<hash>` and become permanent regression tests when committed.

### 1.11 Structural type assertions and `any`

We use `any` (Go 1.18+ alias for `interface{}`) at JSON boundaries. Type assertions `v.(string)` use the two-value form so JSON quirks don't panic:
```go
if s, ok := me["Email"].(string); ok { ... }
```

### 1.12 `io.NopCloser` + `bytes.NewReader`

In `internal/webauthn/transport/http/util.go` we need to forward a JSON-extracted payload as a fresh request body for the webauthn library:

```go
cp := r.Clone(r.Context())
cp.Body = io.NopCloser(bytes.NewReader(body))
cp.ContentLength = int64(len(body))
```

`io.NopCloser` wraps a `Reader` to satisfy `ReadCloser` (Close is a no-op). `r.Clone` deep-copies headers and URL so we don't mutate the live request.

### 1.13 Generics (very lightly used)

We chose not to introduce generic repository or generic option types. The codebase reads better with explicit `*postgres.Repository` types per domain. Generics show up only in stdlib calls (`atomic.Pointer[phase]`).

---

## 2. Layer-by-layer code tour

### 2.1 `internal/shared/password` — Argon2id

```go
hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
// returns 32B; we encode salt+hash into "$argon2id$v=19$m=...$t=...$p=...$<salt>$<hash>"
```

- Params: memory=64MB, time=3, parallelism=2, salt=16B, key=32B — OWASP "interactive" preset.
- `subtle.ConstantTimeCompare(a, b) == 1` for the comparison — no early-exit branch leaks bit info.
- **Edge case**: `Verify("0", "$$$$$")` used to panic inside argon2 because empty `expectedHash` became `keyLength=0`. We added an explicit guard:
  ```go
  if len(salt) == 0 || len(expectedHash) == 0 { return false }
  ```
  Fuzz caught this in ~3 seconds. The minimised input is preserved in `testdata/fuzz/FuzzVerify_NoPanic/c6091420777c30e5` as a permanent regression.

### 2.2 `internal/shared/token` — random + SHA-256

```go
func GenerateRandom(n int) (string, error) {
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil { return "", err }
    return base64.RawURLEncoding.EncodeToString(b), nil
}
func Hash(token string) string {
    sum := sha256.Sum256([]byte(token))
    return hex.EncodeToString(sum[:])
}
```

- `crypto/rand` (CSPRNG), not `math/rand`. The latter is deterministic and trivially predicted.
- `RawURLEncoding` (no padding, URL-safe) so tokens can ride in cookies, query strings, headers without escaping.
- `Hash` is deterministic (SHA-256 is). We use it to store refresh tokens hashed; the raw token never sees disk.

### 2.3 `internal/token/app` — JWT issuance & verification

```go
type Claims struct {
    jwt.RegisteredClaims                 // iss, sub, aud, exp, nbf, iat, jti
    TenantID    string   `json:"tid,omitempty"`
    UserID      string   `json:"uid,omitempty"`
    SessionID   string   `json:"sid,omitempty"`
    Email       string   `json:"email,omitempty"`
    Roles       []string `json:"roles,omitempty"`
    Permissions []string `json:"permissions,omitempty"`
    Nonce       string   `json:"nonce,omitempty"`
}
```

- Custom claims live alongside standard ones via struct embedding.
- `Issue` resolves the active signing key from the DB, picks the right `jwt.SigningMethod`, then attaches the `kid` header so verify can look up the right key:
  ```go
  token := jwt.NewWithClaims(signingMethod, claims)
  token.Header["kid"] = key.ID
  return token.SignedString(signer)
  ```
- `Verify` constrains acceptable algorithms with `jwt.WithValidMethods([]string{"ES256", "RS256"})`. This is what kills `alg=none` and "alg substitution" attacks (CVE-2015-9235 class).
- `Verify` reads `kid` from the header, fetches the key by ID, and rejects unknown kids. This means rotated keys can be removed from the DB safely after the longest live access-token age (15 min today).

### 2.4 `internal/oauth/app` — code + token grants

`authorize.go`:
- Validates `response_type=code`, `code_challenge_method=S256`, `redirect_uri` is in client's allowlist.
- Generates a 32-byte random code, stores `AuthorizationCode{Code, ClientID, TenantID, IdentityID, UserID, Scopes, RedirectURI, CodeChallenge, Nonce, ExpiresAt}` in Redis with 10-min TTL.

`token.go`:
- `authorization_code` grant:
  - `codeStore.Consume(code)` — **Redis GetDel**, atomic; second redeem cannot succeed.
  - PKCE: `verifyPKCE(verifier, stored.CodeChallenge)` uses `subtle.ConstantTimeCompare`.
  - Client secret check (confidential clients): also constant-time.
  - Creates a session + JWT + (optionally) ID token.
- `refresh_token` grant: hashes input → DB lookup → revoke old → create new — same flow as `/refresh`.

### 2.5 `internal/auth/middleware/authentication.go` — the lift

```go
func (m *AuthenticationMiddleware) Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if p := m.fromBearer(r); p != nil {        // (a) stateless JWT
            ctx := authctx.WithPrincipal(r.Context(), p)
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }
        if p := m.fromSessionHeader(r); p != nil { // (b) X-Session-ID + cache + DB
            ctx := authctx.WithPrincipal(r.Context(), p)
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }
        http.Error(w, "unauthorized", http.StatusUnauthorized)
    })
}
```

- (a) is preferred — no I/O.
- (b) consults the **Principal cache** first; on miss it does 4 sequential DB reads and then **puts** the result in the cache for next time.
- Both paths converge on the same `Principal` struct, so handlers stay ignorant of how the user proved their identity.

### 2.6 `internal/auth/middleware/principal_cache.go`

```go
func (c *PrincipalCache) Get(ctx context.Context, sessionID string) (*principal.Principal, bool) {
    b, err := c.client.Get(ctx, cachePrefix+sessionID).Bytes()
    if err != nil { metrics.PrincipalCacheMisses.Inc(); return nil, false }
    p := &principal.Principal{}
    if err := json.Unmarshal(b, p); err != nil { metrics.PrincipalCacheMisses.Inc(); return nil, false }
    metrics.PrincipalCacheHits.Inc()
    return p, true
}
```

- Encoded as JSON so debugging (`redis-cli GET auth:principal:...`) gives human-readable output.
- The `cache *PrincipalCache` value is allowed to be `nil` — every method early-returns. This means tests that don't care about caching can pass `nil`.
- `Delete` is called from `LogoutUseCase` and from `RefreshUseCase` (the refresh path revokes the old session).

### 2.7 `internal/audit/app` — publisher + consumer

Publisher (in the HTTP path):
```go
func (p *Publisher) Emit(e *domain.Event) {
    if p == nil || p.conn == nil { return }       // nil-safe
    if e.ID == "" { e.ID = id.New() }
    if e.CreatedAt.IsZero() { e.CreatedAt = time.Now().UTC() }
    b, _ := json.Marshal(e)
    if err := p.conn.Publish(Subject, b); err != nil {
        slog.Warn("audit publish failed", "err", err, "event_type", e.EventType)
    }
}
```

- **Best-effort, never blocking, never panicking** — audit is not in the critical path. A NATS outage cannot take down login.
- Consumer in `cmd/worker/main.go` decodes the JSON and persists to `audit_events`.

### 2.8 `internal/tenant/app/policy_enforcer.go`

```go
func (e *PolicyEnforcer) ValidatePassword(p *domain.Policy, password string) error {
    if p == nil { p = domain.DefaultPolicy() }
    if len(password) < p.PasswordMinLength { return ErrPasswordTooShort }
    if p.PasswordRequireUpper && !hasMatch(password, unicode.IsUpper) { return ErrPasswordNeedsUpper }
    if p.PasswordRequireDigit && !hasMatch(password, unicode.IsDigit) { return ErrPasswordNeedsDigit }
    if p.PasswordRequireSymbol && !hasMatch(password, isSymbol) { return ErrPasswordNeedsSymbol }
    return nil
}
```

- Defaults applied when policy is `nil` — caller never has to nil-check.
- `unicode.IsUpper / IsDigit / IsPunct / IsSymbol` handle Unicode correctly (a Cyrillic uppercase counts as upper, an emoji counts as symbol). ASCII-only checks would be wrong.

### 2.9 `internal/platform/metrics/metrics.go`

```go
HTTPDuration = prometheus.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "auth_http_request_duration_seconds",
        Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
    },
    []string{"method", "route", "status"},
)
```

The middleware wraps the response writer to capture the status code:
```go
type statusRecorder struct {
    http.ResponseWriter
    status int
}
func (s *statusRecorder) WriteHeader(code int) {
    s.status = code
    s.ResponseWriter.WriteHeader(code)
}
```

Embedding `http.ResponseWriter` is structural composition: `statusRecorder` automatically has every method the writer has; we override `WriteHeader` to record. **Edge case**: handlers that call `Write` without first calling `WriteHeader` implicitly produce a 200, so the middleware defaults `status=200`.

---

## 3. Persistence: pgx, transactions, the Executor trick

### 3.1 Why pgx (not database/sql)

- Native Postgres driver — no ODBC overhead.
- Connection pool (`pgxpool`) with strong defaults; we can read load info via `pool.Stat()`.
- Typed `pgconn.CommandTag` for rows-affected counts without a second roundtrip.
- Native `pgx.ErrNoRows` we check with `errors.Is`.

### 3.2 Transactions across multiple repos

The transaction manager wraps `Begin/Commit/Rollback`:
```go
func (m *Manager) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
    tx, err := m.db.Begin(ctx)
    if err != nil { return err }
    txCtx := context.WithValue(ctx, contextKey{}, tx)
    if err := fn(txCtx); err != nil {
        _ = tx.Rollback(ctx)
        return err
    }
    return tx.Commit(ctx)
}
```

Use cases that touch multiple tables (e.g. `Register`: identity + credential + tenant + user + role) wrap their work with this. Each repo's `executor(ctx)` returns the `tx` because `FromContext(ctx)` finds it.

### 3.3 Nullable column handling

Postgres `NULL` ↔ Go `nil` translation is explicit. We use `*string` / `*time.Time` in the domain struct, and the repo passes `nil` if the field is empty so postgres stores `NULL` (not the empty string).

```go
var secret any
if c.ClientSecretHash != "" { secret = c.ClientSecretHash }
// passing nil any → driver writes NULL
```

### 3.4 `INET` column handling

`sessions.ip_address` is `text` (not `inet`) — pragmatic decision in v0.1.0 to avoid pgx INET serialisation issues. The `audit_events.ip_address` IS `inet`, and we use `$N::inet` casting in the INSERT:
```sql
INSERT INTO audit_events (... ip_address ...) VALUES (... $7::inet ...)
```
Pass `nil` if no IP — Postgres NULL.

---

## 4. HTTP request lifecycle

```
TCP accept
  ↓
chi.Router
  ↓
[middleware stack, outer → inner]
  CORS                 → adds ACAO; short-circuits OPTIONS preflight with 204
  RequestLogger        → wraps response writer, defers a slog line
  metrics.Middleware   → defers a histogram observation + counter inc
  withAuth?            → on protected routes: JWT verify, else session-id cache+DB, else 401
  withPerm("X")?       → on RBAC-gated routes: 403 if Permission missing
  ↓
handler
  ↓
use case (.Execute(ctx, Input{...}))
  ↓
domain repo (interface)
  ↓
postgres impl
  ↓
pgxpool / pgx.Tx (via Executor)
```

Order matters: CORS first so preflight short-circuits, then logging so we see the actual status code, then metrics, then auth, then perm, then handler. Each middleware passes/wraps the request context — never mutates the original.

---

## 5. Concurrency primitives we rely on

### 5.1 `*pgxpool.Pool`

Internally serialises concurrent calls. Safe to share across goroutines. Connection acquisition is fast (LIFO queue + sync.Cond).

### 5.2 Redis `go-redis/v9` client

Thread-safe; underlying connection pool. `GetDel` is the atomic "consume" we lean on heavily for one-time tokens (auth codes, MFA tokens, WebAuthn ceremonies).

### 5.3 NATS `nats.go` connection

Thread-safe Publish; Subscribe runs handlers on internal goroutines. The audit consumer therefore needs its own context discipline — we use the request-scoped context `ctx` from the worker's `context.WithCancel`.

### 5.4 The `chi.Mux`

Reads-after-build are race-free; we register all routes before `server.Start()`. No dynamic route registration in our code.

### 5.5 Test concurrency

Stress / soak / spike / A/B all spawn goroutine pools and aggregate samples via a `sync.Mutex`-protected slice. Counters are `atomic.Int64`. The race detector (`go test -race`) is run as part of `./test/race.sh` — zero races detected across the suite.

---

## 6. Error model

### 6.1 Three levels

- **Sentinel errors** in `internal/shared/errors/errors.go` — domain-meaningful: `ErrNotFound`, `ErrUnauthorized`, `ErrInvalidCredentials`, `ErrConflict`, `ErrForbidden`, `ErrTenantMismatch`.
- **Domain-local errors** — e.g. `oauth/app.ErrInvalidGrant`, `mfa/app.ErrInvalidCode`. They live next to their use case.
- **Wrapped errors** for context — `fmt.Errorf("create session: %w", err)`. Callers unwrap with `errors.Is`/`errors.As`.

### 6.2 HTTP mapping

Done in the handler, not the use case. Pattern:
```go
if err != nil {
    if err == sharederrors.ErrInvalidCredentials {
        writeError(w, "invalid credentials", 401); return
    }
    if err == authapp.ErrMFAEnrollmentRequired {
        writeError(w, "mfa enrollment required", 403); return
    }
    writeError(w, "internal error", 500)
    return
}
```

The handler chooses the user-facing message; the use case never knows about HTTP.

### 6.3 5xx vs 4xx in metrics & logging

`statusRecorder` captures the status; the request logger upgrades the slog level (`>=500: ERROR; >=400: WARN; else INFO`). Prometheus `auth_http_requests_total{status="500"}` lets us alert on error rate.

---

## 7. Testing implementation deep-dive

### 7.1 The 10-layer pyramid

| Layer | Tooling | What it catches |
|---|---|---|
| Unit | `go test` | Wrong-input bugs in pure logic |
| Fuzz | `testing.F` | Inputs the developer didn't think of |
| Race | `go test -race` | Data races across goroutines |
| Smoke | bash + curl | "Did I break the wiring?" |
| Integration | go test over HTTP | Multi-step flows |
| Security | go test + canonical attacks | OWASP-class regressions |
| Stress + SLA | custom binary | Throughput, p95/p99 budgets that fail CI |
| Soak | custom binary | Memory leaks, drift over time |
| Spike | custom binary | Burst handling and recovery |
| A/B | custom binary | Statistical comparison of two paths |

### 7.2 Why we wrote our own stress/A/B (instead of `hey` / `wrk`)

- We need to do multi-step flows (PKCE handshake, MFA challenge) within a single "request".
- We want statistical assertions (Welch t-test) for the A/B harness.
- We want SLA budgets baked in as flags that exit non-zero.
- A few hundred lines of Go is easier to maintain than yet another tool.

### 7.3 Integration test client (`test/integration/client.go`)

A thin wrapper around `*http.Client` that remembers `AccessToken`, `RefreshToken`, `SessionID`, `TenantID`, `UserID` across calls. Tests look like:
```go
c := authedClient(t, "myprefix")    // registers + logs in a unique user
resp, body := c.Get("/me")          // Bearer auth applied automatically
MustStatus(t, resp, body, 200, "/me")
```
Each test gets a fresh tenant + user, so tests are independent and parallel-safe.

### 7.4 SLA assertion mechanism

```go
if *flagSLAp99 > 0 && pct(0.99) > *flagSLAp99 {
    breaches = append(breaches, fmt.Sprintf("p99 %s > budget %s", pct(0.99), *flagSLAp99))
}
// ...
if len(breaches) > 0 {
    for _, b := range breaches { fmt.Printf("  - %s\n", b) }
    os.Exit(2)
}
```

Non-zero exit code propagates up through CI. Zero budget means "don't assert" — so the same binary works for ad-hoc runs and gated CI runs.

### 7.5 Welch t-test in `test/abtest/main.go`

```go
t := (meanA - meanB) / math.Sqrt(varA/nA+varB/nB)
df := math.Pow(varA/nA+varB/nB, 2) /
      (math.Pow(varA/nA, 2)/(nA-1) + math.Pow(varB/nB, 2)/(nB-1))
```

Welch handles unequal variances and unequal sample sizes (the standard two-sample test assumes equal variance). With `n > 30000` per side, the t-distribution is essentially normal, so `|t| > 1.96 ≈ p<0.05`.

---

## 8. Common pitfalls + how the code prevents them

| Pitfall | Where it would hit | How we prevent it |
|---|---|---|
| String-keyed context value collision | `tx`, `principal` keys | Unexported `contextKey struct{}` |
| Forgetting transaction propagation | Multi-step writes (Register, etc.) | `r.executor(ctx)` checks `FromContext` automatically |
| JWT `alg=none` acceptance | Anything verifying JWTs | `jwt.WithValidMethods([]string{"ES256", "RS256"})` |
| Timing attacks on password / PKCE / client secret | `password.Verify`, `verifyPKCE`, OAuth secret check | `subtle.ConstantTimeCompare` everywhere |
| PKCE downgrade to `plain` | `/oauth/authorize` | Reject any method !== `S256` |
| Auth code reuse | `/oauth/token` | Redis `GetDel` (atomic consume) |
| Refresh token reuse after rotation | `/refresh` | Old session is `Revoke`d; `RevokedAt != nil` rejects |
| Cached principal after role change | `/me` via session-id | TTL=5min; on logout/refresh we explicitly `Delete` |
| Argon2 panic on malformed hash | `password.Verify` | Empty salt/hash guard; **caught by fuzz, regression-locked** |
| CSRF on refresh cookie | `/refresh` | `SameSite=Strict` + JSON content type only |
| Cross-tenant data leak | Any read | Tenant-scoped repo methods by default; OAuth client tenant matched to principal tenant |
| Goroutine leak in worker | Cleanup tick + audit consumer | `context.WithCancel` + `select { case <-ctx.Done(): return }` |

---

## 9. Conventions to keep when adding code

1. **Domain first**. Add the interface in `domain/`. Add the use case in `app/`. Last, add the postgres impl in `infra/postgres/`. HTTP handler last of all.
2. **Never panic in production code**. `MustPrincipal()`-style helpers were removed in v0.2.0; use the `(value, ok)` form.
3. **Constant-time compare for any secret**. `subtle.ConstantTimeCompare`. Never `==`.
4. **No package-level mutable state**. Everything reachable from `main` is constructed in `main`.
5. **Every repo method takes `ctx`**. No `context.TODO()` in production code.
6. **JSON tags on response structs only**. Domain entities can stay tagless; tag them only when crossing the HTTP boundary.
7. **Sentinel errors are the contract**. If your use case can fail in a domain-meaningful way, return a sentinel; let the handler decide the HTTP code.
8. **Unit-test the use case with in-memory repos**. Don't reach for testcontainers unless the test is integration-flavored — those live in `test/integration/`.
9. **Add a fuzz target for any parser**. Cheap insurance; takes ~20 lines and runs in 5s in CI.
10. **Wire metrics + audit events at the moment the domain event happens**. Don't sprinkle counters in handlers — they belong in the use case or the middleware.
11. **Bench when you change a hot path**. `BenchmarkJWT_Issue`, `BenchmarkHash` and friends already exist; add more.
12. **Keep cardinality bounded** in any new Prometheus label. Don't label by `tenant_id` or `user_id`. Use route templates not raw URLs.
13. **Document the WHY in commit messages, not in code comments**. We don't write "// returns true if X" — the function name says that. We write commit messages that explain why we needed it.

---

## 10. Files-of-interest cross-reference

| Topic | Open these first |
|---|---|
| HTTP wiring | `cmd/iam-server/main.go` |
| Worker | `cmd/worker/main.go` |
| Key rotation | `cmd/key-rotator/main.go` |
| JWT lifecycle | `internal/token/app/jwt_service.go`, `keygen.go` |
| OAuth flow | `internal/oauth/app/{authorize,token}.go` |
| MFA flow | `internal/mfa/app/{totp,complete,challenge_store}.go` |
| WebAuthn | `internal/webauthn/app/{service,login_complete,user,session_store}.go` |
| Principal lifecycle | `internal/auth/middleware/{authentication,principal_cache}.go` |
| Per-tenant policy | `internal/tenant/app/policy_enforcer.go`, `infra/postgres/policy_repository.go` |
| Audit | `internal/audit/{domain,app,infra/postgres}` |
| Metrics | `internal/platform/metrics/metrics.go` |
| Transaction trick | `internal/platform/postgres/tx/tx.go` |
| Test runner | `test/run-all.sh` |
| Stress + SLA | `test/stress/main.go` |
| A/B + Welch | `test/abtest/main.go` |
| Soak | `test/soak/main.go` |
| Spike | `test/spike/main.go` |
| Fuzz | `internal/oauth/app/pkce_fuzz_test.go`, `internal/token/app/jwt_fuzz_test.go`, `internal/shared/password/password_fuzz_test.go` |
| Security | `test/security/security_test.go` |
