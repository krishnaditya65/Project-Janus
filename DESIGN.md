# Auth Server — Design Document

## 0. Purpose & Scope

A multi-tenant identity & access management service that issues, verifies, and rotates credentials over HTTP. It speaks several standards (OAuth 2.0, OpenID Connect, WebAuthn, TOTP) so that any client following those specs can authenticate without custom integration.

Non-goals (today): SAML, SCIM, social login, full admin UI, custom claim mapping. Each is named in the roadmap.

---

## 1. Architectural Pillars

### 1.1 Clean architecture (ports & adapters)

Every domain is split into four layers:

```
internal/<domain>/
  domain/        — entities + repository interfaces (ports)
  app/           — use cases (business logic)
  infra/...      — postgres / redis / nats implementations (adapters)
  transport/http — HTTP handlers (delivery)
  middleware/    — request-level concerns
```

Use cases depend on interfaces, never on concrete implementations. The composition root (`cmd/iam-server/main.go`) is the only place where concrete types are picked. This gives us:
- **Testability**: in-memory repos for unit tests of use cases.
- **Swappability**: a postgres repo can be replaced with a redis repo with no domain change.
- **No god classes**: each file fits in your head.

### 1.2 Composition root, not framework

There is no DI framework. `main.go` wires everything by hand. This is verbose but explicit — you can trace dependencies by reading 250 lines top to bottom, no struct tags, no reflection, no init() side effects.

### 1.3 Multi-tenancy from day one

Two tables anchor the model:
- `identities` — one row per human (global, email-unique, email-verified bit, status)
- `users` — one row per (tenant, identity) pair (tenant-scoped membership, can have its own username/display name)

A single person logging into two tenants gets two `users` rows with one shared `identities` row. Every query above the identity layer is tenant-scoped by default; mixing tenants is impossible by construction.

### 1.4 Stateless and stateful auth side by side

- **JWT access tokens** (15 min) → stateless verify, no DB lookup, scales horizontally.
- **Opaque refresh tokens** (7 d) → stored hashed (SHA-256) in `sessions.refresh_token_hash`, rotated on each refresh, revoked sessions can't be replayed.
- **Session-ID auth** (legacy / mobile fallback) → DB-backed, now cached in Redis (5 min TTL) for sub-2ms verify.

Both auth paths produce the same `Principal` struct in context, so handlers never have to know which path was used.

---

## 2. Domain Map

```
auth-server/
├── cmd/
│   ├── iam-server/      composition root (HTTP API)
│   ├── worker/          audit consumer + session cleanup
│   ├── key-rotator/     generates/rotates ES256/RS256 signing keys
│   └── migrate/         (placeholder)
└── internal/
    ├── identity/        identities + tenant-scoped users
    ├── auth/            register / login / refresh / logout / authn middleware
    ├── authorization/   roles, permissions, RBAC checks
    ├── tenant/          tenant + tenant policies
    ├── session/         opaque-refresh-token-backed sessions
    ├── token/           JWT signing keys + issuance/verification
    ├── oauth/           authorization code + PKCE + refresh_token grants
    ├── oidc/            ID tokens, discovery, userinfo
    ├── mfa/             TOTP enrollment + challenge
    ├── webauthn/        passkey registration + discoverable login
    ├── audit/           NATS publisher/consumer + audit_events repo
    ├── platform/
    │   ├── postgres/    pgx pool + Pools (writer/reader)
    │   ├── redis/       go-redis client
    │   ├── nats/        nats.go connection
    │   ├── httpserver/  chi router + CORS + request logger
    │   ├── metrics/     Prometheus registry + middleware
    │   └── config/      env loader
    └── shared/
        ├── context/     typed context keys (principal, transaction)
        ├── principal/   Principal struct
        ├── errors/      sentinel errors
        ├── password/    Argon2id hash/verify
        ├── token/       random + SHA-256 helpers
        ├── id/          UUID generation
        ├── slug/        slug generation
        └── tx/          transaction manager
```

---

## 3. Authentication Flows

### 3.1 Password login (no MFA)

```
client                   server                       postgres                  redis
  |--POST /login-------->|
  |                      |--GetByEmail-------------->|
  |                      |<-identity, credential-----|
  |                      | argon2.Verify (CPU bound)
  |                      |--GetByIdentityID--------->|
  |                      |<-user----------------------|
  |                      |--TenantPolicy.Get--------->|
  |                      |<-policy--------------------|
  |                      |--GetVerifiedFactors------>|
  |                      |<-[] (no MFA)---------------|
  |                      |--GenerateRandom(32)
  |                      |--SHA-256 hash refresh
  |                      |--GetRoles + GetPermissions->|
  |                      |--Create session------------>|
  |                      |--JWT.Issue (ES256)
  |<--200 + access_token-|
  |    + Set-Cookie: refresh_token; HttpOnly; SameSite=Strict
```

### 3.2 Login with MFA enrolled

```
client                   server                       redis
  |--POST /login-------->|
  |  ...password verify...
  |                      |--GetVerifiedFactors-->...
  |                      |   factors > 0
  |                      |--GenerateRandom(32) (mfa_token)
  |                      |--Store challenge------->| TTL=5min
  |<--200 {mfa_required:true, mfa_token}
  |
  |--POST /mfa/complete->|
  |                      |--ChallengeStore.Consume->| (one-time GetDel)
  |                      |--TOTPService.Verify (window=1 step)
  |                      |--create session + JWT
  |<--200 + tokens
```

### 3.3 Login when policy requires MFA but no factors enrolled

```
client                   server
  |--POST /login-------->|
  |  ...password verify...
  |                      |--TenantPolicy.Get
  |                      |   policy.RequireMFA=true
  |                      |--GetVerifiedFactors-->[]
  |<--403 "mfa enrollment required"
```

Out-of-band: an admin or a previous-session-with-mfa flow must enroll TOTP first.

### 3.4 Refresh (token rotation)

```
client                   server                       postgres                  redis
  |--POST /refresh------>|
  |  cookie or body
  |                      |--SHA-256 refresh
  |                      |--GetByRefreshTokenHash----->|
  |                      |   check ExpiresAt, RevokedAt
  |                      |--sessionRepo.Revoke(old)--->|
  |                      |--principalCache.Delete----->|
  |                      |--GenerateRandom(32) (new refresh)
  |                      |--Create new session-------->|
  |                      |   parent_session_id = old.ID
  |                      |--Identity + Roles + Perms-->|
  |                      |--JWT.Issue
  |<--200 + new tokens + Set-Cookie (new refresh)
```

Replay-prevention property: the **old** refresh token's hash is no longer in the table for a non-revoked row, so a stolen old token returns 401.

### 3.5 OAuth Authorization Code + PKCE

```
SPA                                   server                     redis
  |--code_verifier = random
  |--code_challenge = base64url(SHA256(verifier))
  |
  |--GET /oauth/authorize?
  |    response_type=code
  |    client_id=...
  |    redirect_uri=...
  |    code_challenge=... method=S256
  |    nonce=...    state=... ----->|
  |                                  |--client repo lookup
  |                                  |--verify redirect_uri allowlist
  |                                  |--Principal must come from session/JWT
  |                                  |--generate code, store in Redis (10 min TTL)
  |<--302 redirect_uri?code=...&state=...
  |
  |--POST /oauth/token
  |    grant_type=authorization_code
  |    code=...
  |    code_verifier=...
  |    client_id=... -------------->|
  |                                  |--CodeStore.Consume (one-time GetDel)
  |                                  |--verify base64url(SHA256(verifier)) == challenge
  |                                  |--verify redirect_uri match
  |                                  |--create session + JWT
  |                                  |--if openid in scopes → IDTokenService.Issue
  |<--{access_token, refresh_token, id_token?, expires_in, scope}
```

PKCE is **mandatory** for every client (public and confidential) and the only supported method is `S256` (RFC 7636 §4.4).

### 3.6 WebAuthn / Passkey login (discoverable)

```
browser                              server                     redis            postgres
  |--POST /webauthn/login/begin --->|
  |                                  |--webauthn.BeginDiscoverableLogin
  |                                  |--store SessionData --->|     TTL=5min
  |<--{session_key, options}--------|
  |
  |--navigator.credentials.get(options)
  |   user taps Touch ID / passkey
  |
  |--POST /webauthn/login/complete-->|
  |    {session_key, response}
  |                                  |--SessionData.Consume <--|
  |                                  |--FinishDiscoverableLogin
  |                                  |   handler resolves user_handle -> user
  |                                  |   verifies signature & sign-count
  |                                  |--update sign_count -------->|
  |                                  |--issue session + JWT
  |<--{access_token, refresh_token, ...}
```

---

## 4. Token Strategy

| Token | TTL | Where stored | Where transmitted | Purpose |
|---|---:|---|---|---|
| Access token (JWT) | 15 min | Client memory (SPA) / secure storage (mobile) | `Authorization: Bearer` | Stateless, sent on every request |
| Refresh token | 7 days | `sessions.refresh_token_hash` (SHA-256) | HTTP-only `Set-Cookie` + JSON body | Get new access token without re-prompting password |
| ID token | 15 min | Client | JSON body of `/oauth/token` (OIDC scope) | Identity claim to relying party |
| Authorization code | 10 min | Redis (`oauth:code:<code>`) | URL query string | Single-use, PKCE-bound |
| MFA challenge token | 5 min | Redis (`mfa:challenge:<token>`) | JSON body | Carries identity context between password and TOTP |
| Signing key | indefinite | `signing_keys` table | Private — never leaves DB; public served via JWKS | ES256/RS256 |

### Cookie semantics for the refresh token

```
Set-Cookie: refresh_token=<token>;
            Path=/;
            Max-Age=604800;
            HttpOnly;
            Secure;             (in prod; off in dev)
            SameSite=Strict
```

- **HttpOnly** — JS can never read it → XSS-proof for the refresh path.
- **SameSite=Strict** — no third-party origin can trigger a refresh → CSRF-proof.
- **Path=/** — sent on every endpoint so `/refresh` and `/logout` can both touch it.

---

## 5. The `Principal` and how it flows

```go
type Principal struct {
    SessionID, IdentityID, TenantID, UserID, Email string
    Roles, Permissions []string
}
```

The authentication middleware loads it (either via JWT decode or DB+cache for session-id) and stores it in the request context under a typed key. Every handler reads it like this:

```go
p, ok := authctx.Principal(r.Context())
if !ok { return 401 }
```

Authorization middleware (`RequirePermission("users:read")`) is a separate layer that checks `p.Permissions` and 403s on mismatch.

---

## 6. Caching strategy (v0.8.0)

### 6.1 Principal cache

Key: `auth:principal:<sessionID>`
Value: JSON-encoded `Principal`
TTL: 5 minutes
Invalidation:
- Explicit `Delete` on logout
- Explicit `Delete` on refresh (which revokes the old session)
- Implicit: TTL expiry (5 min)

**Tradeoff**: a role grant takes up to 5 minutes to propagate to active sessions. That's the cost of skipping 4 DB reads on every request. Acceptable for auth; not acceptable for, say, billing.

### 6.2 Code store + MFA challenge store + WebAuthn session store

All three use the same Redis-`GetDel` pattern: single-use, short TTL, atomic consume. Code:
```go
b, err := client.GetDel(ctx, key).Bytes()
if err == goredis.Nil { return ErrNotFound }
```
GetDel is atomic in Redis — there is no race window where two clients could redeem the same code.

---

## 7. Observability (v0.8.0)

| Stream | Tool | What it captures |
|---|---|---|
| Logs | `slog` JSON to stdout | Per-request line + ERROR/WARN on failure, structured fields, signal-grade |
| Metrics | Prometheus at `GET /metrics` | RED metrics + auth events + cache hit-rate |
| Audit | NATS → worker → `audit_events` table | Long-term immutable record (planned in v0.10.0) |

### 7.1 Metric labels

We deliberately keep cardinality bounded:
- `route` = chi route template (`/users/{userID}`), not the actual URL
- `status` = e.g. `200`, `401`, `500` — not `2xx`
- **No** `tenant_id` or `user_id` labels — that would explode cardinality on a busy server.

### 7.2 Histogram buckets

`{1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s}` — covers JWT verify (≈4ms) through password login (≈100ms) through worst-case timeouts.

---

## 8. Multi-tenancy & per-tenant policy (v0.9.0)

```
tenants ─── 1:1 ─── tenant_policies (NULL row = system defaults)
                    │
                    ├── password_{min_length, require_upper, require_digit, require_symbol}
                    ├── allowed_email_domains JSONB
                    ├── require_mfa
                    └── max_active_sessions
```

Policy is fetched on the hot path (login). Defaults apply when no row exists — no migration is needed for existing tenants. New tenants get nothing extra until an admin `PUT /tenant/policy`-s.

### 8.1 Tenant-scoped permissions

`permissions.tenant_id` is now nullable. `NULL` = system/global permission (existing rows). The unique constraint moved from `(name)` to `COALESCE(tenant_id::text, '') + name` so each tenant can have its own permission space without colliding with the global one. This lays the groundwork for tenant-defined permissions in v0.11.0.

---

## 9. Cryptography summary

| Use | Algorithm | Why |
|---|---|---|
| Password storage | Argon2id (m=64MB, t=3, p=2, salt=16B) | Memory-hard, side-channel resistant, OWASP-recommended |
| Password compare | `crypto/subtle.ConstantTimeCompare` | Defeats timing attacks |
| Refresh token | 32B random → SHA-256 → hex | Hash is what's stored; the raw token is the bearer secret |
| JWT signing | ES256 (P-256 ECDSA) by default; RS256 also supported | Small signatures, fast verify; RS256 for legacy RP compatibility |
| PKCE | SHA-256 → base64url, S256 method only | Plain method is insecure (RFC 7636 §7.2) |
| TOTP | SHA-1, 6 digits, 30s, ±1 step tolerance | Google Authenticator compatibility (SHA-256/512 are stronger but break compatibility) |
| WebAuthn | ES256 / RS256 / EdDSA (whatever authenticator supports) | Discoverable resident keys (passkeys) |
| Signing key rotation | Manual via `cmd/key-rotator -alg ES256` | New keys become active, old keys remain in JWKS for ~7 days for in-flight tokens |

---

## 10. Failure modes and how we handle them

| Failure | Today | Future |
|---|---|---|
| Redis down | Principal cache returns "miss"; system falls back to 4-DB-read path. Code store / MFA challenge fail outright with `invalid_grant` — acceptable since they need state | Optional in-memory secondary cache |
| NATS down | Audit publish silently dropped (logged at WARN) | Local file buffer with replay |
| DB down | Server returns 500. Liveness probe fails. | Read-replica fallback, circuit breaker |
| Key rotation mid-flight | Old kid still in `signing_keys` for 7 days → tokens stay valid | Keyless JWT acceptance window |
| Replay of revoked refresh | `RevokedAt != nil` → 401 | Same |
| MFA factor compromised | Admin must delete via DB | Self-service `DELETE /mfa/factors/{id}` (already implemented) |

---

## 11. Tradeoffs taken

| Decision | Why we chose it | What we gave up |
|---|---|---|
| Hand-wired DI | Explicit, debuggable | Verbosity in main.go |
| Postgres-only persistence | Single source of truth, transactions for free | No multi-region writes |
| Redis for ephemeral state | Atomic GetDel, sub-ms TTL | Extra dep, extra failure mode |
| 1:1 `tenant_policies` table (not columns on `tenants`) | Easy to add new policy fields without schema churn on `tenants` | One extra join (avoided on the hot path by caching) |
| Bearer JWT in JSON body, refresh in cookie | Works for SPA + mobile + SSR identically | Slightly more client complexity (must remember the cookie is set) |
| ES256 default | Modern, small, fast | Some legacy OIDC RPs need RS256 — supported as second key alg |
| Argon2id at m=64MB | Industry recommendation, ~100ms login | Can't sustain >10 logins/s/CPU; mitigated by horizontal scaling, not by weakening params |
| No DI framework | Build is `go run`; no codegen step | Repetition in tests |
| Native Go `testing.F` for fuzz | Zero extra deps, runs in CI | Less feature-rich than libFuzzer |

---

## 12. Roadmap (after v0.9.0)

In priority order (locked in the planning doc):

1. **Identity & Access** — email verification, password reset, magic links, social login (Google/GitHub/Apple), SAML, SCIM, account linking, impersonation, session management API, API keys, custom JWT claims.
2. **OAuth Advanced** — third-party client registration with consent, client credentials grant (M2M), device authorization grant, token revocation, token introspection, PAR.
3. **Security Hardening** — rate limiting (close the documented brute-force gap), constant-time login (close the documented timing gap), account lockout, anomaly detection, DPoP, mTLS service accounts, encrypted signing keys at rest.
4. **FAPI** — JAR, JARM, mTLS-bound tokens, JTI replay prevention.

---

## 13. References

- RFC 6749 — OAuth 2.0
- RFC 7636 — PKCE
- RFC 6238 — TOTP
- RFC 7519 — JWT
- RFC 7517 — JWK
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- OpenID Connect Core 1.0
- WebAuthn Level 3
- OWASP ASVS v4 Level 2 — used as the security audit checklist
