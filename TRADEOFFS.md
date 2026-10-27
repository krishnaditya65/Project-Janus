# Project Janus — Deep Tradeoffs Analysis

A staff-engineer-level audit of every architectural, language-level, and code-level decision in this codebase. Each entry follows the same structure:

> **Decision** — what we did
> **Assumption** — what we believed when we chose it
> **Alternatives considered** — what else was on the table
> **Reasoning** — why this beat the alternatives
> **Cost** — what we gave up
> **When this is wrong** — the future state where we'd reverse the call
> **Revisit trigger** — concrete metric/event that should make us re-open the question

If a decision doesn't have a "When this is wrong" line, the decision is either trivial or hiding a problem. Every non-trivial choice should be reversible in principle.

---

## Table of contents

1. Architectural posture
2. Language & runtime
3. Persistence
4. Cache & messaging
5. HTTP layer
6. Identity & tenancy model
7. Authentication strategy
8. Cryptography
9. OAuth 2.0 / OIDC
10. MFA
11. WebAuthn
12. Per-tenant policy
13. Observability
14. Concurrency
15. Error model
16. Testing strategy
17. Operational design
18. Things we explicitly didn't build
19. Where we likely got it wrong
20. Decision-review cadence

---

## 1. Architectural posture

### 1.1 Modular monolith over microservices

**Decision** — Single deployable HTTP binary (`iam-server`) + one worker. All domains live in one Go module under `internal/`.
**Assumption** — Auth is a low-write, very-high-read service on a single tight bounded context (identity). Splitting it now would buy us nothing and would multiply operational surface.
**Alternatives considered** — Microservices per domain (auth/identity/oauth/mfa each its own service); serverless functions per endpoint; a service-mesh-of-modules pattern.
**Reasoning** — Auth domains are too tightly coupled to split: login → session → JWT → audit happens within one request. Splitting would introduce sync RPCs that recreate a monolith with network in between. A clean Go module gives us internal package boundaries without distributed-system tax.
**Cost** — One process becomes the SPOF; can't scale auth and OAuth flows independently; refactoring across domains is easier than it should be (we can short-circuit the public interface). Compile time grows with the codebase.
**When this is wrong** — When a single domain becomes a runaway CPU consumer (e.g. WebAuthn attestation parsing under attack) and starves login; or when one domain needs a wildly different runtime (e.g. SCIM batched writes needing a different DB connection pool tuning).
**Revisit trigger** — p99 latency contention on `/login` traceable to non-login code paths; or build time > 60s.

### 1.2 Clean architecture (ports & adapters)

**Decision** — Each domain has `domain/` (entities + repo interfaces), `app/` (use cases), `infra/` (postgres/redis/nats adapters), `transport/http/` (handlers).
**Assumption** — Business logic shouldn't know its persistence story. Tests should be able to replace persistence with in-memory.
**Alternatives considered** — Active Record (entity == DB row, methods on the entity), transaction script (handlers call SQL directly), Domain-Driven Design with aggregates and value objects.
**Reasoning** — We have multiple persistence stores per domain (Postgres + Redis + NATS); active record would require entity-per-store. We don't have rich domain invariants that need DDD aggregates. Clean architecture gives us testable use cases without overhead.
**Cost** — Lots of small files (a use case can be a one-liner that calls a repo); indirection makes "where does this query run" harder for newcomers; interface explosion if not disciplined.
**When this is wrong** — If the domain ever has many cross-aggregate invariants that you can't express as a single use case (e.g. financial double-entry bookkeeping). Then DDD aggregates would pay for themselves.
**Revisit trigger** — Use cases that take 6+ repository dependencies. That's a signal the use case is too big and probably an aggregate is hiding.

### 1.3 Hand-wired dependency injection in `main.go`

**Decision** — Composition root in `cmd/iam-server/main.go`; ~250 lines of `New...(dep1, dep2, ...)` calls.
**Assumption** — Reading code top-to-bottom should let an engineer trace every dependency. No magic.
**Alternatives considered** — Google Wire (codegen DI), Uber FX (reflection-based DI), package-level `init()` registries, struct tags + reflection.
**Reasoning** — DI frameworks shine when you have hundreds of services. We have ~30. Going from a function-call to a code-gen step or runtime registry adds debugging friction without saving real time. A long `main.go` is brutally explicit; you can grep for `NewLoginUseCase(` and find every site.
**Cost** — `main.go` is now 320 lines. Constructor parameter ordering bugs are possible (mitigated by `Input` struct pattern). Refactors that add a new dependency to a popular type touch many lines.
**When this is wrong** — When `main.go` crosses ~800 lines or when more than half of new bugs are wiring bugs. Then Wire becomes worth the learning curve.
**Revisit trigger** — Two wiring-typo bugs in a single quarter.

### 1.4 Domain-named packages (`auth`, `tenant`, `mfa`) not technical-layer packages (`handlers`, `services`)

**Decision** — Code is grouped by business capability, not by technical concern.
**Assumption** — Most changes ride a vertical (touch the same domain at multiple layers); few changes ride a horizontal (touch all handlers).
**Reasoning** — When MFA changes, we want all MFA code in one place, not scattered across `handlers/mfa.go`, `services/mfa.go`, `models/mfa.go`. Vertical packaging matches how features actually evolve.
**Cost** — `internal/foo/transport/http/handler.go` is verbose. The `http` sub-package name shadows the stdlib `net/http` so we always have to import-alias one of them.
**When this is wrong** — In a UI-monolith where the UI is uniform across domains, horizontal packaging by view-layer can be cleaner. Not our situation.

---

## 2. Language & runtime

### 2.1 Go (over Rust, Java/Kotlin, Node)

**Decision** — Go 1.26.
**Assumption** — Auth is concurrency-heavy I/O with simple data structures and crypto. We need a language that handles 10k+ concurrent connections without operator gymnastics and that compiles to a single binary.
**Alternatives considered** —
- **Rust**: best correctness, hardest hiring. Borrow checker pays off in cryptographic code where memory bugs are catastrophic, but pays the cost everywhere else.
- **Java/Kotlin + Spring**: massive ecosystem (Keycloak, Spring Security), GC pauses unpredictable for sub-10ms p99, JVM startup hurts horizontal scaling.
- **Node.js**: easy to hire, but the event loop blocks on Argon2 which is CPU-heavy.
**Reasoning** — Go's goroutine model is cheap concurrency for I/O-bound auth flows; the standard library covers HTTP, JSON, cryptography, and SQL drivers natively; static binary makes Docker/k8s deploys trivial. The Argon2 issue (CPU-bound on a goroutine) doesn't block the runtime — Go schedules other goroutines on other Ps while crypto runs.
**Cost** — Generics in Go are deliberately limited; no `Option<T>` / `Result<E, T>` — we lean on `(value, ok)` and `error`. No sum types makes some domain modelling clumsy (e.g. our `Credential` is one struct that could be a sum of `Password | WebAuthn | OIDC`).
**When this is wrong** — If memory safety becomes the dominant concern (a CVE-prone area like attestation parsing or ASN.1 cert decoding starts shipping vulnerabilities), Rust starts paying for itself. Then again, those parts are already library code so we're inheriting that risk anyway.

### 2.2 Standard library bias

**Decision** — `net/http`, `log/slog`, `encoding/json`, `crypto/*`, `database/sql` (via pgx). Only external libraries where the stdlib doesn't cover: JWT (golang-jwt), OAuth client validation, TOTP (pquerna/otp), WebAuthn (go-webauthn), Prometheus instrumentation.
**Assumption** — Stdlib correctness and performance are excellent. The Go team's compatibility promise outlives any third-party package.
**Reasoning** — Every external dep is a future CVE / abandoned project / breaking-change risk. Stdlib is the safest place to build.
**Cost** — We write more glue. `chi` is one of the rare exceptions (the stdlib's `http.ServeMux` only got proper routing in 1.22 and is still less ergonomic).
**When this is wrong** — When a third-party library has a feature we'd otherwise reimplement (e.g. webauthn protocol parsing — we wouldn't roll our own).

### 2.3 `slog` (over `zap`, `logrus`)

**Decision** — Standard library `log/slog` (Go 1.21+).
**Assumption** — A structured logger we don't have to vendor or migrate is worth a small perf hit.
**Reasoning** — `zap` is faster (~5-10ns per call vs slog's ~50ns) but adds an import; logrus is slower than slog. For a 10k req/s service, slog's overhead is <0.1% of request budget. Not the bottleneck.
**Cost** — `slog` is younger; ecosystem (loki integration etc.) is catching up. `LogAttrs` is verbose if you forget the typed helpers.
**When this is wrong** — If we ever profile and find slog in the top 5 by CPU. Then `zap` is a drop-in.

### 2.4 No interface-as-config / no `any` flying around

**Decision** — Inputs and outputs use concrete typed structs. `any` only at JSON boundaries.
**Assumption** — Static typing catches more bugs than it costs in verbosity.
**Reasoning** — Once a refactor breaks the type, the compiler tells us every caller. `any` would mean every refactor needs runtime tests to catch.
**Cost** — Adding a field to an `Input` struct touches every caller; some calls feel ceremony-heavy.

---

## 3. Persistence

### 3.1 PostgreSQL as the single source of truth

**Decision** — Postgres only. No MongoDB, no DynamoDB, no Cassandra.
**Assumption** — Multi-row transactions matter (register creates 5 rows; refresh revokes-and-creates atomically); strong consistency is non-negotiable.
**Alternatives considered** —
- **NoSQL** (DynamoDB): scales horizontally with predictable cost, but cross-document writes need transactional API which is weaker than SQL transactions. Indexing flexibility is lower.
- **MySQL**: similar story, but Postgres JSONB, partial indexes, and `INET` type are genuinely better for our shape.
- **CockroachDB**: distributed SQL with the same wire protocol; lets us do multi-region. Heavier ops, immature compared to Postgres at our scale.
**Reasoning** — Auth is OLTP. Postgres is the best OLTP engine in 2026 and the operational ecosystem (pgvector, pgbouncer, pglogical, pgBackRest) is mature.
**Cost** — We can't go multi-region active-active without serious rework (logical replication + careful conflict resolution).
**When this is wrong** — When write latency from a single region to another becomes a customer issue. Then CockroachDB or Spanner becomes interesting.
**Revisit trigger** — A real ask for "EU data residency" or "5 RTT writes in APAC".

### 3.2 pgx over `database/sql`

**Decision** — `jackc/pgx/v5` (native Postgres protocol), via `pgxpool`.
**Reasoning** — Native protocol is meaningfully faster than ODBC; `pgconn.CommandTag.RowsAffected()` is free; typed parameter binding catches mismatches at compile time. The pgx team's release cadence has been steady for years.
**Cost** — Locks us out of any database that isn't Postgres. Adapters that target `database/sql` (e.g. some ORMs) won't work.
**When this is wrong** — If we ever wanted database portability for an on-prem customer who refuses Postgres.

### 3.3 Schema migrations as numbered SQL files

**Decision** — `migrations/000001_*.up.sql` and `.down.sql`. Applied via `psql` in dev; not yet via the `cmd/migrate` binary (placeholder).
**Assumption** — SQL is the right interface for schema. Migrations should be reversible.
**Alternatives considered** — golang-migrate library, sqlc-generated migrations, GORM auto-migrate.
**Reasoning** — SQL is the ultimate truth. Hand-written migrations are easier to review than codegen, and downs are explicit.
**Cost** — `cmd/migrate/main.go` is empty; we shell out to `psql` in dev which is operationally crude. Production needs a proper apply mechanism.
**When this is wrong** — As soon as we ship to production. The cmd/migrate binary must be implemented before then.
**Revisit trigger** — Pre-prod deploy planning.

### 3.4 The "Executor trick" for transaction propagation

**Decision** — A shared `Executor` interface in `internal/platform/postgres/tx/tx.go` satisfied by both `*pgxpool.Pool` and `pgx.Tx`. Repos check the context for a transaction and pick the right executor automatically.
**Assumption** — Use cases shouldn't have to thread a `tx` parameter through every call.
**Alternatives considered** —
- Pass `tx` explicitly as a parameter ("functional" Go).
- One repo type for pool, another for transaction (doubles the code).
- A "unit of work" pattern with a session object.
**Reasoning** — Context-passed transactions match Go's existing pattern for request-scoped data; the executor abstraction means repos don't change. The interface is small (3 methods) so the surface area is minimal.
**Cost** — A repo method run outside a transaction looks identical to one inside; you can accidentally pass the wrong context (`context.Background()` instead of `txCtx`) and silently bypass the transaction. We mitigate this by always using `txCtx` inside `WithinTransaction(ctx, func(txCtx context.Context) error { ... })`.
**When this is wrong** — If you needed to compose transactions across services (sagas across HTTP), the in-process transaction model breaks down. That's a microservices problem we don't have.

### 3.5 Two-layer identity (`identities` + `users`) vs single `users` table

**Decision** — `identities` is the global, email-unique human; `users` is the tenant-scoped membership. A single `users` row can never appear in two tenants — but one identity can be linked to many `users`.
**Assumption** — A single person realistically belongs to multiple tenants (consultants, multi-org employees, support staff).
**Alternatives considered** —
- `users(email, tenant_id)` with `UNIQUE(email)` global → one email = one tenant only. Common in SaaS but limiting.
- `users(email, tenant_id)` with `UNIQUE(email, tenant_id)` → email duplicated per tenant; password reset has to ask "which tenant?".
**Reasoning** — Splitting global from tenant-scoped is the cleanest model for multi-tenancy. Federation (v0.12.0) and SCIM (v0.13.0) both need a stable identity ID independent of tenant.
**Cost** — Every query needs a join. Schema is harder to explain to newcomers ("why is email on identities but username on users?").
**When this is wrong** — Never, in a B2B/B2B2C product. In a strict B2C product (consumer app where users belong to "the platform" not to tenants), the join is overhead.

### 3.6 `ip_address` as `text` in `sessions`, but `inet` in `audit_events`

**Decision** — Pragmatic inconsistency from early in development.
**Assumption** — None — this is technical debt.
**Reasoning** — We hit pgx serialization issues with `inet` early in v0.1.0 and shipped `text`. By v0.8.0 (audit) we'd figured it out and used `inet` properly.
**Cost** — Two formats for the same data; can't run efficient subnet queries on `sessions`.
**When this is wrong** — When we want to do anomaly detection by subnet (v0.14.0). Then we should migrate `sessions.ip_address` to `inet`.
**Revisit trigger** — v0.14.0 risk scoring work.

### 3.7 Refresh tokens stored on `sessions`, not on the dead `refresh_tokens` table

**Decision** — `sessions.refresh_token_hash` is the live field. The `refresh_tokens` table created in migration 000003 is unused.
**Assumption** — One session = one refresh token at a time. Rotation creates a new session, not a new row in `refresh_tokens`.
**Reasoning** — Simpler model. The cost of a separate `refresh_tokens` table is a join for every refresh + a more complex rotation flow.
**Cost** — Dead schema sitting there confusing future engineers. We should `DROP TABLE refresh_tokens` in a future migration.
**When this is wrong** — If we ever want multiple concurrent refresh tokens per session (e.g. one per device). Then `refresh_tokens` becomes the right model.

### 3.8 Tenant-scoped permissions via nullable `tenant_id`, not a separate table

**Decision** — `permissions.tenant_id NULL` means "system/global permission". Per-tenant permissions have a non-null tenant ID. The unique constraint is `(COALESCE(tenant_id::text, '') , name)`.
**Assumption** — System permissions ("users:read") and tenant-defined permissions ("acme:custom-report") share the same name space, just scoped differently.
**Alternatives considered** —
- Separate tables `system_permissions` and `tenant_permissions` — duplication, joins become unions.
- A `scope` enum column with `system | tenant` and `tenant_id` mandatory when tenant — more complex check constraint.
**Reasoning** — Nullable FK is the simplest expression of "0..1 owner". The `COALESCE` trick makes the unique constraint expressive.
**Cost** — Queries that want "all permissions for this tenant including system" must `WHERE tenant_id = $1 OR tenant_id IS NULL`. Easy to forget.
**When this is wrong** — If tenants ever need to be able to *redefine* a system permission. Then the union becomes ambiguous and the separate-table approach pays off.

---

## 4. Cache & messaging

### 4.1 Redis for transient state (auth codes, MFA challenges, principal cache)

**Decision** — `redis/go-redis/v9`.
**Assumption** — We need atomic single-use semantics (auth codes can't be redeemed twice) and sub-millisecond reads.
**Alternatives considered** —
- In-process LRU (`hashicorp/golang-lru`): no network, but breaks under horizontal scale (auth code created on instance A, redeemed on instance B → 404).
- Postgres with `DELETE ... RETURNING *`: works but adds DB load and 1-5ms latency for what's a hot path.
- Memcached: no `GETDEL`; have to do GET + DEL non-atomically.
**Reasoning** — Redis `GETDEL` (or our use of `Get` + Lua) is the atomic primitive we need. Throughput is high, TTLs are native, ops are well-understood.
**Cost** — Operational dep (Redis cluster on prod). If Redis is down, OAuth code grants fail and Principal cache misses fall back to DB (degraded but still works).
**When this is wrong** — If we ever need durable single-use tokens (e.g. one-time admin links). Then a Postgres row with `consumed_at` is correct.

### 4.2 Redis `GetDel` for one-time tokens (over `WATCH/MULTI` or Lua)

**Decision** — Atomic GET + DEL via the native `GETDEL` command.
**Reasoning** — `GETDEL` is server-side atomic, one network round-trip. Alternatives need either optimistic concurrency (WATCH) or a Lua script (extra surface, harder to audit).
**Cost** — `GETDEL` requires Redis 6.2+ which is universal now.

### 4.3 Principal cache TTL = 5 minutes

**Decision** — 5 minutes hard TTL on cached principal, plus explicit invalidation on logout and refresh.
**Assumption** — Role changes are infrequent (admin edits) and a 5-minute propagation delay is acceptable.
**Alternatives considered** —
- 1 minute: faster propagation, lower hit rate.
- 1 hour: better hit rate, role-change lag too long.
- No TTL, explicit invalidation only: requires every role-change code path to fire the invalidation; missing one is a security bug.
**Reasoning** — TTL is a backstop against missed invalidations. 5 minutes is a tradeoff that gives ~95% hit rate (most sessions live shorter than 5 min between requests on busy sites) while keeping the worst-case stale window short.
**Cost** — A revoked role can still authorize for up to 5 minutes.
**When this is wrong** — In high-security environments (banking, healthcare) where revocation must be instant. Then explicit-only invalidation + a publish/subscribe invalidation channel is correct.
**Revisit trigger** — Any compliance ask that says "revocation must be immediate".

### 4.4 NATS for audit events (not Kafka)

**Decision** — NATS connection, single subject `audit.events`, no JetStream.
**Assumption** — Audit events are small, frequent, fire-and-forget. Persistence is the consumer's job (the worker writes to Postgres).
**Alternatives considered** — Kafka (durable, but heavyweight ops), Postgres LISTEN/NOTIFY (no payload size limit, but one DB connection per consumer), in-process channel + write directly (loses the async benefit).
**Reasoning** — NATS Core is light, in-memory, fast. The publisher is best-effort (we explicitly accept lost events on broker outage). Consumer is single-tenant simple.
**Cost** — A NATS broker outage drops audit events for the duration. We accept this for now; compliance-grade ops would want JetStream + at-least-once delivery.
**When this is wrong** — When audit log must satisfy SOC 2 / HIPAA. Then JetStream with persistence or Kafka with retention is correct.
**Revisit trigger** — First compliance audit.

### 4.5 Audit publisher is non-blocking and silent on failure

**Decision** — `Emit` logs a WARN and drops the event if NATS publish fails. Never returns an error to the auth flow.
**Assumption** — A flaky audit pipeline must not flake login.
**Cost** — Silent loss of events. We mitigate by logging the failure so ops can alert on `audit publish failed` log count.
**When this is wrong** — When we cross compliance threshold; then we need durable buffering + at-least-once semantics. v0.11.0 hash-chain integrity work partially addresses this.

---

## 5. HTTP layer

### 5.1 `chi` router over stdlib `http.ServeMux` or `gorilla/mux`

**Decision** — `go-chi/chi/v5`.
**Assumption** — We need path params, route templates for metrics labels, and middleware chains. The 1.22 stdlib finally supports path params but middleware ergonomics are still cleaner in chi.
**Alternatives considered** — stdlib (clunky middleware), gorilla (unmaintained), echo (heavier), gin (different idioms).
**Reasoning** — chi is small (~3000 LoC), idiomatic, and gives us `chi.RouteContext(r.Context()).RoutePattern()` which is exactly what the Prometheus metric label needs.
**Cost** — Yet another dep. Locks us out of stdlib-only deployments (not a real constraint).
**When this is wrong** — If chi stops being maintained. Risk seems low.

### 5.2 Middleware order: `CORS → RequestLogger → Metrics → Auth → Perm → handler`

**Decision** — CORS first, auth deep, perm just before handler.
**Reasoning** —
- **CORS first** so the OPTIONS preflight short-circuits before any other work.
- **Logger and metrics second** so they capture the actual response status the handler returns (after any later middleware decides 401/403).
- **Auth before perm** so we know who you are before checking what you can do.
- **Perm right before handler** so a 403 response still flows through the logger and metrics.
**Cost** — A misconfigured CORS at the front can short-circuit everything; debugging unexpected 204s starts at the front.
**When this is wrong** — If we ever want to log unauthenticated requests separately (e.g. honeypot routes). Then a different log middleware sits inside the auth gate.

### 5.3 CORS is wildcard `Access-Control-Allow-Origin: *`

**Decision** — Dev default. Allow all origins. No credentials.
**Assumption** — In dev, you want to try the API from any origin. In prod, this must be overridden.
**Cost** — In prod with default config, CSRF via cross-origin POST is theoretically possible. We mitigate by **not** sending credentials, but cookies on the refresh path would be exposed.
**When this is wrong** — In production, always. This needs a per-tenant origin allowlist before any prod deploy.
**Revisit trigger** — Pre-prod deploy. This is a v0.15.0 security-review pass blocker.

### 5.4 Request logger embeds `http.ResponseWriter` and overrides `WriteHeader`

**Decision** — `statusRecorder { http.ResponseWriter; status int }` wraps the writer to capture status.
**Reasoning** — Standard Go idiom. Embedding gives us every method the underlying writer has; we override only what we want.
**Cost** — If the handler does `http.NewResponseController(w)` (1.20+) to access `Flush`/`Hijack`/`Push`, those reach through to the embedded writer correctly. But code that type-asserts to `http.Flusher` and similar won't find it on `statusRecorder` directly. For our use case (JSON APIs, no streaming) this is fine.
**When this is wrong** — When we add server-sent events or websockets. Then we need to forward those interfaces explicitly.

---

## 6. Identity & tenancy model

### 6.1 Tenant-scoped vs row-level security

**Decision** — Application-level tenant scoping. Every repo method that returns data takes `tenantID` as a parameter and filters in the SQL.
**Alternatives considered** —
- Postgres Row-Level Security (RLS) policies that filter automatically.
- Schema-per-tenant.
- DB-per-tenant.
**Reasoning** —
- **RLS** would push enforcement into the DB which is excellent defense-in-depth, but adds complexity (every connection needs to `SET app.current_tenant = ...`) and complicates the Executor abstraction. Worth doing as a v0.15.0 hardening pass.
- **Schema-per-tenant** scales to ~100s of tenants and breaks down beyond. We expect 1000+ tenants.
- **DB-per-tenant** is operationally expensive (backup, monitoring, migration coordination) and ruled out.
**Cost** — A bug in the app layer can cross-leak tenants. We don't have RLS as a safety net.
**When this is wrong** — As soon as the first multi-tenant cross-leak bug ships. RLS becomes the cheap insurance.
**Revisit trigger** — v0.15.0 security review.

### 6.2 Tenant policy as 1:1 sidecar table, not columns on `tenants`

**Decision** — `tenant_policies` references `tenants(id)`; absent row means defaults.
**Reasoning** — Tenants table is heavily read (every request needs `tenant_id` validation upstream); we don't want to widen it every time we add a policy field. Sidecar table is fetched only when policy decisions are made (login, register).
**Cost** — An extra join when we want both at once. Mitigated by tenant data being heavily cached.
**When this is wrong** — If we ever discover that 99% of requests need policy data; then denormalising into `tenants` saves the lookup.

---

## 7. Authentication strategy

### 7.1 JWT + opaque refresh token (over session-only or JWT-only)

**Decision** — Two-token model.
**Assumption** — Stateless verify is worth a lot (no DB on every request); but we still need a revocation story (you can't revoke a JWT, only let it expire).
**Alternatives considered** —
- **Session-only** (every request hits the DB): simple, instant revoke. Doesn't scale to 10k req/s without serious caching, which we add anyway.
- **JWT-only with 15-min TTL**: no revoke, just wait 15 min. Acceptable for low-stakes apps; unacceptable for auth.
- **Short JWT + DB-backed introspection on critical actions**: hybrid. We're not at FAPI-grade today.
**Reasoning** — Two-token is the OAuth 2.0 default and what every client expects. Refresh tokens give us revocation; access tokens give us stateless scale.
**Cost** — Client complexity (must store both, must know when access expires). Mitigated by including `expires_in` in every response.
**When this is wrong** — If a customer says "we revoked an admin's session and they used the access token for the next 14 minutes to delete data". Then either we shorten access tokens to 60s (more refresh load) or we add introspection on destructive endpoints (more code).

### 7.2 Access token TTL = 15 minutes

**Decision** — Hardcoded constant `accessTokenTTL = 15 * time.Minute`.
**Assumption** — Balance between "stale roles are bad" (short TTL) and "refresh load is bad" (long TTL).
**Reasoning** — 15 min is the Auth0 / Google / Microsoft default. After v0.8.0's Principal cache (5-min TTL on cached principals), even our session-id auth has at most 5-min stale role data, so 15-min access tokens are consistent.
**Cost** — A token issued just before a role revocation is valid for up to 15 min.
**When this is wrong** — For high-value actions (banking transfer, password change, admin operations). Those should require re-auth or a fresh access token (`max_age` param).
**Revisit trigger** — v0.15.0 security review or first sensitive-action design.

### 7.3 Refresh token TTL = 7 days, rotated on every refresh

**Decision** — Constant `refreshTokenTTL = 7 * 24 * time.Hour`; refresh atomically revokes the old session and issues a new one.
**Assumption** — Mobile apps want sessions that survive a week of inactivity. Sliding window via rotation gives "active users stay logged in indefinitely" while inactive sessions die.
**Reasoning** — Rotation defeats stolen-refresh-token replay: if the attacker uses the token, the legit user's next refresh fails (their token is now revoked) and we have a tripwire for "session compromise detected" alerting (not yet implemented; v0.14.0 risk work).
**Cost** — Every refresh writes 2 rows (revoke + insert). At very high refresh rates this matters; we don't have that scale today.
**When this is wrong** — If we add long-lived "API keys" that look like refresh tokens. They shouldn't rotate. Hence the v0.11.0 / Identity & Access plan to add a proper API-key domain instead of misusing refresh.

### 7.4 Refresh token transport: HTTP-only cookie AND JSON body

**Decision** — Login sets `Set-Cookie: refresh_token=...; HttpOnly; SameSite=Strict; Path=/` and returns the token in the JSON body.
**Assumption** — One auth server must serve SPAs, mobile apps, server-rendered apps, and CLIs without each needing a different code path.
**Alternatives considered** —
- **Cookie only**: SPAs work cleanly; mobile can't easily read cookies.
- **Body only**: mobile works; SPAs have to use `localStorage` which is XSS-exposed.
- **Per-client choice via request header**: cleaner but doubles test surface.
**Reasoning** — Returning both lets each client use the form that's safest for it. The cookie is `HttpOnly` so it can't be exfiltrated via XSS. `SameSite=Strict` kills CSRF on the refresh endpoint.
**Cost** — A web app that mistakenly stores the body-token in localStorage gets the worst of both worlds (XSS exposure). We document this clearly.
**When this is wrong** — When we add session-binding (cnf claims, DPoP) — the cookie becomes redundant and confusing.

### 7.5 Bearer JWT path comes BEFORE the session-id path in middleware

**Decision** — `fromBearer(r)` runs first; falls back to `fromSessionHeader(r)`.
**Reasoning** — Bearer is the modern, scalable path; session-id is the legacy fallback. Putting Bearer first means common case is fast (no DB).
**Cost** — A client that has both could get unexpected behaviour if the JWT is expired but the session is still valid; we'd reject the JWT and never look at the session-id, returning 401. Fixed in v0.8.0 by also accepting either header type.

### 7.6 Session-id header is `X-Session-ID` (custom header, not standard)

**Decision** — Custom header, not `Cookie:` or `Authorization:`.
**Assumption** — In v0.1.0 we shipped this and haven't changed it.
**Cost** — Non-standard; doesn't get sent automatically by browsers (we'd need an interceptor); confuses standards-aware tools.
**When this is wrong** — Now, actually. The right migration is "remove session-id auth from the public API, keep it internal only or remove entirely". v0.8.0's Principal cache made the perf gap small enough that we could just rely on JWT.
**Revisit trigger** — When the SDK redesign happens (post-v0.13.0).

---

## 8. Cryptography

### 8.1 Argon2id (over bcrypt, scrypt, PBKDF2)

**Decision** — `golang.org/x/crypto/argon2.IDKey` with m=64MB, t=3, p=2, salt=16B, key=32B.
**Assumption** — Memory-hard hashing defeats GPU/ASIC brute force. Argon2id is the OWASP-recommended algorithm in 2026.
**Alternatives considered** —
- **bcrypt**: 1999 design, memory-cheap, GPU-vulnerable. Still acceptable but inferior.
- **scrypt**: memory-hard but parameters harder to tune.
- **PBKDF2**: stretching only, easily GPU-accelerated. Acceptable for legacy compat only.
**Reasoning** — Argon2id is the OWASP and IETF (RFC 9106) consensus recommendation.
**Cost** — ~100ms per hash on commodity hardware. Login throughput per CPU is bounded by this. We mitigate by horizontal scaling; we deliberately do NOT lower the parameters.
**When this is wrong** — Never, at the parameter level. The parameters might need raising over time as hardware improves; we should review them every 2 years.
**Revisit trigger** — OWASP changes its recommendation, or 2028 (parameter aging review).

### 8.2 Argon2 parameter choice: m=64MB t=3 p=2

**Decision** — OWASP "Interactive" preset.
**Reasoning** — Targets ~100ms on a CPU. Memory cost defeats GPU brute force; iteration count defeats CPU brute force; parallelism uses 2 cores.
**Cost** — At 100 logins/sec on a single CPU we saturate. Real number on modern hardware is closer to 10/sec/core; a 16-core server does ~160 logins/sec. Account for this in capacity planning.
**When this is wrong** — On a tiny VPS where 100ms is too long. Then drop to OWASP "Cheap" (m=15MB) — never below.

### 8.3 No password peppering, no envelope encryption of hashes

**Decision** — Just salt + hash, salt stored alongside hash in the standard Argon2 encoded form.
**Reasoning** — A peppered hash only adds value if your DB leaks but your application secret doesn't, which is a narrow threat model. Operational cost (key management, rotation, recovery) is high.
**Cost** — A full DB dump = an offline attack target.
**When this is wrong** — Defense-in-depth requirement for compliance. Add envelope encryption of the entire password column in v0.15.0.

### 8.4 ES256 (P-256 ECDSA) as default JWT alg, RS256 as fallback

**Decision** — `cmd/key-rotator -alg ES256` is the default. RS256 is available with `-alg RS256`.
**Assumption** — ECDSA signatures are smaller (~70B vs 256B for RS256) and faster to verify; modern (post-2018) OIDC RPs all support ES256.
**Alternatives considered** —
- **EdDSA (Ed25519)**: even smaller and faster than ECDSA, no parameter ambiguity. But RFC 8037 support in legacy OIDC RPs is weak.
- **RS256 only**: most compatible, but bigger and slower.
**Reasoning** — ES256 is the modern default; RS256 covers compatibility. EdDSA is the future but not yet ubiquitous.
**Cost** — Two algorithms to test. Mitigated by `Verify` taking `jwt.WithValidMethods([]string{"ES256", "RS256"})` once.
**When this is wrong** — When most clients are EdDSA-capable. Add Ed25519 then.

### 8.5 Allowlisting `ValidMethods` is the alg=none defense

**Decision** — Every `Verify` call passes `jwt.WithValidMethods([]string{"ES256", "RS256"})`.
**Reasoning** — Critical. Without this, `alg=none` JWTs are accepted (the CVE-2015-9235 class). Our fuzz test asserts this.
**Cost** — Adding a new algorithm requires touching all `Verify` call sites. We have one.

### 8.6 Refresh tokens hashed with SHA-256 (not Argon2)

**Decision** — `Hash(rand32) = hex(sha256(rand32))`.
**Reasoning** — The raw token is high-entropy (256 bits) so brute force is impossible. We hash to prevent DB readers from using the token directly. SHA-256 is fast (we do this on every refresh) and that's all we need.
**Cost** — None at the threat model we accept. A DB-read attacker can do an online attack (try the token against the API) but the token they read is high-entropy and won't be guessed.

### 8.7 PKCE S256 only, never plain

**Decision** — Reject any `code_challenge_method != S256` at `/oauth/authorize`.
**Reasoning** — RFC 7636 §7.2: "plain" leaks the verifier to network attackers when the auth code is intercepted. S256 binds the verifier to a hash that can't be reversed.
**Cost** — Some very old OAuth client libraries don't support S256. We are not in that ecosystem.

### 8.8 Constant-time compare via `subtle.ConstantTimeCompare`

**Decision** — Used for password hash compare, PKCE challenge compare, client secret compare.
**Reasoning** — A non-constant-time compare leaks one byte per timing measurement; attackers in a million-request budget can recover secrets.
**Cost** — Slightly more CPU than `==`; negligible.

### 8.9 Signing key rotation via grace period in JWKS

**Decision** — `signing_keys.ListPublic()` returns keys where `rotated_at IS NULL OR rotated_at > NOW() - INTERVAL '7 days'`.
**Assumption** — Access tokens live 15 minutes. We could shrink the JWKS window to 1 hour and be safe.
**Reasoning** — 7-day window covers cached JWKS (some clients cache for a day) and gives lots of margin.
**Cost** — A compromised key remains in JWKS for 7 days. We can do an emergency rotation by manually deleting the old row.
**When this is wrong** — Emergency. We should add `cmd/key-rotator -emergency` that deletes by ID.

---

## 9. OAuth 2.0 / OIDC

### 9.1 Auth code stored in Redis with TTL, not in DB

**Decision** — 10-min TTL Redis key.
**Reasoning** — Codes are single-use, short-lived. Postgres would handle this with `DELETE ... RETURNING`, but it's a write per code which adds load. Redis is built for this.
**Cost** — Redis outage = OAuth flow broken. Acceptable since the flow is already user-interactive (no autopilot reads it).

### 9.2 OAuth client → tenant binding is strict (no cross-tenant clients)

**Decision** — `client.TenantID` must match `principal.TenantID` at authorize time.
**Assumption** — In v0.4.0 we had no concept of a "platform" tenant that owns global clients. We may need one in v0.12.0 (federation IdP redirect URIs).
**Cost** — A "platform admin" tenant can't own a global OAuth client today; cross-tenant OAuth needs schema changes.

### 9.3 OAuth `oauth_clients.redirect_uris` is JSONB (exact match)

**Decision** — Each row is a strict literal allowlist.
**Assumption** — No wildcards. No pattern matching.
**Reasoning** — RFC 6749 §10.6 is explicit: redirect URI matching MUST be exact. Wildcards are a known attack surface.
**Cost** — Clients with multi-environment URIs (dev/stage/prod) have to register each.

### 9.4 OIDC discovery + JWKS are HTTP-cached

**Decision** — `Cache-Control: public, max-age=3600` on both.
**Reasoning** — These endpoints get hammered by RPs; cacheable for an hour is standard.
**Cost** — Key rotation propagation is delayed by up to one hour. Our 7-day grace window covers this.

### 9.5 `iss` claim defaults to `http://localhost:8080`

**Decision** — Env `JWT_ISSUER`; default `http://localhost:8080` for dev.
**Cost** — Misconfigured prod servers issue tokens with an `iss` that doesn't match the JWKS URL. RPs reject. Failure mode is loud and quick to diagnose.

---

## 10. MFA

### 10.1 TOTP with SHA-1, 6 digits, 30s window, ±1 step

**Decision** — RFC 6238 defaults via `pquerna/otp`.
**Assumption** — Google Authenticator compatibility is non-negotiable.
**Alternatives considered** — SHA-256 / SHA-512 are stronger but Google Authenticator silently ignores the algorithm choice — codes won't match.
**Reasoning** — SHA-1 in TOTP is not a security issue (we're not relying on collision resistance, only on HMAC). RFC 6238 explicitly allows it.
**Cost** — A user who hand-crafts an OTP URI with SHA-256 will fail with Google Authenticator. We document SHA-1 as the standard.

### 10.2 TOTP secret stored as base32 in `mfa_factors.secret_encrypted`

**Decision** — Column is named `secret_encrypted` but holds the literal base32 secret today.
**Assumption** — Eventually we'll add envelope encryption via KMS; column name is forward-looking.
**Reasoning** — Schema-naming-as-design-intent is a forcing function.
**Cost** — Today, a DB dump = stolen TOTP secrets = bypass MFA. Mitigated by DB encryption at rest + access controls.
**When this is wrong** — Right now, for any production deploy. v0.10.0 should add envelope encryption.
**Revisit trigger** — Pre-prod blocker.

### 10.3 MFA challenge token = 32B random in Redis, 5-min TTL

**Decision** — `mfa:challenge:<token>` stores `{IdentityID, TenantID, UserID, IPAddress, UserAgent, ExpiresAt}` as JSON.
**Assumption** — 5 minutes covers user reaching for their phone, navigating to the authenticator app, reading the code.
**Reasoning** — 32 bytes is overkill for a 5-min token; 16 would suffice. We use 32 for consistency with refresh tokens.
**Cost** — Negligible.

### 10.4 MFA challenge is consumed even on wrong code, but TOTP factor is not "locked"

**Decision** — `Consume` deletes the Redis key; the user has to re-`/login` to get a fresh `mfa_token` on wrong code.
**Assumption** — Forcing a re-login after wrong code rate-limits MFA guessing implicitly (the password verify in re-login takes ~100ms).
**Cost** — UX friction: a typo means restart. A friendlier flow would let the user retry 3 times with the same token.
**When this is wrong** — In an interactive admin UI where retry latency matters. v0.10.0 lockout could expose `attempts_remaining` so a UI can retry without restart.

### 10.5 MFA factor verification accepts ANY of the user's verified factors

**Decision** — `Verify` loops over all factors; first one to validate wins.
**Reasoning** — User might enroll TOTP + WebAuthn + a YubiKey, any of which should work.
**Cost** — None.

### 10.6 No MFA recovery codes today

**Decision** — Deferred to v0.10.0.
**Assumption** — Lost-authenticator is the #1 reason users get locked out of MFA-enabled accounts. We must solve this before mandating MFA for any customer.
**Cost** — Today, lost device = manual admin reset (DB row delete).
**When this is wrong** — Before any tenant with `require_mfa=true` goes live in prod.
**Revisit trigger** — First customer with `require_mfa=true`.

---

## 11. WebAuthn

### 11.1 Discoverable credentials only (passkey-first)

**Decision** — Registration uses `ResidentKeyRequired`; login uses `BeginDiscoverableLogin`.
**Assumption** — Modern authenticators (Touch ID, Windows Hello, Pixel, YubiKey 5+) all support resident keys. Non-resident credentials require asking for a username first; passkeys don't.
**Reasoning** — Cleaner UX (no username field), better security (no username enumeration via WebAuthn).
**Cost** — Excludes some older U2F-only YubiKeys.

### 11.2 User handle = `identity_id` for the first credential; reused thereafter

**Decision** — First credential's user-handle is the identity UUID; subsequent credentials inherit it.
**Assumption** — All credentials for one identity share one user handle (per W3C spec).
**Cost** — A credential created against an identity that's later deleted leaves an orphan user-handle. ON DELETE CASCADE on `webauthn_credentials` handles this.

### 11.3 sign-count strictly increasing per credential

**Decision** — `UpdateSignCount` on every successful login. We don't reject yet on non-monotonic sign-count, just store it. Should reject.
**Cost** — A cloned authenticator wouldn't be detected today. v0.10.0 security pass should add the comparison + alert.
**Revisit trigger** — v0.10.0 security pass.

### 11.4 No attestation verification

**Decision** — Accept all attestation formats; don't verify against MDS3.
**Assumption** — We're not in a regulated industry yet; enforcing "only Apple-attested keys" is a v0.15.0 FAPI concern.
**Cost** — A user can register a software credential we wouldn't trust in a high-stakes flow.

---

## 12. Per-tenant policy

### 12.1 Policy fetched on the hot path (login)

**Decision** — `policyEnforcer.Get` is called during login.
**Cost** — One extra DB read per login. After v0.8.0 caching, this can be cached too; we haven't yet because of write rarity.
**When this is wrong** — When login p99 exceeds budget. Then policy goes in the principal cache.

### 12.2 `DefaultPolicy()` returned on no row, not on nil

**Decision** — `Get` returns `(*Policy, error)`, never `(nil, nil)`.
**Reasoning** — Callers should never have to nil-check policy. Defensive programming for the most common path.
**Cost** — The defaults are duplicated in code (`DefaultPolicy()`) and in the migration's `DEFAULT` clause. They must stay in sync.

### 12.3 `max_active_sessions` is in the schema but unenforced

**Decision** — Column exists; no code reads it.
**Reasoning** — Enforcement requires a query on every login to count active sessions for the user. Add when there's a real ask.
**Cost** — Misleading schema; schema-as-documentation is wrong here.
**Revisit trigger** — First customer asks for "max 1 active session per user".

---

## 13. Observability

### 13.1 Bounded-cardinality Prometheus labels

**Decision** — Labels are `method`, `route` (chi template), `status`. Never `tenant_id`, `user_id`, `path` (raw URL).
**Reasoning** — Cardinality explosion is the #1 way to break Prometheus. A label that takes UUIDs creates millions of time series. We pre-template the URL via chi.
**Cost** — Per-tenant Prometheus dashboards are impossible from these metrics. Per-tenant insight has to come from logs or audit.
**When this is wrong** — If we want per-tenant rate dashboards. Then we need to push tenant-level aggregates through audit/NATS, not through Prometheus.

### 13.2 `slog.LogAttrs` over `slog.Info` with keyvals

**Decision** — Hot-path logs use the `LogAttrs(ctx, level, msg, slog.String(...), ...)` form.
**Reasoning** — Zero-allocation logging. The `slog.Info("x", "k", v)` form converts via reflection and allocates.
**Cost** — Verbose. Worth it on the auth path where we log per-request.

### 13.3 Audit-on-NATS rather than audit-on-DB-directly

**Decision** — Publisher fires to NATS, consumer in worker writes to DB.
**Reasoning** — Auth path doesn't take a DB write on every event. NATS publish is microseconds.
**Cost** — Audit lag (publisher → consumer → DB write). Acceptable since audit reads are eventual-consistency anyway.
**When this is wrong** — Compliance regime requiring "all auth events MUST be durably written before the request returns 200". Then synchronous DB write is correct.

---

## 14. Concurrency

### 14.1 `pgxpool` + Redis pool: rely on driver pooling

**Decision** — No custom connection management.
**Reasoning** — pgxpool is well-tuned. go-redis has internal pooling.
**Cost** — Sane defaults but no instrumentation per-pool yet. We should add pool-saturation metrics in v0.10.0.

### 14.2 Atomic counters and `sync.Pointer[T]` over mutexes for hot paths

**Decision** — `atomic.AddInt64` for metrics-like counters; `atomic.Pointer[phase]` in the spike test.
**Reasoning** — Mutexes are fine until they're a bottleneck. Atomic ops are cheaper for simple counter increments. The compiler intrinsics generate single LOCK INC instructions.
**Cost** — More error-prone than mutexes when you actually need critical-section semantics. We use mutexes for that.

### 14.3 No global rate limiter today

**Decision** — Per-route rate limits are v0.10.0 work.
**Cost** — A single attacker can hammer `/login` at full throughput. Documented in security tests.

---

## 15. Error model

### 15.1 Sentinel errors over typed error structs

**Decision** — `var ErrNotFound = errors.New("not found")` style.
**Alternatives** — `type NotFoundError struct { Resource string }` style.
**Reasoning** — Our error space is small (~10 sentinels). Comparison via `errors.Is` is enough. Typed errors with fields shine when callers want to inspect details; ours don't.
**Cost** — Caller has to wrap with `fmt.Errorf("...: %w", err)` to add context.
**When this is wrong** — If we wanted machine-readable errors over the API (e.g. `{"error": "not_found", "resource": "user", "id": "..."}`). Then typed errors carry the info.

### 15.2 Use cases return sentinels; handlers map to HTTP

**Decision** — `if err == sharederrors.ErrInvalidCredentials { writeError(w, "...", 401) }`.
**Reasoning** — Domain doesn't know HTTP. Handler does the mapping.
**Cost** — Boilerplate at every handler. We could centralize via an error-mapper middleware; haven't yet.

### 15.3 Panics are never expected

**Decision** — `MustPrincipal` was removed in v0.2.0. We use `(value, ok)` everywhere.
**Reasoning** — A panic in a request handler crashes the goroutine but not the server (Go's `http.Server` recovers). However, debugging from panics is worse than from explicit errors.
**Cost** — More verbose call sites.

---

## 16. Testing strategy

### 16.1 Ten test layers — overkill or just right?

**Decision** — Unit, fuzz, race, smoke, integration, security, stress+SLA, soak, spike, A/B.
**Assumption** — Auth is high-trust; each layer catches different bugs. The fuzz layer caught a real one. The security layer caught two documented gaps. The A/B layer informed the Principal cache decision.
**Cost** — Slow CI on full runs (~10 min). Mitigated by `run-all.sh` doing the full suite while individual layers run fast.
**When this is wrong** — In a small team where test maintenance starves feature work. We're a small team; the suite has been worth it.

### 16.2 Custom stress/soak/spike binaries over `wrk` / `hey` / `vegeta`

**Decision** — Roll our own.
**Reasoning** — Off-the-shelf tools can't do multi-step flows (PKCE handshake, MFA challenge). They can't do A/B with Welch t-test. They don't have SLA-budget flags that exit non-zero.
**Cost** — ~1500 LoC of test tooling we maintain.
**When this is wrong** — If a tool grows that does exactly what we need (e.g. k6 with custom JS). The maintenance shift would be worth it.

### 16.3 Welch t-test for A/B significance

**Decision** — Two-sample Welch t-test (unequal variances).
**Reasoning** — We can't assume equal variance between the two auth paths (DB-backed has much higher variance under contention). Welch is the right test.
**Cost** — Most users won't read the t value. We output a plain-English significance level.

### 16.4 Integration tests against a live server (not testcontainers per test)

**Decision** — `AUTH_BASE_URL` env points at a running server; tests do real HTTP.
**Alternatives** — Spin up testcontainers per test, in-memory Postgres + Redis fakes, `httptest.Server`.
**Reasoning** — A real server catches real bugs (middleware order, routing, CORS). Per-test isolation is achieved by unique emails / unique tenants per test.
**Cost** — Tests can't run without a server. We document this; CI provisions one.
**When this is wrong** — When parallelism wants more isolation than per-tenant scoping gives.

### 16.5 Fuzz running for 5s in CI

**Decision** — Smoke run only; deep runs are nightly/manual.
**Reasoning** — 5s is enough to catch obvious regressions. Deep fuzzing is for finding new bugs.
**Cost** — A regression that takes 30+ seconds to discover would slip through CI.

### 16.6 Coverage stuck at 7.7% because of HTTP-level integration tests

**Decision** — We document this rather than rig it.
**Reasoning** — Runtime coverage of an HTTP-tested binary requires graceful SIGTERM flushing of cover counters, which our server doesn't yet implement.
**Cost** — Coverage as a metric is misleading. We have actually-good coverage of the hot paths through integration tests, but it doesn't show.
**Revisit trigger** — Adding graceful shutdown is on the v0.10.0 list for the constant-time-login refactor anyway.

---

## 17. Operational design

### 17.1 Two binaries: `iam-server` and `worker`

**Decision** — HTTP API + background jobs are different processes.
**Reasoning** — Background jobs (audit consume, session cleanup, future key rotation) should NOT consume HTTP-serving capacity. Separate process means separate scale, separate restart, separate metrics.
**Cost** — Two deployment units to operate.

### 17.2 Worker is single-instance (no leader election)

**Decision** — Tickers in the worker run unconditionally; we assume one worker.
**Cost** — Running two workers does each job twice. NATS audit consume is idempotent per event (we'd insert duplicates without an idempotency key); session cleanup is idempotent (DELETE WHERE).
**When this is wrong** — As soon as we want HA workers. v0.10.0 should add leader election (Postgres advisory lock is the simplest).

### 17.3 `cmd/migrate` is empty

**Decision** — In dev we shell out to `psql`.
**Cost** — Production deploys don't have a story. **Pre-prod blocker.**
**Revisit trigger** — First prod deploy plan.

### 17.4 Key rotation is manual today

**Decision** — `cmd/key-rotator` is a one-shot binary.
**Cost** — Ops has to remember. Documented in v0.7.0 changelog.
**Revisit trigger** — v0.10.0 plan.

### 17.5 Session retention = 30 days (in `cmd/worker`)

**Decision** — Hardcoded constant `sessionRetention = 30 * 24 * time.Hour`.
**Assumption** — 30 days covers most analytics needs; beyond that the data is rarely queried.
**Cost** — Hardcoded; should be `SESSION_RETENTION_DAYS` env.

### 17.6 No graceful shutdown on `iam-server`

**Decision** — `server.Start()` blocks forever; signal kills hard.
**Cost** — In-flight requests can be cut. Cover counters can't flush. v0.10.0 must add a signal handler that calls `http.Server.Shutdown(ctx)` with a grace period.

---

## 18. Things we explicitly didn't build

| Not built | Why not | When |
|---|---|---|
| Admin UI | Out of scope for an auth server | Outside this repo, ever |
| Email sending | No notification component yet; defer until v0.11.0 (password reset, account lockout email) | v0.11.0 |
| Account linking | Defer until federation; first link will surface the design need | v0.12.0 |
| Federation | Big enough to be its own phase | v0.12.0 |
| SCIM | Enterprise customer demand needed first | v0.13.0 |
| Risk scoring | Defer until federation surfaces fresh attack vectors | v0.14.0 |
| FAPI / DPoP | Defer until first regulated industry customer | v0.15.0 |
| OpenTelemetry tracing | We have `slog` correlation IDs only via request ID, no spans | v0.10.0 |
| Encrypted secrets at rest | Big operational lift (KMS / Vault) | v0.10.0 |
| Read-replica use | `Pools` struct exists; nothing reads from `Reader` yet | When we have a real replica |

---

## 19. Where we likely got it wrong

This section is the honest list. Decisions that, if I had to rewrite, I'd revisit.

### 19.1 `X-Session-ID` header

A custom header for auth in 2026 is non-standard and confusing. Should have been `Authorization: Session ...` or scrapped entirely in favor of JWT-only. v0.10.0 should probably deprecate it.

### 19.2 `ip_address` as `text` on `sessions`

Should have invested 30 minutes to fix the pgx INET issue in v0.1.0. Now we have two formats for the same data. Future migration.

### 19.3 Hardcoded constants for TTLs

`accessTokenTTL`, `refreshTokenTTL`, `sessionRetention`, etc. are constants. Should be config. Easy to fix.

### 19.4 No graceful shutdown

Should have been v0.1.0. Now it's a blocker for coverage measurement, in-flight request safety, and key-flush.

### 19.5 No HTTP-only refresh cookie `Secure=true` in dev

`Secure: false` in dev was a shortcut. Should be configurable via env so tests can run on HTTP but prod is HTTPS-only.

### 19.6 No idempotency for audit consumer

If the worker restarts mid-message, we could insert the same event twice. We should add a `nats_msg_id` UUID column and `ON CONFLICT DO NOTHING`.

### 19.7 Authorization perm strings are stringly-typed

`withPerm("users:read")` is a string. A constant per permission would catch typos at compile time. Defer until permission count exceeds ~30.

### 19.8 Tenant policy `max_active_sessions` exists but isn't enforced

Schema says we do; code says we don't. Either remove the column or implement.

### 19.9 No real connection-pool metrics

We instrument the HTTP layer but not pgxpool / Redis pool saturation. Will bite us under unexpected load.

### 19.10 No request ID propagation

`slog` doesn't yet carry a request ID across the request. We can correlate by `session_id` for authenticated requests, not unauthenticated ones.

### 19.11 OAuth `Token` use case is a god method

`internal/oauth/app/token.go` has both `authorization_code` and `refresh_token` grants in one type with many dependencies. Should be split into two use cases with a shared dependency struct.

### 19.12 No back-pressure on the audit publisher

Under NATS slowness, `Publish` queues internally. Under sustained load this is a memory leak waiting to happen. Should have a bounded queue + drop-on-full.

---

## 20. Decision-review cadence

The decisions in this document are not eternal. They reflect what was known at a point in time. The following should be reviewed on a schedule:

| Review | Cadence | Trigger |
|---|---|---|
| Crypto parameters (Argon2 m/t/p, signing alg defaults) | Every 2 years | OWASP guidance update |
| TTLs (access, refresh, cache, code) | Every release that touches auth | Latency SLO miss or token-revocation incident |
| Cardinality of Prometheus labels | Quarterly | Prometheus scrape time exceeds budget |
| External dependencies (pgx, chi, slog ecosystem, JWT) | Quarterly | CVE notice or maintainer change |
| Custom test binaries vs adopting a tool | Annually | Maintenance time exceeds 1 PR-day per quarter |
| Operational decisions (single worker, manual key rotation) | Each phase release | Incident retrospective |
| Tradeoffs document (this file) | Each release | Anything that changes a "When this is wrong" line |

---

## 21. How to use this document

- **Reviewing a PR**: scan the relevant section. If the PR changes a decision, the author should update both the code and this document.
- **Onboarding a new engineer**: read this first; it's the "why" that the code can't tell you.
- **Architecture interview / RFC**: cite this when proposing a change so the change-author has to engage with the reasoning, not just override it.
- **Incident postmortem**: search for the failing component; the "When this is wrong" line is often the postmortem in retrospect.
- **Pre-prod readiness review**: the **Revisit trigger** rows tagged with "pre-prod" are blockers. Specifically: 17.3 (migrate cmd), 17.6 (graceful shutdown), 5.3 (CORS allowlist), 10.2 (TOTP secret encryption), 19.4 (graceful shutdown again), 19.5 (Secure cookie).

This document is the running record of why the codebase looks the way it looks. Keep it honest. Add a "revisit trigger" to every new non-trivial decision. Mark "When this is wrong" lines explicitly — they prove you considered the failure case at decision time.
