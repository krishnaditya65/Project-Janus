# Project Janus (`custom-auth-server`) — Complete, Exhaustive Codebase Reference

> Module path: `github.com/krishnaditya65/Project-Janus` (import path in code: `github.com/krishnaditya65/auth-server`)
> Root: `/Users/krishnaditya/Documents/ideas/projects/custom-auth-server/`
> Go module root: `auth-server/` (own git repo, `go 1.26.3`, single module across all six `cmd/` binaries)
> This document is a from-first-principles, function-by-function reference to every file, folder, execution flow, and architectural decision in the codebase, cross-checked against the hand-written design docs (`DESIGN.md`, `IMPLEMENTATION.md`, `TRADEOFFS.md`, `THREAT_MODEL.md`, `BENCHMARKS.md`) at the project root, plus `changelogs/` and `testdocs/`.
>
> **⚠ Post-split update note (this revision):** the codebase has since been split into **three deployable services** — `cmd/iam-server` (auth gateway: auth/oauth/oidc/session/authorization + the audit/platform/tenant/token shared libraries), `cmd/identity-service` (owns `internal/identity`'s Postgres access, reached over HTTP via `internal/identity/infra/httpclient`), and `cmd/mfa-service` (owns `internal/mfa` + `internal/webauthn`, reached over HTTP via `internal/mfa/infra/httpclient`) — plus a **transaction-integrity fix** in `RegisterUseCase`/`CreateUserUseCase`: `identityRepo.Create` now happens *outside* the local Postgres transaction (it's a network call to identity-service), with an explicit compensating `identityRepo.Delete` if the local transaction subsequently fails. Sections §0–§28 below are the original single-binary-era reference, updated in place wherever the split changed behavior; §29–§30 are new sections covering the service split, network topology, and deployment specifically. Every place this revision touched carries a note; unmarked prose still describes correctly-unchanged behavior (e.g. the crypto/OAuth/RBAC internals, which the split did not touch).

---

## Table of Contents

0. [How to read this document](#0-how-to-read-this-document)
1. [Top-level project layout](#1-top-level-project-layout)
2. [Architectural pattern](#2-architectural-pattern)
3. [`cmd/` — the four binaries](#3-cmd--the-four-binaries)
4. [`internal/platform/` — infrastructure layer](#4-internalplatform--infrastructure-layer)
5. [`internal/shared/` — cross-cutting utilities](#5-internalshared--cross-cutting-utilities)
6. [Database schema — all migrations](#6-database-schema--all-migrations)
7. [`internal/auth/` — login, registration, refresh, logout](#7-internalauth--login-registration-refresh-logout)
8. [`internal/session/` — session domain & persistence](#8-internalsession--session-domain--persistence)
9. [`internal/token/` — JWT issuance, verification, signing keys, JWKS](#9-internaltoken--jwt-issuance-verification-signing-keys-jwks)
10. [`internal/oauth/` — OAuth2 authorization code + PKCE](#10-internaloauth--oauth2-authorization-code--pkce)
11. [`internal/oidc/` — OpenID Connect layer](#11-internaloidc--openid-connect-layer)
12. [`internal/mfa/` — TOTP multi-factor authentication](#12-internalmfa--totp-multi-factor-authentication)
13. [`internal/webauthn/` — WebAuthn / FIDO2 / passkeys](#13-internalwebauthn--webauthn--fido2--passkeys)
14. [`internal/authorization/` — RBAC](#14-internalauthorization--rbac)
15. [`internal/tenant/` — multi-tenancy & policy](#15-internaltenant--multi-tenancy--policy)
16. [`internal/identity/` — identity & user management](#16-internalidentity--identity--user-management)
17. [`internal/provisioning/` and `internal/serviceaccount/` — unimplemented](#17-internalprovisioning-and-internalserviceaccount--unimplemented)
18. [`internal/federation/`, `pam/`, `risk/`, `notification/`, `admin/` — unimplemented](#18-internalfederation-pam-risk-notification-admin--unimplemented)
19. [`internal/audit/` — async audit logging](#19-internalaudit--async-audit-logging)
20. [Complete HTTP route table](#20-complete-http-route-table)
21. [End-to-end execution flow traces](#21-end-to-end-execution-flow-traces)
22. [`test/` — the ten-layer test pyramid](#22-test--the-ten-layer-test-pyramid)
23. [`web/`, `coverage/`, `configs/`, `deployments/`, `api/`, `scripts/`, `tools/`, `docs/` — empty scaffolding](#23-web-coverage-configs-deployments-api-scripts-tools-docs--empty-scaffolding)
24. [Root documentation summaries](#24-root-documentation-summaries)
25. [`changelogs/` — version-by-version build history](#25-changelogs--version-by-version-build-history)
26. [`testdocs/` — manual/point-in-time test snapshots](#26-testdocs--manual-point-in-time-test-snapshots)
27. [Catalog of known gaps, dead code, and security findings](#27-catalog-of-known-gaps-dead-code-and-security-findings)
28. [Quick-reference tables](#28-quick-reference-tables)
29. [The 3-service split: network topology, service boundaries, error mapping](#29-the-3-service-split-network-topology-service-boundaries-error-mapping)
30. [Deployment: Dockerfile, docker-compose, environment variables](#30-deployment-dockerfile-docker-compose-environment-variables)

---

## 0. How to read this document

This codebase is a **multi-tenant Identity & Access Management (IAM) server** ("Project Janus") written from scratch in Go, currently at version **v0.9.0** ("multi-tenancy & policies") **plus an unversioned in-progress service-split refactor** (see §29–§30). It is explicitly *not* a toy — it ships its own Argon2id password hashing, its own JWT service with key rotation, its own OAuth2 Authorization Code + PKCE implementation, its own OIDC layer, TOTP MFA, WebAuthn/passkeys, RBAC, per-tenant policy, async audit logging, and an 11-layer test pyramid (unit/fuzz/race/smoke/integration/security/stress/soak/spike/A-B/coverage).

**As of this revision, the single `cmd/iam-server` binary described throughout most of this document has been split into three independently deployable services** sharing one Postgres database and one Redis instance (a network-API boundary split, not a data-ownership split):

| Service | Owns | Listens on (env) | Reaches |
|---|---|---|---|
| `cmd/iam-server` | auth, oauth, oidc, session, authorization, tenant, token, audit (all still linked in-process as shared libraries) | `HTTP_PORT` (default 8080) | identity-service (HTTP), mfa-service (HTTP), Postgres, Redis, NATS |
| `cmd/identity-service` | `internal/identity`'s Postgres access (the `identities` table only — `users` stays with iam-server via `internal/identity/infra/postgresuser`) | `IDENTITY_HTTP_PORT` (default 8081) | Postgres only |
| `cmd/mfa-service` | `internal/mfa` (TOTP factors, MFA challenges) + `internal/webauthn` (passkey credentials) | `MFA_HTTP_PORT` (default 8082) | identity-service (HTTP), Postgres, Redis |

Most of §§1–28 below still applies to the *business logic* unchanged — RBAC, OAuth/PKCE, TOTP math, WebAuthn ceremonies, crypto parameters, etc. are untouched by the split. What changed is **who owns the Postgres connection for identities and MFA/WebAuthn data**, and **how `cmd/iam-server` reaches that data** (HTTP client adapters instead of direct repositories), plus a **new compensating-delete saga** in the two use cases that create an `Identity` and then do more work in a local transaction. Every section below that the split touches is marked; see §29 for the consolidated topology view and §30 for deployment.

At the same time, **several directories that look like they should contain major subsystems are empty scaffolding**: `internal/provisioning/`, `internal/serviceaccount/`, `internal/federation/`, `internal/pam/`, `internal/risk/`, `internal/notification/`, `internal/admin/` all exist as folder trees with zero Go files. This document reports that honestly rather than inventing content for them — see §17, §18.

The five root markdown documents (`DESIGN.md`, `IMPLEMENTATION.md`, `TRADEOFFS.md`, `THREAT_MODEL.md`, `BENCHMARKS.md`) are a genuinely exceptional internal engineering diary — they are summarized in full in §24, and this reference cross-checks the actual code against their claims wherever possible.

---

## 1. Top-level project layout

```
custom-auth-server/                       (not itself a git repo)
├── .claude/                              Claude Code project settings
├── .gitignore
├── DESIGN.md                             ~18KB — architecture overview + roadmap
├── IMPLEMENTATION.md                     ~28KB — Go idioms, wiring, code tour
├── TRADEOFFS.md                          ~58KB — 20-section staff-engineer tradeoff audit
├── THREAT_MODEL.md                       ~39KB — STRIDE-style, 28 numbered threats
├── BENCHMARKS.md                         ~13KB — measured perf numbers, SLOs
├── changelogs/                           9 files, v0.1.0 → v0.9.0, chronological build log
├── testdocs/                             3 files, point-in-time manual/strategy test snapshots
└── auth-server/                          THE GO MODULE (its own git repo)
    ├── go.mod / go.sum                   module github.com/krishnaditya65/Project-Janus, go 1.26.3
    ├── .gitignore
    ├── cmd/                              6 binaries: iam-server, identity-service, mfa-service, key-rotator, migrate, worker (§29)
    ├── internal/                         ~20 domain modules + platform + shared (see below)
    ├── migrations/                       6 golang-migrate up/down SQL pairs (000001–000006)
    ├── test/                             10-layer test pyramid (unit tests live inside internal/) — ⚠ NOT updated for the 3-service split, see §22/§29.5
    ├── configs/                          EMPTY
    ├── deployments/                      EMPTY (docker-compose.yml/Dockerfile live at auth-server/ root instead, see §30)
    ├── api/openapi/, api/proto/          EMPTY
    ├── scripts/, tools/                  EMPTY
    ├── docs/ (inside auth-server)        EMPTY
    ├── web/admin/, web/login/            EMPTY
    ├── coverage/                         historical coverage/log artifacts from a May-31 test run
    ├── Dockerfile                        generic multi-stage build, parameterized by --build-arg SERVICE=<cmd dir> (§30)
    └── docker-compose.yml                postgres+redis+nats+identity-service+mfa-service (iam-server not containerized) (§30)
```

**Module dependency direction** (informal, not enforced by Go tooling but consistent throughout): `cmd/* → internal/{domain modules} → internal/platform → internal/shared`. Each domain module (`auth`, `session`, `token`, `oauth`, `oidc`, `mfa`, `webauthn`, `authorization`, `tenant`, `identity`, `audit`) follows the same internal four/five-folder shape:

```
internal/<domain>/
├── domain/      pure Go structs + repository INTERFACES — zero framework/DB imports
├── app/         use cases (application/service layer) — depend on domain interfaces only
├── infra/       concrete adapters (postgres/redis) implementing domain interfaces
├── transport/   HTTP handlers (package http) — depend on app use cases
└── middleware/  (only in auth, authorization, tenant) — chi middleware reading context
```
This is textbook **hexagonal / ports-and-adapters / clean architecture**, applied per-domain rather than per-technical-layer (i.e., there's no repo-wide `handlers/`, `services/`, `models/` folder — instead each business domain owns its own vertical slice through all layers). All wiring happens by hand in `cmd/iam-server/main.go` — there is no DI framework, no reflection-based container.

---

## 2. Architectural pattern

Key structural facts, true across almost every domain module:

1. **Repository interfaces live in `domain/`, implementations live in `infra/`.** Application code (`app/`) only ever imports the `domain` package, never `infra` directly — dependency inversion, allowing in-memory fakes in unit tests (e.g. `memKeyRepo`, `memFactorRepo`), **and, since the service split (§29), allowing an HTTP client to satisfy the exact same interface a Postgres repository would** (`internal/identity/infra/httpclient.Repository` implements `identitydomain.Repository`; `internal/mfa/infra/httpclient.Repository`/`ChallengeStoreClient` implement `mfadomain.Repository`/a `LoginUseCase`-local `MFAChallengeStore` interface). This is the single architectural property that made the split possible without touching any `app/`-layer code beyond swapping which concrete type gets passed into a constructor in `main.go`.
2. **The "Executor trick"**: nearly every Postgres repository defines
   ```go
   func (r *Repository) executor(ctx context.Context) pgtx.Executor {
       if tx, ok := pgtx.FromContext(ctx); ok { return tx }
       return r.db
   }
   ```
   where `pgtx.Executor` is a 3-method interface (`Exec`, `QueryRow`, `Query`) satisfied structurally by both `*pgxpool.Pool` and `pgx.Tx`. This lets any repository transparently participate in an ambient transaction (started by `tx.Manager.WithinTransaction`, itself defined in `internal/platform/postgres/tx`) or fall back to the raw pool — without repositories needing to know whether they're inside a transaction.
3. **Typed, unexported context keys** everywhere a value is threaded through `context.Context` (`principal`, `tenant_id`, the ambient transaction) — avoids string-key collisions across packages.
4. **Sentinel errors** (`internal/shared/errors`: `ErrNotFound`, `ErrUnauthorized`, `ErrForbidden`, `ErrConflict`, `ErrInvalidCredentials`, `ErrTenantMismatch`) form the entire cross-layer error vocabulary; transport handlers map them to HTTP status codes via `errors.Is`, not centrally but per-handler.
5. **Hand-wired DI**: `cmd/iam-server/main.go` is one large, linear, ~300+ line function that constructs every repository, service, use case, and handler in dependency order and registers routes. No `init()` functions, no reflection.
6. **No panics in request-handling code** (an early v0.1.0 issue — `MustPrincipal()` used to panic on a missing context value; fixed in v0.2.0 to a `(value, bool)` pattern in the HTTP path). The context-package `MustPrincipal` still exists and still panics, but it's used only in code paths that are structurally guaranteed to run after auth middleware (documented as a "should never happen" invariant, not a normal error path).
7. **Multi-tenancy is application-level, not database-level.** There is no Postgres Row-Level Security; every tenant-scoped query takes `tenant_id` as an explicit `WHERE` parameter, and it's always sourced from the authenticated `Principal.TenantID`, never from client-supplied input. `THREAT_MODEL.md` explicitly flags this as an unmitigated risk (#17, "Tenant escape") with RLS deferred to a future v0.15.0 hardening pass.

---

## 3. `cmd/` — the six binaries

> **⚠ Post-split**: this section previously described 4 binaries. There are now **six**: `iam-server`, `identity-service`, `mfa-service`, `key-rotator`, `migrate`, `worker`. `iam-server` is no longer "the only binary that wires up the full HTTP surface" — MFA and WebAuthn's entire HTTP surface moved to `mfa-service`, and identity's Postgres access moved to `identity-service`. See §29 for the full topology diagram and §30 for how these are deployed.

### 3.1 `cmd/iam-server/main.go` — the auth-gateway API server

Still the primary user-facing binary (auth, session, OAuth2, OIDC, RBAC, tenant policy, JWKS), but **identity and MFA are now reached over HTTP instead of owned directly**. Startup sequence:

1. Configures a global `slog` JSON logger to stdout at Info level.
2. `cfg := config.Load()` (loads `.env` via `godotenv`, falls back to real env vars, applies defaults — see §29.3/§30.3 for the full env-var table, now including `IDENTITY_SERVICE_URL`/`MFA_SERVICE_URL`).
3. Connects Postgres (`platformpostgres.New(cfg.DatabaseURL)`), Redis (`redis.New(cfg.RedisAddr)`), NATS (`nats.New(cfg.NATSURL)`) — any connection failure exits(1); all three are `defer`-closed. **No graceful shutdown** is implemented — the process just blocks on `ListenAndServe` until killed (flagged repeatedly in `TRADEOFFS.md` as a pre-production blocker; still true post-split).
4. Builds a `pgtx.NewManager(db)` transaction manager.
5. **Identity repository is now an HTTP client, not Postgres:**
   ```go
   identityRepo := identityhttpclient.NewRepository(cfg.IdentityServiceURL)
   ```
   A code comment in `main.go` states: *"identityRepo now talks to identity-service over HTTP instead of Postgres directly ... This is the only line that changed for this binary's identity dependency; everything downstream still just depends on identitydomain.Repository."* — see §29.1 for the client's error mapping.
6. **MFA repository and challenge store are also now HTTP clients:**
   ```go
   mfaRepo := mfahttpclient.NewRepository(cfg.MFAServiceURL)
   mfaChallengeStore := mfahttpclient.NewChallengeStoreClient(cfg.MFAServiceURL)
   ```
   These are injected only into `LoginUseCase` (§7.4) — iam-server registers **no** `/mfa/*` or `/webauthn/*` HTTP routes at all anymore (neither served locally nor reverse-proxied; there is no `httputil.ReverseProxy` anywhere in the repo). A caller needing MFA enrollment/completion or WebAuthn ceremonies must call `mfa-service` directly on its own port.
7. Repositories still built directly against Postgres in this binary: `authpostgres.NewRepository` (credential), `tenantpostgres.NewRepository` (tenant), `postgresuser.NewRepository` (the `users` tenant-membership table — **distinct from and not moved to identity-service**, since it's a tenant-scoped projection iam-server still owns), `sessionpostgres.NewRepository`, the four `authorizationpostgres` repos (permission/role/role_permission/user_role), `tokenpostgres.NewRepository` (signing_key), `oauthpostgres.NewClientRepository`, `tenantpostgres.NewPolicyRepository`; Redis-backed `oauthredis.NewCodeStore(cache)`.
8. Builds services: `tokenapp.NewJWTService`, `tenantapp.NewPolicyEnforcer`, `authmiddleware.NewPrincipalCache` (Redis-backed), `auditapp.NewPublisher(msgBus)` (**still constructed but discarded** — `_ = auditPublisher`, unchanged by the split, see §19), `tenantapp.NewSlugService`, authorization bootstrap + permission-bootstrap services. **`mfaapp.NewTOTPService` is no longer built here** — TOTP logic now lives only inside `mfa-service`.
9. Constructs use cases: register / login / refresh / logout (auth); identity get/list/create-user (still wired here, since `identityapp.CreateUserUseCase` mixes the HTTP-client identity repo with local-Postgres user/role repos — see §16.4/§29.2); role create/list/assign-permission/list-role-permissions; OAuth authorize/token use cases; OIDC ID-token service. **No WebAuthn service or MFA `CompleteUseCase` is constructed here anymore** — both moved into `mfa-service`.
10. Builds HTTP handlers: auth, identity, authorization, tenant policy, JWKS, OIDC discovery/userinfo, OAuth; and `authmiddleware.NewAuthenticationMiddleware(sessionRepo, identityRepo, userRoleRepo, rolePermissionRepo, jwtService, principalCache)` — note `identityRepo` here is the HTTP client, so the session-header auth path (§7.9) now makes a network call to identity-service on every cache-miss.
11. `httpserver.New(cfg.HTTPPort)` → gets its `chi.Mux`, registers global middleware in this exact order: `httpserver.CORS` → `httpserver.RequestLogger` → `metrics.Middleware` (extracts the *matched chi route pattern*, not the raw path, for bounded-cardinality Prometheus labels).
12. Registers **public** routes: `/health`, `/register`, `/login`, `/refresh`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/metrics`, `/oauth/token`. **`/mfa/complete`, `/webauthn/login/begin`, `/webauthn/login/complete` are gone from this list** — they moved to `mfa-service` (§3.3).
13. Registers **authenticated** routes (`withAuth = authMiddleware.Authenticate`) and **permission-gated** routes (`withPerm(p) = authorizationmiddleware.RequirePermission(p)`, always chained *after* `withAuth`): `/me`, `/logout`, `/oauth/authorize`, `/oauth/userinfo`, `/tenant/policy` (GET any authed user; PUT requires `tenant:update`), `/users` (GET requires `users:read`, POST requires `users:create`), `/roles` (POST `roles:create`, GET `roles:read`), `/roles/{roleID}/permissions` (POST `roles:update`, GET `roles:read`). **MFA enrollment (`/mfa/enroll/*`, `/mfa/factors`) and WebAuthn registration (`/webauthn/register/*`, `/webauthn/credentials`) routes are gone from this list** — moved to `mfa-service`. See §20 (updated) / §29.4 for the complete 3-service route table.
14. `server.Start()` — blocking `http.ListenAndServe`, no `ReadTimeout`/`WriteTimeout`/`IdleTimeout` configured (unchanged pre-existing gap).

### 3.2 `cmd/identity-service/main.go` — new: identity's own Postgres-backed HTTP service

**New binary, entirely added by the service split.** Its own header comment: *"the only binary that talks to Postgres for identitydomain.Repository (Create/GetByEmail/GetByID on Identity) directly ... Note: the database itself stays shared across iam-server and identity-service ... this split is a network-API boundary, not a data-ownership split."*

Startup: `cfg := config.Load()`; `db := platformpostgres.New(cfg.DatabaseURL)` (**no Redis, no NATS connection at all**); `identityRepo := identitypostgres.NewRepository(db)` (the real Postgres adapter, §16.6, now with a `Delete` method — §29.2); builds use cases `identityapp.NewGetIdentityByEmailUseCase`, `NewGetIdentityByIDUseCase`, `NewPersistIdentityUseCase`, `NewDeleteIdentityUseCase` (all thin wrappers around the one repo); `identityhttp.NewIdentityHandler(getByEmailUseCase, getByIDUseCase, persistUseCase, deleteUseCase)` (a **new** handler package, `internal/identity/transport/http/identity_handler.go`, distinct from the existing `identity/transport/http` handlers used by iam-server's `/users` routes).

`httpserver.New(cfg.IdentityHTTPPort)`; middleware `httpserver.RequestLogger` + `metrics.Middleware(...)` (**no CORS** — this is an internal service-to-service API, not meant to be called from a browser).

**Route table** (all under `/internal/identities`, no authentication — trust boundary is "only reachable by other services on the private network", not enforced in code):

| Method | Path | Handler |
|---|---|---|
| GET | `/health` | inline liveness |
| * (mounted) | `/metrics` | `metrics.Handler()` |
| GET | `/internal/identities/by-email?email=` | `identityHandler.GetIdentityByEmail` — any error → 404 |
| GET | `/internal/identities/{id}` | `identityHandler.GetIdentityByID` — any error → 404 |
| POST | `/internal/identities` | `identityHandler.CreateIdentity` — full `Identity` JSON body (caller pre-generates ID/status/timestamps); `ErrConflict`→409 "email already exists", else 500; success→201 |
| DELETE | `/internal/identities/{id}` | `identityHandler.DeleteIdentity` — any error→500, success→204. Doc comment: *"backs the compensating-delete path used by callers that persisted an Identity here but then failed a subsequent step in their own local transaction."* |

Listens on `IDENTITY_HTTP_PORT` (default `8081`); reached by `iam-server` and `mfa-service` via `IDENTITY_SERVICE_URL` (default `http://localhost:8081`).

### 3.3 `cmd/mfa-service/main.go` — new: MFA + WebAuthn's own HTTP service

**New binary.** Header comment: *"standalone binary that owns internal/mfa (TOTP factors, MFA challenges) and internal/webauthn (WebAuthn/passkey credentials), split out of cmd/iam-server the same way cmd/identity-service split identity out earlier."*

Startup: connects to the **shared** Postgres (`cfg.DatabaseURL`) and **shared** Redis (`cfg.RedisAddr`) directly (no NATS); builds `identityRepo := identityhttpclient.NewRepository(cfg.IdentityServiceURL)` — mfa-service itself reaches identity-service over HTTP too (needed for email lookups during TOTP enrollment/QR generation and WebAuthn user resolution), the exact same client type iam-server uses. Also builds `sessionpostgres.NewRepository`, `postgresuser.NewRepository`, the two `authorizationpostgres` read repos (user_role/role_permission — needed to build a full `Principal` after MFA/WebAuthn completion), `tokenpostgres.NewRepository` + `tokenapp.NewJWTService` (mfa-service **issues its own JWTs** directly on MFA-complete/WebAuthn-login, using the same signing-key table iam-server uses), `authmiddleware.NewPrincipalCache(cache)`.

MFA wiring (unchanged internals, just relocated from iam-server into this binary): `mfapostgres.NewRepository(db)`, `mfaapp.NewChallengeStore(cache)`, `mfaapp.NewTOTPService(mfaRepo, cfg.JWTIssuer)`, `mfaapp.NewCompleteUseCase(mfaChallengeStore, totpService, sessionRepo, identityRepo, userRoleRepo, rolePermissionRepo, jwtService)`, `mfahttp.NewHandler(totpService, mfaCompleteUseCase)` (public-facing) **plus a new `mfahttp.NewInternalHandler(mfaRepo, mfaChallengeStore)`** that backs `internal/mfa/infra/httpclient` — the HTTP-facing counterpart of the client iam-server's `LoginUseCase` calls into (§29.1).

WebAuthn wiring (also just relocated, no logic change): `wapostgres.NewRepository(db)`, `waapp.NewSessionStore(cache)`, `waapp.NewService(cfg.WebAuthnName, cfg.WebAuthnRPID, []string{cfg.WebAuthnOrigin}, waCredRepo, identityRepo, waSessionStore)`, `waapp.NewLoginUseCase(waService, sessionRepo, identityRepo, userRepo, userRoleRepo, rolePermissionRepo, jwtService)`, `wahttp.NewHandler(waService, waLoginUseCase)`. **There is no `internal/webauthn/infra/httpclient` package** — WebAuthn never needed a client adapter because no code in iam-server calls into it anymore at all (unlike MFA, which iam-server's `LoginUseCase` still needs for the "does this identity have MFA enrolled" decision at login time); see §29.1 for why the two subsystems' split shape differs.

Rebuilds its own `authmiddleware.NewAuthenticationMiddleware(sessionRepo, identityRepo, userRoleRepo, rolePermissionRepo, jwtService, principalCache)` for its principal-authenticated routes (identical construction to iam-server's, since both need to authenticate a Bearer/session-header request the same way).

`httpserver.New(cfg.MFAHTTPPort)`; middleware `httpserver.RequestLogger` + `metrics.Middleware(...)` (no CORS — same internal-service posture as identity-service, except the MFA-complete/WebAuthn-login/register/list routes below ARE meant to be called by end-user browsers/apps directly, not just other services).

**Route table:**

| Method | Path | Auth | Handler |
|---|---|---|---|
| GET | `/health` | public | inline liveness |
| * (mounted) | `/metrics` | public | `metrics.Handler()` |
| POST | `/mfa/complete` | public | `mfaHandler.Complete` |
| POST | `/webauthn/login/begin` | public | `waHandler.LoginBegin` |
| POST | `/webauthn/login/complete` | public | `waHandler.LoginComplete` |
| POST | `/internal/mfa/factors` | internal, no auth mw | `mfaInternalHandler.CreateFactor` |
| GET | `/internal/mfa/factors/by-identity?identity_id=` | internal | `mfaInternalHandler.GetFactorsByIdentity` |
| GET | `/internal/mfa/factors/verified?identity_id=` | internal | `mfaInternalHandler.GetVerifiedFactorsByIdentity` |
| GET | `/internal/mfa/factors/{id}` | internal | `mfaInternalHandler.GetFactorByID` |
| POST | `/internal/mfa/factors/{id}/verify` | internal | `mfaInternalHandler.MarkFactorVerified` |
| DELETE | `/internal/mfa/factors/{id}` | internal | `mfaInternalHandler.DeleteFactor` |
| POST | `/internal/mfa/challenges` | internal | `mfaInternalHandler.StoreChallenge` |
| POST | `/internal/mfa/challenges/consume` | internal | `mfaInternalHandler.ConsumeChallenge` (maps `ErrNotFound`→404, the server side of the client's mapping — §29.1) |
| POST | `/mfa/enroll/totp` | withAuth | `mfaHandler.EnrollTOTP` |
| POST | `/mfa/enroll/verify` | withAuth | `mfaHandler.VerifyEnrollment` |
| GET | `/mfa/factors` | withAuth | `mfaHandler.List` |
| POST | `/webauthn/register/begin` | withAuth | `waHandler.RegisterBegin` |
| POST | `/webauthn/register/complete` | withAuth | `waHandler.RegisterComplete` |
| GET | `/webauthn/credentials` | withAuth | `waHandler.List` |

Listens on `MFA_HTTP_PORT` (default `8082`); reached by `iam-server` via `MFA_SERVICE_URL` (default `http://localhost:8082`) for `LoginUseCase`'s MFA-required check only — all other MFA/WebAuthn endpoints must be called on this service's own port directly.

### 3.4 `cmd/key-rotator/main.go` — one-shot JWT signing-key rotation CLI

**Unaffected by the service split** — still connects only to Postgres, no identity/MFA involvement.

Flag: `-alg` (default `"ES256"`, or `"RS256"`). Loads config, connects **only** to Postgres, builds `tokenpostgres.NewRepository(db)`. Sequence:
1. `tokenapp.GenerateKey(*alg)` — generates a fresh keypair.
2. `repo.DeactivateAll(ctx)` — flips every currently-active signing key to `is_active=false`, stamps `rotated_at=NOW()`.
3. `repo.Create(ctx, key)` — inserts the new key as `is_active=true`.
Logs `kid`/`alg` on success; any error at any step exits(1). Old keys are **never deleted** — they remain resolvable by `kid` forever (so tokens signed before rotation keep validating), but drop out of the public JWKS listing 7 days after `rotated_at` (see §9).

### 3.5 `cmd/migrate/main.go` — a no-op stub

**Unaffected by the service split** — still a stub, migrations still applied manually against the one shared Postgres database that all three HTTP services connect to.

```go
package main
func main() {}
```
**Not implemented.** Migrations are applied manually via `psql` or the `golang-migrate` CLI in development; there is no in-repo migration runner. `TRADEOFFS.md` §17.3 explicitly calls this out as a **pre-production blocker**.

### 3.6 `cmd/worker/main.go` — long-running background worker

**Unaffected by the service split** — still connects only to Postgres + NATS, no identity/MFA dependency at all.

Two responsibilities per its doc comment: (1) subscribe to NATS subject `audit.events` and persist to `audit_events`; (2) periodically purge expired/revoked sessions. Constants: `sessionCleanupInterval = 5 * time.Minute`, `sessionRetention = 30 * 24 * time.Hour`.

Startup: JSON slog logger; `config.Load()`; connects Postgres + NATS (deferred `Close`); cancelable root context. Builds `auditpostgres.NewRepository(db)` + `auditapp.NewConsumer(bus, auditRepo)`, calls `consumer.Subscribe(ctx)` (returns a NATS subscription, deferred `Unsubscribe`). Builds `sessionpostgres.NewRepository(db)` and launches `runSessionCleanup(ctx, sessionRepo)` as a goroutine — runs `DeleteExpiredOrRevoked` once immediately, then every 5 minutes via `time.Ticker`, logging deleted-row counts only when non-zero. Blocks on SIGINT/SIGTERM, then `cancel()`s the context (best-effort shutdown — **no `sync.WaitGroup`** to wait for the cleanup goroutine to fully drain before process exit; single-instance, no leader election, so scaling this binary to >1 replica risks double-processing since NATS Core consumption isn't idempotent — flagged in `TRADEOFFS.md` §17.6/§19.6). Note the `sessions` table it cleans is still owned by iam-server's own Postgres repository (`internal/session`), not affected by the identity/MFA split.

---

## 4. `internal/platform/` — infrastructure layer

### 4.1 `config/config.go`
```go
type Config struct {
    AppEnv, HTTPPort, DatabaseURL, DatabaseReadURL,
    RedisAddr, NATSURL, JWTIssuer,
    WebAuthnRPID, WebAuthnName, WebAuthnOrigin string
}
func Load() Config
func getEnv(key, fallback string) string   // unexported
```
`Load()` calls `godotenv.Load()` (logs, doesn't fail, if `.env` missing), then reads each field with a default: `APP_ENV=development`, `HTTP_PORT=8080`, `DATABASE_URL=""`, `DATABASE_READ_URL=""`, `REDIS_ADDR=localhost:6380`, `NATS_URL=nats://localhost:4223`, `JWT_ISSUER=http://localhost:8080`, `WEBAUTHN_RPID=localhost`, `WEBAUTHN_NAME=Auth Server`, `WEBAUTHN_ORIGIN=http://localhost:3000`. **No validation** — an empty `DatabaseURL` fails later at pgx connect time, not at config-load time.

### 4.2 `httpserver/server.go`
```go
type Server struct{ port string; mux *chi.Mux }
func New(port string) *Server
func (s *Server) Router() *chi.Mux
func (s *Server) Start() error
func CORS(next http.Handler) http.Handler
```
`CORS` is **fully permissive**: `Access-Control-Allow-Origin: *`, methods `GET, POST, PUT, DELETE, OPTIONS`, headers `Content-Type, Authorization, X-Session-ID`, max-age 86400; handles `OPTIONS` preflight with `204`. Code comment explicitly flags this as needing tightening in production — corroborated by `TRADEOFFS.md` §5.3 which calls the wildcard a documented pre-prod blocker.

### 4.3 `httpserver/logging.go`
```go
type statusRecorder struct{ http.ResponseWriter; status int; bytes int }
func RequestLogger(next http.Handler) http.Handler
```
Wraps `ResponseWriter` to capture status/byte-count (defaults status to 200 if `Write` is called without an explicit `WriteHeader`). Logs one structured `slog.LogAttrs` line per request: `method, path, status, dur, bytes, remote, ua`; level escalates Error(5xx)/Warn(4xx)/Info(else).

### 4.4 `metrics/metrics.go`
```go
var HTTPRequests *prometheus.CounterVec        // labels: method, route, status
var HTTPDuration *prometheus.HistogramVec      // same labels, buckets 0.001s..10s
var AuthEvents *prometheus.CounterVec          // label: event
var PrincipalCacheHits, PrincipalCacheMisses prometheus.Counter
func Handler() http.Handler                    // promhttp.Handler()
func Middleware(routeFn func(*http.Request) string) func(http.Handler) http.Handler
```
Package doc explicitly states the cardinality goal: label by method + **route template** + status class, never by tenant/user ID. `Middleware`'s `routeFn` lets the caller supply chi's matched route pattern instead of the raw URL, bounding label cardinality; falls back to `"unknown"` if nil/empty.

### 4.5 `nats/nats.go`
```go
func New(url string) (*natsgo.Conn, error)
```
Thin wrapper over `nats.Connect`, no reconnect/backoff tuning beyond library defaults.

### 4.6 `postgres/postgres.go`
```go
func New(databaseURL string) (*pgxpool.Pool, error)
```
Parses DSN, creates pool, `Ping`s with a 10s timeout to fail fast on unreachable DB — distinct wrapped errors per stage for diagnosability.

### 4.7 `postgres/pools.go` — read-replica scaffolding (unused)
```go
type Pools struct{ Writer, Reader *pgxpool.Pool }
func (p *Pools) Close()
func NewPools(writerURL, readerURL string) (*Pools, error)
```
Supports primary+replica split; if `readerURL` is empty or equal to `writerURL`, `Reader` reuses the writer pool. **Not wired into `cmd/iam-server/main.go`** — that binary still calls single-pool `postgres.New` directly. Read-replica support exists as infrastructure but is not exercised.

### 4.8 `postgres/tx/tx.go` — the real transaction manager
```go
type Executor interface { Exec(...); QueryRow(...) pgx.Row; Query(...) (pgx.Rows, error) }
type Manager struct{ db *pgxpool.Pool }
func NewManager(db *pgxpool.Pool) *Manager
func (m *Manager) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
func FromContext(ctx context.Context) (pgx.Tx, bool)
```
`WithinTransaction`: begins a tx, `defer tx.Rollback(ctx)` (no-op if already committed), injects the tx into a derived context, calls `fn(txCtx)`; commits only if `fn` returns nil. Canonical "defer rollback, commit on success" pattern. This is the concrete implementation of the abstract `internal/shared/tx.Manager` interface that use cases depend on.

### 4.9 `redis/redis.go`
```go
func New(addr string) (*goredis.Client, error)
```
`go-redis` client, `Addr` only (no TLS, no auth password, no pool tuning), pings immediately to fail fast.

### 4.10 `secrets/`
**Empty directory.** No secrets-management (Vault/KMS/SSM) integration exists.

---

## 5. `internal/shared/` — cross-cutting utilities

Four of the fourteen subpackages — `crypto`, `logging`, `tracing`, `validation` — are **empty directories**, planned extension points with no code.

### 5.1 `clock/clock.go`
```go
type Clock interface{ Now() time.Time }
type RealClock struct{}
func (r RealClock) Now() time.Time  // time.Now().UTC()
```
Testability abstraction for deterministic time; production always UTC.

### 5.2 `context/principal.go`
```go
func WithPrincipal(ctx, p *principal.Principal) context.Context
func Principal(ctx) (*principal.Principal, bool)
func MustPrincipal(ctx) *principal.Principal   // panics if absent
```
`MustPrincipal` panics with `"principal missing from context"` — used only where a route is structurally guaranteed to run behind auth middleware (programming-error detector, not a normal error path).

### 5.3 `errors/errors.go`
```go
var ErrNotFound, ErrUnauthorized, ErrForbidden, ErrConflict, ErrInvalidCredentials, ErrTenantMismatch error
```
The entire domain-error vocabulary, mapped to 404/401/403/409/401/403 respectively at transport layer via `errors.Is`.

### 5.4 `id/id.go`
```go
func New() string   // uuid.NewString()
```
Canonical entity-ID generator (UUIDv4) for every Postgres `UUID PRIMARY KEY`.

### 5.5 `password/password.go` — Argon2id hashing
Constants: `memory = 64*1024` (64 MiB), `iterations = 3`, `parallelism = 2`, `saltLength = 16`, `keyLength = 32` — OWASP "interactive" preset.
```go
func Hash(password string) (string, error)
func Verify(password, encodedHash string) bool
```
`Hash`: random 16-byte salt (`crypto/rand`), `argon2.IDKey` derives 32-byte key, base64-raw-encodes both, formats `$argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<saltB64>$<hashB64>`.
`Verify`: splits on `$` (expects 6 parts), decodes salt/hash, **re-derives using the hardcoded package constants** (not the params embedded in the string — if those constants ever change, old hashes with different params would silently fail to verify, since m/t/p in the encoded string are decorative, not parsed back out), compares via `subtle.ConstantTimeCompare` (timing-safe). A fuzz-caught bug (`("0","$$$$$")` → nil pointer dereference from `keyLength=0` inside `argon2`/`blake2b`) was fixed here at v0.7.1, regression preserved at `testdata/fuzz/FuzzVerify_NoPanic/c6091420777c30e5`.

### 5.6 `principal/principal.go` + `helpers.go`
```go
type Principal struct {
    SessionID, IdentityID, TenantID, UserID, Email string
    Roles, Permissions []string
}
func (p *Principal) HasRole(role string) bool
func (p *Principal) HasPermission(permission string) bool   // linear scan
func (p *Principal) Require(permission string) bool          // alias for HasPermission
```
The single authenticated-actor representation threaded through context on every authenticated request. **Has no `json` tags**, so `/me` (which serializes it directly) emits Go export-case field names.

### 5.7 `slug/slug.go`
```go
func FromEmail(email string) string
```
Local-part-of-email → lowercase, `.`→`-`. No uniqueness handling (that's `tenant/app/slug_service.go`'s job).

### 5.8 `tenancy/context.go`
```go
func WithTenant(ctx, tenantID string) context.Context
func TenantID(ctx) (string, bool)
```
Parallel-structured to `shared/context/principal.go` but a distinct, simpler concept — **not actually used on the live request path** (see §15.4 — the middleware that would populate this key is never registered).

### 5.9 `token/token.go`
```go
func GenerateRandom(length int) (string, error)   // crypto/rand, base64.RawURLEncoding
func Hash(token string) string                     // SHA-256, hex
```
The canonical "generate opaque secret, store only its hash" pattern used for refresh tokens, MFA challenge tokens, OAuth authorization codes.

### 5.10 `tx/tx.go` — the abstract interface (distinct package from `platform/postgres/tx`)
```go
type Manager interface {
    WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}
```
Pure interface, no implementation — this is what `app`-layer use cases depend on (dependency inversion); concretely satisfied by `platform/postgres/tx.Manager`, wired in `main.go` via `pgtx.NewManager(db)`.

---

## 6. Database schema — all migrations

Six golang-migrate up/down SQL pairs, `auth-server/migrations/000001`–`000006`. `cmd/migrate` doesn't apply these (it's a stub) — applied manually in dev.

| Migration | Change |
|---|---|
| **000001_init_schema** | Foundational schema. `pgcrypto` extension. Tables: `tenants` (slug unique, display_name, status); `identities` (global human identity, primary_email unique, email_verified, status); `users` (tenant membership: tenant_id+identity_id FK cascade, username, unique(tenant_id,identity_id), unique(tenant_id,username)); `credentials` (identity_id FK, credential_type, password_hash); `devices` (fingerprinting: fingerprint/platform/browser/os, trusted flag, last_seen_at); `mfa_factors` (identity_id FK, factor_type, secret_encrypted, public_key, label, verified); `sessions` (tenant_id+identity_id+user_id FK, refresh_token_hash, `parent_session_id` self-FK for rotation chains, `ip_address INET`, user_agent, expires_at, revoked_at); `roles` (tenant-scoped, unique(tenant_id,name)); `permissions` (global, name unique — later altered); `role_permissions`/`user_roles` (composite-PK join tables); `policies` (tenant-scoped ABAC-ish: name/effect/condition); `oauth_clients` (client_id unique, client_secret_hash, redirect_uris/grant_types/scopes JSONB, confidential flag); `service_accounts` (client_id unique, client_secret_hash — table exists in schema but **no app code reads/writes it**, see §17); `audit_events` (tenant_id/actor_identity_id nullable, event_type, resource_type/id, ip_address, payload JSONB). 13 supporting indexes. |
| **000002_add_created_at_to_permissions** | Adds `permissions.created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()` (corrective — original table lacked it). |
| **000003_refresh_tokens** | Creates a standalone `refresh_tokens` table (id TEXT PK, session_id TEXT FK→sessions, token_hash TEXT unique, expires_at, revoked_at, created_at) + 2 indexes. **This table and its domain interface (`auth/domain/refresh_token.go`) are dead code in the live system** — refresh-token state actually lives in `sessions.refresh_token_hash` (one row per token generation, chained via `parent_session_id`). Notable: `id`/`session_id` are `TEXT` here, inconsistent with `UUID` PKs used elsewhere — likely because refresh-token IDs are opaque random strings, not UUIDs, from an earlier design iteration that was superseded. |
| **000004_signing_keys** | `signing_keys` (id TEXT PK = `kid`, algorithm, public_key, private_key **PEM cleartext**, is_active BOOLEAN default true, created_at, rotated_at nullable), index `idx_signing_keys_active ON (is_active, created_at DESC)` — optimized for "find latest active key." |
| **000005_webauthn_credentials** | `webauthn_credentials` (id UUID PK, identity_id FK cascade, credential_id BYTEA unique, public_key BYTEA, attestation TEXT, aaguid BYTEA, `sign_count BIGINT default 0`, transports JSONB, `user_handle BYTEA not null`, label, created_at, last_used_at), indexes on identity_id and user_handle. Maps directly onto `go-webauthn/webauthn`'s credential model. |
| **000006_tenant_policies** | (v0.9.0) `tenant_policies` (tenant_id UUID PK+FK cascade, 1:1 with tenants — missing row means "system defaults apply"): `password_min_length` (default 8), `password_require_upper/digit/symbol` (bool, default false), `allowed_email_domains` JSONB (default `[]`), `require_mfa` bool, `max_active_sessions` INT (default 0 = "unlimited" — declared but **unenforced anywhere in the code**), `updated_at`. Also **alters** `permissions`: adds nullable `tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE`, drops the old global `permissions_name_key` unique constraint, replaces with `permissions_tenant_name_uq ON (COALESCE(tenant_id::text,''), name)` — converts permissions from strictly-global to global-or-tenant-scoped (NULL = global, coalesced to `''` so multiple tenants can each define a same-named permission without collision). Down migration reverses symmetrically. |

**Schema/code inconsistencies worth flagging**: `sessions.ip_address` is stored/read as `INET` but cast to `text` in Go scan code in one place (pragmatic v0.1.0 workaround per `IMPLEMENTATION.md` §3) whereas `audit_events.ip_address` is properly `inet` throughout — documented tech debt, revisit slated for the v0.14.0 risk-scoring work per `TRADEOFFS.md` §3.

---

## 7. `internal/auth/` — login, registration, refresh, logout

### 7.1 `domain/credential.go`
```go
type Credential struct{ ID, IdentityID, CredentialType, PasswordHash string; CreatedAt, UpdatedAt time.Time }
type Repository interface {
    Create(ctx, *Credential) error
    GetByIdentityID(ctx, identityID string) (*Credential, error)
}
```

### 7.2 `domain/refresh_token.go` / `refresh_token.repository.go` — **dead code**
```go
type RefreshToken struct{ ID, SessionID, TokenHash string; ExpiresAt time.Time; RevokedAt *time.Time; CreatedAt time.Time }
type RefreshTokenRepository interface { Create; GetByHash; Revoke }
```
Legacy design for refresh tokens as a standalone entity. Never wired in `main.go`, no infra implementation used. The live system stores refresh-token state in `session.Session.RefreshTokenHash` instead (one session row per token generation).

### 7.3 `infra/postgres/repository.go`
Implements `authdomain.Repository` against `credentials` — standard `Create`/`GetByIdentityID`, same `executor(ctx)` ambient-tx pattern used everywhere.

### 7.4 `app/login.go` — `LoginUseCase`

> **⚠ Post-split**: `LoginUseCase`'s dependencies on `identityRepo` and MFA are now satisfied over HTTP, not local Postgres/Redis, though the use case's own code is otherwise unchanged (dependency inversion at work — see §2 point 1, §29.1). The struct now carries an interface for the challenge store rather than a concrete type:
> ```go
> // MFAChallengeStore is the minimal surface LoginUseCase needs from mfa's
> // challenge store. It used to be handed a concrete *mfaapp.ChallengeStore
> // (Redis-backed, constructed in-process); now that mfa is its own service,
> // this is satisfied by mfa/infra/httpclient.ChallengeStoreClient instead.
> type MFAChallengeStore interface {
>     Store(ctx context.Context, c *mfaapp.Challenge) error
> }
>
> type LoginUseCase struct {
>     identityRepo       identitydomain.Repository        // httpclient.Repository in cmd/iam-server
>     credentialRepo     authdomain.Repository             // still direct Postgres
>     userRepo           identitydomain.UserRepository     // still direct Postgres
>     userRoleRepo       authorizationdomain.UserRoleRepository
>     rolePermissionRepo authorizationdomain.RolePermissionRepository
>     sessionRepo        sessiondomain.Repository
>     jwtService         *tokenapp.JWTService
>     mfaRepo            mfadomain.Repository              // httpclient.Repository in cmd/iam-server
>     mfaChallengeStore  MFAChallengeStore                 // httpclient.ChallengeStoreClient in cmd/iam-server
>     policyEnforcer     *tenantapp.PolicyEnforcer
> }
> ```
> Concretely: step 1 below (`identityRepo.GetByEmail`) is now an HTTP round trip to identity-service; step 6 (`mfaRepo.GetVerifiedByIdentity` and, on the MFA-required branch, `mfaChallengeStore.Store`) are HTTP round trips to mfa-service. No TOTP code verification happens in this use case or in iam-server at all — that only happens inside mfa-service's own `mfaapp.CompleteUseCase` when the client later calls `POST /mfa/complete` directly against mfa-service (§12.4, §21.2 — updated).

```go
var ErrMFAEnrollmentRequired = errors.New("mfa enrollment required")
const accessTokenTTL = 15 * time.Minute
const refreshTokenTTL = 7 * 24 * time.Hour

type LoginInput struct{ Email, Password, IPAddress, UserAgent string }
type LoginOutput struct {
    SessionID, TenantID, UserID string
    Roles, Permissions []string
    AccessToken string; ExpiresIn int; RefreshToken string
    MFARequired bool; MFAToken string
}
func (u *LoginUseCase) Execute(ctx, input LoginInput) (*LoginOutput, error)
```
**Exact flow** (steps 1 and 6 are now network calls, see box above):
1. `identityRepo.GetByEmail` — any failure masked to `sharederrors.ErrInvalidCredentials` (prevents user enumeration via this path, though `/register`'s 409 still leaks existence — see §27).
2. `credentialRepo.GetByIdentityID` — same masking.
3. `password.Verify` (Argon2id, constant-time) — fail ⇒ `ErrInvalidCredentials`.
4. `userRepo.GetByIdentityID` → tenant-scoped `User`.
5. `policyEnforcer.Get(ctx, user.TenantID)` → tenant policy.
6. `mfaRepo.GetVerifiedByIdentity(identity.ID)`:
   - If `policy.RequireMFA && len(factors)==0` → `ErrMFAEnrollmentRequired` (403 at transport) — blocks login entirely until enrollment.
   - If `len(factors) > 0`: generate a 32-byte random MFA challenge token, store `mfaapp.Challenge{Token, IdentityID, TenantID, UserID, IPAddress, UserAgent, ExpiresAt:+5m}` in Redis, return `{MFARequired:true, MFAToken}` — **no session/JWT issued yet**.
   - Else: proceed to normal issuance.
7. `userRoleRepo.GetRolesForUser` + `rolePermissionRepo.GetPermissionsForUser`.
8. Generate raw refresh token (32 random bytes, base64url) + SHA-256 hash.
9. Create `sessiondomain.Session{ID:uuid, TenantID, IdentityID, UserID, RefreshTokenHash, IPAddress:&ip, UserAgent, ExpiresAt:+7d, CreatedAt}` → `sessionRepo.Create`.
10. Build `principal.Principal`, `jwtService.Issue(ctx, p, IssueOptions{TTL:15m})` → signed JWT.
11. Return `LoginOutput` with the raw refresh token (returned once, never stored plaintext).

**Critically: `policyEnforcer.ValidatePassword`/`ValidateEmailDomain` are implemented and unit-tested but never called from `LoginUseCase`, `RegisterUseCase`, or `CreateUserUseCase`** — password-complexity and email-domain-allowlist tenant policy is dead-letter, enforced nowhere on the live request path (only `RequireMFA` is actually enforced, and only at login time). Confirmed by two independent exploration passes.

### 7.5 `app/register.go` — `RegisterUseCase`

> **⚠ Post-split, transaction-integrity fix (the most significant behavioral change from the service split):** `identityRepo.Create` can no longer participate in the local `txManager.WithinTransaction` block, because it is now a network call to identity-service rather than a write against the same Postgres connection/transaction as the credential/tenant/user/role writes below it. The old single-local-transaction guarantee ("everything commits or nothing does") no longer holds across the identity-service boundary, so the code was restructured into an explicit **saga with a compensating action**: create the identity first, *outside* any local transaction; if anything in the subsequent local transaction fails, explicitly delete the now-orphaned identity via `identityRepo.Delete`.

```go
type RegisterInput struct{ Email, Password string }
func (u *RegisterUseCase) Execute(ctx, input RegisterInput) error
```
**Exact current flow:**
1. Build `identity := &identitydomain.Identity{ID: id.New(), PrimaryEmail: input.Email, EmailVerified: false, Status: "active"}`.
2. **Outside** `txManager.WithinTransaction` — a plain call on `ctx`, not `txCtx`: `if err := u.identityRepo.Create(ctx, identity); err != nil { return err }`. In-code comment: *"identityRepo.Create is a network call to identity-service, not part of the local Postgres transaction below — it happens first, outside txManager.WithinTransaction, so a failure here needs no compensation of its own and the transaction below only ever runs against an identity that already exists."* A unique-violation on email surfaces from identity-service as `sharederrors.ErrConflict` (identity-service's own handler maps `pgerrcode.UniqueViolation` → `ErrConflict` → HTTP 409; the httpclient maps HTTP 409 back → `ErrConflict` — see §29.1) → 409 at iam-server's transport layer, same observable behavior as before the split.
3. Enter `u.txManager.WithinTransaction(ctx, func(txCtx) error {...})`, inside which, in order (all still one atomic local Postgres transaction, all unchanged from pre-split): `password.Hash` → create `Credential{CredentialType:"password", PasswordHash}` → `slug.FromEmail` + `slugService.GenerateUniqueSlug` (base, then `base-1`..`base-5`) → create a **brand-new** `Tenant{Slug, DisplayName:email, Status:"active"}` → create `User{TenantID, IdentityID, Username:email, DisplayName:email, Status:"active"}` → `bootstrapService.CreateTenantOwnerRole(tenant.ID)` → `permissionBootstrapService.BootstrapTenantOwnerPermissions(role.ID)` → `userRoleRepo.AssignRole(UserRole{UserID, RoleID})`. Any step's error short-circuits and rolls back this local transaction (but, critically, does **not** undo the identity created in step 2 — that row is now orphaned in identity-service's database).
4. **After** the transaction block returns, if it produced an error, run the compensating delete:
   ```go
   if delErr := u.identityRepo.Delete(ctx, identity.ID); delErr != nil {
       slog.Error(
           "register: failed to compensate for orphaned identity after transaction failure",
           "identity_id", identity.ID,
           "tx_error", err,
           "delete_error", delErr,
       )
       return fmt.Errorf(
           "register: transaction failed (%w) and compensating identity delete also failed for identity %s: %w",
           err, identity.ID, delErr,
       )
   }
   return err
   ```
   The comment above this block: *"The identity was already persisted in identity-service (outside this local transaction, which has since rolled back), so it must be explicitly compensated for or it is orphaned: a row in identity-service with no matching credential/tenant/user in this service's database."* Note `ctx` (not `txCtx`) is used for the compensating `Delete` too — it's a separate network round trip, unrelated to (and unaffected by) the already-rolled-back local Postgres transaction.
5. If the double-failure branch is hit (transaction failed *and* the compensating delete also failed), the caller sees a wrapped error naming both failures, and an **orphaned identity row genuinely remains** in identity-service with no corresponding tenant/user/credential — a residual gap of the saga pattern (no outbox, no retry, no reconciliation job for this specific case) worth flagging in §27's gap catalog. If the compensating delete succeeds, the net observable behavior for the caller is identical to the pre-split single-transaction rollback: nothing persisted, plain error returned.
6. On full success, `return nil`.

Registration still does **not** return a session — the caller must separately `POST /login`. `identity-service`'s own `Delete` handler treats "identity not found" (404, e.g. if it were somehow already gone) as success too (§29.1/§29.2), so the compensating call is itself idempotent.

### 7.6 `app/refresh.go` — `RefreshUseCase`, refresh-token rotation with session chaining
```go
type RefreshInput struct{ RefreshToken string }
type RefreshOutput struct{ SessionID, TenantID, UserID string; Roles, Permissions []string; AccessToken string; ExpiresIn int; RefreshToken string }
func (u *RefreshUseCase) Execute(ctx, input RefreshInput) (*RefreshOutput, error)
```
1. Hash incoming token → `sessionRepo.GetByRefreshTokenHash` — any failure (not found or other) ⇒ constant `ErrUnauthorized` (no detail leak).
2. Reject if `RevokedAt != nil` or `now > ExpiresAt`.
3. **Revoke the old session immediately** (`sessionRepo.Revoke`) — refresh tokens are single-use; a stolen-and-reused old token fails step 2 on its next attempt. Also `invalidator.Delete(ctx, session.ID)` purges any cached `Principal` for that session ID (see §7.8) so revocation takes effect immediately for the session-header auth path.
4. Generate new refresh token + hash, create a **new** `Session` with `ParentSessionID: &oldSessionID` — an explicit audit chain enabling detection of refresh-token-theft races (if both the legitimate holder and an attacker try to use the same now-revoked token, one succeeds and the other's *next* refresh attempt fails — this "tripwire" is detected structurally but **not currently acted on**, e.g. no family-wide revocation or user notification; flagged in `THREAT_MODEL.md` #9).
5. Re-fetch identity + fresh roles/permissions (role/permission changes since original issuance are picked up on refresh).
6. New `Principal`, new 15-minute JWT bound to the new session ID.
7. Return everything including the new raw refresh token.

### 7.7 `app/logout.go`
```go
type PrincipalInvalidator interface{ Delete(ctx, sessionID string) }
func (u *LogoutUseCase) Execute(ctx, input LogoutInput) error
```
`PrincipalInvalidator` is a tiny interface deliberately decoupling `app` from `middleware` (satisfied by `middleware.PrincipalCache`). Idempotent: already-revoked session ⇒ just invalidate cache and return nil.

### 7.8 `app/me.go` — `MeUseCase` (defined, **never invoked**)
Independently re-derives session→identity→user→roles from a session ID, bypassing whatever `Principal` is already on context. The actual `/me` handler doesn't call this — it just echoes the context `Principal` directly. Effectively dead code (or forward-wired for a future programmatic use).

### 7.9 `middleware/authentication.go` — `AuthenticationMiddleware`
```go
func (m *AuthenticationMiddleware) Authenticate(next http.Handler) http.Handler
```
Two auth strategies tried in order:
1. **Bearer JWT** (`fromBearer`): `Authorization: Bearer <token>` → `jwtService.Verify` → build `Principal` **entirely from JWT claims** (zero DB hits — roles/permissions/email/tenant/user/session-id all embedded at issuance).
2. **Session header** (`fromSessionHeader`): `X-Session-ID` → check `PrincipalCache.Get` (Redis) first; on miss, 4 sequential DB reads (`sessionRepo.GetByID` with revoked/expired check → `identityRepo.GetByID` → `userRoleRepo.GetRolesForUser` → `rolePermissionRepo.GetPermissionsForUser`), assembles `Principal`, `cache.Put`s (5-min TTL).
Neither path succeeding ⇒ `401`. On success, `authctx.WithPrincipal` stores the result on context.

### 7.10 `middleware/principal_cache.go` — `PrincipalCache`
```go
const cachePrefix = "auth:principal:"; const defaultTTL = 5 * time.Minute
func (c *PrincipalCache) Get(ctx, sessionID) (*principal.Principal, bool)
func (c *PrincipalCache) Put(ctx, p *principal.Principal)
func (c *PrincipalCache) Delete(ctx, sessionID)
```
JSON-serializes `Principal` into Redis (`auth:principal:<sessionID>`, TTL 5min); records `metrics.PrincipalCacheHits`/`Misses`; nil-safe (works even constructed with a nil client, used in some tests). **Only invalidation path is explicit `Delete`** (called from logout and refresh) — otherwise a role/permission change can be served stale for up to 5 minutes. Measured effect at v0.8.0: session-ID `/me` p50 went from 14.1ms → 1.5ms, a 9× speedup (`BENCHMARKS.md` §3, `changelogs/v0.8.0`).

### 7.11 `transport/http/*.go`
- **`handler.go`**: `Handler{registerUseCase, loginUseCase, refreshUseCase, logoutUseCase}`.
- **`register.go`** (`Register`): decode+validate (`isValidEmail` — one `@`, non-empty parts, domain has a `.`; password ≥8 chars); `ErrConflict`→409, else 500; success→201 `{"message":"registration successful"}`.
- **`login.go`** (`Login`): `extractIP(r)` (XFF first component → X-Real-IP → `net/netip`-parsed `RemoteAddr`) + `r.UserAgent()`; error map `ErrInvalidCredentials`→401, `ErrMFAEnrollmentRequired`→403, else 500; success sets **both** an httpOnly refresh cookie (`setRefreshCookie`) **and** returns the raw refresh token in the JSON body — dual delivery, flagged as a redundant exposure surface in §27.
- **`logout.go`**: requires context `Principal`; revoke + clear cookie; 204.
- **`me.go`**: `writeJSON(w, p)` — serializes the context `Principal` directly (no `json` tags → Go export-name keys: `SessionID`, `IdentityID`, etc.).
- **`refresh.go`**: token from JSON body, falling back to the `refresh_token` cookie only if body decode fails entirely; empty→400; `ErrUnauthorized`→401; success rotates cookie + JSON body (dual delivery again). Note: `RefreshResponse` DTO defined in `refresh_response.go` is **unused** — the handler returns `authapp.RefreshOutput` directly.
- **`response.go`**: `writeError`/`writeJSON`; refresh-cookie constants — `refresh_token`, MaxAge 7d, `HttpOnly:true`, **`Secure:false`** (flagged — relies entirely on an external TLS-terminating proxy for cookie safety, no defense-in-depth), `SameSite:Strict`.

**Routes** (all mounted at root, not under `/auth`): `POST /register`, `POST /login`, `POST /refresh` (public); `GET /me`, `POST /logout` (withAuth).

---

## 8. `internal/session/` — session domain & persistence

### 8.1 `domain/session.go`
```go
type Session struct {
    ID, TenantID, IdentityID, UserID, RefreshTokenHash string
    ParentSessionID *string
    IPAddress *string
    UserAgent string
    ExpiresAt time.Time
    RevokedAt *time.Time
    CreatedAt time.Time
}
```
Single source of truth for both "login session" and "refresh-token record" — one row per refresh-token generation, chained via `ParentSessionID`.

### 8.2 `domain/repository.go`
```go
type Repository interface {
    Create(ctx, *Session) error
    GetByID(ctx, id string) (*Session, error)
    GetByRefreshTokenHash(ctx, hash string) (*Session, error)
    Revoke(ctx, id string) error
    DeleteExpiredOrRevoked(ctx, olderThan time.Time) (int64, error)
}
```

### 8.3 `infra/postgres/repository.go`
Standard CRUD, tx-aware `executor`. `Create` inserts all 11 columns. `Revoke`: `UPDATE sessions SET revoked_at=NOW() WHERE id=$1`. `DeleteExpiredOrRevoked`: `DELETE FROM sessions WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1)`, returns affected-row count — consumed by `cmd/worker`'s cleanup goroutine.

Session rows are shared across **every** issuance path — password login, MFA-complete, WebAuthn login, and both OAuth2 grants (authorization_code and refresh_token) all create/rotate rows in this same `sessions` table.

---

## 9. `internal/token/` — JWT issuance, verification, signing keys, JWKS

### 9.1 `domain/claims.go`
```go
type Claims struct {
    jwt.RegisteredClaims
    TenantID    string   `json:"tid,omitempty"`
    UserID      string   `json:"uid,omitempty"`
    SessionID   string   `json:"sid,omitempty"`
    Email       string   `json:"email,omitempty"`
    Roles       []string `json:"roles,omitempty"`
    Permissions []string `json:"permissions,omitempty"`
    Nonce       string   `json:"nonce,omitempty"`
}
```
Embeds `golang-jwt/jwt/v5`'s standard `RegisteredClaims` (iss/sub/aud/exp/iat/nbf/jti). `Subject` (`sub`) is always the **IdentityID**. `Nonce` is present on every token (unused on plain access tokens, essential for OIDC ID tokens).

### 9.2 `domain/signing_key.go`
```go
type SigningKey struct{ ID, Algorithm, PublicKey, PrivateKey string; IsActive bool; CreatedAt time.Time; RotatedAt *time.Time }
type Repository interface {
    GetActive(ctx) (*SigningKey, error)
    GetByID(ctx, id string) (*SigningKey, error)
    Create(ctx, *SigningKey) error
    DeactivateAll(ctx) error
    ListPublic(ctx) ([]*SigningKey, error)
}
```
`PrivateKey` is PEM cleartext in Postgres — no KMS/HSM/envelope encryption (flagged as a pre-prod blocker, `THREAT_MODEL.md` #11).

### 9.3 `app/keygen.go`
```go
func GenerateKey(algorithm string) (*domain.SigningKey, error)
```
`"ES256"` → `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`, SEC1-PEM private / PKIX-PEM public. `"RS256"` → `rsa.GenerateKey(rand.Reader, 2048)`, PKCS1-PEM private / PKIX-PEM public. `ID = uuid.NewString()` becomes the JWT `kid`.

### 9.4 `app/jwt_service.go` — `JWTService`
```go
func (s *JWTService) Issue(ctx, p *principal.Principal, opts IssueOptions) (string, error)
func (s *JWTService) Verify(ctx, tokenStr string) (*domain.Claims, error)
```
**`Issue`**: fetch `keyRepo.GetActive` → build `Claims` (Issuer, Subject=IdentityID, Audience=opts.Audience, IssuedAt/ExpiresAt/NotBefore, ID=fresh uuid jti, plus tenant/user/session/email/roles/permissions/nonce) → `parsePrivateKey` decodes PEM (tries native format, falls back to PKCS8) → `jwt.NewWithClaims`, sets `token.Header["kid"]=key.ID`, signs.

**`Verify`**: `jwt.ParseWithClaims(..., jwt.WithValidMethods([]string{"ES256","RS256"}))` — **this is the sole and complete defense against `alg=none`/algorithm-confusion attacks**, fuzz-tested (`FuzzJWT_RejectsAlgNone`). `keyFunc` extracts `kid` from the header (missing `kid` → immediate reject), fetches that exact key by ID via `GetByID` (independent of `is_active` — this is what lets old, rotated-out keys keep verifying), decodes the public key by the algorithm recorded on the key row (not by trusting the JWT's own `alg` header for key-material selection). Any failure anywhere collapses to `sharederrors.ErrUnauthorized`.

### 9.5 `infra/postgres/repository.go`
- `GetActive`: `SELECT ... WHERE is_active=true ORDER BY created_at DESC LIMIT 1`.
- `GetByID`: `SELECT ... WHERE id=$1` (works regardless of active status).
- `DeactivateAll`: `UPDATE ... SET is_active=false, rotated_at=NOW() WHERE is_active=true`.
- `ListPublic`: `SELECT ... WHERE rotated_at IS NULL OR rotated_at > NOW() - INTERVAL '7 days'` — the JWKS exposure window; a key stays discoverable for 7 days after rotation, but `Verify`'s direct `GetByID` lookup is unaffected by JWKS listing, so old tokens keep validating indefinitely (keys are never deleted).

### 9.6 `transport/http/jwks.go`
```go
func (h *Handler) JWKS(w, r)   // GET /.well-known/jwks.json
```
Converts each `ListPublic` key to an RFC 7517 JWK (`kty`, `use:"sig"`, `alg`, `kid`, EC fields `crv:"P-256",x,y` or RSA fields `n,e`); `Cache-Control: public, max-age=3600`. `bigIntBytes` manually big-endian-encodes the RSA exponent.

### 9.7 Tests
`jwt_service_test.go`: in-memory `memKeyRepo`; ES256+RS256 round trips, tampered-token rejection, expired-token rejection, unknown-`kid` rejection, nonce/audience propagation, `Issue`/`Verify` benchmarks. `jwt_fuzz_test.go`: `FuzzJWT_Verify` (soundness — any success must be a fully legitimate token), `FuzzJWT_RejectsAlgNone` (regression guard for the classic unsigned-token attack).

### 9.8 Key rotation lifecycle
`cmd/key-rotator -alg ES256` → new key generated → all previously-active keys deactivated (`rotated_at` stamped) → new key inserted active. New issuance uses the new key on the very next `Issue` call (no cache/restart needed — queried per-issuance). Old tokens remain verifiable forever (`GetByID` has no active-status filter). Old key stays in JWKS for 7 days post-rotation, then is delisted from discovery but still directly resolvable.

---

## 10. `internal/oauth/` — OAuth2 authorization code + PKCE

### 10.1 `domain/client.go`
```go
type Client struct {
    ID, TenantID, ClientID, ClientSecretHash, ClientName string
    RedirectURIs, GrantTypes, Scopes []string
    Confidential bool
    CreatedAt time.Time
}
func (c *Client) HasGrantType(g string) bool
func (c *Client) HasRedirectURI(u string) bool
func (c *Client) AllowsScope(s string) bool
type ClientRepository interface{ GetByClientID; Create }
```
`Confidential` distinguishes confidential (must present `client_secret`) from public (PKCE-only) clients — **but PKCE is mandatory for every client regardless**, stricter than the RFC baseline.

### 10.2 `domain/code.go`
```go
type AuthorizationCode struct {
    Code, ClientID, TenantID, IdentityID, UserID string
    Scopes []string
    RedirectURI, CodeChallenge, CodeChallengeMethod, Nonce string
    ExpiresAt time.Time
}
type CodeStore interface{ Store; Consume }   // Consume = one-time retrieval
```

### 10.3 `app/authorize.go` — `AuthorizeUseCase` (`/oauth/authorize`)
```go
const codeTTL = 10 * time.Minute
func (u *AuthorizeUseCase) Execute(ctx, in AuthorizeInput) (*AuthorizeOutput, error)
```
**Exact validation order**:
1. `response_type` must be exactly `"code"` else `ErrUnsupportedResponse`.
2. `code_challenge` non-empty else `ErrMissingPKCE`.
3. `code_challenge_method` must be exactly `"S256"` (plain rejected) else `ErrUnsupportedChallenge`.
4. `clientRepo.GetByClientID` — not found ⇒ `ErrInvalidClient`.
5. `client.HasRedirectURI` — **exact string match** else `ErrInvalidRedirectURI`.
6. `client.HasGrantType("authorization_code")` else `ErrUnsupportedGrant`.
7. Each requested scope (whitespace-split via `splitScopes`) must be `client.AllowsScope` else `ErrInvalidScope`.
8. `client.TenantID != Principal.TenantID` ⇒ `ErrInvalidClient` — cross-tenant client-authorization block.
9. Generate 32-byte random code, build `AuthorizationCode{..., ExpiresAt:+10m}`, `codeStore.Store`.
10. Return `{Code, State, RedirectURI}`.

### 10.4 `app/token.go` — `TokenUseCase` (`/oauth/token`)
```go
type IDTokenIssuer interface {
    IssueIDToken(ctx, p *principal.Principal, clientID, nonce string, ttl time.Duration) (string, error)
}
func (u *TokenUseCase) Execute(ctx, in TokenInput) (*TokenOutput, error)   // dispatches on grant_type
```
**`authorizationCodeGrant`**:
1. `clientRepo.GetByClientID` — not found ⇒ `ErrInvalidClient`.
2. If confidential: hash presented secret, `subtle.ConstantTimeCompare` against `ClientSecretHash` — mismatch ⇒ `ErrInvalidClient`.
3. `codeStore.Consume(Code)` — Redis `GETDEL`, atomic one-time-use at the storage layer — not found ⇒ `ErrInvalidGrant`.
4. Expiry check, `ClientID` match, `RedirectURI` exact match — all ⇒ `ErrInvalidGrant` on failure.
5. `verifyPKCE(CodeVerifier, code.CodeChallenge)` — `sha256(verifier)` → base64url-raw → `subtle.ConstantTimeCompare` — fail ⇒ `ErrInvalidGrant`.
6. Load identity + roles + permissions; generate refresh token; create a **new, unparented** Session (fresh OAuth-originated session in the same `sessions` table as password login).
7. `jwtService.Issue` with `Audience:[ClientID]` — **OAuth access tokens carry an `aud` claim; plain password-login access tokens do not.**
8. If `hasScope(code.Scopes,"openid") && idTokenIssuer != nil` → `idTokenIssuer.IssueIDToken(...)` (dependency-inverted OIDC hook — `TokenUseCase` doesn't import `oidc` directly).

**`refreshTokenGrant`**: independently duplicated (not shared code) rotation logic nearly identical to `authapp.RefreshUseCase` — hash lookup, revoke old, chain new session (`ParentSessionID` set here, unlike the authorization_code path), reissue with `Audience:[ClientID]`. **Does not** re-check client_id/secret against the session's originating client, and **does not** re-issue an `id_token` even for originally-`openid`-scoped grants — a real gap vs. full OIDC spec.

### 10.5 `infra/postgres/client_repository.go`
JSON-(un)marshals `redirect_uris`/`grant_types`/`scopes`; `client_secret_hash` nullable (public clients).

### 10.6 `infra/redis/code_store.go`
```go
const codePrefix = "oauth:code:"
func (s *CodeStore) Store(ctx, code) error   // SET ... EX <ttl-until-expiry>
func (s *CodeStore) Consume(ctx, code) (*AuthorizationCode, error)   // GETDEL
```

### 10.7 `transport/http/handler.go`
- **`Authorize`** (`GET /oauth/authorize`, `withAuth`): requires context `Principal` (must already be logged in via cookie/bearer — no login-page redirect exists). Pulls query params, calls `AuthorizeUseCase.Execute`. Error → `oauthErrorRedirect`: 302 back to `redirect_uri` with `error`/`error_description`(+`state`) query params (or a JSON error if `redirect_uri` itself was empty). Success → 302 with `code`(+`state`).
- **`Token`** (`POST /oauth/token`, public): `r.ParseForm()`; `extractClientCreds` (HTTP Basic first, then form params); error mapping `ErrInvalidClient`→401, `ErrInvalidGrant`→400, `ErrUnsupportedGrant`→400, else 500 — all `invalid_client`/`invalid_grant`/`unsupported_grant_type`/`server_error` per RFC 6749 §5.2; success sets `Cache-Control: no-store` + `Pragma: no-cache` (RFC-mandated).

### 10.8 PKCE tests
`pkce_test.go`: exact-match, mismatch, empty-verifier, and the **official RFC 7636 Appendix B.1 test vector**. `pkce_fuzz_test.go`: `FuzzVerifyPKCE` (never a false positive across fuzzed inputs), `FuzzSplitScopes` (no empty-string tokens in split results).

---

## 11. `internal/oidc/` — OpenID Connect layer

Thin composition layer — `app` + `transport/http` only, no `domain`/`infra`/`middleware`.

### 11.1 `app/id_token_service.go`
```go
func (s *IDTokenService) IssueIDToken(ctx, p *principal.Principal, clientID, nonce string, ttl time.Duration) (string, error)
```
Implements `oauthapp.IDTokenIssuer`. Builds a **stripped-down** `Principal` (only SessionID/IdentityID/TenantID/UserID/Email — deliberately drops Roles/Permissions so ID tokens don't leak authorization data meant only for access tokens), delegates to `jwtService.Issue` with `Audience:[clientID], Nonce:nonce`. Structurally identical to an access token except empty roles/permissions and populated nonce — no `at_hash`, no explicit `auth_time` — a minimal, spec-light implementation.

### 11.2 `transport/http/discovery.go`
`GET /.well-known/openid-configuration` (public): static JSON — `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri` (all issuer-prefixed), `response_types_supported:["code"]`, `grant_types_supported:["authorization_code","refresh_token"]`, `subject_types_supported:["public"]`, `id_token_signing_alg_values_supported:["ES256","RS256"]`, `scopes_supported:["openid","profile","email"]`, `token_endpoint_auth_methods_supported:["client_secret_basic","client_secret_post","none"]`, `code_challenge_methods_supported:["S256"]`, `claims_supported:[...]`. `Cache-Control: public, max-age=3600`.

### 11.3 `transport/http/userinfo.go`
`GET /oauth/userinfo` (`withAuth` — accepts either Bearer or `X-Session-ID`, not exclusively OAuth access tokens): builds `{sub:Principal.IdentityID, email:Principal.Email}`, overlays `email_verified` via a live `identityRepo.GetByID` lookup (and back-fills `Email` if the context principal's was empty).

---

## 12. `internal/mfa/` — TOTP multi-factor authentication

> **⚠ Post-split**: all the code in this section (`domain`, `app`, `infra/postgres`, `transport/http/handler.go`) is **unchanged in logic and now runs exclusively inside `cmd/mfa-service`** (§3.3) — the Postgres repo, `TOTPService`, `ChallengeStore`, and `CompleteUseCase` are all still concrete types wired together in-process there, since mfa-service owns this data directly. What's new: (1) a **new** `internal/mfa/infra/httpclient` package (§29.1) that lets *other* services (currently only `cmd/iam-server`, for `LoginUseCase`'s MFA-required check) reach this data over HTTP instead of importing this package's Postgres/Redis adapters directly; (2) a **new** `internal/mfa/transport/http/internal_handler.go` (`InternalHandler`) exposing factor CRUD and challenge store/consume over `/internal/mfa/...` routes, purely to back that httpclient from the server side. `iam-server` no longer imports `mfaapp.TOTPService`, `mfaapp.ChallengeStore`, or `mfapostgres` at all — see §3.1/§7.4.

**No backup/recovery codes exist anywhere in this codebase** (confirmed via repo-wide case-insensitive grep for `BackupCode`/`backup_code`) — flagged in `TRADEOFFS.md` §10 as a required pre-prod closure before any tenant sets `require_mfa=true`.

### 12.1 `domain/factor.go`
```go
type Factor struct{ ID, IdentityID, FactorType, SecretEncrypted, Label string; Verified bool; CreatedAt time.Time }
type Repository interface {
    Create; GetByID; GetByIdentity; GetVerifiedByIdentity; MarkVerified; Delete
}
```
**`SecretEncrypted` is a misleading name — it stores the raw base32 TOTP seed with zero encryption applied anywhere in `app` or `infra`.** Plaintext-at-rest. Flagged as a pre-prod blocker in both `TRADEOFFS.md` §10 and `THREAT_MODEL.md`.

### 12.2 `app/challenge_store.go` — Redis, single-use, TTL'd
```go
const challengeTTL = 5 * time.Minute
func (s *ChallengeStore) Store(ctx, c *Challenge) error
func (s *ChallengeStore) Consume(ctx, token string) (*Challenge, error)   // GETDEL
```
`Consume` uses atomic `GETDEL` — the core replay-protection mechanism; a challenge can only ever be read once.

### 12.3 `app/totp.go` — `TOTPService`
```go
func (s *TOTPService) Enroll(ctx, identityID, email, label string) (*EnrollmentResult, error)
func (s *TOTPService) VerifyEnrollment(ctx, factorID, code string) error
func (s *TOTPService) Verify(ctx, identityID, code string) error
func (s *TOTPService) Unenroll(ctx, factorID string) error
func (s *TOTPService) List(ctx, identityID string) ([]*domain.Factor, error)
```
- **`Enroll`**: `pquerna/otp/totp.Generate` (random base32 secret, ~160-bit entropy) → persist unverified `Factor` → manually builds an `otpauth://` URL with explicit `algorithm=SHA1, digits=6, period=30` (Google-Authenticator-compatible RFC 6238 defaults).
- **`VerifyEnrollment`**: `totp.Validate(code, secret)` (single time-step, no configured skew window) → on success `MarkVerified`.
- **`Verify`** (used at login-completion time): loop-checks the submitted code against **every** verified factor for the identity; succeeds on first match (supports multiple registered authenticators).
- **`Unenroll`**: hard delete.

### 12.4 `app/complete.go` — `CompleteUseCase` (`POST /mfa/complete`)
```go
const accessTokenTTL = 15*time.Minute; const refreshTokenTTL = 7*24*time.Hour
func (u *CompleteUseCase) Execute(ctx, in CompleteInput) (*CompleteOutput, error)
```
1. `challengeStore.Consume(MFAToken)` — atomic GETDEL; missing ⇒ `ErrInvalidCode`.
2. Defense-in-depth expiry re-check even though Redis TTL should have already expired it.
3. `totpService.Verify(challenge.IdentityID, Code)` — any failure ⇒ `ErrInvalidCode`. **Because the challenge was already consumed in step 1, a wrong code forces the user to restart login from scratch** — no multi-attempt retry per challenge.
4. Load identity/roles/permissions; generate refresh token; create `Session` (carries over IP/UA/tenant/user from the original challenge, captured at password-login time); issue 15-min JWT.
5. Return full session/token payload — structurally identical to plain password login output.

### 12.5 `infra/postgres/repository.go`
Standard CRUD against `mfa_factors`; `GetVerifiedByIdentity` filters `WHERE identity_id=$1 AND verified=true`.

### 12.6 `transport/http/handler.go` — served by `cmd/mfa-service` (§3.3), not iam-server
- `EnrollTOTP` (`POST /mfa/enroll/totp`, withAuth) → 201 `{factor_id, secret, qr_url}`.
- `VerifyEnrollment` (`POST /mfa/enroll/verify`, withAuth) → `ErrInvalidCode`→401, else 204.
- `Complete` (`POST /mfa/complete`, **public**) → generic 401 `"invalid mfa challenge or code"` on any failure (deliberately vague — doesn't leak whether token or code was wrong).
- `List` (`GET /mfa/factors`, withAuth) → `[{id, factor_type, label, verified}]` (secrets never returned).

All four of these routes are on **mfa-service's own port** (`MFA_HTTP_PORT`, default 8082) — a client must call mfa-service directly for enrollment/completion; `iam-server` exposes none of them (§3.1).

### 12.6a `transport/http/internal_handler.go` — new: `InternalHandler`, backs `internal/mfa/infra/httpclient`

```go
type InternalHandler struct {
    factorRepo     mfadomain.Repository
    challengeStore *mfaapp.ChallengeStore
}
func NewInternalHandler(factorRepo mfadomain.Repository, challengeStore *mfaapp.ChallengeStore) *InternalHandler
```
Methods (`factors.go`): `CreateFactor`, `GetFactorByID`, `GetFactorsByIdentity`, `GetVerifiedFactorsByIdentity`, `MarkFactorVerified`, `DeleteFactor` — each a thin marshal/unmarshal wrapper around the same `mfadomain.Repository` used by the public handlers above. Methods (`challenges.go`): `StoreChallenge`, `ConsumeChallenge` — the latter is the server-side half of the client mapping documented in §29.1:
```go
if err := ...; err != nil {
    if errors.Is(err, sharederrors.ErrNotFound) {
        http.Error(w, "challenge not found", http.StatusNotFound)
        return
    }
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
}
```
Mounted under `/internal/mfa/factors...` and `/internal/mfa/challenges...` on mfa-service, **no authentication middleware** — trust boundary is "only reachable on the private network," not enforced in code (same posture as identity-service's `/internal/identities/...`, §3.2).

### 12.7 Tests
`totp_test.go`: in-memory `memFactorRepo`; enrollment→verify→activate; wrong-code rejection; multi-factor any-verifies; unverified-factor-ignored; unenroll. **Not updated for the split** — still exercises `TOTPService`/`ChallengeStore` directly in-process; there is no unit or integration test exercising `internal/mfa/infra/httpclient` against a running `InternalHandler` (§22, §29.5).

---

## 13. `internal/webauthn/` — WebAuthn / FIDO2 / passkeys

> **⚠ Post-split**: unlike `internal/mfa`, this package got **no httpclient adapter at all** and did not need one. All the code below is unchanged and now runs exclusively inside `cmd/mfa-service` (§3.3) — `wapostgres.NewRepository(db)` is constructed there directly. `iam-server` has **zero webauthn wiring left**: no import of any `internal/webauthn/*` package, and a code comment in `cmd/iam-server/main.go` states plainly *"mfa/webauthn routes (enroll, verify, list, complete, register, login) are served directly by mfa-service now ... not proxied through iam-server."* The structural reason webauthn's split shape differs from MFA's: `internal/auth/app.LoginUseCase` (which stays in iam-server) needs `mfadomain.Repository`/`ChallengeStore` in-process to decide "is MFA required" and issue a challenge during `POST /login` — that's a real cross-service call iam-server must make, hence a client. WebAuthn login is a **primary, self-contained login method** with no equivalent call site in iam-server; a caller wanting passkey login talks to `mfa-service`'s own port directly for the entire ceremony, so there's nothing for iam-server to call and nothing to build a client for. There is also no reverse proxy anywhere in the repo (`grep -r ReverseProxy` is empty) — this is a hard service boundary, not a transparent one.

Uses `go-webauthn/webauthn` + `go-webauthn/x`.

### 13.1 `domain/credential.go`
```go
type Credential struct {
    ID, IdentityID string
    CredentialID, PublicKey, AAGUID []byte
    Attestation string
    SignCount uint32
    Transports []string
    UserHandle []byte
    Label string
    CreatedAt time.Time
    LastUsedAt *time.Time
}
type Repository interface {
    Create; GetByCredentialID; ListByIdentity; ListByUserHandle; UpdateSignCount; Delete
}
```
`ListByUserHandle` is what enables **discoverable-credential (passkey) login** — the browser presents a `userHandle` from the authenticator, resolved back to an identity with no username typed first.

### 13.2 `app/user.go` — `WAUser`
Adapter implementing the library's `webauthn.User` interface; `WebAuthnCredentials()` converts stored `domain.Credential`s into the library's `wa.Credential` shape so prior registrations can be excluded at registration time and validated at login time.

### 13.3 `app/session_store.go`
Redis, 5-min TTL, `GETDEL`-based `Consume` — single-use, exactly mirroring the MFA challenge store.

### 13.4 `app/service.go` — `Service`, the ceremony orchestrator
```go
func NewService(rpDisplayName, rpID string, rpOrigins []string, credRepo, identityRepo, sessions) (*Service, error)
func (s *Service) BeginRegistration(ctx, identityID) (*protocol.CredentialCreation, string, error)
func (s *Service) FinishRegistration(ctx, identityID, sessionKey, label string, r *http.Request) (*domain.Credential, error)
func (s *Service) BeginLogin(ctx) (*protocol.CredentialAssertion, string, error)
func (s *Service) FinishLogin(ctx, sessionKey string, r *http.Request) (*domain.Credential, error)
```

**Registration ceremony:**
- `BeginRegistration`: loads identity + existing credentials → determines a **stable `userHandle`** (identity-ID bytes for a first credential, reused from `existing[0].UserHandle` thereafter — keeps every passkey for one identity under one WebAuthn user.id) → `webauthn.BeginRegistration(user, WithResidentKeyRequirement(Required), WithAuthenticatorSelection{RequireResidentKey:true, UserVerification:Preferred})` — library generates a CSPRNG challenge, builds `CredentialCreationOptions` (excludeCredentials populated from existing creds so the same authenticator can't double-register) → opaque `sessionKey := id.New()` stores the real `SessionData` in Redis (5-min TTL) → returns options for `navigator.credentials.create()`.
- `FinishRegistration`: `sessions.Consume` (single-use GETDEL) → rebuild identical `WAUser` view → `webauthn.FinishRegistration(user, sessionData, r)` — parses `clientDataJSON` (`type=="webauthn.create"`, challenge match, origin ∈ RPOrigins), parses CBOR `attestationObject` (`rpIdHash` check, UP/UV flag checks), verifies the attestation statement/signature per format, extracts COSE public key + credential ID + AAGUID + initial sign count + transports → persist `domain.Credential`.

**Authentication ceremony (usernameless/discoverable):**
- `BeginLogin`: `webauthn.BeginDiscoverableLogin()` — fresh challenge, **empty `allowCredentials`** (the authenticator itself picks a matching resident credential and returns its `userHandle`). `randomKey()` reads 16 `crypto/rand` bytes **but discards them**, returning `id.New()` (UUIDv4) instead — dead-code artifact, functionally harmless since UUIDv4 is also CSPRNG-backed, but confusing.
- `FinishLogin`: `sessions.Consume` → inline `handler(rawID, userHandle)` callback resolves `WAUser` via `credRepo.ListByUserHandle` + `identityRepo.GetByID` → `webauthn.FinishDiscoverableLogin(handler, sessionData, r)` — verifies `clientDataJSON` (`type=="webauthn.get"`, challenge, origin), verifies `authenticatorData` (rpIdHash, UP/UV), matches credential by ID, verifies assertion signature against the stored COSE public key, **checks `signCount`** — but per `THREAT_MODEL.md` #27 and cross-checked in code, a non-increasing counter is **not actually rejected**, only stored (clone-detection gap, closure slated for v0.10.0). `credRepo.GetByCredentialID` re-fetches canonical row; `UpdateSignCount` persists new counter + `last_used_at` (error from this call is silently swallowed — `_ =` — so a transient DB failure here doesn't fail the login but does leave the counter stale).

### 13.5 `app/login_complete.go` — `LoginUseCase` (WebAuthn's own, distinct from `auth.LoginUseCase`)
This is a **primary, passwordless login method**, not a second factor. `Complete(ctx, sessionKey, r)`: `service.FinishLogin` → load identity/user/roles/permissions → generate refresh token → create `Session` (note: **no `IPAddress` set here**, only `UserAgent` — unlike the password/MFA paths) → issue 15-min JWT. Output shape identical to password/MFA-complete login.

### 13.6 `infra/postgres/repository.go`
`Transports` stored as JSONB array; raw `bytea` for credential_id/public_key/aaguid/user_handle; `UpdateSignCount` also stamps `last_used_at=NOW()`.

### 13.7 `transport/http/handler.go` + `util.go`
- `RegisterBegin`/`RegisterComplete` (withAuth), `LoginBegin`/`LoginComplete` (public), `List` (withAuth).
- `requestWithBody(r, body)`: clones the incoming request, replaces `Body`/`ContentLength` with the inner `response` JSON extracted from the outer `{session_key, label, response}` envelope — a shim because go-webauthn's `Finish*` functions read the ceremony response directly from `r.Body`, not from a pre-parsed struct.

**Routes** (all served on `cmd/mfa-service`'s port, `MFA_HTTP_PORT` default 8082 — not on iam-server, §3.3): `POST /webauthn/login/begin`, `POST /webauthn/login/complete` (public); `POST /webauthn/register/begin`, `POST /webauthn/register/complete`, `GET /webauthn/credentials` (withAuth).

---

## 14. `internal/authorization/` — RBAC

### 14.1 `domain/`
- **`permission.go`**: `Permission{ID, Name, Description, CreatedAt}` — `resource:action` convention (e.g. `users:create`).
- **`role.go`**: `Role{ID, TenantID, Name, Description, CreatedAt}` — roles are per-tenant; two tenants can each have a role literally named `"admin"` with independent IDs/permissions.
- **`role_permission.go`** / **`user_role.go`**: pure join-table structs.
- Repository interfaces: `PermissionRepository`, `RoleRepository`, `RolePermissionRepository` (`AssignPermission`, `GetPermissionsForRole`, **`GetPermissionsForUser`** — the critical 3-way-join query), `UserRoleRepository` (`AssignRole`, `GetRolesForUser`).

### 14.2 `app/`
- **`create_role.go`**: dedup-checks `(TenantID,Name)` → `ErrConflict` if exists, else creates.
- **`assign_permission_to_role.go`**: fetches role, **tenant-ownership check** (`role.TenantID != input.TenantID` → `ErrForbidden`), looks up permission by name (must pre-exist — not auto-created), inserts the join row.
- **`list_roles.go`** / **`list_role_permissions.go`**: thin reads, the latter re-enforces the same tenant-ownership check.
- **`bootstrap.go`** (`BootstrapService`): creates a hardcoded `Role{Name:"tenant_owner"}` for a new tenant — called only from `RegisterUseCase`.
- **`permission_bootstrap.go`** (`PermissionBootstrapService`): 10 hardcoded permissions (`users:create/read/update/delete`, `roles:create/read/update/delete`, `tenant:update/delete`) — lazily created if missing (idempotent but race-prone across concurrent first-registrations, functionally harmless), then unconditionally assigned to the given role. **Note: no `mfa:*`/`webauthn:*`/`oauth:*`/`tenant:read` permissions exist** — `/tenant/policy` GET requires only authentication, not a specific permission, so this omission is benign there but means the RBAC system has no fine-grained coverage of those subsystems.

### 14.3 `infra/postgres/` — 4 repos, identical shared shape
`executor(ctx)` ambient-tx pattern throughout. Key queries:
- `GetPermissionsForRole`: `role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=$1`.
- **`GetPermissionsForUser`** (the authorization hot-path query): `user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=$1`, `SELECT DISTINCT p.name` (dedupes multi-role grants of the same permission).
- `GetRolesForUser`: `user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1`.

### 14.4 `middleware/authorization.go` — `RequirePermission`
```go
func RequirePermission(permission string) func(http.Handler) http.Handler
```
A middleware **factory**, called once per route at wiring time. At request time: reads context `Principal` (401 if absent) → `p.HasPermission(permission)` (linear scan, no DB access — purely in-memory) → 403 if false, else calls `next`. **This is the entire authorization decision** — all the expensive role→permission resolution happened earlier, either at JWT-issue time or Principal-resolution/caching time. Deliberate perf tradeoff: role/permission changes take up to the JWT's 15-minute lifetime (bearer path, since JWTs are self-contained and never re-checked mid-life) or the 5-minute cache TTL (session-header path) to propagate.

**Important gap** (`THREAT_MODEL.md` #18): there is **no compiler-enforced requirement** that every new route call `RequirePermission` — a route added without `withPerm(...)` is silently open to any authenticated user. Also, `assign_permission.go`'s transport handler maps *any* use-case error (including the tenant-ownership `ErrForbidden`) to a generic 500 rather than differentiating 403/404 — a minor transport-layer gap.

### 14.5 `transport/http/`
`create_role.go`, `list_roles.go`, `assign_permission.go`, `list_role_permissions.go` — all derive `TenantID` from the context `Principal`, **never from client input** (prevents cross-tenant role manipulation even if a client tries to inject a different tenant ID).

**Routes**: `POST /roles` (`roles:create`), `GET /roles` (`roles:read`), `POST /roles/{roleID}/permissions` (`roles:update`), `GET /roles/{roleID}/permissions` (`roles:read`) — all `withAuth` + `withPerm`.

---

## 15. `internal/tenant/` — multi-tenancy & policy

### 15.1 `domain/tenant.go` + `repository.go`
```go
type Tenant struct{ ID, Slug, DisplayName, Status string; CreatedAt, UpdatedAt time.Time }
type Repository interface{ Create; GetByID; GetBySlug; ExistsBySlug }
```

### 15.2 `domain/policy.go`
```go
type Policy struct {
    TenantID string
    PasswordMinLength int
    PasswordRequireUpper, PasswordRequireDigit, PasswordRequireSymbol bool
    AllowedEmailDomains []string   // empty = any domain allowed
    RequireMFA bool
    MaxActiveSessions int          // 0 = unlimited — declared, NEVER enforced anywhere
}
func DefaultPolicy() *Policy   // {PasswordMinLength:8}, else zero-value
type PolicyRepository interface{ Get; Upsert }   // Get contract: never returns nil
```

### 15.3 `app/policy_enforcer.go` — `PolicyEnforcer`
```go
func (e *PolicyEnforcer) Get(ctx, tenantID) (*domain.Policy, error)
func (e *PolicyEnforcer) ValidatePassword(p *domain.Policy, password string) error
func (e *PolicyEnforcer) ValidateEmailDomain(p *domain.Policy, email string) error
```
`Get` is nil-safe (returns `DefaultPolicy()` if the enforcer or its repo is nil — used in tests via `NewPolicyEnforcer(nil)`). `ValidatePassword`: length check then (if configured) unicode-aware upper/digit/symbol checks, short-circuiting. `ValidateEmailDomain`: nil-policy or empty allowlist ⇒ allow-any; else case-insensitive domain-suffix match after the last `@`.

**As established in §7.4: neither validation function has any call site in `RegisterUseCase` or `CreateUserUseCase`** — fully implemented and unit-tested (`policy_enforcer_test.go`), but not wired into any signup/user-creation flow. Only `RequireMFA` is actually enforced anywhere, and only inside `LoginUseCase`.

### 15.4 `app/slug_service.go` — `SlugService`
```go
const maxSlugAttempts = 5
func (s *SlugService) GenerateUniqueSlug(ctx, base string) (string, error)
```
Tries `base`, then `base-1`..`base-5`; error after 5 collisions. Used exclusively by `RegisterUseCase`.

### 15.5 `infra/postgres/`
`PolicyRepository.Get`: on `pgx.ErrNoRows`, returns `DefaultPolicy()` with `TenantID` stamped — never a raw not-found error, matching the "never nil" contract. `Upsert`: `INSERT ... ON CONFLICT(tenant_id) DO UPDATE`.

### 15.6 `middleware/tenant.go` — `ResolveTenant` — **dead code**
```go
func ResolveTenant(next http.Handler) http.Handler
```
Reads `MustPrincipal` (panics if missing — must run after auth middleware), stores `p.TenantID` under the separate `shared/tenancy` context key. **Never registered in `main.go`** — grep-confirmed zero references outside its own definition. Live tenant scoping happens by handlers reading `p.TenantID` directly off the `Principal`, not through this middleware or the `tenancy` context key.

### 15.7 `transport/http/policy_handler.go`
- `Get` (`GET /tenant/policy`, withAuth only — no specific permission): `enforcer.Get(ctx, p.TenantID)` → JSON.
- `Put` (`PUT /tenant/policy`, withAuth + `tenant:update`): builds `Policy{TenantID:p.TenantID, ...}` (server-enforced tenant scoping, ignoring any client-supplied tenant field), floors `PasswordMinLength` to 8 if ≤0, `repo.Upsert` directly (bypassing the enforcer's `Get` since this is a write path).

### 15.8 Runtime application
The **only** place tenant policy is actually consulted at runtime is `LoginUseCase.Execute`: `policyEnforcer.Get(user.TenantID)` → if `RequireMFA && no verified factors` → block login (403) until MFA enrollment. That's the entirety of live policy enforcement.

---

## 16. `internal/identity/` — identity & user management

Two-level model: global `Identity` (one per human, unique email, holds credentials) vs. tenant-scoped `User` (one per `(tenant, identity)` pair).

> **⚠ Post-split**: `internal/identity` is now spread across two binaries. `cmd/identity-service` (§3.2) is the only binary that constructs `identitypostgres.NewRepository` (Identity's Postgres adapter) — it owns the `identities` table exclusively at the network-API level (Postgres itself is still shared, per §0/§29). `cmd/iam-server` still constructs `postgresuser.NewRepository` directly (the `User`/tenant-membership table stays with iam-server, since it's tenant-scoped data iam-server's own RBAC/tenant logic needs locally) but reaches `Identity` only through `internal/identity/infra/httpclient` (§29.1). `cmd/mfa-service` also uses the same httpclient for identity lookups (email for TOTP/WebAuthn). This means `identitydomain.Repository` now has **two** production implementations — `infra/postgres` (used only inside identity-service) and `infra/httpclient` (used by both iam-server and mfa-service) — versus `identitydomain.UserRepository`, which still has exactly one (`infra/postgresuser`, used only inside iam-server; `User` data never moved).

### 16.1 `domain/identity.go` + `repository.go`
```go
type Identity struct{ ID, PrimaryEmail, Status string; EmailVerified bool; CreatedAt, UpdatedAt time.Time }
type Repository interface {
    Create(ctx context.Context, identity *Identity) error
    GetByEmail(ctx context.Context, email string) (*Identity, error)
    GetByID(ctx context.Context, id string) (*Identity, error)
    Delete(ctx context.Context, id string) error   // ⚠ new, added for the register/create-user compensating-delete saga (§7.5, §16.4, §29.2)
}
```

### 16.2 `domain/user.go` + `user_repository.go`
```go
type User struct{ ID, TenantID, IdentityID, Username, DisplayName, Status string; CreatedAt, UpdatedAt time.Time }
type UserRepository interface{
    Create; GetByID; GetByTenantAndIdentity; GetByIdentityID; GetByTenantAndID; ListByTenant
}
```

### 16.3 `app/create_identity.go` — **dead code**
`CreateIdentityUseCase.Execute` builds and persists a bare `Identity`. **Never invoked from `main.go`** — `RegisterUseCase` and `CreateUserUseCase` both create identities inline with their own logic instead. Possibly a placeholder for a future standalone admin "create identity" endpoint.

### 16.4 `app/create_user.go` — `CreateUserUseCase` (the live, wired flow, still hosted in `cmd/iam-server`)

> **⚠ Post-split, same saga pattern as §7.5's `RegisterUseCase`**: `identityRepo.Create` moved outside the local transaction, with a compensating `identityRepo.Delete` on failure. This use case stays wired in `cmd/iam-server` (not moved to identity-service) precisely because it needs to mix the HTTP-client identity repo with local-Postgres `credentialRepo`/`userRepo`/`roleRepo`/`userRoleRepo` in one flow — it's a cross-cutting use case, not identity-service's own concern.

```go
type CreateUserInput struct{ TenantID, Email, Password, DisplayName, RoleName string }
func (u *CreateUserUseCase) Execute(ctx, input) (*identitydomain.User, error)
```
**Exact current flow:**
1. Build `identity`.
2. **Outside** `txManager.WithinTransaction`: `if err := u.identityRepo.Create(ctx, identity); err != nil { return nil, err }` — identical comment/rationale to `RegisterUseCase` step 2 (§7.5): this is a network call to identity-service and needs no compensation of its own if it fails.
3. Enter `u.txManager.WithinTransaction(ctx, func(txCtx) error {...})`: `password.Hash` → create `Credential` → build `identitydomain.User{TenantID: input.TenantID, ...}` (the **caller's own tenant**, from `Principal.TenantID` at the handler level) → `userRepo.Create` → `roleRepo.GetByTenantAndName(txCtx, input.TenantID, input.RoleName)` — **the named role must already exist in the caller's tenant; no auto-creation, no default-role fallback** — if missing, the whole transaction rolls back → `userRoleRepo.AssignRole`.
4. On transaction failure, the same compensating-delete block as `RegisterUseCase` (§7.5), with a `create_user:`-prefixed log message and wrapped error instead of `register:`:
   ```go
   if delErr := u.identityRepo.Delete(ctx, identity.ID); delErr != nil {
       slog.Error("create_user: failed to compensate for orphaned identity after transaction failure", ...)
       return nil, fmt.Errorf("create_user: transaction failed (%w) and compensating identity delete also failed for identity %s: %w", err, identity.ID, delErr)
   }
   return nil, err
   ```
5. On success, `return created, nil`.

Both `RegisterUseCase` and `CreateUserUseCase` now implement the *identical* "outside-tx create, on-failure compensating delete" saga — same log-message shape, same double-failure wrapped-error format — differing only in which local rows get created inside the transaction (new tenant + owner role vs. existing tenant + pre-existing named role).

### 16.5 `app/get_user.go` / `list_users.go`
Tenant-scoped reads (`GetByTenantAndID`, `ListByTenant`) — cannot fetch/list another tenant's users. Unaffected by the split — these only ever touched `UserRepository` (still local Postgres), never `identitydomain.Repository`.

### 16.6 `infra/postgres/repository.go` (Identity) and `infra/postgresuser/repository.go` (User — note distinct package name to avoid collision)

> **⚠ Post-split**: `infra/postgres` (Identity) is now constructed **only** inside `cmd/identity-service` (§3.2) — iam-server and mfa-service reach it exclusively through `infra/httpclient` (§29.1). `infra/postgresuser` (User) is unaffected — still constructed only inside `cmd/iam-server`.

Identity's `Create` specifically catches `pgerrcode.UniqueViolation` (duplicate email) and translates to `sharederrors.ErrConflict` — this now happens inside `identity-service`'s process, and its own transport handler (§29.2) maps `ErrConflict`→409, which the httpclient then maps back to `sharederrors.ErrConflict` client-side, preserving the same observable 409 at iam-server's `/users` and `/register` endpoints as before the split. **New method**: `Delete(ctx, id) error` — plain `DELETE FROM identities WHERE id = $1` via the same `r.executor(ctx)` ambient-tx helper as the other methods, with no `pgerrcode`/`sharederrors` mapping (a raw DB error passes through unmapped) — added specifically to back the compensating-delete saga (§7.5, §16.4). User repo: standard CRUD, `ListByTenant` ordered `ORDER BY created_at`, unchanged.

### 16.7 `transport/http/` — two distinct handler sets now live under this path across two services

- **`internal/identity/transport/http/handler.go`** (pre-existing, still hosted in `cmd/iam-server`): `CreateUser` (`POST /users`, `users:create`) → 201 + created user, or 409 on duplicate email. `ListUsers` (`GET /users`, `users:read`). `GetUser` (`GET /users/{userID}`, `users:read`) → 404 on any error (not found or otherwise). Unchanged in behavior — still the public-facing `/users` API, still permission-gated, still tenant-scoped via `Principal.TenantID`.
- **`internal/identity/transport/http/identity_handler.go`** (⚠ new, hosted only in `cmd/identity-service`, §3.2): `IdentityHandler` with `CreateIdentity`/`GetIdentityByEmail`/`GetIdentityByID`/`DeleteIdentity`, backing the `/internal/identities/...` routes that `infra/httpclient` calls. Unauthenticated (internal trust boundary), distinct route namespace (`/internal/identities` vs `/users`), distinct purpose (raw `Identity` CRUD for other services, not the tenant-scoped `User`-centric public API).

**Note**: no `users:update`/`users:delete` routes exist even though those permissions are bootstrapped for tenant owners — forward-looking/unused permissions with no corresponding HTTP surface today (unchanged by the split).

---

## 17. `internal/provisioning/` and `internal/serviceaccount/` — unimplemented

Both directories contain only the four empty subfolders `app/`, `domain/`, `infra/`, `transport/` — **zero Go files, confirmed via `find -type f`**. There is no SCIM-like provisioning flow and no service-account/machine-identity code anywhere in this repo (repo-wide grep for `ServiceAccount`/`serviceaccount`/`provisioning` outside these stub dirs returns nothing relevant).

Note that the `service_accounts` **table** does exist in the Postgres schema (migration 000001), but no application code reads or writes it — pure unused scaffolding, schema ahead of code.

The de facto "provisioning" flows that actually exist and are wired into the running server are `auth.RegisterUseCase` (provisions Identity+Tenant+User+owner-Role+bootstrap-Permissions in one shot, §7.5) and `identity.CreateUserUseCase` (provisions an additional user inside an *existing* tenant, §16.4). There is no client-credentials OAuth grant or API-key mechanism distinct from human password/MFA/WebAuthn/session flows — `internal/oauth`'s authorization_code flow is still keyed to an authenticated human session, and would be the natural place a future service-account client-credentials grant gets added.

---

## 18. `internal/federation/`, `pam/`, `risk/`, `notification/`, `admin/` — unimplemented

All five directories are **completely empty** across every subfolder (`app/domain/infra/transport`, 0 files each), verified two ways: `find -type f` returns nothing, and `git log --all --oneline -- internal/<dir>` returns nothing for any of them — meaning these directories were never committed to git at all as anything but empty scaffolding (git doesn't track empty dirs; the folder trees exist on the filesystem only). A repo-wide grep for `federation`, `pam`, `risk`, `notification`, `admin` across `.go`/`.sql`/`.yaml`/`.md` turns up zero real hits outside these directories — the only incidental string matches are unrelated (`authadmin` as the Postgres username, and an `"admin'--"` SQL-injection test payload in `test/security/security_test.go`).

Concretely, this means: **no federated/external-IdP login, no PAM/break-glass/elevation workflow, no risk scoring/adaptive auth, no email/SMS/push notification sending, and no admin API** exist anywhere in the codebase as of this writing. `TRADEOFFS.md` §18 lists all five as explicitly deferred roadmap items (federation/SCIM → v0.12.0/v0.13.0, risk scoring → v0.14.0), consistent with this finding — this is intentional phased scope, not an oversight in the exploration.

> **⚠ Re-verified for this revision (post identity/mfa split):** `internal/federation/` and `internal/notification/` were independently re-confirmed to still be **completely empty of code** — `find internal/federation internal/notification -type f` returns zero results in the current tree, and both still contain only the four scaffolded empty subfolders (`app/`, `domain/`, `infra/`, `transport/`). The 3-service split touched only `identity` and `mfa`/`webauthn`; it did not add, remove, or populate any of these five directories.

---

## 19. `internal/audit/` — async audit logging

The **only** one of the six §18-adjacent modules with real code.

### 19.1 `domain/event.go`
```go
const (
    EventLogin="auth.login"; EventLoginFailed="auth.login_failed"; EventLogout="auth.logout"
    EventRefresh="auth.refresh"; EventRegister="auth.register"
    EventMFAEnrolled="mfa.enrolled"; EventMFAVerified="mfa.verified"; EventMFAComplete="mfa.complete"
    EventOAuthAuthorize="oauth.authorize"; EventOAuthToken="oauth.token"; EventOAuthCodeReused="oauth.code_reused"
)
type Event struct {
    ID, TenantID, ActorIdentityID, EventType, ResourceType, ResourceID, IPAddress string
    Payload json.RawMessage
    CreatedAt time.Time
}
type Repository interface{ Insert(ctx, *Event) error }
```
These event-type constants anticipate audit coverage of login/logout/refresh/register/MFA/OAuth flows, **but none of `internal/auth`, `internal/mfa`, or `internal/oauth`'s handlers actually reference these constants or call the publisher** (repo-wide grep confirms zero real call sites).

### 19.2 `app/publisher.go` — `Publisher`
```go
const Subject = "audit.events"
func (p *Publisher) Emit(e *domain.Event)   // fire-and-forget, non-blocking, never errors
```
Fills `ID`/`CreatedAt` if unset, JSON-marshals, publishes to NATS. Any marshal/publish error is `slog.Warn`-logged and swallowed — deliberately, per the package comment: "we never want audit instrumentation to slow down the auth path." Nil-guards on both `p` and `p.conn`.

### 19.3 `app/consumer.go` — `Consumer`
```go
func (c *Consumer) Subscribe(ctx) (*natsgo.Subscription, error)
```
Subscribes to `audit.events`; on each message, unmarshals to `domain.Event` (drop+log on bad JSON), `repo.Insert` (log+drop on DB failure, no retry). Returns the subscription for clean `Unsubscribe()` on shutdown.

### 19.4 `infra/postgres/repository.go`
`Insert`: parameterized `INSERT INTO audit_events (...)`, converts empty-string optional fields to Go `nil` before binding so they land as SQL `NULL`; `IPAddress` cast to `inet` via `$7::inet`.

### 19.5 The wiring gap
In `cmd/iam-server/main.go`:
```go
auditPublisher := auditapp.NewPublisher(msgBus)
_ = auditPublisher // emit calls added in handlers/use cases in follow-up; keep for now
```
The publisher is constructed and immediately discarded. **The producer side was never actually connected** — the entire pipeline (NATS pub/sub, Postgres persistence, worker consumer wiring) is built and independently testable, and `cmd/worker` runs the consumer correctly, but in the live running system today **no code path ever calls `Emit`**, so **zero rows would ever land in `audit_events`** despite the table, consumer, and worker all being ready to receive them. `THREAT_MODEL.md` #25 ("audit log tampering") and the broader "durable audit trail" narrative in `DESIGN.md`/`changelogs/v0.8.0` describe the intended architecture; this is the one place where intent and current wiring diverge.

---

## 20. Complete HTTP route table

> **⚠ Post-split: this is now three separate route tables on three separate ports**, not one. See §29.4 for the consolidated cross-service view with a topology diagram; the tables below are the per-binary breakdown.

### 20.1 `cmd/iam-server` (port `HTTP_PORT`, default 8080) — public-facing auth gateway

`withAuth = authMiddleware.Authenticate`; `withPerm(p) = authorizationmiddleware.RequirePermission(p)` (always chained after `withAuth`). **`/mfa/*` and `/webauthn/*` are no longer registered here** — moved to mfa-service (§20.3).

| Method | Path | Auth | Handler |
|---|---|---|---|
| GET | `/health` | public | inline liveness check |
| POST | `/register` | public | `authhttp.Handler.Register` |
| POST | `/login` | public | `authhttp.Handler.Login` |
| POST | `/refresh` | public | `authhttp.Handler.Refresh` |
| GET | `/.well-known/jwks.json` | public | `tokenhttp.Handler.JWKS` |
| GET | `/.well-known/openid-configuration` | public | `oidchttp.Handler.Discovery` |
| GET | `/metrics` | public | `metrics.Handler()` (Prometheus) |
| POST | `/oauth/token` | public (client-authed via Basic/body) | `oauthhttp.Handler.Token` |
| GET | `/me` | withAuth | `authhttp.Handler.Me` |
| POST | `/logout` | withAuth | `authhttp.Handler.Logout` |
| GET | `/oauth/authorize` | withAuth | `oauthhttp.Handler.Authorize` |
| GET | `/oauth/userinfo` | withAuth | `oidchttp.UserInfoHandler.UserInfo` |
| GET | `/tenant/policy` | withAuth | `tenanthttp.PolicyHandler.Get` |
| PUT | `/tenant/policy` | withAuth + `tenant:update` | `tenanthttp.PolicyHandler.Put` |
| GET | `/users` | withAuth + `users:read` | `identityhttp.Handler.ListUsers` |
| GET | `/users/{userID}` | withAuth + `users:read` | `identityhttp.Handler.GetUser` |
| POST | `/users` | withAuth + `users:create` | `identityhttp.Handler.CreateUser` |
| POST | `/roles` | withAuth + `roles:create` | `authorizationhttp.Handler.CreateRole` |
| GET | `/roles` | withAuth + `roles:read` | `authorizationhttp.Handler.ListRoles` |
| POST | `/roles/{roleID}/permissions` | withAuth + `roles:update` | `authorizationhttp.Handler.AssignPermission` |
| GET | `/roles/{roleID}/permissions` | withAuth + `roles:read` | `authorizationhttp.Handler.ListRolePermissions` |

### 20.2 `cmd/identity-service` (port `IDENTITY_HTTP_PORT`, default 8081) — ⚠ new, internal-only

No CORS, no `withAuth` (trust boundary = network reachability, not an auth check).

| Method | Path | Handler |
|---|---|---|
| GET | `/health` | inline liveness |
| GET | `/metrics` | `metrics.Handler()` |
| GET | `/internal/identities/by-email?email=` | `identityHandler.GetIdentityByEmail` |
| GET | `/internal/identities/{id}` | `identityHandler.GetIdentityByID` |
| POST | `/internal/identities` | `identityHandler.CreateIdentity` |
| DELETE | `/internal/identities/{id}` | `identityHandler.DeleteIdentity` |

### 20.3 `cmd/mfa-service` (port `MFA_HTTP_PORT`, default 8082) — ⚠ new; mixes end-user and internal routes

No CORS. `withAuth` here is mfa-service's own re-constructed `authmiddleware.NewAuthenticationMiddleware` (§3.3) — same JWT/session verification logic as iam-server's, independently instantiated.

| Method | Path | Auth | Handler |
|---|---|---|---|
| GET | `/health` | public | inline liveness |
| GET | `/metrics` | public | `metrics.Handler()` |
| POST | `/mfa/complete` | public | `mfahttp.Handler.Complete` |
| POST | `/webauthn/login/begin` | public | `wahttp.Handler.LoginBegin` |
| POST | `/webauthn/login/complete` | public | `wahttp.Handler.LoginComplete` |
| POST | `/internal/mfa/factors` | internal | `mfaInternalHandler.CreateFactor` |
| GET | `/internal/mfa/factors/by-identity?identity_id=` | internal | `mfaInternalHandler.GetFactorsByIdentity` |
| GET | `/internal/mfa/factors/verified?identity_id=` | internal | `mfaInternalHandler.GetVerifiedFactorsByIdentity` |
| GET | `/internal/mfa/factors/{id}` | internal | `mfaInternalHandler.GetFactorByID` |
| POST | `/internal/mfa/factors/{id}/verify` | internal | `mfaInternalHandler.MarkFactorVerified` |
| DELETE | `/internal/mfa/factors/{id}` | internal | `mfaInternalHandler.DeleteFactor` |
| POST | `/internal/mfa/challenges` | internal | `mfaInternalHandler.StoreChallenge` |
| POST | `/internal/mfa/challenges/consume` | internal | `mfaInternalHandler.ConsumeChallenge` |
| POST | `/mfa/enroll/totp` | withAuth | `mfahttp.Handler.EnrollTOTP` |
| POST | `/mfa/enroll/verify` | withAuth | `mfahttp.Handler.VerifyEnrollment` |
| GET | `/mfa/factors` | withAuth | `mfahttp.Handler.List` |
| POST | `/webauthn/register/begin` | withAuth | `wahttp.Handler.RegisterBegin` |
| POST | `/webauthn/register/complete` | withAuth | `wahttp.Handler.RegisterComplete` |
| GET | `/webauthn/credentials` | withAuth | `wahttp.Handler.List` |

No `users:update`/`users:delete` routes exist despite those permissions being bootstrapped. No admin, federation, PAM, risk, notification, provisioning, or service-account routes exist (§17, §18). No route on any of the three services performs cross-service authentication delegation — a client must independently authenticate (present the same Bearer JWT or `X-Session-ID`) against whichever service it calls directly; iam-server does not forward or attach caller identity when it makes its own internal HTTP calls to identity-service/mfa-service (those internal routes are unauthenticated by design, §29.1).

---

## 21. End-to-end execution flow traces

> **⚠ Post-split**: traces below are updated to show the network hops introduced by the identity/mfa split. Every hop labeled **[HTTP →]** is a new inter-service call that did not exist pre-split; everything else is the original in-process call chain, unchanged.

### 21.1 Password login → session + tokens (updated: now involves a network call to identity-service, and to mfa-service if MFA is required)

`POST /login` (on `cmd/iam-server`, port 8080) → `authhttp.Handler.Login` → decode+validate → `extractIP`+`UserAgent` → `authapp.LoginUseCase.Execute`:
1. **[HTTP → identity-service]** `identityRepo.GetByEmail` — iam-server's `identityhttpclient.Repository` issues `GET {IDENTITY_SERVICE_URL}/internal/identities/by-email?email=...` to `cmd/identity-service` (port 8081); a 404 there maps to `sharederrors.ErrNotFound` client-side, then masked to `ErrInvalidCredentials` by `LoginUseCase` (unchanged enumeration-prevention behavior — see §29.1 for the exact mapping).
2. `credentialRepo.GetByIdentityID` — still direct Postgres (credentials table stays with iam-server).
3. `password.Verify` (Argon2id) — unchanged, in-process.
4. `userRepo.GetByIdentityID` → tenant-scoped `User` — still direct Postgres (`postgresuser`, stays with iam-server).
5. `policyEnforcer.Get` — still direct Postgres.
6. **[HTTP → mfa-service]** `mfaRepo.GetVerifiedByIdentity` — iam-server's `mfahttpclient.Repository` issues `GET {MFA_SERVICE_URL}/internal/mfa/factors/verified?identity_id=...` to `cmd/mfa-service` (port 8082). If factors exist: **[HTTP → mfa-service]** `mfaChallengeStore.Store` — `POST {MFA_SERVICE_URL}/internal/mfa/challenges` — [MFA branch continues at §21.2] → returns `{mfa_required:true, mfa_token}`, **no session yet**. Else: proceed straight through.
7. `userRoleRepo`/`rolePermissionRepo` → generate+hash refresh token → `sessionRepo.Create` — all still direct Postgres.
8. Build `Principal` → `tokenapp.JWTService.Issue` (fetch active key, build Claims, sign, `kid` header) — still direct Postgres + in-process, unchanged — → `LoginOutput`.

Handler sets refresh cookie **and** returns it in JSON, unchanged. Subsequent requests: `AuthenticationMiddleware.Authenticate` (Bearer stateless verify — no network call, JWT is self-contained; **or** `X-Session-ID` via cache-then-DB-join, where the identity lookup step is now **[HTTP → identity-service]** on a principal-cache miss) injects `Principal` into context for downstream handlers/middleware. Net effect: a bearer-token request that hits the Redis principal cache still makes zero cross-service calls; a cold password login always makes at least one (identity-service), and two if MFA is enrolled (identity-service + mfa-service).

### 21.2 TOTP MFA enrollment + login completion (updated: entirely hosted on mfa-service now, reached on its own port)

Enroll and complete are **no longer reachable through iam-server at all** — a client calls `cmd/mfa-service` (port 8082) directly for all of this except the initial `/login` call that produces the `mfa_token` (§21.1, step 6, still on iam-server).

Enroll: `POST /mfa/enroll/totp` (on mfa-service) → `TOTPService.Enroll` (random secret, unverified Factor persisted to the shared Postgres `mfa_factors` table, mfa-service connects directly) → `POST /mfa/enroll/verify` → `totp.Validate` → `MarkVerified`. Login completion: `POST /mfa/complete {mfa_token, code}` (on mfa-service) → `ChallengeStore.Consume` (mfa-service's own direct Redis connection, atomic GETDEL, single-use — wrong code here forces a full login restart from iam-server's `/login`) → expiry re-check → `TOTPService.Verify` (checks against every verified factor, in-process against mfa-service's own Postgres) → mfa-service builds its **own** `Session`/JWT (it has direct access to `sessionpostgres` and `tokenapp.JWTService`, using the same shared signing-key table iam-server uses) — session/JWT issuance is structurally identical to §21.1's tail but executed inside a different process. The `mfa_token` itself crossed no additional network hop at completion time (it's presented by the client directly to mfa-service, which already owns the challenge it maps to via its own Redis store — the earlier `Store` call in §21.1 step 6 was the only cross-service hop in this whole flow).

### 21.3 WebAuthn registration + passwordless login (updated: entirely hosted on mfa-service, iam-server has zero involvement)

All five WebAuthn endpoints are served exclusively by `cmd/mfa-service` (port 8082) — iam-server registers none of these routes and makes no calls into this flow at any point (§13's post-split note). Registration: `POST /webauthn/register/begin` (authed against mfa-service's own auth middleware) → `Service.BeginRegistration` (stable userHandle — resolved via **[HTTP → identity-service]** through the same `identityhttpclient.Repository` mfa-service constructs for itself, resident-key-required options, challenge stored in mfa-service's own Redis via opaque sessionKey) → browser `navigator.credentials.create()` → `POST /webauthn/register/complete` → `Service.FinishRegistration` (consume session, full attestation verification: clientData type/challenge/origin, CBOR attestationObject, rpIdHash, UP/UV flags, attestation-statement signature) → persist `Credential` to mfa-service's direct Postgres connection. Login: `POST /webauthn/login/begin` (public, on mfa-service) → `BeginDiscoverableLogin` (empty allowCredentials, usernameless) → browser `navigator.credentials.get()` → `POST /webauthn/login/complete` → `Service.FinishLogin` (consume session, resolve identity via `userHandle` callback — another **[HTTP → identity-service]** call — verify assertion signature, check-but-not-enforce sign-count) → `waapp.LoginUseCase.Complete` → mfa-service issues its own session/JWT directly (same pattern as §21.2's completion — no IP recorded, unlike password/MFA paths, unchanged from pre-split). A full passkey login therefore makes exactly one cross-service hop (to identity-service, to resolve the identity behind the presented `userHandle`), entirely within mfa-service's process — the calling browser/client only ever talks to mfa-service's port, never iam-server's, for this entire flow.

### 21.4 OAuth2 Authorization Code + PKCE, `/authorize` → `/token`
Client generates `code_verifier`/`code_challenge=S256(verifier)`. User must already hold a session. `GET /oauth/authorize?...` (withAuth) → `AuthorizeUseCase.Execute` (response_type/PKCE-mandatory/S256-only/client lookup/exact redirect_uri/grant-type/scope/tenant-match validation chain) → generate code, `codeStore.Store` (Redis, 10min TTL) → 302 redirect with `code`+`state` (or error redirect). Client backend: `POST /oauth/token {grant_type:authorization_code,...}` with Basic-auth or body client creds → `TokenUseCase.authorizationCodeGrant`: client lookup, constant-time secret compare, `codeStore.Consume` (atomic GETDEL — single-use), expiry/client_id/redirect_uri checks, `verifyPKCE` (sha256+base64url+constant-time compare), identity/roles/permissions load, new unparented `Session`, JWT issue with `Audience:[clientID]`, and (if `openid` scope) `IDTokenService.IssueIDToken` via the `IDTokenIssuer` interface. Refresh: `POST /oauth/token {grant_type:refresh_token,...}` → `refreshTokenGrant` (hash lookup, revoke old, chain new session, reissue — **no re-issued `id_token`** even for originally-`openid` grants).

### 21.5 OIDC discovery + ID token + UserInfo
`GET /.well-known/openid-configuration` (public, static JSON) → client drives §21.4's flow with `scope=openid ...&nonce=...` → token exchange includes `id_token` (built by stripping Roles/Permissions from the Principal, signed via the same `JWTService.Issue`, same `kid`/algorithm as access tokens, embedding the client's `nonce`) → client either validates the ID token itself via `/.well-known/jwks.json`, or calls `GET /oauth/userinfo` (withAuth, accepts Bearer or session-header) which derives `sub`/`email` from context `Principal` and live-enriches `email_verified`.

### 21.6 RBAC: creating a role and assigning permissions, and the authorization decision path
`POST /roles` (withAuth+`roles:create`) → `CreateRoleUseCase` (dedup on `(tenant,name)` → `ErrConflict`/409, else create). `POST /roles/{roleID}/permissions` (withAuth+`roles:update`) → `AssignPermissionToRoleUseCase` (role lookup, tenant-ownership check → `ErrForbidden`, permission-by-name lookup — must pre-exist, insert join row). Reading back: `GET /roles/{roleID}/permissions` → `GetPermissionsForRole` join query. **The authorization decision itself** (`RequirePermission` middleware) never touches the DB — it inspects `Principal.Permissions`, which were resolved once either at JWT-issue time (bearer path, stale for up to the JWT's 15-min lifetime) or at session Principal-resolution/cache time (session-header path, stale for up to the 5-min cache TTL). A newly assigned permission therefore does not retroactively affect already-issued tokens or cached principals.

### 21.7 Tenant resolution and policy enforcement
There is **no dedicated "resolve tenant from request" step** distinct from authentication — `Principal.TenantID` (populated from JWT claims or the session row) *is* the tenant-resolution mechanism; the dedicated `tenant.middleware.ResolveTenant` exists but is dead code (§15.6). Policy read: `GET /tenant/policy` (withAuth only) → `PolicyEnforcer.Get` → DB (defaults if no row). Policy write: `PUT /tenant/policy` (withAuth+`tenant:update`) → server-enforced `TenantID` from Principal → `Upsert`. Runtime enforcement is limited to `LoginUseCase`'s `RequireMFA` check (§21.2) — `ValidatePassword`/`ValidateEmailDomain` are unused dead functions (§15.3, §27).

### 21.8 Provisioning a new user/identity, end to end (updated: now a saga across two services, with a compensating-delete failure path)

Self-service signup (`RegisterUseCase`, §7.5): **[HTTP → identity-service, outside any local transaction]** `identityRepo.Create` (`POST /internal/identities`) → *then* Credential+**new Tenant**+User+bootstrapped-owner-Role+10-permission-bootstrap+UserRole, all in **one local Postgres transaction on iam-server** → no session issued, caller must separately log in. **Failure path (new):** if any step of the local transaction fails, iam-server issues **[HTTP → identity-service]** `identityRepo.Delete` (`DELETE /internal/identities/{id}`) to remove the now-orphaned identity row; if that compensating call *also* fails, the identity is left permanently orphaned in identity-service's database (no session/tenant/user/credential anywhere referencing it) and both failures are wrapped into the single error returned to the caller — see §7.5 for the exact code and §27 for this as a cataloged residual gap.

Admin-driven additional user (`CreateUserUseCase`, §16.4): identical saga shape — **[HTTP → identity-service, outside tx]** `identityRepo.Create` → Credential+User **in the caller's existing tenant** (role assignment requires a pre-existing role name, no auto-bootstrap) in one local transaction on iam-server → same compensating **[HTTP → identity-service]** `identityRepo.Delete` on local-transaction failure.

Both flows now make **at least one, and on any local failure exactly two,** cross-service HTTP round trips to identity-service — versus zero pre-split, when identity creation was just another statement inside the single local transaction.

### 21.9 Service-account creation and differentiated machine authentication
**Not implemented** (§17) — no distinct flow exists; the nearest analog is `internal/oauth`'s authorization_code grant, which is still keyed to a human session.

---

## 22. `test/` — the ten-layer test pyramid

> **⚠ Major finding of this revision: the test suite has NOT been updated for the 3-service split.** A repo-wide grep across all of `test/` for `identity-service`, `mfa-service`, `IDENTITY_SERVICE_URL`, `MFA_SERVICE_URL`, `8081`, `8082`, `IdentityHTTPPort`, or `MFAHTTPPort` returns **zero matches**. Every layer below — integration, security, smoke, stress, spike, soak, A/B — still targets a single `BASE`/`AUTH_BASE_URL` env var defaulting to `http://localhost:8080` (i.e. `iam-server` alone), including `test/integration/mfa_test.go` and `test/integration/webauthn_test.go`, whose target endpoints (`/mfa/enroll/totp`, `/mfa/complete`, `/webauthn/*`) **no longer exist on iam-server at all** post-split — they moved to `mfa-service` on port 8082 (§3.3, §20.3). Run as-is against a freshly-composed `docker-compose.yml` environment (where iam-server isn't even containerized — §30), these tests would fail or 404 on every MFA/WebAuthn assertion unless the operator manually runs iam-server locally *and* separately arranges for it to proxy or the tester points `AUTH_BASE_URL` somewhere that serves all of it (which nothing does — see §3.1's confirmation that iam-server proxies nothing). `test/integration/dbhelper.go` also still assumes unrestricted direct Postgres access from the test process for fixture setup, which remains true (Postgres is still shared, §0), but the HTTP-level assumptions are stale. Treat every "against a live running server" description below as **pre-split-accurate and currently broken for MFA/WebAuthn** until the test suite is updated to either (a) run iam-server + identity-service + mfa-service together and target each on its own port, or (b) split the test files themselves along service lines. See §29.5 for further discussion.

Per `run-all.sh`, ordered, stop-on-first-failure: **[1] unit** (`go test ./internal/...`) → **[2] race** (`race.sh`: `-race -count=1` across `internal/...` and `test/integration/...`) → **[3] fuzz smoke** (5s each of 5 fuzz targets, 3s for one) → **[4] smoke** (`smoke.sh`, pure bash+curl, 21 checks) → **[5] integration** (`test/integration/...`, against a live server) → **[6] security** (`test/security/security_test.go`) → **[7] stress w/ SLA** → **[8] spike** → **[9] A/B** → **[10] coverage** (`coverage.sh`).

### 22.1 `test/integration/` — 5 test files + 2 shared helpers, all against a **live running server**
- **`client.go`**: `Client` struct tracking AccessToken/RefreshToken/SessionID/TenantID/UserID/Email across calls; `Register`/`Login`/`LoginExpect`; auto-Bearer-attaching `Get`/`Post`; `PKCEPair()`; `UniqueEmail(prefix)` (nanosecond-timestamped, enables test parallelism).
- **`dbhelper.go`**: shared `pgxpool.Pool`, `t.Skip`s (not fails) if DB unreachable; `CreateOAuthClientForTenant` directly inserts a test OAuth client row, bypassing any admin API (none exists).
- **`auth_test.go`** (8 tests): register→login→me; session-header fallback auth; **refresh rotates and old-token-reuse is rejected**; logout invalidates session; register validation table; JWKS shape; OIDC discovery shape; unauthorized-access table across 5 protected routes.
- **`mfa_test.go`** (3 tests): full TOTP flow with a real generated code; wrong-code rejected; factors list. **⚠ Targets `AUTH_BASE_URL` (iam-server, 8080) — but these routes now live only on mfa-service (8082); will 404 against the split topology unless pointed there manually.**
- **`oauth_test.go`** (7 tests): full PKCE handshake; wrong-verifier rejected; **code-reuse rejected**; missing-PKCE still redirects but with `error=`; refresh_token grant rotates; userinfo returns matching sub/email. A historical `coverage/integration.log` run shows 4 of these OAuth tests failing with `error=invalid_client` — a captured point-in-time regression/flakiness in test fixtures, not necessarily current.
- **`webauthn_test.go`** (3 tests, server-side only — "requires a real authenticator... we can only verify server-side challenge generation"): register-begin options shape; login-begin discoverable-challenge shape; empty credentials list for a fresh user. **⚠ Same staleness as `mfa_test.go` — these endpoints are mfa-service-only post-split.**
- **`tenant_policy_test.go`** (4 tests + Prometheus assertions): defaults; PUT updates; **`require_mfa=true` blocks a new login without an enrolled factor (403)**; `/metrics` returns Prometheus format containing `auth_http_requests_total`; principal-cache hit/miss counters visible in `/metrics` after two session-header `/me` calls.

### 22.2 `test/security/security_test.go` — 10 tests, explicit category comment header (JWT/SQLi/brute-force/header-injection/timing/CORS/PKCE)
1. `alg:none` JWT → 401. 2. Tampered-payload JWT → 401. 3. Garbage/empty/very-long Bearer → 401. 4. 6 classic SQLi payloads via login email → never 200/500. 5. SQLi-looking tenant_name accepted literally, server stays healthy. 6. 20 wrong-password attempts, **not asserted to fail** — logs `"KNOWN GAP... Tracked for v0.8.0"` (still open as of the codebase's actual v0.9.0 state — the gap outlived its original target version). 7. CRLF in email field must not inject an `X-Injected` header. 8. Timing comparison (real-wrong-password vs nonexistent-user, 7 samples each) — **quantified in `testdocs`/`THREAT_MODEL.md` at ~62× ratio (95ms vs 1.5ms)**, logged as `"KNOWN GAP: login time leaks account existence"`, informational not hard-failing. 9. CORS preflight with a hostile Origin must not be reflected verbatim. 10. `code_challenge_method=plain` must never succeed.

### 22.3 `test/abtest/main.go` — statistical A/B harness
Compares stateless-JWT `/me` (Variant A) vs `X-Session-ID` DB-backed `/me` (Variant B, 4 sequential DB reads pre-cache / cache-hit post-v0.8.0), interleaved per worker to cancel transient noise. Computes a **Welch two-sample t-test** with Welch-Satterthwaite degrees of freedom, reports significance bands and a winner. Flags: `-concurrency` (default 50 pairs), `-duration` (default 15s).

### 22.4 `test/soak/main.go` — endurance
Steady worker pool against `GET /me` for `-duration` (default 5m), per-`-bucket` (default 30s) p50/p95/p99/fail%/heap-size reporting via `runtime.ReadMemStats`. `-sla-drift-pct`: compares first-vs-last-bucket p99, exits 2 on breach ("DRIFT SLA BREACH"). Goal: catch slow leaks (memory, connections, FDs) that short tests miss.

### 22.5 `test/spike/main.go` — burst
Three phases (baseline → burst → recovery), `atomic.Pointer[phase]` lets worker goroutines record into the correct phase's stats without a mutex. SLA flags `-sla-burst-fail-pct` (default 5%), `-sla-recovery-p99` — breach exits 2 ("SPIKE SLA BREACH").

### 22.6 `test/stress/main.go` — throughput/latency load generator
Scenarios: `login` (full Argon2+DB+JWT), `jwt-verify` (stateless), `session-auth` (4-DB-read/cache path), `jwks`, `oauth-token` (full PKCE handshake incl. Redis), `mixed` (70/20/10 weighted). `-warmup` excluded from stats. SLA flags `-sla-p95/-p99/-fail-pct/-min-rps`, plus a default 1%-fail-rate guard even without explicit flags — any breach exits 2.

### 22.7 Shell harnesses
- **`smoke.sh`**: 21 curl-based pass/fail checks, colorized, exits 1 on any failure.
- **`run-all.sh`**: the master 10-layer orchestrator described above.
- **`coverage.sh`**: unit-only coverage (`-coverpkg=./internal/...`), top-20-file report; explicitly notes integration/smoke/security tests **don't** contribute to in-process counters (would need a `-cover`-built binary + graceful shutdown to flush — neither exists, hence the low 7.7% headline coverage number being structurally misleading, not a quality signal).
- **`race.sh`**: `-race -count=1` across `internal/...` + `test/integration/...`.

### 22.8 `test/fuzz/` and `test/e2e/` — empty directories
Real fuzz targets live inline as `*_fuzz_test.go` files inside `internal/oauth/app/`, `internal/token/app/`, `internal/shared/password/` (not under `test/fuzz/`, which is empty). `test/e2e/` has no files at all.

---

## 23. `web/`, `coverage/`, `configs/`, `deployments/`, `api/`, `scripts/`, `tools/`, `docs/` — empty scaffolding

- **`web/admin/`, `web/login/`**: completely empty — no frontend code, no `package.json`, nothing. `TRADEOFFS.md` §18 lists an admin UI as explicitly "never, out of repo scope" — consistent with these being deliberate non-goals rather than unstarted work.
- **`coverage/runtime/`**: empty (runtime/HTTP-level coverage requires a `-cover`-built binary + graceful shutdown, neither implemented — tracked since `coverage.sh`'s own v0.8.0-era comment, still open). The parent `coverage/` directory (not `runtime/`) does hold historical artifacts from a May-31 test run: `coverage.out`/`unit.out` (1054 lines, `mode: atomic`), `coverage.html` (255KB), `runtime.out` (**0 bytes**, confirming the gap), a 19.5MB coverage-instrumented `iam-server-cov` binary, `server.log`/`smoke.log` (21/21 PASS)/`security.log` (all passed)/`integration.log` (shows the historical 4-test OAuth `invalid_client` failure noted in §22.1).
- **`configs/`, `deployments/`**: both entirely empty — no environment configs, no Docker Compose, no Kubernetes manifests, no Terraform.
- **`api/openapi/`, `api/proto/`**: both empty — no formal API contract artifacts exist; the contract lives implicitly in the chi route registrations and transport DTOs.
- **`scripts/`, `tools/`**: both empty.
- **`docs/`** (inside `auth-server/`, distinct from the root-level `.md` files): empty. The `.gitignore` even references a generated `ARCHITECTURE.md` "docs (generated, not versioned)" — implying a doc-generation workflow that intentionally isn't checked in, and hasn't produced anything checked into this directory either.

---

## 24. Root documentation summaries

These five files (at `custom-auth-server/`, one level above the Go module) are an unusually thorough internal engineering diary. Full summaries:

### 24.1 `DESIGN.md` (~18KB, 410 lines)
High-level architecture: clean-architecture pillars, domain map (matches §1's tree), ASCII sequence diagrams for password/MFA/policy-blocked/refresh/OAuth-PKCE/WebAuthn login flows, a token-strategy table (matches §9/§10 TTLs exactly), the `Principal` struct, v0.8.0 caching design, v0.8.0 observability design, v0.9.0 multi-tenancy/policy design, a crypto-parameters summary table, a failure-modes table (Redis-down/NATS-down/DB-down/mid-rotation/revoked-refresh/compromised-MFA-factor), a condensed tradeoffs table, a detailed roadmap (Identity&Access, OAuth Advanced, Security Hardening, FAPI groupings), and RFC/spec references (6749, 7636, 6238, 7519, 7517, 8414, OIDC Core 1.0, WebAuthn L3, OWASP ASVS v4 L2).

### 24.2 `IMPLEMENTATION.md` (~28KB, 665 lines)
Engineer-facing Go-idiom companion. Covers: typed context keys, interface segregation + in-memory test doubles, the Executor trick (§2 of this doc), Input-struct-per-use-case pattern, sentinel errors + `%w` wrapping, hand-wired-only DI, zero-alloc `slog.LogAttrs`, goroutine/channel patterns in `cmd/worker`, native fuzzing conventions (seed corpus via `f.Add`, regression corpus under `testdata/fuzz/`), light generics use. A layer-by-layer code tour with real snippets for password hashing, token generation, JWT service, OAuth authorize/token, auth middleware, principal cache, audit publisher, policy enforcer, metrics middleware. A persistence section explaining the `sessions.ip_address text` vs `audit_events.ip_address inet` inconsistency as documented tech debt. An HTTP request lifecycle diagram matching §3.1's middleware order exactly, with rationale (CORS-first for preflight short-circuit; logger/metrics before auth so final status is captured; auth before permission-check). A concurrency-primitives section. A 3-level error model. A testing deep-dive matching §22. A 12-row "common pitfalls → prevention mechanism" table. 13 numbered conventions for adding new code. A files-of-interest cross-reference table.

### 24.3 `TRADEOFFS.md` (~58KB, 841 lines) — 20-section staff-engineer audit
Every entry: Decision / Assumption / Alternatives / Reasoning / Cost / When-this-is-wrong / Revisit-trigger. Sections cover: architectural posture (modular monolith, clean architecture, hand-wired DI, domain-named packages); language/runtime (Go over Rust/Java/Node, stdlib bias, slog over zap); persistence (Postgres-only, pgx over `database/sql`, the Executor trick's risk of silently bypassing an open tx via `context.Background()`, the two-layer identity/user model, the `ip_address` type inconsistency, the dead `refresh_tokens` table, the nullable-`tenant_id` COALESCE trick); cache/messaging (Redis GetDel atomicity rationale, Principal-cache TTL tradeoff, NATS-Core-not-Kafka rationale and its at-most-once audit-drop consequence); HTTP layer (chi choice, middleware order rationale, **CORS wildcard flagged as a documented pre-prod blocker**, `statusRecorder` won't forward `Flusher`/`Hijacker` if SSE/websockets are ever added); identity/tenancy (app-level scoping over RLS, deferred to v0.15.0); authentication strategy (two-token model rationale, TTL choices, refresh-rotation-as-tripwire limitation, dual cookie+body refresh-token delivery risk, `X-Session-ID` flagged as "where we likely got it wrong"); cryptography (Argon2id OWASP-interactive preset with an explicit "do not weaken" note and a 2028 review-cadence date, no peppering/envelope-encryption gap, ES256-default/RS256-fallback, SHA-256-not-Argon2 for refresh-token-at-rest justified by the token's own 256-bit entropy, 7-day JWKS grace window with no emergency-rotation tooling); OAuth/OIDC (Redis-not-DB auth codes, strict tenant-bound clients with no "platform" global-client concept yet, exact-match redirect_uri per RFC 6749 §10.6); MFA (TOTP SHA1/6-digit/30s for compatibility, the plaintext-`secret_encrypted` naming flagged as a pre-prod blocker, no recovery codes flagged as a pre-prod blocker before any tenant enables `require_mfa`); WebAuthn (discoverable-only/passkey-first design choice, sign-count-stored-but-not-enforced gap, no attestation/MDS3 verification deferred to v0.15.0); per-tenant policy (`max_active_sessions` called out explicitly as "misleading schema" — column exists, never enforced); observability (bounded-cardinality label rationale, audit-via-NATS-not-direct-write tradeoff); concurrency (relies entirely on pgxpool/go-redis internal pooling, no custom pool metrics, no global rate limiter — flagged as a v0.10.0 gap); error model (small sentinel-error vocabulary tradeoff); testing strategy (ten-layer-pyramid cost/benefit, custom stress/soak/spike-over-wrk rationale, Welch-t-test rationale, live-server-not-testcontainers integration approach, the 7.7%-coverage-is-structurally-misleading note); operational design (two-binary split rationale, **worker has no leader election — double-processing risk if scaled**, `cmd/migrate` empty flagged as a pre-prod blocker, hardcoded 30-day session retention, manual key rotation, **no graceful shutdown flagged repeatedly as the top-priority gap**); an explicit "things not built" table with target versions; a 12-item **"where we likely got it wrong"** honest retrospective (matches many items catalogued in §27 of this document); a decision-review-cadence table; and a closing section explicitly enumerating the pre-prod-readiness blockers by section number.

### 24.4 `THREAT_MODEL.md` (~39KB, 736 lines) — STRIDE-style, 28 numbered threats
Each threat: Threat / Attacker model / Attack surface / Concrete attack steps / Today's mitigation / Residual risk / Detection / Roadmap closure, with a ⚠ flag for unacceptable-for-regulated-customers residual risk. Out-of-scope assumptions: TLS/MITM, OS compromise, direct Postgres network access, physical access, client malware. The 28 threats (condensed, ⚠ = flagged residual risk): credential stuffing ⚠ (no rate limit today), online brute force ⚠, offline brute force after a DB leak ⚠ (Argon2id mitigates but no peppering), account enumeration ⚠ (confirmed 62× login-timing oracle, quantified), session fixation ✅, session hijacking ⚠ (TTL-bounded only, no DPoP), XSS token exfiltration (refresh cookie immune, access token in body is client's responsibility), CSRF ✅ (SameSite=Strict + Bearer-immunity), refresh-token replay ✅-mostly (rotation+revoke works, but the tripwire signal isn't acted on), access-token replay after revocation ⚠ (up to 15min window, no denylist), signing-key compromise ⚠ (plaintext PEM in DB — matches §9.2's finding exactly), JWT alg=none/confusion ✅ (matches §9.4's `WithValidMethods` finding), PKCE downgrade ✅, auth-code reuse/leak ✅, OAuth redirect-URI hijack ✅-mostly, open redirect ✅, **tenant escape ⚠ (no RLS, no detection mechanism for a missed `WHERE tenant_id` — matches §2's/§27's finding)**, privilege escalation within a tenant ⚠ (**no compiler-enforced permission-check requirement per route** — matches §14.4's finding exactly), MFA bypass/TOTP-replay-within-window ⚠ (no used-code denylist), SQL injection ✅ (parameterized throughout, grep-confirmed, security-test-passed), header injection ✅, timing oracles ⚠ (duplicate of the login-existence leak), SSRF via future federation IdP URLs (N/A, not built, pre-registered acceptance criteria for when it is), rate-limit/DoS ⚠ (no app-level limiting, no request-size cap), **audit log tampering ⚠ (total — `audit_events` rows are freely UPDATE-able, no tamper-evidence; compounds with §19.5's finding that nothing is even being written today)**, supply-chain compromise (go.sum pins hashes, no `govulncheck`/`gosec` in CI yet), WebAuthn assertion replay/cloned-authenticator ⚠ (**sign-count stored but not enforced strictly-increasing — matches §13.4's finding exactly**), tenant-scoped policy bypass (✅ on `/login` today, but explicitly warns future federation/password-reset paths won't automatically inherit the check). Closes with a full threat-to-mitigation summary table and a living-document note tying future endpoint additions back to threats #17/#18/#28 specifically.

### 24.5 `BENCHMARKS.md` (~13KB, 338 lines)
Rig: Apple Silicon 10-core/32GB, Go 1.26 darwin/arm64, Postgres 16 + Redis 7 + NATS 2.10 in Docker, ES256 active key, Principal cache enabled. Microbenchmarks: Argon2id hash/verify ≈95ms/op (10.5 ops/sec/core by design — intentionally expensive); JWT issue 53.2µs/op (~18.8k ops/sec); JWT verify 81.1µs/op (~12.3k ops/sec) — **1,170× faster than Argon2**. Login end-to-end: c=4 → 20.1 req/s, p50=195ms; c=50 → throughput *drops* to 8.9 req/s, p99=10.3s (queue-depth-bound, not CPU-bound past the Argon2-parallelism sweet spot — concurrent in-flight logins should stay ≤GOMAXPROCS/2). Auth middleware: JWT-verify path 9,738 req/s (p99=24.1ms, still hits DB per-request for the signing key by `kid` — no in-process key cache, flagged as a v0.10.0 opportunity); session-ID+cache path **20,972 req/s** (p99=10.0ms) — 2.2× faster than JWT specifically *because* of that missing key cache. Refresh: 732.5 req/s (p99=70.8ms, occasional 597ms autovacuum-correlated spike) — supports ~660k active users at a 1-refresh-per-15min assumption. OAuth code exchange (full PKCE): 1,287 req/s (p99=27.9ms). Redis cache hit rate: measured 99.974% (193,826 hits / 50 misses). Server-side `/me` histogram (682,796 requests): mean 4.70ms, p99≤25ms. Headline bottleneck-order table (cached `/me` 20,972 → JWT `/me` 9,738 → OAuth exchange 1,287 → refresh 733 → login 20 req/s), an SLO table, capacity-planning math (mixed realistic workload uses ~23% of one node), and 5 concrete next-optimization candidates (in-process signing-key LRU projected to drop JWT p99 24ms→<8ms; parallel refresh fan-out via errgroup projected p99 71ms→~40ms; login dummy-hash pre-warm — which would *also* close the account-enumeration timing oracle from `THREAT_MODEL.md` #4/#22; pooling the JWT encoder; routing session-lookup fallback through the still-unused `Pools.Reader`). Explicit blind-spots list: no GC-pause visibility, no connection-pool saturation metrics, local-SSD-masked disk latency (production EBS gp3 will be 2-3× slower on writes). Closing reproduction recipe with exact commands and a note that these numbers must be re-run before any hot-path-touching release.

---

## 25. `changelogs/` — version-by-version build history

- **`v0.1.0-initial.md`**: foundation build — clean-architecture skeleton, identity/auth/session/RBAC/tenancy domains, full DB schema laid down upfront (including OAuth/MFA/devices/service-accounts/audit tables with **no app code yet** for most of them at that point). Ends with a 15-item known-issues table (debug `fmt.Println`s, hardcoded IP, `MustPrincipal()` panic risk, string-keyed-context collision risk, duplicated executor interfaces, a `UserRoleRepository` transaction-bypass bug, no logout, no validation, no CORS, no structured logging, a `SlugService` retry-10000-times bug, leaked internal errors) — **all resolved in v0.2.0**.
- **`v0.2.0-stabilization.md`**: zero new features, resolves all 15 v0.1.0 issues one-for-one (matches this doc's §2/§5/§27 findings about the typed-context-key and Executor-trick patterns being deliberately introduced here). Adds `/logout`, CORS (wildcard, dev-only by design at the time), `slog`, input validation, consistent JSON error envelopes, and route-registration helpers (`withAuth`/`withPerm`) that collapsed `main.go`'s route section from ~180 to ~15 lines.
- **`v0.3.0-jwt-access-tokens.md`**: introduces ES256 JWT access tokens alongside opaque refresh tokens, `signing_keys` table, `cmd/key-rotator`, JWKS endpoint, Bearer-then-session-header auth-middleware ordering — matches §9/§7.9 exactly.
- **`v0.4.0-oauth-pkce.md`**: OAuth2 Authorization Code + mandatory S256-only PKCE — matches §10 exactly, including the three token-endpoint auth methods and the security-properties list.
- **`v0.5.0-oidc.md`**: OIDC ID tokens + discovery + UserInfo — matches §11 exactly.
- **`v0.6.0-mfa-totp.md`**: TOTP enrollment + two-step login challenge, backward-compatible with unenrolled identities — matches §12, notes the plaintext-secret-storage deferral explicitly even at introduction time.
- **`v0.7.0-webauthn-passkeys.md`**: passkey registration + passwordless discoverable login via `go-webauthn` — matches §13, explicitly notes sign-count is stored+updated but not yet enforced strictly-increasing (a gap acknowledged from day one, not discovered later).
- **`v0.8.0-scalability-observability.md`**: Principal cache (**measured 9× speedup**, session-ID `/me` p50 14.1ms→1.5ms), structured logging, Prometheus metrics, async audit via NATS→worker (**note: the changelog describes this as shipped/working — but as established in §19.5, the producer-side wiring was never actually completed**, a discrepancy between the changelog's framing and the current code state worth flagging explicitly), session-cleanup worker, read-replica scaffolding (`Pools`, unused). Includes a before/after A/B re-validation: pre-v0.8.0 session-ID was 3.6× *slower* than JWT; post-v0.8.0 (with caching) session-ID became 1.5× *faster* than JWT — directly credited to the Principal cache.
- **`v0.9.0-multi-tenancy-policies.md`**: per-tenant policy (password rules, email-domain allowlist, MFA requirement, max-sessions), the nullable-`tenant_id`-on-`permissions` COALESCE trick, `LoginUseCase`'s `ErrMFAEnrollmentRequired` addition. Explicitly notes as future work that the permission-bootstrap service still seeds permissions as global (NULL tenant_id) even though the schema now supports tenant-scoped permissions — flipping that is an acknowledged follow-up, matching §14.2's finding.

---

## 26. `testdocs/` — manual/point-in-time test snapshots

- **`v0.2.0-endpoint-tests.md`** (dated 2026-05-30): 31 numbered manual curl tests at the earliest, pre-JWT/pre-OAuth API surface. Surfaces two **500-should-be-400** bugs (missing `role_name` on user-create, assigning an unknown permission name) that were live known-issues at that point — worth checking whether they were ever fixed in later code (not independently re-verified in this pass, but the current `assign_permission.go` handler mapping *all* use-case errors to 500 rather than differentiating — noted in §14.4 — suggests the unknown-permission variant may still reproduce as of the current codebase). Also flags the refresh-token-in-JSON-body-as-XSS-risk point (predates the eventual httpOnly-cookie fix, which itself still leaves the body-delivery redundancy noted in §27).
- **`v0.7.0-test-strategy.md`** (dated 2026-05-31): full test-strategy snapshot covering JWT+OAuth+OIDC+MFA+WebAuthn — unit 32 tests all passing, smoke 21/21, integration 19 tests/21 sub-tests all passing, stress 5 scenarios all meeting targets, A/B result **pre-Principal-cache**: JWT 3.64× faster than session-ID (Welch t=-524.68, p<0.001) — this is the exact baseline number that directly motivated v0.8.0's caching investment, and matches `BENCHMARKS.md`/`changelogs/v0.8.0`'s retelling precisely.
- **`v0.7.1-advanced-testing.md`** (same day, a deepening pass): opens with the real fuzz-caught bug narrative (`password.Verify` nil-pointer panic on `("0","$$$$$")`, found in ~3 seconds of fuzzing, fixed, regression seed preserved) — matches §5.5 exactly. Documents the SLA-assertion mechanism proven both ways (a passing run and a deliberately-breaching run with a 1ms budget forcing exit code 2). Soak: 670,878 requests, zero failures, p99 drift +3.9%, heap 11MB→9.7MB (GC working correctly, no leak signature). Spike: baseline p99=1.83ms → burst p99=17.48ms (predictable 10× queuing jump, zero failures) → recovery p99=2.25ms (near-full recovery). Fuzz: up to 758,524 executions in 5s for `FuzzVerifyPKCE`. Race: zero races across 6 packages. Security: full 10-test results table, explicitly marking brute-force and timing tests ⚠ KNOWN GAP with the same quantified 62×/95ms/1.5ms numbers as `THREAT_MODEL.md`. Coverage: confirms and explains the 7.7% figure. Closes with a table of external tools deliberately *not* automated in-repo (OIDC Conformance Suite, RFC 6819 OAuth threat audit, OWASP ASVS L2 checklist, Burp/ZAP, OSS-Fuzz, hey/wrk ad-hoc load).

---

## 27. Catalog of known gaps, dead code, and security findings

Consolidated from all six exploration passes and cross-checked against the project's own `TRADEOFFS.md`/`THREAT_MODEL.md` — items marked **(self-documented)** are things the codebase's own docs already flag; items marked **(found independently)** were surfaced by reading the code and were not explicitly called out in the docs (or were found to be still-open despite a docs note suggesting closure).

### Dead / unused code
- `internal/auth/domain/refresh_token.go` + `refresh_token.repository.go` + migration `000003_refresh_tokens` table — entirely unused; live refresh-token state is in `sessions.refresh_token_hash`. **(self-documented, TRADEOFFS §3)**
- `internal/auth/app/me.go` (`MeUseCase`) — never invoked; `/me` handler bypasses it and echoes the context `Principal` directly. **(found independently)**
- `internal/identity/app/create_identity.go` (`CreateIdentityUseCase`) — never invoked; both live provisioning flows create identities inline instead. **(found independently)**
- `internal/tenant/middleware/tenant.go` (`ResolveTenant`) — defined, never registered in `main.go`. **(found independently)**
- `internal/webauthn/app/service.go`'s `randomKey()` — reads 16 `crypto/rand` bytes then discards them, returning a UUIDv4 instead; harmless (UUIDv4 is also CSPRNG-backed) but confusing dead code. **(found independently)**
- `service_accounts` table (migration 000001) — schema exists, zero application code reads/writes it. **(found independently)**
- `internal/tenant/app/policy_enforcer.go`'s `ValidatePassword`/`ValidateEmailDomain` — fully implemented and unit-tested, but zero call sites anywhere in `RegisterUseCase`/`CreateUserUseCase`/`LoginUseCase`. **(found independently — significant, since tenant password/email policy reads as enforced from the API surface but isn't)**

### Security-relevant gaps
- `mfa_factors.secret_encrypted` stores the raw base32 TOTP seed in plaintext — the column name implies encryption that was never implemented. **(self-documented as a pre-prod blocker, TRADEOFFS §10)**
- `signing_keys.private_key` — cleartext PEM in Postgres, no KMS/envelope encryption. **(self-documented, THREAT_MODEL #11)**
- No MFA backup/recovery codes exist anywhere. **(self-documented as a pre-prod blocker before enabling `require_mfa`, TRADEOFFS §10)**
- WebAuthn `sign_count` is stored and updated but **not enforced as strictly increasing** — cloned-authenticator replay is detectable in principle but not actually rejected. **(self-documented, THREAT_MODEL #27 — confirmed still true in current code)**
- Login has a quantified ~62× timing oracle (real-wrong-password ≈95ms vs nonexistent-user ≈1.5ms) that leaks account existence. **(self-documented and quantified, THREAT_MODEL #4/#22, testdocs v0.7.1)**
- No rate limiting / brute-force lockout on `/login`, `/refresh`, `/oauth/token`, `/mfa/complete`, `/register` — `security_test.go` documents but does not fail on this. **(self-documented, THREAT_MODEL #1/#2/#24)**
- No RLS / defense-in-depth against a missed `WHERE tenant_id=$1` — a single such bug anywhere would be a silent cross-tenant data leak with no detection mechanism. **(self-documented, THREAT_MODEL #17)**
- No compiler-enforced requirement that every route call `RequirePermission` — an added route can be silently open to any authenticated user; confirmed concretely relevant since `internal/authorization`'s own `assign_permission.go` handler collapses `ErrForbidden` (cross-tenant) into a generic 500 instead of 403. **(self-documented, THREAT_MODEL #18; the 500-vs-403 specific instance found independently)**
- Refresh token is delivered **both** as an httpOnly cookie and in the JSON response body on `/login` and `/refresh` — redundant exposure surface, since anything with body access (e.g. a compromised frontend) gets the raw token regardless of the cookie's protections. **(self-documented as "where we likely got it wrong," TRADEOFFS §19; found independently in the transport-handler code)**
- Refresh cookie is `Secure: false` — relies entirely on an external TLS-terminating proxy; no defense-in-depth if that assumption breaks. **(self-documented, TRADEOFFS §19)**
- CORS is a wildcard (`Access-Control-Allow-Origin: *`) — explicitly flagged in code comments and docs as a pre-prod blocker. **(self-documented, TRADEOFFS §5.3)**
- `audit_events` rows are freely UPDATE-able by anyone with DB write access — no tamper-evidence/hash-chaining. **(self-documented, THREAT_MODEL #25)**
- **The audit pipeline's producer side is entirely unwired** — `auditPublisher` is constructed in `main.go` and immediately discarded (`_ = auditPublisher`); no code path anywhere calls `Emit`. In the currently running system, **zero rows would ever be written to `audit_events`**, despite the consumer, worker, and Postgres schema all being fully built and independently correct. This is more severe than the docs' framing suggests — `changelogs/v0.8.0` describes async audit logging as a shipped feature of that release, when in fact only the infrastructure shipped, not any producer call site. **(found independently — the single most significant discrepancy between documentation/changelog narrative and actual code state in this codebase)**

### Operational gaps
- `cmd/migrate` is a no-op stub — migrations are applied manually. **(self-documented as a pre-prod blocker, TRADEOFFS §17.3)**
- No graceful shutdown on `cmd/iam-server` (blocking `ListenAndServe`, no signal handling, no in-flight-request draining). **(self-documented as the top-priority operational gap, TRADEOFFS §17.6/§19.4)**
- `cmd/worker` is single-instance with no leader election; scaling it to >1 replica risks double-processing since NATS Core consumption isn't idempotent (no dedup on the consumer side). **(self-documented, TRADEOFFS §17.6/§19.6)**
- Hardcoded TTL/retention constants throughout (15min access, 7d refresh, 5min MFA/WebAuthn challenges, 30d session retention) rather than config-driven. **(self-documented, TRADEOFFS §19)**
- No connection-pool saturation metrics, no request-ID propagation, stringly-typed permission strings with no compile-time typo detection, `max_active_sessions` schema-vs-enforcement mismatch. **(self-documented, TRADEOFFS §19, full 12-item list)**
- `internal/platform/postgres/pools.go`'s read-replica support (`Pools{Writer,Reader}`) is built but never wired into `main.go` — `iam-server` still uses a single pool. **(found independently, corroborated as "whenever a real replica exists" in TRADEOFFS §18)**

### Test-suite observations
- Code coverage sits at a structurally-misleading 7.7% because HTTP-level integration/smoke/security/stress suites don't flow through in-process Go coverage counters (would need a `-cover`-built binary plus a graceful-shutdown flush mechanism — neither exists). **(self-documented, TRADEOFFS §16.6, coverage.sh comments)**
- A captured historical run (`coverage/integration.log`) shows 4 of the 7 OAuth integration tests failing with `error=invalid_client` — whether this is a stale test-fixture issue or a real regression at that point in time was not further diagnosed by any of the exploration passes; worth a live re-run before relying on this suite's current green/red status.
- Two apparent 500-should-be-400 bugs documented in `testdocs/v0.2.0-endpoint-tests.md` (missing `role_name` on user-create, unknown-permission-name assignment) — the current `AssignPermissionToRoleUseCase`/handler code (§14.2/§14.4) still maps errors generically enough that the unknown-permission variant plausibly still reproduces; not independently re-tested in this pass.

### ⚠ New findings from this revision (the identity/mfa service split)
- **The entire `test/` suite (integration/security/smoke/stress/spike/soak/A-B) is unaware of the 3-service split** — zero references to `identity-service`, `mfa-service`, `IDENTITY_SERVICE_URL`, `MFA_SERVICE_URL`, port 8081, or port 8082 anywhere under `test/`. `test/integration/mfa_test.go` and `test/integration/webauthn_test.go` in particular target routes that no longer exist on iam-server post-split. **(found independently — see §22's revised intro and §29.5; this is the single largest piece of staleness this revision found and fixed in the documentation, though the underlying tests themselves were left untouched per this task's documentation-only scope)**
- **The compensating-delete saga in `RegisterUseCase`/`CreateUserUseCase` has a residual orphan-identity gap**: if the local Postgres transaction fails *and* the compensating `identityRepo.Delete` call to identity-service also fails (e.g. transient network partition), the identity row is permanently orphaned in identity-service with no retry, outbox, or reconciliation job to clean it up later — the code only logs and returns a wrapped double-error to the caller. **(found independently — a new gap introduced by the split, not present in the pre-split single-transaction design, where this failure mode was structurally impossible)**
- **Both identity-service's `/internal/identities/*` and mfa-service's `/internal/mfa/*`/`/internal/mfa/challenges/*` internal APIs are entirely unauthenticated** — no shared secret, mTLS, or network-policy enforcement visible in code; the trust boundary is "assumed only reachable from other services on the private network," identical in spirit to the pre-split app-level (not DB-level) tenant-scoping trust model (§2 point 7), but now extended to a genuine network boundary rather than just an in-process one. Not flagged in `THREAT_MODEL.md` (which predates the split) — worth adding as a new threat entry in a future revision of that document. **(found independently)**
- **Postgres and Redis remain shared, not partitioned, across the three services** — the split is explicitly a network-API boundary only (per `main.go` comments in both new binaries), meaning any of the three services could in principle still reach tables/keys it doesn't "own" if a future change reintroduced a direct repository construction; there is no database-user-level or schema-level enforcement of the ownership boundary, only convention. **(found independently)**
- **`iam-server` has no docker-compose service block** — only `identity-service` and `mfa-service` are containerized; `iam-server` is still expected to run outside Docker (e.g. `go run ./cmd/iam-server`) with manually-set `IDENTITY_SERVICE_URL`/`MFA_SERVICE_URL` pointing at the composed services' host-mapped ports. **(found independently — see §30)**

---

## 28. Quick-reference tables

### 28.1 "Where do I look for X?"

| I want to understand... | Look at |
|---|---|
| How passwords are hashed | `internal/shared/password/password.go` (§5.5) |
| How JWTs are issued/verified/rotated | `internal/token/app/jwt_service.go`, `keygen.go`, `cmd/key-rotator/main.go` (§9) |
| How login works end to end | `internal/auth/app/login.go` (§7.4, §21.1) |
| How MFA/TOTP works | `internal/mfa/app/totp.go`, `complete.go` (§12, §21.2) |
| How WebAuthn/passkeys work | `internal/webauthn/app/service.go`, `login_complete.go` (§13, §21.3) |
| How OAuth2+PKCE works | `internal/oauth/app/authorize.go`, `token.go` (§10, §21.4) |
| How OIDC ID tokens/discovery work | `internal/oidc/app/id_token_service.go`, `transport/http/*` (§11, §21.5) |
| How RBAC/permission checks work | `internal/authorization/middleware/authorization.go`, `domain/role_permission_repository.go` (§14, §21.6) |
| How multi-tenancy/policy works | `internal/tenant/app/policy_enforcer.go`, `transport/http/policy_handler.go` (§15, §21.7) |
| Full DB schema | `auth-server/migrations/000001`–`000006` (§6) |
| All HTTP routes (now 3 services) | `cmd/iam-server`, `cmd/identity-service`, `cmd/mfa-service` `main.go` files (§3, §20, §29.4) |
| Deep design rationale | `TRADEOFFS.md` (§24.3) |
| Security posture / threat coverage | `THREAT_MODEL.md` (§24.4) |
| Measured performance | `BENCHMARKS.md` (§24.5) |
| What's NOT built yet | §17, §18, §27 of this document |
| How the identity/mfa service split works, network boundaries | §0, §29 of this document |
| The identity/mfa httpclient adapters' error mapping | `internal/identity/infra/httpclient`, `internal/mfa/infra/httpclient` (§29.1) |
| The register/create-user compensating-delete saga | `internal/auth/app/register.go`, `internal/identity/app/create_user.go` (§7.5, §16.4) |
| Docker/deployment setup | `auth-server/Dockerfile`, `auth-server/docker-compose.yml` (§30) |

### 28.2 Token lifetimes

| Token/artifact | TTL | Storage |
|---|---|---|
| Access JWT | 15 minutes | client-held only, stateless |
| Refresh token | 7 days | `sessions.refresh_token_hash` (SHA-256), rotated on use |
| OIDC ID token | 15 minutes | client-held only |
| OAuth authorization code | 10 minutes | Redis, single-use (`GETDEL`) |
| MFA challenge token | 5 minutes | Redis, single-use (`GETDEL`) |
| WebAuthn ceremony session | 5 minutes | Redis, single-use (`GETDEL`) |
| Principal cache entry | 5 minutes | Redis, explicit invalidation on logout/refresh |
| Signing key | indefinite (never deleted) | Postgres; 7-day JWKS-listing grace window post-rotation |
| Session-cleanup retention | 30 days past expiry/revocation | purged by `cmd/worker` every 5 minutes |

### 28.3 Crypto parameters

| Purpose | Algorithm/params |
|---|---|
| Password hashing | Argon2id, m=64MiB, t=3, p=2, salt=16B, key=32B (OWASP "interactive" preset) |
| Refresh/MFA/code tokens | 32 random bytes (`crypto/rand`) → `base64.RawURLEncoding`; stored as SHA-256 hex hash |
| JWT signing | ES256 (ECDSA P-256) default, RS256 (2048-bit RSA) fallback; `kid`-based key lookup; `WithValidMethods` allowlist blocks `alg=none` |
| PKCE | S256 only (`plain` rejected) |
| TOTP | SHA-1 HMAC, 6 digits, 30s step (RFC 6238 / Google Authenticator compatible) |
| WebAuthn | ES256/RS256 per authenticator, resident-key-required (passkeys), user-verification preferred |
| Constant-time comparisons | `crypto/subtle.ConstantTimeCompare` for password verify, PKCE verify, OAuth client-secret verify |

### 28.4 Empty / unimplemented directories (do not assume code exists here)

`internal/provisioning/`, `internal/serviceaccount/`, `internal/federation/`, `internal/pam/`, `internal/risk/`, `internal/notification/`, `internal/admin/`, `internal/platform/secrets/`, `internal/shared/crypto/`, `internal/shared/logging/`, `internal/shared/tracing/`, `internal/shared/validation/`, `auth-server/configs/`, `auth-server/deployments/`, `auth-server/api/openapi/`, `auth-server/api/proto/`, `auth-server/scripts/`, `auth-server/tools/`, `auth-server/docs/`, `auth-server/web/admin/`, `auth-server/web/login/`, `auth-server/coverage/runtime/`, `auth-server/test/fuzz/`, `auth-server/test/e2e/`. **All still confirmed empty post-split, including `internal/federation/` and `internal/notification/` — re-verified for this revision (§18).**

`cmd/migrate/main.go` is a compiling-but-empty stub.

### 28.5 The 3-service split, one-paragraph summary (see §29 for full depth)

`cmd/iam-server` (port 8080) is the public auth gateway — auth/oauth/oidc/session/authorization/tenant/token/audit all still live in-process as shared libraries. `cmd/identity-service` (port 8081, new) exclusively owns Postgres access for the `identities` table and exposes it over an unauthenticated internal HTTP API (`/internal/identities/*`); `cmd/mfa-service` (port 8082, new) exclusively owns Postgres/Redis access for MFA factors, MFA challenges, and WebAuthn credentials, exposing both an internal API (`/internal/mfa/*`) and the real end-user-facing `/mfa/*`/`/webauthn/*` routes (which moved off iam-server entirely — no proxy). iam-server reaches identity-service and mfa-service through `internal/identity/infra/httpclient` and `internal/mfa/infra/httpclient` respectively, both implementing the same domain-layer repository interfaces a Postgres/Redis adapter would. Postgres and Redis themselves remain **shared** across all three services — this is a network-API boundary, not a data-ownership boundary. The one behavioral change beyond wiring: `RegisterUseCase`/`CreateUserUseCase` now create the `Identity` via a network call *outside* their local Postgres transaction, with an explicit compensating delete if the local transaction subsequently fails (§7.5, §16.4, §29.2).

---

## 29. The 3-service split: network topology, service boundaries, error mapping

### 29.1 The `httpclient` adapters — the mechanism that makes the split possible

Both `internal/identity/infra/httpclient` and `internal/mfa/infra/httpclient` follow an identical shape and convention, described once here rather than duplicated per-package (see §16, §12 for the per-domain call sites):

```go
type Repository struct {
    baseURL string
    client  *http.Client   // Timeout: 5 * time.Second (defaultTimeout), both packages
}
func NewRepository(baseURL string) *Repository {
    return &Repository{baseURL: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: defaultTimeout}}
}
```

Both implement their respective `domain.Repository` interface exactly (`identitydomain.Repository`: `Create`/`GetByEmail`/`GetByID`/`Delete`; `mfadomain.Repository`: `Create`/`GetByID`/`GetByIdentity`/`GetVerifiedByIdentity`/`MarkVerified`/`Delete`), so no `app`-layer code anywhere needed to change — only the concrete type constructed in `main.go` changed (§2 point 1). `internal/mfa/infra/httpclient` additionally ships a second type, `ChallengeStoreClient`, satisfying the small `MFAChallengeStore` interface `LoginUseCase` defines locally (§7.4) — `Store`/`Consume`, mirroring the original Redis-backed `mfaapp.ChallengeStore`'s contract exactly so `LoginUseCase` needed no changes beyond its constructor's parameter type.

**Error-mapping convention, identical across both packages** (this is the single most important thing to understand about the split's failure semantics):

| HTTP status | Mapped to | Applies to |
|---|---|---|
| 200/201 (decodable body) | success, response unmarshaled into the output struct | all `Create`/`Get*` calls |
| 404 on a `Get*` call | `sharederrors.ErrNotFound` | `GetByID` (both packages), `GetByEmail`/`GetByID` (identity), challenge `Consume` (mfa) |
| 409 on `Create` | `sharederrors.ErrConflict` | identity `Create` only (duplicate email) |
| 200/204/404 on `Delete` | `nil` (success) — **404 is deliberately treated as success**, not `ErrNotFound` | both packages' `Delete` |
| anything else non-2xx | opaque wrapped error via `unexpectedStatus(op, resp)`, which reads up to 2048 bytes of the response body into the error string | everything else |
| transport-level failure (`client.Do` erroring, timeout, DNS failure, connection refused) | opaque wrapped `error`, **no dedicated sentinel** | everything |

```go
func unexpectedStatus(op string, resp *http.Response) error {
    b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
    return fmt.Errorf("<identity|mfa> httpclient: %s: unexpected status %d: %s", op, resp.StatusCode, string(b))
}
```

Two design consequences worth calling out explicitly:
1. **`Delete` being idempotent-on-404** is what makes the compensating-delete saga (§7.5, §16.4) safe to call more than once or against an identity that (for whatever reason) never actually got created server-side — the caller cannot distinguish "already deleted" from "successfully deleted just now," which is the correct semantics for a compensating action (the desired end state — no such row — holds either way).
2. **There is no sentinel for "service unreachable."** A network partition, mfa-service/identity-service being down, or a timeout all surface as the same opaque wrapped `error` that `errors.Is(err, sharederrors.ErrXxx)` will never match. Every call site that only branches on the shared sentinel errors (e.g. `LoginUseCase` masking `identityRepo.GetByEmail` failures to `ErrInvalidCredentials` — §7.4 step 1) will therefore also mask a genuine identity-service outage as "invalid credentials," which is a **new failure-mode ambiguity introduced by the split**: pre-split, a Postgres connection failure on that same call would have propagated as a distinguishable low-level DB error; post-split, it's indistinguishable from a wrong password to the caller (though still correctly logged server-side via whatever wraps the use case, since `slog`-style logging isn't stripped, just the *typed* distinction). Not currently called out in `THREAT_MODEL.md` (which predates the split) — worth adding as a new entry there.

**Why MFA got a client but WebAuthn didn't** (also covered in §13's post-split note): iam-server's own `LoginUseCase` needs `mfadomain.Repository`/`ChallengeStore` in-process, because deciding "is MFA required for this login" and issuing the challenge token both happen inside iam-server's `/login` handler. WebAuthn login is a complete, self-contained alternative login method with no code path inside iam-server that needs to touch it at all — a client wanting passkey login talks to mfa-service's own port for the whole ceremony, so there was nothing in iam-server to give a client to.

### 29.2 The compensating-delete saga — consolidated view

Both `RegisterUseCase.Execute` (`internal/auth/app/register.go`, §7.5) and `CreateUserUseCase.Execute` (`internal/identity/app/create_user.go`, §16.4) now follow the identical shape:

```
1. identity := build Identity{...}
2. identityRepo.Create(ctx, identity)         // network call, OUTSIDE any local tx
   └─ fails? return immediately — nothing else has happened yet, no compensation needed
3. txManager.WithinTransaction(ctx, func(txCtx) error {
       // credential, tenant/role lookups, user, role assignment — all local Postgres,
       // unchanged from pre-split logic
   })
4. tx block returned an error?
   └─ identityRepo.Delete(ctx, identity.ID)   // network call, compensating action
       ├─ succeeds → return the ORIGINAL tx error (net effect: as if nothing was ever created)
       └─ ALSO fails → log both errors, return a wrapped error naming both
                        (net effect: identity is ORPHANED — see §27's new-findings entry)
5. tx succeeded → return success
```

This is a textbook **saga pattern** (specifically: a single-compensating-action saga, not a full choreographed/orchestrated saga with a durable log) applied at exactly the one place in the codebase where a cross-service write needs to be all-or-nothing with a same-service transaction. It is *not* a general pattern used elsewhere — no other cross-service write in the codebase (e.g. mfa-service's own writes, which are all local to its own process) needs one, because nowhere else does one service's local transaction depend on another service's write having already succeeded.

### 29.3 Network topology diagram

```
                                   ┌─────────────────────────────┐
                                   │        End users /          │
                                   │   OAuth clients / browsers  │
                                   └──────────────┬───────────────┘
                     ┌───────────────────────────┼────────────────────────────┐
                     │                            │                            │
                     ▼                            ▼                            ▼
        ┌─────────────────────────┐  ┌─────────────────────────┐   (no route on iam-server
        │   cmd/iam-server         │  │   cmd/mfa-service        │    reaches these — direct
        │   :8080 (HTTP_PORT)      │  │   :8082 (MFA_HTTP_PORT)  │    calls only)
        │                          │  │                          │
        │  /register /login        │  │  /mfa/complete            │
        │  /refresh /logout /me     │  │  /mfa/enroll/*  (withAuth)│
        │  /oauth/* /oidc/*         │  │  /webauthn/*               │
        │  /tenant/policy /users    │  │  /internal/mfa/* (no auth)│
        │  /roles/*  /.well-known/* │  │                          │
        └──────────┬───────────────┘  └──────────┬───────────────┘
                    │  IDENTITY_SERVICE_URL        │  IDENTITY_SERVICE_URL
                    │  (identityhttpclient)         │  (identityhttpclient)
                    │  MFA_SERVICE_URL               │
                    │  (mfahttpclient, LoginUseCase  │
                    │   only)                        │
                    │                                │
                    ▼                                ▼
        ┌─────────────────────────────────────────────────────┐
        │           cmd/identity-service :8081                 │
        │           (IDENTITY_HTTP_PORT)                       │
        │           /internal/identities/*   (no auth)         │
        └───────────────────────┬───────────────────────────────┘
                                 │
        ┌────────────────────────┴───────────────────────────────┐
        │                                                          │
        ▼                                                          ▼
┌───────────────────────┐                              ┌───────────────────────┐
│  Postgres (shared)     │◄─────────────────────────────┤  Redis (shared)        │
│  identities, users,     │   iam-server + mfa-service    │  principal cache,      │
│  credentials, sessions,│   connect directly too         │  oauth codes,          │
│  tenants, roles,        │                                │  MFA challenges,       │
│  permissions, mfa_      │                                │  WebAuthn ceremony     │
│  factors, webauthn_     │                                │  sessions              │
│  credentials, signing_ │                                │                        │
│  keys, oauth_clients,   │                                │  (iam-server + mfa-    │
│  audit_events           │                                │   service only —       │
└───────────────────────┘                                │   identity-service     │
                                                            │   doesn't touch Redis) │
                                                            └───────────────────────┘

  NATS: iam-server (publisher, unwired — §19) ←→ cmd/worker (consumer). Neither
  identity-service nor mfa-service touch NATS at all.
```

Key properties visible in the diagram: (1) `iam-server` is the only service reachable from both identity-service and mfa-service's dependents *and* the only one end users hit for auth/OAuth/RBAC; (2) `mfa-service` is the only service with a dual role — internal API consumer of identity-service *and* direct end-user-facing surface for MFA/WebAuthn; (3) `identity-service` is a pure leaf — no NATS, no Redis, no outbound calls to anything, just Postgres in and HTTP out; (4) Postgres and Redis are genuinely shared infrastructure, not partitioned — the boundary the split introduced is purely at the HTTP-API layer.

### 29.4 Consolidated cross-service route index

See §20.1–§20.3 for the three full per-service tables; this is a compact combined view of just the paths, to make "which service do I call for X" scannable in one place:

| Path prefix | Service | Port |
|---|---|---|
| `/register`, `/login`, `/refresh`, `/logout`, `/me` | iam-server | 8080 |
| `/oauth/*` | iam-server | 8080 |
| `/.well-known/*` | iam-server | 8080 |
| `/tenant/policy` | iam-server | 8080 |
| `/users`, `/users/{id}` | iam-server | 8080 |
| `/roles`, `/roles/{id}/permissions` | iam-server | 8080 |
| `/mfa/complete`, `/mfa/enroll/*`, `/mfa/factors` | mfa-service | 8082 |
| `/webauthn/*` | mfa-service | 8082 |
| `/internal/mfa/*` (factors + challenges) | mfa-service | 8082 |
| `/internal/identities/*` | identity-service | 8081 |
| `/health`, `/metrics` | all three | 8080 / 8081 / 8082 (independently) |

Note `/health` and `/metrics` exist independently on all three services — there is no unified health/metrics aggregation endpoint; a monitoring system must scrape/poll all three separately.

### 29.5 Why the test suite doesn't reflect any of this yet

As established in §22's revised introduction, the entire `test/` tree still assumes one server on port 8080. This is the clearest signal that the service split is a genuinely **in-progress refactor** rather than a finished, fully-propagated architectural change: `main.go` wiring, `config.go`, the Dockerfile, and `docker-compose.yml` were all updated consistently (§30), but the test harnesses, `TRADEOFFS.md`/`THREAT_MODEL.md`/`DESIGN.md` (§24, still describing the pre-split single binary), and the changelog (§25, no `v0.10.0`-or-later entry documenting this split at all) were not. Anyone picking up this codebase next should treat "update the test suite and root docs to match the split" as the natural next unit of work, not an oversight to work around silently.

---

## 30. Deployment: Dockerfile, docker-compose, environment variables

### 30.1 `auth-server/Dockerfile` — one generic multi-stage build for all six binaries

```dockerfile
# Generic Dockerfile for any cmd/* binary in this module.
# Build with --build-arg SERVICE=<name>, e.g. SERVICE=identity-service or
# SERVICE=iam-server, matching a directory under cmd/.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS build
ARG SERVICE
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/service ./cmd/${SERVICE}

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/service /service
ENTRYPOINT ["/service"]
```

One `Dockerfile`, parameterized by `SERVICE` build-arg, produces any of `iam-server`/`identity-service`/`mfa-service`/`key-rotator`/`migrate`/`worker` as a `CGO_ENABLED=0` static binary on a `distroless/static` final image (no shell, no package manager, minimal attack surface). There is exactly one Dockerfile in the whole repo — no per-service Dockerfiles.

### 30.2 `auth-server/docker-compose.yml` — full topology, minus iam-server

```yaml
name: auth-server

services:
  postgres:      # postgres:16, port 5433:5432, healthcheck via pg_isready
  redis:         # redis:7-alpine --appendonly yes, port 6380:6379, healthcheck via redis-cli ping
  nats:          # nats:2.10, ports 4223:4222 + 8223:8222, no healthcheck defined

  identity-service:
    build: {context: ., dockerfile: Dockerfile, args: {SERVICE: identity-service}}
    ports: ["8081:8081"]
    environment:
      APP_ENV: development
      IDENTITY_HTTP_PORT: "8081"
      DATABASE_URL: postgres://authadmin:authpassword@postgres:5432/authserver?sslmode=disable
    depends_on: {postgres: {condition: service_healthy}}
    healthcheck: {test: ["CMD", "wget", "-qO-", "http://localhost:8081/health"], interval: 10s}

  mfa-service:
    build: {context: ., dockerfile: Dockerfile, args: {SERVICE: mfa-service}}
    ports: ["8082:8082"]
    environment:
      APP_ENV: development
      MFA_HTTP_PORT: "8082"
      DATABASE_URL: postgres://authadmin:authpassword@postgres:5432/authserver?sslmode=disable
      REDIS_ADDR: redis:6379
      IDENTITY_SERVICE_URL: http://identity-service:8081
      JWT_ISSUER: http://localhost:8080
      WEBAUTHN_RPID: localhost
      WEBAUTHN_NAME: Auth Server
      WEBAUTHN_ORIGIN: http://localhost:3000
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}
      identity-service: {condition: service_healthy}
    healthcheck: {test: ["CMD", "wget", "-qO-", "http://localhost:8082/health"], interval: 10s}

  # iam-server is NOT containerized here — comment in the file states it's
  # included only to document the env vars it needs (IDENTITY_SERVICE_URL,
  # MFA_SERVICE_URL) to reach the two services above when run separately
  # (e.g. `go run ./cmd/iam-server` on the host, pointed at the composed
  # services' host-mapped ports http://localhost:8081 / :8082).

volumes: {auth_server_postgres_data:, auth_server_redis_data:}
networks: {auth-server-network: {driver: bridge}}
```

**⚠ `iam-server` has no compose service block** — it, `key-rotator`, `migrate`, and `worker` are all still expected to be run directly (`go run ./cmd/<binary>` or a manually-built binary) against the composed infra, not launched by `docker compose up`. `depends_on: condition: service_healthy` chains ensure `mfa-service` won't start serving until both `postgres`/`redis` are healthy *and* `identity-service`'s own healthcheck passes — a real startup-ordering dependency, since mfa-service's own `identityhttpclient` calls would fail against a not-yet-ready identity-service otherwise. No Kubernetes manifests exist anywhere in the repo.

### 30.3 Full environment variable table (all three HTTP services, consolidated)

All env vars are read through the single `internal/platform/config/config.go` `Load()`/`Config` struct — every one of the three services parses the *same* struct shape and simply ignores fields it doesn't use.

| Env var | Default | Used by |
|---|---|---|
| `APP_ENV` | `development` | all three |
| `HTTP_PORT` | `8080` | iam-server (listen port) |
| `DATABASE_URL` | `""` (must be set) | all three (same shared Postgres) |
| `DATABASE_READ_URL` | `""` | loaded everywhere, **not actually wired to any code path** in any binary (§4.7's `Pools` scaffolding remains unused post-split too) |
| `REDIS_ADDR` | `localhost:6380` | iam-server, mfa-service (identity-service doesn't touch Redis) |
| `NATS_URL` | `nats://localhost:4223` | iam-server only (worker also reads it independently) |
| `JWT_ISSUER` | `http://localhost:8080` | iam-server, mfa-service (both issue JWTs against the same shared signing-key table) |
| `WEBAUTHN_RPID` | `localhost` | mfa-service only (post-split; iam-server loads it into cfg but no longer uses it) |
| `WEBAUTHN_NAME` | `Auth Server` | mfa-service only |
| `WEBAUTHN_ORIGIN` | `http://localhost:3000` | mfa-service only |
| `IDENTITY_HTTP_PORT` | `8081` | identity-service (listen port) |
| `IDENTITY_SERVICE_URL` | `http://localhost:8081` | iam-server, mfa-service (both reach identity-service as a client) |
| `MFA_HTTP_PORT` | `8082` | mfa-service (listen port) |
| `MFA_SERVICE_URL` | `http://localhost:8082` | iam-server only (mfa-service doesn't call itself) |

Notable gaps: **no `IDENTITY_DATABASE_URL` / `MFA_DATABASE_URL`** — all three services share the literal same `DATABASE_URL` value; there is no way, short of editing code, to point identity-service or mfa-service at a genuinely separate database, which would be the natural next step if the "network-API boundary, not data-ownership split" framing is ever tightened into a real data-ownership split. No `IDENTITY_SERVICE_URL`/`MFA_SERVICE_URL` client-side timeout/retry configuration exists beyond the hardcoded 5-second `http.Client{Timeout: ...}` in each httpclient package (§29.1) — not configurable via env var.

### 30.4 Running the full 3-service stack locally

Not scripted anywhere in the repo (no `Makefile`, no `scripts/` content — §23) — the closest thing to a documented procedure, reconstructed from the compose file and `config.Load()` defaults:
1. `docker compose up -d postgres redis nats identity-service mfa-service` — brings up shared infra plus the two containerized services (waits on healthchecks).
2. Apply migrations manually against `postgres://authadmin:authpassword@localhost:5433/authserver` (`cmd/migrate` is still a no-op stub, §3.5) — e.g. via the `golang-migrate` CLI pointed at `auth-server/migrations/`.
3. On the host (not in Docker): `IDENTITY_SERVICE_URL=http://localhost:8081 MFA_SERVICE_URL=http://localhost:8082 DATABASE_URL=postgres://authadmin:authpassword@localhost:5433/authserver?sslmode=disable REDIS_ADDR=localhost:6380 NATS_URL=nats://localhost:4223 go run ./cmd/iam-server`.
4. Optionally, `go run ./cmd/worker` (same env) for audit-consumer/session-cleanup, and `go run ./cmd/key-rotator -alg ES256` once to seed an initial signing key (all three HTTP services read the same `signing_keys` table, so one rotation is sufficient for all of them).
5. `test/smoke/smoke.sh http://localhost:8080` would exercise iam-server's own routes correctly, but — per §22/§29.5 — would fail on any MFA/WebAuthn check baked into it that still assumes those routes live on 8080; those specific checks would need to be pointed at `http://localhost:8082` manually until the test suite itself is updated.
