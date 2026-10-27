# custom-auth-server — Infra, Dependency & Complexity Analysis

Audience: LLM agents that will write or run tests. Nothing in `qa-docs/` has been executed; treat every command as a spec to verify against source first.

## 1. What it is
Multi-tenant IAM / OAuth2 + OIDC authorization server in Go (`auth-server/`, module root). ~169 Go files / 13.4k LOC, 12 SQL migrations (420 LOC). Hexagonal layout per bounded context: `internal/<ctx>/{domain,app,infra,transport}`.

## 2. Deployables (`auth-server/cmd/`)
| Binary | Default port | Role |
|---|---|---|
| `iam-server` | 8080 (`PORT`) | Public API: register/login/refresh/logout, OAuth2 authorize/token/userinfo, OIDC discovery + JWKS, MFA, WebAuthn, RBAC, users, tenant policy, `/metrics`, `/health` |
| `identity-service` | 8081 | Internal identity CRUD: `/internal/identities[...]` |
| `mfa-service` | 8082 | Internal MFA factors/challenges: `/internal/mfa/...` |
| `worker` | – | NATS consumer (notifications, audit, async provisioning) |
| `key-rotator` | – | Signing-key rotation job (JWKS overlap window) |
| `migrate` | – | Applies `migrations/*.sql` |

## 3. Infra (`auth-server/docker-compose.yml`)
| Service | Image | Host port | Used for |
|---|---|---|---|
| postgres | postgres:16 | 5433 | system of record (identities, tenants, clients, refresh tokens, roles, factors, audit) |
| redis | redis:7-alpine | 6380 | sessions, rate limits, auth-code / challenge / token-revocation caches |
| nats | nats:2.10 | 4223 (client), 8223 (monitor) | domain events → worker |
| identity-service | built | 8081 | internal |
| mfa-service | built | 8082 | internal |

## 4. Direct dependencies (`go.mod`)
chi/v5 (router) · pgx/v5 + pgerrcode (Postgres) · go-redis/v9 · nats.go · golang-jwt/jwt/v5 · go-webauthn/webauthn · pquerna/otp (TOTP) · x/crypto (password hashing) · prometheus/client_golang · google/uuid · godotenv.

## 5. Bounded contexts (`internal/`)
auth, identity, session, token, oauth, oidc, mfa, webauthn, authorization (RBAC + middleware), tenant (+middleware), admin, provisioning, serviceaccount, federation, pam, risk, audit, notification.
Platform: config, postgres, redis, nats, secrets, httpserver, metrics. Shared: crypto, password, token, tx, tenancy, principal, clock, id, errors, validation, tracing, logging, slug.

## 6. Public HTTP surface (extracted from router registrations)
`POST /register /login /logout /refresh /mfa/complete /mfa/enroll/totp /mfa/enroll/verify /oauth/token /roles /roles/{roleID}/permissions /users /webauthn/{register,login}/{begin,complete}`
`GET /me /mfa/factors /oauth/authorize /oauth/userinfo /roles /roles/{roleID}/permissions /users /users/{userID} /tenant/policy /webauthn/credentials /.well-known/openid-configuration /.well-known/jwks.json /health /metrics`
`PUT /tenant/policy`
Internal: `POST|GET|DELETE /internal/identities[/{id}|/by-email]`, `/internal/mfa/factors[...]`, `/internal/mfa/challenges[/consume]`.
OAuth params read: `client_id client_secret code code_challenge code_challenge_method code_verifier grant_type redirect_uri refresh_token response_type scope state nonce`. Headers: `Authorization, X-Session-ID, X-Forwarded-For, X-Real-IP`.

## 7. Existing tests (do not duplicate; extend)
`test/integration/{auth,mfa,oauth,tenant_policy,webauthn}_test.go` (+`client.go`, `dbhelper.go`), `test/security/security_test.go`, `test/smoke/smoke.sh`, load mains: `test/{stress,spike,soak,abtest}/main.go`, empty `test/{e2e,fuzz}/`, runners `test/{run-all,race,coverage}.sh`. Unit tests in `internal/{token,oauth,tenant,mfa,identity,auth}/app` and `internal/shared/{password,token}`. Prior docs: `testdocs/v0.2.0-endpoint-tests.md`, `v0.7.0-test-strategy.md`, `v0.7.1-advanced-testing.md`; also `THREAT_MODEL.md`, `BENCHMARKS.md`, `DESIGN.md`. Makefile: `run fmt vet test race tidy build clean`.

## 8. Complexity & risk hot-spots (test priority order)
| # | Area | Why risky | Failure class |
|---|---|---|---|
| 1 | Refresh-token rotation + reuse detection (`internal/token`) | concurrent refresh of same token; family revocation | race, replay, lost session |
| 2 | Auth-code + PKCE (`internal/oauth`) | single-use code, redirect_uri exact match, verifier check | replay, open redirect, code injection |
| 3 | Tenant isolation (`internal/tenant`, `shared/tenancy`) | every query must be tenant-scoped | cross-tenant read/write |
| 4 | Session store in Redis | Redis is both cache and source of truth for sessions | fail-open vs fail-closed on Redis loss |
| 5 | Key rotation (`cmd/key-rotator`, JWKS) | tokens signed with old kid must verify during overlap | mass 401 after rotation |
| 6 | MFA challenge consume | single-use, TTL, brute-force of 6-digit TOTP | bypass, replay within time step |
| 7 | WebAuthn ceremony state | challenge stored between begin/complete; sign-counter regression | cloned authenticator accepted |
| 8 | RBAC middleware | permission cache staleness after role change | privilege persistence |
| 9 | Outbox/NATS publish vs DB commit (`shared/tx`, `platform/nats`) | dual write | lost / duplicate events |
| 10 | Split services (identity, mfa) over HTTP | partial failure, timeouts, no auth on `/internal/*` if exposed | cascading failure, SSRF-style access |
| 11 | Rate limit / risk engine using `X-Forwarded-For` | header spoofing | lockout bypass / victim lockout |
| 12 | Password hashing cost | CPU-bound → login is the DoS surface | latency collapse under load |

## 9. Data invariants to assert in every test tier
1. A refresh token is usable at most once; reuse revokes the whole family.
2. An authorization code is usable at most once and only with the original `redirect_uri`, `client_id`, PKCE verifier.
3. No row is readable through tenant A's token if `tenant_id = B`.
4. `email` unique per tenant (not globally) — confirm against migration.
5. A token whose `kid` is in JWKS verifies; one whose `kid` was removed does not.
6. Logout ⇒ session gone in Redis ⇒ access token rejected where introspected/`/me` session-bound.
7. Audit row exists for every auth-relevant state change (login ok/fail, MFA enroll, role grant, policy change).
8. Password hash never appears in any response body or log line.

## 10. Environment for tests
```
cd auth-server && docker compose up -d postgres redis nats
go run ./cmd/migrate            # verify flags in cmd/migrate/main.go
go run ./cmd/identity-service & go run ./cmd/mfa-service & go run ./cmd/iam-server & go run ./cmd/worker &
```
Config keys live in `internal/platform/config/*.go` (PORT=8080, Redis `localhost:6380`, identity 8081, mfa 8082). Confirm DSN/env names there before scripting.

## 11. Verification caveat
Routes and ports above were extracted mechanically. Request/response JSON field names were NOT read; confirm in `internal/*/transport/*.go` and `api/openapi/` before asserting on bodies.
