# custom-auth-server — Detailed Test Reference (Scenarios & Cases)

Audience: LLM/QA agents executing or automating tests. Nothing here has been run. Every fact tagged **[src]** was read from source (`auth-server/…`); everything else is a requirement-level expectation and must be confirmed against behaviour before raising a defect.

---------------------------------------------------------------------------------------------------
## 0. How to use this document
* Case ID format `AUTH-<AREA>-<NNN>`. Priority: **P0** release-blocker (security/data-loss), **P1** major functional, **P2** minor/UX, **P3** cosmetic.
* Tags: `[SMK]` smoke, `[FUN]` functional, `[NEG]` negative, `[BND]` boundary, `[SEC]` security, `[INT]` integration, `[E2E]`, `[REG]` regression-suite member, `[RACE]`, `[CON]` consistency, `[LOAD]`, `[STR]` stress, `[SPK]` spike, `[SOAK]`, `[SCAL]`, `[CHA]` chaos, `[DUR]` durability.
* Each case lists: **Setup** → **Action** → **Expected** (HTTP, body, DB/Redis/NATS side effects, metrics, logs). "Body error `X`" means JSON `{"error":"X"}` **[src: response.go `error` field]**.
* Every case that mutates state ends with the **post-condition audit** in §14 (invariants) unless stated otherwise.
* Scripts implementing these cases: `03-TEST-SCRIPTS.md`.

---------------------------------------------------------------------------------------------------
## 1. System facts the tests rely on [src]
| Fact | Value |
|---|---|
| Binaries / ports | `iam-server` :8080, `identity-service` :8081, `mfa-service` :8082, `worker`, `key-rotator`, `migrate` |
| Public iam routes | `GET /health` (body `ok`), `POST /register`, `POST /login`, `POST /refresh`, `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`, `/metrics`, `POST /oauth/token` |
| Authenticated iam routes | `GET /me`, `POST /logout`, `GET /oauth/authorize`, `GET /oauth/userinfo`, `GET /tenant/policy` |
| Permission-gated iam routes | `PUT /tenant/policy` → `tenant:update`; `GET /users`, `GET /users/{userID}` → `users:read`; `POST /users` → `users:create`; `POST /roles` → `roles:create`; `GET /roles`, `GET /roles/{roleID}/permissions` → `roles:read`; `POST /roles/{roleID}/permissions` → `roles:update` |
| mfa-service public | `POST /mfa/complete`, `POST /webauthn/login/begin`, `POST /webauthn/login/complete` |
| mfa-service authenticated | `POST /mfa/enroll/totp`, `POST /mfa/enroll/verify`, `GET /mfa/factors`, `POST /webauthn/register/begin`, `POST /webauthn/register/complete`, `GET /webauthn/credentials` |
| Internal (no auth middleware wired!) | identity-service: `GET /internal/identities/by-email`, `GET/DELETE /internal/identities/{id}`, `POST /internal/identities`; mfa-service: `POST /internal/mfa/factors`, `GET …/by-identity`, `GET …/verified`, `GET/DELETE …/{id}`, `POST …/{id}/verify`, `POST /internal/mfa/challenges`, `POST /internal/mfa/challenges/consume` |
| Authentication middleware | Accepts `Authorization: Bearer <JWT>` (verify via jwtService) **or** `X-Session-ID: <session id>` (cache → `sessions` table, rejects `revoked_at != nil`); else 401 plain text `unauthorized` |
| Middleware chain | CORS → RequestLogger → metrics (label = chi route pattern) |
| Login request | `{"email","password"}`; 400 `invalid request body` on bad JSON; 400 `email and password are required`; 401 `invalid credentials`; 403 `mfa enrollment required`; 500 `internal error` |
| Login response (`LoginOutput`) | `session_id, tenant_id, user_id, roles[], permissions[], access_token, expires_in, refresh_token, mfa_required, mfa_token` (all omitempty) + `Set-Cookie` refresh cookie |
| Refresh cookie | `Path=/`, `MaxAge=604800` (7 d), `HttpOnly`, `SameSite=Strict`, **`Secure=false`** |
| Refresh request / response | `{"refresh_token"}` → `{session_id, tenant_id, user_id, refresh_token}` (+ access token fields — verify) |
| Register | `{"email","password"}` → `{"message"}` |
| Create user (admin) | `{"email","password","display_name","role_name"}` |
| Roles | create `{"name","description"}`; assign permission `{"permission"}` |
| MFA | enroll `{label}` → `{factor_id, …}`; verify `{factor_id, code}`; complete `{mfa_token, code}`; list items `{id, factor_type, label, verified}` |
| WebAuthn | begin → `{session_key, options}`; complete `{session_key, label?, response}`; credential `{id,label,transports[],created_at,last_used_at}` |
| Tenant policy | `password_min_length` (default 8), `password_require_upper`, `password_require_digit`, `password_require_symbol`, `allowed_email_domains[]`, `require_mfa`, `max_active_sessions` |
| JWT custom claims | `tid, uid, sid, email, roles[], permissions[], nonce` (+ registered `sub, iss, aud, exp, iat`) |
| JWKS key fields | `kty, use, alg, kid, crv` (EC and RSA both supported: errors "not an ECDSA key"/"not an RSA key") |
| OIDC discovery keys | `issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, response_types_supported, grant_types_supported, subject_types_supported, id_token_signing_alg_values_supported, scopes_supported, token_endpoint_auth_methods_supported, code_challenge_methods_supported, claims_supported` |
| userinfo | `{sub, email, email_verified}` |
| Auth code record | `code, client_id, tenant_id, identity_id, user_id, scopes[], redirect_uri, code_challenge, code_challenge_method, nonce, expires_at` |
| TTLs / constants | access token **15 min**; refresh token **7 d**; auth code **10 min**; MFA/WebAuthn challenge **5 min**; session cache TTL **5 min**; session cleanup every **5 min**; inter-service client timeout **5 s**; tenant slug generation **max 5 attempts** |
| Password hashing | **argon2id**, salt 16 B, key 32 B, PHC string `$argon2id$v=19$m=…,t=…,p=…$salt$hash` (fuzz test exists for malformed hashes) |
| PKCE | only `S256` accepted (`authorize.go`), else `unsupported_challenge_method`; missing → `missing_pkce` |
| OAuth error codes | `invalid_client, invalid_grant, invalid_redirect_uri, invalid_scope, missing_pkce, unsupported_challenge_method, unsupported_grant_type, unsupported_response_type` (body `{error, error_description}`) |
| Domain errors | `conflict, email domain not allowed, factor not found, forbidden, invalid code, invalid credentials, mfa enrollment required, not found, password requires digit, password requires symbol, password requires uppercase letter, password too short, tenant mismatch, unauthorized, unknown credential` |
| Client IP | from `X-Forwarded-For` (first hop) then `X-Real-IP` then RemoteAddr — **client-controlled**, stored in `sessions.ip_address` and audit |
| Tables | tenants, identities (`primary_email` **globally UNIQUE**), users (UNIQUE tenant_id+identity_id, tenant_id+username), credentials, devices, mfa_factors, sessions, roles (UNIQUE tenant_id+name), permissions (unique `COALESCE(tenant_id,'')+name`), role_permissions, user_roles, policies, oauth_clients (`client_id` UNIQUE), service_accounts (`client_id` UNIQUE), audit_events, refresh_tokens (`token_hash` UNIQUE), signing_keys, webauthn_credentials (`credential_id` UNIQUE), tenant_policies |
| Audit event | `id, tenant_id, actor_identity_id, event_type, resource_type, resource_id, ip_address, payload, created_at` |
| Not implemented (empty `domain/`) | federation, pam, risk, provisioning, serviceaccount — and **no rate limiting / lockout code found** |

---------------------------------------------------------------------------------------------------
## 2. Test environments & data
| Env | Composition | Used for |
|---|---|---|
| E-UNIT | `go test ./internal/...` (no infra) | domain/app logic, fuzz |
| E-INT | `docker compose up postgres redis nats` + `go run ./cmd/migrate` + 3 services + worker | integration, functional, negative |
| E-HA | E-INT ×3 iam replicas behind nginx/haproxy, 2 identity, 2 mfa | consistency, scalability, chaos |
| E-PERF | E-HA on dedicated hosts, PG tuned, k6 runners separate | load/stress/soak |
| E-CHAOS | E-HA + toxiproxy in front of PG/Redis/NATS/identity/mfa | chaos |

**Seed data set `DS-1`** (scripted): tenants T1 (default policy), T2 (`require_mfa=true`), T3 (`allowed_email_domains=["corp.test"]`, `password_min_length=14`, all require_* true, `max_active_sessions=2`); per tenant: admin (all perms), `viewer` role (`users:read`,`roles:read`), plain user; one OAuth client per tenant with redirect `https://app.test/cb` and scopes `openid email profile`; one service account client.
**Credentials corpus `PW-SET`**: `Aa1!aaaa` (8, all classes), `aaaaaaaa` (lower only), `AAAAAAAA1!`, `Aa1!` (4), `Aa1!`+`a`*1018 (1 KB), 1 MB string, unicode `Pässwörd1!`, emoji `🔐🔐Aa1!xx`, string with NUL `Aa1!\u0000xxx`, whitespace-only `"        "`, leading/trailing spaces `" Aa1!aaaa "`.
**Email corpus `EM-SET`**: `a@b.co`, `UPPER@Case.Test`, `upper@case.test` (dup by case?), `x+tag@corp.test`, `"quoted"@corp.test`, `a@sub.corp.test`, `a@corp.test.evil.com`, `a@CORP.TEST`, `ünï@corp.test`, `a@xn--bcher-kva.example`, 254-char valid, 255+, no `@`, two `@`, empty, `<script>@x.y`, `' OR 1=1--@x.y`.

---------------------------------------------------------------------------------------------------
## 3. Health, discovery, JWKS, metrics
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-HLT-001 | E-INT | `GET :8080/health` | 200, body exactly `ok` | P0 | SMK |
| AUTH-HLT-002 | | `GET :8081/health`, `GET :8082/health` | 200 | P0 | SMK |
| AUTH-HLT-003 | stop Postgres | `GET /health` on each | Document: health is shallow (still 200) → defect P2 "no readiness signal"; LB will route to broken pods | P2 | CHA |
| AUTH-OIDC-001 | | `GET /.well-known/openid-configuration` | 200 JSON with all 13 keys of §1; `issuer` equals JWT `iss`; endpoints absolute URLs reachable | P0 | SMK FUN |
| AUTH-OIDC-002 | | discovery `code_challenge_methods_supported` | exactly `["S256"]` (matches enforcement) | P1 | FUN |
| AUTH-OIDC-003 | | discovery `grant_types_supported` vs `/oauth/token` behaviour | every advertised grant works; every unadvertised returns `unsupported_grant_type` | P1 | FUN |
| AUTH-OIDC-004 | | `response_types_supported` | contains `code`; `token`/`id_token` absent (implicit flow not supported) | P1 | SEC |
| AUTH-OIDC-005 | | `scopes_supported`, `claims_supported` | userinfo only returns claims listed | P2 | FUN |
| AUTH-OIDC-006 | | `Cache-Control` on discovery | cacheable (public, max-age) | P3 | FUN |
| AUTH-JWKS-001 | | `GET /.well-known/jwks.json` | 200 `{keys:[…]}`, ≥1 key, each has `kty,use=sig,alg,kid`; EC keys have `crv` | P0 | SMK |
| AUTH-JWKS-002 | | inspect key material | **no private parameters** (`d`, `p`, `q`, `dp`, `dq`, `qi`) | P0 | SEC |
| AUTH-JWKS-003 | | login, decode JWT header | `kid` ∈ JWKS, `alg` matches key | P0 | FUN |
| AUTH-JWKS-004 | run `key-rotator` | JWKS before/after | new kid added; old kid retained until all tokens signed with it expired (≥15 min) | P0 | FUN |
| AUTH-JWKS-005 | token signed before rotation | `GET /me` after rotation | 200 (old key still verifies) | P0 | REG |
| AUTH-JWKS-006 | old key retired (after overlap) | old token `GET /me` | 401 | P1 | FUN |
| AUTH-JWKS-007 | | two iam replicas | identical JWKS (keys from `signing_keys` table, not per-process) | P0 | CON |
| AUTH-MET-001 | | `GET /metrics` | Prometheus text; request counter/histogram labelled with route **pattern** (`/users/{userID}`), not raw path | P1 | FUN |
| AUTH-MET-002 | 10k requests to `/users/<random uuid>` | metric series count | does not grow with distinct ids (cardinality bounded) | P1 | STR |
| AUTH-MET-003 | 404 on unknown path `/x/<random>` ×10k | metric series | label falls back to `req.URL.Path` **[src]** → unbounded cardinality → defect P1 if confirmed | P1 | SEC STR |
| AUTH-MET-004 | | metrics endpoint exposure | public on :8080 without auth — document; must not expose emails/tokens in labels | P2 | SEC |

---------------------------------------------------------------------------------------------------
## 4. Registration — `POST /register`
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-REG-001 | fresh email | `{"email":"new@t.test","password":"Aa1!aaaa"}` | 2xx (201/200 — record which), body `{message}`; rows: identities(1), tenants(1, slug derived), users(1), credentials(1, argon2id PHC); audit `register` event; NATS event published | P0 | SMK FUN |
| AUTH-REG-002 | after 001 | `SELECT secret FROM credentials` | starts `$argon2id$v=19$`, salt 16 B, hash 32 B base64; plaintext absent | P0 | SEC |
| AUTH-REG-003 | | response headers/body/logs | no password or hash anywhere (grep logs for the plaintext) | P0 | SEC |
| AUTH-REG-004 | email exists | register same email | 409 body `conflict` (or generic) — no 500 | P0 | NEG |
| AUTH-REG-005 | `User@T.test` exists | register `user@t.test` | must be treated as duplicate (case-insensitive) — if 2xx and two identities → defect P1 (account confusion) | P1 | NEG |
| AUTH-REG-006 | | email with surrounding spaces `" a@t.test "` | trimmed or 400; never stored with spaces | P2 | BND |
| AUTH-REG-007 | each EM-SET invalid item | register | 400; no rows | P1 | NEG |
| AUTH-REG-008 | 254-char valid email | register | 2xx | P2 | BND |
| AUTH-REG-009 | 320+ char email | register | 400 | P2 | BND |
| AUTH-REG-010 | missing `email` / missing `password` / both empty | register | 400 | P1 | NEG |
| AUTH-REG-011 | body `{`, `[]`, `null`, `""`, form-encoded, `text/plain` | register | 400 `invalid request body` | P1 | NEG |
| AUTH-REG-012 | unknown fields `{"email","password","tenant_id":"<T1>","role":"admin","is_admin":true}` | register then login | ignored: new tenant/no admin perms (mass assignment) | P0 | SEC |
| AUTH-REG-013 | default policy (min 8) | password 7 chars `Aa1!aaa` | 400 `password too short` | P1 | BND |
| AUTH-REG-014 | | password exactly 8 | 2xx | P1 | BND |
| AUTH-REG-015 | | 1 KB password | 2xx; hashing time < 1 s | P2 | BND |
| AUTH-REG-016 | | 1 MB password | 400/413 quickly (argon2 over 1 MB is CPU DoS) — if accepted and slow → defect P1 | P1 | SEC STR |
| AUTH-REG-017 | | unicode/emoji password | 2xx; login with same string works; NFC vs NFD variants behaviour documented | P2 | BND |
| AUTH-REG-018 | | password with NUL | accepted & round-trips, or 400 — must not truncate at NUL (login with prefix must fail) | P1 | SEC |
| AUTH-REG-019 | | whitespace-only password | 400 | P2 | NEG |
| AUTH-REG-020 | registration does it apply tenant policy? | register into a tenant with require_upper | register creates its own tenant → policy of *new* tenant (default) applies; document | P2 | FUN |
| AUTH-REG-021 | slug collision | register 6 identities whose emails derive the same slug base | first 5 retries succeed; 6th → defined error (not 500 loop); `maxSlugAttempts=5` | P2 | BND |
| AUTH-REG-022 | | 50 concurrent registers same email | exactly 1 success, 49 × 409; no 500 (unique violation mapped) | P0 | RACE |
| AUTH-REG-023 | | 50 concurrent registers different emails same slug base | all succeed with unique slugs or bounded failures; no duplicate slug rows | P1 | RACE |
| AUTH-REG-024 | | response time existing vs new email | similar (≤ 50 ms delta) — user enumeration via timing | P2 | SEC |
| AUTH-REG-025 | NATS down | register | registration succeeds (or fails atomically) — never row-without-event silently lost; see §11 | P1 | CHA |
| AUTH-REG-026 | identity-service down | register | 503/500 within ~5 s timeout; no partial rows in iam DB | P1 | CHA |

---------------------------------------------------------------------------------------------------
## 5. Login, sessions, refresh, logout, /me
### 5.1 Login `POST /login`
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-LGN-001 | DS-1 user | correct creds | 200 `LoginOutput` with `session_id, tenant_id, user_id, roles, permissions, access_token, expires_in=900, refresh_token`; `Set-Cookie` refresh (HttpOnly, SameSite=Strict, Max-Age=604800); row in `sessions` (ip, UA), row in `refresh_tokens` (hash only); audit `login.success` | P0 | SMK |
| AUTH-LGN-002 | | decode access JWT | `sub`=identity, `tid`=tenant, `uid`=user, `sid`=session_id, `roles`/`permissions` = DB state, `exp-iat`=900 s, `iss` = discovery issuer | P0 | FUN |
| AUTH-LGN-003 | | `refresh_tokens.token_hash` | hash of returned token (token itself not stored) | P0 | SEC |
| AUTH-LGN-004 | | wrong password | 401 `invalid credentials`; audit `login.failure` | P0 | NEG |
| AUTH-LGN-005 | | unknown email | 401 `invalid credentials` (identical body) | P0 | SEC |
| AUTH-LGN-006 | | timing unknown vs wrong password over 200 samples | median delta < 20 ms (dummy argon2 on unknown user) — else enumeration defect P2 | P2 | SEC |
| AUTH-LGN-007 | | email different case | succeeds iff stored normalised (consistent with AUTH-REG-005) | P1 | FUN |
| AUTH-LGN-008 | | missing fields / empty strings | 400 `email and password are required` | P1 | NEG |
| AUTH-LGN-009 | | malformed body | 400 `invalid request body` | P1 | NEG |
| AUTH-LGN-010 | T2 (`require_mfa=true`) user with no factor | login | 403 `mfa enrollment required` | P0 | FUN |
| AUTH-LGN-011 | T2 user with verified TOTP | login | 200 with `mfa_required=true`, `mfa_token`, **no** `access_token`/`refresh_token`/cookie | P0 | SEC |
| AUTH-LGN-012 | non-MFA tenant user who enrolled TOTP voluntarily | login | `mfa_required=true` (enrolled factor enforced) — document actual | P1 | FUN |
| AUTH-LGN-013 | T3 `max_active_sessions=2` | 3 logins | 3rd: oldest session revoked (or 3rd rejected) — document; `count(active sessions) ≤ 2` always | P1 | FUN BND |
| AUTH-LGN-014 | | 100 failed logins then correct | **Current: succeeds (no lockout implemented)** → raise P1 security defect "no brute-force protection"; when fixed expect 429/423 after N | P1 | SEC |
| AUTH-LGN-015 | | `X-Forwarded-For: 1.2.3.4` | `sessions.ip_address` = `1.2.3.4` — spoofable; document; when behind trusted proxy must use right-most trusted hop | P2 | SEC |
| AUTH-LGN-016 | | `X-Forwarded-For: <script>`, 10 KB XFF, `'; DROP TABLE` | stored safely (text column), no 500 | P2 | SEC |
| AUTH-LGN-017 | | 1 MB password at login | fast 400/401, not CPU burn | P1 | STR |
| AUTH-LGN-018 | user deleted via identity-service DELETE | login | 401 | P1 | FUN |
| AUTH-LGN-019 | | login with stored hash corrupted (`UPDATE credentials SET secret='$argon2id$v=19$m=0'`) | 401/500 without panic (fuzz-covered) | P2 | NEG |
| AUTH-LGN-020 | Redis down | login | either 503 or success with DB session; never 200 without usable session | P1 | CHA |
### 5.2 Session usage and `/me`
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-SES-001 | logged in | `GET /me` Bearer | 200 principal of caller | P0 | SMK |
| AUTH-SES-002 | | `GET /me` with `X-Session-ID: <session_id>` only | 200 (session path) | P0 | FUN |
| AUTH-SES-003 | | `X-Session-ID` of another user's session (leaked id) | 200 as that user — **session id is a bearer credential**; verify ids are unguessable (UUIDv4/128-bit) and never logged/returned elsewhere | P0 | SEC |
| AUTH-SES-004 | | random UUID in X-Session-ID | 401 | P0 | NEG |
| AUTH-SES-005 | | non-UUID X-Session-ID (`' OR 1=1`, 10 KB) | 401, no 500 | P1 | SEC |
| AUTH-SES-006 | session revoked in DB | X-Session-ID within cache TTL (≤5 min) | **may still pass from cache** → document window; P1 if > 5 min | P1 | CON |
| AUTH-SES-007 | revoked | after 5 min cache TTL | 401 | P1 | FUN |
| AUTH-SES-008 | | Bearer variants: `bearer x` (lowercase), `Bearer  x` (two spaces), `Bearer` (no token), `Basic …`, token in query `?access_token=` | 401 for all except exact `Bearer <jwt>` | P1 | NEG |
| AUTH-SES-009 | | JWT expired (`exp` past) | 401 | P0 | NEG |
| AUTH-SES-010 | | JWT `exp` = now ± leeway (craft with test key or wait 15 min) | boundary deterministic; leeway ≤ 60 s | P2 | BND |
| AUTH-SES-011 | | `alg:none` token with valid-looking claims | 401 | P0 | SEC |
| AUTH-SES-012 | | HS256 token signed with JWKS public key bytes | 401 | P0 | SEC |
| AUTH-SES-013 | | header `kid` missing | 401 (`missing kid header`) | P1 | NEG |
| AUTH-SES-014 | | header `kid` = unknown / path traversal / SQL | 401 | P1 | SEC |
| AUTH-SES-015 | | modify payload `permissions` + keep signature | 401 | P0 | SEC |
| AUTH-SES-016 | | `jku`/`x5u`/`jwk` header injection | ignored → 401 | P0 | SEC |
| AUTH-SES-017 | | JWT valid, but session `sid` revoked (logout) | Bearer path does **not** consult session (stateless) → token valid until exp (≤15 min); document as accepted risk or defect P1 | P1 | SEC CON |
| AUTH-SES-018 | | JWT with `tid` of T1 used for T2 resources | 403/404 (`tenant mismatch`) | P0 | SEC |
| AUTH-SES-019 | | session cleanup job | expired sessions purged within 5 min of expiry | P2 | FUN |
### 5.3 Refresh `POST /refresh`
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-REF-001 | logged in | body `{"refresh_token":RT}` | 200 new RT (≠ RT) (+ access token); cookie updated; old `refresh_tokens` row revoked/rotated | P0 | FUN |
| AUTH-REF-002 | | refresh using **cookie only** (no body) | 200 if cookie supported — document | P1 | FUN |
| AUTH-REF-003 | after 001 | reuse old RT | 401 `invalid_grant`/unauthorized; **family revoked** (new RT from 001 also invalid) — if not, P1 defect "no reuse detection" | P0 | SEC |
| AUTH-REF-004 | | garbage / empty / 10 KB / JWT as RT | 400/401, no 500 | P1 | NEG |
| AUTH-REF-005 | | RT after 7 d (time-travel via DB `expires_at` update) | 401 | P1 | BND |
| AUTH-REF-006 | | RT after logout | 401 | P0 | FUN |
| AUTH-REF-007 | | RT of user whose roles changed | new access token reflects new roles/permissions | P1 | CON |
| AUTH-REF-008 | | RT of deleted user / disabled tenant | 401 | P1 | FUN |
| AUTH-REF-009 | | 50 parallel refresh same RT | ≤1 success (row-level lock / CAS on token_hash) | P0 | RACE |
| AUTH-REF-010 | | refresh chain 1000 times | each RT single-use; DB rows bounded (old rows expire/cleanup) | P2 | SOAK |
| AUTH-REF-011 | | CSRF: cross-site POST /refresh with cookie | SameSite=Strict blocks cookie; CORS must not allow credentialed cross-origin | P1 | SEC |
### 5.4 Logout `POST /logout`
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-OUT-001 | | logout with Bearer | 204/200; session `revoked_at` set; refresh family revoked; cookie cleared (`Max-Age=0`) | P0 | FUN |
| AUTH-OUT-002 | | `/me` with X-Session-ID after logout | 401 (after cache invalidation — must be immediate on same replica; ≤5 min on others) | P0 | CON |
| AUTH-OUT-003 | | logout twice | idempotent 2xx/401, never 500 | P2 | NEG |
| AUTH-OUT-004 | | logout without auth | 401 | P1 | NEG |
| AUTH-OUT-005 | two sessions | logout one | other session still valid | P1 | FUN |

---------------------------------------------------------------------------------------------------
## 6. MFA (mfa-service :8082)
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-MFA-001 | logged-in user | `POST :8082/mfa/enroll/totp {"label":"phone"}` | 200 `factor_id`, secret/otpauth URI (base32, ≥160-bit), factor row `verified=false` | P0 | FUN |
| AUTH-MFA-002 | | `GET /mfa/factors` | lists factor `{id,factor_type:"totp",label,verified:false}`; no secret in list | P0 | SEC |
| AUTH-MFA-003 | | `POST /mfa/enroll/verify {factor_id, code:<valid>}` | 200; `verified=true`; audit | P0 | FUN |
| AUTH-MFA-004 | | verify wrong code | 400/401 `invalid code`; still unverified | P0 | NEG |
| AUTH-MFA-005 | | verify with code from previous step (t-30 s) and next (t+30 s) | accepted per skew window (document ±1) ; t±60 s rejected | P1 | BND |
| AUTH-MFA-006 | | verify factor_id of another user | 404 `factor not found` (not 403 leaking existence) | P0 | SEC |
| AUTH-MFA-007 | | codes `""`, `12345`, `1234567`, `abcdef`, ` 123456`, `123 456` | 400/401 | P1 | NEG |
| AUTH-MFA-008 | verified TOTP | login → `mfa_token` → `POST :8082/mfa/complete {mfa_token, code}` | 200 full token set + cookie; session created only now | P0 | FUN |
| AUTH-MFA-009 | | complete with wrong code | 401 `invalid code`; mfa_token still usable until consumed/expired? document attempts limit | P0 | NEG |
| AUTH-MFA-010 | | complete reusing the same mfa_token after success | 401 (challenge consumed) | P0 | SEC |
| AUTH-MFA-011 | | complete same valid TOTP code twice (two mfa_tokens, same 30 s step) | second rejected (replay protection) — if accepted P1 defect | P1 | SEC |
| AUTH-MFA-012 | | mfa_token after 5 min | 401 (challengeTTL) | P1 | BND |
| AUTH-MFA-013 | | brute-force: 1,000,000 codes is infeasible but 1000 attempts per token? | attempts per mfa_token limited (≤5) — absent → P1 defect | P1 | SEC |
| AUTH-MFA-014 | | 50 parallel completes same mfa_token + valid code | exactly 1 success (`/internal/mfa/challenges/consume` atomic) | P0 | RACE |
| AUTH-MFA-015 | | `mfa_token` of user A with TOTP of user B | 401 | P0 | SEC |
| AUTH-MFA-016 | | enroll twice | two factors or replaces — document; unverified factors don't count toward login MFA | P2 | FUN |
| AUTH-MFA-017 | | access_token obtained pre-MFA? | impossible (AUTH-LGN-011) | P0 | SEC |
| AUTH-MFA-018 | T2 require_mfa | enroll while having `mfa enrollment required` (403 at login) | document bootstrap path (how does user enroll without a session?) — gap analysis | P1 | FUN |
| AUTH-MFA-019 | | TOTP secret storage | encrypted at rest or plaintext? (`mfa_factors`) — plaintext → P2 finding | P2 | SEC |
## 6.1 WebAuthn (mfa-service)
| ID | Setup | Action | Expected | Pri | Tags |
|---|---|---|---|---|---|
| AUTH-WA-001 | logged-in; virtual authenticator (Chrome DevTools / `go-webauthn` test helper / soft-webauthn lib) | `register/begin` → `{session_key, options}` | options: rp.id = configured domain, challenge ≥16 B random, user.id opaque (not email), `excludeCredentials` lists existing | P0 | FUN |
| AUTH-WA-002 | | `register/complete {session_key,label,response}` | 200; row in `webauthn_credentials` (credential_id UNIQUE, public key, sign_count) | P0 | FUN |
| AUTH-WA-003 | | `GET /webauthn/credentials` | lists `{id,label,transports,created_at,last_used_at:null}` | P1 | FUN |
| AUTH-WA-004 | | login begin/complete | 200 tokens; `last_used_at` set; sign_count updated | P0 | FUN |
| AUTH-WA-005 | | complete with wrong `session_key` / expired (>5 min) / reused | 400/401 | P0 | NEG |
| AUTH-WA-006 | | assertion from origin `https://evil.test` | rejected (origin check) | P0 | SEC |
| AUTH-WA-007 | | rpIdHash mismatch | rejected | P0 | SEC |
| AUTH-WA-008 | | sign_count not increasing (cloned authenticator) | rejected or flagged | P1 | SEC |
| AUTH-WA-009 | | register same authenticator twice | `excludeCredentials` / UNIQUE prevents duplicate | P2 | NEG |
| AUTH-WA-010 | | unknown credential id at login | 401 `unknown credential` | P1 | NEG |
| AUTH-WA-011 | | `response` malformed JSON / CBOR garbage / 1 MB | 400, no panic | P1 | SEC |
| AUTH-WA-012 | | UV flag absent when required | rejected per policy | P2 | SEC |
| AUTH-WA-013 | two users | user B lists credentials | only own | P0 | SEC |

---------------------------------------------------------------------------------------------------
## 7. OAuth 2.0 / OIDC
Setup for all: DS-1 client `C1` (`client_id`, `client_secret`, redirect `https://app.test/cb`, scopes `openid email profile`), logged-in user U (Bearer — `/oauth/authorize` is behind `withAuth` **[src]**), PKCE pair (V, C=BASE64URL(SHA256(V))).
| ID | Action | Expected | Pri | Tags |
|---|---|---|---|---|
| AUTH-OA-001 | `GET /oauth/authorize?response_type=code&client_id=C1&redirect_uri=https://app.test/cb&scope=openid%20email&state=s1&nonce=n1&code_challenge=C&code_challenge_method=S256` | 302 `Location: https://app.test/cb?code=…&state=s1`; code row: tenant, identity, scopes, challenge, nonce, `expires_at=now+10m` | P0 | SMK FUN |
| AUTH-OA-002 | `POST /oauth/token` form `grant_type=authorization_code&code&redirect_uri&client_id&client_secret&code_verifier=V` | 200 `access_token, token_type=Bearer, expires_in=900, refresh_token, id_token`; id_token `aud=C1`, `nonce=n1`, `sub` | P0 | FUN |
| AUTH-OA-003 | same code again | 400 `invalid_grant`; tokens from first exchange revoked (RFC 6749 §4.1.2) — absent → P1 | P0 | SEC |
| AUTH-OA-004 | code after 10 min | `invalid_grant` | P1 | BND |
| AUTH-OA-005 | wrong verifier | `invalid_grant` | P0 | SEC |
| AUTH-OA-006 | missing `code_challenge` at authorize | `missing_pkce` (error redirect or 400) | P0 | SEC |
| AUTH-OA-007 | `code_challenge_method=plain` / absent / `s256` (lowercase) | `unsupported_challenge_method` (case-sensitive per src) | P1 | SEC |
| AUTH-OA-008 | missing `code_verifier` at token | `invalid_grant` | P0 | SEC |
| AUTH-OA-009 | verifier length 42 / 43 / 128 / 129, invalid chars (`+`,`/`,`=`) | RFC 7636: 43–128 unreserved only | P2 | BND |
| AUTH-OA-010 | unknown client_id at authorize | 400 `invalid_client` **without redirect** | P0 | SEC |
| AUTH-OA-011 | redirect_uri variants: `https://app.test/cb/`, `https://app.test/cb?x=1`, `https://APP.test/cb`, `https://app.test/cb#f`, `https://app.test.evil.com/cb`, `https://app.test@evil.com/cb`, `http://app.test/cb`, `https://app.test/cb/../evil`, `javascript:alert(1)`, empty | 400 `invalid_redirect_uri`, **never** a 302 to the supplied URI (exact match) | P0 | SEC |
| AUTH-OA-012 | `response_type=token` / `id_token` / `code token` / empty | `unsupported_response_type` | P1 | SEC |
| AUTH-OA-013 | scope not allowed for client (`admin`) | `invalid_scope` | P1 | SEC |
| AUTH-OA-014 | scope subset (`openid` only) | userinfo omits email | P2 | FUN |
| AUTH-OA-015 | `state` missing | flow works (state is client's concern) or 400 — document; `state` echoed verbatim incl. special chars URL-encoded | P2 | FUN |
| AUTH-OA-016 | `state`=`<script>`/CRLF `%0d%0aSet-Cookie:x` | encoded in Location; no header injection | P0 | SEC |
| AUTH-OA-017 | token request with code issued to C1 but `client_id=C2` (valid C2 creds) | `invalid_grant` | P0 | SEC |
| AUTH-OA-018 | token request with wrong `client_secret` / missing secret for confidential client | `invalid_client` (401 with `WWW-Authenticate` if Basic) | P0 | SEC |
| AUTH-OA-019 | client auth via HTTP Basic vs body — match `token_endpoint_auth_methods_supported` | advertised methods work, others rejected | P1 | FUN |
| AUTH-OA-020 | `redirect_uri` at token differs from authorize | `invalid_grant` | P0 | SEC |
| AUTH-OA-021 | `grant_type=refresh_token` with RT | new pair; rotation & reuse rules = §5.3 | P0 | FUN |
| AUTH-OA-022 | `grant_type=client_credentials` (service account) | if advertised: access token without refresh, `sub`=client; else `unsupported_grant_type` (`serviceaccount` domain is empty → likely unsupported) | P1 | FUN |
| AUTH-OA-023 | `grant_type=password` / `implicit` / `urn:ietf:params:oauth:grant-type:device_code` / empty | `unsupported_grant_type` | P1 | SEC |
| AUTH-OA-024 | token endpoint with JSON body instead of form | 400 or supported — document (RFC requires form) | P2 | NEG |
| AUTH-OA-025 | `/oauth/authorize` without login | 401 (not login redirect) — document UX | P2 | FUN |
| AUTH-OA-026 | code bound to tenant T1; user session in T2 | `tenant mismatch` | P0 | SEC |
| AUTH-OA-027 | userinfo with access token | `{sub,email,email_verified}`; `sub` equals id_token `sub` | P0 | FUN |
| AUTH-OA-028 | userinfo with expired/garbage/id_token | 401 | P1 | NEG |
| AUTH-OA-029 | 50 concurrent exchanges of one code | exactly 1 success | P0 | RACE |
| AUTH-OA-030 | id_token signature verify with JWKS; `iss`,`aud`,`exp`,`iat`,`nonce` checks; `at_hash` if present | valid | P0 | FUN |
| AUTH-OA-031 | open-redirect via error path: unknown scope with valid client+redirect | error delivered to registered redirect only | P1 | SEC |
| AUTH-OA-032 | Authorization code leakage via Referer | Location response has `Referrer-Policy` / page doesn't load third-party | P3 | SEC |

---------------------------------------------------------------------------------------------------
## 8. RBAC, users, roles, tenant policy
### 8.1 Permission matrix (exhaustive) [src]
For each role R ∈ {admin(all), viewer(users:read, roles:read), plain(none), cross-tenant admin (T2 admin calling T1 ids)} and each route, assert:

| Route | admin | viewer | plain | T2-admin on T1 object |
|---|---|---|---|---|
| GET /tenant/policy | 200 | 200 | 200 | own tenant only |
| PUT /tenant/policy | 200 | 403 | 403 | n/a (implicit tenant) |
| GET /users | 200 (T1 only) | 200 | 403 | returns T2 users only |
| GET /users/{T1 user} | 200 | 200 | 403 | **404** (never T1 data) |
| POST /users | 201 | 403 | 403 | creates in T2 only |
| POST /roles | 201 | 403 | 403 | T2 only |
| GET /roles | 200 | 200 | 403 | T2 only (+ global roles?) |
| POST /roles/{T1 role}/permissions | 200 | 403 | 403 | **404/403** |
| GET /roles/{T1 role}/permissions | 200 | 200 | 403 | **404/403** |
IDs AUTH-RBAC-001…036 = each cell. P0 for every cross-tenant cell and every 403 cell.
### 8.2 Users & roles functional
| ID | Action | Expected | Pri | Tags |
|---|---|---|---|---|
| AUTH-USR-001 | admin `POST /users {email,password,display_name,role_name:"viewer"}` | 201; new user in caller's tenant with viewer role; can log in | P0 | FUN |
| AUTH-USR-002 | `role_name` nonexistent | 400/404; no user created (atomic) | P1 | NEG |
| AUTH-USR-003 | `role_name` of other tenant's role | 404 (cannot bind foreign role) | P0 | SEC |
| AUTH-USR-004 | `role_name:"admin"` by admin who is not super-admin | allowed? document privilege escalation path (admin can create admins) | P2 | SEC |
| AUTH-USR-005 | create user violating tenant policy (T3 domain/length/classes) | 400 with specific error (`email domain not allowed`, `password too short`, `password requires …`) | P1 | FUN |
| AUTH-USR-006 | email already exists in another tenant | 409 (global unique `primary_email`) — document cross-tenant enumeration side-channel | P2 | SEC |
| AUTH-USR-007 | `GET /users` pagination params (`limit`, `offset`, `cursor`) if any; 10k users | bounded page size; no full-table response | P2 | STR |
| AUTH-USR-008 | `GET /users/{id}` non-UUID / nil UUID / deleted | 400/404 | P2 | NEG |
| AUTH-USR-009 | user responses | never include credential hash, MFA secret | P0 | SEC |
| AUTH-ROL-001 | `POST /roles {name:"editor",description}` | 201; unique per tenant | P1 | FUN |
| AUTH-ROL-002 | duplicate name same tenant | 409 `conflict` | P1 | NEG |
| AUTH-ROL-003 | same name different tenant | 201 (UNIQUE tenant_id,name) | P1 | FUN |
| AUTH-ROL-004 | name empty / 1 KB / unicode / `<script>` | 400 or stored+escaped | P2 | NEG |
| AUTH-ROL-005 | assign permission `{"permission":"users:read"}` | 200; users holding role get it on next token issuance (login/refresh); current access token unchanged until expiry (≤15 min) | P0 | CON |
| AUTH-ROL-006 | assign unknown permission `foo:bar` | 400/404 | P1 | NEG |
| AUTH-ROL-007 | assign same permission twice | idempotent | P2 | NEG |
| AUTH-ROL-008 | self-escalation: viewer obtains `roles:update` somehow? (no) ; admin assigns `tenant:update` to viewer role then viewer refreshes | viewer gains it only after refresh | P1 | SEC |
| AUTH-ROL-009 | permission revocation | **no revoke endpoint found** → document gap; revocation only via DB | P2 | FUN |
### 8.3 Tenant policy
| ID | Action | Expected | Pri | Tags |
|---|---|---|---|---|
| AUTH-POL-001 | GET default | `password_min_length=8`, require_* false, `allowed_email_domains=[]`, `require_mfa=false`, `max_active_sessions` default (record) | P1 | FUN |
| AUTH-POL-002 | PUT full valid body | 200; persisted in `tenant_policies`; audit with old/new | P1 | FUN |
| AUTH-POL-003 | `password_min_length` 0, -1, 7, 8, 128, 129, 10000 | lower bound ≥ 8 enforced? upper bound? record; never accept negative | P1 | BND |
| AUTH-POL-004 | `max_active_sessions` 0, -1, 1, 1000 | 0 = unlimited or invalid — document; negative → 400 | P1 | BND |
| AUTH-POL-005 | `allowed_email_domains` `["CORP.TEST"]` vs user `a@corp.test`; `["corp.test"]` vs `a@sub.corp.test`, `a@corp.test.evil.com`, `a@evilcorp.test` | exact (case-insensitive) domain match; suffix tricks rejected | P0 | SEC |
| AUTH-POL-006 | partial body (only `require_mfa`) | other fields unchanged (PATCH semantics) or reset to zero (PUT semantics) — **zero-reset of min_length to 0 would be a security bug**; verify | P0 | SEC |
| AUTH-POL-007 | wrong types (`"8"` string, `true` for int) | 400 | P2 | NEG |
| AUTH-POL-008 | policy change effect on existing passwords | not retroactive; next password set enforces | P2 | FUN |
| AUTH-POL-009 | `require_mfa` toggled on while users logged in | existing sessions continue; next login enforces | P1 | FUN |
| AUTH-POL-010 | concurrent PUTs | last-writer-wins whole-object; no torn mix of fields | P2 | RACE |

---------------------------------------------------------------------------------------------------
## 9. Internal services (identity-service :8081, mfa-service internal)
| ID | Action | Expected | Pri | Tags |
|---|---|---|---|---|
| AUTH-INT-001 | `POST :8081/internal/identities` valid | 201 identity | P1 | INT |
| AUTH-INT-002 | `GET /internal/identities/by-email?email=` exact/case/missing param | 200/404/400 | P1 | INT |
| AUTH-INT-003 | `GET/DELETE /internal/identities/{id}` | 200/204; delete cascades sessions/refresh tokens/factors? document | P1 | INT CON |
| AUTH-INT-004 | **Any internal route without credentials from outside the private network** | must be unreachable (network policy) — **no auth middleware in code [src]** → P0 deployment requirement; test from public interface | P0 | SEC |
| AUTH-INT-005 | `GET /internal/identities/by-email` enumerates users; `DELETE` deletes any user | confirms impact of 004; recommend mTLS/shared secret | P0 | SEC |
| AUTH-INT-006 | `POST /internal/mfa/factors/{id}/verify` directly | marks factor verified without code → MFA bypass if reachable | P0 | SEC |
| AUTH-INT-007 | `POST /internal/mfa/challenges/consume` twice | second fails (single-use) | P0 | FUN |
| AUTH-INT-008 | iam→identity contract: map identity 404→401 (login), 409→409 (register), 5xx/timeout(5 s)→503 | | P1 | INT |
| AUTH-INT-009 | iam→mfa contract under 5xx/timeout | MFA users **fail closed** (no tokens) | P0 | INT CHA |
| AUTH-INT-010 | malformed JSON from internal service (toxiproxy body corruption) | 5xx handled, no panic | P2 | CHA |

---------------------------------------------------------------------------------------------------
## 10. Security test catalogue (cross-cutting)
| ID | Test | Expected | Pri |
|---|---|---|---|
| AUTH-SEC-001 | SQL injection in every string input (email, names, role_name, permission, ids, query params) with payload set `' OR '1'='1`, `'; SELECT pg_sleep(5)--`, `\x00` | no behaviour change, no delay (pgx parameterised) | P0 |
| AUTH-SEC-002 | CORS: `Origin: https://evil.test` with credentials on `/refresh`, `/me` | no `Access-Control-Allow-Origin: https://evil.test` with `Allow-Credentials: true`; wildcard + credentials never | P0 |
| AUTH-SEC-003 | Cookie flags in production config | `Secure` must be true over HTTPS — currently hard-coded false **[src]** → P1 defect | P1 |
| AUTH-SEC-004 | Security headers on HTML pages (`web/login`, `web/admin`): CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options | present | P2 |
| AUTH-SEC-005 | Clickjacking on consent/authorize | framing denied | P2 |
| AUTH-SEC-006 | Log hygiene: grep all service logs after full suite for passwords, refresh tokens, access tokens, TOTP secrets, `mfa_token` | none | P0 |
| AUTH-SEC-007 | Error leakage: force 500s (DB down) | body `internal error` only; no stack/SQL | P1 |
| AUTH-SEC-008 | HTTP method confusion (`GET /login`, `PUT /register`, `TRACE`) | 405 | P3 |
| AUTH-SEC-009 | Request body size limit on all POST | > 1 MB → 413 quickly | P1 |
| AUTH-SEC-010 | Slowloris on :8080 (server read header timeout) | connections closed | P2 |
| AUTH-SEC-011 | Fuzz targets: password PHC parser (exists), JWT parser, PKCE verifier compare, redirect URI matcher, policy JSON, WebAuthn response parser | 1 h each, no crash | P1 |
| AUTH-SEC-012 | Constant-time compare: client_secret, PKCE, refresh token hash lookup | via code review + timing test | P2 |
| AUTH-SEC-013 | Key storage: `signing_keys` private material encrypted? (`platform/secrets`) | document | P1 |
| AUTH-SEC-014 | Audit completeness: every action in §4–§8 produces exactly one `audit_events` row with correct actor/tenant/ip | 100 % | P1 |
| AUTH-SEC-015 | Dependency scan `govulncheck ./...` | no reachable vulns | P1 |

---------------------------------------------------------------------------------------------------
## 11. Integration: Postgres / Redis / NATS / worker / key-rotator
| ID | Scenario | Expected | Pri |
|---|---|---|---|
| AUTH-INF-001 | `cmd/migrate` on empty DB; rerun | all 12 migrations applied once; rerun no-op; tables §1 exist | P0 |
| AUTH-INF-002 | migrate down/up (if supported) | reversible | P2 |
| AUTH-INF-003 | schema vs code: every repository query executes (run full functional suite with `log_min_error_statement=error`) | zero SQL errors in PG log | P1 |
| AUTH-INF-004 | Redis keys after login: namespace, TTL ≤ 5 min for session cache | `redis-cli --scan` shows TTL set (no immortal keys) | P1 |
| AUTH-INF-005 | NATS: subjects published per action (register, login, logout, role change, policy change) | exactly one message per action; payload schema stable (snapshot) | P1 |
| AUTH-INF-006 | worker consumes and acks; redelivery after worker crash is idempotent | no duplicate side effects | P1 |
| AUTH-INF-007 | DB commit vs publish ordering: kill iam between commit and publish (failpoint) | event eventually published (outbox) or documented loss | P1 |
| AUTH-INF-008 | key-rotator run twice concurrently | one active signing key; JWKS consistent | P1 |
| AUTH-INF-009 | key-rotator crash mid-rotation | system still signs & verifies | P1 |
| AUTH-INF-010 | pgx pool exhaustion (pool=small, 500 concurrent) | queued with timeout; 503 not hang | P1 |

---------------------------------------------------------------------------------------------------
## 12. End-to-end journeys
| ID | Journey (each step asserts as in referenced cases) | Pri |
|---|---|---|
| AUTH-E2E-001 | Register → login → /me → enroll TOTP → verify → logout → login (mfa_required) → /mfa/complete → refresh ×3 → logout → old RT/AT/session rejected (REF-006, SES-017 window) | P0 |
| AUTH-E2E-002 | Admin: create role `support` → assign `users:read` → create user with role → user logs in → GET /users 200 → POST /users 403 → admin assigns `users:create` → user refreshes → POST /users 201 | P0 |
| AUTH-E2E-003 | OAuth app: authorize+PKCE → token → userinfo → refresh → reuse old RT (family revoked) → re-authorize | P0 |
| AUTH-E2E-004 | Passkey: register passkey → logout → WebAuthn login → list credentials shows last_used_at | P1 |
| AUTH-E2E-005 | Policy hardening: set T3 policy → existing weak-password user can still log in → new user creation enforces → domain restriction enforced | P1 |
| AUTH-E2E-006 | Key rotation during live traffic (1k active sessions, k6 at 200 rps) → zero 401 spikes | P0 |
| AUTH-E2E-007 | Multi-tenant isolation journey: T1 & T2 admins perform full CRUD; cross-tenant attempts at every step fail | P0 |
| AUTH-E2E-008 | Web UI (`web/login`, `web/admin`) via Playwright mirroring 001/002 | P2 |

---------------------------------------------------------------------------------------------------
## 13. Non-functional
### 13.1 Concurrency / race (all P0/P1)
AUTH-RACE-001 50× same register (=REG-022) · 002 50× same refresh (=REF-009) · 003 50× same code exchange (=OA-029) · 004 50× same mfa_token complete (=MFA-014) · 005 login burst exceeding `max_active_sessions` (T3, 20 parallel logins) → active sessions ≤ 2 after settle · 006 role permission assign racing token refresh → token has either old or new perms, never partial · 007 policy PUT racing user creation → user validated against one consistent policy · 008 logout racing refresh → no surviving token family · 009 key-rotator racing login burst → all issued tokens verifiable · 010 `go test -race ./...` + race-built binaries under LOAD-005 → zero reports.
### 13.2 Consistency
AUTH-CON-001 multi-replica: token issued by replica A verifies on B/C immediately · 002 logout on A → X-Session-ID rejected on B within cache TTL (measure) · 003 after 10k random ops (register/login/refresh/logout/role change): every active session has a live refresh family; no refresh token without session; no user without identity · 004 audit row count == action count · 005 NATS event count == action count · 006 JWT roles/permissions == DB at issuance time.
### 13.3 Load (thresholds are initial targets; calibrate with `BENCHMARKS.md`)
| ID | Profile | Pass criteria |
|---|---|---|
| AUTH-LOAD-001 | Login 50→500 rps ramp 10 min (argon2id cost dominates) | p99 < 500 ms; errors < 0.1 %; CPU saturation point recorded |
| AUTH-LOAD-002 | `/me` Bearer 3k rps | p99 < 30 ms (pure JWT verify) |
| AUTH-LOAD-003 | `/me` X-Session-ID 3k rps (cache hit path) | p99 < 30 ms; Redis/PG QPS observed |
| AUTH-LOAD-004 | Refresh 500 rps unique tokens | p99 < 150 ms |
| AUTH-LOAD-005 | Mixed 60 % /me, 20 % refresh, 15 % login, 5 % register, 30 min | stable latency; no error drift |
| AUTH-LOAD-006 | OAuth code flow 100 rps | p99 < 800 ms |
| AUTH-LOAD-007 | JWKS/discovery 5k rps | p99 < 20 ms |
### 13.4 Stress / spike / soak / scalability
AUTH-STR-001 ramp login until errors > 5 % → record knee; degrade with 503/timeout not crash; recover < 60 s · 002 PG pool exhaustion · 003 Redis maxclients · 004 1 M identities / 10 M refresh_tokens → login & refresh p99 regression < 20 %, `EXPLAIN` shows index on `token_hash`, `primary_email` · 005 1 MB passwords flood (100 rps) → service stays responsive (input cap) · AUTH-SPK-001 0→2000 rps in 1 s ×3 (`test/spike`) · AUTH-SOAK-001 24 h @ 30 % (`test/soak`) → RSS, goroutines, FDs, PG conns, Redis keys, `sessions`/`refresh_tokens` table size bounded by cleanup · AUTH-SCAL-001 iam replicas 1→2→4 → throughput ≥ 1.8×/3.4× · 002 mfa/identity replicas scale independently.
### 13.5 Chaos / resilience
| ID | Fault (inject during AUTH-LOAD-005) | Expected |
|---|---|---|
| AUTH-CHA-001 | Redis killed | session-header path fails closed (401/503), Bearer path continues; login 503 or degrades to DB; recover automatically |
| AUTH-CHA-002 | Redis FLUSHALL | session cache rebuilds from DB; revoked sessions stay revoked |
| AUTH-CHA-003 | Postgres killed 60 s | 503 fast; no partial writes; pools reconnect without restart |
| AUTH-CHA-004 | Postgres `docker pause` 30 s | requests time out (≤ server timeout); goroutines return to baseline |
| AUTH-CHA-005 | NATS down | auth path unaffected; events delivered after recovery (or loss documented) |
| AUTH-CHA-006 | identity-service down / +5 s latency / 50 % 500 | login/register 503 within ~5 s; no thread pile-up |
| AUTH-CHA-007 | mfa-service down | non-MFA logins OK; MFA users fail closed (no tokens) |
| AUTH-CHA-008 | SIGTERM iam under load | graceful drain; ≤ in-flight errors |
| AUTH-CHA-009 | SIGKILL iam during refresh | client retry yields exactly one valid family |
| AUTH-CHA-010 | toxiproxy 200 ms latency + 5 % loss iam↔PG | bounded tail; no data corruption |
| AUTH-CHA-011 | Clock skew ±5 min on one replica | tokens from skewed replica rejected/accepted per leeway; TOTP window behaviour documented |
| AUTH-CHA-012 | PG disk full | writes fail cleanly; reads/token verify OK |
| AUTH-CHA-013 | worker crash mid-message | redelivery idempotent |
| AUTH-CHA-014 | key-rotator killed between insert-new and retire-old | signing works; JWKS valid |
### 13.6 Durability
AUTH-DUR-001 `kill -9` PG right after 2xx register → row present after restart · 002 backup/restore → all refresh tokens, signing keys, factors valid; JWKS unchanged · 003 Redis restart (no persistence) → only cache lost · 004 migrations on populated DB (copy of prod-like data) succeed · 005 signing keys survive restart of all stateless services (never regenerated silently → would invalidate all tokens).

---------------------------------------------------------------------------------------------------
## 14. Invariant audit (run after every suite; SQL in 03-TEST-SCRIPTS `consistency_check.sh`)
I1 no identity duplicates by lower(primary_email) · I2 each refresh family has ≤1 active token · I3 no active session for deleted identity / revoked family · I4 no `users` row whose tenant ≠ role's tenant (via user_roles) · I5 no `role_permissions` linking a role to another tenant's permission · I6 all `credentials.secret` are argon2id PHC · I7 audit_events per action · I8 auth codes past `expires_at` cannot be redeemed and are purged · I9 every JWKS kid has a `signing_keys` row and vice-versa for active keys.

## 15. Regression pack & traceability
Regression pack = all `[REG]` + all P0 cases + existing `test/integration/*`, `test/security`, `test/smoke/smoke.sh`, unit tests. Snapshot artefacts: discovery JSON, JWKS shape, error string list (§1), LoginOutput field set, metric names, migration checksums, NATS payload schemas.
| Requirement area | Cases |
|---|---|
| Credential security | REG-002/003/016/018, LGN-005/006/014, SEC-006 |
| Token lifecycle | LGN-001/002, REF-*, OUT-*, SES-009…017, JWKS-* |
| MFA | MFA-*, WA-*, LGN-010/011, INT-006/009 |
| OAuth/OIDC | OIDC-*, OA-* |
| Authorization & tenancy | RBAC-*, USR-*, ROL-*, POL-*, SES-018, OA-026 |
| Availability | CHA-*, STR-*, SOAK-* |

## 16. Known gaps to report as findings (from source reading)
1. No brute-force protection / lockout / rate limit on `/login`, `/mfa/complete`, `/oauth/token` (P1). 2. Internal routes on identity/mfa services unauthenticated (P0 if reachable). 3. Refresh cookie `Secure=false` hard-coded (P1). 4. Client IP from `X-Forwarded-For` trusted unconditionally (P2). 5. Bearer JWT not checked against session revocation → up to 15 min post-logout validity (P2, accepted risk?). 6. Metric label falls back to raw path on unmatched routes (P2). 7. federation/pam/risk/provisioning/serviceaccount are empty packages — no tests possible; don't advertise related grants (P3).

## 17. Entry / exit criteria & defect severity
Entry: E-INT healthy, DS-1 seeded, migrations clean. Exit: 100 % P0 pass; ≥ 95 % P1 pass with no open P1 security defect; invariants §14 clean after full run; race detector clean; LOAD-005 within SLO; soak leak-free. Severity: S1 auth bypass/cross-tenant/data loss; S2 functional break of a primary flow; S3 secondary flow/edge; S4 cosmetic.
