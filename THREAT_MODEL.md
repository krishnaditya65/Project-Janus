# Project Janus — Threat Model

A STRIDE-style threat analysis covering every attack class that's been demonstrated against modern auth servers. Each threat follows the same template:

> **Threat** — what the attacker is trying to do
> **Attacker model** — who they are, what they start with, what they can intercept
> **Attack surface** — where they touch our system
> **Concrete attack steps** — what they actually try
> **Today's mitigation** — code that defeats or weakens the attack (with file paths)
> **Residual risk** — what the mitigation doesn't cover
> **Detection** — how we'd notice the attack happened
> **Roadmap closure** — which planned version addresses the residual risk

If a threat has no "Roadmap closure," it means we believe the residual risk is acceptable. If a threat shows a "Residual risk" we'd be uncomfortable shipping to a regulated customer, it's flagged ⚠.

---

## Table of contents

1. Credential stuffing
2. Online password brute force
3. Offline password brute force (DB leak)
4. Account enumeration
5. Session fixation
6. Session hijacking (token theft)
7. XSS-mediated token exfiltration
8. CSRF
9. Refresh-token replay
10. Access-token replay after revocation
11. Signing-key compromise
12. JWT algorithm-confusion / `alg=none`
13. PKCE downgrade
14. Authorization-code reuse / leak
15. OAuth redirect-URI hijack
16. Open redirect via `state` / `redirect_uri`
17. Tenant escape (cross-tenant data access)
18. Privilege escalation within a tenant
19. MFA bypass (TOTP reuse, factor enumeration)
20. SQL injection
21. Header injection / response splitting
22. Timing oracles (account enumeration, secret comparison)
23. SSRF via federation IdP URLs (future v0.12.0)
24. Rate-limit / DoS
25. Audit log tampering
26. Supply-chain compromise
27. Replay of WebAuthn assertions (cloned authenticator)
28. Tenant-scoped policy bypass

---

## Out-of-scope (assumed safe / inherited from platform)

- **TLS / network MITM** — assume HTTPS with a trusted CA between client and our load balancer. We do not pin certs in the server.
- **Operating system compromise** — root on the host is game over by definition.
- **Postgres direct connection from attacker** — assume DB is on a private network and creds are managed externally.
- **Physical access to the server** — out of scope.
- **Client-side malware on the user's device** — out of scope.

If any of these assumptions is wrong for a deployment, additional controls are needed and are not covered here.

---

## 1. Credential stuffing

**Threat** — Use a large list of `(email, password)` pairs leaked from another site to log in to ours.

**Attacker model** — Has tens of millions of plaintext passwords (haveibeenpwned-scale list). No prior access to our system. Distributes across thousands of IPs to evade naive throttling.

**Attack surface** — `POST /login`, `POST /oauth/token` (refresh_token grant — but they need our refresh token, which they don't have).

**Concrete attack steps**
1. Acquire `breachdb.txt` with `email:password` pairs.
2. Make 1000s of `/login` requests, one per pair, rotating source IPs (botnet, residential proxies, Tor).

**Today's mitigation**
- Argon2id verify is **~95 ms/login** (`internal/shared/password/password.go`) — pricey enough to slow naive attackers and force them to invest CPU.
- That's it. **No rate limit, no account lockout, no IP throttle today.** Documented in `test/security/security_test.go:TestSec_BruteForce_NotRateLimited` (the test passes by *demonstrating the gap*, then logs a TODO).

**Residual risk** — ⚠ **High.** A distributed attacker can stuff against us at full server capacity (~20 logins/sec/node). At ~95 ms per attempt × N nodes, a few hours can confirm matches against a 100k-email list.

**Detection** — Prometheus `auth_http_requests_total{route="/login",status="401"}` rate spike would flag it. We don't alert on this today.

**Roadmap closure** — **v0.10.0 — Security Hardening Phase 1** is dedicated to this. Plan:
- **Per-IP token-bucket** (Redis-backed sliding window): 30 req/min/IP on `/login`, `/refresh`, `/oauth/token`, `/mfa/complete`, `/register`. Returns 429 + `Retry-After`.
- **Per-account counter** (DB-backed): 5 failed logins / 15 min → lock for 15 min. `423 Locked` response + email-unlock-link (when notification component lands).
- **Distributed-stuffing detection**: count of distinct successful-IPs per account per hour — if > 5, mark identity for step-up MFA on next login.

---

## 2. Online password brute force

**Threat** — Try millions of passwords against a single known account.

**Attacker model** — Knows a target email (LinkedIn, leaked email list); guessing one account.

**Attack surface** — `POST /login` for that account.

**Concrete attack steps** — Same as credential stuffing but with the email pinned.

**Today's mitigation** — Argon2id (95 ms/attempt). At our throughput ceiling (20 logins/sec from one node, or ~1.7 million/day from one node), a 12-character random password would still take centuries. An 8-character lowercase-only password (the kind users actually pick) would fall in days.

**Residual risk** — ⚠ Without lockout, weak passwords are guessable. Default tenant `password_min_length=8` (per `internal/tenant/domain/policy.go`) means we admit weak passwords.

**Detection** — Same as #1.

**Roadmap closure** — Same as #1. **Account lockout in v0.10.0** removes the practical attack window.

---

## 3. Offline password brute force (DB leak)

**Threat** — Attacker steals the `credentials` table dump (DBA error, backup leak, SQLi against a sister app) and brute-forces hashes offline.

**Attacker model** — Has the entire DB. No network access required.

**Attack surface** — `credentials.password_hash` column.

**Today's mitigation**
- **Argon2id** with m=64MB, t=3, p=2 (`internal/shared/password/password.go`). One GPU-hour cracks a few hundred thousand weak passwords; strong (≥12 char random) passwords stay intractable.
- **Per-user random salt** (16 bytes from `crypto/rand`) — defeats rainbow tables, forces per-user work.
- **No password peppering** (no application-wide secret added to the hash). Means a DB leak alone is enough — attacker doesn't need to also steal app secrets.

**Residual risk** — ⚠ **Medium-High.** Argon2's memory cost makes GPU farms slow, but a determined attacker with $10k of cloud compute can run sustained Argon2 cracking against weak passwords. Compounded by our 8-char default minimum.

**Detection** — DB-leak detection is out of scope for this server. Compromise indicator: customer hears their passwords appear on a breach site.

**Roadmap closure**
- **v0.10.0**: Stronger default password policy (`password_min_length=12`, `password_require_digit=true` etc. as the default).
- **v0.15.0**: Password peppering via an application secret OR envelope encryption of the `credentials.password_hash` column with a KMS key. The latter is the bigger win — even a full DB dump becomes unusable without the KMS key.

---

## 4. Account enumeration

**Threat** — Determine whether a given email is registered, separate from logging in.

**Attacker model** — Wants to build a target list for credential stuffing (#1) or social engineering.

**Attack surface** — Any endpoint that responds differently for "user exists" vs "user does not exist." Specifically: `/register`, `/login`, `/auth/forgot-password` (future).

**Concrete attack steps**
1. `POST /login` with target email and a fake password. If response is 401 fast (< 5 ms), email doesn't exist; if 401 slow (~ 95 ms after Argon2), it does.
2. `POST /register` with the email — 409 means exists.

**Today's mitigation**
- `POST /register` returns **409** with `"email already registered"` for duplicates — **leaks existence**. Trade-off: required UX (users need to know they have an account).
- `POST /login` — ⚠ **leaks via timing**. Documented in `test/security/security_test.go:TestSec_Timing_LoginConstantTime`: real user wrong password = 95 ms, fake user any password = 1.5 ms. Ratio of 62× is a clean timing oracle.

**Residual risk** — ⚠ **Confirmed gap.** Anyone with a network connection can enumerate our user base via timing.

**Detection** — Hard. A patient attacker spreads requests over hours.

**Roadmap closure** — **v0.10.0 constant-time login**: when `GetByEmail` returns "not found," still run `argon2.Verify(input.Password, dummyHash)` against a server-startup dummy hash. Total time becomes constant. After this lands, the existing timing test flips its assertion to "ratio in [0.5, 2.0]."

---

## 5. Session fixation

**Threat** — Attacker fixes a session ID, lures victim into authenticating with it, then uses the same ID to act as the victim.

**Attacker model** — Web attacker; can serve victim a crafted link with a known session ID, or set a cookie via a sibling-subdomain XSS.

**Attack surface** — Any code path that accepts a client-supplied session identifier and elevates it on login.

**Today's mitigation**
- **We never accept a client-supplied session ID at login.** Login always generates a fresh session UUID (`id.New()` in `internal/auth/app/login.go`).
- The session ID is created server-side, returned in the response body. There's no API to "log in as session X."
- The refresh cookie is `SameSite=Strict` so a fixed cookie planted via cross-site request gets stripped.

**Residual risk** — Low. The only fixation vector would be the (legacy) `X-Session-ID` header — but that header is only honored *after* login created the session, so an attacker can't pre-create a session and have us bless it.

**Detection** — None needed; mitigation is structural.

**Roadmap closure** — None required. (Long term: drop `X-Session-ID` entirely once SDKs migrate to JWT.)

---

## 6. Session hijacking (token theft over the wire)

**Threat** — Attacker steals an access token / refresh token by sniffing or reading client storage, then uses it.

**Attacker model** — Network attacker (with broken TLS, or able to read client storage via XSS — covered separately in #7).

**Attack surface** — All tokens we issue.

**Today's mitigation**
- **TLS** is assumed at the load balancer (out of scope assumption; if not present, ALL bets are off).
- **Refresh token in `HttpOnly`, `Secure`, `SameSite=Strict` cookie** — not readable from JavaScript, not sent on cross-origin requests, not sent over HTTP in prod. (`internal/auth/transport/http/response.go:setRefreshCookie`).
- **Access token short-lived** (15 minutes) — bounds the damage window.
- **No token binding to client TLS or DPoP today.** A stolen access token works for whoever holds it.

**Residual risk** — Within 15 minutes of theft, the access token is usable from any IP. Refresh token (if also stolen) lasts 7 days but the rotation tripwire catches it (see #9).

**Detection** — Auth-event audit captures the IP of every login + refresh. A future v0.14.0 risk scorer would flag "same session, two distant IPs in N minutes" as an anomaly.

**Roadmap closure**
- **v0.14.0** adaptive: anomaly detection on IP/device/geo per session.
- **v0.15.0** DPoP: binds access token to a client-held private key. A stolen token without the private key is useless.

---

## 7. XSS-mediated token exfiltration

**Threat** — XSS in a relying-party app reads tokens from `localStorage` / `sessionStorage` / cookies.

**Attacker model** — Web attacker who finds an XSS in the RP.

**Attack surface** — Wherever the client stores tokens.

**Today's mitigation** (server-side; client is responsible for their own storage)
- **Refresh token cookie is `HttpOnly`** — `document.cookie` cannot read it. XSS cannot exfiltrate the refresh.
- **Access token returned in JSON body** — recommended to store in JS memory only, not in `localStorage`. We document this (`DESIGN.md` §4) but cannot enforce it.
- **No script-readable session cookie.** The only session cookie we set is the refresh, which is `HttpOnly`.

**Residual risk** — If the RP stores the access token in `localStorage`, an XSS reads it for 15 minutes. We cannot prevent client misuse, only narrow the blast radius.

**Detection** — None at our layer.

**Roadmap closure**
- **v0.15.0** DPoP: even if the access token is exfiltrated, it's useless without the private key (which a malicious script also can't reach if stored in IndexedDB via `crypto.subtle.exportKey: false`).

---

## 8. CSRF

**Threat** — Victim is logged in. Attacker site issues cross-origin request to our server using the victim's cookie, e.g. `<img src="https://janus/refresh">`.

**Attacker model** — Web attacker, victim has an active session with us.

**Attack surface** — Any endpoint that the browser will auto-include cookies on. For us, that's `/refresh` (the only cookie we set).

**Today's mitigation**
- **`SameSite=Strict` on the refresh cookie** (`internal/auth/transport/http/response.go`) — browser refuses to send the cookie on cross-site requests. This is the modern CSRF defense and is sufficient for our cookie surface.
- **Bearer JWT path is immune to CSRF by design** — browsers don't auto-send `Authorization` headers on cross-origin requests.
- **No JSON-only check** (we accept `application/x-www-form-urlencoded` on `/oauth/token`). For that endpoint, the OAuth client_secret + PKCE verifier serve as anti-CSRF.

**Residual risk** — Browsers without `SameSite` support (deeply unmaintained ones). Modern Chrome/Firefox/Safari are safe.

**Detection** — None needed.

**Roadmap closure** — None required.

---

## 9. Refresh-token replay

**Threat** — Attacker steals a refresh token. Either uses it before the legit user does, or uses it after the legit user already refreshed (replay).

**Attacker model** — Has the refresh token (#7 or #6 vector).

**Attack surface** — `POST /refresh`.

**Today's mitigation**
- **Rotation on every refresh** (`internal/auth/app/refresh.go`): the old session is `Revoke`d the moment a refresh succeeds. If the attacker uses an already-rotated token, the lookup finds a session with `RevokedAt != nil` and returns 401.
- **Single-use refresh tokens**: only one refresh per session. Concurrent legitimate refreshes from the same client (e.g. double-clicked button) — one wins, one fails.
- **SHA-256 hashed at rest** (`internal/shared/token/token.go:Hash`) — a DB-read attacker doesn't get raw tokens.
- **Principal cache invalidated on revoke** (`internal/auth/middleware/principal_cache.go:Delete` called from `RefreshUseCase`) — the old session is also kicked out of the cache.
- **Tripwire on race**: if attacker uses token first, legit user's next refresh fails (their token is now revoked). This is the standard OAuth 2.0 refresh-rotation pattern that gives "session compromise detected" signals.

**Residual risk** — We **don't yet act** on the tripwire. The legit user's failed refresh just looks like a normal expired-session. We should detect the race and revoke the whole token family.

**Detection** — Today, the legit user gets a 401 and re-logins. They lose visibility into what happened. In v0.11.0 (audit query API) we'll be able to retroactively spot the pattern.

**Roadmap closure**
- **v0.10.0 (Security Phase 1)**: implement the tripwire. When a refresh fails because the session is already revoked AND the `parent_session_id` chain shows recent activity, revoke the whole family and notify the user.
- **v0.11.0**: audit query API lets ops investigate.

---

## 10. Access-token replay after revocation

**Threat** — Admin revokes a session (logout, role change), but the user's already-issued access token works until it expires (≤ 15 min).

**Attacker model** — Insider gone bad; admin tries to immediately revoke their session.

**Attack surface** — Every authenticated endpoint accepting a Bearer JWT.

**Today's mitigation**
- **15-minute access token TTL** is the bound on damage.
- **Principal cache invalidated on logout** (`internal/auth/app/logout.go` calls `PrincipalInvalidator.Delete`). This kills the session-id auth path immediately but **does not** affect Bearer JWT.
- **No JWT introspection** — we don't check a denylist on every JWT verify.

**Residual risk** — ⚠ **By design.** A revoked admin can take destructive action for up to 15 minutes after revocation.

**Detection** — Audit log shows actions taken after the revoke event. Forensic only.

**Roadmap closure**
- **v0.15.0** Token introspection (RFC 7662) for high-stakes endpoints: optional `POST /oauth/introspect` lookup forces a DB check that respects revocations.
- Alternative: shorten access-token TTL to 5 min for sensitive tenants (per-tenant policy, easy add).

---

## 11. Signing-key compromise

**Threat** — Attacker steals an active JWT private signing key (DB read, RAM scrape, malicious operator). Can mint arbitrary JWTs.

**Attacker model** — Has read access to `signing_keys.private_key` or to process memory.

**Attack surface** — Anyone who can decode our private key forges valid Bearer tokens for any tenant/user/permission.

**Today's mitigation**
- Private key stored in DB as plain PEM (`signing_keys.private_key TEXT`). ⚠ **Plaintext at rest in the DB.** No envelope encryption today.
- Key rotation infrastructure (`cmd/key-rotator`): can be invoked to mint a new key and mark the old one rotated. JWKS keeps the old key for 7 days for in-flight token verification.
- **Algorithm allowlist** (`jwt.WithValidMethods`) prevents `alg=none` / RS-as-HS attacks.

**Residual risk** — ⚠ **High.** A DB read gives the keys.

**Detection** — No tamper detection on the `signing_keys` table today.

**Roadmap closure**
- **v0.10.0**: automate `cmd/key-rotator` so old keys age out on a 90-day cycle even without incident.
- **v0.15.0**: encrypt `signing_keys.private_key` with a KMS-held DEK (envelope encryption). DB compromise no longer = key compromise.
- **v0.15.0**: emergency rotation procedure documented + tested (delete the key row → JWKS removes it → all access tokens minted with it become 401 on next request).

---

## 12. JWT algorithm-confusion / `alg=none`

**Threat** — Attacker submits a JWT with `alg=none` (no signature) or with the algorithm switched (e.g. RS256 token re-signed as HS256 using the public key as the HMAC secret).

**Attacker model** — Anyone with network access.

**Attack surface** — Every endpoint that accepts a Bearer JWT.

**Today's mitigation**
- **Strict algorithm allowlist**: `jwt.WithValidMethods([]string{"ES256", "RS256"})` passed to `Verify` (`internal/token/app/jwt_service.go`). Tokens with any other `alg` are rejected before any signature check happens. `alg=none` cannot match.
- **Key resolution by `kid` only** — we don't infer key from `alg`. Even if the attacker forces an `alg` we accept, the key lookup happens by `kid` and the verifier checks the algorithm matches the key's type.
- **Fuzzed**: `FuzzJWT_RejectsAlgNone` permanently asserts this can never regress.
- **Security tested**: `TestSec_JWT_AlgNoneRejected` confirms HTTP-level rejection.

**Residual risk** — None practical.

**Detection** — `auth_http_requests_total{route="/me",status="401"}` spike. The fuzz test would catch any code regression.

**Roadmap closure** — None required.

---

## 13. PKCE downgrade

**Threat** — Attacker forces the OAuth flow to use the `plain` PKCE method, then intercepts the code on the way to the redirect URI; since `plain` reveals the verifier, attacker can exchange the code.

**Attacker model** — Network attacker between user and our authorize endpoint, OR malicious app sharing the same redirect URI scheme as the legitimate client.

**Attack surface** — `GET /oauth/authorize`.

**Today's mitigation**
- **`S256` is the only accepted method** (`internal/oauth/app/authorize.go`: explicit rejection of any other `code_challenge_method`).
- **Missing `code_challenge` is rejected** (returns `error=invalid_request` in the redirect).
- **Security tested**: `TestSec_PKCE_PlainMethodRejected`.
- **Fuzzed**: `FuzzVerifyPKCE` asserts the PKCE verifier function never returns true for a non-matching pair.

**Residual risk** — None for the downgrade attack.

**Detection** — Logged as 4xx by request logger.

**Roadmap closure** — None.

---

## 14. Authorization-code reuse / leak

**Threat** — Attacker intercepts a code (referrer leak, browser-history leak, malicious extension) and exchanges it before the legitimate client does.

**Attacker model** — Has read access to the code somehow (rare; most leaks happen via redirect-URI hijack — see #15).

**Attack surface** — `POST /oauth/token` with `grant_type=authorization_code`.

**Today's mitigation**
- **Codes are single-use** via Redis `GETDEL` (`internal/oauth/infra/redis/code_store.go:Consume`). Atomic; first exchange wins, second returns `invalid_grant`.
- **10-minute TTL** on every code.
- **PKCE binds the code to the client's verifier**: even if the attacker intercepts the code, they don't have the `code_verifier` (it never leaves the client until the token exchange). Without it the exchange fails.
- **`redirect_uri` checked at exchange** — must match what was used at `/authorize`.
- **Tenant ownership check** — the client_id used at exchange must belong to the same tenant whose principal authorized.
- **Integration tested**: `TestOAuth_CodeReuseRejected`, `TestOAuth_PKCEWrongVerifierRejected`.

**Residual risk** — Negligible. PKCE is the workhorse.

**Detection** — `auth_http_requests_total{route="/oauth/token",status="400"}` spike.

**Roadmap closure** — None.

---

## 15. OAuth redirect-URI hijack

**Threat** — Register a malicious client whose redirect URI matches a prefix or wildcard, so codes get sent there.

**Attacker model** — Has the ability to register OAuth clients (currently admin-only; will become self-serve in v0.12.0).

**Attack surface** — `oauth_clients.redirect_uris`.

**Today's mitigation**
- **Exact-match comparison** in `internal/oauth/domain/client.go:HasRedirectURI`. No wildcards, no prefixes, no substring matching.
- **JSONB array of literal URIs** in the schema.
- RFC 6749 §10.6 compliance.

**Residual risk** — A misconfigured admin who registers `http://localhost/*` as a literal won't get wildcard matching, but a typo where they put a developer's URL into a prod client is real. Not a mitigation a server can offer; needs admin review.

**Detection** — Audit log of client registration (future v0.11.0).

**Roadmap closure**
- **v0.12.0**: when self-serve client registration ships, require `https://` for redirect URIs in non-localhost mode and add a manual-review queue for new third-party clients.

---

## 16. Open redirect via `state` / `redirect_uri`

**Threat** — Attacker uses our `/oauth/authorize` as a phishing redirector to a malicious site.

**Attacker model** — Attacker controls a URL that looks like ours, tricks user into clicking it; we redirect to attacker's site.

**Attack surface** — `GET /oauth/authorize`.

**Today's mitigation**
- The redirect URI is **always validated against the registered client** before any redirect happens (`internal/oauth/app/authorize.go`).
- Error responses (`invalid_request`, etc.) only redirect to URIs that ARE registered — we don't echo user-supplied URLs into the response.

**Residual risk** — None.

**Detection** — None needed.

**Roadmap closure** — None.

---

## 17. Tenant escape (cross-tenant data access)

**Threat** — A user in tenant A reads/writes data in tenant B.

**Attacker model** — Legitimate user of tenant A.

**Attack surface** — Every endpoint that reads or writes per-tenant data.

**Today's mitigation**
- **Application-level tenant scoping**: every repo method takes `tenantID` and filters in SQL. Examples:
  - `userRepo.GetByID(ctx, tenantID, userID)` — won't return a user from another tenant.
  - `roleRepo.GetByTenantAndName(ctx, tenantID, name)` — same.
- **Principal-derived tenant**: `tenantID` always comes from `p.TenantID` (the authenticated principal), never from a URL parameter or header. A user cannot ask for "give me user X from tenant Y."
- **OAuth client → tenant binding**: at `/oauth/authorize` we check `client.TenantID == principal.TenantID` (`internal/oauth/app/authorize.go`). Cross-tenant code exchange is impossible.
- **Tenant policies** are tenant-scoped automatically.
- **Sessions** carry `TenantID`; revoke + cache check both honor it.
- **No Postgres RLS** as a second layer. ⚠

**Residual risk** — ⚠ A single bug in a single repo method that forgets the `WHERE tenant_id = $1` clause silently leaks across tenants. We have no defense-in-depth — the application is the only line.

**Detection** — None. A leak would surface only via customer complaint.

**Roadmap closure**
- **v0.15.0 (Security Review Pass)**: implement Postgres Row-Level Security as a backstop. Every connection sets `SET app.current_tenant = '<uuid>'`; every table has a policy `USING (tenant_id = current_setting('app.current_tenant')::uuid)`. App-level bugs become silent no-ops instead of cross-tenant leaks.

---

## 18. Privilege escalation within a tenant

**Threat** — Authenticated user with role X performs action requiring role Y.

**Attacker model** — Logged-in user in our tenant; tries to access an endpoint above their permission.

**Attack surface** — Every authenticated endpoint with a permission requirement.

**Today's mitigation**
- **`RequirePermission(p string)` middleware** (`internal/authorization/middleware/authorization.go`) returns 403 if the principal's permission set doesn't include `p`.
- **Permissions are loaded at auth time** (JWT claims OR cached principal); the middleware checks list membership.
- **Permissions are not mutable client-side**: JWT claims are signed and verified; the cached Principal is server-only.
- **Test coverage**: `TestSec_*` and `TestUnauthorizedAccess` confirm 401/403 paths.

**Residual risk**
- A handler not wrapped with `withPerm(...)` accepts any authenticated user. We have no compiler check enforcing this. **A new route added without `withPerm` is a privilege escalation by omission.**
- Stale cache (5 min) means a revoked permission still works for up to 5 min via session-id path. Mitigated for the JWT path by access token expiry (15 min worst case).

**Detection** — Audit log records actor + endpoint; post-hoc only.

**Roadmap closure**
- **v0.15.0**: introduce a route-registration helper that *requires* a permission argument; routes without one go on an explicit "public" list. Compile-time enforcement of the policy.

---

## 19. MFA bypass (TOTP code reuse, factor enumeration)

**Threat** — Replay a valid TOTP code; enumerate which users have MFA; bypass MFA via challenge replay.

**Attacker model** — Has captured a single valid TOTP code (over the shoulder, malware screen capture).

**Attack surface** — `POST /mfa/complete`, `POST /mfa/enroll/verify`.

**Today's mitigation**
- **TOTP codes change every 30s** — replay window is at most one step (±1 step tolerance = 90s window). Beyond that the code is invalid.
- **No TOTP code denylist** — we don't track which codes have been used. A code used once in the 30s window CAN be replayed within the same 30s window. This is a known TOTP gap; the standard mitigation is to track the last-used timestep per factor.
- **MFA challenge tokens are single-use** via Redis `GETDEL` (`internal/mfa/app/challenge_store.go`). An attacker can't replay a `mfa_token`.
- **Challenge token expires in 5 minutes**.
- **Factor enumeration**: `POST /login` returns the same shape (`{mfa_required: true, mfa_token}`) regardless of which factor type is enrolled. We don't reveal "user has TOTP" vs "user has WebAuthn" until they ask for the specific factor flow. (Future improvement: a factor-type field in the challenge response will leak this; trade for UX.)
- **Tested**: `TestMFA_FullFlow`, `TestMFA_WrongCodeRejected`.

**Residual risk** — Within a single 30s timestep, a captured code IS replayable.

**Detection** — None for in-window replay; it looks like a successful login.

**Roadmap closure**
- **v0.10.0 (MFA hardening alongside recovery codes)**: add `mfa_factors.last_used_step BIGINT` column; reject codes for timesteps ≤ last used. Standard mitigation; ~20 LoC.

---

## 20. SQL injection

**Threat** — User-supplied input injected into an SQL query.

**Attacker model** — Anyone with API access.

**Attack surface** — Every endpoint that takes input.

**Today's mitigation**
- **`pgx` parameterized queries everywhere** — we use `$1`, `$2`, etc., never string concatenation. The driver binds parameters separately from the SQL text.
- **No `fmt.Sprintf` SQL building anywhere** in the repos. Confirmed via grep.
- **Security tested** with 6 classic payloads in `TestSec_SQLi_LoginEmail` and `TestSec_SQLi_RegisterTenantName`. All payloads either 401 (invalid credentials) or 201 (stored literally) — no 500s, no successful injections.

**Residual risk** — Negligible. The only SQLi vector would be a future `fmt.Sprintf`'d query; CI doesn't enforce this.

**Detection** — A 500 on a "weird" input would surface in metrics + logs.

**Roadmap closure** — Optional `gosec` lint in CI to catch future `fmt.Sprintf`-built queries.

---

## 21. Header injection / response splitting

**Threat** — Inject `\r\n` into a user-controlled field that gets echoed into a response header, smuggling another header (e.g., `Set-Cookie:`).

**Attacker model** — Anyone with API access.

**Attack surface** — Anywhere a request field reaches `w.Header().Set()`.

**Today's mitigation**
- **We don't echo user input into headers** today. The only `Set-Cookie` we write is `refresh_token` whose value is `crypto/rand` bytes.
- **Go's `net/http`** sanitizes header values written via `Set()` — `\r\n` is stripped by the standard library.
- **Security tested**: `TestSec_HeaderInjection_EmailField` confirms a `\r\nX-Injected: yes` payload doesn't appear as a separate header.

**Residual risk** — None.

**Detection** — None needed.

**Roadmap closure** — None.

---

## 22. Timing oracles

**Threat** — Measure response time to learn information (account existence, secret comparison, etc.).

**Attacker model** — Network attacker with enough samples to do statistical analysis.

**Attack surface** — Every comparison of a secret OR conditional that depends on a secret.

**Today's mitigation**
- **`subtle.ConstantTimeCompare`** for:
  - Password hash compare (`internal/shared/password/password.go`)
  - PKCE challenge compare (`internal/oauth/app/token.go:verifyPKCE`)
  - OAuth client_secret compare (`internal/oauth/app/token.go`)
- **MFA TOTP code compare** uses `pquerna/otp.Validate` which is constant-time internally.

**Residual risk** — ⚠ **Confirmed**: account-enumeration timing on `/login` (see #4). Fix is in v0.10.0.

**Detection** — None.

**Roadmap closure** — v0.10.0 constant-time login.

---

## 23. SSRF via federation IdP URLs (future v0.12.0)

**Threat** — Federation flow takes an upstream IdP URL (e.g., authorization endpoint). An attacker who can configure a federation provider could point it at `http://169.254.169.254/` (AWS metadata) and read responses through our error messages.

**Attacker model** — Tenant admin with `tenant:update` permission, OR a misconfigured self-serve registration if v0.12.0 ships that path.

**Attack surface** — Future federation provider config fields.

**Today's mitigation** — N/A (not built yet).

**Residual risk** — Not present today; will be when v0.12.0 lands.

**Roadmap closure** — **v0.12.0 acceptance criteria**: federation provider config must reject any URL whose host resolves to a private/loopback/link-local IP. Validate at config time AND at request time (DNS-rebinding defense). This goes on the v0.12.0 plan as a non-negotiable.

---

## 24. Rate-limit / DoS

**Threat** — Attacker floods cheap endpoints (e.g., `/me`, `/health`) to exhaust capacity.

**Attacker model** — Anyone with network access.

**Attack surface** — All endpoints.

**Today's mitigation**
- **CPU-bound endpoints (login)** self-limit via Argon2 (~95 ms each = 20 req/s/node ceiling).
- **JWT verify** sustains ~10k req/s/node (see BENCHMARKS.md §3.1) — not trivial to DoS without large bandwidth.
- **No application-level rate limit today.**
- **No request-size limit** (Go default reads up to 32 MB form data; we should cap at 64 KB JSON).

**Residual risk** — ⚠ Volumetric DoS handled by infra (load balancer rate limit, Cloudflare). At the application layer, we're naive.

**Detection** — `auth_http_requests_total` rate spike.

**Roadmap closure**
- **v0.10.0**: per-IP rate limit on `/login`, `/refresh`, `/oauth/token`, `/mfa/complete`, `/register` (already in the plan for credential stuffing).
- **v0.10.0**: max request body size middleware (`http.MaxBytesReader`, ~64 KB).

---

## 25. Audit log tampering

**Threat** — Attacker with DB write access (insider, compromise) edits or deletes `audit_events` rows to hide their activity.

**Attacker model** — Compromised DBA / app credential.

**Attack surface** — `audit_events` table.

**Today's mitigation** — None. `audit_events` is just a row, anyone with `UPDATE` privilege can rewrite history.

**Residual risk** — ⚠ Total.

**Detection** — None today.

**Roadmap closure**
- **v0.11.0 hash chain**: `audit_events.event_hash = SHA256(prev_hash || canonical_json(event))`. `GET /audit/verify` recomputes the chain and reports the first divergence. Tamper is detectable.
- **v0.15.0**: stronger options if compliance requires — append-only ledger via a separate KMS-signed log, or write to an immutable store (S3 object lock).

---

## 26. Supply-chain compromise

**Threat** — A malicious version of one of our dependencies (golang-jwt, pquerna/otp, go-webauthn, pgx, etc.) ships code that exfiltrates secrets or backdoors auth.

**Attacker model** — Compromised maintainer account or typosquat.

**Attack surface** — `go.mod` direct + transitive deps.

**Today's mitigation**
- **`go.sum`** pins exact module hashes. A swap requires updating the sum.
- **Module proxy** (`proxy.golang.org`) caches a snapshot of each version. Versions don't change after publish.
- **Dependency review**: we use well-known, widely-deployed libraries. No exotic deps.

**Residual risk** — A new release of a popular library is published before anyone reviews it. Dependabot-style auto-PRs would compound this risk.

**Detection** — `gosec` / `govulncheck` against known CVE list. Not yet in CI.

**Roadmap closure**
- **v0.10.0**: add `govulncheck ./...` to CI; fail on known vulnerable deps.
- Manual dep updates only (no auto-merge of dep bumps).

---

## 27. Replay of WebAuthn assertions (cloned authenticator)

**Threat** — Attacker clones a hardware authenticator (rare; some software-backed credentials are clonable) and uses the same credential from a different device.

**Attacker model** — Has physical or software access to the user's authenticator.

**Attack surface** — `POST /webauthn/login/complete`.

**Today's mitigation**
- **Authenticator sign-count is stored** in `webauthn_credentials.sign_count`. The library updates it on each verify.
- ⚠ **We don't reject** when the incoming sign-count is ≤ stored. Cloned authenticators wouldn't be detected. Documented gap in TRADEOFFS.md §11.3.

**Residual risk** — Cloned-authenticator detection is not enforced today.

**Detection** — Manual SQL query on `webauthn_credentials.sign_count` decreases.

**Roadmap closure**
- **v0.10.0**: enforce strictly increasing sign-count in `internal/webauthn/app/service.go:FinishLogin`. ~10 LoC; trip an audit event on mismatch.

---

## 28. Tenant-scoped policy bypass

**Threat** — Tenant admin sets `require_mfa=true` but a user with `password` only still logs in.

**Attacker model** — User with no MFA enrolled in a tenant that mandates MFA.

**Attack surface** — `POST /login`.

**Today's mitigation** — `internal/auth/app/login.go` fetches the tenant policy and returns `ErrMFAEnrollmentRequired` → HTTP 403 if `policy.RequireMFA && len(verifiedFactors) == 0`. Tested by `TestTenantPolicy_RequireMFA_BlocksLoginWithoutFactor`.

**Residual risk**
- The policy is fetched on every login (one DB read per login). If we cache it later and miss an invalidation, a policy change has a stale window.
- The federation flow (v0.12.0) doesn't honor `require_mfa` yet — SSO bypasses MFA. Must be added at v0.12.0 design time.
- Password-reset flow (v0.11.0) and magic-link login (v0.11.0) need the same policy check.

**Detection** — Audit shows login event; admin can spot policy violations after the fact (v0.11.0 query API needed).

**Roadmap closure**
- **v0.11.0 / v0.12.0** acceptance: every new login pathway (federation, magic link, password reset re-auth) calls the same `policyEnforcer.Get()` and applies `require_mfa`.

---

## Threat-to-mitigation summary table

| # | Threat | Mitigation strength | Roadmap closure |
|---:|---|---|---|
| 1 | Credential stuffing | ⚠ Weak (Argon2 only) | v0.10.0 rate limit + lockout |
| 2 | Online brute force | ⚠ Weak | v0.10.0 |
| 3 | Offline brute force (DB leak) | ⚠ Medium | v0.10.0 stronger defaults; v0.15.0 envelope encryption |
| 4 | Account enumeration | ⚠ Leaks via timing | v0.10.0 constant-time login |
| 5 | Session fixation | ✅ Structural | — |
| 6 | Token theft over wire | ⚠ TTL-bounded | v0.15.0 DPoP |
| 7 | XSS exfiltration | ✅ HttpOnly cookie; ⚠ access token if client stores in localStorage | v0.15.0 DPoP |
| 8 | CSRF | ✅ SameSite=Strict | — |
| 9 | Refresh replay | ✅ Rotation + revoke | v0.10.0 tripwire alerting |
| 10 | Access token after revoke | ⚠ By design (TTL ≤ 15 min) | v0.15.0 introspection |
| 11 | Signing-key compromise | ⚠ Plain DB | v0.10.0 auto-rotate; v0.15.0 envelope encryption |
| 12 | JWT alg=none | ✅ ValidMethods allowlist + fuzz | — |
| 13 | PKCE downgrade | ✅ S256 only | — |
| 14 | Code reuse | ✅ Redis GETDEL + PKCE | — |
| 15 | Redirect-URI hijack | ✅ Exact match | v0.12.0 self-serve guardrails |
| 16 | Open redirect | ✅ Validated upstream | — |
| 17 | Tenant escape | ⚠ App-level only | v0.15.0 Postgres RLS |
| 18 | Privilege escalation | ⚠ Route omission risk | v0.15.0 compile-time guard |
| 19 | MFA replay | ⚠ Within 30s window | v0.10.0 last-used-step |
| 20 | SQL injection | ✅ Parameterized + tested | — |
| 21 | Header injection | ✅ stdlib sanitizes | — |
| 22 | Timing oracles | ⚠ Login leaks existence | v0.10.0 |
| 23 | SSRF via federation | N/A (not built) | v0.12.0 design constraint |
| 24 | Rate-limit / DoS | ⚠ None at app layer | v0.10.0 |
| 25 | Audit log tampering | ⚠ Total | v0.11.0 hash chain |
| 26 | Supply chain | ⚠ Manual review | v0.10.0 govulncheck in CI |
| 27 | WebAuthn replay (clone) | ⚠ Not enforced | v0.10.0 strict sign-count |
| 28 | Tenant policy bypass | ✅ Enforced on /login | v0.11.0/v0.12.0 consistency |

**Legend**: ✅ adequate today; ⚠ documented gap with planned closure.

---

## Living document

A new attack class or a CVE relevant to a dependency should add a section here. Every new endpoint or auth pathway must be added to the impact analysis of the threats above (especially #17 tenant escape, #18 privilege escalation, #28 policy bypass). A red-team or pentest report becomes the input for re-scoring every "Residual risk" line.

Review cadence: **every release**, and as part of the v0.15.0 security review pass.
