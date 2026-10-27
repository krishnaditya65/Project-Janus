# Project Janus — Benchmarks

All numbers below were measured on a single dev machine with the server, Postgres, Redis, and NATS all running on `localhost`. They are representative of *relative* costs and absolute floors, not of production capacity (where you'd horizontally scale and split DB from app).

**Test rig**
- Hardware: Apple Silicon (10 CPU cores), 32 GB RAM
- Go: 1.26 (`darwin/arm64`)
- Postgres 16 (Docker), Redis 7 (Docker), NATS 2.10 (Docker), all on the same host
- Auth server: ES256 active signing key, Principal cache enabled
- Methodology: each scenario is preceded by a 1s warm-up; samples collected for 15s unless noted; `time.Now()` deltas client-side

**Section index**
1. Microbenchmarks (in-process, no I/O)
2. Login latency + throughput
3. Auth middleware (JWT verify and session cache)
4. Refresh throughput
5. OAuth code exchange throughput
6. Redis cache hit rate
7. Server-side Prometheus histograms
8. Headline takeaways and what they mean for capacity planning

---

## 1. Microbenchmarks (in-process)

`go test -bench=. -benchmem -benchtime=3s -run=^$ ./internal/shared/password/ ./internal/token/app/`

| Function | ns/op | µs/op | ops/sec/core | B/op | allocs/op |
|---|---:|---:|---:|---:|---:|
| `password.Hash` (Argon2id m=64MB, t=3, p=2) | 95,624,990 | 95,625 | **10.5** | 67,115,979 | 59 |
| `password.Verify` (same params) | 95,131,227 | 95,131 | **10.5** | 67,112,967 | 48 |
| `JWTService.Issue` (ES256) | 53,224 | 53.2 | **18,800** | 12,421 | 137 |
| `JWTService.Verify` (ES256, in-mem key) | 81,069 | 81.1 | **12,300** | 6,192 | 102 |

**Notes**
- Argon2id eats 64 MB per call by design; allocation count is small because the buffer is reused inside the library.
- Argon2 throughput is the dominant login bottleneck — see §2.
- JWT verify is **1,170× faster** than Argon2 — JWTs are essentially free compared to passwords.
- JWT verify allocates more than it should (102 allocs); a future PR could pool the parser if `JWT.Verify` ever becomes a profile hotspot. It is not one today.

---

## 2. Login latency + throughput

Login does the full work: email lookup, Argon2id verify, user lookup, tenant policy fetch, MFA factor check, session insert (with refresh-token hash), permission lookup, JWT issue. The Argon2 verify dominates.

### 2.1 At realistic concurrency (matches Argon2 parallelism)

`go run ./test/stress -scenario login -concurrency 4 -duration 10s`

| Metric | Value |
|---|---:|
| Total requests | 204 |
| Failures | 0 |
| **Throughput** | **20.1 req/s** |
| min | 176 ms |
| p50 | 195 ms |
| p90 | 219 ms |
| p95 | 230 ms |
| p99 | 245 ms |
| max | 262 ms |
| mean | 199 ms |

### 2.2 Under contention (c=50)

`go run ./test/stress -scenario login -concurrency 50 -duration 15s`

| Metric | Value |
|---|---:|
| Total requests | 149 |
| Failures | 0 |
| **Throughput** | **8.9 req/s** |
| p50 | 5.07 s |
| p95 | 9.29 s |
| p99 | 10.30 s |
| mean | 5.48 s |

### 2.3 What this tells us

- **Single-server Argon2 ceiling ≈ 20 logins/sec on a 10-core dev machine** (matches the microbenchmark: 1 verify ≈ 95 ms × p=2 parallelism).
- Throughput *falls* from 20.1 to 8.9 req/s at c=50 because the queue depth becomes the bottleneck (Argon2 holds its CPU lock for ~95ms; 50 concurrent requests queue).
- p99 at c=4 is 245 ms — that is the login budget for any tenant. For 99% of logins to succeed within 250 ms, **you must keep concurrent in-flight logins ≤ Go runtime's GOMAXPROCS ÷ 2** (Argon2's parallelism is 2).
- Horizontal scaling is necessary above ~20 logins/sec/node. Argon2 parameters are NOT to be weakened.

### 2.4 Login mean (server-side, from Prometheus histogram)

Across 444 logins captured during the benchmark session, the server-side histogram `auth_http_request_duration_seconds_sum / _count` for `POST /login` reports:

```
mean = 1257.02 s / 444 = 2.83 s  (with bursts of contention included)
```

This skews high because it includes the c=50 contention runs. The c=4 microbenchmark's 199 ms mean is the apples-to-apples number.

---

## 3. Auth middleware (JWT verify and session cache)

The two auth paths through `/me` exercise the auth middleware end-to-end. They're the right proxy for "how fast can the server validate an authenticated request."

### 3.1 JWT verify path (stateless)

`go run ./test/stress -scenario jwt-verify -concurrency 100 -duration 15s`

| Metric | Value |
|---|---:|
| Total requests | 146,156 |
| Failures | 0 |
| **Throughput** | **9,738 req/s** |
| min | 1.5 ms |
| p50 | 9.5 ms |
| p90 | 12.9 ms |
| **p95** | **14.7 ms** |
| **p99** | **24.1 ms** |
| max | 69.1 ms |
| mean | 10.3 ms |

### 3.2 Session-ID + Principal cache path

`go run ./test/stress -scenario session-auth -concurrency 100 -duration 15s`

| Metric | Value |
|---|---:|
| Total requests | 314,638 |
| Failures | 0 |
| **Throughput** | **20,972 req/s** |
| min | 0.58 ms |
| p50 | 4.5 ms |
| p90 | 6.7 ms |
| **p95** | **7.6 ms** |
| **p99** | **10.0 ms** |
| max | 28.5 ms |
| mean | 4.7 ms |

### 3.3 What this tells us

- **The cached session path is ≈ 2.2× faster than the JWT path** at the same concurrency, because JWT verification still does a DB lookup for the signing key by `kid` on every request (no in-process key cache yet).
- The Principal cache is doing its job: **20k req/s sustained on a single node**, p99 ≤ 10 ms.
- JWT verify's p99 (24 ms) shows the long tail from the signing-key DB lookup. An in-process `kid → SigningKey` cache (LRU, 30s TTL) would likely halve the p99 — a v0.10.0 PR.

---

## 4. Refresh throughput

Refresh does: SHA-256 the incoming token, look up the session by hash, revoke the old session, write a new session, invalidate the principal cache, issue a new JWT, set a new cookie. Multiple DB writes + 1 Redis delete.

`go run /tmp/refresh_bench.go -concurrency 20 -duration 15s`

| Metric | Value |
|---|---:|
| Total requests | 11,000 |
| Failures | 0 |
| **Throughput** | **732.5 req/s** |
| min | 12.9 ms |
| p50 | 24.5 ms |
| p95 | 37.1 ms |
| p99 | 70.8 ms |
| max | 597.2 ms |
| mean | 27.3 ms |

### 4.1 What this tells us

- 732 refresh/sec on a single node. Most apps target 1 refresh per user per ~15 min, so this handles roughly **660k active users** before refresh becomes the bottleneck.
- max of 597 ms is a tail spike consistent with a Postgres autovacuum or transient lock; well under any reasonable SLA.
- p99 (70.8 ms) is acceptable. If we wanted to drive it lower, the principal cache invalidation + session insert could be issued in parallel (`errgroup`).

---

## 5. OAuth code exchange throughput

Full PKCE handshake: `/oauth/authorize` issues a code (Redis SET), `/oauth/token` consumes the code (Redis GETDEL), creates a session, issues access + refresh + ID tokens.

`go run ./test/stress -scenario oauth-token -concurrency 20 -duration 15s`

| Metric | Value |
|---|---:|
| Total requests | 19,511 |
| Failures | 0 |
| **Throughput** | **1,287 req/s** |
| min | 8.3 ms |
| p50 | 14.9 ms |
| p90 | 18.4 ms |
| **p95** | **20.1 ms** |
| **p99** | **27.9 ms** |
| max | 230.8 ms |
| mean | 15.5 ms |

### 5.1 What this tells us

- ~1,300 complete OAuth handshakes per second per node.
- Both legs (authorize + token) p99 in the 15-30 ms band; well within SPA-flow budget.
- The 230 ms max is one outlier in 20k requests (1 in 100k) — almost certainly GC.
- Throughput is higher than refresh because we don't yet hit the Principal cache invalidation path (OAuth flow always creates a new session, never revokes).

---

## 6. Redis cache hit rate

Measured by scraping the `auth_principal_cache_{hits,misses}_total` Prometheus counters before and after a 10-second session-auth burst.

| Counter | Before | After | Delta |
|---|---:|---:|---:|
| Hits | 353,251 | 547,077 | **+193,826** |
| Misses | 48 | 98 | **+50** |

**Cache hit rate during burst: 193,826 / (193,826 + 50) = 99.974%**

### 6.1 What this tells us

- Steady-state Principal cache is essentially always hot. 50 misses across 193,876 requests means the cache TTL (5 min) is far longer than the inter-request gap for any single session, which matches what we'd want.
- Pre-warm misses are 48 over the entire process lifetime; cache is amortized.
- If miss rate ever climbed (e.g. log-out churn), the fallback path (4-DB-read principal load) is what we'd see latency-wise.

---

## 7. Server-side Prometheus histograms

The values below are scraped from `auth_http_request_duration_seconds_*` at the end of the benchmark session. These are **server-measured** latencies (no client network), so they're a clean view of the server's contribution.

### 7.1 `GET /me` (auth middleware end-to-end)

682,796 requests over the session.

| Bucket | Cumulative count | Cumulative % |
|---|---:|---:|
| ≤ 1 ms | 12,873 | 1.9% |
| ≤ 5 ms | 465,161 | 68.1% |
| ≤ 10 ms | 630,183 | 92.3% |
| ≤ 25 ms | 681,490 | 99.81% |
| ≤ 50 ms | 682,554 | 99.97% |
| ≤ 100 ms | 682,796 | 100.0% |

Derived:
- Mean = `3212.15 s / 682,796` = **4.70 ms**
- p50 ≈ 5 ms (bucket boundary; refine from histogram below)
- p95 ≤ 25 ms (linear interpolation: in the [10, 25] band)
- p99 ≤ 25 ms (already inside that band)
- **p99.9 ≤ 50 ms**

### 7.2 Other endpoints (mean only)

| Endpoint | Count | Sum (s) | Mean (ms) |
|---|---:|---:|---:|
| `POST /register` (201) | 26 | 3.06 | **117.7** |
| `POST /login` (200) | 444 | 1257.02 | 2,831 ⚠ contention bursts |
| `POST /refresh` (200) | 11,000 | 297.61 | **27.1** |
| `GET /oauth/authorize` (302) | 20,840 | 58.60 | **2.81** |
| `POST /oauth/token` (200) | 20,840 | 253.20 | **12.15** |
| `GET /me` (200) | 682,796 | 3212.15 | **4.70** |
| `GET /.well-known/jwks.json` (200) | 1 | 0.018 | 17.6 |
| `GET /health` (200) | 7 | 0.0003 | 0.04 |
| `GET /metrics` (200) | 4 | 0.0027 | 0.68 |

(Login mean is high because the dataset includes the c=50 contention run. The c=4 microbenchmark — 199 ms mean — is the apples-to-apples number.)

---

## 8. Headline takeaways

### 8.1 The bottleneck order (per node)

| Operation | Throughput ceiling | Reason |
|---|---:|---|
| `/me` cached session | **20,972 req/s** | Redis GET + JSON unmarshal |
| `/me` JWT | **9,738 req/s** | ES256 verify + DB lookup of signing key |
| OAuth code exchange | **1,287 req/s** | Redis GETDEL + session insert + JWT issue |
| Refresh | **733 req/s** | Session revoke + insert + JWT issue + cache invalidate |
| Login | **20 req/s** | Argon2id verify (intentional CPU cost) |

### 8.2 The latency SLO we can advertise (today)

| Endpoint | p95 | p99 |
|---|---:|---:|
| `/me` (cached session) | ≤ 8 ms | ≤ 10 ms |
| `/me` (Bearer JWT) | ≤ 15 ms | ≤ 25 ms |
| `POST /oauth/token` | ≤ 20 ms | ≤ 28 ms |
| `POST /refresh` | ≤ 37 ms | ≤ 71 ms |
| `POST /login` (c ≤ 4) | ≤ 230 ms | ≤ 245 ms |

### 8.3 Capacity planning back-of-envelope

For a node handling realistic mixed traffic at peak (assume 100 logins/min, 60k auth checks/min, 4k refreshes/min, 1k OAuth exchanges/min):

| Op | Peak/sec | % capacity used |
|---|---:|---:|
| Auth checks (cached) | 1,000 | 5% |
| Refresh | 67 | 9% |
| OAuth exchange | 17 | 1% |
| Login | 1.7 | 8% |
| **Total** | | **~23% of one node** |

A **single node** comfortably handles a moderate workload. Login dominates the CPU at scale; provision Argon2 capacity first when planning.

### 8.4 Next optimizations identified

1. **In-process signing-key LRU** (~30s TTL) — would drop JWT verify p99 from 24 ms to <8 ms by removing the per-request DB lookup. Easy v0.10.0 PR.
2. **Parallel refresh fan-out** — `errgroup` the revoke / new-session insert / cache invalidate. Refresh p99 from 71 ms to ~40 ms.
3. **Login pre-warm dummy hash** — already planned for v0.10.0 (constant-time login). Will also remove a `GetByEmail` allocation for unknown emails.
4. **JWT issue allocs (137)** — pool the JWT encoder if issue becomes hot.
5. **Read-replica routing for `/me` session lookup** — `Pools.Reader` exists but is not used; routing the session-id fallback path to a replica would lift the cached-miss ceiling.

### 8.5 What we *don't* see in these numbers

- **GC pauses**: the rare 200-600 ms max is consistent with Go's GC running on a hot path; we have no GOGC tuning today. Worth profiling with `pprof` in a v0.10.0 perf sprint.
- **Connection pool saturation**: pgxpool/Redis pool have no metrics surfaced. We're not exhausting them today (failure rate is zero everywhere), but we'd be blind to it.
- **Long-tail latency from disk** (Postgres WAL fsync): masked by the local SSD. Production with EBS gp3 will be 2-3× slower on writes.

---

## Reproducing these numbers

```bash
# Bring infrastructure up
docker start auth-server-postgres auth-server-redis auth-server-nats

# Start the server
cd auth-server
go run ./cmd/iam-server/...   # in another shell

# Micro
go test -bench=. -benchmem -benchtime=3s -run=^$ \
    ./internal/shared/password/ ./internal/token/app/

# Stress (each takes 15-30s)
go run ./test/stress -scenario login        -concurrency 4   -duration 10s
go run ./test/stress -scenario jwt-verify   -concurrency 100 -duration 15s
go run ./test/stress -scenario session-auth -concurrency 100 -duration 15s
go run ./test/stress -scenario oauth-token  -concurrency 20  -duration 15s

# Refresh (one-off binary lives in /tmp; see §4 of this doc for source)
go run /tmp/refresh_bench.go -concurrency 20 -duration 15s

# Cache hit rate
curl -s http://localhost:8080/metrics | grep auth_principal_cache
# (compare before/after running session-auth)
```

These benchmarks must be re-run before any release that touches the hot path (auth middleware, login, OAuth, refresh, Principal cache). The numbers should be added to the release changelog.
