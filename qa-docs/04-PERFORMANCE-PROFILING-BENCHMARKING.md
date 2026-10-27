# custom-auth-server — Performance, Profiling & Benchmarking Reference (04)

Audience: LLM agents / engineers executing performance work. Companion to `01-INFRA-…` (architecture), `02-TEST-SCENARIOS.md` (functional cases), `03-TEST-SCRIPTS.md` (functional scripts). Facts marked **[src]** were read from source; everything else is a proposed procedure or a target to calibrate. Nothing here has been executed.

---

## 0. Scope and honesty statement

- This document defines *how to measure*; it does not contain measured numbers. Every target below is a **starting hypothesis** — after the first baseline run, replace it with `baseline × tolerance`.
- Passing all performance cases does **not** prove absence of performance bugs; it proves the measured workloads on the measured hardware met the recorded thresholds. Unmeasured workloads (other mixes, other data volumes, other hardware) remain unknown.

## 1. Performance model of the system [src]

| Component | Port | Hot path | Dominant cost per op |
|---|---|---|---|
| auth-server (Go, chi, pgx) | 8080 | `/login`, `/oauth/token`, `/refresh`, `/me`, `/.well-known/jwks.json` | argon2id hash verify (CPU + 64 MiB RAM), JWT sign/verify, Postgres round trips, Redis ops |
| identity-service | 8081 | `/internal/identities[...]` | Postgres point reads |
| mfa-service | 8082 | MFA/WebAuthn begin/complete, `/internal/mfa/challenges/consume` | Redis challenge get/del, TOTP HMAC, WebAuthn signature verify |
| Postgres 16 | 5433 | identities, credentials, refresh_tokens, audit | write amplification on login/refresh (audit + token rows) |
| Redis 7 | 6380 | sessions, auth codes, challenges, revocation cache | network RTT; memory growth with TTL'd keys |

**argon2id parameters [src `internal/shared/password/password.go`]:** `memory = 64*1024` KiB (64 MiB), `iterations = 3`, `parallelism = 2`, salt 16 B, key 32 B.
Consequences to test explicitly:
- Each concurrent `/login` (and `/register`, password change) allocates ~64 MiB transient. N concurrent logins ⇒ ~N×64 MiB peak RSS. 100 concurrent ⇒ ~6.4 GiB → OOM-kill risk in a container with a 1–2 GiB limit. **There is no rate limiting or lockout [src]**, so the login path is also the cheapest amplification vector.
- Login latency floor ≈ one argon2id evaluation (typically 50–200 ms on modern x86 at these params); throughput ceiling ≈ `cores / (t_hash × parallelism-efficiency)`.
- Go GC: 64 MiB slabs inflate heap → GC pacing (`GOGC`) and `GOMEMLIMIT` dominate tail latency of *all* routes on the same process.

Other per-request costs:
- `/me` with Bearer JWT: stateless signature verify (ECDSA or RSA per JWKS key type [src]) — RSA-2048 verify ≈ tens of µs, ECDSA P-256 verify ≈ 50–100 µs; no DB.
- `/me` with `X-Session-ID`: the existing stress harness documents **4 sequential DB reads** [src `test/stress/main.go`] — latency = 4 × (pool acquire + RTT + query).
- `/oauth/token` (authorization_code): code lookup/delete (Redis), PKCE S256 hash, client lookup, token mint, refresh row insert.
- `/refresh`: rotation = read + revoke old + insert new (transactional) → row-lock contention on concurrent refresh of the same token family.

Existing instrumentation [src `internal/platform/metrics/metrics.go`, router exposes `GET /metrics`]:
`auth_http_request_duration_seconds` (histogram), `auth_http_requests_total`, `auth_events_total`, `auth_principal_cache_hits_total`, `auth_principal_cache_misses_total`.
No `net/http/pprof` endpoint is registered [src: grep found none].

Existing harnesses [src `test/`]: `stress/` (scenarios `login | jwt-verify | session-auth | jwks | oauth-token | mixed`, flags `-concurrency -duration -base -db -warmup -sla-p95 -sla-p99`), `soak/`, `spike/`, `abtest/`, `race.sh`, `coverage.sh`, `run-all.sh`, `fuzz/`.

## 2. Environment & reproducibility rules

1. Dedicated host or VM; record CPU model, core count, RAM, kernel, Go version, Postgres/Redis versions, container limits, `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT`.
2. Load generator on a **different** machine (or pinned to disjoint cores via `taskset`/`cpuset`) — otherwise generator CPU steals from the SUT.
3. Disable CPU frequency scaling (`cpupower frequency-set -g performance`), turbo noted; disable swap or record it.
4. Warm-up ≥ 60 s (JIT-free Go still needs pool fill, page cache, Redis warm keys). Discard warm-up samples.
5. Seed data sized per scenario (§6) and recorded in `meta.json`. Re-seed between runs (`TRUNCATE … RESTART IDENTITY CASCADE`) or snapshot/restore the volume.
6. Each scenario ≥ 3 repetitions; report median of runs and the spread (min/max). Reject runs whose coefficient of variation of throughput > 5%.
7. Use open-model (constant arrival rate) generators for latency SLOs (`k6 constant-arrival-rate`, `wrk2 -R`, `vegeta -rate`) to avoid coordinated omission. Closed-model (`-concurrency`) only for max-throughput discovery.

## 3. Data-retrieval contract (where every number lives)

All runs write to `perf-results/auth/<YYYYMMDD-HHMM>-<gitsha>/<scenario-id>/`:

| File | Producer | Content |
|---|---|---|
| `meta.json` | `collect.sh` | hardware, versions, env vars, seed sizes, git sha, start/end epoch |
| `k6-summary.json` | `k6 --summary-export` | http_req_duration percentiles, iterations, failures |
| `k6-raw.json.gz` | `k6 --out json=` | per-request samples (for re-bucketing) |
| `hdr.hgrm` | wrk2 `--latency` / vegeta `report -type=hdrplot` | full HDR percentile distribution |
| `stress.txt` | `go run ./test/stress` | harness output (throughput, p50/p95/p99) |
| `prom/*.csv` | `collect.sh` via Prometheus HTTP API | time series for §3.1 queries, step 5 s |
| `pprof/{cpu,heap,allocs,goroutine,mutex,block}.pb.gz` | `go tool pprof` / pprof endpoint | profiles captured at steady state |
| `pprof/*.svg`, `top.txt` | `go tool pprof -svg / -top` | rendered views |
| `pg/statements.csv` | `pg_stat_statements` | per-query calls/total/mean/stddev/rows |
| `pg/waits.csv` | sampled `pg_stat_activity` | wait events histogram |
| `redis/info.txt`, `redis/latency.txt`, `redis/slowlog.txt` | `redis-cli` | memory, ops/sec, latency doctor |
| `host/{vmstat,iostat,pidstat}.txt` | sysstat | CPU, run-queue, IO, per-process |
| `summary.json` | `summarize.py` | normalized record (schema below) |

`summary.json` schema (one per scenario; append to `perf-results/auth/history.jsonl` for trend queries):
```json
{"project":"auth","scenario":"PERF-LOGIN-02","git":"abc123","ts":"2026-10-14T10:00:00Z",
 "load":{"model":"open","rate_rps":200,"duration_s":300,"vus_max":400},
 "throughput_rps":198.7,"error_rate":0.0004,
 "latency_ms":{"p50":82,"p90":120,"p95":141,"p99":230,"p999":410,"max":900},
 "resources":{"cpu_cores_avg":7.6,"rss_mb_peak":5120,"gc_pause_p99_ms":3.1,"pg_conns_peak":40,"redis_ops":1200},
 "slo":{"p99_ms":300,"error_rate":0.001},"pass":true,"notes":""}
```
Retrieval: `jq -s 'map(select(.scenario=="PERF-LOGIN-02")) | sort_by(.ts) | .[] | [.ts,.git,.throughput_rps,.latency_ms.p99] | @tsv' perf-results/auth/history.jsonl`.

### 3.1 PromQL queries to snapshot (save each to `prom/<name>.csv`)
```
rps_by_route     = sum by (route) (rate(auth_http_requests_total[30s]))      # VERIFY label names in metrics.go
err_ratio        = sum(rate(auth_http_requests_total{status=~"5.."}[30s])) / sum(rate(auth_http_requests_total[30s]))
p99_by_route     = histogram_quantile(0.99, sum by (le, route) (rate(auth_http_request_duration_seconds_bucket[30s])))
p50_by_route     = histogram_quantile(0.50, sum by (le, route) (rate(auth_http_request_duration_seconds_bucket[30s])))
cache_hit_ratio  = rate(auth_principal_cache_hits_total[1m]) / (rate(auth_principal_cache_hits_total[1m]) + rate(auth_principal_cache_misses_total[1m]))
events           = sum by (event) (rate(auth_events_total[1m]))
go_heap          = go_memstats_heap_inuse_bytes
go_gc_p99        = histogram_quantile(0.99, rate(go_gc_duration_seconds_bucket[1m]))   # summary in client_golang: use go_gc_duration_seconds{quantile="1"}
goroutines       = go_goroutines
rss              = process_resident_memory_bytes
cpu              = rate(process_cpu_seconds_total[30s])
```
If no Prometheus is in compose, run one: `docker run -d --network host -v $PWD/prom.yml:/etc/prometheus/prometheus.yml prom/prometheus:v2.53.0` with a scrape job for `localhost:8080/metrics`, `8081`, `8082` (scrape_interval 5s) plus `postgres_exporter` (`:9187`) and `redis_exporter` (`:9121`).

### 3.2 collect.sh (snapshot everything for a time window)
```bash
#!/usr/bin/env bash
# usage: collect.sh <outdir> <start_epoch> <end_epoch>
set -euo pipefail; OUT=$1; S=$2; E=$3; P=${PROM:-http://localhost:9090}
mkdir -p $OUT/prom $OUT/pg $OUT/redis
q(){ curl -sG "$P/api/v1/query_range" --data-urlencode "query=$2" -d start=$S -d end=$E -d step=5 \
     | jq -r '.data.result[] | (.metric|tostring) as $m | .values[] | [$m,.[0],.[1]] | @csv' > $OUT/prom/$1.csv; }
q rps 'sum by (route)(rate(auth_http_requests_total[30s]))'
q p99 'histogram_quantile(0.99,sum by (le,route)(rate(auth_http_request_duration_seconds_bucket[30s])))'
q p50 'histogram_quantile(0.50,sum by (le,route)(rate(auth_http_request_duration_seconds_bucket[30s])))'
q heap 'go_memstats_heap_inuse_bytes'; q rss 'process_resident_memory_bytes'; q cpu 'rate(process_cpu_seconds_total[30s])'
q goroutines 'go_goroutines'
psql "$PGDSN" -Atc "copy (select queryid,calls,total_exec_time,mean_exec_time,stddev_exec_time,rows,shared_blks_hit,shared_blks_read,left(query,200) from pg_stat_statements order by total_exec_time desc limit 50) to stdout with csv header" > $OUT/pg/statements.csv
redis-cli -p 6380 info all > $OUT/redis/info.txt; redis-cli -p 6380 latency doctor > $OUT/redis/latency.txt; redis-cli -p 6380 slowlog get 128 > $OUT/redis/slowlog.txt
jq -n --arg git "$(git rev-parse --short HEAD)" --arg s "$S" --arg e "$E" --arg cpu "$(lscpu 2>/dev/null | grep 'Model name' | cut -d: -f2 | xargs || sysctl -n machdep.cpu.brand_string)" \
  --arg go "$(go version)" '{git:$git,start:$s,end:$e,cpu:$cpu,go:$go,env:env|with_entries(select(.key|test("^(GO|AUTH|PG|REDIS)")))}' > $OUT/meta.json
```
Reset before each run: `psql -c "select pg_stat_statements_reset()"`, `redis-cli -p 6380 config resetstat`, `redis-cli -p 6380 slowlog reset`.

## 4. Tool matrix

| Need | Tool | Command / note |
|---|---|---|
| Go micro-benchmarks | `go test -bench` + `benchstat` | `go test -run=^$ -bench=. -benchmem -count=10 ./internal/... > new.txt; benchstat old.txt new.txt` |
| CPU profile (bench) | `go test -cpuprofile` | `go test -run=^$ -bench=BenchmarkVerify -cpuprofile cpu.out ./internal/shared/password` |
| CPU/heap profile (live) | `net/http/pprof` (add, see §7.1) | `go tool pprof -http=:0 http://localhost:6060/debug/pprof/profile?seconds=30` |
| Execution trace | `runtime/trace` | `curl -o trace.out localhost:6060/debug/pprof/trace?seconds=5; go tool trace trace.out` (GC, scheduler latency, network blocking) |
| Continuous profiling | Pyroscope / Parca | Pyroscope Go SDK push or Parca eBPF agent (no code change) |
| Off-CPU / syscalls | `perf`, `bpftrace`, `offcputime` (bcc) | `sudo offcputime-bpfcc -p $(pgrep auth-server) 30 > offcpu.txt` → flamegraph.pl |
| Flamegraphs | `go tool pprof -http`, Brendan Gregg FlameGraph, speedscope | pprof “Flame Graph” view; `perf script | stackcollapse-perf.pl | flamegraph.pl` |
| HTTP load (open model) | k6, wrk2, vegeta | see §8 |
| HTTP load (existing) | `go run ./test/stress` | closed model; use for max-throughput discovery |
| Postgres | `pg_stat_statements`, `EXPLAIN (ANALYZE, BUFFERS)`, `auto_explain`, `pg_stat_activity` wait sampling, `pgbadger` | `ALTER SYSTEM SET auto_explain.log_min_duration='20ms'` |
| Redis | `redis-cli --latency-history`, `--bigkeys`, `--memkeys`, `INFO commandstats`, `LATENCY DOCTOR` | |
| Pool health | `pgxpool.Stat()` | expose AcquireCount, AcquireDuration, EmptyAcquireCount, IdleConns (add gauge, §7.4) |
| Host | `pidstat -urd -p <pid> 1`, `vmstat 1`, `iostat -x 1`, `sar -n DEV 1` | |
| Container | `docker stats --no-stream --format '{{json .}}'`, cAdvisor | memory limit hit → OOMKilled in `docker inspect` |
| Memory leaks | pprof `heap` diff (`-base`), `goleak` in tests | `go tool pprof -base heap1.pb.gz heap2.pb.gz` |
| Lock contention | pprof `mutex`/`block` (`runtime.SetMutexProfileFraction(5)`, `SetBlockProfileRate(1e6)`) | |

## 5. Micro-benchmarks (code level)

Add to the listed packages (files `*_bench_test.go`). Each must call `b.ReportAllocs()` and be deterministic.

| ID | Package | Benchmark | What it isolates | Record |
|---|---|---|---|---|
| MB-01 | `internal/shared/password` | `BenchmarkHash`, `BenchmarkVerify_OK`, `BenchmarkVerify_Wrong` | argon2id cost at m=64MiB,t=3,p=2 | ns/op, B/op (expect ≈ 64 MiB/op), allocs/op |
| MB-02 | same | `BenchmarkVerify_Parallel` with `b.RunParallel` and `b.SetParallelism(1,2,4,8)` | memory-bandwidth saturation across cores | ns/op vs parallelism curve |
| MB-03 | same | `BenchmarkVerify_MalformedPHC` | parser fast-fail path (must be ≪ hash cost) | ns/op |
| MB-04 | `internal/token/app` | `BenchmarkSignAccess_{EC,RSA}`, `BenchmarkVerifyAccess_{EC,RSA}` | JWT sign/verify per key type | ns/op, allocs |
| MB-05 | `internal/token/app` | `BenchmarkParseInvalidSig`, `BenchmarkParseExpired` | rejection path must not be slower than accept | ns/op |
| MB-06 | PKCE helper | `BenchmarkPKCE_S256` | sha256+base64url | ns/op |
| MB-07 | TOTP (mfa) | `BenchmarkTOTPValidate` incl. ±skew window | HMAC-SHA1 × window | ns/op |
| MB-08 | WebAuthn | `BenchmarkAssertionVerify` (fixture) | CBOR parse + sig verify | ns/op, allocs |
| MB-09 | router | `BenchmarkRouter_Me` using `httptest` + fake repos | middleware chain overhead | ns/op, allocs |
| MB-10 | principal cache | `BenchmarkPrincipalCache_{Hit,Miss}` parallel | cache lock contention | ns/op at P=1..32 |

Template:
```go
func BenchmarkVerify_OK(b *testing.B) {
    h, _ := password.Hash("Aa1!aaaa-bench")
    b.ReportAllocs(); b.ResetTimer()
    for i := 0; i < b.N; i++ { if ok, _ := password.Verify("Aa1!aaaa-bench", h); !ok { b.Fatal("mismatch") } }
}
func BenchmarkVerify_Parallel(b *testing.B) {
    h, _ := password.Hash("x"); b.ReportAllocs()
    b.RunParallel(func(pb *testing.PB) { for pb.Next() { password.Verify("x", h) } })
}
```
(VERIFY exact exported names in `password.go`/`jwt_service.go` before compiling.)

Run & compare:
```bash
go test -run='^$' -bench=. -benchmem -count=10 -cpu=1,2,4,8 ./internal/... | tee perf-results/auth/$RUN/micro.txt
benchstat perf-results/auth/<baseline>/micro.txt perf-results/auth/$RUN/micro.txt > perf-results/auth/$RUN/micro.benchstat.txt
```
Gate: any `sec/op` delta > +10% with p < 0.05 in benchstat ⇒ regression.

## 6. Macro performance scenarios

Format: ID · Workload · Load profile · Seed · Measure · Proposed target (calibrate) · Pass rule.

### 6.1 Baseline / single-route characterization
| ID | Workload | Load | Seed | Measure | Target |
|---|---|---|---|---|---|
| PERF-JWKS-01 | `GET /.well-known/jwks.json` | open 500→5000 rps step 500 / 60 s | — | max rps at p99<20 ms | > 5k rps/core-ish; zero DB queries (pg_stat_statements unchanged) |
| PERF-OIDC-01 | `GET /.well-known/openid-configuration` | same | — | as above | same |
| PERF-ME-JWT-01 | `GET /me` Bearer | open 1k→10k rps | 10k users, tokens pre-minted | p50/p99, CPU/op | p99 < 10 ms; CPU flat w.r.t. user count |
| PERF-ME-SESS-01 | `GET /me` X-Session-ID | open 500→5k rps | 10k sessions | p99, pg calls per request (expect 4 [src]) | p99 < 25 ms; calls/req exactly as designed |
| PERF-LOGIN-01 | `POST /login` | open 10→(cores×10) rps step 10 | 100k users | knee point, RSS peak | knee recorded; RSS ≤ container limit × 0.8 |
| PERF-LOGIN-02 | `POST /login` | closed concurrency 1,2,4,8,16,32,64,128 | 100k users | throughput, p99, RSS, OOM | throughput plateaus ≈ cores/(t_hash); **record concurrency at which OOM occurs** |
| PERF-LOGIN-03 | wrong-password login | as 01 | | must cost ≈ same as success (no timing oracle) | |p50(ok) − p50(wrong)| < 5% |
| PERF-LOGIN-04 | unknown-email login | as 01 | | user enumeration via timing | p50 within 5% of PERF-LOGIN-03 (if much faster ⇒ finding: enumeration) |
| PERF-REG-01 | `POST /register` | open 5→50 rps | — | insert rate, identities/tenants/users rows | p99 < 2× login p99 |
| PERF-TOKEN-01 | `POST /oauth/token` authorization_code (full: authorize → code → token, S256) | open 20→400 rps | 1 client | p99 per leg, Redis ops/req | per-leg breakdown captured |
| PERF-REFRESH-01 | `POST /refresh` distinct families | open 50→1000 rps | 50k refresh tokens | row inserts/s, index bloat | p99 < 30 ms |
| PERF-REFRESH-02 | same refresh token concurrently ×N (N=2..64) | burst | 1 family | lock waits (`pg_stat_activity.wait_event=transactionid`), exactly-one-wins | no deadlocks; 1 success, N-1 rejected; p99 bounded |
| PERF-MFA-01 | TOTP verify on :8082 | open 100→2000 rps | 10k factors | p99, Redis ops | p99 < 15 ms |
| PERF-WA-01 | WebAuthn login begin+complete on :8082 | open 50→500 rps | 1k credentials | sig verify CPU | |
| PERF-INT-01 | identity-service `GET /internal/identities/by-email` | open 1k→10k rps | 100k identities | index usage (`EXPLAIN` shows Index Scan) | p99 < 10 ms |

### 6.2 Mixed / realistic
| ID | Mix | Load | Measure |
|---|---|---|---|
| PERF-MIX-01 | 70% `/me` JWT, 20% `/login`, 10% JWKS (matches harness `mixed`) | open, 50% of measured knee | p99 per route; does login's 64 MiB churn raise `/me` p99 (GC interference)? |
| PERF-MIX-02 | 60% `/me`, 15% refresh, 10% token, 10% login, 5% register | open, 30/60/90% of knee | per-route SLO table |
| PERF-MIX-03 | same as 02 with session auth instead of JWT | | DB headroom |

### 6.3 Stress / spike / soak / capacity
| ID | Type | Procedure | Pass / capture |
|---|---|---|---|
| PERF-STRESS-01 | Stress to failure | step +10% rps every 2 min until error_rate > 1% or p99 > 10× baseline | record breaking point, failure mode (5xx? timeouts? OOMKilled? pool exhaustion?) |
| PERF-STRESS-02 | Login memory bomb | concurrency 256 logins for 60 s under container limit 2 GiB | expected finding: OOM (no limiter). Capture `docker inspect --format '{{.State.OOMKilled}}'`, last heap profile |
| PERF-SPIKE-01 | Spike | 10% → 300% knee in 5 s, hold 60 s, back | time to recover p99 to baseline (< 30 s target), no stuck goroutines (`go_goroutines` returns to baseline) |
| PERF-SOAK-01 | Soak | MIX-02 at 60% knee for 8–24 h (`test/soak`) | heap_inuse slope ≈ 0 (linear regression slope < 1 MiB/h), goroutines flat, Redis `used_memory` bounded by TTL (sessions 7 d!) , pg table/index sizes growth = expected rows |
| PERF-POOL-01 | Pool exhaustion | set pg pool max=4 (env/config — VERIFY name), drive MIX-02 | requests queue (acquire wait) not crash; measure `AcquireDuration` |
| PERF-DEP-01 | Redis latency | `toxiproxy` +5/+20/+100 ms on Redis | p99 rises ≈ ops/req × added latency (computes ops/req) |
| PERF-DEP-02 | Postgres latency | toxiproxy +5/+20 ms on 5433 | same for DB calls/req |
| PERF-SCALE-01 | Horizontal | 1,2,4 auth-server replicas behind LB, fixed DB | throughput vs replicas; fit USL (§9) |
| PERF-SCALE-02 | Vertical | GOMAXPROCS 1,2,4,8 | login scaling efficiency |
| PERF-GC-01 | GC tuning | MIX-01 with GOGC=100/200/off+GOMEMLIMIT | p99 vs RSS trade-off table |

## 7. Profiling playbooks

### 7.1 Enabling live pprof (test builds only — never expose publicly)
```go
// cmd/auth-server/pprof.go  (build tag keeps it out of prod)
//go:build pprof
package main
import ( "net/http"; _ "net/http/pprof"; "runtime" )
func init() { runtime.SetMutexProfileFraction(5); runtime.SetBlockProfileRate(1_000_000)
  go http.ListenAndServe("127.0.0.1:6060", nil) }
```
Build: `go build -tags pprof -o bin/auth-server-prof ./cmd/...` (VERIFY cmd path). Same for identity/mfa on 6061/6062.

### 7.2 Capture at steady state (during PERF-MIX-02)
```bash
B=http://127.0.0.1:6060/debug/pprof; D=$OUT/pprof; mkdir -p $D
curl -s "$B/profile?seconds=30" > $D/cpu.pb.gz
curl -s "$B/heap" > $D/heap.pb.gz;   curl -s "$B/allocs" > $D/allocs.pb.gz
curl -s "$B/goroutine" > $D/goroutine.pb.gz; curl -s "$B/goroutine?debug=2" > $D/goroutine.txt
curl -s "$B/mutex" > $D/mutex.pb.gz; curl -s "$B/block" > $D/block.pb.gz
curl -s "$B/trace?seconds=5" > $D/trace.out
for p in cpu heap allocs mutex block; do go tool pprof -top -nodecount=40 $D/$p.pb.gz > $D/$p.top.txt; go tool pprof -svg $D/$p.pb.gz > $D/$p.svg; done
go tool pprof -sample_index=alloc_space -top $D/allocs.pb.gz > $D/alloc_space.top.txt
```

### 7.3 What to look for (expected signatures)
| Symptom | Profile | Expected culprit | Action |
|---|---|---|---|
| CPU saturated at low login rps | cpu | `golang.org/x/crypto/argon2.processBlocks` / `blake2b` ≥ 80% | expected; tune params vs SLO, add concurrency limiter (semaphore) on hashing |
| Huge alloc_space | allocs | `argon2.IDKey` 64 MiB/op | add bounded worker pool; consider `sync.Pool` not applicable (argon2 allocates internally) |
| `/me` p99 spikes when logins run | trace | GC STW/assist; mark assist in `/me` goroutines | GOMEMLIMIT, separate login worker process, limit concurrent hashes |
| High `runtime.selectgo`/`sync.(*Mutex).Lock` | mutex/block | principal cache lock, pgxpool acquire | shard cache, size pool |
| Many goroutines blocked in `net.(*conn).Read` to 5433 | goroutine | pool starvation / slow queries | pg_stat_statements top, indexes |
| JSON encode heavy | cpu | `encoding/json` reflection | precomputed JWKS bytes, `json.Encoder` reuse |
| ECDSA/RSA sign dominates token endpoint | cpu | `crypto/ecdsa.Sign` / `rsa.SignPKCS1v15` | expected; prefer EC P-256/Ed25519, cache parsed keys |

### 7.4 Database profiling
```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;  -- requires shared_preload_libraries
SELECT left(query,120), calls, round(mean_exec_time::numeric,2) mean_ms, round(stddev_exec_time::numeric,2) sd, rows/calls rows_per_call,
       round(100.0*shared_blks_hit/nullif(shared_blks_hit+shared_blks_read,0),1) hit_pct
FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 25;
-- wait sampling (run every 1s during load, append to pg/waits.csv)
SELECT now(), wait_event_type, wait_event, count(*) FROM pg_stat_activity WHERE state<>'idle' GROUP BY 1,2,3;
-- per-table write amplification
SELECT relname, n_tup_ins, n_tup_upd, n_tup_del, n_dead_tup, last_autovacuum FROM pg_stat_user_tables ORDER BY n_tup_ins DESC;
-- index usage
SELECT relname, indexrelname, idx_scan, idx_tup_read FROM pg_stat_user_indexes ORDER BY idx_scan;
```
For each top statement run `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` with representative parameters and save to `pg/explain-<queryid>.json` (visualize with explain.dalibo.com — local copy only, plans can contain data).
Expected checks: lookup by email uses a unique index (case handling — VERIFY lower(email) index if emails are normalized); refresh token lookup by hash is indexed; audit inserts are append-only and unindexed except FK.

Pool gauges to add (test builds): export `pgxpool.Stat()` every 5 s as `auth_pg_pool_{acquired,idle,total}_conns`, `auth_pg_pool_acquire_duration_seconds_total`, `auth_pg_pool_empty_acquire_total`.

### 7.5 Redis profiling
`redis-cli -p 6380 info commandstats` before/after → ops/req per route = Δcalls / Δrequests. `--latency-history -i 1` during runs; `--bigkeys` after soak (session hashes should be small); check `expired_keys` vs `evicted_keys` (any eviction ⇒ maxmemory too low ⇒ sessions/codes silently lost = correctness bug, not just perf).

### 7.6 Off-CPU and kernel
```bash
sudo perf record -F 99 -g -p $(pgrep -f auth-server) -- sleep 30; sudo perf script > perf.stacks
stackcollapse-perf.pl perf.stacks | flamegraph.pl > oncpu.svg
sudo offcputime-bpfcc -df -p $(pgrep -f auth-server) 30 | flamegraph.pl --color=io > offcpu.svg
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_futex /pid==PID/ { @[ustack]=count(); }'
```
Go binaries need `-gcflags=all=-N -l` *not* for perf (keep optimizations); perf resolves Go symbols natively; frame pointers are enabled by default in Go ≥1.21 on amd64/arm64.

## 8. Load scripts

### 8.1 k6 — open-model login + me (save as `perf/k6/auth-mix.js`)
```javascript
import http from 'k6/http'; import { check } from 'k6'; import { SharedArray } from 'k6/data';
const B = __ENV.BASE || 'http://localhost:8080';
const users = new SharedArray('u', () => JSON.parse(open('./users.json')));      // [{email,password}]
export const options = {
  discardResponseBodies: false,
  scenarios: {
    me:    { executor:'constant-arrival-rate', rate: +__ENV.ME_RPS||700, timeUnit:'1s', duration: __ENV.DUR||'5m', preAllocatedVUs:200, maxVUs:2000, exec:'me' },
    login: { executor:'constant-arrival-rate', rate: +__ENV.LOGIN_RPS||50, timeUnit:'1s', duration: __ENV.DUR||'5m', preAllocatedVUs:100, maxVUs:1000, exec:'login' },
    jwks:  { executor:'constant-arrival-rate', rate: +__ENV.JWKS_RPS||100, timeUnit:'1s', duration: __ENV.DUR||'5m', preAllocatedVUs:20, maxVUs:200, exec:'jwks' },
  },
  thresholds: {
    'http_req_failed': ['rate<0.001'],
    'http_req_duration{scenario:me}':    ['p(99)<10'],
    'http_req_duration{scenario:login}': ['p(99)<400'],
    'http_req_duration{scenario:jwks}':  ['p(99)<20'],
  },
  summaryTrendStats: ['min','med','avg','p(90)','p(95)','p(99)','p(99.9)','max'],
};
let tok = null;
export function setup(){ const u=users[0]; const r=http.post(`${B}/login`, JSON.stringify(u), {headers:{'Content-Type':'application/json'}});
  return { token: r.json('access_token') };   // VERIFY field name (see 02 facts table)
}
export function me(d){ const r=http.get(`${B}/me`, {headers:{Authorization:`Bearer ${d.token}`}, tags:{route:'/me'}}); check(r,{'200':x=>x.status===200}); }
export function login(){ const u=users[Math.floor(Math.random()*users.length)];
  const r=http.post(`${B}/login`, JSON.stringify(u), {headers:{'Content-Type':'application/json'}, tags:{route:'/login'}}); check(r,{'200':x=>x.status===200}); }
export function jwks(){ http.get(`${B}/.well-known/jwks.json`, {tags:{route:'jwks'}}); }
```
Run: `k6 run --summary-export $OUT/k6-summary.json --out json=$OUT/k6-raw.json perf/k6/auth-mix.js` then `gzip $OUT/k6-raw.json`.
Users seed: `go run ./test/stress -scenario login -concurrency 1 -duration 1s` creates setup data (VERIFY), or insert via `/register` loop and dump `users.json`.

### 8.2 Knee finder (step load with wrk2)
```bash
for R in 50 100 200 400 800 1600 3200; do
  wrk2 -t4 -c256 -d60s -R$R --latency -s perf/wrk/me.lua http://localhost:8080/me > $OUT/wrk2-me-$R.txt
done
grep -H -E '99.000%|Requests/sec' $OUT/wrk2-me-*.txt
```
`me.lua`: `wrk.headers["Authorization"]="Bearer "..os.getenv("TOKEN")`.

### 8.3 vegeta (precise rate, HDR output)
```bash
echo "POST http://localhost:8080/login
Content-Type: application/json
@perf/login.json" | vegeta attack -rate=100/s -duration=120s | tee $OUT/login.bin | vegeta report -type=hdrplot > $OUT/hdr.hgrm
vegeta report -type=json $OUT/login.bin > $OUT/vegeta.json
```

### 8.4 Existing harness (closed model)
```bash
for c in 1 4 16 64 128; do go run ./test/stress -scenario login -concurrency $c -duration 60s -warmup 10s > $OUT/stress-login-c$c.txt; done
go run ./test/stress -scenario mixed -concurrency 200 -duration 120s -sla-p95 50ms -sla-p99 200ms
```

### 8.5 summarize.py (k6 summary → summary.json line)
```python
import json,sys,time
s=json.load(open(sys.argv[1])); m=s['metrics']; d=m['http_req_duration']
rec={"project":"auth","scenario":sys.argv[2],"git":sys.argv[3],"ts":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
 "throughput_rps":m['http_reqs']['rate'],"error_rate":m['http_req_failed']['value'],
 "latency_ms":{k.replace('p(','p').replace(')','').replace('.',''):v for k,v in d.items() if k.startswith('p(') or k in('med','max')}}
open(sys.argv[4],'a').write(json.dumps(rec)+'\n'); print(json.dumps(rec,indent=1))
```

## 9. Scalability analysis method

1. For PERF-SCALE-01/02 record throughput X(N) for N ∈ {1,2,4,8}.
2. Fit Universal Scalability Law `X(N) = λN / (1 + σ(N−1) + κN(N−1))` (e.g., `scipy.optimize.curve_fit`). Report σ (contention: expected from pg row locks on refresh, Redis single thread) and κ (coherency). κ > 0.01 ⇒ investigate shared state.
3. Little's law sanity: `concurrency_in_system = throughput × mean_latency`; mismatch with generator's VU count ⇒ client-side queueing (coordinated omission).
4. Login capacity planning: `max_login_rps ≈ cores_effective / t_hash`; memory headroom: `max_concurrent_hashes ≤ (mem_limit − baseline_rss) / 64 MiB`.

## 10. Regression gating (CI)

| Gate | Source | Rule |
|---|---|---|
| Micro | benchstat | sec/op +10% (p<0.05) or allocs/op increase ⇒ fail |
| Macro smoke | k6 thresholds (§8.1) at 30% knee for 2 min | any threshold breach ⇒ fail |
| Memory | soak 1 h | heap slope > 5 MiB/h ⇒ fail |
| DB | pg_stat_statements | calls/request for `/me`(session) > 4 or new seq scans on hot tables ⇒ fail |

## 11. Report template (`REPORT.md` per run)
```
Run: <date> git <sha>  host <cpu/cores/ram>  config <GOMAXPROCS/GOGC/GOMEMLIMIT/pool>
| Scenario | Load | rps | err% | p50 | p95 | p99 | p99.9 | CPU cores | RSS peak | verdict |
Knee points: login=<rps>@p99<..>, me=<rps>, refresh=<rps>
Top-5 CPU frames (cpu.top.txt) / Top-5 alloc sites / Top-5 SQL by total time
USL: σ=…, κ=…, predicted peak N=…
Regressions vs baseline <sha>: …
Findings / tickets: …
```

## 12. Performance risks identified from source (to confirm with the scenarios above)
| # | Risk | Evidence | Scenario |
|---|---|---|---|
| R1 | Unbounded concurrent argon2id (64 MiB each) ⇒ OOM / CPU starvation; no rate limit/lockout | [src] params + no limiter | PERF-LOGIN-02, STRESS-02 |
| R2 | Login GC churn inflates p99 of every other route on the same process | 64 MiB allocs/op | PERF-MIX-01, GC-01 |
| R3 | Session auth = 4 sequential DB reads per request | [src] stress harness comment | PERF-ME-SESS-01 |
| R4 | Refresh rotation contention on same family | transactional rotate | PERF-REFRESH-02 |
| R5 | Redis memory growth from 7-day refresh/session TTLs | TTLs [src] | PERF-SOAK-01 |
| R6 | Timing difference unknown-email vs wrong-password (enumeration) | needs measurement | PERF-LOGIN-03/04 |
| R7 | No pprof in binary — profiling requires a tagged build | [src] | §7.1 |
