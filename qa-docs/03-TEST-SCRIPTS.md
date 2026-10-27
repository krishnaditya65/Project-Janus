# custom-auth-server — Test Scripts (reference implementations, NOT executed)

JSON field names (`email`, `password`, `access_token`, `refresh_token`, `tenant`) are assumptions — confirm in `auth-server/internal/*/transport` and `test/integration/client.go` and adjust `lib.sh` only. Requires: bash, curl, jq, docker, k6, go, redis-cli, psql, openssl.

## lib.sh
```bash
#!/usr/bin/env bash
set -euo pipefail
IAM=${IAM:-http://localhost:8080}; IDS=${IDS:-http://localhost:8081}; MFA=${MFA:-http://localhost:8082}
PG=${PG:-postgres://postgres:postgres@localhost:5433/iam?sslmode=disable}; REDIS_PORT=${REDIS_PORT:-6380}
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "PASS $1"; }; ko(){ FAIL=$((FAIL+1)); echo "FAIL $1 :: $2"; }
# code METHOD URL [json] [bearer] -> prints status, body in /tmp/b
code(){ curl -s -o /tmp/b -w '%{http_code}' -X "$1" "$2" -H 'Content-Type: application/json' ${4:+-H "Authorization: Bearer $4"} ${3:+-d "$3"}; }
expect(){ local id=$1 want=$2; shift 2; local got; got=$(code "$@"); [[ "$got" == "$want" ]] && ok "$id" || ko "$id" "want $want got $got $(head -c200 /tmp/b)"; }
rnd(){ openssl rand -hex 6; }
reg(){ code POST $IAM/register "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null; }
login(){ code POST $IAM/login "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null; AT=$(jq -r .access_token /tmp/b); RT=$(jq -r .refresh_token /tmp/b); }
summary(){ echo "pass=$PASS fail=$FAIL"; [[ $FAIL == 0 ]]; }
```

## smoke.sh (SMK-001..005)
```bash
. ./lib.sh
for u in $IAM $IDS $MFA; do expect SMK-001:$u 200 GET $u/health; done
expect SMK-002 200 GET $IAM/.well-known/openid-configuration
J=$(jq -r .jwks_uri /tmp/b); [[ $(curl -s "$J" | jq '.keys|length') -ge 1 ]] && ok SMK-003 || ko SMK-003 nokeys
E="smk-$(rnd)@t.io"; P='Sm0ke!Passw0rd#1'
expect SMK-004a 201 POST $IAM/register "{\"email\":\"$E\",\"password\":\"$P\"}"
login "$E" "$P"; expect SMK-004b 200 GET $IAM/me "" "$AT"
expect SMK-004c 200 POST $IAM/logout "" "$AT"; expect SMK-004d 401 GET $IAM/me "" "$AT"
curl -s $IAM/metrics | grep -q '^# TYPE' && ok SMK-005 || ko SMK-005 nometrics
summary
```

## negative_boundary.sh (NEG/BND)
```bash
. ./lib.sh
E="n-$(rnd)@t.io"; P='Neg!Passw0rd#12'; reg "$E" "$P"
expect NEG-001 409 POST $IAM/register "{\"email\":\"$E\",\"password\":\"$P\"}"
expect NEG-002a 401 POST $IAM/login "{\"email\":\"$E\",\"password\":\"bad\"}"; A=$(cat /tmp/b)
expect NEG-002b 401 POST $IAM/login "{\"email\":\"nouser-$(rnd)@t.io\",\"password\":\"bad\"}"
[[ "$A" == "$(cat /tmp/b)" ]] && ok NEG-002-enum || ko NEG-002-enum "bodies differ"
for body in '{' '' '[]' '{"email":1}' 'null' '{"email":"a@b.c","password":"x"}trailing'; do expect "NEG-003:${body:0:8}" 400 POST $IAM/login "$body"; done
none=$(printf '%s.%s.' "$(printf '{"alg":"none"}'|base64|tr -d '=\n')" "$(printf '{"sub":"x"}'|base64|tr -d '=\n')")
for t in garbage "$none" "a.b.c" ""; do expect "NEG-004:${t:0:6}" 401 GET $IAM/me "" "$t"; done
# AUTH-REG-018: hashing is argon2id [src] (no 72-byte bcrypt truncation) — check NUL/prefix truncation instead
E2="b-$(rnd)@t.io"; reg "$E2" 'Aa1!aaaa\u0000SUFFIX'
expect AUTH-REG-018-prefix 401 POST $IAM/login "{\"email\":\"$E2\",\"password\":\"Aa1!aaaa\"}"
B72=$(head -c 72 /dev/zero | tr '\0' 'a'); E3="c-$(rnd)@t.io"; reg "$E3" "A1!${B72}X"
expect AUTH-REG-long-distinct 401 POST $IAM/login "{\"email\":\"$E3\",\"password\":\"A1!${B72}Y\"}"
# AUTH-INT-004/005/006: internal routes have NO auth middleware [src] — must be unreachable from the public network
for u in "$IDS/internal/identities/by-email?email=$E2" "$MFA/internal/mfa/factors/by-identity?identity_id=x"; do
  c=$(curl -s -o /dev/null -w '%{http_code}' "$u"); [[ $c == 401 || $c == 403 || $c == 000 ]] && ok "AUTH-INT-004 $u" || ko "AUTH-INT-004 $u" "internal endpoint answered $c without credentials (run this from OUTSIDE the private network)"; done
BIG=$(head -c 1048576 /dev/zero | tr '\0' 'a'); echo "{\"email\":\"x@t.io\",\"password\":\"$BIG\"}" >/tmp/big
c=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST $IAM/register -H 'Content-Type: application/json' --data-binary @/tmp/big); [[ $c =~ ^4 ]] && ok BND-003 || ko BND-003 $c
for id in not-a-uuid 00000000-0000-0000-0000-000000000000 "1%27%20OR%201=1--" ../../etc; do c=$(code GET "$IAM/users/$id" "" "$AT"); [[ $c =~ ^4 ]] && ok "BND-005:$id" || ko "BND-005:$id" $c; done
# SEC-012 mass assignment
E3="m-$(rnd)@t.io"; code POST $IAM/register "{\"email\":\"$E3\",\"password\":\"$P\",\"role\":\"admin\",\"is_admin\":true,\"tenant_id\":\"other\"}" >/dev/null
login "$E3" "$P"; expect SEC-012 403 POST $IAM/roles '{"name":"x"}' "$AT"
summary
```

## oauth_pkce.sh (FUN-005, NEG-007..009) — needs `CLIENT_ID`, `REDIRECT` of a seeded client and a session cookie/bearer `$AT`
```bash
. ./lib.sh
V=$(openssl rand -base64 60 | tr -d '=+/\n' | cut -c1-64); C=$(printf %s "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
auth(){ curl -s -o /dev/null -D - -H "Authorization: Bearer $AT" "$IAM/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$1&scope=openid&state=st1&nonce=n1&code_challenge=$C&code_challenge_method=S256"; }
LOC=$(auth "$REDIRECT" | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r'); CODE=$(sed -E 's/.*code=([^&]+).*/\1/' <<<"$LOC")
grep -q 'state=st1' <<<"$LOC" && ok FUN-005-state || ko FUN-005-state "$LOC"
tok(){ curl -s -o /tmp/b -w '%{http_code}' -X POST $IAM/oauth/token -d grant_type=authorization_code -d client_id=$CLIENT_ID -d redirect_uri="$REDIRECT" -d code="$1" -d code_verifier="$2"; }
[[ $(tok "$CODE" wrongverifier0000000000000000000000000000000000) == 400 ]] && ok NEG-008 || ko NEG-008 "$(cat /tmp/b)"
LOC=$(auth "$REDIRECT" | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r'); CODE=$(sed -E 's/.*code=([^&]+).*/\1/' <<<"$LOC")
[[ $(tok "$CODE" "$V") == 200 ]] && ok FUN-005 || ko FUN-005 "$(cat /tmp/b)"
[[ $(tok "$CODE" "$V") == 400 ]] && ok NEG-009-reuse || ko NEG-009-reuse "code reusable!"
for bad in "$REDIRECT/" "${REDIRECT}?x=1" "https://evil.example/cb" "${REDIRECT}%23frag" "$(tr a-z A-Z <<<"$REDIRECT")"; do
  auth "$bad" | grep -qi "^location: *$bad" && ko "NEG-007:$bad" "redirected to unregistered uri" || ok "NEG-007:$bad"; done
summary
```

## race.sh (RACE-001, 003, 009)
```bash
. ./lib.sh
E="r-$(rnd)@t.io"; P='Race!Passw0rd#1'; reg "$E" "$P"; login "$E" "$P"
seq 50 | xargs -P50 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST $IAM/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT\"}" | sort | uniq -c | tee /tmp/r
n=$(awk '$2==200{print $1}' /tmp/r); [[ ${n:-0} -le 1 ]] && ok RACE-001 || ko RACE-001 "$n successes"
D="dup-$(rnd)@t.io"
seq 50 | xargs -P50 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST $IAM/register -H 'Content-Type: application/json' -d "{\"email\":\"$D\",\"password\":\"$P\"}" | sort | uniq -c | tee /tmp/r
[[ $(awk '$2==201{print $1}' /tmp/r) == 1 && -z $(awk '$2>=500' /tmp/r) ]] && ok RACE-003 || ko RACE-003 "$(cat /tmp/r)"
[[ $(psql "$PG" -Atc "select count(*) from identities where email='$D'") == 1 ]] && ok RACE-003-db || ko RACE-003-db rows   # table name: verify in migrations
seq 100 | xargs -P100 -I{} curl -s -o /dev/null -X POST $IAM/login -H 'Content-Type: application/json' -d "{\"email\":\"$E\",\"password\":\"bad\"}"
expect AUTH-LGN-014-lockout 429 POST $IAM/login "{\"email\":\"$E\",\"password\":\"$P\"}"   # EXPECTED TO FAIL today: no lockout/rate-limit code exists [src] — file as P1 finding
# MFA lives on mfa-service :8082 [src]: enroll -> verify -> login(mfa_required) -> /mfa/complete
login "$E" "$P"; code POST $MFA/mfa/enroll/totp '{"label":"qa"}' "$AT" >/dev/null; FID=$(jq -r .factor_id /tmp/b); SECRET=$(jq -r '.secret // empty' /tmp/b)
[[ -n $SECRET ]] && TOTP=$(oathtool --totp -b "$SECRET") && expect AUTH-MFA-003 200 POST $MFA/mfa/enroll/verify "{\"factor_id\":\"$FID\",\"code\":\"$TOTP\"}" "$AT"
code POST $IAM/login "{\"email\":\"$E\",\"password\":\"$P\"}" >/dev/null; MT=$(jq -r '.mfa_token // empty' /tmp/b)
[[ -n $MT && $(jq -r '.access_token // empty' /tmp/b) == "" ]] && ok AUTH-LGN-011 || ko AUTH-LGN-011 "tokens issued before MFA: $(head -c 200 /tmp/b)"
seq 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST $MFA/mfa/complete -H 'Content-Type: application/json' -d "{\"mfa_token\":\"$MT\",\"code\":\"$(oathtool --totp -b "$SECRET")\"}" | sort | uniq -c > /tmp/r
[[ $(awk '$2==200{print $1}' /tmp/r) == 1 ]] && ok AUTH-MFA-014 || ko AUTH-MFA-014 "$(cat /tmp/r | tr '\n' ' ')"
(cd ../auth-server && go test -race -count=1 ./...) && ok RACE-010 || ko RACE-010 "data race"
summary
```

## load.k6.js (LOAD-001..005, SPK-001, SOAK-001 via `-e PROFILE=`)
```js
import http from 'k6/http'; import { check, sleep } from 'k6'; import { SharedArray } from 'k6/data';
const IAM = __ENV.IAM || 'http://localhost:8080', H = { headers: { 'Content-Type': 'application/json' } };
const profiles = {
  load:  [{ duration: '2m', target: 100 }, { duration: '6m', target: 500 }, { duration: '2m', target: 0 }],
  stress:[{ duration: '2m', target: 500 }, { duration: '5m', target: 2000 }, { duration: '5m', target: 5000 }, { duration: '2m', target: 0 }],
  spike: [{ duration: '1s', target: 2000 }, { duration: '60s', target: 2000 }, { duration: '10s', target: 0 }, { duration: '60s', target: 0 }, { duration: '1s', target: 2000 }, { duration: '60s', target: 2000 }],
  soak:  [{ duration: '5m', target: 150 }, { duration: '8h', target: 150 }, { duration: '5m', target: 0 }],
};
export const options = { stages: profiles[__ENV.PROFILE || 'load'],
  thresholds: { http_req_failed: ['rate<0.001'], 'http_req_duration{op:login}': ['p(99)<500'], 'http_req_duration{op:me}': ['p(99)<50'], 'http_req_duration{op:refresh}': ['p(99)<150'] } };
const users = new SharedArray('u', () => Array.from({ length: 2000 }, (_, i) => ({ email: `load${i}@t.io`, password: 'L0ad!Passw0rd#1' })));
export function setup() { users.forEach(u => http.post(`${IAM}/register`, JSON.stringify(u), H)); }
export default function () {
  const u = users[Math.floor(Math.random() * users.length)], r = Math.random();
  const l = http.post(`${IAM}/login`, JSON.stringify(u), { ...H, tags: { op: 'login' } });
  if (!check(l, { 'login 200': x => x.status === 200 })) return;
  let at = l.json('access_token'), rt = l.json('refresh_token');
  for (let i = 0; i < 6; i++) { check(http.get(`${IAM}/me`, { headers: { Authorization: `Bearer ${at}` }, tags: { op: 'me' } }), { 'me 200': x => x.status === 200 }); }
  if (r < 0.5) { const f = http.post(`${IAM}/refresh`, JSON.stringify({ refresh_token: rt }), { ...H, tags: { op: 'refresh' } });
    check(f, { 'refresh 200': x => x.status === 200 });
    check(http.post(`${IAM}/refresh`, JSON.stringify({ refresh_token: rt }), H), { 'old refresh rejected': x => x.status >= 400 }); }
  if (r < 0.1) http.post(`${IAM}/logout`, null, { headers: { Authorization: `Bearer ${at}` } });
  sleep(0.1);
}
```
Run: `k6 run -e PROFILE=load load.k6.js`. Existing Go drivers: `go run ./test/{stress,spike,soak,abtest}`.

## chaos.sh (CHA-001,003,005,006,008,009) — run while `k6 -e PROFILE=load` is active in another shell
```bash
. ./lib.sh; cd ../auth-server
probe(){ for i in $(seq $2); do printf '%s %s\n' "$1" "$(curl -s -o /dev/null -m 3 -w '%{http_code} %{time_total}' -X POST $IAM/login -H 'Content-Type: application/json' -d '{"email":"load1@t.io","password":"L0ad!Passw0rd#1"}')"; sleep 0.5; done; }
fault(){ local id=$1 svc=$2 want=$3; echo "== $id stop $svc"; docker compose stop $svc; probe "$id-down" 10 | tee /tmp/c
  grep -vqE " ($want) " /tmp/c && ko $id "unexpected status during fault" || ok "$id-degraded"
  awk '$3>3{bad=1}END{exit bad}' /tmp/c && ok "$id-bounded-latency" || ko "$id-bounded-latency" hang
  docker compose start $svc; sleep 10; probe "$id-up" 5 | grep -q ' 200 ' && ok "$id-recovered" || ko "$id-recovered" "no auto-recovery"; }
fault CHA-001 redis '503|401'
fault CHA-003 postgres '503'
fault CHA-005 nats '200'            # async dependency must not break auth
fault CHA-006 identity-service '503'
docker compose pause postgres; probe CHA-004 6 | awk '$3>3.1{b=1}END{exit b}' && ok CHA-004 || ko CHA-004 "no deadline"; docker compose unpause postgres
# CHA-008 graceful shutdown: count 5xx/conn-reset during SIGTERM
PID=$(pgrep -f 'cmd/iam-server|iam-server$' | head -1); ( for i in $(seq 200); do curl -s -o /dev/null -w '%{http_code}\n' $IAM/health; done > /tmp/g ) & sleep 0.3; kill -TERM $PID; wait
grep -cE '^(000|5..)$' /tmp/g | { read n; echo "CHA-008 dropped=$n (only requests after listener close may be 000)"; }
# CHA-013/CON-002: event parity
B=$(curl -s localhost:8223/jsz | jq '.messages // 0'); for i in $(seq 100); do reg "ev-$(rnd)@t.io" 'Ev!Passw0rd#12'; done
echo "CON-002 events delta=$(( $(curl -s localhost:8223/jsz | jq '.messages // 0') - B )) expected>=100 (verify subject/stream)"
summary
```

## consistency_check.sh (CON-001)
```bash
. ./lib.sh
# after any load/chaos run: sessions in Redis must each map to a non-revoked refresh family (key/table names: verify)
redis-cli -p $REDIS_PORT --scan --pattern 'session:*' | wc -l
psql "$PG" -Atc "select count(*) from refresh_tokens where revoked_at is null and expires_at>now()"
psql "$PG" -Atc "select email,tenant_id,count(*) from identities group by 1,2 having count(*)>1"   # must be empty
psql "$PG" -Atc "select count(*) from refresh_tokens t where parent_id is not null and (select count(*) from refresh_tokens c where c.parent_id=t.parent_id and c.revoked_at is null)>1" # >0 => rotation race
```

## Go test skeletons to add (`auth-server/test/`)
```go
// test/fuzz/redirect_fuzz_test.go  (SEC-016)
func FuzzRedirectMatch(f *testing.F){ f.Add("https://app/cb","https://app/cb"); f.Fuzz(func(t *testing.T, reg, got string){
    if oauth.RedirectAllowed(reg, got) && reg != got { t.Fatalf("non-exact match accepted: %q vs %q", reg, got) } }) } // adapt to real fn
// test/integration/tenant_isolation_test.go  (NEG-006, SEC-013)
func TestCrossTenantIsolation(t *testing.T){ a:=newTenantAdmin(t); b:=newTenantAdmin(t); u:=a.CreateUser(t)
    for _, p := range []string{"/users/"+u.ID, "/roles", "/tenant/policy"} { if c:=b.Get(p).StatusCode; c==200 && strings.Contains(p,u.ID) { t.Fatalf("tenant B read tenant A %s", p) } } }
// test/integration/refresh_race_test.go  (RACE-001)
func TestRefreshSingleUse(t *testing.T){ s:=login(t); var ok int32; var wg sync.WaitGroup
    for i:=0;i<64;i++{ wg.Add(1); go func(){ defer wg.Done(); if refresh(s.RT).StatusCode==200 { atomic.AddInt32(&ok,1) } }() }; wg.Wait()
    if ok>1 { t.Fatalf("%d concurrent refreshes succeeded", ok) } }
```

## Run order
`smoke → negative_boundary → oauth_pkce → go test ./... -race → race → k6 load → chaos (with load) → consistency_check → k6 stress/spike → k6 soak`.
