#!/usr/bin/env bash
# Smoke test: quick sanity check that every endpoint is reachable and behaves at the right HTTP level.
# Does NOT cover edge cases (those live in integration tests). Goal: prove the server is alive and wired.
#
# Usage:  ./smoke.sh [base-url]
# Exits 0 if all pass, 1 otherwise.

set -u
BASE="${1:-http://localhost:8080}"

PASS=0
FAIL=0
FAIL_NAMES=()

c_g="\033[32m"; c_r="\033[31m"; c_y="\033[33m"; c_n="\033[0m"

# expect <name> <expected-status> <actual-status>
expect() {
    local name="$1" want="$2" got="$3"
    if [[ "$got" == "$want" ]]; then
        echo -e "${c_g}PASS${c_n} ${name}  (HTTP ${got})"
        PASS=$((PASS+1))
    else
        echo -e "${c_r}FAIL${c_n} ${name}  expected ${want}, got ${got}"
        FAIL=$((FAIL+1))
        FAIL_NAMES+=("$name")
    fi
}

# unique identifier per run
SUFFIX="$(date +%s)$$"
EMAIL="smoke-${SUFFIX}@test.local"
PASSWORD="smoke-password-${SUFFIX}"

echo "Base URL: ${BASE}"
echo "Test user: ${EMAIL}"
echo "================================================="

# 1. Liveness
S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/health")
expect "health"                              "200" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/.well-known/jwks.json")
expect "jwks discovery"                      "200" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/.well-known/openid-configuration")
expect "oidc discovery"                      "200" "$S"

# 2. Register
S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"tenant_name\":\"Smoke ${SUFFIX}\"}")
expect "register new user"                   "201" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"tenant_name\":\"dup\"}")
expect "register duplicate email"            "409" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"bad-email\",\"password\":\"${PASSWORD}\",\"tenant_name\":\"x\"}")
expect "register invalid email"              "400" "$S"

# 3. Login
LOGIN_BODY=$(curl -s -X POST "${BASE}/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")
ACCESS_TOKEN=$(echo "$LOGIN_BODY" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
REFRESH_TOKEN=$(echo "$LOGIN_BODY" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
SESSION_ID=$(echo "$LOGIN_BODY" | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)

if [[ -n "$ACCESS_TOKEN" && -n "$REFRESH_TOKEN" && -n "$SESSION_ID" ]]; then
    expect "login returns jwt + session + refresh" "200" "200"
else
    expect "login returns jwt + session + refresh" "tokens" "missing"
fi

S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"WRONG\"}")
expect "login wrong password"                "401" "$S"

# 4. Authenticated routes via Bearer JWT
S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/me" -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/me via bearer jwt"                  "200" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/me" -H "X-Session-ID: ${SESSION_ID}")
expect "/me via session id"                  "200" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/me")
expect "/me no auth"                         "401" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/users" -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/users via bearer"                   "200" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/roles" -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/roles via bearer"                   "200" "$S"

# 5. UserInfo
S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/oauth/userinfo" -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/oauth/userinfo via bearer"          "200" "$S"

# 6. Refresh via cookie
S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/refresh" \
    -H "Cookie: refresh_token=${REFRESH_TOKEN}")
expect "/refresh via cookie"                 "200" "$S"

# Old refresh token now revoked
S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/refresh" \
    -H "Cookie: refresh_token=${REFRESH_TOKEN}")
expect "/refresh reuse old token rejected"   "401" "$S"

# 7. MFA endpoints reachable
S=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/mfa/factors" -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/mfa/factors"                        "200" "$S"

# 8. WebAuthn challenge endpoints reachable
S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/webauthn/register/begin" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/webauthn/register/begin"            "200" "$S"

S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/webauthn/login/begin")
expect "/webauthn/login/begin (public)"      "200" "$S"

# 9. CORS preflight
S=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS "${BASE}/login" \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: POST")
expect "CORS preflight"                      "204" "$S"

# 10. Logout
S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/logout" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")
expect "/logout"                             "204" "$S"

echo "================================================="
echo -e "Passed: ${c_g}${PASS}${c_n}    Failed: ${c_r}${FAIL}${c_n}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "${c_y}Failing tests:${c_n}"
    for name in "${FAIL_NAMES[@]}"; do echo "  - $name"; done
    exit 1
fi
exit 0
