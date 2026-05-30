#!/usr/bin/env bash
# Master test runner.
# Layers in execution order:
#   1. Unit
#   2. Race detection
#   3. Fuzz (5s smoke per target)
#   4. Smoke (HTTP)
#   5. Integration
#   6. Security
#   7. Stress with SLA budgets
#   8. Spike
#   9. A/B
#  10. Coverage report
#
# Stops on first failing layer. Exits non-zero on any failure or SLA breach.
#
# Usage:
#   ./test/run-all.sh [base-url]
set -e

BASE="${1:-http://localhost:8080}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

heading() {
    echo ""
    echo "================================================="
    echo ">>> $1"
    echo "================================================="
}

heading "[1/10] UNIT"
go test ./internal/... -count=1

heading "[2/10] RACE DETECTION"
./test/race.sh

heading "[3/10] FUZZ (5s smoke per target)"
go test ./internal/oauth/app/      -run="^$" -fuzz=FuzzVerifyPKCE        -fuzztime=5s
go test ./internal/oauth/app/      -run="^$" -fuzz=FuzzSplitScopes       -fuzztime=5s
go test ./internal/token/app/      -run="^$" -fuzz=FuzzJWT_Verify        -fuzztime=5s
go test ./internal/token/app/      -run="^$" -fuzz=FuzzJWT_RejectsAlgNone -fuzztime=3s
go test ./internal/shared/password/ -run="^$" -fuzz=FuzzVerify_NoPanic    -fuzztime=5s

heading "[4/10] SMOKE"
./test/smoke/smoke.sh "${BASE}"

heading "[5/10] INTEGRATION"
AUTH_BASE_URL="${BASE}" go test ./test/integration/... -count=1 -v

heading "[6/10] SECURITY"
AUTH_BASE_URL="${BASE}" go test ./test/security/... -count=1 -v

heading "[7/10] STRESS w/ SLA budgets (jwt-verify, 15s)"
go run ./test/stress \
    -scenario jwt-verify -concurrency 50 -duration 15s -base "${BASE}" \
    -sla-p95 20ms -sla-p99 50ms -sla-fail-pct 1.0

heading "[8/10] SPIKE (10 -> 110 workers)"
go run ./test/spike -baseline 10 -burst 100 \
    -baseline-duration 5s -burst-duration 5s -recovery-duration 10s \
    -base "${BASE}"

heading "[9/10] A/B (20s)"
go run ./test/abtest -concurrency 50 -duration 20s -base "${BASE}"

heading "[10/10] COVERAGE"
./test/coverage.sh

echo ""
echo "================================================="
echo "  ALL LAYERS COMPLETED"
echo "================================================="
