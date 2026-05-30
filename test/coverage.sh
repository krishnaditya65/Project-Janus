#!/usr/bin/env bash
# Coverage report for unit tests (in-process).
#
# Integration / smoke / security tests exercise the running server over HTTP
# and therefore don't contribute to in-process counters. To measure them you
# need to build `iam-server` with `go build -cover` and add a graceful SIGTERM
# handler that lets the runtime flush counters on shutdown (tracked for v0.8.0).
#
# Output:  coverage/coverage.out  +  coverage/coverage.html
set -e

OUT="coverage"
mkdir -p "$OUT"

echo ">>> Running unit tests with -coverpkg=./internal/..."
go test -count=1 \
    -coverprofile="$OUT/coverage.out" \
    -covermode=atomic \
    -coverpkg=./internal/... \
    ./internal/...

echo ""
echo ">>> Per-file coverage (top of list):"
go tool cover -func="$OUT/coverage.out" | head -20

TOTAL=$(go tool cover -func="$OUT/coverage.out" | tail -1 | awk '{print $3}')
echo ""
echo ">>> TOTAL unit coverage of internal/: $TOTAL"
echo ">>> (Integration / smoke / security suites are validated independently and"
echo "    do not contribute to in-process coverage counters by design.)"

go tool cover -html="$OUT/coverage.out" -o "$OUT/coverage.html"
echo ">>> HTML report: $OUT/coverage.html"
