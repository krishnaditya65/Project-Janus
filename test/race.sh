#!/usr/bin/env bash
# Run all Go tests with the race detector. Catches data races in any
# concurrently-tested code path (middleware, repository pool, JWT signing).
#
# Race-detected binaries are ~10x slower and ~2x memory; we run the whole
# repo, both unit and integration suites, then exit non-zero on any race.
set -e

echo ">>> go test -race ./..."
go test -race -count=1 ./internal/... ./test/integration/...
echo ""
echo ">>> No data races detected."
