#!/usr/bin/env bash
set -euo pipefail

SHARD_INDEX="${1:-1}"
SHARD_TOTAL="${2:-1}"

TESTS=$(go test -list '.*' ./tests/integration | grep "^Test")
SHARD_TESTS=$(echo "$TESTS" | awk -v total="$SHARD_TOTAL" -v idx="$SHARD_INDEX" 'NR % total == (idx - 1)')

if [ -z "$SHARD_TESTS" ]; then
  echo "No tests found for shard $SHARD_INDEX of $SHARD_TOTAL"
  exit 0
fi

COUNT=$(echo "$SHARD_TESTS" | wc -l | tr -d ' ')
echo "=== Running integration test shard $SHARD_INDEX of $SHARD_TOTAL ($COUNT tests) ==="

PATTERN=$(echo "$SHARD_TESTS" | paste -sd '|' -)

exec go test -race -timeout 15m ./tests/integration -run "^($PATTERN)$"
