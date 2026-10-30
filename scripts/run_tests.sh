#!/usr/bin/env bash
# Everything that runs without a GPU, a PBX or an outbound connection.
# test_docker.py additionally needs a reachable Docker daemon plus gcc; it
# skips itself with a reason when one is missing.
set -uo pipefail
cd "$(dirname "$0")/.."

failed=0
for test in tests/test_units.py tests/test_proxy.py tests/test_docker.py; do
  [[ -f "$test" ]] || continue
  echo "=============================================================="
  echo "  $test"
  echo "=============================================================="
  if timeout 900 python3 "$test"; then
    echo "-> OK"
  else
    echo "-> FAILED"
    failed=$((failed + 1))
  fi
  echo
done

if [[ $failed -gt 0 ]]; then
  echo "$failed test file(s) failed"
  exit 1
fi
echo "all test files passed"
