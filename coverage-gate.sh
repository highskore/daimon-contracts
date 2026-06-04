#!/usr/bin/env bash
#
# Coverage gate (#119). `forge` has no native --fail-under, so we run the summary report and fail if ANY metric
# on the Total row drops below the floor. Order-independent: it checks every percentage on that row, so it does
# not matter which column is lines/statements/branches/funcs. The floor is a no-regression ratchet set below the
# current minimum metric — raise it as coverage is backfilled toward ~100%. Override with COVERAGE_FLOOR.
#
set -uo pipefail

FLOOR=${COVERAGE_FLOOR:-88}

SUMMARY=$(forge coverage --no-match-coverage '(^|/)(test|script)/' --report summary) || {
  echo "coverage-gate: forge coverage failed" >&2
  exit 1
}
echo "$SUMMARY"

# Anchor to the aggregate summary row ("| Total ...") so a source file whose name contains "Total" cannot match.
echo "$SUMMARY" | awk -v floor="$FLOOR" '
  /^\| *Total / {
    n = 0
    line = $0
    while (match(line, /[0-9]+\.[0-9]+%/)) {
      pcts[n++] = substr(line, RSTART, RLENGTH - 1) + 0
      line = substr(line, RSTART + RLENGTH)
    }
  }
  END {
    if (n == 0) { print "coverage-gate: no Total row found"; exit 1 }
    fail = 0
    for (i = 0; i < n; i++)
      if (pcts[i] < floor) { printf "coverage-gate: %.2f%% < %d%% floor\n", pcts[i], floor; fail = 1 }
    if (fail) { print "coverage-gate: FAIL"; exit 1 }
    printf "coverage-gate: PASS (all %d Total metrics >= %d%%)\n", n, floor
  }'
