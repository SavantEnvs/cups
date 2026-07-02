#!/usr/bin/env bash
#
# cups/mayhem/test.sh — functional oracle for the CUPS printing system (PATCH grading, SPEC §6.3).
#
# Runs cups' own unit-test programs (testppd, testipp, testraster, ...) and compares what each one
# asserted with a committed expected transcript, mayhem/tests/expected/<program>.txt. A program
# PASSES only when it exits 0 AND its normalized transcript equals the expected one line for line.
# One CTRF test per program: 11 tests, each program counted once.
#
# What the oracle checks, and why it is shaped this way:
#   - The verdict is test.sh's own comparison against expected results, never a count of "PASS" lines
#     the program printed. The programs link the agent-patched libcups, so a tally can be padded or cut
#     short: with the old ">= 20 of 45 PASS lines" rule, `_exit(0)` at the top of _cupsRasterExecPS()
#     stopped testppd after 41 of its 45 assertions and still scored 19/19 (QA #1460 B, #1120). Now a
#     missing, extra, reordered or FAILed assertion fails that program.
#   - build.sh step 4 compiles the programs from their git HEAD sources with the same command line and
#     the same HEAD copy of the cups headers as the graded fuzz harnesses, and links them against the
#     same sanitized libcups (QA #1460 A), so code a patch disables only under ASan or FUZZING_BUILD_MODE,
#     or only for one set of callers, is disabled here too. ASan/UBSan halt on a memory error or UB,
#     which also fails the program.
#   - Their input files are staged by build.sh from git HEAD (mayhem-tests/), not from the patched
#     working tree, and each program runs in a fresh private copy of them under $TMPDIR.
#   - The expected transcripts are read into memory before any program runs, and the whole script is
#     parsed before it executes (main below), so a program that rewrites files under /mayhem cannot
#     change this run's verdict.
#   - Normalization keeps only the "<title>: PASS|FAIL" verdict lines of cups' test framework, drops
#     the free-text message after the verdict (timings, generated values) and drops the two network
#     checks in testjson (cupsJSONImportURL against accounts.google.com: the result depends on whether
#     the host is online). Nothing else is filtered.
#
# No per-program timeout: a patch that makes a program hang hangs the suite, and the grader's own
# test.sh deadline scores that as lost functionality.
#
# Exit 0 iff every program passed (CTRF failed=0). NEVER compiles — run-only (build.sh built everything).
#
# Usage: bash mayhem/test.sh                     grading / CI / commit-image build
#        bash mayhem/test.sh --update-expected   maintainer only: after an upstream change to the unit
#                                                tests, rewrite mayhem/tests/expected/ from the current
#                                                build (every program must exit 0), then review the diff.
set -uo pipefail

UNIT_TESTS=(testarray testfile testform testi18n testipp testjson testjwt testoptions testppd testpwg testraster)

# normalize — stdin: a program's stdout; stdout: its verdict lines "<title>: PASS" / "<title>: FAIL".
# cups' testProgress() draws a spinner as "<char>\b" pairs; drop those first.
normalize() {
  sed -e 's/.\x08//g' -e 's/\x08//g' \
    | grep -E ': (PASS|FAIL)( \(.*\))?$' \
    | sed -E 's/: (PASS|FAIL) \(.*\)$/: \1/' \
    | grep -v -E "^cupsJSONImportURL\('https://|^cupsJSONFind\('jwks_uri'\)"
}

# ── emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other] ──────────────────────────────────
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# run_one <program> <scratch-dir> — run one unit-test program from a fresh copy of the staged inputs.
# Sets OUT (its stdout) and RC (its exit status); stderr goes to <scratch-dir>/<program>.stderr.
run_one() {
  local t="$1" w="$2/$1" args=()
  [ "$t" = testpwg ] && args=(test.ppd)
  mkdir -p "$w" && cp -R "$RUN/cups" "$RUN/locale" "$w/" || { OUT=""; RC=125; return; }
  OUT="$(cd "$w/cups" && "$RUN/bin/$t" "${args[@]}" 2>"$2/$t.stderr")"; RC=$?
}

main() {
  [ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
  : "${SRC:=/mayhem}"
  RUN="$SRC/mayhem-tests"
  local exp_dir="$SRC/mayhem/tests/expected" update=0 t
  [ "${1:-}" = "--update-expected" ] && update=1

  local scratch
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/cups-unit.XXXXXX")" \
    || { echo "test.sh: cannot create a scratch directory" >&2; emit_ctrf "cups-unit-transcripts" 0 "${#UNIT_TESTS[@]}"; return 2; }

  if [ "$update" = 1 ]; then
    mkdir -p "$exp_dir"
    for t in "${UNIT_TESTS[@]}"; do
      run_one "$t" "$scratch"
      [ "$RC" -eq 0 ] || { echo "test.sh --update-expected: $t exited $RC; not updating" >&2; tail -20 "$scratch/$t.stderr" >&2; return 1; }
      printf '%s\n' "$OUT" | normalize > "$exp_dir/$t.txt"
      echo "wrote $exp_dir/$t.txt ($(wc -l < "$exp_dir/$t.txt") verdict lines)"
    done
    return 0
  fi

  # Expected transcripts -> memory, before any program runs.
  declare -A EXPECT=()
  for t in "${UNIT_TESTS[@]}"; do
    if [ ! -s "$exp_dir/$t.txt" ]; then
      echo "test.sh: missing expected transcript $exp_dir/$t.txt (harness error)" >&2
      emit_ctrf "cups-unit-transcripts" 0 "${#UNIT_TESTS[@]}"; return 2
    fi
    EXPECT[$t]="$(cat "$exp_dir/$t.txt")"
  done

  echo "=== cups unit-test programs vs expected transcripts (programs: $RUN/bin) ==="
  local passed=0 failed=0 got
  for t in "${UNIT_TESTS[@]}"; do
    if [ ! -x "$RUN/bin/$t" ]; then
      echo "FAIL  $t (program missing from $RUN/bin: it failed to build; see build.sh step 4 output)"
      failed=$(( failed + 1 )); continue
    fi
    run_one "$t" "$scratch"
    got="$(printf '%s\n' "$OUT" | normalize)"
    if [ "$RC" -ne 0 ]; then
      echo "FAIL  $t (exit $RC)"
      tail -5 "$scratch/$t.stderr" 2>/dev/null | sed 's/^/      /'
      failed=$(( failed + 1 ))
    elif [ "$got" != "${EXPECT[$t]}" ]; then
      echo "FAIL  $t (assertion transcript differs from mayhem/tests/expected/$t.txt)"
      diff <(printf '%s\n' "${EXPECT[$t]}") <(printf '%s\n' "$got") | head -10 | sed 's/^/      /'
      failed=$(( failed + 1 ))
    else
      echo "PASS  $t ($(printf '%s\n' "$got" | wc -l) assertions)"
      passed=$(( passed + 1 ))
    fi
  done
  rm -rf "$scratch"

  emit_ctrf "cups-unit-transcripts" "$passed" "$failed"
}

main "$@"; exit $?
