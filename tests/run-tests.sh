#!/usr/bin/env bash
# run-tests.sh — Test runner for skillvet
# Usage: bash tests/run-tests.sh
# Returns: 0 = all pass, 1 = failures

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT="$PROJECT_DIR/scripts/skill-audit.sh"
FIXTURES="$SCRIPT_DIR/fixtures"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASSED=0
FAILED=0
TOTAL=0

run_test() {
  local name="$1"
  local fixture="$2"
  local expected_exit="$3"
  local expect_pattern="${4:-}"
  local reject_pattern="${5:-}"

  TOTAL=$((TOTAL + 1))

  output=$(bash "$AUDIT" --json "$fixture" 2>&1)
  actual_exit=$?

  local fail_reason=""

  if [ "$actual_exit" -ne "$expected_exit" ]; then
    fail_reason="exit code: expected $expected_exit, got $actual_exit"
  fi

  if [ -n "$expect_pattern" ] && ! echo "$output" | grep -qiE "$expect_pattern"; then
    fail_reason="${fail_reason:+$fail_reason; }expected pattern not found: $expect_pattern"
  fi

  if [ -n "$reject_pattern" ] && echo "$output" | grep -qiE "$reject_pattern"; then
    fail_reason="${fail_reason:+$fail_reason; }rejected pattern was found: $reject_pattern"
  fi

  if [ -z "$fail_reason" ]; then
    printf "${GREEN}PASS${NC} %s\n" "$name"
    PASSED=$((PASSED + 1))
  else
    printf "${RED}FAIL${NC} %s — %s\n" "$name" "$fail_reason"
    FAILED=$((FAILED + 1))
  fi
}

echo "Running skillvet tests..."
echo "---"

# Clean skill — should pass with no findings
run_test "clean-skill (exit 0)" \
  "$FIXTURES/clean-skill" 0 \
  '"critical":0' \
  ""

# Check #22 — string construction evasion
run_test "trigger-string-evasion (exit 2, check #22)" \
  "$FIXTURES/trigger-string-evasion" 2 \
  "string construction evasion" \
  ""

# Check #23 — data flow chain analysis
run_test "trigger-chain-analysis (exit 2, check #23)" \
  "$FIXTURES/trigger-chain-analysis" 2 \
  "data flow chain" \
  ""

# Check #24 — time bomb detection
run_test "trigger-time-bomb (exit 2, check #24)" \
  "$FIXTURES/trigger-time-bomb" 2 \
  "time bomb" \
  ""

# Check #7 — reverse shell
run_test "trigger-reverse-shell (exit 2, check #7)" \
  "$FIXTURES/trigger-reverse-shell" 2 \
  "reverse.*shell" \
  ""

# Check #9 — prompt injection
run_test "trigger-prompt-injection (exit 2, check #9)" \
  "$FIXTURES/trigger-prompt-injection" 2 \
  "prompt injection" \
  ""

# Check #2 — env theft
run_test "trigger-env-theft (exit 2, check #2)" \
  "$FIXTURES/trigger-env-theft" 2 \
  "env harvesting" \
  ""

# Check #4 — obfuscation
run_test "trigger-obfuscation (exit 2, check #4)" \
  "$FIXTURES/trigger-obfuscation" 2 \
  "obfuscation" \
  ""

# Check #1 — exfil endpoint
run_test "trigger-exfil-endpoint (exit 2, check #1)" \
  "$FIXTURES/trigger-exfil-endpoint" 2 \
  "exfiltration endpoint" \
  ""

# Check #3 — credential access
run_test "trigger-credential-access (exit 2, check #3)" \
  "$FIXTURES/trigger-credential-access" 2 \
  "foreign credentials" \
  ""

# False positive — educational prompt injection context
run_test "false-positive-prompt-injection (exit 0)" \
  "$FIXTURES/false-positive-prompt-injection" 0 \
  '"critical":0' \
  ""

# False positive — own declared keys
run_test "false-positive-own-keys (exit 0)" \
  "$FIXTURES/false-positive-own-keys" 0 \
  '"critical":0' \
  ""

echo "---"
printf "Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC}, %d total\n" "$PASSED" "$FAILED" "$TOTAL"

if [ $FAILED -gt 0 ]; then
  exit 1
fi
exit 0
