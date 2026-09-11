#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
maintenance_script=$(dirname -- "$script_dir")/cleanup-refresh-tokens.sh
test_dir=$(mktemp -d "$script_dir/cleanup-refresh-tokens.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

assert_contains() {
  expected=$1
  output_file=$2
  if ! grep -Fq "$expected" "$output_file"; then
    echo "Expected output to contain: $expected" >&2
    sed 's/^/  /' "$output_file" >&2
    exit 1
  fi
}

run_and_capture() {
  expected_status=$1
  output_file=$2
  shift 2

  set +e
  "$@" >"$output_file" 2>&1
  actual_status=$?
  set -e

  if [ "$actual_status" -ne "$expected_status" ]; then
    echo "Expected exit status $expected_status, got $actual_status" >&2
    sed 's/^/  /' "$output_file" >&2
    exit 1
  fi
}

invalid_output="$test_dir/invalid.log"
run_and_capture 1 "$invalid_output" \
  env REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS=9999999999 \
  sh "$maintenance_script"
assert_contains "must be an integer from 60 to 999999999" "$invalid_output"

small_output="$test_dir/small.log"
run_and_capture 1 "$small_output" \
  env REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS=59 \
  sh "$maintenance_script"
assert_contains "must be at least 60" "$small_output"

failure_bin="$test_dir/failure-bin"
mkdir "$failure_bin"
cat >"$failure_bin/psql" <<'EOF'
#!/usr/bin/env sh
if [ "${PSQL_TEST_MODE:-}" = "missing-table" ]; then
  echo "f"
  exit 0
fi
echo "psql: simulated connection failure" >&2
exit 2
EOF
cat >"$failure_bin/sleep" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$1" >>"$SLEEP_LOG"
EOF
chmod +x "$failure_bin/psql" "$failure_bin/sleep"

failure_output="$test_dir/failure.log"
sleep_log="$test_dir/sleep.log"
run_and_capture 1 "$failure_output" \
  env PATH="$failure_bin:$PATH" SLEEP_LOG="$sleep_log" \
  REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS=60 \
  sh "$maintenance_script"

attempt_count=$(grep -c "\[db-maintenance\] readiness attempt" "$failure_output")
sleep_count=$(wc -l <"$sleep_log" | tr -d ' ')
if [ "$attempt_count" -ne 12 ] || [ "$sleep_count" -ne 11 ]; then
  echo "Readiness retries were not bounded as expected." >&2
  sed 's/^/  /' "$failure_output" >&2
  exit 1
fi
assert_contains "readiness attempt 12/12 failed; exiting" "$failure_output"

missing_output="$test_dir/missing-table.log"
missing_sleep_log="$test_dir/missing-table-sleep.log"
run_and_capture 1 "$missing_output" \
  env PATH="$failure_bin:$PATH" SLEEP_LOG="$missing_sleep_log" \
  PSQL_TEST_MODE=missing-table REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS=60 \
  sh "$maintenance_script"
missing_attempt_count=$(grep -c "\[db-maintenance\] readiness attempt" "$missing_output")
if [ "$missing_attempt_count" -ne 12 ]; then
  echo "A missing migration did not produce bounded readiness retries." >&2
  sed 's/^/  /' "$missing_output" >&2
  exit 1
fi
assert_contains "readiness attempt 12/12 failed; exiting" "$missing_output"

success_bin="$test_dir/success-bin"
mkdir "$success_bin"
cat >"$success_bin/psql" <<'EOF'
#!/usr/bin/env sh
for argument in "$@"; do
  case "$argument" in
    --command=*)
      echo "t"
      exit 0
      ;;
    --file=*)
      echo "DELETE 2"
      exit 0
      ;;
  esac
done
exit 2
EOF
cat >"$success_bin/sleep" <<'EOF'
#!/usr/bin/env sh
if [ "$1" = "900" ]; then
  exit 23
fi
exit 0
EOF
chmod +x "$success_bin/psql" "$success_bin/sleep"

success_output="$test_dir/success.log"
run_and_capture 23 "$success_output" \
  env PATH="$success_bin:$PATH" REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS= \
  sh "$maintenance_script"
assert_contains "refresh_tokens table is ready" "$success_output"
assert_contains "running refresh-token cleanup" "$success_output"
assert_contains "DELETE 2" "$success_output"
assert_contains "next cleanup in 900 seconds" "$success_output"

echo "cleanup-refresh-tokens.sh tests passed."
