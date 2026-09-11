#!/usr/bin/env sh
set -eu

cleanup_interval="${REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS:-900}"

case "$cleanup_interval" in
  *[!0-9]*|??????????*)
    echo "REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS must be an integer from 60 to 999999999." >&2
    exit 1
    ;;
esac

if [ "$cleanup_interval" -lt 60 ]; then
  echo "REFRESH_TOKEN_CLEANUP_INTERVAL_SECONDS must be at least 60." >&2
  exit 1
fi

ready_attempt=1
ready_max_attempts=12

while :; do
  if ready_result=$(psql \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --set=ON_ERROR_STOP=1 \
    --command="SELECT to_regclass('public.refresh_tokens') IS NOT NULL") \
    && [ "$ready_result" = "t" ]; then
    echo "[db-maintenance] refresh_tokens table is ready."
    break
  fi

  if [ "$ready_attempt" -ge "$ready_max_attempts" ]; then
    echo "[db-maintenance] readiness attempt $ready_attempt/$ready_max_attempts failed; exiting. Check database credentials and migrations." >&2
    exit 1
  fi

  echo "[db-maintenance] readiness attempt $ready_attempt/$ready_max_attempts failed; retrying in 5 seconds." >&2
  ready_attempt=$((ready_attempt + 1))
  sleep 5
done

while :; do
  echo "[db-maintenance] running refresh-token cleanup."
  psql \
    --no-psqlrc \
    --set=ON_ERROR_STOP=1 \
    --file=/maintenance/cleanup_refresh_tokens.sql
  echo "[db-maintenance] next cleanup in $cleanup_interval seconds."
  sleep "$cleanup_interval"
done
