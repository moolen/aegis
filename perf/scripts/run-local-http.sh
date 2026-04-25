#!/usr/bin/env bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_tool curl
require_tool k6
resolve_go_bin
require_executable "${REPO_ROOT}/bin/aegis"

SCENARIO="http"
CONFIG_PATH="perf/config/local-http.yaml"
K6_SCRIPT="perf/k6/http.js"
TARGET_PATH="/allowed"
TARGET_HOST="127.0.0.1"
TARGET_PORT="18080"
PROXY_URL="http://127.0.0.1:3128"
METRICS_URL="http://127.0.0.1:9090"

RESULT_DIR="$(new_result_dir "$SCENARIO" "local")"
FIXTURE_BIN="${RESULT_DIR}/fixtures"
FIXTURE_ENV="${RESULT_DIR}/fixture.env"
FIXTURE_LOG="${RESULT_DIR}/fixture.log"
AEGIS_LOG="${RESULT_DIR}/aegis.log"

log "result dir: ${RESULT_DIR}"
build_fixture_helper "$FIXTURE_BIN"
start_fixture "$FIXTURE_BIN" "http" "${TARGET_HOST}:${TARGET_PORT}" "$TARGET_PATH" "$FIXTURE_ENV" "$FIXTURE_LOG"
source "$FIXTURE_ENV"

export RESULT_DIR PROXY_URL HTTP_PROXY="$PROXY_URL"
export TARGET_HOST TARGET_PORT TARGET_PATH
export VUS="${VUS:-10}"
export DURATION="${DURATION:-30s}"
export EXPECTED_STATUS="${EXPECTED_STATUS:-204}"
export SLEEP_SECONDS="${SLEEP_SECONDS:-1}"

start_aegis "$CONFIG_PATH" "$AEGIS_LOG"
wait_for_http_ok "${METRICS_URL}/healthz"
capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-before.txt"

write_meta_env "${RESULT_DIR}/meta.env" <<EOF
SCENARIO=${SCENARIO}
TARGET=local
CONFIG_PATH=${CONFIG_PATH}
K6_SCRIPT=${K6_SCRIPT}
RESULT_DIR=${RESULT_DIR}
FIXTURE_MODE=http
FIXTURE_ADDR=${LISTEN_ADDR}
TARGET_HOST=${TARGET_HOST}
TARGET_PORT=${TARGET_PORT}
TARGET_PATH=${TARGET_PATH}
PROXY_URL=${PROXY_URL}
METRICS_URL=${METRICS_URL}
VUS=${VUS}
DURATION=${DURATION}
EXPECTED_STATUS=${EXPECTED_STATUS}
SLEEP_SECONDS=${SLEEP_SECONDS}
EOF

(
  cd "$REPO_ROOT"
  k6 run "$K6_SCRIPT"
) | tee "${RESULT_DIR}/summary.txt"

capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-after.txt"
