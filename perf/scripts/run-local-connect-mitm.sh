#!/usr/bin/env bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_tool curl
require_tool k6
require_tool base64
resolve_go_bin
require_executable "${REPO_ROOT}/bin/aegis"

SCENARIO="connect-mitm"
CONFIG_PATH="perf/config/local-connect-mitm.yaml"
K6_SCRIPT="perf/k6/connect_mitm.js"
TARGET_PATH="/allowed"
TARGET_HOST="127.0.0.1"
TARGET_PORT="18443"
PROXY_URL="http://127.0.0.1:3128"
METRICS_URL="http://127.0.0.1:9090"
PROXY_CA_CERT="/tmp/aegis-perf/mitm-ca.crt"
PROXY_CA_KEY="/tmp/aegis-perf/mitm-ca.key"

RESULT_DIR="$(new_result_dir "$SCENARIO" "local")"
FIXTURE_BIN="${RESULT_DIR}/fixtures"
FIXTURE_ENV="${RESULT_DIR}/fixture.env"
FIXTURE_LOG="${RESULT_DIR}/fixture.log"
AEGIS_LOG="${RESULT_DIR}/aegis.log"
FIXTURE_ROOT_CA="${RESULT_DIR}/fixture-root-ca.pem"
SSL_CERT_FILE_OVERRIDE="${RESULT_DIR}/ssl-cert-file.pem"

log "result dir: ${RESULT_DIR}"
generate_mitm_ca "$PROXY_CA_CERT" "$PROXY_CA_KEY"
build_fixture_helper "$FIXTURE_BIN"
start_fixture "$FIXTURE_BIN" "mitm" "${TARGET_HOST}:${TARGET_PORT}" "$TARGET_PATH" "$FIXTURE_ENV" "$FIXTURE_LOG"
source "$FIXTURE_ENV"

[ -n "${ROOT_CA_PEM_B64:-}" ] || die "fixture did not publish ROOT_CA_PEM_B64"
decode_base64_to_file "$ROOT_CA_PEM_B64" "$FIXTURE_ROOT_CA"
build_ssl_cert_file "$FIXTURE_ROOT_CA" "$SSL_CERT_FILE_OVERRIDE"

export RESULT_DIR PROXY_URL HTTPS_PROXY="$PROXY_URL"
export TARGET_HOST TARGET_PORT TARGET_PATH
export VUS="${VUS:-10}"
export DURATION="${DURATION:-30s}"
export EXPECTED_STATUS="${EXPECTED_STATUS:-204}"
export SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
export SSL_CERT_FILE="$SSL_CERT_FILE_OVERRIDE"

start_aegis "$CONFIG_PATH" "$AEGIS_LOG"
wait_for_http_ok "${METRICS_URL}/healthz"
capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-before.txt"

write_meta_env "${RESULT_DIR}/meta.env" <<EOF
SCENARIO=${SCENARIO}
TARGET=local
CONFIG_PATH=${CONFIG_PATH}
K6_SCRIPT=${K6_SCRIPT}
RESULT_DIR=${RESULT_DIR}
FIXTURE_MODE=mitm
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
PROXY_CA_CERT=${PROXY_CA_CERT}
PROXY_CA_KEY=${PROXY_CA_KEY}
FIXTURE_ROOT_CA=${FIXTURE_ROOT_CA}
SSL_CERT_FILE=${SSL_CERT_FILE}
EOF

(
  cd "$REPO_ROOT"
  k6 run "$K6_SCRIPT"
) | tee "${RESULT_DIR}/summary.txt"

capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-after.txt"
