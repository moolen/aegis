#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PERF_TMP_DIR="${PERF_TMP_DIR:-/tmp/aegis-perf}"
GO_BIN="${GO_BIN:-}"
declare -a CLEANUP_PIDS=()

log() {
  printf '[perf] %s\n' "$*"
}

die() {
  printf '[perf] error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  local pid
  for ((idx=${#CLEANUP_PIDS[@]}-1; idx>=0; idx--)); do
    pid="${CLEANUP_PIDS[idx]}"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done

  sleep 0.2

  for ((idx=${#CLEANUP_PIDS[@]}-1; idx>=0; idx--)); do
    pid="${CLEANUP_PIDS[idx]}"
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  done

  exit "$status"
}

trap cleanup EXIT INT TERM

track_pid() {
  CLEANUP_PIDS+=("$1")
}

require_tool() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: ${tool}"
}

require_file() {
  local path="$1"
  [ -e "$path" ] || die "required path not found: ${path}"
}

require_executable() {
  local path="$1"
  [ -x "$path" ] || die "required executable not found: ${path}"
}

resolve_go_bin() {
  if [ -n "$GO_BIN" ]; then
    require_executable "$GO_BIN"
    return
  fi

  if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
    return
  fi

  if [ -x /usr/local/go/bin/go ]; then
    GO_BIN="/usr/local/go/bin/go"
    return
  fi

  die "required tool not found: go"
}

new_result_dir() {
  local scenario="$1"
  local target="$2"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local dir="${REPO_ROOT}/perf/results/${ts}-${scenario}-${target}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

wait_for_http_ok() {
  local url="$1"
  local timeout_seconds="${2:-30}"
  local deadline=$((SECONDS + timeout_seconds))

  while (( SECONDS < deadline )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  die "timed out waiting for ${url}"
}

capture_metrics() {
  local url="$1"
  local out="$2"
  curl -fsS "${url}/metrics" >"$out"
}

build_fixture_helper() {
  local out="$1"
  resolve_go_bin
  mkdir -p "$(dirname -- "$out")"
  (
    cd "$REPO_ROOT"
    "$GO_BIN" build -o "$out" ./perf/scripts
  )
}

wait_for_env_key() {
  local pid="$1"
  local env_file="$2"
  local key="$3"
  local timeout_seconds="${4:-15}"
  local deadline=$((SECONDS + timeout_seconds))

  while (( SECONDS < deadline )); do
    if [ -f "$env_file" ] && grep -q "^${key}=" "$env_file"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      die "process ${pid} exited before publishing ${key}"
    fi
    sleep 0.1
  done

  die "timed out waiting for ${key} in ${env_file}"
}

start_fixture() {
  local fixture_bin="$1"
  local mode="$2"
  local listen="$3"
  local path="$4"
  local env_file="$5"
  local log_file="$6"
  local -a required_keys=("LISTEN_ADDR")

  : >"$env_file"
  : >"$log_file"

  case "$mode" in
    passthrough|mitm)
      required_keys+=("ROOT_CA_PEM_B64")
      ;;
  esac

  "$fixture_bin" -mode "$mode" -listen "$listen" -path "$path" >"$env_file" 2>"$log_file" &
  local pid=$!
  track_pid "$pid"

  local key
  for key in "${required_keys[@]}"; do
    wait_for_env_key "$pid" "$env_file" "$key"
  done
}

start_aegis() {
  local config_path="$1"
  local log_file="$2"

  : >"$log_file"

  (
    cd "$REPO_ROOT"
    ./bin/aegis -config "$config_path"
  ) >"$log_file" 2>&1 &
  local pid=$!
  track_pid "$pid"
}

write_meta_env() {
  local out="$1"
  cat >"$out"
}

find_system_ca_bundle() {
  local path
  for path in \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/cert.pem
  do
    if [ -r "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done

  return 1
}

decode_base64_to_file() {
  local value="$1"
  local out="$2"

  if printf '%s' "$value" | base64 --decode >"$out" 2>/dev/null; then
    return 0
  fi
  if printf '%s' "$value" | base64 -d >"$out" 2>/dev/null; then
    return 0
  fi
  if printf '%s' "$value" | base64 -D >"$out" 2>/dev/null; then
    return 0
  fi

  die "failed to decode base64 payload into ${out}"
}

build_ssl_cert_file() {
  local extra_cert="$1"
  local out="$2"
  local system_bundle

  if system_bundle="$(find_system_ca_bundle)"; then
    cat "$system_bundle" "$extra_cert" >"$out"
    return 0
  fi

  cp "$extra_cert" "$out"
}

generate_mitm_ca() {
  local cert_file="$1"
  local key_file="$2"

  require_tool openssl
  mkdir -p "$(dirname -- "$cert_file")"

  openssl ecparam -name prime256v1 -genkey -noout -out "$key_file"
  openssl req \
    -new \
    -x509 \
    -sha256 \
    -days 1 \
    -key "$key_file" \
    -out "$cert_file" \
    -subj "/CN=aegis-perf-mitm-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -addext "subjectKeyIdentifier=hash"
  chmod 0600 "$key_file"
}
