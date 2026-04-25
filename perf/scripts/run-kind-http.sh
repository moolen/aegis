#!/usr/bin/env bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_tool curl
require_tool docker
require_tool helm
require_tool k6
require_tool kind
require_tool kubectl

SCENARIO="http"
CLUSTER_NAME="${CLUSTER_NAME:-aegis-perf}"
# Set KEEP_CLUSTER=1 to preserve a newly created Kind cluster after the run.
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
NAMESPACE="aegis-perf"
RELEASE_NAME="aegis-perf"
IMAGE_REF="${IMAGE_REF:-aegis:perf-kind}"
IMAGE_REPO="${IMAGE_REF%:*}"
IMAGE_TAG="${IMAGE_REF##*:}"
VALUES_FILE="perf/config/kind-http-values.yaml"
K6_SCRIPT="perf/k6/http.js"
PROXY_URL="http://127.0.0.1:3128"
METRICS_URL="http://127.0.0.1:9090"
TARGET_URL="http://echo.aegis-perf.svc.cluster.local/allowed"
CLUSTER_CREATED=0

kctl() {
  kubectl --context "$KUBE_CONTEXT" "$@"
}

ensure_kind_cluster() {
  if kind get clusters | grep -Fxq "$CLUSTER_NAME"; then
    return 0
  fi
  (
    cd "$REPO_ROOT"
    kind create cluster --name "$CLUSTER_NAME" --config hack/kind-config.yaml
  )
  CLUSTER_CREATED=1
}

build_and_load_image() {
  (
    cd "$REPO_ROOT"
    docker build -t "$IMAGE_REF" .
    kind load docker-image "$IMAGE_REF" --name "$CLUSTER_NAME"
  )
}

cleanup_kind() {
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

  if [ "$KEEP_CLUSTER" != "1" ] && [ "$CLUSTER_CREATED" = "1" ]; then
    kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi

  exit "$status"
}

trap cleanup_kind EXIT INT TERM

apply_http_echo() {
  kctl create namespace "$NAMESPACE" --dry-run=client -o yaml | kctl apply -f -
  cat <<'EOF' | kctl -n "$NAMESPACE" apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: hashicorp/http-echo:1.0.0
          args:
            - -text=ok
            - -listen=:8080
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  selector:
    app: echo
  ports:
    - port: 80
      targetPort: 8080
EOF
  kctl -n "$NAMESPACE" rollout status deployment/echo --timeout=180s
}

deploy_chart() {
  (
    cd "$REPO_ROOT"
    helm upgrade --install "$RELEASE_NAME" ./deploy/helm \
      --namespace "$NAMESPACE" \
      --create-namespace \
      --set "image.repository=${IMAGE_REPO}" \
      --set "image.tag=${IMAGE_TAG}" \
      -f "$VALUES_FILE" \
      --wait \
      --timeout 180s
  )
  kctl -n "$NAMESPACE" rollout status deployment/aegis --timeout=180s
}

start_port_forward() {
  local log_file="$1"
  : >"$log_file"
  kctl -n "$NAMESPACE" port-forward svc/aegis 3128:3128 9090:9090 >"$log_file" 2>&1 &
  local pid=$!
  track_pid "$pid"
  wait_for_http_ok_pid "$pid" "${METRICS_URL}/healthz" 30
}

RESULT_DIR="$(new_result_dir "kind-${SCENARIO}" "kind")"
PORT_FORWARD_LOG="${RESULT_DIR}/port-forward.log"

log "result dir: ${RESULT_DIR}"
ensure_kind_cluster
build_and_load_image
apply_http_echo
deploy_chart
start_port_forward "$PORT_FORWARD_LOG"
capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-before.txt"

export RESULT_DIR PROXY_URL HTTP_PROXY="$PROXY_URL"
export TARGET_URL
export VUS="${VUS:-10}"
export DURATION="${DURATION:-30s}"
export EXPECTED_STATUS="${EXPECTED_STATUS:-200}"
export SLEEP_SECONDS="${SLEEP_SECONDS:-1}"

write_meta_env "${RESULT_DIR}/meta.env" <<EOF
SCENARIO=${SCENARIO}
TARGET=kind
CLUSTER_NAME=${CLUSTER_NAME}
KUBE_CONTEXT=${KUBE_CONTEXT}
NAMESPACE=${NAMESPACE}
RELEASE_NAME=${RELEASE_NAME}
IMAGE_REF=${IMAGE_REF}
VALUES_FILE=${VALUES_FILE}
K6_SCRIPT=${K6_SCRIPT}
RESULT_DIR=${RESULT_DIR}
TARGET_URL=${TARGET_URL}
PROXY_URL=${PROXY_URL}
METRICS_URL=${METRICS_URL}
KEEP_CLUSTER=${KEEP_CLUSTER}
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
