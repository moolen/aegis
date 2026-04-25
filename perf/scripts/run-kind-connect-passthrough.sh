#!/usr/bin/env bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_tool curl
require_tool docker
require_tool helm
require_tool k6
require_tool kind
require_tool kubectl
require_tool openssl

SCENARIO="connect-passthrough"
CLUSTER_NAME="${CLUSTER_NAME:-aegis-perf}"
# Set KEEP_CLUSTER=1 to preserve a newly created Kind cluster after the run.
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
NAMESPACE="aegis-perf"
RELEASE_NAME="aegis-perf"
IMAGE_REF="${IMAGE_REF:-aegis:perf-kind}"
IMAGE_REPO="${IMAGE_REF%:*}"
IMAGE_TAG="${IMAGE_REF##*:}"
VALUES_FILE="perf/config/kind-connect-passthrough-values.yaml"
K6_SCRIPT="perf/k6/connect_passthrough.js"
PROXY_URL="http://127.0.0.1:3128"
METRICS_URL="http://127.0.0.1:9090"
TARGET_URL="https://echo-tls.aegis-perf.svc.cluster.local/"
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

generate_upstream_tls() {
  local ca_cert="$1"
  local ca_key="$2"
  local server_cert="$3"
  local server_key="$4"
  local csr_file="$5"

  openssl ecparam -name prime256v1 -genkey -noout -out "$server_key"
  openssl req -new -key "$server_key" -out "$csr_file" -subj "/CN=echo-tls.aegis-perf.svc.cluster.local"
  cat >"${RESULT_DIR}/upstream-server.ext" <<'EOF'
subjectAltName=DNS:echo-tls.aegis-perf.svc.cluster.local
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
  openssl x509 -req \
    -in "$csr_file" \
    -CA "$ca_cert" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$server_cert" \
    -days 1 \
    -sha256 \
    -extfile "${RESULT_DIR}/upstream-server.ext"
}

apply_https_echo() {
  local ca_cert="$1"
  local ca_key="$2"
  local server_cert="$3"
  local server_key="$4"
  local csr_file="$5"

  generate_upstream_tls "$ca_cert" "$ca_key" "$server_cert" "$server_key" "$csr_file"

  kctl create namespace "$NAMESPACE" --dry-run=client -o yaml | kctl apply -f -
  kctl -n "$NAMESPACE" create secret tls echo-tls \
    --cert="$server_cert" \
    --key="$server_key" \
    --dry-run=client \
    -o yaml | kctl apply -f -
  cat <<'EOF' | kctl -n "$NAMESPACE" apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: echo-tls-nginx
data:
  default.conf: |
    server {
      listen 8443 ssl;
      server_name echo-tls.aegis-perf.svc.cluster.local;
      ssl_certificate /etc/nginx/tls/tls.crt;
      ssl_certificate_key /etc/nginx/tls/tls.key;
      location / {
        return 200 'ok';
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-tls
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-tls
  template:
    metadata:
      labels:
        app: echo-tls
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports:
            - containerPort: 8443
          volumeMounts:
            - name: tls
              mountPath: /etc/nginx/tls
              readOnly: true
            - name: config
              mountPath: /etc/nginx/conf.d
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: echo-tls
        - name: config
          configMap:
            name: echo-tls-nginx
---
apiVersion: v1
kind: Service
metadata:
  name: echo-tls
spec:
  selector:
    app: echo-tls
  ports:
    - port: 443
      targetPort: 8443
EOF
  kctl -n "$NAMESPACE" rollout status deployment/echo-tls --timeout=180s
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
UPSTREAM_CA_CERT="${RESULT_DIR}/upstream-ca.crt"
UPSTREAM_CA_KEY="${RESULT_DIR}/upstream-ca.key"
UPSTREAM_SERVER_CERT="${RESULT_DIR}/upstream-server.crt"
UPSTREAM_SERVER_KEY="${RESULT_DIR}/upstream-server.key"
UPSTREAM_SERVER_CSR="${RESULT_DIR}/upstream-server.csr"

log "result dir: ${RESULT_DIR}"
ensure_kind_cluster
build_and_load_image
generate_mitm_ca "$UPSTREAM_CA_CERT" "$UPSTREAM_CA_KEY"
apply_https_echo "$UPSTREAM_CA_CERT" "$UPSTREAM_CA_KEY" "$UPSTREAM_SERVER_CERT" "$UPSTREAM_SERVER_KEY" "$UPSTREAM_SERVER_CSR"
deploy_chart
start_port_forward "$PORT_FORWARD_LOG"
capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-before.txt"

export RESULT_DIR PROXY_URL HTTPS_PROXY="$PROXY_URL"
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
UPSTREAM_CA_CERT=${UPSTREAM_CA_CERT}
UPSTREAM_SERVER_CERT=${UPSTREAM_SERVER_CERT}
EOF

(
  cd "$REPO_ROOT"
  k6 run "$K6_SCRIPT"
) | tee "${RESULT_DIR}/summary.txt"

capture_metrics "$METRICS_URL" "${RESULT_DIR}/metrics-after.txt"
