#!/usr/bin/env bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_tool kubectl

SCENARIO="http"
TF_DIR="${TF_DIR:-${REPO_ROOT}/deploy/azure/terraform}"
K6_SCRIPT="perf/k6/http.js"
RESULT_DIR="$(new_result_dir "${SCENARIO}" "azure")"
NAMESPACE="${NAMESPACE:-aegis-cloud}"
K6_IMAGE="${K6_IMAGE:-grafana/k6:0.49.0}"
K6_CONFIGMAP="${K6_CONFIGMAP:-aegis-k6-http}"
K6_POD="${K6_POD:-aegis-k6-http}"
K6_POD_RESULT_DIR="${K6_POD_RESULT_DIR:-/tmp/aegis-perf-results}"
RUNNER_WARMUP_SECONDS="${RUNNER_WARMUP_SECONDS:-15}"

tf_output() {
  local name="$1"
  terraform -chdir="${TF_DIR}" output -raw "$name"
}

tf_output_json() {
  local name="$1"
  terraform -chdir="${TF_DIR}" output -json "$name"
}

require_tool terraform

PROXY_URL="${PROXY_URL:-$(tf_output aegis_proxy_url)}"
TARGET_URL="${TARGET_URL:-$(tf_output nginx_url)}"
VUS="${VUS:-10}"
DURATION="${DURATION:-30s}"
EXPECTED_STATUS="${EXPECTED_STATUS:-200}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"

mapfile -t PROXY_IPS < <(tf_output_json aegis_proxy_private_ips | tr -d '[]"' | tr ',' '\n' | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d')
[ "${#PROXY_IPS[@]}" -ge 1 ] || die "terraform output aegis_proxy_private_ips returned no private IPs"

sample_client_pod() {
  kubectl -n "${NAMESPACE}" get pods -l app=sample-client -o name \
    | sed 's|^pod/||' \
    | grep '^sample-client-' \
    | head -n1
}

capture_remote_metrics() {
  local out="$1"
  local pod
  pod="$(sample_client_pod)"
  [ -n "${pod}" ] || die "sample-client pod not found in namespace ${NAMESPACE}"

  : >"${out}"
  local ip
  for ip in "${PROXY_IPS[@]}"; do
    {
      printf '## instance=%s\n' "${ip}"
      kubectl -n "${NAMESPACE}" exec "${pod}" -- sh -c \
        "curl -fsS http://${ip}:9090/metrics | grep -E 'aegis_policy_discovery_policies_active|aegis_request_decisions_total|aegis_requests_total'"
      printf '\n'
    } >>"${out}"
  done
}

wait_for_remote_policy_sync() {
  local pod
  pod="$(sample_client_pod)"
  [ -n "${pod}" ] || die "sample-client pod not found in namespace ${NAMESPACE}"

  local deadline=$((SECONDS + 90))
  local ip
  while (( SECONDS < deadline )); do
    local ready=1
    for ip in "${PROXY_IPS[@]}"; do
      if ! kubectl -n "${NAMESPACE}" exec "${pod}" -- sh -c \
        "curl -fsS http://${ip}:9090/metrics | grep -q 'aegis_policy_discovery_policies_active{provider=\"azure\",source=\"azure-policies\"} 2'"; then
        ready=0
        break
      fi
    done
    if [ "${ready}" -eq 1 ]; then
      return 0
    fi
    sleep 2
  done

  die "timed out waiting for remote Azure policies to become active on all Aegis instances"
}

create_k6_runner() {
  kubectl -n "${NAMESPACE}" delete pod "${K6_POD}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "${NAMESPACE}" create configmap "${K6_CONFIGMAP}" \
    --from-file=http.js="${REPO_ROOT}/${K6_SCRIPT}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${K6_POD}
  namespace: ${NAMESPACE}
  labels:
    app: sample-client
    run: ${K6_POD}
spec:
  restartPolicy: Never
  containers:
  - name: k6
    image: ${K6_IMAGE}
    command: ["sh", "-c", "sleep infinity"]
    env:
    - name: PROXY_URL
      value: ${PROXY_URL}
    - name: HTTP_PROXY
      value: ${PROXY_URL}
    - name: HTTPS_PROXY
      value: ${PROXY_URL}
    - name: TARGET_URL
      value: ${TARGET_URL}
    - name: K6_NO_USAGE_REPORT
      value: "true"
    - name: RESULT_DIR
      value: ${K6_POD_RESULT_DIR}
    - name: VUS
      value: "${VUS}"
    - name: DURATION
      value: "${DURATION}"
    - name: EXPECTED_STATUS
      value: "${EXPECTED_STATUS}"
    - name: SLEEP_SECONDS
      value: "${SLEEP_SECONDS}"
    volumeMounts:
    - name: scripts
      mountPath: /scripts
      readOnly: true
  volumes:
  - name: scripts
    configMap:
      name: ${K6_CONFIGMAP}
EOF

  kubectl -n "${NAMESPACE}" wait --for=condition=Ready "pod/${K6_POD}" --timeout=180s >/dev/null
  sleep "${RUNNER_WARMUP_SECONDS}"
}

log "result dir: ${RESULT_DIR}"
kubectl -n "${NAMESPACE}" wait --for=condition=available deploy/sample-client --timeout=180s >/dev/null
wait_for_remote_policy_sync
create_k6_runner
capture_remote_metrics "${RESULT_DIR}/metrics-before.txt"

write_meta_env "${RESULT_DIR}/meta.env" <<EOF
SCENARIO=${SCENARIO}
TARGET=azure
TF_DIR=${TF_DIR}
K6_SCRIPT=${K6_SCRIPT}
RESULT_DIR=${RESULT_DIR}
PROXY_URL=${PROXY_URL}
TARGET_URL=${TARGET_URL}
VUS=${VUS}
DURATION=${DURATION}
EXPECTED_STATUS=${EXPECTED_STATUS}
SLEEP_SECONDS=${SLEEP_SECONDS}
NAMESPACE=${NAMESPACE}
K6_IMAGE=${K6_IMAGE}
K6_CONFIGMAP=${K6_CONFIGMAP}
K6_POD=${K6_POD}
K6_POD_RESULT_DIR=${K6_POD_RESULT_DIR}
RUNNER_WARMUP_SECONDS=${RUNNER_WARMUP_SECONDS}
PROXY_IPS=${PROXY_IPS[*]}
EOF

kubectl -n "${NAMESPACE}" exec "${K6_POD}" -- sh -c \
  "rm -rf '${K6_POD_RESULT_DIR}' && mkdir -p '${K6_POD_RESULT_DIR}' && k6 run /scripts/http.js" \
  | tee "${RESULT_DIR}/summary.txt"

kubectl -n "${NAMESPACE}" exec "${K6_POD}" -- cat "${K6_POD_RESULT_DIR}/summary.json" > "${RESULT_DIR}/summary.json"
capture_remote_metrics "${RESULT_DIR}/metrics-after.txt"
kubectl -n "${NAMESPACE}" delete pod "${K6_POD}" --ignore-not-found >/dev/null 2>&1 || true
