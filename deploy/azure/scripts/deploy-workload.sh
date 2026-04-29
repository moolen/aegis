#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
TF_DIR="${TF_DIR:-${REPO_ROOT}/deploy/azure/terraform}"
NAMESPACE="${NAMESPACE:-aegis-cloud}"

require_tool() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'error: required tool not found: %s\n' "$tool" >&2
    exit 1
  }
}

tf_output() {
  local name="$1"
  terraform -chdir="${TF_DIR}" output -raw "$name"
}

require_tool kubectl

if [ -z "${AEGIS_PROXY_URL:-}" ]; then
  require_tool terraform
  AEGIS_PROXY_URL="$(tf_output aegis_proxy_url)"
else
  AEGIS_PROXY_URL="${AEGIS_PROXY_URL}"
fi

NO_PROXY_VALUE="${NO_PROXY_VALUE:-127.0.0.1,localhost,.localhost,kubernetes.default.svc,kubernetes.default.svc.cluster.local,.svc,.cluster.local,169.254.169.254}"

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
sed \
  -e "s|__NAMESPACE__|${NAMESPACE}|g" \
  -e "s|__HTTP_PROXY__|${AEGIS_PROXY_URL}|g" \
  -e "s|__HTTPS_PROXY__|${AEGIS_PROXY_URL}|g" \
  -e "s|__NO_PROXY__|${NO_PROXY_VALUE}|g" \
  "${REPO_ROOT}/deploy/azure/manifests/workload.yaml" | kubectl apply -f -

kubectl -n "${NAMESPACE}" rollout status deployment/sample-client --timeout=180s
