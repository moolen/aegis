#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
TF_DIR="${TF_DIR:-${REPO_ROOT}/deploy/azure/terraform}"

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

require_tool terraform

proxy_metrics_endpoints() {
  terraform -chdir="${TF_DIR}" output -json aegis_proxy_private_ips \
    | tr -d '[]"' \
    | tr ',' '\n' \
    | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d' -e 's/$/:9090/' \
    | paste -sd, -
}

printf 'export AEGIS_PROXY_URL=%q\n' "$(tf_output aegis_proxy_url)"
printf 'export AEGIS_TARGET_URL=%q\n' "$(tf_output nginx_url)"
printf 'export AEGIS_TARGET_HTTPS_URL=%q\n' "$(tf_output nginx_https_url)"
printf 'export AZURE_STORAGE_ACCOUNT_NAME=%q\n' "$(tf_output policy_storage_account_name)"
printf 'export AZURE_POLICY_CONTAINER=%q\n' "$(tf_output policy_container_name)"
printf 'export AZURE_POLICY_PREFIX=%q\n' "$(tf_output policy_blob_prefix)"
printf 'export AEGIS_METRICS_ENDPOINTS=%q\n' "$(proxy_metrics_endpoints)"
printf 'export PROXY_URL=%q\n' "$(tf_output aegis_proxy_url)"
printf 'export TARGET_URL=%q\n' "$(tf_output nginx_url)"
printf 'export TARGET_HTTPS_URL=%q\n' "$(tf_output nginx_https_url)"
printf 'export AKS_GET_CREDENTIALS_COMMAND=%q\n' "$(tf_output aks_get_credentials_command)"
