# Azure Deployment

This directory contains the Azure deployment scaffold for the cloud perf
environment described in `docs/superpowers/plans/2026-04-28-aegis-azure-cloud-perf.md`.

## Prerequisites

- Terraform 1.6 or newer
- Azure CLI authenticated to the target subscription
- An operator SSH public key for the NGINX VM bootstrap

## Terraform Apply

Terraform configuration lives in `deploy/azure/terraform`.

```bash
terraform -chdir=deploy/azure/terraform init
terraform -chdir=deploy/azure/terraform apply
```

Future tasks add the remaining infrastructure resources, outputs, and helper
scripts that make the apply flow fully runnable.

## Workload Deploy

Later tasks add the AKS workload manifest and deployment helper under
`deploy/azure/manifests` and `deploy/azure/scripts`.

Planned flow:

```bash
deploy/azure/scripts/deploy-workload.sh
```

## Perf Run

The Azure perf runner executes `k6` from inside AKS so the benchmark path stays on the private VNet and traverses the same Aegis ACI and NGINX VM path as the real workload.

Flow:

```bash
eval "$(deploy/azure/scripts/export-env.sh)"
eval "$AKS_GET_CREDENTIALS_COMMAND"
deploy/azure/scripts/deploy-workload.sh
perf/scripts/run-azure-http.sh
```

## Cloud E2E Run

The Go cloud integration suite targets the same preprovisioned Azure
environment:

```bash
eval "$(deploy/azure/scripts/export-env.sh)"
eval "$AKS_GET_CREDENTIALS_COMMAND"
deploy/azure/scripts/deploy-workload.sh
go test -tags cloud_e2e -timeout 60m ./e2e/...
```

The export script provides the Azure Blob container/prefix and Aegis metrics
endpoint environment that the `cloud_e2e` harness expects.
