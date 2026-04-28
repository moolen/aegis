# Aegis Azure Cloud Perf Environment Design

**Date:** 2026-04-28
**Status:** Approved for implementation

## Goal

Add a repo-native Azure bootstrap environment that provisions the base
infrastructure needed to run Aegis in Azure and execute the existing perf
package against a private Azure target instead of the public internet.

The design must:

- provision an AKS cluster with flat pod networking where pods receive IP
  addresses directly from an Azure virtual network subnet
- keep the AKS API public while restricting access with authorized IP ranges
- run Aegis as two internal-only Azure Container Instances with 4 vCPU each
- publish sample Aegis policies to Azure Blob Storage for remote policy
  discovery
- provision a dedicated private Azure VM running NGINX to act as the perf
  target
- keep Terraform responsible only for infrastructure bootstrapping
- leave workload deployment into AKS and perf execution to repo-native `make`
  targets

## Scope

### In scope

- new Terraform under `deploy/azure/terraform`
- Azure resource group, VNet, subnets, routeable internal network layout
- AKS with Azure CNI Pod Subnet networking
- public AKS API restricted by authorized IP ranges
- Azure Container Instances for Aegis on a delegated subnet
- Azure Blob container with sample policy documents
- private DNS for internal Aegis name resolution
- a private Azure VM running NGINX for static test content
- repo-native `make` targets and scripts for:
  - deploying workloads into AKS with `HTTP_PROXY` / `HTTPS_PROXY`
  - deploying sample workload manifests into AKS
  - running perf against the Azure NGINX target through Aegis
- documentation for bootstrap, deploy, and perf flows

### Out of scope

- private AKS control plane
- exposing Aegis publicly
- provisioning the AKS application workloads in Terraform
- provisioning the `k6` runner in Terraform
- auto-scaling or production HA hardening beyond the requested two Aegis
  instances
- replacing the existing local and Kind perf flows

## Requirements And Constraints

### AKS networking

AKS must use flat pod networking, not Azure CNI Overlay. Pods should get VNet
IP addresses directly from a dedicated pod subnet so traffic to Aegis and the
private NGINX VM stays fully routable inside the VNet without overlay address
translation or internet-bound SNAT in the data path.

### Control plane exposure

The AKS API server remains public for operator simplicity, but Terraform must
require an explicit allowlist of authorized CIDRs and apply them to the
cluster.

### Aegis deployment shape

Aegis runs as two independent Azure Container Instance groups, each with:

- 4 vCPU
- enough memory to run the requested perf scenarios
- private-only networking on a delegated subnet
- managed identity for Azure Blob access

The first slice does not attempt to expose Aegis via a public endpoint or a
full Azure ingress stack. Clients inside the VNet reach Aegis through a private
DNS name that resolves to the ACI private IPs.

### Perf target

The load-test upstream must be a dedicated Azure VM running NGINX that serves
static content from a private VNet address. Perf must not use public internet
destinations as the benchmark upstream.

### Ownership split

Terraform owns infrastructure only.

Repo-native scripts own:

- deploying Aegis-adjacent AKS workloads
- setting workload proxy environment variables
- invoking the perf harness

## High-Level Architecture

The environment is organized into one Azure VNet with distinct subnets:

- `aks_nodes` for AKS node pools
- `aks_pods` for Azure CNI Pod Subnet pod IP allocation
- `aci` for the two Aegis Azure Container Instances
- `vm` for the private NGINX VM

Supporting resources:

- one NAT gateway attached to the ACI subnet so VNet-injected ACI has supported
  outbound connectivity for image pulls and Azure API access
- one storage account with a blob container for sample policy objects
- one private DNS zone for an internal Aegis name
- network security groups attached so inbound access is explicitly constrained
  per subnet role

Traffic shape:

1. AKS workloads resolve the private Aegis DNS name.
2. DNS returns both ACI private IPs.
3. Workloads use `HTTP_PROXY` / `HTTPS_PROXY` to send traffic to Aegis.
4. Aegis loads policies from Azure Blob using managed identity.
5. Allowed traffic is forwarded to the private NGINX VM.
6. The perf harness targets the private NGINX VM URL through the same Aegis
   proxy path.

## Terraform Design

## Directory Layout

Add a new deployment root:

- `deploy/azure/terraform/main.tf`
- `deploy/azure/terraform/variables.tf`
- `deploy/azure/terraform/outputs.tf`
- `deploy/azure/terraform/versions.tf`
- `deploy/azure/terraform/locals.tf`
- `deploy/azure/terraform/userdata/nginx-cloud-init.yaml`
- `deploy/azure/terraform/policies/*.yaml`

The Terraform package should be self-contained and should not modify the
existing AWS Fargate starter files.

## Resource Model

### Core network

Terraform creates:

- resource group
- virtual network
- AKS node subnet
- AKS pod subnet
- delegated ACI subnet
- VM subnet
- NAT gateway and public IP for the ACI subnet
- NSGs and subnet associations

The AKS pod subnet is separate from the node subnet so Azure CNI Pod Subnet can
allocate pod IPs directly without consuming node subnet capacity.

### AKS

Terraform provisions:

- one AKS cluster
- system-assigned managed identity
- one default node pool on the node subnet
- Azure CNI Pod Subnet network profile wired to the pod subnet
- API server authorized IP ranges from an input variable
- the minimum cluster settings required for a working bootstrap environment,
  without introducing optional add-ons in this slice

The cluster remains public but locked down.

### Blob storage

Terraform provisions:

- one storage account
- one private blob container for Aegis policy objects
- several sample policy blobs uploaded from versioned repo files

The sample policies should be simple and deterministic. They should allow:

- workload egress from designated AKS namespaces or labels
- traffic to the private NGINX hostname / IP and port
- the HTTP methods and paths used by the perf scenario

### Aegis ACI

Terraform provisions two container groups:

- `aegis-0`
- `aegis-1`

Each container group includes:

- the Aegis container image
- `cpu = 4`
- internal-only IP on the ACI subnet
- managed identity
- environment needed for Azure Blob discovery, including the storage account
  name expected by the current Azure client implementation
- Aegis config rendered from Terraform template content

The Aegis config should enable:

- proxy listener on port `3128`
- metrics listener on port `9090`
- remote policy discovery from the blob container and configured prefix
- Azure Kubernetes identity discovery for AKS workloads

If Azure-specific Kubernetes discovery auth needs managed-cluster metadata, the
Terraform config should render the required fields explicitly from the created
AKS cluster outputs.

### Private DNS

Terraform provisions:

- one private DNS zone, for example `aegis.internal`
- two A records for the shared Aegis service name pointing at the two ACI
  private IPs
- one A record for the private NGINX VM host name
- VNet links so AKS nodes and pods can resolve the records

Using DNS instead of assuming fixed ACI IPs keeps the design aligned with ACI
recreate behavior. Terraform is the source of truth for updating the private
records on apply.

### NGINX VM

Terraform provisions:

- one Linux VM in the VM subnet
- NIC with private IP only
- cloud-init or custom data to install and configure NGINX
- static content directory used by perf

The VM should expose a predictable test path such as `/static/allowed` and
return deterministic content lengths so perf baselines stay comparable.

## Runtime Integration Design

## Workload deployment

Workload deployment stays outside Terraform and should be implemented with
repo-native manifests or Helm overlays. The deploy flow should:

- create a namespace for Azure cloud tests
- deploy one or more sample workloads into AKS
- inject:
  - `HTTP_PROXY=http://<aegis-private-dns>:3128`
  - `HTTPS_PROXY=http://<aegis-private-dns>:3128`
  - `NO_PROXY` for cluster-local service ranges and required internal hosts

These workloads are validation fixtures and not part of the Terraform state.

## Perf integration

The existing `perf/` package already has local and Kind targets. The Azure
slice should add a separate Azure target instead of modifying the semantics of
the existing ones.

New pieces:

- a `make` target such as `perf-azure-http`
- one shell runner under `perf/scripts/`
- one Azure-specific config source for target URLs and proxy URL

The Azure perf target should:

- require an operator to provide Terraform outputs or an env file
- point `HTTP_PROXY` at the Aegis private DNS endpoint
- set `TARGET_URL` to the private NGINX VM URL
- reuse the existing `perf/k6/http.js` scenario where possible
- capture result artifacts under `perf/results/` in the same shape as current
  runs

The load generator remains separate from Terraform. The first slice assumes the
operator runs the make target from a machine that can reach the Azure private
network, such as a peered workstation, VPN-connected host, or Azure-resident
runner.

## Configuration And Interfaces

## Terraform inputs

The Terraform package should expose explicit variables for:

- `name`
- `location`
- `resource_group_name`
- `aks_kubernetes_version`
- `aks_node_count`
- `aks_node_vm_size`
- `aks_api_authorized_ip_ranges`
- `vnet_cidr`
- `aks_node_subnet_cidr`
- `aks_pod_subnet_cidr`
- `aci_subnet_cidr`
- `vm_subnet_cidr`
- `aegis_image`
- `aegis_cpu`
- `aegis_memory`
- `aegis_instances`
- `policy_blob_prefix`
- `nginx_vm_size`
- `operator_ssh_public_key`
- `tags`

Defaults should be sensible for a bootstrap environment, but authorized API
CIDRs should not silently default to unrestricted public access.

## Terraform outputs

The Terraform package should emit:

- AKS cluster name
- AKS resource group
- kubeconfig retrieval command hint
- Aegis private DNS name
- Aegis proxy URL
- blob container name
- policy prefix
- NGINX private IP
- NGINX target URL

These outputs are the contract consumed by the repo-side deploy and perf
scripts.

## Sample policy design

Sample policy blobs should use the existing Kubernetes-style `ProxyPolicy`
resource format so they exercise the native Azure Blob discovery path already
implemented in Aegis.

The initial sample set should include:

- one allow policy for the cloud-test workload namespace / labels
- egress rule for the private NGINX endpoint on the served HTTP port
- explicit allowed path list matching the static test path

The sample policies should avoid internet FQDN rules so the test environment
stays fully private on the upstream side.

## Security Model

- Aegis is internal-only; no public load balancer or public DNS name
- AKS API is public but restricted by authorized IP ranges
- NGINX VM is private-only
- Blob access uses managed identity and RBAC rather than storage keys
- NSGs should limit inbound proxy traffic to the AKS pod and node address space
  and limit metrics access to operator networks or explicitly chosen internal
  sources
- SSH access to the VM, if enabled at all, should be key-based and restricted

## Failure Handling

### Terraform lifecycle

Terraform should tolerate normal recreate semantics for the ACI groups. On
re-apply, the private DNS records should follow the currently assigned ACI
private IPs.

### Aegis policy discovery

If Azure Blob policy discovery is temporarily unavailable, Aegis keeps its
last-good remote policy snapshot according to the existing runtime behavior.
This design does not introduce a separate Azure-specific fallback path.

### Perf execution

The Azure perf runner should fail fast when:

- required Terraform outputs are missing
- the Aegis proxy endpoint is unreachable
- the NGINX target URL is unreachable through the proxy

This keeps cloud perf failures attributable to environment readiness rather
than hidden retries.

## Testing Strategy

Testing should stay proportional to the bootstrap slice.

### Terraform validation

- `terraform fmt -check`
- `terraform validate`
- optional `terraform plan` smoke checks with a documented sample tfvars file

### Repo-side script validation

- shell syntax checks where practical
- focused unit tests for any new Go helpers reused by Azure perf scripts
- dry-run or render checks for workload manifests if templating is introduced

### Operator validation flow

1. Apply Terraform.
2. Verify AKS nodes and pod subnet allocation.
3. Verify both ACI groups are healthy and resolvable via private DNS.
4. Verify sample policy blobs exist in storage.
5. Deploy AKS workloads with proxy environment variables.
6. Verify proxied access to the private NGINX path.
7. Run the Azure perf make target.

## Implementation Notes

- Prefer reusing the existing Helm chart and perf script conventions rather
  than introducing a second deployment toolchain.
- Keep Azure-specific values and templates in dedicated files so the local and
  Kind paths remain readable.
- The first slice should optimize for reproducible cloud testing, not for a
  fully generic Azure platform module.
