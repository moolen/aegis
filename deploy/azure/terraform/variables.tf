variable "name" {
  description = "Short environment name used as the resource prefix."
  type        = string
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group that owns the Azure cloud perf environment."
  type        = string
}

variable "aks_api_authorized_ip_ranges" {
  description = "CIDR ranges allowed to reach the public AKS API server."
  type        = list(string)
}

variable "vnet_cidr" {
  description = "Address space for the Azure VNet."
  type        = string
}

variable "aks_node_subnet_cidr" {
  description = "CIDR for the AKS node subnet."
  type        = string
}

variable "aks_pod_subnet_cidr" {
  description = "CIDR for the AKS pod subnet used by Azure CNI Pod Subnet."
  type        = string
}

variable "aci_subnet_cidr" {
  description = "CIDR for the delegated Azure Container Instances subnet."
  type        = string
}

variable "vm_subnet_cidr" {
  description = "CIDR for the private NGINX VM subnet."
  type        = string
}

variable "aks_kubernetes_version" {
  description = "Optional AKS Kubernetes version for the cluster."
  type        = string
  default     = null
}

variable "aks_node_vm_size" {
  description = "VM size for the AKS system node pool."
  type        = string
  default     = "Standard_D4s_v5"
}

variable "aks_node_count" {
  description = "Node count for the AKS system node pool."
  type        = number
  default     = 3

  validation {
    condition     = var.aks_node_count >= 1
    error_message = "aks_node_count must be at least 1."
  }
}

variable "aegis_image" {
  description = "Container image reference for the Aegis ACI groups."
  type        = string
}

variable "aegis_instances" {
  description = "Number of Aegis ACI instances to provision."
  type        = number
  default     = 2

  validation {
    condition     = var.aegis_instances >= 2
    error_message = "aegis_instances must be at least 2."
  }
}

variable "aegis_cpu" {
  description = "vCPU allocation for each Aegis ACI instance."
  type        = number
  default     = 4

  validation {
    condition     = var.aegis_cpu > 0
    error_message = "aegis_cpu must be greater than zero."
  }
}

variable "aegis_memory" {
  description = "Memory in GB for each Aegis ACI instance."
  type        = number
  default     = 8

  validation {
    condition     = var.aegis_memory > 0
    error_message = "aegis_memory must be greater than zero."
  }
}

variable "aegis_policy_poll_interval" {
  description = "Policy discovery poll interval used by the Aegis ACI instances."
  type        = string
  default     = "30s"
}

variable "aegis_kubernetes_resync_period" {
  description = "Kubernetes discovery resync period used by the Aegis ACI instances."
  type        = string
  default     = "30s"
}

variable "policy_blob_prefix" {
  description = "Prefix within the blob container that stores sample policy objects."
  type        = string
  default     = "tenants/sample"
}

variable "operator_ssh_public_key" {
  description = "SSH public key installed on the private NGINX VM."
  type        = string
}

variable "vm_size" {
  description = "VM size for the private NGINX host."
  type        = string
  default     = "Standard_B2s"
}

variable "vm_admin_username" {
  description = "Admin username for the private NGINX VM."
  type        = string
  default     = "azureuser"
}

variable "tags" {
  description = "Additional Azure resource tags."
  type        = map(string)
  default     = {}
}
