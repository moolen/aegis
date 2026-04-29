locals {
  prefix = trim(replace(lower(var.name), "/[^0-9a-z-]/", "-"), "-")
  common_tags = merge(var.tags, {
    project = "aegis"
    env     = var.name
  })

  sanitized_alnum_name       = replace(lower(var.name), "/[^0-9a-z]/", "")
  storage_account_seed       = local.sanitized_alnum_name == "" ? "aegis" : local.sanitized_alnum_name
  storage_account_prefix     = substr("${local.storage_account_seed}pol", 0, 18)
  aks_cluster_name           = "${local.prefix}-aks"
  aks_identity_name          = "${local.prefix}-aks-id"
  policy_container_name      = "policies"
  policy_blob_prefix_trimmed = trim(var.policy_blob_prefix, "/")
  policy_blob_prefix         = local.policy_blob_prefix_trimmed == "" ? "" : "${local.policy_blob_prefix_trimmed}/"
  aegis_private_dns_zone     = "aegis.internal"
  aegis_proxy_host           = "proxy.${local.aegis_private_dns_zone}"
  nginx_host                 = "nginx.${local.aegis_private_dns_zone}"
  nginx_vm_name              = "${local.prefix}-nginx"
  aegis_namespace            = "aegis-cloud"
  aegis_discovery_name       = "aks-cloud"
  aegis_policy_source        = "azure-policies"
  policy_files = {
    "allow-nginx.yaml"       = "${path.module}/policies/allow-nginx.yaml"
    "allow-health.yaml"      = "${path.module}/policies/allow-health.yaml"
    "allow-nginx-https.yaml" = "${path.module}/policies/allow-nginx-https.yaml"
  }

  aegis_instances = {
    for idx in range(var.aegis_instances) : tostring(idx) => {
      ordinal       = idx + 1
      name          = substr("${local.prefix}-aegis-${format("%02d", idx + 1)}", 0, 63)
      identity_name = substr("${local.prefix}-aegis-id-${format("%02d", idx + 1)}", 0, 128)
    }
  }

  aegis_config = yamlencode({
    proxy = {
      listen                = ":3128"
      enforcement           = "enforce"
      unknownIdentityPolicy = "deny"
      ca = {
        certFile = "/aegis-ca/ca.crt"
        keyFile  = "/aegis-ca/ca.key"
      }
    }
    metrics = {
      listen = ":9090"
    }
    shutdown = {
      gracePeriod = "10s"
    }
    dns = {
      cache_ttl = "30s"
      timeout   = "5s"
      servers   = []
      rebindingProtection = {
        allowedHostPatterns = [local.nginx_host]
        allowedCIDRs        = [var.vm_subnet_cidr]
      }
    }
    discovery = {
      kubernetes = [
        {
          name = local.aegis_discovery_name
          auth = {
            provider       = "aks"
            subscriptionID = data.azurerm_client_config.current.subscription_id
            resourceGroup  = var.resource_group_name
            clusterName    = local.aks_cluster_name
          }
          namespaces   = []
          resyncPeriod = var.aegis_kubernetes_resync_period
        }
      ]
      ec2 = []
      policies = [
        {
          name         = local.aegis_policy_source
          provider     = "azure"
          bucket       = local.policy_container_name
          prefix       = local.policy_blob_prefix
          pollInterval = var.aegis_policy_poll_interval
          auth = {
            mode = "default"
          }
        }
      ]
    }
    policies = [
      {
        name = "bootstrap-placeholder"
        subjects = {
          cidrs = ["192.0.2.255/32"]
        }
        egress = [
          {
            fqdn  = local.nginx_host
            ports = [80, 443]
            tls = {
              mode = "mitm"
            }
            http = {
              allowedMethods = ["GET"]
              allowedPaths   = ["/static/allowed", "/healthz"]
            }
          }
        ]
      }
    ]
  })

  aks_api_authorized_ip_ranges = distinct(concat(
    var.aks_api_authorized_ip_ranges,
    azurerm_public_ip.nat.ip_address == null ? [] : ["${azurerm_public_ip.nat.ip_address}/32"],
  ))

  policy_blobs = {
    for file_name, path in local.policy_files :
    "${local.policy_blob_prefix}${file_name}" => file(path)
  }
}
