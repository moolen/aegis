data "azurerm_client_config" "current" {}

resource "tls_private_key" "aegis_ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "aegis_ca" {
  private_key_pem = tls_private_key.aegis_ca.private_key_pem

  subject {
    common_name  = "aegis-azure-mitm-ca"
    organization = "Aegis Perf"
  }

  validity_period_hours = 24
  is_ca_certificate     = true
  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
    "key_encipherment",
    "server_auth",
    "client_auth",
  ]
}

resource "tls_private_key" "nginx_server" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "nginx_server" {
  private_key_pem = tls_private_key.nginx_server.private_key_pem

  subject {
    common_name  = local.nginx_host
    organization = "Aegis Perf"
  }

  dns_names = [local.nginx_host]
}

resource "tls_locally_signed_cert" "nginx_server" {
  cert_request_pem   = tls_cert_request.nginx_server.cert_request_pem
  ca_private_key_pem = tls_private_key.aegis_ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.aegis_ca.cert_pem

  validity_period_hours = 24
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "random_string" "storage_suffix" {
  length  = 6
  upper   = false
  lower   = true
  numeric = true
  special = false
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.common_tags
}

resource "azurerm_virtual_network" "this" {
  name                = "${local.prefix}-vnet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_cidr]
  tags                = local.common_tags
}

resource "azurerm_subnet" "aks_nodes" {
  name                 = "${local.prefix}-aks-nodes"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.aks_node_subnet_cidr]
}

resource "azurerm_subnet" "aks_pods" {
  name                 = "${local.prefix}-aks-pods"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.aks_pod_subnet_cidr]

  delegation {
    name = "aks-delegation"

    service_delegation {
      name = "Microsoft.ContainerService/managedClusters"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_subnet" "aci" {
  name                 = "${local.prefix}-aci"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.aci_subnet_cidr]

  delegation {
    name = "aci"

    service_delegation {
      name = "Microsoft.ContainerInstance/containerGroups"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_subnet" "vm" {
  name                 = "${local.prefix}-vm"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.vm_subnet_cidr]
}

resource "azurerm_network_security_group" "aks_nodes" {
  name                = "${local.prefix}-aks-nodes-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_network_security_group" "aks_pods" {
  name                = "${local.prefix}-aks-pods-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_network_security_group" "aci" {
  name                = "${local.prefix}-aci-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_network_security_group" "vm" {
  name                = "${local.prefix}-vm-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "aks_nodes" {
  subnet_id                 = azurerm_subnet.aks_nodes.id
  network_security_group_id = azurerm_network_security_group.aks_nodes.id
}

resource "azurerm_subnet_network_security_group_association" "aks_pods" {
  subnet_id                 = azurerm_subnet.aks_pods.id
  network_security_group_id = azurerm_network_security_group.aks_pods.id
}

resource "azurerm_subnet_network_security_group_association" "aci" {
  subnet_id                 = azurerm_subnet.aci.id
  network_security_group_id = azurerm_network_security_group.aci.id
}

resource "azurerm_subnet_network_security_group_association" "vm" {
  subnet_id                 = azurerm_subnet.vm.id
  network_security_group_id = azurerm_network_security_group.vm.id
}

resource "azurerm_public_ip" "nat" {
  name                = "${local.prefix}-nat-pip"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.common_tags
}

resource "azurerm_nat_gateway" "this" {
  name                    = "${local.prefix}-nat"
  location                = azurerm_resource_group.this.location
  resource_group_name     = azurerm_resource_group.this.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  tags                    = local.common_tags
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  nat_gateway_id       = azurerm_nat_gateway.this.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "aci" {
  subnet_id      = azurerm_subnet.aci.id
  nat_gateway_id = azurerm_nat_gateway.this.id
}

resource "azurerm_subnet_nat_gateway_association" "vm" {
  subnet_id      = azurerm_subnet.vm.id
  nat_gateway_id = azurerm_nat_gateway.this.id
}

resource "azurerm_storage_account" "policies" {
  name                            = substr("${local.storage_account_prefix}${random_string.storage_suffix.result}", 0, 24)
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true
  min_tls_version                 = "TLS1_2"
  tags                            = local.common_tags
}

resource "azurerm_storage_container" "policies" {
  name                  = local.policy_container_name
  storage_account_id    = azurerm_storage_account.policies.id
  container_access_type = "private"
}

resource "azurerm_storage_blob" "policies" {
  for_each = local.policy_blobs

  name                   = each.key
  storage_account_name   = azurerm_storage_account.policies.name
  storage_container_name = azurerm_storage_container.policies.name
  type                   = "Block"
  source_content         = each.value
  content_type           = "application/yaml"
}

resource "azurerm_private_dns_zone" "aegis" {
  name                = local.aegis_private_dns_zone
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "aegis" {
  name                  = "${local.prefix}-aegis-link"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.aegis.name
  virtual_network_id    = azurerm_virtual_network.this.id
  registration_enabled  = false
  tags                  = local.common_tags
}

resource "azurerm_network_interface" "nginx" {
  name                = "${local.prefix}-nginx-nic"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "nginx" {
  name                            = local.nginx_vm_name
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  size                            = var.vm_size
  admin_username                  = var.vm_admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.nginx.id]
  custom_data = base64encode(templatefile("${path.module}/userdata/nginx-cloud-init.yaml", {
    nginx_tls_cert_pem = join("\n", [
      for line in split("\n", trimspace(tls_locally_signed_cert.nginx_server.cert_pem)) : "      ${line}"
    ])
    nginx_tls_key_pem = join("\n", [
      for line in split("\n", trimspace(tls_private_key.nginx_server.private_key_pem)) : "      ${line}"
    ])
  }))
  tags = local.common_tags

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = var.operator_ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}

resource "azurerm_private_dns_a_record" "nginx" {
  name                = "nginx"
  zone_name           = azurerm_private_dns_zone.aegis.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 30
  records             = [azurerm_network_interface.nginx.private_ip_address]
  tags                = local.common_tags
}

resource "azurerm_user_assigned_identity" "aks" {
  name                = local.aks_identity_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_role_assignment" "aks_network_contributor" {
  scope                            = azurerm_virtual_network.this.id
  role_definition_name             = "Network Contributor"
  principal_id                     = azurerm_user_assigned_identity.aks.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_kubernetes_cluster" "this" {
  name                              = local.aks_cluster_name
  location                          = azurerm_resource_group.this.location
  resource_group_name               = azurerm_resource_group.this.name
  dns_prefix                        = local.aks_cluster_name
  kubernetes_version                = var.aks_kubernetes_version
  role_based_access_control_enabled = true
  tags                              = local.common_tags

  default_node_pool {
    name           = "system"
    vm_size        = var.aks_node_vm_size
    node_count     = var.aks_node_count
    vnet_subnet_id = azurerm_subnet.aks_nodes.id
    pod_subnet_id  = azurerm_subnet.aks_pods.id
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
    tenant_id          = data.azurerm_client_config.current.tenant_id
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
    outbound_type  = "loadBalancer"
  }

  api_server_access_profile {
    authorized_ip_ranges = local.aks_api_authorized_ip_ranges
  }

  depends_on = [
    azurerm_role_assignment.aks_network_contributor,
    azurerm_subnet_network_security_group_association.aks_nodes,
    azurerm_subnet_network_security_group_association.aks_pods,
  ]
}

resource "azurerm_user_assigned_identity" "aegis" {
  for_each = local.aegis_instances

  name                = each.value.identity_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

resource "azurerm_role_assignment" "aegis_storage_blob_reader" {
  for_each = local.aegis_instances

  scope                            = azurerm_storage_account.policies.id
  role_definition_name             = "Storage Blob Data Reader"
  principal_id                     = azurerm_user_assigned_identity.aegis[each.key].principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "operator_storage_blob_contributor" {
  scope                = azurerm_storage_account.policies.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "aegis_aks_cluster_user" {
  for_each = local.aegis_instances

  scope                            = azurerm_kubernetes_cluster.this.id
  role_definition_name             = "Azure Kubernetes Service Cluster User Role"
  principal_id                     = azurerm_user_assigned_identity.aegis[each.key].principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "aegis_aks_rbac_reader" {
  for_each = local.aegis_instances

  scope                            = azurerm_kubernetes_cluster.this.id
  role_definition_name             = "Azure Kubernetes Service RBAC Reader"
  principal_id                     = azurerm_user_assigned_identity.aegis[each.key].principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_container_group" "aegis" {
  for_each = local.aegis_instances

  name                = each.value.name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  ip_address_type     = "Private"
  os_type             = "Linux"
  restart_policy      = "Always"
  subnet_ids          = [azurerm_subnet.aci.id]
  tags                = local.common_tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aegis[each.key].id]
  }

  container {
    name   = "aegis"
    image  = var.aegis_image
    cpu    = var.aegis_cpu
    memory = var.aegis_memory

    environment_variables = {
      AZURE_CLIENT_ID            = azurerm_user_assigned_identity.aegis[each.key].client_id
      AZURE_STORAGE_ACCOUNT_NAME = azurerm_storage_account.policies.name
      AZURE_STORAGE_ACCOUNT      = azurerm_storage_account.policies.name
      SSL_CERT_FILE              = "/aegis-ca/ca.crt"
    }

    ports {
      port     = 3128
      protocol = "TCP"
    }

    ports {
      port     = 9090
      protocol = "TCP"
    }

    volume {
      name       = "config"
      mount_path = "/etc/aegis"
      read_only  = true
      secret = {
        "aegis.yaml" = base64encode(local.aegis_config)
      }
    }

    volume {
      name       = "ca"
      mount_path = "/aegis-ca"
      read_only  = true
      secret = {
        "ca.crt" = base64encode(trimspace(tls_self_signed_cert.aegis_ca.cert_pem))
        "ca.key" = base64encode(trimspace(tls_private_key.aegis_ca.private_key_pem))
      }
    }
  }

  depends_on = [
    azurerm_private_dns_a_record.nginx,
    azurerm_storage_blob.policies,
    azurerm_role_assignment.aegis_storage_blob_reader,
    azurerm_role_assignment.aegis_aks_cluster_user,
    azurerm_role_assignment.aegis_aks_rbac_reader,
    azurerm_subnet_nat_gateway_association.aci,
  ]

}

resource "azurerm_private_dns_a_record" "proxy" {
  name                = "proxy"
  zone_name           = azurerm_private_dns_zone.aegis.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 30
  records = [
    for key in sort(keys(azurerm_container_group.aegis)) :
    azurerm_container_group.aegis[key].ip_address
  ]
  tags = local.common_tags
}
