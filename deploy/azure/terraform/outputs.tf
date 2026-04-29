output "resource_group_name" {
  value = azurerm_resource_group.this.name
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.this.name
}

output "aks_get_credentials_command" {
  value = "az aks get-credentials --resource-group ${azurerm_resource_group.this.name} --name ${azurerm_kubernetes_cluster.this.name} --overwrite-existing"
}

output "aegis_proxy_host" {
  value = local.aegis_proxy_host
}

output "aegis_proxy_url" {
  value = "http://${local.aegis_proxy_host}:3128"
}

output "aegis_container_group_names" {
  value = [
    for key in sort(keys(azurerm_container_group.aegis)) :
    azurerm_container_group.aegis[key].name
  ]
}

output "aegis_proxy_private_ips" {
  value = [
    for key in sort(keys(azurerm_container_group.aegis)) :
    azurerm_container_group.aegis[key].ip_address
  ]
}

output "nginx_host" {
  value = local.nginx_host
}

output "nginx_private_ip" {
  value = azurerm_network_interface.nginx.private_ip_address
}

output "nginx_url" {
  value = "http://${local.nginx_host}/static/allowed"
}

output "nginx_https_url" {
  value = "https://${local.nginx_host}/static/allowed"
}

output "policy_storage_account_name" {
  value = azurerm_storage_account.policies.name
}

output "policy_container_name" {
  value = azurerm_storage_container.policies.name
}

output "policy_blob_prefix" {
  value = local.policy_blob_prefix
}

output "private_dns_zone_name" {
  value = azurerm_private_dns_zone.aegis.name
}
