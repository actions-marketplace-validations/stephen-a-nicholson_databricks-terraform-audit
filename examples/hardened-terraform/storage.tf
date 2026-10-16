resource "azurerm_storage_account" "datalake" {
  name                     = "stlakehouseprod"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "ZRS"
  is_hns_enabled           = true
  min_tls_version          = "TLS1_2"
  public_network_access_enabled = false
  tags                     = var.tags

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.databricks_private.id]
  }

  lifecycle {
    prevent_destroy = true
  }
}
