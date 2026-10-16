resource "azurerm_databricks_workspace" "this" {
  name                          = "dbw-lakehouse-prod"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  sku                                   = "premium"
  public_network_access_enabled         = false
  network_security_group_rules_required = "NoAzureDatabricksRules"
  customer_managed_key_enabled          = true
  managed_services_cmk_key_vault_key_id = var.managed_services_key_id
  tags                                  = var.tags

  custom_parameters {
    virtual_network_id  = azurerm_virtual_network.this.id
    public_subnet_name  = azurerm_subnet.databricks_public.name
    private_subnet_name = azurerm_subnet.databricks_private.name
    no_public_ip        = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_role_assignment" "sp_rg_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_object_id
}

variable "service_principal_object_id" {
  description = "Object ID of the deployment service principal"
  type        = string
}
