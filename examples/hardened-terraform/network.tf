resource "azurerm_resource_group" "main" {
  name     = "rg-lakehouse-prod"
  location = "uksouth"
  tags     = var.tags
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-lakehouse-prod"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.10.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "databricks_public" {
  name                 = "databricks-public"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_subnet" "databricks_private" {
  name                 = "databricks-private"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.10.2.0/24"]
}
