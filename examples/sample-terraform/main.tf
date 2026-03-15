terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "azurerm_resource_group" "main" {
  name     = "rg-databricks"
  location = "uksouth"
}

resource "azurerm_storage_account" "datalake" {
  name                     = "mydatalakestorage"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  is_hns_enabled           = true

  allow_nested_items_to_be_public = true

  tags = {
    Environment = "production"
  }
}

resource "azurerm_databricks_workspace" "this" {
  name                          = "test-workspace"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  sku                           = "standard"
  public_network_access_enabled = true

  tags = {
    Environment = "production"
  }
}

resource "azurerm_role_assignment" "sp_contributor" {
  scope                = "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  role_definition_name = "Contributor"
  principal_id         = "00000000-0000-0000-0000-000000000000"
}

resource "databricks_cluster" "shared" {
  cluster_name            = "shared-cluster"
  spark_version           = "13.3.x-scala2.12"
  node_type_id            = "Standard_DS3_v2"
  autotermination_minutes = 0
  num_workers             = 8
}
