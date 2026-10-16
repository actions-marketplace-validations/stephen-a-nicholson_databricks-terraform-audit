# Back-end and front-end Private Link, storage private endpoints, DNS, egress and CMK.
# This is the shape the Databricks Security Reference Architecture uses, reduced to
# the minimum that passes the hardened profile.

resource "azurerm_subnet" "private_endpoints" {
  name                 = "private-endpoints"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.10.3.0/24"]
}

resource "azurerm_private_dns_zone" "databricks" {
  name                = "privatelink.azuredatabricks.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone" "dfs" {
  name                = "privatelink.dfs.core.windows.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_private_endpoint" "backend" {
  name                = "pe-dbw-backend"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "psc-dbw-backend"
    private_connection_resource_id = azurerm_databricks_workspace.this.id
    is_manual_connection           = false
    subresource_names              = ["databricks_ui_api"]
  }

  private_dns_zone_group {
    name                 = "databricks"
    private_dns_zone_ids = [azurerm_private_dns_zone.databricks.id]
  }
}

resource "azurerm_private_endpoint" "webauth" {
  name                = "pe-dbw-webauth"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "psc-dbw-webauth"
    private_connection_resource_id = azurerm_databricks_workspace.this.id
    is_manual_connection           = false
    subresource_names              = ["browser_authentication"]
  }

  private_dns_zone_group {
    name                 = "databricks"
    private_dns_zone_ids = [azurerm_private_dns_zone.databricks.id]
  }
}

resource "azurerm_private_endpoint" "datalake_dfs" {
  name                = "pe-datalake-dfs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "psc-datalake-dfs"
    private_connection_resource_id = azurerm_storage_account.datalake.id
    is_manual_connection           = false
    subresource_names              = ["dfs"]
  }

  private_dns_zone_group {
    name                 = "dfs"
    private_dns_zone_ids = [azurerm_private_dns_zone.dfs.id]
  }
}

resource "azurerm_route_table" "databricks" {
  name                = "rt-databricks"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  route {
    name                   = "default-to-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = var.firewall_private_ip
  }
}

resource "azurerm_subnet_route_table_association" "private" {
  subnet_id      = azurerm_subnet.databricks_private.id
  route_table_id = azurerm_route_table.databricks.id
}

resource "databricks_mws_network_connectivity_config" "this" {
  provider = databricks.account
  name     = "ncc-lakehouse-prod"
  region   = azurerm_resource_group.main.location
}

resource "databricks_mws_ncc_binding" "this" {
  provider                       = databricks.account
  network_connectivity_config_id = databricks_mws_network_connectivity_config.this.network_connectivity_config_id
  workspace_id                   = azurerm_databricks_workspace.this.workspace_id
}

variable "firewall_private_ip" {
  description = "Private IP of the hub firewall that Databricks egress is routed through"
  type        = string
}

variable "managed_services_key_id" {
  description = "Key Vault key for managed services CMK"
  type        = string
}
