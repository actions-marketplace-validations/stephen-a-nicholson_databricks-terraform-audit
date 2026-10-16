resource "databricks_metastore_assignment" "this" {
  workspace_id = azurerm_databricks_workspace.this.workspace_id
  metastore_id = var.metastore_id
}

variable "metastore_id" {
  description = "ID of the regional Unity Catalog metastore"
  type        = string
}

resource "databricks_cluster_policy" "default" {
  name = "Default policy"
  definition = jsonencode({
    "autotermination_minutes" : {
      "type" : "fixed",
      "value" : 60
    }
  })
}

resource "databricks_cluster" "shared" {
  cluster_name            = "shared-cluster"
  spark_version           = "15.4.x-scala2.12"
  node_type_id            = "Standard_DS3_v2"
  autotermination_minutes = 60
  num_workers             = 2
  policy_id               = databricks_cluster_policy.default.id
}
