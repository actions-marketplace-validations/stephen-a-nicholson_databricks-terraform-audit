"""Per-file checks: one passing and one failing case for each rule."""

from checks.databricks import (
    check_cluster_without_policy,
    check_legacy_hive_metastore,
    check_vnet_injection,
    check_workspace_sku,
)
from checks.security import (
    check_public_network_access,
    check_service_principal_scope,
    check_storage_network_rules,
    check_tls_version,
)
from checks.standards import (
    check_hardcoded_values,
    check_lifecycle_protection,
    check_provider_version,
    check_required_tags,
)

STORAGE_OK = '''
resource "azurerm_storage_account" "x" {
  name            = "x"
  min_tls_version = "TLS1_2"
  network_rules {
    default_action = "Deny"
  }
  lifecycle {
    prevent_destroy = true
  }
  tags = {
    Environment = "prod"
    Owner       = "a"
    CostCentre  = "b"
    Project     = "c"
  }
}
'''
STORAGE_BAD = 'resource "azurerm_storage_account" "x" { name = "x" }'


def test_public_network_access(tf) -> None:
    assert check_public_network_access(*tf('resource "azurerm_databricks_workspace" "w" { public_network_access_enabled = true }')) != []
    assert check_public_network_access(*tf('resource "azurerm_databricks_workspace" "w" { public_network_access_enabled = false }')) == []


def test_storage_network_rules_and_tls(tf) -> None:
    assert check_storage_network_rules(*tf(STORAGE_BAD)) != []
    assert [f.severity.value for f in check_tls_version(*tf(STORAGE_BAD))] == ["LOW"]
    assert [f.severity.value for f in check_tls_version(*tf('resource "azurerm_storage_account" "x" { min_tls_version = "TLS1_0" }'))] == ["HIGH"]
    assert check_storage_network_rules(*tf(STORAGE_OK)) == []
    assert check_tls_version(*tf(STORAGE_OK)) == []


def test_subscription_scope_role_assignment(tf) -> None:
    bad = 'resource "azurerm_role_assignment" "r" { scope = "/subscriptions/abc" role_definition_name = "Owner" principal_id = "p" }'
    ok = 'resource "azurerm_role_assignment" "r" { scope = azurerm_resource_group.main.id role_definition_name = "Contributor" principal_id = "p" }'
    assert check_service_principal_scope(*tf(bad)) != []
    assert check_service_principal_scope(*tf(ok)) == []


def test_required_tags(tf) -> None:
    assert check_required_tags(*tf(STORAGE_BAD)) != []
    assert check_required_tags(*tf(STORAGE_OK)) == []
    # A subnet has no tags argument in azurerm and must never be flagged.
    assert check_required_tags(*tf('resource "azurerm_subnet" "s" { name = "s" }')) == []
    # Tags passed as a variable cannot be inspected and must not be flagged.
    assert check_required_tags(*tf('resource "azurerm_resource_group" "g" { name = "g" tags = var.tags }')) == []


def test_provider_version(tf) -> None:
    unpinned = 'terraform { required_providers { azurerm = { source = "hashicorp/azurerm" } } }'
    pinned = 'terraform { required_providers { azurerm = { source = "hashicorp/azurerm" version = "~> 4.0" } } }'
    assert check_provider_version(*tf(unpinned)) != []
    assert check_provider_version(*tf(pinned)) == []
    # No terraform block in this file is not a per-file problem.
    assert check_provider_version(*tf(STORAGE_OK)) == []


def test_lifecycle_protection(tf) -> None:
    assert check_lifecycle_protection(*tf(STORAGE_BAD)) != []
    assert check_lifecycle_protection(*tf(STORAGE_OK)) == []


def test_hardcoded_uuid(tf) -> None:
    assert check_hardcoded_values(*tf('provider "azurerm" { subscription_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }')) != []
    assert check_hardcoded_values(*tf('provider "azurerm" { subscription_id = var.subscription_id }')) == []


def test_vnet_injection(tf) -> None:
    none = 'resource "azurerm_databricks_workspace" "w" { name = "w" }'
    no_scc = 'resource "azurerm_databricks_workspace" "w" { custom_parameters { virtual_network_id = "v" } }'
    full = 'resource "azurerm_databricks_workspace" "w" { custom_parameters { virtual_network_id = "v" no_public_ip = true } }'
    assert [f.severity.value for f in check_vnet_injection(*tf(none))] == ["CRITICAL"]
    assert [f.severity.value for f in check_vnet_injection(*tf(no_scc))] == ["LOW"]
    assert check_vnet_injection(*tf(full)) == []


def test_cluster_without_policy(tf) -> None:
    assert check_cluster_without_policy(*tf('resource "databricks_cluster" "c" { cluster_name = "c" }')) != []
    assert check_cluster_without_policy(*tf('resource "databricks_cluster" "c" { policy_id = "p" }')) == []


def test_workspace_sku(tf) -> None:
    assert check_workspace_sku(*tf('resource "azurerm_databricks_workspace" "w" { sku = "standard" }')) != []
    assert check_workspace_sku(*tf('resource "azurerm_databricks_workspace" "w" { sku = "premium" }')) == []


def test_legacy_hive_metastore(tf) -> None:
    assert check_legacy_hive_metastore(*tf('resource "databricks_grants" "g" { catalog = "hive_metastore" }')) != []
    assert check_legacy_hive_metastore(*tf('resource "databricks_grants" "g" { catalog = "main" }')) == []


def test_scc_explicit_false_is_high_and_unset_is_low(tf) -> None:
    off = 'resource "azurerm_databricks_workspace" "w" { custom_parameters { virtual_network_id = "v" no_public_ip = false } }'
    unset = 'resource "azurerm_databricks_workspace" "w" { custom_parameters { virtual_network_id = "v" } }'
    assert [f.severity.value for f in check_vnet_injection(*tf(off))] == ["HIGH"]
    assert [f.severity.value for f in check_vnet_injection(*tf(unset))] == ["LOW"]


def test_workspace_public_access_unset_is_medium(tf) -> None:
    unset = 'resource "azurerm_databricks_workspace" "w" { name = "w" }'
    off = 'resource "azurerm_databricks_workspace" "w" { public_network_access_enabled = false }'
    assert [f.severity.value for f in check_public_network_access(*tf(unset))] == ["MEDIUM"]
    assert check_public_network_access(*tf(off)) == []
    # Only workspaces are flagged for relying on the default.
    assert check_public_network_access(*tf('resource "azurerm_storage_account" "s" { name = "s" }')) == []


def test_tls_from_variable_is_not_flagged(tf) -> None:
    assert check_tls_version(*tf('resource "azurerm_storage_account" "x" { min_tls_version = var.tls }')) == []


def test_separate_network_rules_resource_satisfies_check(tf) -> None:
    src = '''
resource "azurerm_storage_account" "x" { name = "x" }
resource "azurerm_storage_account_network_rules" "x" {
  storage_account_id = azurerm_storage_account.x.id
  default_action     = "Deny"
}
'''
    assert check_storage_network_rules(*tf(src)) == []


def test_resource_group_scope_is_not_flagged(tf) -> None:
    rg = 'resource "azurerm_role_assignment" "r" { scope = "/subscriptions/${var.sub}/resourceGroups/rg-x" role_definition_name = "Contributor" principal_id = "p" }'
    sub = 'resource "azurerm_role_assignment" "r" { scope = data.azurerm_subscription.current.id role_definition_name = "Owner" principal_id = "p" }'
    assert check_service_principal_scope(*tf(rg)) == []
    assert check_service_principal_scope(*tf(sub)) != []


def test_hive_metastore_in_comment_is_ignored(tf) -> None:
    assert check_legacy_hive_metastore(*tf('# migrated off hive_metastore in 2025\nresource "databricks_grants" "g" { catalog = "main" }')) == []


def test_backend_only_terraform_block_is_not_unpinned(tf) -> None:
    assert check_provider_version(*tf('terraform { backend "azurerm" { key = "x" } }')) == []
