"""Project-level checks must look across files, not within one."""

from pathlib import Path

from checks.project import (
    Project,
    check_cluster_policy_exists,
    check_terraform_block_exists,
    check_unity_catalog_assignment,
)

WORKSPACE = '''
resource "azurerm_databricks_workspace" "this" {
  name = "dbw"
  sku  = "premium"
}
'''
ASSIGNMENT = '''
resource "databricks_metastore_assignment" "this" {
  workspace_id = azurerm_databricks_workspace.this.workspace_id
  metastore_id = "abc"
}
'''
POLICY = '''
resource "databricks_cluster_policy" "default" {
  name       = "Default"
  definition = "{}"
}
'''
VERSIONS = '''
terraform {
  required_version = ">= 1.5.0"
}
'''


def _project(tf, **files: str) -> Project:
    project = Project(root=Path("."))
    for name, text in files.items():
        parsed, path = tf(text, name=f"{name}.tf")
        project.files[path] = parsed
    return project


def test_metastore_in_separate_file_is_not_flagged(tf) -> None:
    project = _project(tf, workspace=WORKSPACE, unity_catalog=ASSIGNMENT)
    assert check_unity_catalog_assignment(project) == []


def test_missing_metastore_is_flagged_once(tf) -> None:
    project = _project(tf, workspace=WORKSPACE, other="")
    findings = check_unity_catalog_assignment(project)
    assert len(findings) == 1
    assert findings[0].filepath.name == "workspace.tf"


def test_no_workspace_means_no_metastore_finding(tf) -> None:
    project = _project(tf, storage='resource "azurerm_storage_account" "x" { name = "x" }')
    assert check_unity_catalog_assignment(project) == []


def test_cluster_policy_in_separate_file_is_not_flagged(tf) -> None:
    project = _project(tf, workspace=WORKSPACE, policies=POLICY)
    assert check_cluster_policy_exists(project) == []


def test_terraform_block_in_versions_file_satisfies_check(tf) -> None:
    project = _project(tf, versions=VERSIONS, workspace=WORKSPACE)
    assert check_terraform_block_exists(project) == []


def test_missing_terraform_block_flagged_once_per_project(tf) -> None:
    project = _project(tf, a=WORKSPACE, b=POLICY, c=ASSIGNMENT)
    assert len(check_terraform_block_exists(project)) == 1
