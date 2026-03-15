"""Databricks-specific checks for Terraform configurations."""

from pathlib import Path

from checks.helpers import iter_resources
from checks.models import Category, Finding, Severity


def _has_resource_type(parsed: dict, target_type: str) -> bool:
    """Check if a specific resource type exists anywhere in the parsed HCL."""
    for rtype, _, _ in iter_resources(parsed):
        if rtype == target_type:
            return True
    return False


def check_unity_catalog(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag missing Unity Catalog configuration."""
    findings: list[Finding] = []

    has_workspace = _has_resource_type(parsed, "azurerm_databricks_workspace")
    has_metastore = _has_resource_type(parsed, "databricks_metastore_assignment")

    if has_workspace and not has_metastore:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=Category.DATABRICKS,
            title="No Unity Catalog metastore assignment",
            message=(
                "Databricks workspace defined without a "
                "databricks_metastore_assignment resource. Without Unity Catalog, "
                "the workspace uses legacy hive_metastore with no centralised "
                "governance."
            ),
            filepath=filepath,
            suggested_fix=(
                'resource "databricks_metastore_assignment" "this" {\n'
                "  workspace_id = azurerm_databricks_workspace.this.workspace_id\n"
                "  metastore_id = databricks_metastore.this.id\n"
                "}"
            ),
        ))

    content = filepath.read_text()
    if "hive_metastore" in content:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=Category.DATABRICKS,
            title="Legacy hive_metastore reference found",
            message=(
                "Found reference to 'hive_metastore'. This indicates legacy "
                "catalogue configuration. Migrate to Unity Catalog for centralised "
                "data governance."
            ),
            filepath=filepath,
        ))

    return findings


def check_vnet_injection(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag Databricks workspaces without VNet injection."""
    findings: list[Finding] = []

    for rtype, rname, config in iter_resources(parsed):
        if rtype != "azurerm_databricks_workspace":
            continue
        custom_params = config.get("custom_parameters", [{}])
        cp = custom_params[0] if isinstance(custom_params, list) else custom_params

        if not cp.get("virtual_network_id"):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=Category.DATABRICKS,
                title="Databricks workspace without VNet injection",
                message=(
                    f"Workspace '{rname}' has no VNet injection configured. "
                    f"The workspace will use Databricks-managed networking, which "
                    f"provides less control over network security."
                ),
                filepath=filepath,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix=(
                    "custom_parameters {\n"
                    "  virtual_network_id  = azurerm_virtual_network.this.id\n"
                    '  public_subnet_name  = "databricks-public"\n'
                    '  private_subnet_name = "databricks-private"\n'
                    "  no_public_ip        = true\n"
                    "}"
                ),
            ))
        elif not cp.get("no_public_ip"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.DATABRICKS,
                title="Secure cluster connectivity not enabled",
                message=(
                    f"Workspace '{rname}' has VNet injection but "
                    f"no_public_ip is not set to true. Enable secure cluster "
                    f"connectivity to prevent cluster nodes from getting public IPs."
                ),
                filepath=filepath,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix="no_public_ip = true",
            ))

    return findings


def check_cluster_policies(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag missing cluster policies."""
    findings: list[Finding] = []

    has_workspace = _has_resource_type(parsed, "azurerm_databricks_workspace")
    has_policies = _has_resource_type(parsed, "databricks_cluster_policy")

    if has_workspace and not has_policies:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=Category.DATABRICKS,
            title="No cluster policies defined",
            message=(
                "Databricks workspace exists but no cluster policies are defined. "
                "Without policies, users can create clusters with any configuration, "
                "leading to uncontrolled costs and inconsistent environments."
            ),
            filepath=filepath,
            suggested_fix=(
                'resource "databricks_cluster_policy" "default" {\n'
                '  name = "Default policy"\n'
                "  definition = jsonencode({\n"
                '    "autotermination_minutes": {\n'
                '      "type":  "fixed",\n'
                '      "value": 60\n'
                "    }\n"
                "  })\n"
                "}"
            ),
        ))

    for rtype, rname, config in iter_resources(parsed):
        if rtype != "databricks_cluster":
            continue
        if not config.get("policy_id"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.DATABRICKS,
                title="Cluster defined without policy",
                message=(
                    f"Cluster '{rname}' has no policy_id. "
                    f"It bypasses any cluster governance policies."
                ),
                filepath=filepath,
                resource_address=f"databricks_cluster.{rname}",
            ))

    return findings


def check_workspace_sku(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag workspaces using standard SKU."""
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        if rtype != "azurerm_databricks_workspace":
            continue
        sku = str(config.get("sku", "")).lower()
        if sku == "standard":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.DATABRICKS,
                title="Workspace using Standard SKU",
                message=(
                    f"Workspace '{rname}' uses the Standard SKU. "
                    f"Unity Catalog, cluster policies, and audit logging "
                    f"require the Premium SKU."
                ),
                filepath=filepath,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix='sku = "premium"',
            ))
    return findings


def run_all_checks(parsed: dict, filepath: Path) -> list[Finding]:
    """Run all Databricks checks against a parsed HCL file."""
    checks = [
        check_unity_catalog,
        check_vnet_injection,
        check_cluster_policies,
        check_workspace_sku,
    ]
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check(parsed, filepath))
    return findings
