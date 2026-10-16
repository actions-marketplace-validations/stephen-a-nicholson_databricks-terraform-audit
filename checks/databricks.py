"""Databricks-specific checks for Terraform configurations."""

from pathlib import Path

from checks.helpers import iter_resources
from checks.models import Category, Finding, Severity


def check_legacy_hive_metastore(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag references to the legacy hive_metastore. Metastore assignment is a project-level check."""
    findings: list[Finding] = []

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
        elif cp.get("no_public_ip") is False:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.DATABRICKS,
                title="Secure cluster connectivity disabled",
                message=(
                    f"Workspace '{rname}' explicitly sets no_public_ip = false, so "
                    f"cluster nodes get public IP addresses. The provider has defaulted "
                    f"this to true since azurerm v3.104.0; turning it off is a deliberate "
                    f"choice that almost no enterprise network policy allows."
                ),
                filepath=filepath,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix="no_public_ip = true",
            ))
        elif "no_public_ip" not in cp:
            findings.append(Finding(
                severity=Severity.LOW,
                category=Category.DATABRICKS,
                title="Secure cluster connectivity relies on provider default",
                message=(
                    f"Workspace '{rname}' does not set no_public_ip. Since azurerm "
                    f"v3.104.0 the default is true, so this is fine on a current provider, "
                    f"but on older pinned versions the default was false and nodes got "
                    f"public IPs. Set it explicitly so a reviewer does not have to know "
                    f"which provider version you are on."
                ),
                filepath=filepath,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix="no_public_ip = true",
            ))

    return findings


def check_cluster_without_policy(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag clusters with no policy_id. Whether any policy exists at all is a project-level check."""
    findings: list[Finding] = []

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
        check_legacy_hive_metastore,
        check_vnet_injection,
        check_cluster_without_policy,
        check_workspace_sku,
    ]
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check(parsed, filepath))
    return findings
