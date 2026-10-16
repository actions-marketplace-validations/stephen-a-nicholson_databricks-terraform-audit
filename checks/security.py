"""Security checks for Terraform configurations."""

from pathlib import Path

from checks.helpers import iter_resources
from checks.models import Category, Finding, Severity


def check_public_network_access(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag resources exposed to the public internet.

    Explicit ``public_network_access_enabled = true`` is CRITICAL on any resource.
    A Databricks workspace that leaves it unset is also public, because the
    provider default is true, so that is flagged at MEDIUM: it is the normal
    state for a workspace without Private Link, but a reviewer should see it.
    """
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        value = config.get("public_network_access_enabled")
        if value is True:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                title="Public network access enabled",
                message=(
                    f"Resource '{rtype}.{rname}' has "
                    f"public_network_access_enabled = true. This exposes "
                    f"the resource to the public internet."
                ),
                filepath=filepath,
                resource_address=f"{rtype}.{rname}",
                suggested_fix=(
                    f'resource "{rtype}" "{rname}" {{\n'
                    f"  public_network_access_enabled = false\n"
                    f"}}"
                ),
            ))
        elif rtype == "azurerm_databricks_workspace" and "public_network_access_enabled" not in config:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                title="Workspace public network access relies on provider default",
                message=(
                    f"Workspace '{rname}' does not set public_network_access_enabled. "
                    f"The provider default is true, so the workspace front end is "
                    f"reachable from the internet. If that is intended, say so "
                    f"explicitly; if not, set it to false and use Private Link."
                ),
                filepath=filepath,
                resource_address=f"{rtype}.{rname}",
                suggested_fix="public_network_access_enabled = false",
            ))
    return findings


def check_storage_network_rules(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag storage accounts without network rules."""
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        if rtype != "azurerm_storage_account":
            continue
        if "network_rules" not in config:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.SECURITY,
                title="Storage account missing network rules",
                message=(
                    f"Storage account '{rname}' has no network_rules block. "
                    f"This defaults to allowing access from all networks."
                ),
                filepath=filepath,
                resource_address=f"azurerm_storage_account.{rname}",
                suggested_fix=(
                    f'resource "azurerm_storage_account" "{rname}" {{\n'
                    f"  # ... existing config ...\n\n"
                    f"  network_rules {{\n"
                    f'    default_action             = "Deny"\n'
                    f"    bypass                     = [\"AzureServices\"]\n"
                    f"    virtual_network_subnet_ids = [azurerm_subnet.databricks_private.id]\n"
                    f"  }}\n"
                    f"}}"
                ),
            ))
    return findings


def check_tls_version(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag storage accounts without minimum TLS 1.2."""
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        if rtype != "azurerm_storage_account":
            continue
        tls = config.get("min_tls_version", "")
        if tls != "TLS1_2":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                title="Storage account not enforcing TLS 1.2",
                message=(
                    f"Storage account '{rname}' does not enforce "
                    f"TLS 1.2 as minimum version."
                ),
                filepath=filepath,
                resource_address=f"azurerm_storage_account.{rname}",
                suggested_fix=(
                    f'resource "azurerm_storage_account" "{rname}" {{\n'
                    f'  min_tls_version = "TLS1_2"\n'
                    f"}}"
                ),
            ))
    return findings


def check_service_principal_scope(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag role assignments at subscription scope."""
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        if rtype != "azurerm_role_assignment":
            continue
        scope = str(config.get("scope", ""))
        role = str(config.get("role_definition_name", ""))
        if "subscription" in scope.lower() and role in ("Owner", "Contributor"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.SECURITY,
                title="Broad role assignment at subscription scope",
                message=(
                    f"Role assignment '{rname}' grants '{role}' at "
                    f"subscription scope. This is overly permissive — scope "
                    f"to a specific resource group instead."
                ),
                filepath=filepath,
                resource_address=f"azurerm_role_assignment.{rname}",
                suggested_fix=(
                    f'resource "azurerm_role_assignment" "{rname}" {{\n'
                    f"  scope                = azurerm_resource_group.main.id\n"
                    f'  role_definition_name = "Contributor"\n'
                    f"  principal_id         = azuread_service_principal.main.id\n"
                    f"}}"
                ),
            ))
    return findings


def run_all_checks(parsed: dict, filepath: Path) -> list[Finding]:
    """Run all security checks against a parsed HCL file."""
    checks = [
        check_public_network_access,
        check_storage_network_rules,
        check_tls_version,
        check_service_principal_scope,
    ]
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check(parsed, filepath))
    return findings
