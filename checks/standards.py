"""Standards checks for Terraform configurations."""

import re
from pathlib import Path

from checks.helpers import iter_resources
from checks.models import Category, Finding, Severity

REQUIRED_TAGS = {"Environment", "Owner", "CostCentre", "Project"}

TAGGABLE_RESOURCES = {
    "azurerm_resource_group",
    "azurerm_storage_account",
    "azurerm_databricks_workspace",
    "azurerm_key_vault",
    "azurerm_virtual_network",
    "azurerm_subnet",
    "azurerm_network_security_group",
    "azurerm_log_analytics_workspace",
}

STATEFUL_RESOURCES = {
    "azurerm_storage_account",
    "azurerm_databricks_workspace",
    "azurerm_key_vault",
    "azurerm_log_analytics_workspace",
}


def check_required_tags(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag resources missing required tags."""
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        if rtype not in TAGGABLE_RESOURCES:
            continue
        tags = config.get("tags", {})
        if not tags:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.STANDARDS,
                title="Missing required tags",
                message=(
                    f"Resource '{rtype}.{rname}' has no tags. "
                    f"Required: {', '.join(sorted(REQUIRED_TAGS))}."
                ),
                filepath=filepath,
                resource_address=f"{rtype}.{rname}",
                suggested_fix=(
                    "tags = {\n"
                    "  Environment = var.environment\n"
                    "  Owner       = var.owner\n"
                    "  CostCentre  = var.cost_centre\n"
                    "  Project     = var.project_name\n"
                    "}"
                ),
            ))
        elif isinstance(tags, dict):
            missing = REQUIRED_TAGS - set(tags.keys())
            if missing:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.STANDARDS,
                    title="Missing some required tags",
                    message=(
                        f"Resource '{rtype}.{rname}' is missing "
                        f"tags: {', '.join(sorted(missing))}."
                    ),
                    filepath=filepath,
                    resource_address=f"{rtype}.{rname}",
                ))
    return findings


def check_provider_version(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag missing or unpinned provider versions."""
    findings: list[Finding] = []
    terraform_blocks = parsed.get("terraform", [])

    has_version_constraint = False
    for block in terraform_blocks:
        for provider_block in block.get("required_providers", []):
            for _provider_name, provider_config in provider_block.items():
                if isinstance(provider_config, dict) and provider_config.get("version"):
                    has_version_constraint = True

    if terraform_blocks and not has_version_constraint:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=Category.STANDARDS,
            title="Provider version not pinned",
            message=(
                "The azurerm provider has no version constraint. "
                "Pin to a specific major version to prevent breaking changes."
            ),
            filepath=filepath,
            suggested_fix=(
                "required_providers {\n"
                "  azurerm = {\n"
                '    source  = "hashicorp/azurerm"\n'
                '    version = "~> 4.0"\n'
                "  }\n"
                "}"
            ),
        ))

    if not terraform_blocks:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=Category.STANDARDS,
            title="Missing terraform block",
            message="No terraform block found. Add required_version and required_providers.",
            filepath=filepath,
            suggested_fix=(
                "terraform {\n"
                '  required_version = ">= 1.5.0"\n\n'
                "  required_providers {\n"
                "    azurerm = {\n"
                '      source  = "hashicorp/azurerm"\n'
                '      version = "~> 4.0"\n'
                "    }\n"
                "  }\n"
                "}"
            ),
        ))
    return findings


def check_lifecycle_protection(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag stateful resources without lifecycle prevent_destroy."""
    findings: list[Finding] = []
    for rtype, rname, config in iter_resources(parsed):
        if rtype not in STATEFUL_RESOURCES:
            continue
        lifecycle = config.get("lifecycle", [{}])
        lc = lifecycle[0] if isinstance(lifecycle, list) else lifecycle
        if not lc.get("prevent_destroy"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.STANDARDS,
                title="Stateful resource missing lifecycle protection",
                message=(
                    f"Resource '{rtype}.{rname}' is stateful but "
                    f"has no lifecycle {{ prevent_destroy = true }}. An accidental "
                    f"terraform destroy could delete this resource and its data."
                ),
                filepath=filepath,
                resource_address=f"{rtype}.{rname}",
                suggested_fix="lifecycle {\n  prevent_destroy = true\n}",
            ))
    return findings


def check_hardcoded_values(parsed: dict, filepath: Path) -> list[Finding]:
    """Flag hardcoded subscription IDs, tenant IDs, and locations."""
    findings: list[Finding] = []
    content = filepath.read_text()

    uuid_pattern = r'["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']'
    for match in re.finditer(uuid_pattern, content, re.IGNORECASE):
        line_num = content[:match.start()].count("\n") + 1
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=Category.STANDARDS,
            title="Hardcoded UUID detected",
            message=(
                f"Found hardcoded UUID '{match.group(1)[:8]}...' at line {line_num}. "
                f"Subscription IDs, tenant IDs, and object IDs should be variables."
            ),
            filepath=filepath,
            suggested_fix=(
                'variable "subscription_id" {\n'
                '  description = "Azure subscription ID"\n'
                "  type        = string\n"
                "}"
            ),
        ))
    return findings


def run_all_checks(parsed: dict, filepath: Path) -> list[Finding]:
    """Run all standards checks against a parsed HCL file."""
    checks = [
        check_required_tags,
        check_provider_version,
        check_lifecycle_protection,
        check_hardcoded_values,
    ]
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check(parsed, filepath))
    return findings
