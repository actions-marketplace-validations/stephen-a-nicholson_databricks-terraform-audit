"""Project-level checks that need to see every file at once.

A Terraform project is normally split across many files: versions.tf,
workspace.tf, unity_catalog.tf and so on. Checks that ask "does a resource of
this type exist anywhere" have to run over the whole project, otherwise they
flag workspace.tf for lacking something that lives in the file next to it.
"""

from dataclasses import dataclass, field
from pathlib import Path

from checks.helpers import iter_resources
from checks.models import Category, Finding, Severity


@dataclass
class Project:
    """Every parsed .tf file in the audited directory, keyed by path."""

    root: Path
    files: dict[Path, dict] = field(default_factory=dict)

    def resource_types(self) -> set[str]:
        types: set[str] = set()
        for parsed in self.files.values():
            for rtype, _, _ in iter_resources(parsed):
                types.add(rtype)
        return types

    def files_with_resource(self, target_type: str) -> list[Path]:
        return [
            path for path, parsed in self.files.items()
            if any(rtype == target_type for rtype, _, _ in iter_resources(parsed))
        ]

    def has_terraform_block(self) -> bool:
        return any(parsed.get("terraform") for parsed in self.files.values())

    def _anchor(self, target_type: str) -> Path:
        """The file to attach a project-level finding to: the one declaring target_type, else the first."""
        matches = self.files_with_resource(target_type)
        if matches:
            return matches[0]
        return next(iter(self.files), self.root)


def check_unity_catalog_assignment(project: Project) -> list[Finding]:
    """A workspace exists but no metastore assignment does, anywhere in the project."""
    types = project.resource_types()
    if "azurerm_databricks_workspace" not in types:
        return []
    if "databricks_metastore_assignment" in types:
        return []
    return [Finding(
        severity=Severity.CRITICAL,
        category=Category.DATABRICKS,
        title="No Unity Catalog metastore assignment",
        message=(
            "A Databricks workspace is defined but no databricks_metastore_assignment "
            "resource exists anywhere in the project. Without Unity Catalog the "
            "workspace falls back to the legacy hive_metastore with no centralised "
            "governance, lineage or access control."
        ),
        filepath=project._anchor("azurerm_databricks_workspace"),
        suggested_fix=(
            'resource "databricks_metastore_assignment" "this" {\n'
            "  workspace_id = azurerm_databricks_workspace.this.workspace_id\n"
            "  metastore_id = databricks_metastore.this.id\n"
            "}"
        ),
    )]


def check_cluster_policy_exists(project: Project) -> list[Finding]:
    """A workspace exists but no cluster policy does, anywhere in the project."""
    types = project.resource_types()
    if "azurerm_databricks_workspace" not in types:
        return []
    if "databricks_cluster_policy" in types:
        return []
    return [Finding(
        severity=Severity.HIGH,
        category=Category.DATABRICKS,
        title="No cluster policies defined",
        message=(
            "A Databricks workspace exists but no databricks_cluster_policy is "
            "defined anywhere in the project. Without policies, users can create "
            "clusters with any configuration, which is how costs and environment "
            "drift get out of hand."
        ),
        filepath=project._anchor("azurerm_databricks_workspace"),
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
    )]


def check_terraform_block_exists(project: Project) -> list[Finding]:
    """No file in the project declares a terraform { } block."""
    if not project.files or project.has_terraform_block():
        return []
    return [Finding(
        severity=Severity.HIGH,
        category=Category.STANDARDS,
        title="Missing terraform block",
        message=(
            "No terraform block found in any file. Add required_version and "
            "required_providers so every engineer and every pipeline runs the same "
            "versions."
        ),
        filepath=next(iter(project.files)),
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
    )]


def run_all_checks(project: Project) -> list[Finding]:
    """Run every project-level check."""
    checks = [
        check_unity_catalog_assignment,
        check_cluster_policy_exists,
        check_terraform_block_exists,
    ]
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check(project))
    return findings
