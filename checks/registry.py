"""Every rule the tool knows about, with an id, a profile and a scope.

Profiles are cumulative: `hardened` runs everything in `baseline` plus its own.
"""

from collections.abc import Callable
from dataclasses import dataclass

from checks import databricks, hardened, project, security, standards

PROFILES = ["baseline", "hardened"]


@dataclass(frozen=True)
class Rule:
    id: str
    profile: str          # the lowest profile that includes this rule
    scope: str            # "file" or "project"
    fn: Callable
    title: str


RULES: list[Rule] = [
    # Security, per file
    Rule("S001", "baseline", "file", security.check_public_network_access, "Public network access"),
    Rule("S002", "baseline", "file", security.check_storage_network_rules, "Storage account network rules"),
    Rule("S003", "baseline", "file", security.check_tls_version, "Storage account TLS version"),
    Rule("S004", "baseline", "file", security.check_service_principal_scope, "Role assignment scope"),
    # Standards, per file
    Rule("T001", "baseline", "file", standards.check_required_tags, "Required tags"),
    Rule("T002", "baseline", "file", standards.check_provider_version, "Provider version pinned"),
    Rule("T003", "baseline", "file", standards.check_lifecycle_protection, "prevent_destroy on stateful resources"),
    Rule("T004", "baseline", "file", standards.check_hardcoded_values, "Hardcoded IDs"),
    # Databricks, per file
    Rule("D001", "baseline", "file", databricks.check_legacy_hive_metastore, "Legacy hive_metastore reference"),
    Rule("D002", "baseline", "file", databricks.check_vnet_injection, "VNet injection and secure cluster connectivity"),
    Rule("D003", "baseline", "file", databricks.check_cluster_without_policy, "Cluster uses a policy"),
    Rule("D004", "baseline", "file", databricks.check_workspace_sku, "Premium SKU"),
    # Project-level
    Rule("P001", "baseline", "project", project.check_unity_catalog_assignment, "Unity Catalog metastore assignment"),
    Rule("P002", "baseline", "project", project.check_cluster_policy_exists, "Cluster policies exist"),
    Rule("P003", "baseline", "project", project.check_terraform_block_exists, "terraform block exists"),
    # Hardened
    Rule("H001", "hardened", "project", hardened.check_backend_private_link, "Back-end Private Link"),
    Rule("H002", "hardened", "project", hardened.check_frontend_private_link, "Front-end Private Link"),
    Rule("H003", "hardened", "project", hardened.check_storage_private_endpoints, "Storage private endpoints"),
    Rule("H004", "hardened", "project", hardened.check_customer_managed_keys, "Customer-managed keys"),
    Rule("H005", "hardened", "project", hardened.check_serverless_ncc, "Serverless NCC"),
    Rule("H006", "hardened", "project", hardened.check_private_dns_zone, "Private DNS zone"),
    Rule("H007", "hardened", "project", hardened.check_egress_control, "Egress control"),
]


def rules_for(profile: str, disabled: set[str] | None = None) -> list[Rule]:
    """Rules active for a profile, minus any the config disables."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; expected one of {PROFILES}")
    level = PROFILES.index(profile)
    disabled = disabled or set()
    return [r for r in RULES if PROFILES.index(r.profile) <= level and r.id not in disabled]


def by_id(rule_id: str) -> Rule:
    for r in RULES:
        if r.id == rule_id:
            return r
    raise KeyError(rule_id)
