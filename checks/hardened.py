"""Hardened-profile checks: the controls the Databricks Security Reference Architecture implements.

All project-level, because private endpoints, DNS zones and firewalls live in
different files (often different modules) from the workspace they protect.

A value like "${var.enable_cmk}" is an expression the tool cannot evaluate. These
rules treat an expression as "configured, decided elsewhere" and do not flag it;
only literal false or absence is a finding.
"""

from checks.helpers import iter_resources
from checks.models import Category, Finding, Severity
from checks.project import Project


def _is_expr(value) -> bool:
    return isinstance(value, str) and "${" in value


def _private_endpoints(project: Project) -> list[tuple[str, dict, object]]:
    """(name, config, filepath) for every azurerm_private_endpoint in the project."""
    out = []
    for path, parsed in project.files.items():
        for rtype, rname, config in iter_resources(parsed):
            if rtype == "azurerm_private_endpoint":
                out.append((rname, config, path))
    return out


def _pe_subresources(config: dict) -> set[str]:
    subs: set[str] = set()
    for conn in config.get("private_service_connection", []) or []:
        c = conn if isinstance(conn, dict) else {}
        for s in c.get("subresource_names", []) or []:
            subs.add(str(s))
    return subs


def _pe_targets(config: dict) -> str:
    return " ".join(
        str((c if isinstance(c, dict) else {}).get("private_connection_resource_id", ""))
        for c in config.get("private_service_connection", []) or []
    )


def _workspaces(project: Project):
    for path, parsed in project.files.items():
        for rtype, rname, config in iter_resources(parsed):
            if rtype == "azurerm_databricks_workspace":
                yield rname, config, path


def check_backend_private_link(project: Project) -> list[Finding]:
    """Back-end Private Link: NSG rules set to NoAzureDatabricksRules and a databricks_ui_api endpoint."""
    findings: list[Finding] = []
    ui_api_pe = any("databricks_ui_api" in _pe_subresources(c) for _, c, _ in _private_endpoints(project))
    for rname, config, path in _workspaces(project):
        nsg = config.get("network_security_group_rules_required")
        if nsg != "NoAzureDatabricksRules" or not ui_api_pe:
            missing = []
            if nsg != "NoAzureDatabricksRules":
                missing.append('network_security_group_rules_required = "NoAzureDatabricksRules"')
            if not ui_api_pe:
                missing.append("an azurerm_private_endpoint with subresource databricks_ui_api")
            findings.append(Finding(
                rule_id="H001",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                title="Back-end Private Link not configured",
                message=(
                    f"Workspace '{rname}' has no back-end Private Link: missing "
                    f"{' and '.join(missing)}. Without it, cluster traffic to the "
                    f"control plane leaves over the public endpoint."
                ),
                filepath=path,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix=(
                    'network_security_group_rules_required = "NoAzureDatabricksRules"\n\n'
                    'resource "azurerm_private_endpoint" "backend" {\n'
                    "  private_service_connection {\n"
                    "    private_connection_resource_id = azurerm_databricks_workspace.this.id\n"
                    '    subresource_names              = ["databricks_ui_api"]\n'
                    "  }\n}"
                ),
            ))
    return findings


def check_frontend_private_link(project: Project) -> list[Finding]:
    """Front-end Private Link: a browser_authentication endpoint and public access not left on."""
    findings: list[Finding] = []
    webauth_pe = any("browser_authentication" in _pe_subresources(c) for _, c, _ in _private_endpoints(project))
    for rname, config, path in _workspaces(project):
        public = config.get("public_network_access_enabled")
        public_on = public is True or (public is None)
        if not webauth_pe or public_on:
            findings.append(Finding(
                rule_id="H002",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                title="Front-end Private Link not configured",
                message=(
                    f"Workspace '{rname}': "
                    + ("no browser_authentication private endpoint" if not webauth_pe else "")
                    + (" and " if (not webauth_pe and public_on) else "")
                    + ("public_network_access_enabled is true or unset" if public_on else "")
                    + ". Users reach the workspace UI over the internet."
                ),
                filepath=path,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix=(
                    "public_network_access_enabled = false\n\n"
                    'resource "azurerm_private_endpoint" "webauth" {\n'
                    "  private_service_connection {\n"
                    "    private_connection_resource_id = azurerm_databricks_workspace.this.id\n"
                    '    subresource_names              = ["browser_authentication"]\n'
                    "  }\n}"
                ),
            ))
    return findings


def check_storage_private_endpoints(project: Project) -> list[Finding]:
    """Every storage account should be reached over a dfs (and blob) private endpoint."""
    findings: list[Finding] = []
    pes = _private_endpoints(project)
    for path, parsed in project.files.items():
        for rtype, rname, config in iter_resources(parsed):
            if rtype != "azurerm_storage_account":
                continue
            ref = f"azurerm_storage_account.{rname}"
            has_dfs = any(
                "dfs" in _pe_subresources(c) and (ref in _pe_targets(c) or _is_expr(_pe_targets(c)))
                for _, c, _ in pes
            )
            if not has_dfs:
                findings.append(Finding(
                    rule_id="H003",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    title="Storage account without a dfs private endpoint",
                    message=(
                        f"Storage account '{rname}' has no azurerm_private_endpoint with "
                        f"subresource dfs pointing at it. Lakehouse traffic to this account "
                        f"will use the public storage endpoint."
                    ),
                    filepath=path,
                    resource_address=ref,
                    suggested_fix=(
                        'resource "azurerm_private_endpoint" "dfs" {\n'
                        "  private_service_connection {\n"
                        f"    private_connection_resource_id = {ref}.id\n"
                        '    subresource_names              = ["dfs"]\n'
                        "  }\n}"
                    ),
                ))
    return findings


def check_customer_managed_keys(project: Project) -> list[Finding]:
    """Managed services and DBFS root encrypted with customer-managed keys."""
    findings: list[Finding] = []
    for rname, config, path in _workspaces(project):
        cmk = config.get("customer_managed_key_enabled")
        ms = config.get("managed_services_cmk_key_vault_key_id")
        ok = (cmk is True or _is_expr(cmk)) and (ms not in (None, "", False))
        if not ok:
            findings.append(Finding(
                rule_id="H004",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                title="Customer-managed keys not configured",
                message=(
                    f"Workspace '{rname}' does not set both customer_managed_key_enabled and "
                    f"managed_services_cmk_key_vault_key_id. Notebooks, secrets and DBFS "
                    f"root are encrypted with Microsoft-managed keys."
                ),
                filepath=path,
                resource_address=f"azurerm_databricks_workspace.{rname}",
                suggested_fix=(
                    "customer_managed_key_enabled          = true\n"
                    "managed_services_cmk_key_vault_key_id = azurerm_key_vault_key.managed_services.id\n"
                    "managed_disk_cmk_key_vault_key_id     = azurerm_key_vault_key.managed_disk.id"
                ),
            ))
    return findings


def check_serverless_ncc(project: Project) -> list[Finding]:
    """Serverless compute egress governed by a Network Connectivity Configuration."""
    types = project.resource_types()
    if "azurerm_databricks_workspace" not in types:
        return []
    if "databricks_mws_ncc_binding" in types or "databricks_mws_network_connectivity_config" in types:
        return []
    return [Finding(
        rule_id="H005",
        severity=Severity.MEDIUM,
        category=Category.DATABRICKS,
        title="No Network Connectivity Configuration for serverless",
        message=(
            "No databricks_mws_network_connectivity_config or databricks_mws_ncc_binding "
            "in the project. Serverless compute will reach storage over public endpoints "
            "with no stable egress identity for firewall rules."
        ),
        filepath=project._anchor("azurerm_databricks_workspace"),
        suggested_fix=(
            'resource "databricks_mws_network_connectivity_config" "this" {\n'
            '  name   = "ncc-${var.environment}"\n'
            "  region = var.location\n}\n\n"
            'resource "databricks_mws_ncc_binding" "this" {\n'
            "  network_connectivity_config_id = databricks_mws_network_connectivity_config.this.network_connectivity_config_id\n"
            "  workspace_id                   = azurerm_databricks_workspace.this.workspace_id\n}"
        ),
    )]


def check_private_dns_zone(project: Project) -> list[Finding]:
    """A privatelink.azuredatabricks.net zone exists when Databricks private endpoints do."""
    pes = _private_endpoints(project)
    needs_zone = any(
        _pe_subresources(c) & {"databricks_ui_api", "browser_authentication"} for _, c, _ in pes
    )
    if not needs_zone:
        return []
    for parsed in project.files.values():
        for rtype, _, config in iter_resources(parsed):
            if rtype == "azurerm_private_dns_zone" and "azuredatabricks" in str(config.get("name", "")):
                return []
            if rtype == "azurerm_private_dns_zone" and _is_expr(config.get("name")):
                return []  # zone name computed; cannot tell, do not flag
    # Zones may be supplied from outside the project (as the SRA allows); only flag if
    # no private_dns_zone_group references them either.
    if any(c.get("private_dns_zone_group") for _, c, _ in pes):
        return []
    return [Finding(
        rule_id="H006",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        title="Databricks private endpoints without a private DNS zone",
        message=(
            "Private endpoints for databricks_ui_api or browser_authentication exist but "
            "no privatelink.azuredatabricks.net zone is declared or linked. Without DNS, "
            "the endpoints resolve to public addresses and the Private Link is bypassed."
        ),
        filepath=project._anchor("azurerm_private_endpoint"),
        suggested_fix=(
            'resource "azurerm_private_dns_zone" "databricks" {\n'
            '  name                = "privatelink.azuredatabricks.net"\n'
            "  resource_group_name = azurerm_resource_group.main.name\n}"
        ),
    )]


def check_egress_control(project: Project) -> list[Finding]:
    """Outbound traffic from Databricks subnets goes through a firewall or a route table."""
    types = project.resource_types()
    if "azurerm_databricks_workspace" not in types:
        return []
    if types & {"azurerm_firewall", "azurerm_route_table", "azurerm_subnet_route_table_association"}:
        return []
    return [Finding(
        rule_id="H007",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        title="No egress control on Databricks subnets",
        message=(
            "No azurerm_firewall or azurerm_route_table in the project. Clusters can "
            "reach any internet destination, which is the data exfiltration path a "
            "hardened deployment is meant to close."
        ),
        filepath=project._anchor("azurerm_databricks_workspace"),
        suggested_fix=(
            'resource "azurerm_route_table" "databricks" {\n'
            "  route {\n"
            '    name                   = "to-firewall"\n'
            '    address_prefix         = "0.0.0.0/0"\n'
            '    next_hop_type          = "VirtualAppliance"\n'
            "    next_hop_in_ip_address = azurerm_firewall.this.ip_configuration[0].private_ip_address\n"
            "  }\n}"
        ),
    )]
