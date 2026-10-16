# Rules

Every rule the audit runs, what it looks for, and why it matters. Severity is the consequence of ignoring it on a real platform, not how hard it is to fix.

Rules are either **per-file** (they only need one `.tf` file) or **project** (they need to see every file, because the thing they're looking for is usually declared in a different file from the one that needs it).

## Security

| Rule | Scope | Severity | What it checks | Why |
|---|---|---|---|---|
| Public network access enabled | per-file | CRITICAL | Any resource with `public_network_access_enabled = true` | For a workspace or storage account this means the control plane or data is reachable from the internet. It's the first thing a security review asks about and the hardest to retrofit once users depend on the public URL. |
| Storage account missing network rules | per-file | HIGH | `azurerm_storage_account` without a `network_rules` block | The default is allow from everywhere. Deny by default with the Databricks subnets allowed is the baseline for a lakehouse storage account. |
| Storage account not enforcing TLS 1.2 | per-file | MEDIUM | `min_tls_version` not set to `TLS1_2` | Older TLS is still accepted unless you say otherwise. Cheap to set, embarrassing to be asked about. |
| Broad role assignment at subscription scope | per-file | HIGH | `azurerm_role_assignment` granting Owner or Contributor at `/subscriptions/...` | A deployment service principal only needs its resource group. Subscription-wide Contributor means a leaked credential can touch everything. |

## Standards

| Rule | Scope | Severity | What it checks | Why |
|---|---|---|---|---|
| Missing required tags | per-file | MEDIUM | Taggable resources with no `tags` block, or missing `Environment`, `Owner`, `CostCentre`, `Project` | Tags are how cost reports and incident pages find the right team. Tags passed via a variable (`tags = var.tags`) are not flagged because their contents can't be inspected statically. `azurerm_subnet` is excluded because it doesn't support tags. |
| Provider version not pinned | per-file | HIGH | A `terraform` block whose `required_providers` has no `version` | Unpinned providers mean two engineers running `terraform init` a month apart get different behaviour. Pin to a major version. |
| Missing terraform block | project | HIGH | No file in the project declares `terraform { }` | Without `required_version` and `required_providers` there's nothing holding the toolchain still. Checked once across the project, since it normally lives in `versions.tf`. |
| Stateful resource missing lifecycle protection | per-file | MEDIUM | Storage, workspace, Key Vault or Log Analytics without `lifecycle { prevent_destroy = true }` | `terraform destroy` on the wrong workspace is a career-defining afternoon. This makes it refuse. |
| Hardcoded UUID detected | per-file | MEDIUM | A UUID literal in quotes anywhere in the file | Subscription, tenant and object IDs belong in variables so the same code deploys to dev, test and prod. |

## Databricks

| Rule | Scope | Severity | What it checks | Why |
|---|---|---|---|---|
| Databricks workspace without VNet injection | per-file | CRITICAL | `azurerm_databricks_workspace` with no `custom_parameters.virtual_network_id` | Managed networking means Databricks picks the address space and you can't reach on-prem, private endpoints or anything else that matters. It can't be changed after creation; the workspace has to be rebuilt. |
| Secure cluster connectivity not enabled | per-file | HIGH | VNet injection present but `no_public_ip` not `true` | Cluster nodes get public IPs. Almost no enterprise network policy allows that. |
| No Unity Catalog metastore assignment | project | CRITICAL | A workspace exists but no `databricks_metastore_assignment` anywhere in the project | Without Unity Catalog the workspace lands on the legacy Hive metastore: no central governance, lineage or fine-grained access control, and a migration later. Checked across files since the assignment normally lives in its own file. |
| Legacy hive_metastore reference found | per-file | HIGH | The string `hive_metastore` anywhere in the file | Something is still pointing at the legacy catalogue. |
| No cluster policies defined | project | HIGH | A workspace exists but no `databricks_cluster_policy` anywhere in the project | Without policies anyone can create any cluster. This is where the surprise bill comes from. |
| Cluster defined without policy | per-file | MEDIUM | `databricks_cluster` with no `policy_id` | The cluster bypasses whatever governance the policies provide. |
| Workspace using Standard SKU | per-file | MEDIUM | `sku = "standard"` | Unity Catalog, cluster policies and audit logs need Premium. Standard is for trying it out, not running it. |

## Adding a rule

A per-file rule is a function in `checks/security.py`, `checks/standards.py` or `checks/databricks.py` with the signature `def check_x(parsed: dict, filepath: Path) -> list[Finding]`, registered in that module's `run_all_checks()`.

A project rule is a function in `checks/project.py` taking a `Project` and returning `list[Finding]`, registered the same way. Use a project rule whenever the question is "does X exist anywhere", since the answer is usually in a different file.

Every rule gets a passing and a failing case in `tests/test_file_checks.py` or `tests/test_project_checks.py`, and a row in this file saying why it exists. The examples under `examples/` are also tests: `clean-terraform` must stay finding-free and `sample-terraform` must keep its three criticals.
