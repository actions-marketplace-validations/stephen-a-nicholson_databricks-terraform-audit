# Experiment: Databricks' own Azure examples

Run on 16 October 2026 against every Azure (`adb-*`) module and example in
[databricks/terraform-databricks-examples](https://github.com/databricks/terraform-databricks-examples)
plus [Azure/terraform-azurerm-avm-res-databricks-workspace](https://github.com/Azure/terraform-azurerm-avm-res-databricks-workspace):
29 directories, 131 findings.

![Findings by rule](findings_by_rule.png)

What it told me, in order of usefulness:

1. **My own tool had a false positive.** The first run flagged eight workspaces for
   "secure cluster connectivity not enabled" because `no_public_ip` was unset. The
   azurerm provider has defaulted that to `true` since v3.104.0, so every one of
   those was wrong. The rule is now HIGH only when it is explicitly `false`, and LOW
   advisory when unset. Running a tool over code you did not write is the fastest
   way to find out what it does not understand.
2. **Standards, not security, dominate.** The biggest bar is `prevent_destroy`
   missing on storage accounts and workspaces. Example code has no reason to set it,
   so that is a comment on production defaults rather than the examples. Same for
   tags, which reflect my required set, not a universal one.
3. **The security findings cluster on storage accounts**: 13 with no network rules
   and 14 not enforcing TLS 1.2. Those are two lines each and worth copying into
   any example that will be forked.
4. **Ten "no metastore assignment" criticals are mostly scope.** The modules that
   provision a workspace leave Unity Catalog to a separate module by design, and the
   tool cannot see across repositories. On a real project they would live in the
   same repo and the finding would be fair. The one genuine critical is the
   Overwatch main workspace module, which creates a workspace with managed
   networking and no VNet injection.

Reproduce: clone the two repos, run `main.py <dir> -q -f json -o results/<name>.json`
per directory, then `python chart.py` with `summary.json` in `results/`.
