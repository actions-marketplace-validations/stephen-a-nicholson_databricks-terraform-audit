import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
surface, ink, ink2, grid, hi, lo = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e1", "#2a78d6", "#c9c8c2"
rows = [
 ("Is the workspace VNet-injected, or on managed networking you can't change later?", False, True),
 ("Is there a Unity Catalog metastore assignment, or is it on legacy Hive?", False, True),
 ("Are there cluster policies, so not everyone can create any cluster?", False, True),
 ("Do clusters actually use a policy?", False, True),
 ("Is the workspace front end public, or was that just the provider default?", False, True),
 ("Do cluster nodes get public IPs (no_public_ip)?", False, True),
 ("Is it the Premium SKU that Unity Catalog and policies need?", False, True),
 ("Does the data plane reach the control plane over Private Link?", True, False),
 ("Is DBFS root encrypted with a customer-managed key?", True, False),
]
fig, ax = plt.subplots(figsize=(11, 7.4), dpi=200); fig.patch.set_facecolor(surface); ax.set_facecolor(surface)
ax.set_xlim(0, 10); ax.set_ylim(-0.7, len(rows)-0.3); ax.axis("off")
cols = {"Checkov": 7.9, "This tool": 9.3}
for name, x in cols.items():
    ax.text(x, len(rows)-0.35, name, ha="center", va="bottom", fontsize=11.5, weight="bold", color=ink)
for i, (q, ck, me) in enumerate(reversed(rows)):
    y = i
    ax.text(0.1, y, q, va="center", fontsize=11, color=ink)
    ax.plot([0.1, 9.8], [y-0.5, y-0.5], color=grid, linewidth=0.8)
    for x, v in ((cols["Checkov"], ck), (cols["This tool"], me)):
        ax.scatter([x], [y], s=260, color=hi if v else surface, edgecolor=hi if v else lo, linewidth=1.5, zorder=3)
        if v: ax.text(x, y, "✓", ha="center", va="center", fontsize=11, color=surface, weight="bold", zorder=4)
fig.text(0.03, 0.955, "What each tool asks about an Azure Databricks workspace", fontsize=16, weight="bold", color=ink)
fig.text(0.03, 0.89, "Checkov has around 4,000 policies and two of them concern Databricks. Trivy has none. Both are good at storage and general Azure;\nneither knows what a Databricks platform is supposed to look like. Run both.", fontsize=10.5, color=ink2)
fig.text(0.03, 0.03, "Measured on 29 directories from databricks/terraform-databricks-examples and the Azure Verified Module: Checkov 377 findings (39 on Databricks workspaces, from 2 checks);\nthis tool 131 findings (39 Databricks-specific, from 6 rules). No overlap between the two sets.  github.com/stephen-a-nicholson/databricks-terraform-audit", fontsize=8.5, color=ink2)
plt.subplots_adjust(left=0.0, right=1.0, top=0.84, bottom=0.11)
fig.savefig("coverage_matrix.png", facecolor=surface); print("ok")
