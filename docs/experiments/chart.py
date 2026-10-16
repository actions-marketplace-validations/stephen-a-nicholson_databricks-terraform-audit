import json, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

d = json.load(open("results/summary.json"))
rows = d["bytitle"]  # (title, n, severity), most common first
rows = sorted(rows, key=lambda r: r[1])  # ascending so biggest at top in barh
status = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#86b6ef"}
labels = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low (advisory)"}
# shorten rule names
short = {
 "Stateful resource missing lifecycle protection": "No prevent_destroy on stateful resource",
 "Storage account not enforcing TLS 1.2": "Storage account not enforcing TLS 1.2",
 "Missing required tags": "No tags on resource",
 "Provider version not pinned": "Provider version not pinned",
 "Storage account missing network rules": "Storage account open to all networks",
 "No cluster policies defined": "No cluster policies defined",
 "No Unity Catalog metastore assignment": "No Unity Catalog metastore assignment",
 "Secure cluster connectivity relies on provider default": "no_public_ip left to provider default",
 "Workspace public network access relies on provider default": "Public network access left to provider default",
 "Hardcoded UUID detected": "Hardcoded subscription or object ID",
 "Missing some required tags": "Some required tags missing",
 "Cluster defined without policy": "Cluster without a policy",
 "Databricks workspace without VNet injection": "Workspace without VNet injection",
}
surface, ink, ink2, grid = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e1"
fig, ax = plt.subplots(figsize=(11, 7.2), dpi=200)
fig.patch.set_facecolor(surface); ax.set_facecolor(surface)
y = range(len(rows))
ax.barh(y, [r[1] for r in rows], color=[status[r[2]] for r in rows], height=0.62, edgecolor=surface, linewidth=2)
ax.set_yticks(list(y)); ax.set_yticklabels([short.get(r[0], r[0]) for r in rows], fontsize=11, color=ink)
for i, r in enumerate(rows):
    ax.text(r[1] + 0.4, i, str(r[1]), va="center", fontsize=10.5, color=ink2)
for s in ["top", "right", "left"]: ax.spines[s].set_visible(False)
ax.spines["bottom"].set_color(grid); ax.tick_params(axis="x", colors=ink2, labelsize=10); ax.tick_params(axis="y", length=0)
ax.xaxis.grid(True, color=grid, linewidth=0.8); ax.set_axisbelow(True)
ax.set_xlim(0, max(r[1] for r in rows) * 1.12)
ax.set_xlabel("Findings across 29 Terraform directories", color=ink2, fontsize=10.5)
total = sum(r[1] for r in rows)
fig.text(0.02, 0.955, "What a Terraform audit finds in Databricks' own Azure examples", fontsize=16, weight="bold", color=ink, ha="left")
fig.text(0.02, 0.895, f"{total} findings from 13 rules, run over every Azure module and example in databricks/terraform-databricks-examples plus the Azure Verified Module.\nStandards, not security, dominate.",
         fontsize=10.5, color=ink2, ha="left", wrap=True)
handles = [Patch(color=status[k], label=labels[k]) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]]
ax.legend(handles=handles, loc="lower right", frameon=False, fontsize=10, title="Severity", title_fontsize=10)
fig.text(0.02, 0.015, "Tool: github.com/stephen-a-nicholson/databricks-terraform-audit  ·  Example code is intentionally minimal; tag and lifecycle rules reflect production defaults, not a flaw in the examples.",
         fontsize=8.5, color=ink2, ha="left")
plt.subplots_adjust(left=0.36, right=0.97, top=0.85, bottom=0.11)
fig.savefig("findings_by_rule.png", facecolor=surface)
print("ok")
