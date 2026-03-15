# databricks-platform-ops-agent

An AI-powered audit agent that checks your Databricks Terraform configurations for security issues, standards violations, and Databricks-specific misconfigurations.

## What it does

Point it at a directory of `.tf` files and it runs **three specialised check modules** in parallel:

| Module | What it checks |
|--------|---------------|
| **Security** | Public network access, missing private endpoints, storage network rules, overly permissive RBAC, service principal scope |
| **Standards** | Required tags, naming conventions, provider version pinning, lifecycle protection, hardcoded values |
| **Databricks** | Unity Catalog configuration, VNet injection, cluster policies, workspace SKU, secure cluster connectivity |

Outputs a severity-ranked **Markdown audit report** with explanations and suggested Terraform fixes.

## AI agent layer

The deterministic Python checks catch known patterns. The three **Claude Code subagents** (in `.claude/agents/`) add a reasoning layer on top:

- They can explain *why* a configuration is risky
- They suggest context-aware fixes based on your specific setup
- They understand trade-offs (e.g., security vs developer experience)

To use the AI layer, run the audit from within [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) and the subagents will be available automatically.

## Quick start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/databricks-platform-ops-agent.git
cd databricks-platform-ops-agent

# Install dependencies
uv sync

# Run against the sample Terraform (ships with deliberate issues)
uv run python main.py ./examples/sample-terraform/

# Run against your own Terraform
uv run python main.py /path/to/your/terraform/
```

## Example output

```
🔍 Auditing Terraform configs in ./examples/sample-terraform/...

  Scanning main.tf...

⚠ Found 10 issue(s):

  🔴 [CRITICAL] Public network access enabled — main.tf
  🔴 [CRITICAL] No Unity Catalog metastore assignment — main.tf
  🔴 [CRITICAL] Databricks workspace without VNet injection — main.tf
  🟠 [HIGH] Storage account missing network rules — main.tf
  🟠 [HIGH] Broad role assignment at subscription scope — main.tf
  🟠 [HIGH] No cluster policies defined — main.tf
  🟡 [MEDIUM] Missing some required tags — main.tf
  🟡 [MEDIUM] Workspace using Standard SKU — main.tf
  🟡 [MEDIUM] Hardcoded UUID detected — main.tf
  🟡 [MEDIUM] Cluster defined without policy — main.tf

📄 Report written to audit_report.md
```

## Using with Claude Code subagents

The real power comes from running this inside Claude Code. The three subagents in `.claude/agents/` are:

- **security-checker** — deep security analysis with read-only access
- **standards-checker** — organisational standards and code quality audit
- **databricks-checker** — Databricks platform best practices review

Each subagent runs in its own context window with `Read`, `Grep`, and `Glob` tools only (no write access). They can reason about your specific configuration and suggest tailored fixes.

```bash
# Inside Claude Code, just ask:
# "Run the security checker against my terraform directory"
# "Have the databricks checker review my workspace config"
# "Audit this entire terraform project"
```

## Adding new checks

1. Add a check function in the appropriate `checks/*.py` module
2. Function signature: `def check_something(parsed: dict, filepath: Path) -> list[Finding]`
3. Register it in the module's `run_all_checks()` function
4. The orchestrator picks it up automatically

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) — package manager (`pip install uv` or see uv docs)
- No Terraform CLI, no cloud credentials, no API keys

## License

MIT
