# Databricks Platform Ops Agent

## What this project does

A CLI tool that audits Databricks Terraform configurations using specialised AI subagents. It parses `.tf` files, runs deterministic checks across three domains (security, standards, Databricks-specific), and produces a severity-ranked Markdown audit report with suggested fixes.

## Architecture

```
User runs: python main.py ./path/to/terraform/
    │
    ▼
Orchestrator (orchestrator.py)
    │
    ├── Security Checker (checks/security.py)
    │   └── Public access, private endpoints, RBAC, service principals
    │
    ├── Standards Checker (checks/standards.py)
    │   └── Naming conventions, required tags, lifecycle blocks, deprecated syntax
    │
    └── Databricks Checker (checks/databricks.py)
        └── Unity Catalog, VNet injection, cluster policies, log delivery
    │
    ▼
Report Generator (report.py)
    │
    ▼
Markdown audit report with findings + suggested fixes
```

## Key design decisions

- **HCL parsing**: Use `python-hcl2` to parse `.tf` files into Python dicts. Never use regex for Terraform parsing.
- **Finding model**: Every check returns a list of `Finding` dataclasses (see `checks/models.py`) with severity, message, file path, and suggested fix.
- **Subagents**: The `.claude/agents/` directory contains three read-only subagents. These add an AI reasoning layer on top of the deterministic Python checks — they can explain *why* something is a problem and suggest context-aware fixes.
- **No Terraform CLI dependency**: This tool works on `.tf` source files only. It does not require `terraform init`, `terraform plan`, or any provider credentials.

## Tech stack

- Python 3.11+
- `uv` for dependency management and packaging
- `python-hcl2` for HCL parsing
- `click` for CLI
- `dataclasses` for the Finding model
- No external AI SDKs — the subagents run natively in Claude Code

## File conventions

- All Python files use type hints
- Functions that check Terraform return `list[Finding]`
- Check functions take a parsed HCL dict and the source file path as arguments
- Use `pathlib.Path` throughout, not string paths

## How to run

```bash
# Install dependencies
uv sync

# Run the audit
uv run python main.py ./examples/sample-terraform/

# Output: audit_report.md in the current directory
```

## How to extend

To add a new check:
1. Add a function in the appropriate `checks/*.py` module
2. The function signature should be: `def check_something(parsed: dict, filepath: Path) -> list[Finding]`
3. Register it in the module's `run_all_checks()` function
4. The orchestrator will pick it up automatically
