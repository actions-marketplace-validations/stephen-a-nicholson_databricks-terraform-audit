# Databricks Platform Ops Agent

## What this project does

A CLI tool that audits Databricks Terraform configurations using specialised AI subagents. It parses `.tf` files, runs deterministic checks across three domains (security, standards, Databricks-specific), and produces a severity-ranked Markdown audit report with suggested fixes.

## Architecture

```
User runs: uv run python main.py ./path/to/terraform/
    │
    ▼
Orchestrator (orchestrator.py)
    │
    ├── Per-file checks, run once per .tf file
    │   ├── Security (checks/security.py)
    │   ├── Standards (checks/standards.py)
    │   └── Databricks (checks/databricks.py)
    │
    └── Project checks, run once over every parsed file (checks/project.py)
        └── "Does X exist anywhere": metastore assignment, cluster policies, terraform block
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
- **Per-file vs project checks**: A rule that asks "does a resource of type X exist" must be a project check in `checks/project.py`, because X usually lives in a different file from the one that needs it. Per-file checks only inspect the resource in front of them.
- **Recursive by default**: `.tf` files in subdirectories are part of the same project. `.terraform/` is always skipped.
- **Examples are tests**: `examples/clean-terraform/` must produce zero findings and `examples/sample-terraform/` must keep its three criticals. CI asserts both.
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
# JSON for CI, failing on HIGH or above:
uv run python main.py ./infra -f json -o - --fail-on high

# Tests and lint
uv sync --extra dev
uv run pytest -q
uv run ruff check .
```

## How to extend

To add a new check:
1. Decide whether it is per-file or project-level (see above)
2. Per-file: add `def check_something(parsed: dict, filepath: Path) -> list[Finding]` to the right `checks/*.py` module. Project: add `def check_something(project: Project) -> list[Finding]` to `checks/project.py`
3. Register it in that module's `run_all_checks()`
4. Add a passing and a failing case to `tests/test_file_checks.py` or `tests/test_project_checks.py`
5. Add a row to `docs/RULES.md` saying what it checks and why
