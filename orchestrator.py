"""Orchestrator that dispatches checks across all modules."""

from pathlib import Path

import hcl2

from checks.databricks import run_all_checks as run_databricks_checks
from checks.models import Finding
from checks.project import Project
from checks.project import run_all_checks as run_project_checks
from checks.security import run_all_checks as run_security_checks
from checks.standards import run_all_checks as run_standards_checks

# Directories that never contain user-authored Terraform worth auditing.
SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv"}


def parse_tf_file(filepath: Path) -> dict | None:
    """Parse a single .tf file into a Python dict. Returns None if it cannot be parsed."""
    try:
        with open(filepath) as f:
            return hcl2.load(f)
    except Exception as e:  # noqa: BLE001 - python-hcl2 raises a mix of lark and value errors
        print(f"  ⚠ Could not parse {filepath}: {e}")
        return None


def discover_tf_files(directory: Path, recursive: bool = True) -> list[Path]:
    """Find all .tf files under a directory.

    Recursive by default so a module tree is audited as a whole; the provider
    cache under .terraform/ and other tool directories are skipped.
    """
    pattern = "**/*.tf" if recursive else "*.tf"
    tf_files = sorted(
        p for p in directory.glob(pattern)
        if not any(part in SKIP_DIRS for part in p.relative_to(directory).parts)
    )
    if not tf_files:
        print(f"No .tf files found in {directory}")
    return tf_files


def run_audit(directory: Path, recursive: bool = True, quiet: bool = False) -> list[Finding]:
    """Run all checks against every .tf file under a directory, sorted by severity."""
    tf_files = discover_tf_files(directory, recursive=recursive)
    project = Project(root=directory)
    all_findings: list[Finding] = []

    for filepath in tf_files:
        if not quiet:
            print(f"  Scanning {filepath.relative_to(directory)}...")
        parsed = parse_tf_file(filepath)
        if parsed is None:
            continue
        project.files[filepath] = parsed

        all_findings.extend(run_security_checks(parsed, filepath))
        all_findings.extend(run_standards_checks(parsed, filepath))
        all_findings.extend(run_databricks_checks(parsed, filepath))

    # Checks that only make sense once every file has been read.
    all_findings.extend(run_project_checks(project))

    all_findings.sort(key=lambda f: (f.severity.sort_order, str(f.filepath), f.title))
    return all_findings
