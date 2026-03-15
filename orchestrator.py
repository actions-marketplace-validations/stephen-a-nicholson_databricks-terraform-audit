"""Orchestrator that dispatches checks across all modules."""

from pathlib import Path

import hcl2

from checks.databricks import run_all_checks as run_databricks_checks
from checks.models import Finding
from checks.security import run_all_checks as run_security_checks
from checks.standards import run_all_checks as run_standards_checks


def parse_tf_file(filepath: Path) -> dict | None:
    """Parse a single .tf file into a Python dict."""
    try:
        with open(filepath) as f:
            return hcl2.load(f)
    except Exception as e:
        print(f"  ⚠ Could not parse {filepath}: {e}")
        return None


def discover_tf_files(directory: Path) -> list[Path]:
    """Find all .tf files in a directory (non-recursive)."""
    tf_files = sorted(directory.glob("*.tf"))
    if not tf_files:
        print(f"No .tf files found in {directory}")
    return tf_files


def run_audit(directory: Path) -> list[Finding]:
    """Run all checks against all .tf files in a directory."""
    tf_files = discover_tf_files(directory)
    all_findings: list[Finding] = []

    for filepath in tf_files:
        print(f"  Scanning {filepath.name}...")
        parsed = parse_tf_file(filepath)
        if parsed is None:
            continue

        # Dispatch to all three checker modules
        all_findings.extend(run_security_checks(parsed, filepath))
        all_findings.extend(run_standards_checks(parsed, filepath))
        all_findings.extend(run_databricks_checks(parsed, filepath))

    # Sort by severity (critical first)
    all_findings.sort(key=lambda f: f.severity.sort_order)

    return all_findings
