"""End-to-end: the shipped examples behave as documented."""

import json
import subprocess
import sys
from pathlib import Path

from orchestrator import run_audit

ROOT = Path(__file__).resolve().parent.parent


def test_sample_terraform_has_expected_criticals(sample_dir: Path) -> None:
    findings = run_audit(sample_dir, quiet=True)
    titles = {f.title for f in findings if f.severity.value == "CRITICAL"}
    assert titles == {
        "Databricks workspace without VNet injection",
        "No Unity Catalog metastore assignment",
        "Public network access enabled",
    }


def test_clean_terraform_has_no_findings(clean_dir: Path) -> None:
    findings = run_audit(clean_dir, quiet=True)
    assert findings == [], [str(f) for f in findings]


def test_findings_sorted_by_severity(sample_dir: Path) -> None:
    findings = run_audit(sample_dir, quiet=True)
    orders = [f.severity.sort_order for f in findings]
    assert orders == sorted(orders)


def test_cli_json_output_and_fail_on(sample_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "main.py", str(sample_dir), "-q", "-o", "-", "-f", "json", "--fail-on", "high"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["total"] == len(payload["findings"])
    assert {"severity", "category", "title", "message", "file", "resource", "suggested_fix"} <= set(
        payload["findings"][0]
    )


def test_cli_passes_clean_dir_with_fail_on(clean_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "main.py", str(clean_dir), "-q", "-o", "-", "--fail-on", "low"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
