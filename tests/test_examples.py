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


def test_unparseable_file_is_a_critical_finding(tmp_path: Path) -> None:
    (tmp_path / "broken.tf").write_text('resource "azurerm_storage_account" "x" {\n  name = \n')
    findings = run_audit(tmp_path, quiet=True)
    assert [f.rule_id for f in findings] == ["X001"]
    assert findings[0].severity.value == "CRITICAL"


def test_json_to_stdout_is_valid_without_quiet(sample_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "main.py", str(sample_dir), "-o", "-", "-f", "json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)  # progress must have gone to stderr
    assert payload["total"] == 17
    assert "Scanning" in result.stderr


def test_empty_directory_passes(tmp_path: Path) -> None:
    assert run_audit(tmp_path, quiet=True) == []
