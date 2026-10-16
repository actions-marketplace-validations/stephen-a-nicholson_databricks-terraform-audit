"""Orchestrator: discover files, parse them, run the active rules, sort the findings."""

from pathlib import Path

import hcl2

from checks import standards
from checks.models import Finding
from checks.project import Project
from checks.registry import Rule, rules_for
from config import Config

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


def _tag(findings: list[Finding], rule: Rule) -> list[Finding]:
    for f in findings:
        f.rule_id = rule.id
    return findings


def run_audit(
    directory: Path,
    recursive: bool = True,
    quiet: bool = False,
    config: Config | None = None,
) -> list[Finding]:
    """Run the rules active under the config's profile against every .tf file."""
    config = config or Config()
    if config.required_tags is not None:
        standards.REQUIRED_TAGS = set(config.required_tags)

    rules = rules_for(config.profile, set(config.disabled))
    file_rules = [r for r in rules if r.scope == "file"]
    project_rules = [r for r in rules if r.scope == "project"]

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
        for rule in file_rules:
            all_findings.extend(_tag(rule.fn(parsed, filepath), rule))

    for rule in project_rules:
        all_findings.extend(_tag(rule.fn(project), rule))

    all_findings.sort(key=lambda f: (f.severity.sort_order, str(f.filepath), f.title))
    return all_findings
