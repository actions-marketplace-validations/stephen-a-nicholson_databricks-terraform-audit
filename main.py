"""CLI entrypoint for the Databricks Terraform Audit."""

import json
import sys
from pathlib import Path

import click

from checks.models import Finding, Severity
from checks.registry import PROFILES
from config import ConfigError, load_config
from orchestrator import run_audit
from report import generate_report, write_report

EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
FAIL_CHOICES = ["critical", "high", "medium", "low", "none"]


def _exceeds_threshold(findings: list[Finding], fail_on: str) -> bool:
    """True if any finding is at or above the fail_on severity."""
    if fail_on == "none":
        return False
    threshold = Severity[fail_on.upper()].sort_order
    return any(f.severity.sort_order <= threshold for f in findings)


@click.command()
@click.argument("target_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=Path("audit_report.md"),
    show_default=True,
    help="Where to write the report. Use '-' to print to stdout.",
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    show_default=True,
    help="Report format. JSON is intended for CI and other tooling.",
)
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_CHOICES),
    default="none",
    show_default=True,
    help="Exit non-zero if any finding is at or above this severity.",
)
@click.option(
    "--no-recursive",
    is_flag=True,
    help="Only scan .tf files in TARGET_DIR itself, not subdirectories.",
)
@click.option(
    "--profile", "-p",
    type=click.Choice(PROFILES),
    default=None,
    help="Rule profile. Overrides the profile in .dbx-audit.toml. Default: baseline.",
)
@click.option(
    "--config", "-c", "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Config file. Default: .dbx-audit.toml in TARGET_DIR if present.",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress per-file progress output.")
def main(
    target_dir: Path,
    output: Path,
    fmt: str,
    fail_on: str,
    no_recursive: bool,
    profile: str | None,
    config_path: Path | None,
    quiet: bool,
) -> None:
    """Audit Databricks Terraform configurations.

    TARGET_DIR is the directory containing .tf files to audit. Subdirectories
    are included by default; the .terraform provider cache is always skipped.
    """
    try:
        config = load_config(target_dir, config_path)
    except ConfigError as e:
        raise click.ClickException(str(e)) from e
    if profile:
        config.profile = profile

    if not quiet:
        src = f" (config: {config.source})" if config.source else ""
        click.echo(f"\n🔍 Auditing Terraform configs in {target_dir} [profile: {config.profile}]{src}\n")
        for rule_id, reason in config.disabled.items():
            click.echo(f"  skipping {rule_id}: {reason}")

    findings = run_audit(target_dir, recursive=not no_recursive, quiet=quiet, config=config)

    if not quiet:
        if findings:
            click.echo(f"\n⚠ Found {len(findings)} issue(s):\n")
            for f in findings:
                rel = f.filepath.relative_to(target_dir)
                click.echo(f"  {EMOJI[f.severity.value]} [{f.severity.value}] {f.rule_id} {f.title} — {rel}")
        else:
            click.echo("\n✅ No issues found!")

    if fmt == "json":
        payload = json.dumps(
            {
                "target": str(target_dir),
                "profile": config.profile,
                "total": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        )
        if str(output) == "-":
            click.echo(payload)
        else:
            output.write_text(payload)
            if not quiet:
                click.echo(f"\n📄 JSON written to {output}")
    elif str(output) == "-":
        click.echo(generate_report(findings, target_dir))
    else:
        write_report(findings, target_dir, output, quiet=quiet)

    if _exceeds_threshold(findings, fail_on):
        if not quiet:
            click.echo(f"\n❌ Findings at or above {fail_on.upper()} severity; failing.", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
