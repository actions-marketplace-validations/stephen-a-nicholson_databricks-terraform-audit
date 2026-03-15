"""CLI entrypoint for the Databricks Platform Ops Agent."""

from pathlib import Path

import click

from orchestrator import run_audit
from report import write_report


@click.command()
@click.argument("target_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=Path("audit_report.md"),
    help="Output path for the audit report.",
)
def main(target_dir: Path, output: Path) -> None:
    """Audit Databricks Terraform configurations.

    TARGET_DIR is the directory containing .tf files to audit.
    """
    click.echo(f"\n🔍 Auditing Terraform configs in {target_dir}...\n")

    findings = run_audit(target_dir)

    if findings:
        click.echo(f"\n⚠ Found {len(findings)} issue(s):\n")
        for f in findings:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}[f.severity.value]
            click.echo(f"  {emoji} [{f.severity.value}] {f.title} — {f.filepath.name}")
    else:
        click.echo("\n✅ No issues found!")

    write_report(findings, target_dir, output)


if __name__ == "__main__":
    main()
