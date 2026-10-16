"""Hardened profile: SRA passes, baseline-clean fixture fails in the expected places, config works."""

from pathlib import Path

from checks.registry import PROFILES, rules_for
from config import Config, ConfigError, load_config
from orchestrator import run_audit

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "examples" / "clean-terraform"
HARDENED = ROOT / "examples" / "hardened-terraform"


def test_profiles_are_cumulative() -> None:
    base = {r.id for r in rules_for("baseline")}
    hard = {r.id for r in rules_for("hardened")}
    assert base < hard
    assert all(r.startswith("H") for r in hard - base)
    assert PROFILES == ["baseline", "hardened"]


def test_clean_baseline_fixture_fails_hardened_where_expected() -> None:
    findings = run_audit(CLEAN, quiet=True, config=Config(profile="hardened"))
    hardened_ids = sorted({f.rule_id for f in findings if f.rule_id.startswith("H")})
    assert hardened_ids == ["H001", "H002", "H003", "H004", "H005", "H007"]
    assert all(f.rule_id for f in findings), "every finding carries a rule id"


def test_hardened_fixture_passes_hardened() -> None:
    findings = run_audit(HARDENED, quiet=True, config=Config(profile="hardened"))
    assert findings == [], [f"{f.rule_id} {f.title} {f.filepath.name}" for f in findings]


def test_disabled_rule_is_skipped_and_needs_reason(tmp_path: Path) -> None:
    (tmp_path / ".dbx-audit.toml").write_text(
        'profile = "hardened"\n[rules.H004]\nenabled = false\nreason = "CMK handled in the landing zone"\n'
    )
    cfg = load_config(tmp_path)
    assert cfg.profile == "hardened" and cfg.disabled == {"H004": "CMK handled in the landing zone"}
    assert "H004" not in {r.id for r in rules_for(cfg.profile, set(cfg.disabled))}

    (tmp_path / ".dbx-audit.toml").write_text('[rules.H004]\nenabled = false\n')
    try:
        load_config(tmp_path)
    except ConfigError as e:
        assert "reason" in str(e)
    else:
        raise AssertionError("disabling without a reason must be rejected")


def test_required_tags_override(tmp_path: Path) -> None:
    (tmp_path / ".dbx-audit.toml").write_text('required_tags = ["Team"]\n')
    (tmp_path / "main.tf").write_text(
        'resource "azurerm_resource_group" "g" { name = "g" location = "uksouth" tags = { Team = "x" } }'
    )
    findings = run_audit(tmp_path, quiet=True, config=load_config(tmp_path))
    assert not [f for f in findings if f.rule_id == "T001"]
