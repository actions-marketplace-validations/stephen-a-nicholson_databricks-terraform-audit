"""Repository configuration: .dbx-audit.toml in the audited directory (or --config).

    profile = "hardened"           # baseline (default) or hardened
    required_tags = ["Environment", "Owner", "CostCentre", "Project"]

    [rules.H004]
    enabled = false
    reason  = "CMK is handled at the landing-zone level, not in this repo"

Every disabled rule needs a reason. A finding you can silence without saying why
is a finding you will forget about.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILENAME = ".dbx-audit.toml"


@dataclass
class Config:
    profile: str = "baseline"
    required_tags: list[str] | None = None
    disabled: dict[str, str] = field(default_factory=dict)  # rule id -> reason
    source: Path | None = None


class ConfigError(ValueError):
    pass


def load_config(target_dir: Path, explicit: Path | None = None) -> Config:
    path = explicit or (target_dir / CONFIG_FILENAME)
    if not path.exists():
        if explicit:
            raise ConfigError(f"config file not found: {explicit}")
        return Config()
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    cfg = Config(source=path)
    cfg.profile = str(raw.get("profile", cfg.profile))
    from checks.registry import PROFILES, RULES  # local import avoids a cycle at module load

    if cfg.profile not in PROFILES:
        raise ConfigError(f"unknown profile {cfg.profile!r}; expected one of {', '.join(PROFILES)}")
    known = {r.id for r in RULES}
    if "required_tags" in raw:
        cfg.required_tags = [str(t) for t in raw["required_tags"]]
    for rule_id, settings in (raw.get("rules") or {}).items():
        if rule_id not in known:
            raise ConfigError(f"rules.{rule_id}: no such rule (see docs/RULES.md for ids)")
        if not isinstance(settings, dict):
            raise ConfigError(f"rules.{rule_id} must be a table")
        if settings.get("enabled", True) is False:
            reason = str(settings.get("reason", "")).strip()
            if not reason:
                raise ConfigError(f"rules.{rule_id} is disabled without a reason; add reason = \"...\"")
            cfg.disabled[rule_id] = reason
    return cfg
