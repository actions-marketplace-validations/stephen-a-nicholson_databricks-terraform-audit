"""Shared fixtures. Fixtures are real Terraform, parsed with python-hcl2, never hand-built dicts."""

from pathlib import Path

import hcl2
import pytest

from checks.helpers import normalise

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def parse(text: str, tmp_path: Path, name: str = "main.tf") -> tuple[dict, Path]:
    """Write a .tf snippet to disk and parse it, returning (parsed, path)."""
    path = tmp_path / name
    path.write_text(text)
    with open(path) as f:
        return normalise(hcl2.load(f)), path


@pytest.fixture
def tf(tmp_path: Path):
    """Factory fixture: tf('resource ...') -> (parsed, path)."""
    def _factory(text: str, name: str = "main.tf") -> tuple[dict, Path]:
        return parse(text, tmp_path, name)
    return _factory


@pytest.fixture
def sample_dir() -> Path:
    return EXAMPLES / "sample-terraform"


@pytest.fixture
def clean_dir() -> Path:
    return EXAMPLES / "clean-terraform"
