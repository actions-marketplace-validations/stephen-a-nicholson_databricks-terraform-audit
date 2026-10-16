"""File discovery: recursion and skipped directories."""

from pathlib import Path

from orchestrator import discover_tf_files


def test_recursive_discovery_finds_modules_and_skips_terraform_cache(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("")
    (tmp_path / "modules" / "net").mkdir(parents=True)
    (tmp_path / "modules" / "net" / "main.tf").write_text("")
    (tmp_path / ".terraform" / "providers").mkdir(parents=True)
    (tmp_path / ".terraform" / "providers" / "junk.tf").write_text("")

    found = {p.relative_to(tmp_path).as_posix() for p in discover_tf_files(tmp_path)}
    assert found == {"main.tf", "modules/net/main.tf"}


def test_non_recursive_discovery(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("")
    (tmp_path / "modules").mkdir()
    (tmp_path / "modules" / "main.tf").write_text("")

    found = {p.name for p in discover_tf_files(tmp_path, recursive=False)}
    assert found == {"main.tf"}
    assert len(discover_tf_files(tmp_path, recursive=False)) == 1
