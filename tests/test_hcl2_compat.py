"""The tool must behave the same whichever python-hcl2 output shape it is given.

python-hcl2 8.x keeps quote characters on labels and strings and adds an
__is_block__ marker. These tests feed the 8.x shape in directly, so they hold
regardless of which version is installed.
"""

from pathlib import Path

from checks.helpers import iter_resources, normalise
from checks.security import check_public_network_access, check_storage_network_rules
from checks.standards import check_required_tags

HCL2_V8_SHAPE = {
    "resource": [
        {
            '"azurerm_storage_account"': {
                '"datalake"': {
                    "name": '"stlakehouse"',
                    "min_tls_version": '"TLS1_2"',
                    "public_network_access_enabled": True,
                    "tags": {"Environment": '"prod"'},
                    "__is_block__": True,
                }
            }
        }
    ]
}


def test_normalise_strips_quotes_and_block_marker() -> None:
    n = normalise(HCL2_V8_SHAPE)
    ((rtype, rname, cfg),) = list(iter_resources(n))
    assert (rtype, rname) == ("azurerm_storage_account", "datalake")
    assert cfg["name"] == "stlakehouse"
    assert cfg["min_tls_version"] == "TLS1_2"
    assert cfg["tags"] == {"Environment": "prod"}
    assert "__is_block__" not in cfg


def test_normalise_leaves_interpolations_alone() -> None:
    assert normalise('"${var.name}-suffix"') == "${var.name}-suffix"
    assert normalise("${var.x}") == "${var.x}"
    assert normalise(True) is True


def test_rules_fire_on_v8_shape_after_normalise(tmp_path: Path) -> None:
    n = normalise(HCL2_V8_SHAPE)
    path = tmp_path / "main.tf"
    path.write_text("")  # hardcoded-id check reads the file; others do not
    assert check_public_network_access(n, path) != []
    assert check_storage_network_rules(n, path) != []
    assert check_required_tags(n, path) != []  # missing Owner/CostCentre/Project


def test_iter_resources_tolerates_unnormalised_input() -> None:
    ((rtype, rname, _),) = list(iter_resources(HCL2_V8_SHAPE))
    assert (rtype, rname) == ("azurerm_storage_account", "datalake")
