"""Helpers for iterating python-hcl2 parsed structures.

python-hcl2 changed its output shape between 4.x/7.x and 8.x: in 8.x, block
labels and string values keep their surrounding quote characters
('"azurerm_storage_account"' rather than 'azurerm_storage_account') and blocks
gain an '__is_block__' marker. Every rule in this tool matches on bare names,
so this module normalises both shapes to the 7.x form. The dependency is also
pinned below 8 in pyproject.toml; this is belt and braces.
"""

from collections.abc import Iterator
from typing import Any

_BLOCK_MARKER = "__is_block__"


def _unquote(value: Any) -> Any:
    """Strip one layer of literal double quotes that python-hcl2 >= 8 leaves on strings."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        # Leave interpolations alone; they are expressions, not quoted literals.
        if "${" in inner and inner.count('"') > 0:
            return value
        return inner
    return value


def normalise(value: Any) -> Any:
    """Recursively normalise a parsed HCL structure to the python-hcl2 7.x shape."""
    if isinstance(value, dict):
        return {
            _unquote(k): normalise(v)
            for k, v in value.items()
            if k != _BLOCK_MARKER
        }
    if isinstance(value, list):
        return [normalise(v) for v in value]
    return _unquote(value)


def iter_resources(parsed: dict) -> Iterator[tuple[str, str, dict]]:
    """Yield (resource_type, resource_name, config) for every resource in parsed HCL.

    python-hcl2 returns resource blocks as a list of single-key dicts:
        {"resource": [
            {"azurerm_resource_group": {"main": {...}}},
            {"azurerm_storage_account": {"datalake": {...}}},
        ]}

    This helper flattens that into a simple iterator. Input is expected to have
    been passed through normalise() already (the orchestrator does this), but
    the names are unquoted again here so direct callers in tests are safe too.
    """
    for resource_block in parsed.get("resource", []):
        for resource_type, resources in resource_block.items():
            for resource_name, config in resources.items():
                # config can sometimes be a list with one element
                if isinstance(config, list):
                    config = config[0]
                yield _unquote(resource_type), _unquote(resource_name), config
