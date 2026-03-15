"""Helpers for iterating python-hcl2 parsed structures."""

from collections.abc import Iterator
from pathlib import Path


def iter_resources(parsed: dict) -> Iterator[tuple[str, str, dict]]:
    """Yield (resource_type, resource_name, config) for every resource in parsed HCL.

    python-hcl2 returns resource blocks as a list of single-key dicts:
        {"resource": [
            {"azurerm_resource_group": {"main": {...}}},
            {"azurerm_storage_account": {"datalake": {...}}},
        ]}

    This helper flattens that into a simple iterator.
    """
    for resource_block in parsed.get("resource", []):
        for resource_type, resources in resource_block.items():
            for resource_name, config in resources.items():
                # config can sometimes be a list with one element
                if isinstance(config, list):
                    config = config[0]
                yield resource_type, resource_name, config
