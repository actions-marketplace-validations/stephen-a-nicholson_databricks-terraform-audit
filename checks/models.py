"""Data models for audit findings."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def sort_order(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }[self]


class Category(Enum):
    SECURITY = "Security"
    STANDARDS = "Standards"
    DATABRICKS = "Databricks"


@dataclass
class Finding:
    """A single audit finding from a Terraform configuration check."""

    severity: Severity
    category: Category
    title: str
    message: str
    filepath: Path
    suggested_fix: str = ""
    resource_address: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.title} — {self.filepath}"
