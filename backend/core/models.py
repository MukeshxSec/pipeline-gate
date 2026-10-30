"""Unified data models for Pipeline-Gate."""
from dataclasses import dataclass, field
from typing import Optional
import hashlib


@dataclass
class Finding:
    """Unified finding schema — every scanner normalizes into this."""
    tool: str
    category: str          # "sast", "sca", "secrets", "dast"
    rule_id: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    url: Optional[str] = None
    sources: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Deterministic ID for deduplication."""
        key = f"{self.file}:{self.line}:{self.rule_id}:{self.category}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Full result of one scan."""
    scan_id: str
    timestamp: str
    target: str
    findings: list
    raw: dict = field(default_factory=dict)
    duration_seconds: float = 0.0