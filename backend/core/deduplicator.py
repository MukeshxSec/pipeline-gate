"""Merge duplicate findings reported by multiple scanners."""
from .models import Finding


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings that report the same issue (same file+line+rule+category).
    Keeps the highest severity, combines sources.
    """
    seen = {}
    for f in findings:
        key = (f.file, f.line, f.rule_id, f.category)

        if key in seen:
            existing = seen[key]
            if f.tool not in existing.sources:
                existing.sources.append(f.tool)
            # Keep highest severity
            if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = f.severity
        else:
            f.sources = [f.tool]
            seen[key] = f

    return list(seen.values())