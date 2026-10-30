"""Simple risk scoring for findings."""
from .models import Finding


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def compute_risk_score(findings: list[Finding]) -> float:
    """
    Compute an overall risk score 0-100 based on finding severities.
    Multiple scanners reporting the same finding increases weight.
    """
    if not findings:
        return 0.0

    total = 0
    for f in findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 0)
        # Bonus if multiple scanners flagged it
        if len(f.sources) > 1:
            weight *= 1.5
        total += weight

    # Normalize: 0 findings = 0, 10 critical = 100
    score = min(100.0, total * 1.0)
    return round(score, 2)


def summarize_by_severity(findings: list[Finding]) -> dict:
    """Count findings by severity level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts