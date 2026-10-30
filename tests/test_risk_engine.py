"""Test the risk scoring engine."""
from backend.core.models import Finding
from backend.core.risk_engine import compute_risk_score, summarize_by_severity


def make(severity, sources=None):
    f = Finding(
        tool="test", category="sast", rule_id="r",
        severity=severity, title="", description="",
    )
    f.sources = sources or ["test"]
    return f


def test_empty_findings_returns_zero():
    assert compute_risk_score([]) == 0.0


def test_single_critical():
    score = compute_risk_score([make("CRITICAL")])
    assert score == 10.0


def test_five_highs():
    findings = [make("HIGH") for _ in range(5)]
    assert compute_risk_score(findings) == 25.0


def test_multi_source_bonus():
    """Same finding from 2 scanners = 1.5x weight."""
    f = make("HIGH", sources=["semgrep", "other"])
    assert compute_risk_score([f]) == 7.5


def test_score_capped_at_100():
    findings = [make("CRITICAL") for _ in range(20)]
    assert compute_risk_score(findings) == 100.0


def test_summarize_by_severity():
    findings = [make("HIGH"), make("HIGH"), make("MEDIUM"), make("CRITICAL")]
    counts = summarize_by_severity(findings)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 2
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 0