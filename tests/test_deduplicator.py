"""Test finding deduplication."""
from backend.core.models import Finding
from backend.core.deduplicator import deduplicate


def make(tool, severity, file="a.py", line=10, rule_id="test-rule"):
    return Finding(
        tool=tool, category="sast", rule_id=rule_id,
        severity=severity, title="", description="",
        file=file, line=line,
    )


def test_merges_duplicates():
    f1 = make("semgrep", "HIGH")
    f2 = make("other-sast", "CRITICAL")

    result = deduplicate([f1, f2])

    assert len(result) == 1
    assert result[0].severity == "CRITICAL"  # highest kept
    assert set(result[0].sources) == {"semgrep", "other-sast"}


def test_keeps_different_findings_separate():
    f1 = make("semgrep", "HIGH", file="a.py", line=10)
    f2 = make("semgrep", "HIGH", file="b.py", line=20)

    result = deduplicate([f1, f2])
    assert len(result) == 2


def test_keeps_same_tool_duplicates():
    # Same tool, different rules at same location = two findings
    f1 = make("semgrep", "HIGH", rule_id="rule-a")
    f2 = make("semgrep", "HIGH", rule_id="rule-b")

    result = deduplicate([f1, f2])
    assert len(result) == 2