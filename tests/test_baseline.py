"""Test baseline filtering (diff-aware gating)."""
from backend.core.models import Finding
from backend.core.baseline import filter_new_findings


def make(file, rule_id, line=1):
    return Finding(
        tool="test", category="sast", rule_id=rule_id,
        severity="HIGH", title="", description="",
        file=file, line=line,
    )


def test_no_baseline_returns_all():
    current = [make("a.py", "r1"), make("b.py", "r2")]
    result = filter_new_findings(current, baseline=None)
    assert len(result) == 2


def test_filters_preexisting():
    current = [make("a.py", "r1"), make("b.py", "r2")]
    baseline = [make("a.py", "r1")]
    result = filter_new_findings(current, baseline)
    assert len(result) == 1
    assert result[0].file == "b.py"


def test_ignores_line_shifts():
    # Same issue on a different line (refactor moved code)
    current = [make("a.py", "r1", line=50)]
    baseline = [make("a.py", "r1", line=10)]
    result = filter_new_findings(current, baseline)
    assert len(result) == 0  # treated as same issue


def test_new_rule_is_new():
    current = [make("a.py", "r2")]
    baseline = [make("a.py", "r1")]
    result = filter_new_findings(current, baseline)
    assert len(result) == 1