"""Test the Semgrep normalizer."""
import json
from pathlib import Path
from backend.core.normalizer import normalize_semgrep


def test_semgrep_normalization():
    fixture = Path(__file__).parent / "fixtures" / "semgrep_output.json"
    raw = json.loads(fixture.read_text(encoding="utf-8"))

    findings = normalize_semgrep(raw)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.tool == "semgrep"
    assert f1.category == "sast"
    assert f1.severity == "HIGH"
    assert f1.file == "app/utils.py"
    assert f1.line == 15
    assert f1.cwe_id == "CWE-78"

    f2 = findings[1]
    assert f2.severity == "MEDIUM"
    assert f2.file == "app/config.py"
    assert f2.cwe_id == "CWE-798"


def test_empty_input():
    assert normalize_semgrep({}) == []
    assert normalize_semgrep({"results": []}) == []