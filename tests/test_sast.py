"""Test the SAST scanner wrapper."""
from unittest.mock import patch, MagicMock
from backend.scanners.sast import SASTScanner


def test_is_available_true():
    """Scanner should be available if semgrep is on PATH."""
    with patch("shutil.which", return_value="/usr/bin/semgrep"):
        scanner = SASTScanner()
        assert scanner.is_available() is True


def test_is_available_false():
    """Scanner should be unavailable if semgrep is missing."""
    with patch("shutil.which", return_value=None):
        scanner = SASTScanner()
        assert scanner.is_available() is False


def test_scan_returns_dict():
    """Scanner should return a dict with 'results' key."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"results": [], "errors": []}'
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        scanner = SASTScanner()
        result = scanner.scan(".")
        assert isinstance(result, dict)
        assert "results" in result
        assert result["results"] == []


def test_scan_handles_invalid_json():
    """Scanner should return error dict on unparseable output."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "this is not json"
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        scanner = SASTScanner()
        result = scanner.scan(".")
        assert "error" in result


def test_scanner_metadata():
    """Scanner should have correct name and category."""
    scanner = SASTScanner()
    assert scanner.name == "semgrep"
    assert scanner.category == "sast"