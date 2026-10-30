"""Test the Flask API."""
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"


def test_version_endpoint(client):
    resp = client.get("/api/version")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["version"] == "0.1.0"
    assert "semgrep" in data["scanners"]


def test_gate_pass_with_no_findings(client):
    resp = client.post("/api/gate", json={"findings": []})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["passed"] is True


def test_gate_fail_on_secret(client):
    resp = client.post("/api/gate", json={
        "findings": [{
            "tool": "gitleaks",
            "category": "secrets",
            "rule_id": "aws-key",
            "severity": "CRITICAL",
            "title": "AWS key",
            "description": "",
        }]
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["passed"] is False
    assert "secret" in data["reason"].lower()


def test_gate_fail_on_critical_threshold(client):
    resp = client.post("/api/gate", json={
        "findings": [{
            "tool": "semgrep",
            "category": "sast",
            "rule_id": "sql-inj",
            "severity": "CRITICAL",
            "title": "SQL injection",
            "description": "",
        }]
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["passed"] is False