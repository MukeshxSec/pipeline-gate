"""Flask API for Pipeline-Gate."""
from flask import Flask, jsonify, request
from backend.core.policy import load_policy
from backend.core.security_gate import evaluate
from backend.core.models import Finding

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "pipeline-gate"})


@app.route("/api/gate", methods=["POST"])
def api_gate():
    """
    Evaluate findings against policy.
    POST body:
    {
        "findings": [{"severity": "HIGH", "tool": "test", ...}],
        "policy_path": "security-policy.yaml"
    }
    """
    data = request.get_json() or {}
    raw_findings = data.get("findings", [])
    policy_path = data.get("policy_path", "security-policy.yaml")

    try:
        findings = [
            Finding(
                tool=f.get("tool", "unknown"),
                category=f.get("category", "sast"),
                rule_id=f.get("rule_id", "unknown"),
                severity=f.get("severity", "LOW"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                file=f.get("file"),
                line=f.get("line"),
            )
            for f in raw_findings
        ]

        policy = load_policy(policy_path)
        gate = evaluate(findings, findings, policy, baseline_available=False)

        return jsonify({
            "passed": gate.passed,
            "reason": gate.reason,
            "blocking_rule": gate.blocking_rule,
            "offending_count": len(gate.offending),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/version", methods=["GET"])
def api_version():
    return jsonify({"version": "0.1.0", "scanners": ["semgrep", "trivy", "gitleaks", "zap"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)