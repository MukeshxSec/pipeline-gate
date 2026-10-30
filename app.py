"""Flask Backend for Professional Pipeline-Gate UI."""
from flask import Flask, render_template, request, jsonify
import subprocess
import json
import re
import os
from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "frontend" / "templates"),
    static_folder=str(BASE_DIR / "frontend" / "static")
)

@app.route("/", methods=["GET"])
def dashboard():
    # This serves the HTML you just pasted
    return render_template("dashboard.html")

@app.route("/api/policy", methods=["GET"])
def api_policy():
    """Serve the policy rules to the UI simulator."""
    try:
        with open("security-policy.yaml", "r") as f:
            data = yaml.safe_load(f)
        fail_on = data.get("fail_on", {})
        return jsonify({
            "critical": fail_on.get("critical", 0),
            "high": fail_on.get("high", 5),
            "medium": fail_on.get("medium", 20),
            "block_secrets": data.get("block_secrets", True)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    scanners = data.get("scanners", [])
    target_url = data.get("target_url")

    # Build CLI command
    cmd = ["python", "cli.py", "scan", "--target", ".", "--policy", "security-policy.yaml"]
    
    if "dast" in scanners and target_url:
        cmd.extend(["--target-url", target_url])
    else:
        cmd.append("--skip-dast")

    # Run the scanner
    subprocess.run(cmd, capture_output=True, text=True)
    
    # Read the generated HTML report to extract data
    findings = []
    risk_score = 0
    gate_failed = False
    reason = "Scan completed"
    
    report_path = BASE_DIR / "reports" / "latest_report.html"
    if report_path.exists():
        html_content = report_path.read_text(encoding="utf-8")
        
        # Extract Status
        if "Status: FAILED" in html_content:
            gate_failed = True
            reason_match = re.search(r"Reason:</strong>\s*(.*?)</p>", html_content)
            reason = reason_match.group(1) if reason_match else "Policy violation"
            
        # Extract Risk Score
        score_match = re.search(r"Risk Score:</strong>\s*([\d.]+)", html_content)
        if score_match:
            risk_score = float(score_match.group(1))
            
        # Extract Findings from the table
        rows = re.findall(r"<tr><td>([^<]+)</td><td>([^<]+)</td><td>([^<]+)</td><td>([^<]+)</td></tr>", html_content)
        for r in rows:
            findings.append({
                "severity": r[0].strip(),
                "scanner": r[1].strip().lower(),
                "location": r[2].strip(),
                "issue": r[3].strip()
            })

    return jsonify({
        "status": "FAILED" if gate_failed else "PASSED",
        "reason": reason,
        "risk_score": risk_score,
        "total_findings": len(findings),
        "findings": findings
    })

@app.route("/api/override", methods=["POST"])
def api_override():
    data = request.get_json() or {}
    reason = data.get("reason", "No reason provided")
    print(f"🚨 MANUAL OVERRIDE APPROVED. Reason: {reason}")
    return jsonify({"status": "approved", "reason": reason})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)