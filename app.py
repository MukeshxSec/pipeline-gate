"""Flask Backend for Professional Pipeline-Gate UI."""
from flask import Flask, render_template, request, jsonify
import subprocess
import re
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

    # Clean the URL (removes #/ or trailing slashes which break ZAP)
    if target_url:
        target_url = target_url.split("#")[0].rstrip("/")

    # Build CLI command
    cmd = ["python", "cli.py", "scan", "--target", ".", "--policy", "security-policy.yaml"]
    
    if "dast" in scanners and target_url:
        cmd.extend(["--target-url", target_url])
    else:
        cmd.append("--skip-dast")

    # Run the scanner and WAIT for it to finish
    subprocess.run(cmd, capture_output=True, text=True)
    
    # Read the generated HTML report to extract data
    findings = []
    risk_score = 0
    gate_failed = False
    reason = "Scan completed"
    
    report_path = BASE_DIR / "reports" / "latest_report.html"
    if report_path.exists():
        html_content = report_path.read_text(encoding="utf-8")
        
        # 1. Extract Status and Reason
        if "Gate failed" in html_content or "Status: FAILED" in html_content:
            gate_failed = True
            reason_match = re.search(r"<p>(.*?)</p>", html_content)
            reason = reason_match.group(1) if reason_match else "Policy violation"
            
        # 2. Extract Risk Score
        score_match = re.search(r"<div class=\"n\">(\d+)<small>/100</small>", html_content)
        if score_match:
            risk_score = float(score_match.group(1))
            
        # 3. Extract Findings from the NEW professional table
        # The HTML looks like: <tr class="r" data-s="CRITICAL"...><td><span class="sev">...</span></td><td><span class="sc">gitleaks</span></td><td class="loc">...</td><td>...</td></tr>
        
        # Extract Severity, Tool, Location, and Issue
        pattern = r'<tr class="r" data-s="[^"]+".*?><td><span class="sev"><i class="dot[^"]*"></i>([A-Z]+)</span></td><td><span class="sc">([^<]+)</span></td><td class="loc">([^<]+)</td><td>([^<]+)'
        rows = re.findall(pattern, html_content, re.DOTALL)
        
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