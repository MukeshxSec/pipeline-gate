"""HTML Report Generator."""
import html

def generate_html_report(scan_id, findings, gate_result, risk_score):
    rows = ""
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.file else f.url or "N/A"
        rows += f"<tr><td>{f.severity}</td><td>{f.tool}</td><td>{loc}</td><td>{html.escape(f.title)}</td></tr>"

    status_color = "#d4edda" if gate_result.passed else "#f8d7da"
    status_text = "PASSED" if gate_result.passed else "FAILED"

    return f"""
    <html>
    <head><title>Pipeline-Gate Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .status {{ padding: 20px; background-color: {status_color}; border-radius: 8px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .CRITICAL {{ color: red; font-weight: bold; }}
        .HIGH {{ color: orange; font-weight: bold; }}
    </style>
    </head>
    <body>
        <h1>🛡️ Pipeline-Gate Security Report</h1>
        <div class="status">
            <h2>Status: {status_text}</h2>
            <p><strong>Reason:</strong> {gate_result.reason}</p>
            <p><strong>Risk Score:</strong> {risk_score}/100</p>
            <p><strong>Total Findings:</strong> {len(findings)}</p>
        </div>
        <table>
            <tr><th>Severity</th><th>Scanner</th><th>Location</th><th>Issue</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """