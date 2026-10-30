"""SARIF Report Generator (GitHub Code Scanning format)."""
import json

def generate_sarif_report(findings):
    results = []
    for f in findings:
        level = "error" if f.severity in ["CRITICAL", "HIGH"] else "warning"
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file or "unknown"},
                    "region": {"startLine": f.line or 1}
                }
            }]
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Pipeline-Gate", "rules": []}},
            "results": results
        }]
    }
    return json.dumps(sarif, indent=2)