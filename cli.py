"""Pipeline-Gate command-line interface."""
import argparse
import sys
import json
import os
from pathlib import Path

from backend.core.normalizer import normalize_all
from backend.core.deduplicator import deduplicate
from backend.core.policy import load_policy
from backend.core.security_gate import evaluate
from backend.core.baseline import filter_new_findings
from backend.core.models import Finding
from backend.scanners.sast import SASTScanner
from backend.scanners.sca import SCAScanner
from backend.scanners.secrets import SecretsScanner
from backend.scanners.dast import DASTScanner
from backend.core.risk_engine import compute_risk_score, summarize_by_severity

# Import report generators
from backend.reports.html_report import generate_html_report
from backend.reports.sarif_report import generate_sarif_report


def load_baseline(path):
    """Load a baseline JSON file (previous findings dump) if it exists."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return [Finding(**item) for item in data]
    except Exception as e:
        print(f"WARNING: could not load baseline '{path}': {e}", file=sys.stderr)
        return None


def save_baseline(path, findings):
    """Save current findings as the new baseline."""
    data = [
        {
            "tool": f.tool,
            "category": f.category,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "file": f.file,
            "line": f.line,
            "cwe_id": f.cwe_id,
        }
        for f in findings
    ]
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def cmd_scan(args):
    print(f"🔍 Pipeline-Gate scanning: {args.target}")
    if args.target_url:
        print(f"   DAST target: {args.target_url}")
    print(f"   Policy: {args.policy}")
    print()

    # 1. Build scanner list — DAST only if URL provided
    scanners = [SASTScanner(), SCAScanner(), SecretsScanner()]
    dast_url = getattr(args, "target_url", None)
    if dast_url:
        scanners.append(DASTScanner())

    raw_outputs = {}

    # 2. Run scanners
    for s in scanners:
        if not s.is_available():
            print(f"❌ ERROR: {s.name} not installed", file=sys.stderr)
            return 2
        print(f"   Running {s.name}...")
        scan_target = dast_url if s.category == "dast" else args.target
        raw_outputs[s.name] = s.scan(scan_target)

    # 3. Normalize + deduplicate
    findings = normalize_all(raw_outputs)
    findings = deduplicate(findings)
    print(f"   Found {len(findings)} unique findings")

    # Show category breakdown for transparency
    if findings:
        by_cat = {}
        for f in findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        print(f"   Categories: {by_cat}")

    # 4. Load policy + baseline
    policy = load_policy(args.policy)
    baseline = load_baseline(args.baseline) if args.baseline else None
    new_findings = filter_new_findings(findings, baseline)

    if baseline is not None:
        print(f"   Baseline: {len(baseline)} known findings, {len(new_findings)} new")
    else:
        print(f"   Baseline: none (all findings are new)")

    # 5. Gate decision
    gate = evaluate(new_findings, findings, policy,
                    baseline_available=baseline is not None)

    # 6. Calculate Risk Score
    risk_score = compute_risk_score(findings)
    severity_counts = summarize_by_severity(findings)

    print()
    print("=" * 60)
    print(f"📊 RISK SCORE: {risk_score}/100")
    print(f"   Critical: {severity_counts['CRITICAL']} | High: {severity_counts['HIGH']} | Medium: {severity_counts['MEDIUM']} | Low: {severity_counts['LOW']}")
    print("-" * 60)
    
    if gate.passed:
        print(f"✅ GATE PASSED — {gate.reason}")
    else:
        print(f"🛑 GATE FAILED — {gate.reason}")
        print()
        for f in gate.offending[:10]:
            if f.file:
                loc = f"{f.file}:{f.line}" if f.line else f.file
            elif f.url:
                loc = f.url
            else:
                loc = "(no location)"
            print(f"   [{f.severity}] {loc} — {f.title}")
        if len(gate.offending) > 10:
            print(f"   ... and {len(gate.offending) - 10} more")
    print("=" * 60)

    # 7. Save baseline if requested
    if args.save_baseline:
        save_baseline(args.save_baseline, findings)
        print(f"📁 Baseline saved: {args.save_baseline}")

    # 8. Generate HTML and SARIF Reports
    os.makedirs("reports", exist_ok=True)
    
    html_content = generate_html_report("scan-1", findings, gate, risk_score)
    with open("reports/latest_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
        
    sarif_content = generate_sarif_report(findings)
    with open("reports/latest_report.sarif", "w", encoding="utf-8") as f:
        f.write(sarif_content)
        
    print("📁 Reports saved to 'reports/' folder (HTML & SARIF)")

    return 0 if gate.passed else 1


def cmd_version(args):
    """Show version and scanner availability."""
    print("Pipeline-Gate v0.1.0")
    print()
    print("Scanner status:")
    for scanner_cls in [SASTScanner, SCAScanner, SecretsScanner, DASTScanner]:
        s = scanner_cls()
        status = "✅ installed" if s.is_available() else "❌ missing"
        print(f"  {s.name:10s} ({s.category}): {status}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="pipeline-gate",
        description="CI/CD security gate for your pipeline",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Run security scan")
    scan_p.add_argument("--target", default=".", help="Directory or file to scan (SAST/SCA/Secrets)")
    scan_p.add_argument("--target-url", default=None, help="URL for DAST scanning (e.g., http://localhost:3000)")
    scan_p.add_argument("--policy", default="security-policy.yaml", help="Policy YAML file")
    scan_p.add_argument("--baseline", default=None, help="Baseline JSON file (previous findings)")
    scan_p.add_argument("--save-baseline", default=None, help="Save current findings as new baseline")

    sub.add_parser("version", help="Show version and tool status")

    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "version":
        return cmd_version(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())