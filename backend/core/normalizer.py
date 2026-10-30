"""Convert raw scanner output into unified Finding objects."""
from .models import Finding


SEVERITY_MAP_SEMGREP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def normalize_semgrep(raw: dict) -> list[Finding]:
    """Convert Semgrep JSON output to Finding list."""
    findings = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_list = meta.get("cwe", [])
        cwe = cwe_list[0].split(":")[0] if cwe_list else None

        findings.append(Finding(
            tool="semgrep",
            category="sast",
            rule_id=r.get("check_id", "unknown"),
            severity=SEVERITY_MAP_SEMGREP.get(extra.get("severity"), "MEDIUM"),
            title=r.get("check_id", "").split(".")[-1],
            description=extra.get("message", ""),
            file=r.get("path"),
            line=r.get("start", {}).get("line"),
            cwe_id=cwe,
            raw=r,
        ))
    return findings


def normalize_trivy(raw: dict) -> list[Finding]:
    """Convert Trivy JSON output to Finding list."""
    findings = []
    for result in raw.get("Results", []):
        target_file = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity == "UNKNOWN":
                severity = "LOW"
            findings.append(Finding(
                tool="trivy",
                category="sca",
                rule_id=vuln.get("VulnerabilityID", "unknown"),
                severity=severity,
                title=vuln.get("Title") or vuln.get("VulnerabilityID", ""),
                description=(vuln.get("Description") or "")[:500],
                file=target_file,
                cve_id=vuln.get("VulnerabilityID"),
                package=vuln.get("PkgName"),
                installed_version=vuln.get("InstalledVersion"),
                fixed_version=vuln.get("FixedVersion"),
                raw=vuln,
            ))
    return findings

def normalize_gitleaks(raw) -> list[Finding]:
    """Convert Gitleaks JSON output to Finding list."""
    # Gitleaks returns a list directly
    if not isinstance(raw, list):
        return []

    findings = []
    for item in raw:
        findings.append(Finding(
            tool="gitleaks",
            category="secrets",
            rule_id=item.get("RuleID", "unknown"),
            severity="CRITICAL",
            title=item.get("Description", "Secret detected"),
            description=f"Secret detected: {item.get('RuleID', 'unknown')}",
            file=item.get("File"),
            line=item.get("StartLine"),
            raw=item,
        ))
    return findings

    findings = []
    for item in raw:
        findings.append(Finding(
            tool="gitleaks",
            category="secrets",
            rule_id=item.get("RuleID", "unknown"),
            severity="CRITICAL",  # any secret leak = CRITICAL
            title=item.get("Description", "Secret detected"),
            description=f"Secret detected in {item.get('File', 'unknown')}",
            file=item.get("File"),
            line=item.get("StartLine"),
            raw=item,
        ))
    return findings

def normalize_zap(raw) -> list[Finding]:
    """Convert ZAP JSON alert list to Finding objects."""
    if not isinstance(raw, list):
        return []

    findings = []
    for alert in raw:
        # ZAP uses "riskdesc" like "Medium (Medium)" or just "risk" like "Medium"
        risk = alert.get("riskdesc") or alert.get("risk") or "Medium"
        severity = str(risk).split()[0].upper()

        # Map ZAP severities to our schema
        if severity in ("INFORMATIONAL", "INFO"):
            severity = "LOW"
        elif severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "MEDIUM"

        # ZAP alerts may contain multiple instances (URLs)
        instances = alert.get("instances", [])
        if instances:
            for inst in instances:
                findings.append(Finding(
                    tool="zap",
                    category="dast",
                    rule_id=str(alert.get("pluginid", "unknown")),
                    severity=severity,
                    title=alert.get("alert", "ZAP finding"),
                    description=(alert.get("desc") or "")[:500],
                    url=inst.get("uri"),
                    cwe_id=str(alert.get("cweid")) if alert.get("cweid") else None,
                    raw=alert,
                ))
        else:
            # Single-instance alert
            findings.append(Finding(
                tool="zap",
                category="dast",
                rule_id=str(alert.get("pluginid", "unknown")),
                severity=severity,
                title=alert.get("alert", "ZAP finding"),
                description=(alert.get("desc") or "")[:500],
                cwe_id=str(alert.get("cweid")) if alert.get("cweid") else None,
                raw=alert,
            ))
    return findings


NORMALIZERS = {
    "semgrep": normalize_semgrep,
    "trivy": normalize_trivy,
    "gitleaks": normalize_gitleaks,
    "zap": normalize_zap,
}


def normalize_all(raw_outputs: dict) -> list[Finding]:
    """Run all normalizers on a dict of {tool_name: raw_output}."""
    all_findings = []
    for tool, raw in raw_outputs.items():
        # Skip errored scanners (dict with "error" key)
        if isinstance(raw, dict) and "error" in raw:
            continue
        normalizer = NORMALIZERS.get(tool)
        if normalizer:
            try:
                all_findings.extend(normalizer(raw))
            except Exception as e:
                print(f"WARNING: normalizer for {tool} failed: {e}")
    return all_findings