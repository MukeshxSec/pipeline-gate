"""Pure gate decision logic — no I/O, no side effects."""
from dataclasses import dataclass, field
from collections import Counter
from typing import Optional

from .models import Finding
from .policy import Policy


@dataclass
class GateResult:
    passed: bool
    reason: str
    offending: list = field(default_factory=list)
    blocking_rule: str = ""


def evaluate(
    new_findings: list[Finding],
    all_findings: list[Finding],
    policy: Policy,
    baseline_available: bool,
) -> GateResult:
    """
    Decide whether the pipeline should pass or fail.

    - new_findings: findings introduced by this change
    - all_findings: complete set (used if no baseline exists)
    - baseline_available: if True, only check new_findings
    """

    # 1. Filter expired/active ignores
    active = _apply_ignores(new_findings, policy)

    # 2. Hard rule: secrets = immediate fail
    if policy.block_secrets:
        secrets = [f for f in active if f.category == "secrets"]
        if secrets:
            return GateResult(
                passed=False,
                reason=f"{len(secrets)} secret(s) detected",
                offending=secrets,
                blocking_rule="block_secrets",
            )

    # 3. Threshold check
    check_set = active if baseline_available else all_findings
    counts = Counter(f.severity for f in check_set)

    # Order matters: check critical first
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        max_allowed = policy.fail_on.get(severity.lower())
        if max_allowed is None:
            continue
        if counts[severity] > max_allowed:
            offending = [f for f in check_set if f.severity == severity]
            return GateResult(
                passed=False,
                reason=f"{counts[severity]} {severity} findings (limit: {max_allowed})",
                offending=offending,
                blocking_rule=f"max_{severity.lower()}",
            )

    return GateResult(passed=True, reason="All checks passed")


def _apply_ignores(findings: list[Finding], policy: Policy) -> list[Finding]:
    """Remove findings matching an active (non-expired) ignore rule."""
    if not policy.ignore:
        return findings

    from datetime import datetime, date
    active_ignore_ids = set()
    for exc in policy.ignore:
        exp = exc.get("expires")
        if exp:
            try:
                exp_date = datetime.fromisoformat(str(exp)).date()
                if exp_date < date.today():
                    continue  # expired, do NOT ignore
            except ValueError:
                continue
        active_ignore_ids.add(exc.get("rule_id"))

    return [f for f in findings if f.rule_id not in active_ignore_ids]