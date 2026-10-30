"""Test the security gate decision logic."""
from backend.core.models import Finding
from backend.core.policy import Policy
from backend.core.security_gate import evaluate


def make_finding(severity, category="sast", rule_id="test"):
    return Finding(
        tool="test", category=category, rule_id=rule_id,
        severity=severity, title="", description="",
    )


def default_policy(**overrides):
    defaults = dict(
        fail_on={"critical": 0, "high": 5, "medium": 20},
        block_secrets=True,
        baseline_enabled=True,
        ignore=[],
    )
    defaults.update(overrides)
    return Policy(**defaults)


def test_pass_under_threshold():
    policy = default_policy()
    findings = [make_finding("HIGH")]  # 1 high, limit 5
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is True
    assert result.reason == "All checks passed"


def test_fail_on_critical():
    policy = default_policy()
    findings = [make_finding("CRITICAL")]  # 1 critical, limit 0
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is False
    assert result.blocking_rule == "max_critical"


def test_fail_on_too_many_high():
    policy = default_policy(fail_on={"high": 2})
    findings = [make_finding("HIGH") for _ in range(3)]  # 3 high, limit 2
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is False
    assert result.blocking_rule == "max_high"


def test_secret_blocks_immediately():
    policy = default_policy()
    findings = [make_finding("LOW", category="secrets")]
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is False
    assert result.blocking_rule == "block_secrets"


def test_secrets_can_be_disabled():
    policy = default_policy(block_secrets=False)
    findings = [make_finding("LOW", category="secrets")]
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is True


def test_ignore_rule_filters_findings():
    policy = default_policy(ignore=[
        {"rule_id": "test", "reason": "known false positive", "expires": "2099-01-01"}
    ])
    findings = [make_finding("CRITICAL", rule_id="test")]
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is True


def test_expired_ignore_does_not_apply():
    policy = default_policy(ignore=[
        {"rule_id": "test", "reason": "old", "expires": "2020-01-01"}
    ])
    findings = [make_finding("CRITICAL", rule_id="test")]
    result = evaluate(findings, findings, policy, baseline_available=True)
    assert result.passed is False  # expired ignore is ignored


def test_baseline_filters_preexisting():
    policy = default_policy()
    # No new findings, but plenty of pre-existing ones
    new_findings = []
    all_findings = [make_finding("CRITICAL") for _ in range(10)]
    result = evaluate(new_findings, all_findings, policy, baseline_available=True)
    assert result.passed is True  # no NEW critical findings


def test_no_baseline_checks_everything():
    policy = default_policy()
    findings = [make_finding("CRITICAL")]
    result = evaluate(findings, findings, policy, baseline_available=False)
    assert result.passed is False