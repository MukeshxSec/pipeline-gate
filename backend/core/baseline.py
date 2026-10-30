"""Diff-aware gating — block only on NEW findings."""
from .models import Finding


def filter_new_findings(
    current: list[Finding],
    baseline: list[Finding] | None,
) -> list[Finding]:
    """
    Return findings in `current` that are NOT present in `baseline`.

    Identity = (file, rule_id, category) — deliberately excludes line number
    so small refactors don't re-trigger old findings.
    """
    if baseline is None:
        return current  # first scan: everything is new

    baseline_keys = {(f.file, f.rule_id, f.category) for f in baseline}
    return [f for f in current if (f.file, f.rule_id, f.category) not in baseline_keys]