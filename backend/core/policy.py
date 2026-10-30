"""Load and validate security policy from YAML."""
import yaml
from dataclasses import dataclass, field
from datetime import datetime, date
from typing import Optional


@dataclass
class Policy:
    fail_on: dict = field(default_factory=dict)
    block_secrets: bool = True
    baseline_enabled: bool = True
    ignore: list = field(default_factory=list)


def load_policy(path: str) -> Policy:
    """Load security-policy.yaml into a Policy object."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Warn on expired exceptions
    for exc in data.get("ignore", []):
        exp = exc.get("expires")
        if exp:
            try:
                exp_date = datetime.fromisoformat(str(exp)).date()
                if exp_date < date.today():
                    print(f"WARNING: expired exception for {exc.get('rule_id')} (expired {exp_date})")
            except ValueError:
                print(f"WARNING: invalid expiry date '{exp}' for {exc.get('rule_id')}")

    return Policy(
        fail_on=data.get("fail_on", {}),
        block_secrets=data.get("block_secrets", True),
        baseline_enabled=data.get("baseline_enabled", True),
        ignore=data.get("ignore", []),
    )