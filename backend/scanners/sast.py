"""Semgrep scanner wrapper."""
import subprocess
import json
import shutil
from .base import BaseScanner


class SASTScanner(BaseScanner):
    name = "semgrep"
    category = "sast"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, target: str, options: dict = None) -> dict:
        """Run Semgrep against target and return raw JSON."""
        cmd = [
            "semgrep", "scan",
            "--config=auto",
            "--json",
            "--quiet",
            target,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            errors="replace",
        )

        # Semgrep exits 0 (no findings) or 1 (findings found)
        if result.returncode not in (0, 1):
            return {"error": f"Semgrep failed (code {result.returncode}): {result.stderr[:500]}"}

        if not result.stdout.strip():
            return {"results": []}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            return {"error": f"Could not parse Semgrep output: {e}"}