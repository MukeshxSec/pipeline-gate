"""Trivy scanner wrapper (SCA — dependency vulnerabilities)."""
import subprocess
import json
import shutil


class SCAScanner:
    name = "trivy"
    category = "sca"

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def scan(self, target: str, options: dict = None) -> dict:
        """Run Trivy against target (usually the repo root)."""
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--quiet",
            "--scanners", "vuln",
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

        if result.returncode not in (0, 1):
            return {"error": f"Trivy failed (code {result.returncode}): {result.stderr[:500]}"}

        if not result.stdout.strip():
            return {"Results": []}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            return {"error": f"Could not parse Trivy output: {e}"}