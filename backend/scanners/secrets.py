"""Gitleaks scanner wrapper (secret detection)."""
import subprocess
import json
import shutil
import tempfile
import os


class SecretsScanner:
    name = "gitleaks"
    category = "secrets"

    # Directories/files to exclude — dependencies, caches, previous reports
    EXCLUDES = [
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".git",
        "node_modules",
        "reports",
        "gl_test.json",
        "gl_rel.json",
        "gl_abs.json",
        "gl_full.json",
        "gl_demo.json",
        "semgrep_raw.json",
        "baseline.json",
    ]

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def scan(self, target: str, options: dict = None):
        """Run Gitleaks against target directory. Returns a list of findings."""
        report_file = os.path.join(tempfile.gettempdir(), "gitleaks_report.json")
        abs_target = os.path.abspath(target)

        cmd = [
            "gitleaks", "detect",
            "--source", abs_target,
            "--report-format", "json",
            "--report-path", report_file,
            "--no-git",
            "--exit-code", "0",
            "--log-level", "error",
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return {"error": "Gitleaks timeout"}

        if not os.path.exists(report_file):
            return []

        try:
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            if data is None:
                return []

            # Filter out findings from excluded directories
            filtered = []
            for finding in data:
                file_path = finding.get("File", "")
                norm_path = file_path.replace("\\", "/")
                if any(excl in norm_path for excl in self.EXCLUDES):
                    continue
                filtered.append(finding)
            return filtered
        except Exception as e:
            return {"error": f"Could not parse Gitleaks output: {e}"}
        finally:
            try:
                os.remove(report_file)
            except Exception:
                pass