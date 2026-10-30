"""OWASP ZAP scanner wrapper (DAST — runtime vulnerabilities)."""
import subprocess
import json
import shutil
import os


class DASTScanner:
    name = "zap"
    category = "dast"

    # Hardcoded ZAP path — confirmed on your system
    ZAP_BAT = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"
    ZAP_DIR = r"C:\Program Files\ZAP\Zed Attack Proxy"

    def is_available(self) -> bool:
        return os.path.exists(self.ZAP_BAT)

    def scan(self, target: str, options: dict = None):
        """
        Run ZAP baseline scan against a URL.
        `target` must be a URL like http://localhost:3000
        Returns a LIST of ZAP alerts.
        """
        if not target.startswith("http"):
            return {"error": f"DAST requires a URL, got: {target}"}

        # ZAP writes report to this file
        report_file = os.path.join(os.getcwd(), "zap_report.json")

        # Remove old report if exists
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except Exception:
                pass

        # Baseline scan: quick, safe, no active attacks
        cmd = [
            self.ZAP_BAT,
            "-cmd",                    # command-line mode (no GUI)
            "-quickurl", target,       # URL to scan
            "-quickout", report_file,  # JSON output path
            "-quickprogress",          # print progress
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,           # 10 min max
                encoding="utf-8",
                errors="replace",
                cwd=self.ZAP_DIR,      # CRITICAL: run from ZAP's folder so it finds its JAR
            )
        except subprocess.TimeoutExpired:
            return {"error": "ZAP scan timeout (10 min)"}
        except FileNotFoundError:
            return {"error": f"ZAP not found at {self.ZAP_BAT}"}

        if not os.path.exists(report_file):
            return {"error": f"ZAP did not produce a report. Stdout: {result.stdout[:300]}"}

        try:
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                return []

            # ZAP quick scan produces JSON
            data = json.loads(content)

            # ZAP report structure has "site" array with "alerts"
            alerts = []
            if isinstance(data, dict):
                for site in data.get("site", []):
                    alerts.extend(site.get("alerts", []))
            elif isinstance(data, list):
                alerts = data

            return alerts

        except json.JSONDecodeError as e:
            return {"error": f"Could not parse ZAP JSON: {e}"}
        except Exception as e:
            return {"error": f"ZAP read error: {e}"}
        finally:
            try:
                if os.path.exists(report_file):
                    os.remove(report_file)
            except Exception:
                pass