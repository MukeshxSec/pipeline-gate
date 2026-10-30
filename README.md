# 🛡️ Pipeline-Gate: CI/CD Security Gate

**Pipeline-Gate** is an automated DevSecOps security gate that integrates four distinct vulnerability scanners into a single, unified CI/CD pipeline. It automatically blocks Pull Requests if critical vulnerabilities, leaked secrets, or high-risk CVEs are detected.

## 🚀 Key Features

- **4-in-1 Scanning**: SAST (Semgrep), SCA (Trivy), Secrets (Gitleaks), and DAST (OWASP ZAP).
- **Smart Gating**: Fails the build based on customizable severity thresholds.
- **Diff-Aware Baseline**: Only blocks on *new* vulnerabilities introduced in the PR, ignoring pre-existing issues (prevents alert fatigue).
- **CI/CD Ready**: Exits with code `1` to block PRs and integrates directly with GitHub Actions.
- **35+ Automated Tests**: The core logic is fully unit-tested.

## 🏗️ Architecture

```text
Scanners (SAST/SCA/Secrets/DAST) 
   ↓ 
Normalizer (Unified Finding Schema) 
   ↓ 
Deduplicator (Merges duplicate findings) 
   ↓ 
Baseline Filter (Ignores pre-existing issues) 
   ↓ 
Security Gate (Applies Policy & Fails Pipeline)