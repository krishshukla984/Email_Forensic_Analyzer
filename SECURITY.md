# Security Policy

## Supported Versions

We actively monitor and patch security vulnerabilities. Please see the table below to verify if the version you are using is currently supported:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| < 1.1.0 | :x:                |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.** 

If you discover a security vulnerability within this project, please report it safely using one of the following methods:

1. **GitHub Private Vulnerability Reporting:** Navigate to the "Security" tab of this repository, select "Advisories", and click "New draft advisory".
2. **Email:** Send a detailed report to **security@yourdomain.com**.

### What to Include in Your Report
To help us patch the issue quickly, please provide:
* A detailed description of the vulnerability.
* Clear steps to reproduce the issue (including proof-of-concept scripts or screenshots if applicable).
* The potential impact (e.g., Remote Code Execution, Privilege Escalation).

### Our Response Process
* **Acknowledgment:** You will receive an initial response within 48 hours confirming receipt of your report.
* **Triage & Patch:** We will investigate and aim to provide a fix or mitigation strategy within 14 days.
* **Disclosure:** We will coordinate a public security advisory with you once a patch is ready and deployed.
Use code with caution.2. Automated Security Workflows (DevSecOps)Create a file named .github/workflows/security-scan.yml to run daily scans for hardcoded secrets, misconfigurations, and vulnerable code dependencies using GitHub's native tools:yamlname: "Security Scan"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
  schedule:
    - cron: '0 0 * * 1' # Runs every Monday at midnight

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  codeql-analysis:
    name: CodeQL Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: 'javascript-typescript' # Change to your language (e.g., python, go, java)

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
