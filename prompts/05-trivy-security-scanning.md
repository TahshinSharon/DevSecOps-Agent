# Prompt — Add Trivy Security Scanning to DevSecOps Agent

You are a senior DevSecOps engineer. Extend the Docker inspection app so it can optionally run Trivy against Docker images found on the local AWS EC2 machine.

Requirements:

1. Add backend support for Trivy CLI.
2. Detect whether Trivy is installed.
3. Allow users to enable or disable Trivy per inspection.
4. Scan unique local container images.
5. Support configurable scanners: `vuln`, `secret`, and `misconfig`.
6. Parse Trivy JSON output.
7. Summarize severity counts, vulnerabilities, secrets, and misconfigurations.
8. Merge Trivy findings into the main AI/rule-based risk report.
9. Show Trivy results on the React report page.
10. Never automatically delete containers or images.

The result should teach students the difference between Docker runtime inspection and image security scanning.
