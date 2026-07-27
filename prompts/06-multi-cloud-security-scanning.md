# Multi-cloud DevSecOps scanning prompt

Build a multi-cloud security scanner for a DevSecOps dashboard. The user must choose exactly one provider: AWS, GCP, or Azure. After selection, show the matching credential form only. Use the credentials only for the active scan request and do not store secrets in the inspection history.

AWS checks:
- Validate identity with STS GetCallerIdentity.
- Scan EC2 Security Groups for public inbound rules, especially SSH/RDP/database ports.
- Scan S3 Public Access Block and public bucket policy status.
- Scan IAM Account Summary for account MFA and IAM user count.

GCP checks:
- Validate service account JSON and project ID.
- Scan Compute Firewall rules for public ingress.
- Scan Cloud Storage IAM policies for allUsers/allAuthenticatedUsers.

Azure checks:
- Validate service principal and subscription access.
- Scan Network Security Groups for public inbound allow rules.
- Scan Storage Accounts for public blob access and HTTPS-only settings.

Return findings with title, severity, resource, reason, and remediation. Merge cloud findings with Docker runtime and Trivy image findings in the final DevSecOps report.
