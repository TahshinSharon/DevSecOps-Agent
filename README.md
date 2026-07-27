# DevSecOps Agent

A web-based security inspection tool that scans Docker containers and cloud infrastructure, then generates an AI-powered risk report with remediation suggestions.

---

## What It Does

You open the dashboard, choose a scan target (local Docker or a cloud provider), hit **Run Inspection**, and get back a prioritized list of security findings — privileged containers, exposed ports, leaked secrets, CVEs in images, open firewall rules, public S3 buckets, and more.

```
┌─────────────────────────────────────────────────┐
│              DevSecOps Agent                    │
│                                                 │
│  Login → Dashboard → Run Scan → Live Progress  │
│                         ↓                      │
│              Security Report + History          │
└─────────────────────────────────────────────────┘
```

---

## Scan Modes

### Local Docker Scan
Connects to the Docker socket on the host machine and inspects every container, image, volume, and network.

```
Your Machine
│
├── Containers  →  privileged? writable root? secret env vars?
├── Images      →  CVEs via Trivy? dangling/unused?
├── Networks    →  unused custom networks?
└── Volumes     →  orphaned volumes?
```

### Cloud Security Scan
Uses temporary credentials to audit cloud resources via their APIs.

```
AWS                    GCP                  Azure
───────────────────    ─────────────────    ─────────────────
ECS / ECR containers   Firewall rules       NSG rules
EC2 Docker via SSM     Cloud Storage        Blob Storage
S3 bucket policies
IAM public access
Security Groups
```

---

## How a Scan Works

```
Browser                  Backend                      External
   │                        │                             │
   │── POST /api/inspect ──▶│                             │
   │                        │── scan Docker socket ──────▶│
   │◀── inspection_id ──────│                             │
   │                        │── scan cloud APIs ─────────▶│
   │── WebSocket connect ──▶│                             │
   │                        │── run Trivy on images ─────▶│
   │◀── live progress msgs ─│                             │
   │                        │── AI analysis (OpenAI) ────▶│
   │                        │   or rule-based fallback    │
   │◀── redirect to report ─│── save to SQLite            │
```

---

## AI Analysis

- **With OpenAI key** — sends scan data to GPT-4o-mini (or your model of choice) for contextual risk narrative and remediation commands.
- **Without a key** — built-in rule engine covers ~15 security checks across containers, images, networks, cloud services, and Trivy findings.

---

## Risk Levels

| Level    | Meaning                                      |
|----------|----------------------------------------------|
| Critical | Privileged container, critical CVE, leaked secret |
| High     | High CVE, high memory/CPU, secret env vars   |
| Medium   | Stopped containers, missing restart policy, open ports |
| Low      | Dangling images, unused networks/volumes     |

