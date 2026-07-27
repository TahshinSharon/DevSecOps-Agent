# DevSecOps Agent Docker Runbook

## Run locally

```bash
cp .env.example .env
docker compose down
docker compose up -d --build
```

Open:

```text
http://localhost:3000
```

## Run on AWS EC2

Update `.env`:

```env
FRONTEND_ORIGIN=http://YOUR_EC2_PUBLIC_IP:3000
```

Start:

```bash
docker compose up -d --build
```

Open:

```text
http://YOUR_EC2_PUBLIC_IP:3000
```

Allow inbound TCP `3000` in the EC2 Security Group. For real usage, restrict source to your IP.

## Cloud scan usage

1. Login to the app.
2. Go to Dashboard.
3. Enable **Cloud Security Scan**.
4. Choose exactly one provider: AWS, GCP, or Azure.
5. Enter read-only credentials.
6. Select cloud services to scan.
7. Click **Run Inspection**.

Credentials are sent to the backend for the active scan request. The app stores a sanitized scope in SQLite, where secret values are replaced with `***provided***`.

## Recommended read-only credentials

### AWS

Use an IAM user or STS temporary credentials with read-only permissions such as:

- `sts:GetCallerIdentity`
- `ec2:DescribeSecurityGroups`
- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketPolicyStatus`
- `iam:GetAccountSummary`

### GCP

Use a service account JSON with read-only access for:

- Compute Firewall viewer permissions
- Storage bucket viewer / IAM policy read permissions

### Azure

Use an Azure service principal with Reader permissions on the subscription or target resource groups.

## Useful commands

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f frontend
docker compose restart
docker compose down
```

Clean reset, including SQLite history and Trivy cache:

```bash
docker compose down -v
docker compose up -d --build
```


## v9 Dashboard Improvements

After login, the dashboard no longer shows host stats immediately. Stats appear only after the user clicks **Run Inspection** and the scan completes. The stat cards now show Host, Running Containers, Stopped Containers, and Disk Used. Docker version was removed from the stat cards.

A new **Container Command Center** section appears after inspection. It lists both running and stopped containers. Select a container to view Docker-like diagnostics from the UI: container logs, healthcheck output, runtime state, exit code, restart count, OOM/dead flags, and detected errors. This allows students to debug containers like an engineer without typing Docker commands.


## Frontend AI key and model

The app can run without any AI key. In that mode, it uses the built-in rule-based analyzer.

You can also provide AI settings in two ways:

1. Backend `.env`:

```env
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OPENAI_BASE_URL=
```

2. Frontend per scan:

Open Dashboard → Optional AI Analysis → enable **Use my AI API key for this scan**.

Then enter:

```text
AI API key
Model name
Base URL optional
```

The frontend key overrides the backend `.env` for that scan only. The actual key is not saved in history.

Use an OpenAI-compatible base URL for non-OpenAI providers.

## AWS region selection in the UI

1. Login to DevSecOps Agent.
2. Enable **Cloud Security Scan**.
3. AWS is selected by default.
4. Enter **Access key ID** and **Secret access key**.
5. Click **Load AWS regions**.
6. Select one or more regions from the region chips.
7. Run Inspection.

The app validates the credentials by calling AWS STS and then loads enabled regions with EC2 `DescribeRegions`. Credentials are used for the scan request and are not stored in inspection history as raw secrets.
