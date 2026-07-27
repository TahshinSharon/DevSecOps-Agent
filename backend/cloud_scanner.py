from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class CloudScanError(Exception):
    pass


def _issue(title: str, severity: str, resource: str, reason: str, remediation: str) -> Dict[str, str]:
    return {
        "title": title,
        "severity": severity,
        "resource": resource,
        "reason": reason,
        "remediation": remediation,
    }


def _port_range(rule: Dict[str, Any]) -> str:
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    proto = rule.get("IpProtocol", "tcp")
    if proto == "-1":
        return "all protocols"
    if from_port is None:
        return str(proto)
    if from_port == to_port:
        return f"{proto}/{from_port}"
    return f"{proto}/{from_port}-{to_port}"


def _is_public_cidr(cidr: Optional[str]) -> bool:
    return cidr in {"0.0.0.0/0", "::/0"}


def _public_port_severity(port_text: str) -> str:
    dangerous = ["22", "3389", "3306", "5432", "6379", "27017", "9200", "9300", "11211"]
    return "critical" if any(p in port_text for p in dangerous) or "all protocols" in port_text else "high"


@dataclass
class CloudScanRequest:
    provider: str
    credentials: Dict[str, Any]
    regions: List[str]
    services: List[str]


def sanitize_cloud_credentials(provider: Optional[str], credentials: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not provider or not credentials:
        return {}
    safe = {"provider": provider}
    for key, value in credentials.items():
        if value in (None, ""):
            continue
        lower = key.lower()
        if any(token in lower for token in ["secret", "key", "password", "token", "json", "pem"]):
            safe[key] = "***provided***"
        else:
            safe[key] = value
    return safe



def load_aws_regions(credentials: Dict[str, Any]) -> List[str]:
    """Return enabled AWS regions for the provided IAM credentials."""
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except Exception as exc:
        raise CloudScanError("AWS region loader requires boto3. Rebuild the backend image with updated requirements.txt.") from exc

    access_key = credentials.get("access_key_id")
    secret_key = credentials.get("secret_access_key")
    session_token = credentials.get("session_token") or None
    default_region = credentials.get("region") or "us-east-1"
    if not access_key or not secret_key:
        raise CloudScanError("Access key ID and Secret access key are required to load AWS regions.")

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=default_region,
        )
        # Validate identity first so the UI can show a useful credential error.
        session.client("sts", region_name=default_region).get_caller_identity()
        ec2 = session.client("ec2", region_name=default_region)
        response = ec2.describe_regions(AllRegions=False)
        regions = sorted([r.get("RegionName") for r in response.get("Regions", []) if r.get("RegionName")])
        if default_region not in regions:
            regions.insert(0, default_region)
        return regions
    except (BotoCoreError, ClientError) as exc:
        raise CloudScanError(f"Unable to load AWS regions: {exc}") from exc



def _aws_session(credentials: Dict[str, Any]):
    try:
        import boto3
    except Exception as exc:
        raise CloudScanError("AWS scanner requires boto3. Rebuild the backend image with updated requirements.txt.") from exc
    access_key = credentials.get("access_key_id")
    secret_key = credentials.get("secret_access_key")
    session_token = credentials.get("session_token") or None
    default_region = credentials.get("region") or "us-east-1"
    if not access_key or not secret_key:
        raise CloudScanError("AWS access key ID and secret access key are required.")
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=default_region,
    )


def load_aws_ec2_instances(credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
    """List EC2 instances and mark whether they are SSM managed in selected regions."""
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except Exception as exc:
        raise CloudScanError("AWS EC2 instance loader requires boto3/botocore.") from exc
    session = _aws_session(credentials)
    default_region = credentials.get("region") or "us-east-1"
    regions = credentials.get("regions") or [default_region]
    results: List[Dict[str, Any]] = []
    try:
        session.client("sts", region_name=default_region).get_caller_identity()
    except Exception as exc:
        raise CloudScanError(f"AWS credential validation failed: {exc}") from exc
    for region in regions:
        ssm_managed: Dict[str, Dict[str, Any]] = {}
        try:
            ssm = session.client("ssm", region_name=region)
            paginator = ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page.get("InstanceInformationList", []):
                    iid = info.get("InstanceId")
                    if iid:
                        ssm_managed[iid] = info
        except (BotoCoreError, ClientError):
            # Keep listing EC2 instances even if SSM visibility is not allowed.
            ssm_managed = {}
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        iid = inst.get("InstanceId")
                        name = ""
                        for tag in inst.get("Tags", []) or []:
                            if tag.get("Key") == "Name":
                                name = tag.get("Value") or ""
                        ssm_info = ssm_managed.get(iid, {})
                        results.append({
                            "region": region,
                            "instance_id": iid,
                            "name": name,
                            "state": (inst.get("State") or {}).get("Name"),
                            "instance_type": inst.get("InstanceType"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "platform": inst.get("PlatformDetails") or inst.get("Platform") or "Linux/UNIX",
                            "ssm_managed": iid in ssm_managed,
                            "ssm_ping_status": ssm_info.get("PingStatus"),
                            "ssm_agent_version": ssm_info.get("AgentVersion"),
                        })
        except (BotoCoreError, ClientError) as exc:
            raise CloudScanError(f"Unable to load EC2 instances in {region}: {exc}") from exc
    return results


def scan_cloud(provider: str, credentials: Dict[str, Any], services: Optional[List[str]] = None, regions: Optional[List[str]] = None) -> Dict[str, Any]:
    provider = (provider or "").lower().strip()
    services = services or []
    regions = regions or []
    if provider == "aws":
        return scan_aws(credentials, services, regions)
    if provider == "gcp":
        return scan_gcp(credentials, services)
    if provider == "azure":
        return scan_azure(credentials, services)
    raise CloudScanError("Unsupported cloud provider. Choose aws, gcp, or azure.")



def _arn_name(arn: Optional[str]) -> str:
    if not arn:
        return ""
    return arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]

def _ecs_scan_status_issue(region: str, service: Dict[str, Any]) -> Optional[Dict[str, str]]:
    desired = int(service.get("desiredCount", 0) or 0)
    running = int(service.get("runningCount", 0) or 0)
    pending = int(service.get("pendingCount", 0) or 0)
    service_name = service.get("serviceName", "unknown-service")
    if desired > running:
        return _issue(
            "ECS service below desired running count",
            "high",
            f"{region}/{service_name}",
            f"Desired count is {desired}, but running count is {running} and pending count is {pending}.",
            "Check ECS service events, task failures, image pull errors, CPU/memory limits, target group health, and deployment status.",
        )
    return None

def _summarize_ecr_findings(findings: Dict[str, Any]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "UNDEFINED": 0}
    enhanced = findings.get("enhancedFindings") or []
    if enhanced:
        for item in enhanced:
            sev = str(item.get("severity") or "UNDEFINED").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    basic = findings.get("findingSeverityCounts") or {}
    for sev, count in basic.items():
        counts[str(sev).upper()] = int(count or 0)
    return counts

def _scan_aws_ecs(session, regions: List[str], issues: List[Dict[str, str]], inventory: Dict[str, Any]) -> None:
    from botocore.exceptions import BotoCoreError, ClientError
    ecs_summary = {"clusters": 0, "services": 0, "tasks": 0, "running_tasks": 0, "stopped_tasks": 0}
    inventory.setdefault("ecs_clusters", [])
    inventory.setdefault("ecs_services", [])
    inventory.setdefault("ecs_tasks", [])
    for region in regions:
        try:
            ecs = session.client("ecs", region_name=region)
            cluster_arns = []
            paginator = ecs.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []))
            ecs_summary["clusters"] += len(cluster_arns)
            for cluster_arn in cluster_arns:
                cluster_name = _arn_name(cluster_arn)
                inventory["ecs_clusters"].append({"region": region, "cluster_name": cluster_name, "cluster_arn": cluster_arn})

                service_arns = []
                try:
                    svc_paginator = ecs.get_paginator("list_services")
                    for page in svc_paginator.paginate(cluster=cluster_arn):
                        service_arns.extend(page.get("serviceArns", []))
                except (ClientError, BotoCoreError) as exc:
                    issues.append(_issue("AWS ECS service listing failed", "medium", f"{region}/{cluster_name}", str(exc), "Check ecs:ListServices permission."))

                for i in range(0, len(service_arns), 10):
                    services = ecs.describe_services(cluster=cluster_arn, services=service_arns[i:i+10]).get("services", [])
                    for service in services:
                        deployments = []
                        for dep in service.get("deployments", []) or []:
                            deployments.append({
                                "status": dep.get("status"),
                                "rollout_state": dep.get("rolloutState"),
                                "desired": dep.get("desiredCount"),
                                "running": dep.get("runningCount"),
                                "failed_tasks": dep.get("failedTasks"),
                            })
                            if dep.get("rolloutState") == "FAILED":
                                issues.append(_issue("ECS deployment failed", "high", f"{region}/{service.get('serviceName')}", dep.get("rolloutStateReason") or "Deployment rollout state is FAILED.", "Review ECS deployment events and task stop reasons."))
                        service_item = {
                            "region": region,
                            "cluster_name": cluster_name,
                            "service_name": service.get("serviceName"),
                            "status": service.get("status"),
                            "launch_type": service.get("launchType"),
                            "desired_count": service.get("desiredCount"),
                            "running_count": service.get("runningCount"),
                            "pending_count": service.get("pendingCount"),
                            "task_definition": service.get("taskDefinition"),
                            "deployments": deployments,
                        }
                        inventory["ecs_services"].append(service_item)
                        ecs_summary["services"] += 1
                        issue = _ecs_scan_status_issue(region, service)
                        if issue:
                            issues.append(issue)

                task_arns = []
                for desired_status in ["RUNNING", "STOPPED"]:
                    try:
                        task_paginator = ecs.get_paginator("list_tasks")
                        for page in task_paginator.paginate(cluster=cluster_arn, desiredStatus=desired_status):
                            task_arns.extend(page.get("taskArns", []))
                    except (ClientError, BotoCoreError) as exc:
                        issues.append(_issue("AWS ECS task listing failed", "medium", f"{region}/{cluster_name}", str(exc), "Check ecs:ListTasks permission."))
                for i in range(0, len(task_arns), 100):
                    tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns[i:i+100]).get("tasks", [])
                    for task in tasks:
                        last_status = task.get("lastStatus")
                        if last_status == "RUNNING":
                            ecs_summary["running_tasks"] += 1
                        elif last_status == "STOPPED":
                            ecs_summary["stopped_tasks"] += 1
                        containers = []
                        for container in task.get("containers", []) or []:
                            cont = {
                                "name": container.get("name"),
                                "image": container.get("image"),
                                "last_status": container.get("lastStatus"),
                                "exit_code": container.get("exitCode"),
                                "reason": container.get("reason"),
                            }
                            containers.append(cont)
                            if container.get("exitCode") not in (None, 0):
                                issues.append(_issue("ECS container exited with non-zero code", "high", f"{region}/{cluster_name}/{container.get('name')}", f"Exit code: {container.get('exitCode')}. Reason: {container.get('reason') or 'No reason returned'}.", "Open ECS task stopped reason and CloudWatch logs for the container."))
                        stopped_reason = task.get("stoppedReason")
                        if last_status == "STOPPED" and stopped_reason:
                            issues.append(_issue("ECS task stopped", "medium", f"{region}/{cluster_name}/{_arn_name(task.get('taskArn'))}", stopped_reason, "Review ECS task events, service events, and CloudWatch logs before redeploying."))
                        inventory["ecs_tasks"].append({
                            "region": region,
                            "cluster_name": cluster_name,
                            "task_arn": task.get("taskArn"),
                            "task_id": _arn_name(task.get("taskArn")),
                            "last_status": last_status,
                            "desired_status": task.get("desiredStatus"),
                            "launch_type": task.get("launchType"),
                            "health_status": task.get("healthStatus"),
                            "started_at": str(task.get("startedAt")) if task.get("startedAt") else None,
                            "stopped_at": str(task.get("stoppedAt")) if task.get("stoppedAt") else None,
                            "stopped_reason": stopped_reason,
                            "containers": containers,
                        })
                        ecs_summary["tasks"] += 1
        except (ClientError, BotoCoreError) as exc:
            issues.append(_issue("AWS ECS scan failed", "medium", region, str(exc), "Check IAM permissions for ecs:ListClusters, ecs:ListServices, ecs:ListTasks, ecs:DescribeServices, and ecs:DescribeTasks."))
    inventory["ecs_summary"] = ecs_summary

def _scan_aws_ecr(session, regions: List[str], issues: List[Dict[str, str]], inventory: Dict[str, Any]) -> None:
    from botocore.exceptions import BotoCoreError, ClientError
    ecr_summary = {"repositories": 0, "images": 0, "critical": 0, "high": 0}
    inventory.setdefault("ecr_repositories", [])
    inventory.setdefault("ecr_images", [])
    for region in regions:
        try:
            ecr = session.client("ecr", region_name=region)
            repositories = []
            paginator = ecr.get_paginator("describe_repositories")
            for page in paginator.paginate():
                repositories.extend(page.get("repositories", []))
            for repo in repositories:
                repo_name = repo.get("repositoryName")
                inventory["ecr_repositories"].append({"region": region, "repository_name": repo_name, "uri": repo.get("repositoryUri"), "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get("scanOnPush")})
                ecr_summary["repositories"] += 1
                if not (repo.get("imageScanningConfiguration") or {}).get("scanOnPush"):
                    issues.append(_issue("ECR scan-on-push disabled", "medium", f"{region}/{repo_name}", "Repository does not have scan-on-push enabled.", "Enable ECR image scanning or use enhanced scanning through Amazon Inspector."))
                images = []
                try:
                    img_paginator = ecr.get_paginator("describe_images")
                    for page in img_paginator.paginate(repositoryName=repo_name):
                        images.extend(page.get("imageDetails", []))
                except (ClientError, BotoCoreError) as exc:
                    issues.append(_issue("ECR image listing failed", "medium", f"{region}/{repo_name}", str(exc), "Check ecr:DescribeImages permission."))
                    continue
                for image in images[:25]:
                    image_digest = image.get("imageDigest")
                    tags = image.get("imageTags") or []
                    severity_counts = {}
                    try:
                        findings = ecr.describe_image_scan_findings(repositoryName=repo_name, imageId={"imageDigest": image_digest}).get("imageScanFindings", {})
                        severity_counts = _summarize_ecr_findings(findings)
                    except ClientError as exc:
                        code = exc.response.get("Error", {}).get("Code")
                        if code not in {"ScanNotFoundException", "ImageNotFoundException"}:
                            issues.append(_issue("ECR scan findings unavailable", "low", f"{region}/{repo_name}", str(exc), "Check ECR scan permissions or enable image scanning."))
                    critical = int(severity_counts.get("CRITICAL", 0) or 0)
                    high = int(severity_counts.get("HIGH", 0) or 0)
                    ecr_summary["critical"] += critical
                    ecr_summary["high"] += high
                    ecr_summary["images"] += 1
                    if critical:
                        issues.append(_issue("ECR image has critical vulnerabilities", "critical", f"{region}/{repo_name}:{tags[0] if tags else image_digest[:12]}", f"ECR reports {critical} critical vulnerability finding(s).", "Rebuild the image with patched base image and dependencies, then redeploy."))
                    elif high:
                        issues.append(_issue("ECR image has high vulnerabilities", "high", f"{region}/{repo_name}:{tags[0] if tags else image_digest[:12]}", f"ECR reports {high} high vulnerability finding(s).", "Patch base image and dependencies, then rerun the image scan."))
                    inventory["ecr_images"].append({
                        "region": region,
                        "repository_name": repo_name,
                        "image_digest": image_digest,
                        "image_tags": tags,
                        "pushed_at": str(image.get("imagePushedAt")) if image.get("imagePushedAt") else None,
                        "size_bytes": image.get("imageSizeInBytes"),
                        "severity_counts": severity_counts,
                    })
        except (ClientError, BotoCoreError) as exc:
            issues.append(_issue("AWS ECR scan failed", "medium", region, str(exc), "Check IAM permissions for ecr:DescribeRepositories, ecr:DescribeImages, and ecr:DescribeImageScanFindings."))
    inventory["ecr_summary"] = ecr_summary

def _run_ssm_command(session, region: str, instance_id: str, commands: List[str], timeout_seconds: int = 120) -> Dict[str, Any]:
    import time
    from botocore.exceptions import ClientError
    ssm = session.client("ssm", region_name=region)
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=timeout_seconds,
        CloudWatchOutputConfig={"CloudWatchOutputEnabled": False},
    )
    command_id = response["Command"]["CommandId"]
    last = {}
    for _ in range(max(1, timeout_seconds // 2)):
        time.sleep(2)
        try:
            last = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                continue
            raise
        if last.get("Status") in {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}:
            return last
    return last or {"Status": "TimedOut", "StandardErrorContent": "Timed out waiting for SSM command output."}


def _remote_docker_script(enable_trivy: bool, install_trivy: bool, scanners: str, severity: str, max_images: int, include_stats: bool = True, include_logs: bool = False, log_tail: int = 120, only_running: bool = False) -> str:
    enable_text = "True" if enable_trivy else "False"
    install_text = "true" if (enable_trivy and install_trivy) else "false"
    scanners = (scanners or "vuln,secret").replace("'", "")
    severity = (severity or "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").replace("'", "")
    max_images = int(max_images or 5)
    stats_text = "True" if include_stats else "False"
    logs_text = "True" if include_logs else "False"
    only_running_text = "True" if only_running else "False"
    log_tail = int(log_tail or 120)
    return f"""#!/usr/bin/env bash
set +e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

if ! command -v docker >/dev/null 2>&1; then
  echo "__DEVSECOPS_JSON_BEGIN__"
  echo '{{"docker_available":false,"error":"Docker is not installed or not in PATH on this EC2 instance.","debug":"command -v docker failed"}}'
  echo "__DEVSECOPS_JSON_END__"
  exit 0
fi

if [ "{install_text}" = "true" ] && ! command -v trivy >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update >/tmp/devsecops-trivy-install.log 2>&1
    sudo apt-get install -y wget apt-transport-https gnupg lsb-release ca-certificates >/tmp/devsecops-trivy-install.log 2>&1
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/tmp/devsecops-trivy-install.log
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null
    sudo apt-get update >/tmp/devsecops-trivy-install.log 2>&1
    sudo apt-get install -y trivy >/tmp/devsecops-trivy-install.log 2>&1
  fi
fi

PYBIN=""
if command -v python3 >/dev/null 2>&1; then PYBIN="python3"; elif command -v python >/dev/null 2>&1; then PYBIN="python"; fi
if [ -z "$PYBIN" ]; then
  echo "__DEVSECOPS_JSON_BEGIN__"
  echo '{{"docker_available":false,"error":"Python is not installed on this EC2 instance. Install python3 or update scanner to shell-only mode."}}'
  echo "__DEVSECOPS_JSON_END__"
  exit 0
fi

cat <<'PYREMOTE' | "$PYBIN"
import json, subprocess, socket, shutil, re, os
ENABLE_TRIVY = {enable_text}
SCANNERS = '{scanners}'
SEVERITY = '{severity}'
MAX_IMAGES = {max_images}
INCLUDE_STATS = {stats_text}
INCLUDE_LOGS = {logs_text}
ONLY_RUNNING = {only_running_text}
LOG_TAIL = {log_tail}
DEBUG = {{'commands': []}}

def run(cmd, timeout=25):
    # Prefer sudo because SSM command user often cannot access /var/run/docker.sock directly.
    candidates = []
    if cmd and cmd[0] in ('docker','trivy'):
        candidates.append(['sudo','-n'] + cmd)
        candidates.append(['sudo'] + cmd)
    candidates.append(cmd)
    last_err = ''
    for candidate in candidates:
        try:
            p = subprocess.run(candidate, text=True, capture_output=True, timeout=timeout)
            DEBUG['commands'].append({{'cmd':' '.join(candidate[:4]), 'rc': p.returncode, 'stderr': (p.stderr or '')[:250]}})
            if p.returncode == 0:
                return p.stdout.strip()
            last_err = (p.stderr or p.stdout or '').strip()
        except Exception as exc:
            last_err = str(exc)
            DEBUG['commands'].append({{'cmd':' '.join(candidate[:4]), 'rc':'exception', 'stderr': last_err[:250]}})
    return ''

def json_lines(text):
    out=[]
    for line in (text or '').splitlines():
        line=line.strip()
        if not line: continue
        try:
            obj=json.loads(line)
            if isinstance(obj, dict): out.append(obj)
        except Exception:
            pass
    return out

def parse_ps_table(text):
    # Fallback for environments where --format '{{json .}}' returns no parseable rows.
    rows=[]
    for line in (text or '').splitlines():
        if not line.strip() or line.startswith('CONTAINER ID') or line.startswith('ID '):
            continue
        parts=re.split(r'\s{{2,}}', line.rstrip())
        if len(parts) < 5:
            continue
        cid=parts[0]
        image=parts[1] if len(parts)>1 else ''
        command=parts[2] if len(parts)>2 else ''
        created=parts[3] if len(parts)>3 else ''
        status=parts[4] if len(parts)>4 else ''
        ports=''
        name=''
        if len(parts) >= 7:
            ports=parts[5]
            name=parts[6]
        elif len(parts) >= 6:
            name=parts[5]
        rows.append({{'ID':cid,'Image':image,'Command':command,'CreatedAt':created,'Status':status,'State':'running' if status.lower().startswith('up') else 'exited','Ports':ports,'Names':name}})
    return rows

ps_raw_json = run(['docker','ps','-a','--no-trunc','--format','{{{{json .}}}}'])
ps = json_lines(ps_raw_json)
ps_table = ''
if not ps:
    ps_table = run(['docker','ps','-a','--no-trunc'], timeout=25)
    ps = parse_ps_table(ps_table)
if ONLY_RUNNING:
    ps = [row for row in ps if str(row.get('State') or row.get('Status') or '').lower().startswith(('running','up'))]

stats = {{}}
if INCLUDE_STATS:
  for item in json_lines(run(['docker','stats','--no-stream','--format','{{{{json .}}}}'], timeout=30)):
    key = item.get('Container') or item.get('ID') or item.get('Name')
    if key: stats[key] = item

images_raw_json = run(['docker','images','--format','{{{{json .}}}}'])
images = json_lines(images_raw_json)
if not images:
    # Minimal fallback: keep raw image table for report debugging.
    images_table = run(['docker','images'], timeout=25)
    images=[]
    for line in images_table.splitlines()[1:]:
        parts=re.split(r'\s{{2,}}', line.strip())
        if len(parts)>=2:
            images.append({{'Repository':parts[0], 'Tag':parts[1]}})

df = run(['docker','system','df','--format','{{{{json .}}}}']) or run(['docker','system','df'])
containers=[]
for c in ps[:60]:
    cid = c.get('ID') or c.get('Container') or c.get('Names') or ''
    name_from_ps = c.get('Names') or c.get('Name') or ''
    inspect_raw = run(['docker','inspect', cid], timeout=20) if cid else ''
    try: inspect = json.loads(inspect_raw) if inspect_raw else []
    except Exception: inspect = []
    item = inspect[0] if inspect else {{}}
    state = item.get('State') or {{}}
    health = state.get('Health') or {{}}
    logs = run(['docker','logs','--tail',str(LOG_TAIL), cid], timeout=25)[:8000] if (INCLUDE_LOGS and cid) else ''
    st = stats.get(cid) or stats.get(cid[:12]) or stats.get(name_from_ps) or {{}}
    raw_status = state.get('Status') or c.get('State') or c.get('Status') or ''
    status = str(raw_status).lower()
    if status.startswith('up'): status='running'
    elif status.startswith('exited') or status.startswith('created'): status='exited'
    containers.append({{
        'id': (cid or '')[:12],
        'full_id': cid,
        'name': (name_from_ps or item.get('Name') or '').lstrip('/'),
        'image': c.get('Image') or item.get('Config',{{}}).get('Image'),
        'status': status,
        'raw_status': c.get('Status') or state.get('Status'),
        'health': health.get('Status'),
        'exit_code': state.get('ExitCode'),
        'restart_count': item.get('RestartCount'),
        'ports': c.get('Ports'),
        'logs_tail': logs,
        'stats': {{'cpu_percent': st.get('CPUPerc'), 'memory': st.get('MemUsage')}},
        'state': {{'status': state.get('Status'), 'oom_killed': state.get('OOMKilled'), 'dead': state.get('Dead'), 'error': state.get('Error'), 'started_at': state.get('StartedAt'), 'finished_at': state.get('FinishedAt')}},
        'detected_error': state.get('Error') or (logs.splitlines()[-1] if re.search(r'(?i)error|exception|failed|traceback', logs or '') else '')
    }})

trivy_result = {{'enabled': ENABLE_TRIVY, 'available': bool(shutil.which('trivy')), 'images_scanned': 0, 'summary': {{'critical':0,'high':0,'secrets':0}}, 'images': []}}
if ENABLE_TRIVY and shutil.which('trivy'):
    seen=[]
    for img in images:
        name = img.get('Repository','') + ((':'+img.get('Tag','')) if img.get('Tag') and img.get('Tag') != '<none>' else '')
        if not name or '<none>' in name or name in seen: continue
        seen.append(name)
        if len(seen) > MAX_IMAGES: break
        raw = run(['trivy','image','--quiet','--scanners',SCANNERS,'--severity',SEVERITY,'--format','json', name], timeout=120)
        crit=high=secrets=0
        try:
            data=json.loads(raw) if raw else {{}}
            for r in data.get('Results',[]) or []:
                for v in r.get('Vulnerabilities',[]) or []:
                    sev=(v.get('Severity') or '').upper()
                    if sev=='CRITICAL': crit+=1
                    if sev=='HIGH': high+=1
                secrets += len(r.get('Secrets',[]) or [])
        except Exception:
            pass
        trivy_result['images_scanned'] += 1
        trivy_result['summary']['critical'] += crit
        trivy_result['summary']['high'] += high
        trivy_result['summary']['secrets'] += secrets
        trivy_result['images'].append({{'image': name, 'critical': crit, 'high': high, 'secrets': secrets}})
elif ENABLE_TRIVY:
    trivy_result['message'] = 'Trivy is not installed on this EC2 instance. Enable auto-install or install Trivy manually.'

result={{
  'docker_available': True,
  'host_name': socket.gethostname(),
  'summary': {{'containers_scanned': len(containers), 'running': sum(1 for c in containers if c.get('status')=='running'), 'stopped': sum(1 for c in containers if c.get('status')!='running'), 'images': len(images)}},
  'containers': containers,
  'images': images[:50],
  'docker_system_df': df,
  'remote_trivy': trivy_result,
  'debug': {{'ps_json_rows': len(json_lines(ps_raw_json)), 'ps_table_used': bool(ps_table), 'ps_table_preview': ps_table[:1000], 'command_attempts': DEBUG.get('commands',[])[:20], 'include_stats': INCLUDE_STATS, 'include_logs': INCLUDE_LOGS, 'only_running': ONLY_RUNNING, 'log_tail': LOG_TAIL}}
}}
print('__DEVSECOPS_JSON_BEGIN__')
print(json.dumps(result))
print('__DEVSECOPS_JSON_END__')
PYREMOTE
"""

def _parse_docker_ps_table_output(text: str) -> List[Dict[str, Any]]:
    import re
    rows: List[Dict[str, Any]] = []
    for line in (text or "").replace("\\n", "\n").splitlines():
        line = line.rstrip()
        if not line.strip() or line.startswith("CONTAINER ID") or line.startswith("ID "):
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 5:
            continue
        cid = parts[0].strip()
        image = parts[1].strip() if len(parts) > 1 else ""
        command = parts[2].strip() if len(parts) > 2 else ""
        created = parts[3].strip() if len(parts) > 3 else ""
        status_text = parts[4].strip() if len(parts) > 4 else ""
        ports = ""
        name = ""
        if len(parts) >= 7:
            ports = parts[5].strip()
            name = parts[6].strip()
        elif len(parts) >= 6:
            name = parts[5].strip()
        normalized = "running" if status_text.lower().startswith("up") else "exited"
        rows.append({
            "id": cid[:12],
            "full_id": cid,
            "name": name,
            "image": image,
            "command": command,
            "created": created,
            "status": normalized,
            "raw_status": status_text,
            "ports": ports,
            "health": None,
            "exit_code": None,
            "detected_error": "Container is stopped or exited" if normalized != "running" else "",
        })
    return rows


def _extract_remote_json(output: str) -> Dict[str, Any]:
    import json
    normalized_output = (output or "").replace("\\n", "\n")
    start = normalized_output.find("__DEVSECOPS_JSON_BEGIN__")
    end = normalized_output.find("__DEVSECOPS_JSON_END__")
    if start == -1 or end == -1:
        # Defensive fallback: if SSM returns a normal docker ps -a table, still parse it.
        table_containers = _parse_docker_ps_table_output(normalized_output)
        if table_containers:
            return {
                "docker_available": True,
                "host_name": "ec2-ssm-target",
                "summary": {
                    "containers_scanned": len(table_containers),
                    "running": sum(1 for c in table_containers if c.get("status") == "running"),
                    "stopped": sum(1 for c in table_containers if c.get("status") != "running"),
                    "images": 0,
                },
                "containers": table_containers,
                "images": [],
                "docker_system_df": "",
                "remote_trivy": {"enabled": False, "available": False, "images_scanned": 0, "summary": {}},
                "debug": {"fallback_table_parser": True, "raw_output_preview": normalized_output[:1000]},
            }
        return {"docker_available": False, "error": "Remote command output did not include DevSecOps JSON markers and no docker ps table could be parsed.", "raw_output": normalized_output[:4000]}
    body = normalized_output[start + len("__DEVSECOPS_JSON_BEGIN__"):end].strip()
    try:
        return json.loads(body)
    except Exception as exc:
        table_containers = _parse_docker_ps_table_output(body)
        if table_containers:
            return {"docker_available": True, "summary": {"containers_scanned": len(table_containers), "running": sum(1 for c in table_containers if c.get("status") == "running"), "stopped": sum(1 for c in table_containers if c.get("status") != "running"), "images": 0}, "containers": table_containers, "images": [], "docker_system_df": "", "remote_trivy": {"enabled": False, "available": False, "images_scanned": 0, "summary": {}}, "debug": {"fallback_table_parser_after_json_error": True}}
        return {"docker_available": False, "error": f"Could not parse remote Docker JSON: {exc}", "raw_output": body[:4000]}



def _json_lines_from_section(text: str, begin: str, end: str) -> List[Dict[str, Any]]:
    import json
    section = _section(text, begin, end)
    rows: List[Dict[str, Any]] = []
    for line in section.splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
        except Exception:
            continue
    return rows


def _section(text: str, begin: str, end: str) -> str:
    text = text or ""
    a = text.find(begin)
    b = text.find(end)
    if a == -1:
        return ""
    a += len(begin)
    if b == -1 or b < a:
        return text[a:]
    return text[a:b]


def _normalize_remote_ps_row(row: Dict[str, Any], stats: Dict[str, Any], state_by_id: Dict[str, Any], logs_by_id: Dict[str, str]) -> Dict[str, Any]:
    cid = row.get("ID") or row.get("Container") or ""
    short = str(cid)[:12]
    name = row.get("Names") or row.get("Name") or ""
    raw_state = (row.get("State") or row.get("Status") or "").lower()
    status = "running" if raw_state.startswith(("running", "up")) else "exited" if raw_state.startswith(("exited", "created", "dead")) else raw_state or "unknown"
    st = stats.get(short) or stats.get(cid) or stats.get(name) or {}
    state_obj = state_by_id.get(short) or state_by_id.get(cid) or {}
    health = state_obj.get("Health") if isinstance(state_obj.get("Health"), dict) else {}
    logs = logs_by_id.get(short) or logs_by_id.get(cid) or ""
    exit_code = state_obj.get("ExitCode") if isinstance(state_obj, dict) else None
    detected_error = ""
    if status != "running":
        detected_error = f"Container is {row.get('Status') or status}"
    if logs and any(token in logs.lower() for token in ["error", "exception", "failed", "traceback", "fatal"]):
        detected_error = (logs.splitlines()[-1] if logs.splitlines() else logs)[:500]
    return {
        "id": short,
        "full_id": cid,
        "name": str(name).lstrip('/'),
        "image": row.get("Image") or row.get("Repository") or "",
        "command": row.get("Command") or "",
        "status": status,
        "raw_status": row.get("Status") or row.get("State") or "",
        "health": health.get("Status") if isinstance(health, dict) else None,
        "exit_code": exit_code,
        "restart_count": state_obj.get("RestartCount") if isinstance(state_obj, dict) else None,
        "ports": row.get("Ports") or "",
        "mounts": row.get("Mounts") or "",
        "logs_tail": logs,
        "stats": {"cpu_percent": st.get("CPUPerc"), "memory": st.get("MemUsage")},
        "state": {
            "status": state_obj.get("Status") if isinstance(state_obj, dict) else None,
            "oom_killed": state_obj.get("OOMKilled") if isinstance(state_obj, dict) else None,
            "dead": state_obj.get("Dead") if isinstance(state_obj, dict) else None,
            "error": state_obj.get("Error") if isinstance(state_obj, dict) else None,
            "started_at": state_obj.get("StartedAt") if isinstance(state_obj, dict) else None,
            "finished_at": state_obj.get("FinishedAt") if isinstance(state_obj, dict) else None,
        },
        "detected_error": detected_error,
    }


def _parse_remote_ec2_docker_output(stdout: str, include_logs: bool) -> Dict[str, Any]:
    import json
    normalized = (stdout or "").replace("\\n", "\n")
    ps_rows = _json_lines_from_section(normalized, "__DEVSECOPS_PS_JSON_BEGIN__", "__DEVSECOPS_PS_JSON_END__")
    if not ps_rows:
        # Fallback to any JSON docker ps rows present anywhere in stdout.
        ps_rows = []
        for line in normalized.splitlines():
            line = line.strip()
            if line.startswith('{') and '"Image"' in line and ('"Names"' in line or '"ID"' in line):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and obj.get("ID") and obj.get("Image"):
                        ps_rows.append(obj)
                except Exception:
                    pass
    stats_rows = _json_lines_from_section(normalized, "__DEVSECOPS_STATS_JSON_BEGIN__", "__DEVSECOPS_STATS_JSON_END__")
    stats: Dict[str, Any] = {}
    for row in stats_rows:
        for key in [row.get("Container"), row.get("ID"), row.get("Name")]:
            if key:
                stats[str(key)] = row
    state_rows = _json_lines_from_section(normalized, "__DEVSECOPS_STATE_JSON_BEGIN__", "__DEVSECOPS_STATE_JSON_END__")
    state_by_id: Dict[str, Any] = {}
    for row in state_rows:
        cid = str(row.get("Id") or "")
        state = row.get("State") or {}
        if cid:
            state_by_id[cid] = state
            state_by_id[cid[:12]] = state
            if "RestartCount" in row and isinstance(state, dict):
                state["RestartCount"] = row.get("RestartCount")
    logs_by_id: Dict[str, str] = {}
    if include_logs:
        for block in normalized.split("__DEVSECOPS_LOG_BEGIN__"):
            if "__DEVSECOPS_LOG_END__" not in block:
                continue
            first, rest = block.split("\n", 1) if "\n" in block else (block, "")
            cid = first.strip()
            content = rest.split("__DEVSECOPS_LOG_END__", 1)[0]
            if cid:
                logs_by_id[cid] = content.strip()[:8000]
                logs_by_id[cid[:12]] = content.strip()[:8000]
    image_rows = _json_lines_from_section(normalized, "__DEVSECOPS_IMAGES_JSON_BEGIN__", "__DEVSECOPS_IMAGES_JSON_END__")
    df = _section(normalized, "__DEVSECOPS_DF_BEGIN__", "__DEVSECOPS_DF_END__").strip()
    containers = [_normalize_remote_ps_row(row, stats, state_by_id, logs_by_id) for row in ps_rows]
    return {
        "docker_available": bool(ps_rows) or "Cannot connect to the Docker daemon" not in normalized,
        "host_name": (normalized.splitlines()[0].strip() if normalized.splitlines() else "ec2-ssm-target"),
        "summary": {
            "containers_scanned": len(containers),
            "running": sum(1 for c in containers if c.get("status") == "running"),
            "stopped": sum(1 for c in containers if c.get("status") != "running"),
            "images": len(image_rows),
        },
        "containers": containers,
        "images": image_rows[:80],
        "docker_system_df": df,
        "remote_trivy": {"enabled": False, "available": False, "images_scanned": 0, "summary": {}},
        "debug": {
            "parser": "backend_marker_parser_v25",
            "stdout_bytes": len(stdout or ""),
            "ps_rows": len(ps_rows),
            "stats_rows": len(stats_rows),
            "state_rows": len(state_rows),
            "image_rows": len(image_rows),
            "stdout_preview": normalized[:1200],
        },
    }


def _remote_ec2_docker_commands(include_stats: bool, include_logs: bool, log_tail: int, only_running: bool) -> List[str]:
    ps_filter = "" if not only_running else "--filter status=running"
    commands = [
        "hostname",
        "echo __DEVSECOPS_PS_JSON_BEGIN__",
        f"sudo docker ps -a --no-trunc {ps_filter} --format '{{{{json .}}}}' 2>&1 || true",
        "echo __DEVSECOPS_PS_JSON_END__",
        "echo __DEVSECOPS_STATE_JSON_BEGIN__",
        "for id in $(sudo docker ps -a -q --no-trunc 2>/dev/null); do sudo docker inspect --format '{\"Id\":\"{{.Id}}\",\"RestartCount\":{{.RestartCount}},\"State\":{{json .State}}}' $id 2>/dev/null || true; done",
        "echo __DEVSECOPS_STATE_JSON_END__",
        "echo __DEVSECOPS_IMAGES_JSON_BEGIN__",
        "sudo docker images --format '{{json .}}' 2>&1 || true",
        "echo __DEVSECOPS_IMAGES_JSON_END__",
        "echo __DEVSECOPS_DF_BEGIN__",
        "sudo docker system df 2>&1 || true",
        "echo __DEVSECOPS_DF_END__",
    ]
    if include_stats:
        commands[4:4] = [
            "echo __DEVSECOPS_STATS_JSON_BEGIN__",
            "sudo docker stats --no-stream --format '{{json .}}' 2>&1 || true",
            "echo __DEVSECOPS_STATS_JSON_END__",
        ]
    if include_logs:
        tail = max(1, min(int(log_tail or 120), 500))
        commands += [
            f"for id in $(sudo docker ps -a -q --no-trunc {ps_filter} 2>/dev/null | head -20); do echo __DEVSECOPS_LOG_BEGIN__; echo $id; sudo docker logs --tail {tail} $id 2>&1 | tail -c 8000; echo __DEVSECOPS_LOG_END__; done"
        ]
    return commands


def _scan_aws_ec2_docker(session, regions: List[str], credentials: Dict[str, Any], issues: List[Dict[str, str]], inventory: Dict[str, Any]) -> None:
    from botocore.exceptions import BotoCoreError, ClientError
    selected = credentials.get("ec2_instance_ids") or []
    if not selected:
        inventory["ec2_docker_summary"] = {"instances": 0, "containers": 0, "running": 0, "stopped": 0}
        issues.append(_issue("AWS EC2 Docker scan skipped", "low", "aws/ec2", "No EC2 instances were selected for remote Docker inspection.", "Click Load EC2 Instances, select SSM-managed instances, then run the scan again."))
        return
    enable_trivy = bool(credentials.get("_remote_trivy_enabled"))
    install_trivy = bool(credentials.get("install_trivy_on_ec2"))
    scanners = str(credentials.get("_trivy_scanners") or "vuln,secret")
    severity = str(credentials.get("_trivy_severity") or "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
    max_images = int(credentials.get("_trivy_max_images") or 5)
    include_stats = bool(credentials.get("_include_stats", True))
    include_logs = bool(credentials.get("_include_logs", False))
    only_running = bool(credentials.get("_only_running", False))
    log_tail = int(credentials.get("_log_tail") or 120)
    inventory.setdefault("ec2_docker_instances", [])
    inventory.setdefault("ec2_docker_containers", [])
    inventory["ec2_docker_selected_targets"] = selected
    inventory.setdefault("ec2_docker_debug", [])
    summary = {"instances": 0, "containers": 0, "running": 0, "stopped": 0, "trivy_images_scanned": 0}
    by_region: Dict[str, List[str]] = {r: [] for r in regions}
    for value in selected:
        if ":" in value:
            reg, iid = value.split(":", 1)
            by_region.setdefault(reg, []).append(iid)
        else:
            for reg in regions:
                by_region.setdefault(reg, []).append(value)
    for region, instance_ids in by_region.items():
        for instance_id in sorted(set(instance_ids)):
            try:
                commands = _remote_ec2_docker_commands(include_stats=include_stats, include_logs=include_logs, log_tail=log_tail, only_running=only_running)
                invocation = _run_ssm_command(session, region, instance_id, commands, timeout_seconds=180)
                status = invocation.get("Status")
                stdout = invocation.get("StandardOutputContent") or ""
                stderr = invocation.get("StandardErrorContent") or ""
                parsed = _parse_remote_ec2_docker_output(stdout, include_logs=include_logs)
                # Legacy fallback, in case a previous rich script response is returned.
                if not parsed.get("containers") and "__DEVSECOPS_JSON_BEGIN__" in stdout:
                    legacy = _extract_remote_json(stdout)
                    if legacy.get("containers"):
                        parsed = legacy
                inst_item = {"region": region, "instance_id": instance_id, "ssm_status": status, "stderr": stderr[:2000], **parsed}
                inventory["ec2_docker_instances"].append(inst_item)
                inventory["ec2_docker_debug"].append({"region": region, "instance_id": instance_id, "status": status, "stdout_bytes": len(stdout), "stderr_preview": stderr[:500], "parsed_summary": parsed.get("summary"), "debug": parsed.get("debug")})
                summary["instances"] += 1
                if status != "Success":
                    issues.append(_issue("EC2 Docker SSM command failed", "high", f"{region}/{instance_id}", stderr or status or "SSM command did not complete successfully.", "Confirm the instance is SSM-managed and can run sudo docker ps -a through Run Command."))
                if parsed.get("docker_available") is False:
                    issues.append(_issue("Docker unavailable on EC2 instance", "medium", f"{region}/{instance_id}", parsed.get("error", "Docker command did not run."), "Install Docker and confirm sudo docker ps -a works from Systems Manager Run Command."))
                containers_found = parsed.get("containers", []) or []
                if status == "Success" and not containers_found:
                    issues.append(_issue("No Docker containers parsed from selected EC2", "medium", f"{region}/{instance_id}", f"SSM succeeded but parser found zero containers. Stdout bytes: {len(stdout)}. Check report debug for stdout preview.", "Run sudo docker ps -a --no-trunc --format '{{json .}}' through SSM and compare output."))
                for container in containers_found:
                    item = {"region": region, "instance_id": instance_id, **container}
                    inventory["ec2_docker_containers"].append(item)
                    summary["containers"] += 1
                    if item.get("status") == "running": summary["running"] += 1
                    else: summary["stopped"] += 1
                    if item.get("detected_error"):
                        issues.append(_issue("EC2 Docker container shows error signal", "medium", f"{region}/{instance_id}/{item.get('name')}", str(item.get("detected_error"))[:500], "Open the container diagnostics/log output and fix the failing app or configuration."))
                if enable_trivy:
                    # Trivy can be added as a separate SSM step later. Keep explicit status for now so the user is not misled.
                    if install_trivy:
                        issues.append(_issue("Remote Trivy auto-install requested", "low", f"{region}/{instance_id}", "This version focuses on reliable EC2 Docker inventory first. Remote Trivy install/scan is not executed in the compact SSM parser path.", "Install Trivy manually on EC2 or use local/ECR image scanning."))
                    else:
                        issues.append(_issue("Remote Trivy not executed", "low", f"{region}/{instance_id}", "Trivy was enabled, but EC2 Docker inventory uses compact SSM mode. Install Trivy on the EC2 host and run a dedicated image scan in a later version.", "trivy image <image>"))
            except (BotoCoreError, ClientError) as exc:
                issues.append(_issue("EC2 Docker SSM scan failed", "high", f"{region}/{instance_id}", str(exc), "Check ssm:SendCommand, ssm:GetCommandInvocation, instance SSM readiness, and region selection."))
            except Exception as exc:
                issues.append(_issue("EC2 Docker scan failed", "high", f"{region}/{instance_id}", str(exc), "Review backend logs and the EC2 SSM setup."))
    inventory["ec2_docker_summary"] = summary



def _remote_ec2_docker_diagnostic_commands(container_id: str, tail: int) -> List[str]:
    import shlex
    safe_id = shlex.quote(str(container_id))
    safe_tail = max(10, min(int(tail or 250), 1000))
    # Put logs first and keep inspect output compact. AWS SSM get-command-invocation
    # truncates StandardOutputContent, and full `docker inspect` output can be huge.
    # If inspect comes first, the useful container logs can be truncated away.
    compact_inspect_template = (
        "'{"
        "\"Id\":{{json .Id}},"
        "\"Name\":{{json .Name}},"
        "\"Config\":{\"Image\":{{json .Config.Image}}},"
        "\"State\":{{json .State}},"
        "\"RestartCount\":{{json .RestartCount}},"
        "\"NetworkSettings\":{\"Ports\":{{json .NetworkSettings.Ports}}},"
        "\"Mounts\":{{json .Mounts}}"
        "}'"
    )
    return [
        "echo __DEVSECOPS_LOGS_BEGIN__",
        f"sudo docker logs --tail {safe_tail} {safe_id} 2>&1 | tail -c 12000 || true",
        "echo __DEVSECOPS_LOGS_END__",
        "echo __DEVSECOPS_INSPECT_BEGIN__",
        f"sudo docker inspect --format {compact_inspect_template} {safe_id} 2>&1 || true",
        "echo __DEVSECOPS_INSPECT_END__",
    ]


def _first_json_object_from_text(text: str) -> Dict[str, Any]:
    """Return the first complete JSON object/list found in SSM text output.

    Docker/SSM output can include shell noise, wrapped text, or a compact
    docker inspect object. This helper avoids treating the word "Error"
    inside docker inspect JSON as an actual command error.
    """
    import json
    if not text:
        return {}
    stripped = str(text).strip()
    # Fast path: the entire payload is a JSON object or list.
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list) and parsed:
            return parsed[0] if isinstance(parsed[0], dict) else {}
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Try line-by-line first because docker inspect --format should emit one line.
    for line in stripped.splitlines():
        line = line.strip()
        if not line or line[0] not in "[{":
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, list) and parsed:
                return parsed[0] if isinstance(parsed[0], dict) else {}
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue

    # Last-resort brace scanner for output with leading/trailing noise.
    start = stripped.find('{')
    if start == -1:
        start = stripped.find('[')
    if start == -1:
        return {}
    opening = stripped[start]
    closing = '}' if opening == '{' else ']'
    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                candidate = stripped[start:idx + 1]
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, list) and parsed:
                        return parsed[0] if isinstance(parsed[0], dict) else {}
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    return {}
    return {}


def get_aws_ec2_docker_diagnostics(credentials: Dict[str, Any], region: str, instance_id: str, container_id: str, tail: int = 250) -> Dict[str, Any]:
    """Fetch live diagnostics for one plain Docker container on an EC2 host via SSM.

    v29 reliability fix:
    - Run docker logs and docker inspect as separate SSM commands.
    - Use the stored full container ID from the scan.
    - Return logs even when inspect output is large or unusual.

    AWS SSM StandardOutputContent can be truncated or polluted by large inspect output.
    Keeping logs in a dedicated invocation avoids losing the actual application error.
    """
    try:
        import boto3
    except Exception as exc:
        raise CloudScanError("AWS diagnostics requires boto3. Rebuild the backend image with updated requirements.txt.") from exc

    access_key = credentials.get("access_key_id")
    secret_key = credentials.get("secret_access_key")
    session_token = credentials.get("session_token") or None
    if not access_key or not secret_key:
        raise CloudScanError("AWS access key ID and secret access key are required to fetch EC2 Docker diagnostics.")
    if not region or not instance_id or not container_id:
        raise CloudScanError("Region, instance ID, and container ID are required for EC2 Docker diagnostics.")

    import shlex

    safe_id = shlex.quote(str(container_id))
    safe_tail = max(10, min(int(tail or 250), 1000))

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region,
    )

    # 1) Fetch logs in a separate command so MySQL/Node/Nginx startup errors are not
    # hidden by large docker inspect output. docker logs may write to stderr, so merge it.
    logs_invocation = _run_ssm_command(
        session,
        region,
        instance_id,
        [f"sudo docker logs --tail {safe_tail} {safe_id} 2>&1 | tail -c 16000 || true"],
        timeout_seconds=90,
    )
    logs_status = logs_invocation.get("Status")
    logs_stdout = logs_invocation.get("StandardOutputContent") or ""
    logs_stderr = logs_invocation.get("StandardErrorContent") or ""
    logs_text = logs_stdout.replace("\\n", "\n").strip()
    if not logs_text and logs_stderr:
        logs_text = logs_stderr.replace("\\n", "\n").strip()

    # 2) Fetch a compact inspect payload. Avoid full docker inspect because it can be huge.
    compact_inspect_template = (
        "'{"
        "\"Id\":{{json .Id}},"
        "\"Name\":{{json .Name}},"
        "\"Config\":{\"Image\":{{json .Config.Image}}},"
        "\"State\":{{json .State}},"
        "\"RestartCount\":{{json .RestartCount}},"
        "\"NetworkSettings\":{\"Ports\":{{json .NetworkSettings.Ports}}},"
        "\"Mounts\":{{json .Mounts}}"
        "}'"
    )
    inspect_invocation = _run_ssm_command(
        session,
        region,
        instance_id,
        [f"sudo docker inspect --format {compact_inspect_template} {safe_id} 2>&1 || true"],
        timeout_seconds=90,
    )
    inspect_status = inspect_invocation.get("Status")
    inspect_stdout = (inspect_invocation.get("StandardOutputContent") or "").replace("\\n", "\n").strip()
    inspect_stderr = (inspect_invocation.get("StandardErrorContent") or "").replace("\\n", "\n").strip()

    if logs_status != "Success" and inspect_status != "Success":
        raise CloudScanError(
            f"SSM diagnostics commands did not succeed. logs={logs_status}, inspect={inspect_status}. "
            f"{(logs_stderr or inspect_stderr)[:800]}"
        )

    inspect_obj: Dict[str, Any] = _first_json_object_from_text(inspect_stdout)

    # Only treat inspect output as an actual command error when it is plain text.
    # A normal docker inspect JSON object contains a State.Error field, so checking
    # the substring "Error" caused false failures and hid container logs.
    if not inspect_obj and ("No such object" in inspect_stdout or "No such container" in inspect_stdout):
        raise CloudScanError(inspect_stdout[:800])

    # Do not fail the diagnostics call if inspect parsing is unusual. Return the
    # logs anyway so stopped containers still show the application error.
    if not inspect_obj:
        inspect_obj = {
            "Id": container_id,
            "Name": str(container_id),
            "Config": {},
            "State": {},
            "RestartCount": None,
            "NetworkSettings": {"Ports": {}},
            "Mounts": [],
        }

    state = inspect_obj.get("State") or {}
    config = inspect_obj.get("Config") or {}
    network_settings = inspect_obj.get("NetworkSettings") or {}
    health = state.get("Health") if isinstance(state.get("Health"), dict) else {}
    cid = inspect_obj.get("Id") or container_id
    name = (inspect_obj.get("Name") or container_id).lstrip("/")
    raw_status = state.get("Status") or "unknown"
    status_norm = str(raw_status).lower()

    detected_error = state.get("Error") or ""
    if not detected_error:
        for line in logs_text.splitlines():
            lowered = line.lower()
            if any(token in lowered for token in ["[error]", " error", "error]", "failed", "fatal", "exception", "traceback", "password option is not specified"]):
                detected_error = line.strip()[:700]
                break
    if not detected_error and status_norm != "running":
        exit_code = state.get("ExitCode")
        detected_error = f"Container is {status_norm} with exit code {exit_code}. Review logs below for the application error."

    health_log = []
    for entry in (health.get("Log") or []) if isinstance(health, dict) else []:
        health_log.append({
            "start": entry.get("Start"),
            "end": entry.get("End"),
            "exit_code": entry.get("ExitCode"),
            "output": (entry.get("Output") or "")[-4000:],
        })

    return {
        "id": str(cid)[:12],
        "full_id": cid,
        "name": name,
        "image": config.get("Image") or inspect_obj.get("Image") or "",
        "status": status_norm,
        "raw_status": raw_status,
        "health": {
            "status": (health.get("Status") if isinstance(health, dict) else None) or "not configured",
            "failing_streak": health.get("FailingStreak") if isinstance(health, dict) else None,
            "log": health_log,
        },
        "exit_code": state.get("ExitCode"),
        "restart_count": inspect_obj.get("RestartCount"),
        "ports": network_settings.get("Ports") or {},
        "mounts": inspect_obj.get("Mounts") or [],
        "logs_tail": logs_text,
        "logs_command_status": logs_status,
        "inspect_command_status": inspect_status,
        "stats": {},
        "state": {
            "status": state.get("Status"),
            "running": state.get("Running"),
            "paused": state.get("Paused"),
            "restarting": state.get("Restarting"),
            "exit_code": state.get("ExitCode"),
            "oom_killed": state.get("OOMKilled"),
            "dead": state.get("Dead"),
            "error": state.get("Error"),
            "started_at": state.get("StartedAt"),
            "finished_at": state.get("FinishedAt"),
        },
        "health_detail": health,
        "inspect": inspect_obj,
        "detected_error": detected_error,
        "region": region,
        "instance_id": instance_id,
        "diagnostics_source": "aws-ssm-live-docker-logs-then-compact-inspect",
    }


def scan_aws(credentials: Dict[str, Any], services: List[str], regions: List[str]) -> Dict[str, Any]:
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except Exception as exc:
        raise CloudScanError("AWS scanner requires boto3. Rebuild the backend image with updated requirements.txt.") from exc

    access_key = credentials.get("access_key_id")
    secret_key = credentials.get("secret_access_key")
    session_token = credentials.get("session_token") or None
    default_region = credentials.get("region") or "us-east-1"
    regions = regions or [default_region]

    if not access_key or not secret_key:
        raise CloudScanError("AWS access key ID and secret access key are required.")

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=default_region,
    )
    issues: List[Dict[str, str]] = []
    inventory: Dict[str, Any] = {"regions": regions, "identity": {}, "security_groups": [], "s3_buckets": [], "ecs_summary": {}, "ecr_summary": {}}

    try:
        identity = session.client("sts").get_caller_identity()
        inventory["identity"] = {"account": identity.get("Account"), "arn": identity.get("Arn"), "user_id": identity.get("UserId")}
    except Exception as exc:
        raise CloudScanError(f"AWS credential validation failed: {exc}") from exc

    if "ec2" in services or "security_groups" in services:
        for region in regions:
            try:
                ec2 = session.client("ec2", region_name=region)
                groups = ec2.describe_security_groups().get("SecurityGroups", [])
                for sg in groups:
                    sg_summary = {"region": region, "group_id": sg.get("GroupId"), "group_name": sg.get("GroupName"), "vpc_id": sg.get("VpcId"), "open_rules": []}
                    for perm in sg.get("IpPermissions", []):
                        port_text = _port_range(perm)
                        for ip_range in perm.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp")
                            if _is_public_cidr(cidr):
                                sg_summary["open_rules"].append({"cidr": cidr, "port": port_text})
                                issues.append(_issue(
                                    "Public inbound security group rule",
                                    _public_port_severity(port_text),
                                    f"{region}/{sg.get('GroupId')}",
                                    f"Inbound {port_text} is open to {cidr}.",
                                    "Restrict the source CIDR to trusted IP ranges or private networks.",
                                ))
                        for ip_range in perm.get("Ipv6Ranges", []):
                            cidr = ip_range.get("CidrIpv6")
                            if _is_public_cidr(cidr):
                                sg_summary["open_rules"].append({"cidr": cidr, "port": port_text})
                                issues.append(_issue(
                                    "Public IPv6 inbound security group rule",
                                    _public_port_severity(port_text),
                                    f"{region}/{sg.get('GroupId')}",
                                    f"Inbound {port_text} is open to {cidr}.",
                                    "Restrict IPv6 ingress to trusted ranges or remove the rule if not required.",
                                ))
                    inventory["security_groups"].append(sg_summary)
            except (ClientError, BotoCoreError) as exc:
                issues.append(_issue("AWS EC2 scan failed", "medium", region, str(exc), "Check IAM permissions for ec2:DescribeSecurityGroups."))

    if "s3" in services:
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket.get("Name")
                bucket_summary = {"name": name, "public_access_block": None, "policy_status": None}
                try:
                    pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                    bucket_summary["public_access_block"] = pab
                    if not all([pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"), pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets")]):
                        issues.append(_issue(
                            "S3 public access block not fully enabled",
                            "medium",
                            name,
                            "One or more S3 Public Access Block controls are disabled.",
                            "Enable all four S3 Public Access Block settings unless a public bucket is intentionally required.",
                        ))
                except ClientError as exc:
                    issues.append(_issue("Cannot read S3 public access block", "low", name, str(exc), "Grant s3:GetBucketPublicAccessBlock or review the bucket manually."))
                try:
                    status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
                    bucket_summary["policy_status"] = status
                    if status.get("IsPublic"):
                        issues.append(_issue("S3 bucket policy is public", "critical", name, "AWS reports the bucket policy as public.", "Review bucket policy immediately and remove public principals unless explicitly required."))
                except ClientError:
                    pass
                inventory["s3_buckets"].append(bucket_summary)
        except (ClientError, BotoCoreError) as exc:
            issues.append(_issue("AWS S3 scan failed", "medium", "s3", str(exc), "Check IAM permissions for s3:ListAllMyBuckets and bucket public access APIs."))

    if "iam" in services:
        try:
            iam = session.client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})
            inventory["iam_summary"] = summary
            if summary.get("AccountMFAEnabled", 0) == 0:
                issues.append(_issue("AWS account MFA not enabled", "high", "iam/account", "Account-level/root MFA is not enabled according to IAM summary.", "Enable MFA for the root account and privileged IAM users."))
            if summary.get("Users", 0) > 0:
                issues.append(_issue("IAM users detected", "low", "iam/users", f"{summary.get('Users')} IAM user(s) exist.", "Prefer IAM Identity Center or short-lived role access where possible."))
        except (ClientError, BotoCoreError) as exc:
            issues.append(_issue("AWS IAM scan failed", "medium", "iam", str(exc), "Check IAM permissions for iam:GetAccountSummary."))

    if "ecs" in services or "aws_containers" in services:
        _scan_aws_ecs(session, regions, issues, inventory)

    if "ecr" in services or "aws_images" in services:
        _scan_aws_ecr(session, regions, issues, inventory)

    if "ec2_docker" in services or "aws_ec2_docker" in services:
        _scan_aws_ec2_docker(session, regions, credentials, issues, inventory)

    return _cloud_result("aws", inventory, issues)


def scan_gcp(credentials: Dict[str, Any], services: List[str]) -> Dict[str, Any]:
    try:
        import json
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
    except Exception as exc:
        raise CloudScanError("GCP scanner requires google-auth and google-api-python-client. Rebuild the backend image with updated requirements.txt.") from exc

    service_account_json = credentials.get("service_account_json")
    project_id = credentials.get("project_id")
    if not service_account_json:
        raise CloudScanError("GCP service account JSON is required.")
    try:
        info = json.loads(service_account_json) if isinstance(service_account_json, str) else service_account_json
        project_id = project_id or info.get("project_id")
        creds = service_account.Credentials.from_service_account_info(
            info,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
    except Exception as exc:
        raise CloudScanError(f"Invalid GCP service account JSON: {exc}") from exc
    if not project_id:
        raise CloudScanError("GCP project_id is required or must exist in the service account JSON.")

    issues: List[Dict[str, str]] = []
    inventory: Dict[str, Any] = {"project_id": project_id, "firewall_rules": [], "buckets": []}

    if "compute" in services or "firewall" in services:
        try:
            compute = build("compute", "v1", credentials=creds, cache_discovery=False)
            result = compute.firewalls().list(project=project_id).execute()
            for rule in result.get("items", []):
                source_ranges = rule.get("sourceRanges", [])
                allowed = rule.get("allowed", [])
                inventory["firewall_rules"].append({"name": rule.get("name"), "network": rule.get("network"), "source_ranges": source_ranges, "allowed": allowed})
                if any(_is_public_cidr(cidr) for cidr in source_ranges):
                    ports = []
                    for allow in allowed:
                        proto = allow.get("IPProtocol")
                        for port in allow.get("ports", ["all"]):
                            ports.append(f"{proto}/{port}")
                    port_text = ", ".join(ports) or "all allowed traffic"
                    issues.append(_issue(
                        "Public GCP firewall rule",
                        _public_port_severity(port_text),
                        rule.get("name", "firewall-rule"),
                        f"Firewall rule allows {port_text} from the internet.",
                        "Restrict sourceRanges to trusted CIDRs or remove the rule if unused.",
                    ))
        except Exception as exc:
            issues.append(_issue("GCP Compute firewall scan failed", "medium", project_id, str(exc), "Grant compute.firewalls.list or review firewall rules manually."))

    if "storage" in services:
        try:
            storage = build("storage", "v1", credentials=creds, cache_discovery=False)
            buckets = storage.buckets().list(project=project_id).execute().get("items", [])
            for bucket in buckets:
                name = bucket.get("name")
                iam = storage.buckets().getIamPolicy(bucket=name).execute()
                bindings = iam.get("bindings", [])
                inventory["buckets"].append({"name": name, "bindings_count": len(bindings)})
                for binding in bindings:
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        issues.append(_issue("Public GCS bucket IAM binding", "critical", name, f"Bucket has public member in role {binding.get('role')}.", "Remove allUsers/allAuthenticatedUsers unless the bucket is intentionally public."))
        except Exception as exc:
            issues.append(_issue("GCP Storage scan failed", "medium", project_id, str(exc), "Grant storage.buckets.list and storage.buckets.getIamPolicy."))

    return _cloud_result("gcp", inventory, issues)


def scan_azure(credentials: Dict[str, Any], services: List[str]) -> Dict[str, Any]:
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import ResourceManagementClient
        from azure.mgmt.storage import StorageManagementClient
    except Exception as exc:
        raise CloudScanError("Azure scanner requires azure-identity and Azure management SDK packages. Rebuild the backend image with updated requirements.txt.") from exc

    tenant_id = credentials.get("tenant_id")
    client_id = credentials.get("client_id")
    client_secret = credentials.get("client_secret")
    subscription_id = credentials.get("subscription_id")
    if not all([tenant_id, client_id, client_secret, subscription_id]):
        raise CloudScanError("Azure tenant_id, client_id, client_secret, and subscription_id are required.")

    cred = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
    issues: List[Dict[str, str]] = []
    inventory: Dict[str, Any] = {"subscription_id": subscription_id, "resource_groups": [], "network_security_groups": [], "storage_accounts": []}

    try:
        rg_client = ResourceManagementClient(cred, subscription_id)
        groups = list(rg_client.resource_groups.list())
        inventory["resource_groups"] = [g.name for g in groups]
    except Exception as exc:
        raise CloudScanError(f"Azure credential validation failed or subscription cannot be read: {exc}") from exc

    if "network" in services or "nsg" in services:
        try:
            network_client = NetworkManagementClient(cred, subscription_id)
            for nsg in network_client.network_security_groups.list_all():
                nsg_summary = {"name": nsg.name, "location": nsg.location, "open_rules": []}
                rules = list(nsg.security_rules or []) + list(nsg.default_security_rules or [])
                for rule in rules:
                    direction = str(rule.direction or "").lower()
                    access = str(rule.access or "").lower()
                    sources = []
                    if rule.source_address_prefix:
                        sources.append(rule.source_address_prefix)
                    sources.extend(rule.source_address_prefixes or [])
                    is_public = any(src in ["*", "Internet", "0.0.0.0/0", "::/0"] for src in sources)
                    if direction == "inbound" and access == "allow" and is_public:
                        port = rule.destination_port_range or ",".join(rule.destination_port_ranges or ["*"])
                        nsg_summary["open_rules"].append({"rule": rule.name, "port": port, "sources": sources})
                        issues.append(_issue("Public Azure NSG inbound rule", _public_port_severity(str(port)), nsg.name, f"Rule {rule.name} allows inbound port {port} from {', '.join(sources)}.", "Restrict source address prefixes to trusted ranges or remove the rule."))
                inventory["network_security_groups"].append(nsg_summary)
        except Exception as exc:
            issues.append(_issue("Azure NSG scan failed", "medium", "network", str(exc), "Grant Network Reader permissions or review NSG rules manually."))

    if "storage" in services:
        try:
            storage_client = StorageManagementClient(cred, subscription_id)
            for account in storage_client.storage_accounts.list():
                summary = {"name": account.name, "location": account.location, "allow_blob_public_access": getattr(account, "allow_blob_public_access", None), "https_only": getattr(account, "enable_https_traffic_only", None)}
                inventory["storage_accounts"].append(summary)
                if summary["allow_blob_public_access"] is True:
                    issues.append(_issue("Azure storage allows blob public access", "high", account.name, "Storage account permits public blob access.", "Disable AllowBlobPublicAccess unless explicitly required."))
                if summary["https_only"] is False:
                    issues.append(_issue("Azure storage HTTPS-only disabled", "medium", account.name, "Storage account does not require HTTPS-only traffic.", "Enable secure transfer required/HTTPS-only traffic."))
        except Exception as exc:
            issues.append(_issue("Azure Storage scan failed", "medium", "storage", str(exc), "Grant Storage Account Reader permissions or review storage accounts manually."))

    return _cloud_result("azure", inventory, issues)


def _cloud_result(provider: str, inventory: Dict[str, Any], issues: List[Dict[str, str]]) -> Dict[str, Any]:
    critical = sum(1 for i in issues if i["severity"] == "critical")
    high = sum(1 for i in issues if i["severity"] == "high")
    medium = sum(1 for i in issues if i["severity"] == "medium")
    risk = "critical" if critical else "high" if high else "medium" if medium else "low"
    return {
        "enabled": True,
        "provider": provider,
        "risk_level": risk,
        "summary": {"issues": len(issues), "critical": critical, "high": high, "medium": medium, "low": sum(1 for i in issues if i["severity"] == "low")},
        "inventory": inventory,
        "issues": issues,
    }
