import json
import os
from typing import Any, Dict, List


def _issue(title: str, severity: str, resource: str, reason: str, command: str = "Review manually") -> Dict[str, str]:
    return {"title": title, "severity": severity, "resource": resource, "reason": reason, "suggested_command": command}

def rule_based_analysis(scan: Dict[str, Any]) -> Dict[str, Any]:
    issues: List[Dict[str, str]] = []
    for c in scan.get("containers", []):
        name = c.get("name") or c.get("id")
        if c.get("privileged"):
            issues.append(_issue("Privileged container", "critical", name, "Privileged containers can access host-level capabilities.", f"docker inspect {name}"))
        if c.get("status") == "exited":
            issues.append(_issue("Stopped container found", "medium", name, "Stopped containers may be old deployments or failed jobs consuming operational attention.", f"docker logs {name}"))
        if not c.get("restart_policy") and c.get("status") == "running":
            issues.append(_issue("No restart policy", "medium", name, "A production container without restart policy may not recover after daemon or host restart.", f"docker update --restart unless-stopped {name}"))
        if c.get("readonly_rootfs") is False:
            issues.append(_issue("Writable root filesystem", "low", name, "Writable root filesystem increases blast radius if the app is compromised.", f"docker inspect {name}"))
        ports = c.get("ports") or {}
        if any(bindings for bindings in ports.values() if bindings):
            issues.append(_issue("Host port exposed", "medium", name, "Container publishes one or more ports on the EC2 host. Confirm security group and app need.", f"docker port {name}"))
        stats = c.get("stats") or {}
        mem = stats.get("memory") or {}
        if mem.get("percent", 0) > 85:
            issues.append(_issue("High memory usage", "high", name, f"Memory usage is around {mem.get('percent')}% of the container limit.", f"docker stats --no-stream {name}"))
        if stats.get("cpu_percent", 0) > 80:
            issues.append(_issue("High CPU usage", "high", name, f"CPU usage is around {stats.get('cpu_percent')}%.", f"docker stats --no-stream {name}"))
        env_keys = [k.upper() for k in c.get("env_keys", [])]
        risky = [k for k in env_keys if any(token in k for token in ["SECRET", "PASSWORD", "TOKEN", "KEY"])]
        if risky:
            issues.append(_issue("Potential secret environment variables", "high", name, f"Sensitive-looking environment keys detected: {', '.join(risky[:6])}.", f"docker inspect {name}"))
    for image in scan.get("images", []):
        if image.get("dangling"):
            issues.append(_issue("Dangling image", "low", image.get("short_id", "image"), "Dangling images may waste disk space.", "docker image prune"))
        elif not image.get("in_use"):
            issues.append(_issue("Unused image", "low", ', '.join(image.get("tags") or [image.get("short_id", "image")]), "Image is not attached to a running or stopped container in this scan.", "docker image ls"))
    for net in scan.get("networks", []):
        if net.get("containers_count") == 0 and net.get("name") not in ["bridge", "host", "none"]:
            issues.append(_issue("Unused custom network", "low", net.get("name"), "Custom network has no attached containers.", f"docker network inspect {net.get('name')}"))


    cloud = scan.get("cloud") or {}
    if cloud.get("enabled"):
        for cloud_issue in cloud.get("issues", []):
            issues.append(_issue(
                f"Cloud: {cloud_issue.get('title', 'Cloud finding')}",
                cloud_issue.get("severity", "medium"),
                cloud_issue.get("resource", cloud.get("provider", "cloud")),
                cloud_issue.get("reason", "Cloud security finding detected."),
                cloud_issue.get("remediation", "Review in the cloud console."),
            ))

    trivy = scan.get("trivy") or {}
    if trivy.get("enabled") and not trivy.get("available", True):
        issues.append(_issue("Trivy not installed", "medium", "security scanner", trivy.get("message", "Trivy CLI is unavailable."), "trivy --version"))
    elif trivy.get("available"):
        sev_counts = {str(k).upper(): int(v) for k, v in (trivy.get("summary", {}).get("severity_counts", {}) or {}).items()}
        if sev_counts.get("CRITICAL", 0):
            issues.append(_issue("Critical image vulnerabilities", "critical", "container images", f"Trivy detected {sev_counts.get('CRITICAL')} critical finding(s) across scanned images.", "trivy image --severity CRITICAL <image>"))
        if sev_counts.get("HIGH", 0):
            issues.append(_issue("High image vulnerabilities", "high", "container images", f"Trivy detected {sev_counts.get('HIGH')} high severity finding(s) across scanned images.", "trivy image --severity HIGH <image>"))
        if (trivy.get("summary", {}) or {}).get("secrets", 0):
            issues.append(_issue("Secrets detected in images", "critical", "container images", f"Trivy detected {(trivy.get('summary', {}) or {}).get('secrets')} secret finding(s). Rotate exposed credentials if confirmed.", "trivy image --scanners secret <image>"))
        if (trivy.get("summary", {}) or {}).get("misconfigurations", 0):
            issues.append(_issue("Image misconfiguration findings", "medium", "container images", f"Trivy detected {(trivy.get('summary', {}) or {}).get('misconfigurations')} misconfiguration finding(s).", "trivy image --scanners misconfig <image>"))

    critical = sum(1 for i in issues if i["severity"] == "critical")
    high = sum(1 for i in issues if i["severity"] == "high")
    risk = "critical" if critical else "high" if high else "medium" if len(issues) > 3 else "low"
    return {
        "executive_summary": f"Scanned {scan.get('summary', {}).get('containers_scanned', 0)} containers and found {len(issues)} inspection findings. Review security, reliability, and cleanup recommendations before taking action.",
        "risk_level": risk,
        "issues": issues,
        "safe_cleanup_notes": [
            "Do not remove containers, images, volumes, or networks without confirming ownership and backup needs.",
            "Suggested Docker commands are review commands by default; destructive cleanup should require human approval.",
            "For AWS, GCP, or Azure findings, confirm ownership and production impact before changing IAM, firewall, storage, or network settings."
        ]
    }

async def analyze_scan(scan: Dict[str, Any], ai_config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    ai_config = ai_config or {}
    frontend_ai_enabled = bool(ai_config.get("enabled") and ai_config.get("api_key"))
    api_key = ai_config.get("api_key") if frontend_ai_enabled else os.getenv("OPENAI_API_KEY")
    model = (ai_config.get("model") if frontend_ai_enabled else os.getenv("OPENAI_MODEL")) or "gpt-4o-mini"
    base_url = (ai_config.get("base_url") if frontend_ai_enabled else os.getenv("OPENAI_BASE_URL")) or None
    if not api_key:
        return rule_based_analysis(scan)
    try:
        from openai import AsyncOpenAI
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        client = AsyncOpenAI(**client_kwargs)
        compact = {"host": scan.get("host"), "summary": scan.get("summary"), "containers": scan.get("containers", [])[:50], "images": scan.get("images", [])[:80], "networks": scan.get("networks", [])[:50], "trivy": scan.get("trivy", {}), "cloud": scan.get("cloud", {})}
        prompt = """You are a senior DevOps/SRE. Analyze this DevSecOps inventory from a Docker host. If Trivy results are present, include CVEs, image secrets, and misconfigurations. If AWS, GCP, or Azure cloud scan results are present, include IAM, network/firewall, storage, and public exposure risks. Return strict JSON with executive_summary, risk_level, issues array, and safe_cleanup_notes. Each issue needs title, severity, resource, reason, suggested_command. Do not suggest destructive commands unless clearly marked as requiring human approval."""
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": prompt}, {"role": "user", "content": json.dumps(compact)}],
            response_format={"type": "json_object"},
        )
        return json.loads(resp.choices[0].message.content)
    except Exception as exc:
        fallback = rule_based_analysis(scan)
        fallback["ai_error"] = str(exc)
        fallback["ai_provider_note"] = "AI call failed. The app fell back to the local rule-based analyzer. For non-OpenAI providers, use an OpenAI-compatible base URL."
        return fallback
