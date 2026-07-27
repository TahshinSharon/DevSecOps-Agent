import json
import os
import shutil
import subprocess
from collections import Counter
from typing import Any, Dict, List, Optional


class TrivyUnavailable(Exception):
    pass


def is_trivy_available() -> bool:
    return shutil.which(os.getenv("TRIVY_BIN", "trivy")) is not None


def get_trivy_version() -> Optional[str]:
    if not is_trivy_available():
        return None
    try:
        proc = subprocess.run(
            [os.getenv("TRIVY_BIN", "trivy"), "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        return (proc.stdout or proc.stderr).strip().splitlines()[0]
    except Exception:
        return None


def _image_ref(image: Dict[str, Any]) -> Optional[str]:
    tags = image.get("tags") or []
    if tags:
        return tags[0]
    image_id = image.get("id") or image.get("short_id")
    if not image_id:
        return None
    # Trivy can scan local images by ID. Keep the sha256 value when available.
    return image_id


def _count_results(payload: Dict[str, Any]) -> Dict[str, Any]:
    severities = Counter()
    vuln_count = 0
    secret_count = 0
    misconfig_count = 0
    license_count = 0
    top_findings: List[Dict[str, Any]] = []

    for result in payload.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "UNKNOWN").upper()
            severities[sev] += 1
            vuln_count += 1
            if len(top_findings) < 12 and sev in {"CRITICAL", "HIGH"}:
                top_findings.append({
                    "type": "vulnerability",
                    "severity": sev.lower(),
                    "target": target,
                    "id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "title": vuln.get("Title") or vuln.get("VulnerabilityID"),
                })
        for secret in result.get("Secrets", []) or []:
            sev = (secret.get("Severity") or "UNKNOWN").upper()
            severities[sev] += 1
            secret_count += 1
            if len(top_findings) < 12:
                top_findings.append({
                    "type": "secret",
                    "severity": sev.lower(),
                    "target": target,
                    "id": secret.get("RuleID"),
                    "title": secret.get("Title") or "Secret detected",
                })
        for misconf in result.get("Misconfigurations", []) or []:
            sev = (misconf.get("Severity") or "UNKNOWN").upper()
            severities[sev] += 1
            misconfig_count += 1
            if len(top_findings) < 12 and sev in {"CRITICAL", "HIGH"}:
                top_findings.append({
                    "type": "misconfiguration",
                    "severity": sev.lower(),
                    "target": target,
                    "id": misconf.get("ID"),
                    "title": misconf.get("Title") or misconf.get("Message"),
                })
        for lic in result.get("Licenses", []) or []:
            license_count += 1

    return {
        "vulnerabilities": vuln_count,
        "secrets": secret_count,
        "misconfigurations": misconfig_count,
        "licenses": license_count,
        "severity_counts": dict(severities),
        "top_findings": top_findings,
    }


def scan_image_with_trivy(image_ref: str, scanners: str, severity: str, timeout_seconds: int) -> Dict[str, Any]:
    if not is_trivy_available():
        raise TrivyUnavailable("Trivy CLI is not installed or not available in PATH")

    cmd = [
        os.getenv("TRIVY_BIN", "trivy"),
        "image",
        "--format", "json",
        "--quiet",
        "--scanners", scanners,
        "--severity", severity,
        image_ref,
    ]

    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )

    # Trivy may return non-zero when vulnerabilities are found if exit-code is configured externally.
    if not proc.stdout.strip():
        return {
            "image": image_ref,
            "status": "failed",
            "error": proc.stderr.strip() or f"Trivy exited with code {proc.returncode}",
            "summary": {},
        }

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"image": image_ref, "status": "failed", "error": f"Invalid Trivy JSON: {exc}", "summary": {}}

    return {
        "image": image_ref,
        "status": "complete" if proc.returncode in (0, 1) else "warning",
        "return_code": proc.returncode,
        "summary": _count_results(payload),
        # Store compact raw metadata only, not the full giant report, to keep SQLite responsive.
        "artifact_name": payload.get("ArtifactName"),
        "artifact_type": payload.get("ArtifactType"),
        "metadata": payload.get("Metadata", {}),
        "stderr": proc.stderr.strip()[-2000:] if proc.stderr else "",
    }


def scan_images_with_trivy(scan: Dict[str, Any], scanners: str = "vuln,secret", severity: str = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", max_images: int = 20, timeout_seconds: int = 180) -> Dict[str, Any]:
    if not is_trivy_available():
        return {
            "enabled": True,
            "available": False,
            "status": "skipped",
            "message": "Trivy CLI is not installed. Install Trivy on the EC2 host to enable image CVE/secret/misconfiguration scanning.",
            "version": None,
            "images": [],
            "summary": {},
        }

    image_refs: List[str] = []
    seen = set()
    for image in scan.get("images", []) or []:
        ref = _image_ref(image)
        if ref and ref not in seen:
            image_refs.append(ref)
            seen.add(ref)
        if len(image_refs) >= max_images:
            break

    results = []
    totals = Counter()
    severity_totals = Counter()
    for ref in image_refs:
        item = scan_image_with_trivy(ref, scanners, severity, timeout_seconds)
        results.append(item)
        summary = item.get("summary") or {}
        totals["vulnerabilities"] += summary.get("vulnerabilities", 0)
        totals["secrets"] += summary.get("secrets", 0)
        totals["misconfigurations"] += summary.get("misconfigurations", 0)
        totals["licenses"] += summary.get("licenses", 0)
        severity_totals.update(summary.get("severity_counts", {}))

    return {
        "enabled": True,
        "available": True,
        "status": "complete",
        "version": get_trivy_version(),
        "scanners": scanners,
        "severity": severity,
        "images_scanned": len(results),
        "images_total_available": len(scan.get("images", []) or []),
        "summary": {**dict(totals), "severity_counts": dict(severity_totals)},
        "images": results,
    }
