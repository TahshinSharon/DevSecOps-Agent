import asyncio
import os
from typing import Dict
from dotenv import load_dotenv
load_dotenv()

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import db
from ai_analyzer import analyze_scan
from auth import create_token, get_current_user, hash_password, verify_password
from docker_scanner import DockerScanError, get_container_diagnostics, get_host_info, inspect_docker
from trivy_scanner import scan_images_with_trivy
from cloud_scanner import CloudScanError, get_aws_ec2_docker_diagnostics, load_aws_regions, load_aws_ec2_instances, scan_cloud
from progress import progress_manager
from schemas import AuthRequest, AwsEc2DockerDiagnosticsRequest, AwsInstancesRequest, AwsRegionsRequest, InspectRequest, InspectStartResponse

app = FastAPI(title="DevSecOps Agent - AWS Docker Inspector", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"), "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await db.init_db()

@app.on_event("shutdown")
async def shutdown():
    await db.close_db()

@app.get("/api/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "devsecops-agent"}

@app.post("/api/auth/signup")
async def signup(payload: AuthRequest):
    try:
        user = await db.create_user(payload.email, hash_password(payload.password))
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="Email already exists") from exc
        raise
    return {"token": create_token(user["id"], user["email"]), "user": user}

@app.post("/api/auth/login")
async def login(payload: AuthRequest):
    user = await db.get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"token": create_token(user["id"], user["email"]), "user": {"id": user["id"], "email": user["email"]}}

@app.post("/api/cloud/aws/regions")
async def aws_regions(payload: AwsRegionsRequest, user=Depends(get_current_user)):
    try:
        regions = load_aws_regions(payload.model_dump())
        return {"regions": regions}
    except CloudScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/cloud/aws/instances")
async def aws_instances(payload: AwsInstancesRequest, user=Depends(get_current_user)):
    try:
        payload_dict = payload.model_dump()
        instances = load_aws_ec2_instances(payload_dict)
        searched_regions = payload_dict.get("regions") or [payload_dict.get("region") or "us-east-1"]
        return {"instances": instances, "searched_regions": searched_regions}
    except CloudScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.get("/api/host")
async def host(user=Depends(get_current_user)):
    try:
        return get_host_info()
    except DockerScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

async def run_inspection_job(inspection_id: int, payload: InspectRequest):
    try:
        await asyncio.sleep(0.1)
        if payload.enable_docker:
            await progress_manager.send(inspection_id, "Connecting to the Docker daemon on the machine where this app is running...")
            host = get_host_info()
            await progress_manager.send(inspection_id, f"Detected local Docker host {host.get('host_name')}...")
            await progress_manager.send(inspection_id, "Scanning local containers, images, volumes, networks, ports, mounts, restart policies, and runtime stats...")
            scan = inspect_docker(payload.include_stats, payload.include_logs, payload.log_tail, payload.only_running, payload.label_filters)
            scan["docker_enabled"] = True
        else:
            await progress_manager.send(inspection_id, "Local Docker runtime scan skipped. Cloud container scan will use cloud APIs instead of this PC's Docker socket...")
            host = {"host_name": "local-docker-scan-skipped", "docker_version": None, "disk_percent": 0}
            scan = {
                "docker_enabled": False,
                "host": host,
                "summary": {"containers_scanned": 0, "running": 0, "stopped": 0, "exited": 0, "images": 0, "dangling_images": 0, "volumes": 0, "networks": 0},
                "containers": [],
                "images": [],
                "volumes": [],
                "networks": [],
            }
        if payload.enable_trivy:
            if not payload.enable_docker:
                await progress_manager.send(inspection_id, "Trivy local image scan skipped because local Docker scan is disabled. Use AWS ECR scanning for AWS image findings.")
                scan["trivy"] = {"enabled": True, "available": False, "message": "Local Trivy image scan requires local Docker image inventory. Enable local Docker scan, or scan AWS ECR via Cloud Security Scan.", "images_scanned": 0, "summary": {}}
            else:
                await progress_manager.send(inspection_id, "Running Trivy image security scan for local Docker images...")
                trivy = scan_images_with_trivy(
                    scan,
                    scanners=payload.trivy_scanners,
                    severity=payload.trivy_severity,
                    max_images=payload.trivy_max_images,
                    timeout_seconds=payload.trivy_timeout_seconds,
                )
                scan["trivy"] = trivy
                if trivy.get("available") is False:
                    await progress_manager.send(inspection_id, "Trivy was requested but is not installed on this machine. Continuing with other analysis...")
                else:
                    await progress_manager.send(inspection_id, f"Trivy scan complete for {trivy.get('images_scanned', 0)} image(s).")
        if payload.cloud.enabled:
            provider = (payload.cloud.provider or "").lower()
            await progress_manager.send(inspection_id, f"Running {provider.upper()} cloud security scan using the provided temporary credentials. For AWS, this includes ECS/ECR container inventory when selected...")
            credential_map = {
                "aws": payload.cloud.aws.model_dump() if payload.cloud.aws else {},
                "gcp": payload.cloud.gcp.model_dump() if payload.cloud.gcp else {},
                "azure": payload.cloud.azure.model_dump() if payload.cloud.azure else {},
            }
            services = list(payload.cloud.services or [])
            if provider == "aws":
                selected_ec2_targets = credential_map["aws"].get("ec2_instance_ids") or []
                if selected_ec2_targets and "ec2_docker" not in services:
                    services.append("ec2_docker")
                    await progress_manager.send(inspection_id, "AWS EC2 Docker targets were selected, so EC2 Docker via SSM was enabled automatically...")
                if "ec2_docker" in services:
                    await progress_manager.send(inspection_id, f"Running AWS EC2 Docker scan via SSM for {len(selected_ec2_targets)} selected target(s): {', '.join(selected_ec2_targets[:5])}...")
                credential_map["aws"]["_remote_trivy_enabled"] = bool(payload.enable_trivy and "ec2_docker" in services)
                credential_map["aws"]["_trivy_scanners"] = payload.trivy_scanners
                credential_map["aws"]["_trivy_severity"] = payload.trivy_severity
                credential_map["aws"]["_trivy_max_images"] = payload.trivy_max_images
                credential_map["aws"]["_include_stats"] = payload.include_stats
                credential_map["aws"]["_include_logs"] = payload.include_logs
                credential_map["aws"]["_only_running"] = payload.only_running
                credential_map["aws"]["_log_tail"] = payload.log_tail
            cloud_scan = scan_cloud(
                provider=provider,
                credentials=credential_map.get(provider, {}),
                services=services,
                regions=payload.cloud.regions,
            )
            scan["cloud"] = cloud_scan
            if provider == "aws" and "ec2_docker" in services:
                ec2d = cloud_scan.get("inventory", {}).get("ec2_docker_summary", {})
                await progress_manager.send(inspection_id, f"AWS EC2 Docker via SSM complete: {ec2d.get('containers', 0)} container(s), {ec2d.get('running', 0)} running, {ec2d.get('stopped', 0)} stopped.")
            await progress_manager.send(inspection_id, f"{provider.upper()} cloud scan complete with {cloud_scan.get('summary', {}).get('issues', 0)} finding(s).")
        ai_mode = "frontend-provided AI settings" if payload.ai.enabled and payload.ai.api_key else "backend AI settings or local rules"
        await progress_manager.send(inspection_id, f"Analyzing container, image, and cloud security signals using {ai_mode}...")
        analysis = await analyze_scan(scan, payload.ai.model_dump() if payload.ai else None)
        result = {"scan": scan, "analysis": analysis}
        await db.update_inspection(
            inspection_id,
            host_name=host.get("host_name"),
            docker_version=host.get("docker_version"),
            containers_scanned=scan.get("summary", {}).get("containers_scanned", 0),
            issues_found=len(analysis.get("issues", [])),
            risk_level=analysis.get("risk_level", "unknown"),
            status="complete",
            result_json=result,
        )
        await progress_manager.send(inspection_id, "Inspection complete")
    except Exception as exc:
        await db.update_inspection(inspection_id, status="failed", result_json={"error": str(exc)})
        await progress_manager.send(inspection_id, f"Inspection failed: {exc}")

@app.post("/api/inspect", response_model=InspectStartResponse)
async def start_inspection(payload: InspectRequest, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    inspection_id = await db.create_inspection(user["id"], payload.sanitized_dict())
    background_tasks.add_task(run_inspection_job, inspection_id, payload)
    return {"inspection_id": inspection_id, "status": "running"}


@app.post("/api/cloud/aws/ec2/docker/diagnostics")
async def aws_ec2_docker_diagnostics(payload: AwsEc2DockerDiagnosticsRequest, user=Depends(get_current_user)):
    try:
        return get_aws_ec2_docker_diagnostics(payload.model_dump(), payload.region, payload.instance_id, payload.container_id, tail=payload.tail)
    except CloudScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.get("/api/containers/{container_id}/diagnostics")
async def container_diagnostics(container_id: str, tail: int = Query(default=200, ge=10, le=1000), user=Depends(get_current_user)):
    try:
        return get_container_diagnostics(container_id, tail=tail)
    except DockerScanError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

@app.get("/api/history")
async def history(user=Depends(get_current_user)):
    return {"items": await db.list_inspections(user["id"])}

@app.get("/api/inspections/{inspection_id}")
async def get_inspection(inspection_id: int, user=Depends(get_current_user)):
    item = await db.get_inspection(user["id"], inspection_id)
    if not item:
        raise HTTPException(status_code=404, detail="Inspection not found")
    return item

@app.websocket("/ws/progress/{inspection_id}")
async def ws_progress(websocket: WebSocket, inspection_id: int):
    await progress_manager.connect(inspection_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        progress_manager.disconnect(inspection_id, websocket)
