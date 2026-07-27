import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import docker
import psutil
from docker.errors import DockerException, NotFound

class DockerScanError(Exception):
    pass

def _client():
    try:
        return docker.from_env()
    except DockerException as exc:
        raise DockerScanError(f"Cannot connect to Docker daemon. Check /var/run/docker.sock permission. Details: {exc}") from exc

def _safe_attrs(obj) -> Dict[str, Any]:
    return obj.attrs if hasattr(obj, "attrs") and isinstance(obj.attrs, dict) else {}

def _calc_cpu_percent(stats: Dict[str, Any]) -> float:
    try:
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
        online_cpus = stats["cpu_stats"].get("online_cpus") or len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [])) or 1
        if system_delta > 0 and cpu_delta > 0:
            return round((cpu_delta / system_delta) * online_cpus * 100, 2)
    except Exception:
        return 0.0
    return 0.0

def _calc_mem(stats: Dict[str, Any]) -> Dict[str, Any]:
    try:
        usage = stats["memory_stats"].get("usage", 0)
        limit = stats["memory_stats"].get("limit", 0)
        pct = round((usage / limit) * 100, 2) if limit else 0
        return {"usage_bytes": usage, "limit_bytes": limit, "percent": pct}
    except Exception:
        return {"usage_bytes": 0, "limit_bytes": 0, "percent": 0}

def get_host_info() -> Dict[str, Any]:
    c = _client()
    try:
        version = c.version()
        info = c.info()
    except DockerException as exc:
        raise DockerScanError(str(exc)) from exc
    return {
        "host_name": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "memory_total_bytes": psutil.virtual_memory().total,
        "disk_percent": psutil.disk_usage('/').percent,
        "docker_version": version.get("Version"),
        "docker_api_version": version.get("ApiVersion"),
        "containers": info.get("Containers"),
        "containers_running": info.get("ContainersRunning"),
        "containers_stopped": info.get("ContainersStopped"),
        "images": info.get("Images"),
        "server_time": datetime.now(timezone.utc).isoformat(),
    }

def _container_item(container, include_stats: bool, include_logs: bool, log_tail: int) -> Dict[str, Any]:
    attrs = _safe_attrs(container)
    config = attrs.get("Config", {})
    labels = config.get("Labels") or {}
    host_config = attrs.get("HostConfig", {})
    state = attrs.get("State", {})
    network_settings = attrs.get("NetworkSettings", {})
    mounts = attrs.get("Mounts", [])
    ports = network_settings.get("Ports") or {}
    stats_payload = None
    logs_payload = None

    if include_stats and state.get("Running"):
        try:
            raw_stats = container.stats(stream=False)
            stats_payload = {"cpu_percent": _calc_cpu_percent(raw_stats), "memory": _calc_mem(raw_stats)}
        except Exception as exc:
            stats_payload = {"error": str(exc)}

    if include_logs:
        try:
            logs_payload = container.logs(tail=log_tail).decode("utf-8", errors="replace")[-12000:]
        except Exception as exc:
            logs_payload = f"Could not read logs: {exc}"

    health = state.get("Health") or {}
    return {
        "id": container.short_id,
        "full_id": container.id,
        "name": container.name,
        "image": config.get("Image"),
        "image_id": attrs.get("Image"),
        "status": container.status,
        "created": attrs.get("Created"),
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "restart_count": attrs.get("RestartCount", 0),
        "health": health.get("Status"),
        "exit_code": state.get("ExitCode"),
        "state_error": state.get("Error"),
        "oom_killed": state.get("OOMKilled"),
        "dead": state.get("Dead"),
        "privileged": host_config.get("Privileged"),
        "restart_policy": (host_config.get("RestartPolicy") or {}).get("Name"),
        "readonly_rootfs": host_config.get("ReadonlyRootfs"),
        "network_mode": host_config.get("NetworkMode"),
        "pid_mode": host_config.get("PidMode"),
        "cap_add": host_config.get("CapAdd"),
        "binds": host_config.get("Binds"),
        "mounts": mounts,
        "ports": ports,
        "env_keys": [e.split("=", 1)[0] for e in config.get("Env") or []],
        "labels": labels,
        "stats": stats_payload,
        "logs_tail": logs_payload,
    }

def inspect_docker(include_stats=True, include_logs=False, log_tail=80, only_running=False, label_filters: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    c = _client()
    try:
        host = get_host_info()
        containers = c.containers.list(all=not only_running)
        images = c.images.list()
        volumes = c.volumes.list()
        networks = c.networks.list()
    except DockerException as exc:
        raise DockerScanError(str(exc)) from exc

    label_filters = label_filters or {}
    container_items: List[Dict[str, Any]] = []
    used_image_ids = set()

    for container in containers:
        attrs = _safe_attrs(container)
        labels = (attrs.get("Config", {}) or {}).get("Labels") or {}
        if any(labels.get(k) != v for k, v in label_filters.items()):
            continue
        item = _container_item(container, include_stats, include_logs, log_tail)
        if item.get("image_id"):
            used_image_ids.add(item["image_id"])
        container_items.append(item)

    image_items = []
    dangling_images = 0
    for image in images:
        attrs = _safe_attrs(image)
        tags = image.tags or []
        dangling = not tags
        dangling_images += 1 if dangling else 0
        image_items.append({
            "short_id": image.short_id,
            "id": attrs.get("Id"),
            "tags": tags,
            "created": attrs.get("Created"),
            "size_bytes": attrs.get("Size"),
            "dangling": dangling,
            "in_use": attrs.get("Id") in used_image_ids,
        })

    volume_items = []
    for volume in volumes:
        attrs = _safe_attrs(volume)
        volume_items.append({"name": volume.name, "driver": attrs.get("Driver"), "mountpoint": attrs.get("Mountpoint"), "labels": attrs.get("Labels"), "created_at": attrs.get("CreatedAt")})

    network_items = []
    for network in networks:
        attrs = _safe_attrs(network)
        network_items.append({"name": network.name, "id": network.short_id, "driver": attrs.get("Driver"), "scope": attrs.get("Scope"), "containers_count": len((attrs.get("Containers") or {}).keys())})

    running_count = sum(1 for x in container_items if x["status"] == "running")
    stopped_count = sum(1 for x in container_items if x["status"] != "running")
    exited_count = sum(1 for x in container_items if x["status"] == "exited")

    return {
        "host": host,
        "summary": {
            "containers_scanned": len(container_items),
            "running": running_count,
            "stopped": stopped_count,
            "exited": exited_count,
            "images": len(image_items),
            "dangling_images": dangling_images,
            "volumes": len(volume_items),
            "networks": len(network_items),
        },
        "containers": container_items,
        "images": image_items,
        "volumes": volume_items,
        "networks": network_items,
    }

def get_container_diagnostics(container_id: str, tail: int = 200) -> Dict[str, Any]:
    c = _client()
    try:
        container = c.containers.get(container_id)
        container.reload()
        attrs = _safe_attrs(container)
        config = attrs.get("Config", {}) or {}
        state = attrs.get("State", {}) or {}
        health = state.get("Health") or {}
        host_config = attrs.get("HostConfig", {}) or {}
        network_settings = attrs.get("NetworkSettings", {}) or {}
        try:
            logs = container.logs(tail=tail, stdout=True, stderr=True, timestamps=True).decode("utf-8", errors="replace")[-30000:]
        except Exception as exc:
            logs = f"Could not read container logs: {exc}"
        health_log = []
        for entry in health.get("Log") or []:
            health_log.append({
                "start": entry.get("Start"),
                "end": entry.get("End"),
                "exit_code": entry.get("ExitCode"),
                "output": (entry.get("Output") or "")[-4000:],
            })
        return {
            "id": container.short_id,
            "full_id": container.id,
            "name": container.name,
            "image": config.get("Image"),
            "status": container.status,
            "state": {
                "status": state.get("Status"),
                "running": state.get("Running"),
                "paused": state.get("Paused"),
                "restarting": state.get("Restarting"),
                "oom_killed": state.get("OOMKilled"),
                "dead": state.get("Dead"),
                "pid": state.get("Pid"),
                "exit_code": state.get("ExitCode"),
                "error": state.get("Error"),
                "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
            },
            "health": {
                "status": health.get("Status") or "not configured",
                "failing_streak": health.get("FailingStreak"),
                "log": health_log,
            },
            "restart_count": attrs.get("RestartCount", 0),
            "restart_policy": (host_config.get("RestartPolicy") or {}).get("Name"),
            "ports": network_settings.get("Ports") or {},
            "mounts": attrs.get("Mounts", []),
            "inspect": {
                "Id": container.id,
                "Name": container.name,
                "Config": {"Image": config.get("Image")},
                "State": state,
                "RestartCount": attrs.get("RestartCount", 0),
                "NetworkSettings": {"Ports": network_settings.get("Ports") or {}},
                "Mounts": attrs.get("Mounts", []),
            },
            "logs_tail": logs,
            "detected_error": state.get("Error") or ("Container exited with non-zero status" if state.get("ExitCode") not in (0, None) else ""),
        }
    except NotFound as exc:
        raise DockerScanError(f"Container not found: {container_id}") from exc
    except DockerException as exc:
        raise DockerScanError(str(exc)) from exc
