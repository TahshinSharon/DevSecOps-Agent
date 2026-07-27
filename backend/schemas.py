from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field, model_validator

class AuthRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)

class AwsCredentials(BaseModel):
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: Optional[str] = ""
    region: str = "us-east-1"
    ec2_instance_ids: List[str] = Field(default_factory=list)
    install_trivy_on_ec2: bool = False

class AwsRegionsRequest(BaseModel):
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = ""
    region: str = "us-east-1"

class AwsInstancesRequest(BaseModel):
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = ""
    region: str = "us-east-1"
    regions: List[str] = Field(default_factory=list)


class AwsEc2DockerDiagnosticsRequest(BaseModel):
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = ""
    region: str
    instance_id: str
    container_id: str
    tail: int = Field(default=250, ge=10, le=1000)

class GcpCredentials(BaseModel):
    project_id: str = ""
    service_account_json: str = ""

class AzureCredentials(BaseModel):
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    subscription_id: str = ""


class AiConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""
    model: str = "gpt-4o-mini"
    base_url: Optional[str] = ""

class CloudScanConfig(BaseModel):
    enabled: bool = False
    provider: Optional[str] = None
    services: List[str] = Field(default_factory=list)
    regions: List[str] = Field(default_factory=list)
    aws: Optional[AwsCredentials] = None
    gcp: Optional[GcpCredentials] = None
    azure: Optional[AzureCredentials] = None

    @model_validator(mode="after")
    def validate_provider(self):
        if not self.enabled:
            return self
        provider = (self.provider or "").lower().strip()
        if provider not in {"aws", "gcp", "azure"}:
            raise ValueError("Choose exactly one cloud provider: aws, gcp, or azure.")
        return self

class InspectRequest(BaseModel):
    enable_docker: bool = True
    include_stats: bool = True
    include_logs: bool = False
    log_tail: int = Field(default=80, ge=1, le=500)
    only_running: bool = False
    label_filters: Optional[Dict[str, str]] = None
    enable_trivy: bool = False
    trivy_scanners: str = "vuln,secret"
    trivy_severity: str = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
    trivy_max_images: int = Field(default=20, ge=1, le=100)
    trivy_timeout_seconds: int = Field(default=180, ge=30, le=900)
    cloud: CloudScanConfig = Field(default_factory=CloudScanConfig)
    ai: AiConfig = Field(default_factory=AiConfig)

    def sanitized_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        ai = data.get("ai") or {}
        if ai.get("api_key"):
            ai["api_key"] = "***provided***"
        data["ai"] = ai
        cloud = data.get("cloud") or {}
        if cloud.get("enabled"):
            provider = cloud.get("provider")
            for key in ["aws", "gcp", "azure"]:
                creds = cloud.get(key)
                if not creds:
                    continue
                safe = {}
                for cred_key, value in creds.items():
                    if value in (None, ""):
                        safe[cred_key] = value
                    elif cred_key in {"region", "project_id", "tenant_id", "client_id", "subscription_id"}:
                        safe[cred_key] = value
                    else:
                        safe[cred_key] = "***provided***"
                cloud[key] = safe
            cloud["selected_credentials"] = provider
        data["cloud"] = cloud
        return data

class InspectStartResponse(BaseModel):
    inspection_id: int
    status: str
