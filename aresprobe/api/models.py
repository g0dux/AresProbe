"""
AresProbe API Models
Pydantic models for API requests and responses
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum

class ScanType(str, Enum):
    """Scan types"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    COMPREHENSIVE = "comprehensive"

class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Status(str, Enum):
    """General status"""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

# Base Models
class BaseResponse(BaseModel):
    """Base API response"""
    status: Status
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseResponse):
    """Error response"""
    status: Status = Status.ERROR
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# Authentication Models
class LoginRequest(BaseModel):
    """Login request"""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")

class LoginResponse(BaseResponse):
    """Login response"""
    status: Status = Status.SUCCESS
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]

class RefreshTokenRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str

class CreateAPIKeyRequest(BaseModel):
    """Create API key request"""
    name: str = Field(..., description="API key name")
    permissions: List[str] = Field(..., description="List of permissions")
    expires_days: Optional[int] = Field(None, description="Expiration in days")

class APIKeyResponse(BaseModel):
    """API key response"""
    key: str
    name: str
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

# Scan Models
class ScanRequest(BaseModel):
    """Scan request"""
    target: HttpUrl = Field(..., description="Target URL")
    scan_types: List[ScanType] = Field(default=[ScanType.COMPREHENSIVE], description="Types of scans to perform")
    options: Optional[Dict[str, Any]] = Field(default={}, description="Scan options")
    callback_url: Optional[HttpUrl] = Field(None, description="Webhook callback URL")

class ScanResponse(BaseResponse):
    """Scan response"""
    status: Status = Status.SUCCESS
    scan_id: str
    target: str
    scan_types: List[ScanType]
    status_message: str = "Scan initiated"

class ScanStatus(BaseModel):
    """Scan status"""
    scan_id: str
    target: str
    status: str  # running, completed, failed, paused
    progress: float = Field(ge=0, le=100)
    started_at: datetime
    completed_at: Optional[datetime]
    vulnerabilities_found: int = 0
    scan_types: List[ScanType]

# Vulnerability Models
class Vulnerability(BaseModel):
    """Vulnerability model"""
    id: str
    type: str
    severity: Severity
    title: str
    description: str
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: Optional[str]
    references: List[str] = []
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    remediation: Optional[str]
    discovered_at: datetime

class VulnerabilityResponse(BaseResponse):
    """Vulnerability response"""
    status: Status = Status.SUCCESS
    vulnerabilities: List[Vulnerability]
    total_count: int
    severity_counts: Dict[Severity, int]

# Report Models
class ReportRequest(BaseModel):
    """Report request"""
    scan_id: Optional[str] = None
    format: str = Field(default="json", description="Report format (json, html, pdf)")
    include_details: bool = Field(default=True, description="Include detailed information")
    severity_filter: Optional[List[Severity]] = Field(None, description="Filter by severity")

class ReportResponse(BaseResponse):
    """Report response"""
    status: Status = Status.SUCCESS
    report_id: str
    format: str
    download_url: Optional[str]
    content: Optional[str]  # For JSON format

# Performance Models
class PerformanceMetrics(BaseModel):
    """Performance metrics"""
    cpu_usage: float = Field(ge=0, le=100)
    memory_usage: float = Field(ge=0, le=100)
    network_throughput: float
    response_time: float
    concurrent_connections: int
    cache_hit_ratio: float
    error_rate: float
    timestamp: datetime

class PerformanceResponse(BaseResponse):
    """Performance response"""
    status: Status = Status.SUCCESS
    current_metrics: PerformanceMetrics
    average_metrics: Optional[PerformanceMetrics]
    optimization_suggestions: List[str] = []

# AI/ML Models
class AIAnalysisRequest(BaseModel):
    """AI analysis request"""
    data: str = Field(..., description="Data to analyze")
    data_type: str = Field(default="text", description="Type of data (text, sequence, network)")
    model: Optional[str] = Field(None, description="Specific model to use")

class AIAnalysisResponse(BaseResponse):
    """AI analysis response"""
    status: Status = Status.SUCCESS
    threat_type: str
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    description: str
    mitigation: str
    false_positive_rate: float = Field(ge=0, le=1)
    model_used: str

# Evasion Models
class EvasionRequest(BaseModel):
    """Evasion request"""
    target: HttpUrl = Field(..., description="Target URL")
    payload: Optional[str] = Field(None, description="Payload to test")
    technique: Optional[str] = Field(None, description="Specific evasion technique")
    attack_type: Optional[str] = Field(None, description="Type of attack")

class EvasionResponse(BaseResponse):
    """Evasion response"""
    status: Status = Status.SUCCESS
    technique: str
    success: bool
    bypass_method: str
    detection_avoided: bool
    response_time: float
    confidence: float = Field(ge=0, le=1)

# System Models
class SystemInfo(BaseModel):
    """System information"""
    version: str
    platform: str
    python_version: str
    uptime: float
    total_scans: int
    active_scans: int
    total_vulnerabilities: int
    engines_status: Dict[str, str]

class SystemResponse(BaseResponse):
    """System response"""
    status: Status = Status.SUCCESS
    system_info: SystemInfo

# Webhook Models
class WebhookEvent(BaseModel):
    """Webhook event"""
    event_type: str
    scan_id: str
    timestamp: datetime
    data: Dict[str, Any]

class WebhookConfig(BaseModel):
    """Webhook configuration"""
    url: HttpUrl
    events: List[str] = Field(..., description="Events to subscribe to")
    secret: Optional[str] = Field(None, description="Webhook secret for verification")
    active: bool = Field(default=True)

# Dashboard Models
class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_scans: int
    active_scans: int
    vulnerabilities_found: int
    severity_distribution: Dict[Severity, int]
    recent_scans: List[Dict[str, Any]]
    system_health: Dict[str, Any]
    performance_metrics: PerformanceMetrics

class DashboardResponse(BaseResponse):
    """Dashboard response"""
    status: Status = Status.SUCCESS
    stats: DashboardStats

# Plugin Models
class PluginInfo(BaseModel):
    """Plugin information"""
    name: str
    version: str
    description: str
    author: str
    category: str
    is_enabled: bool
    dependencies: List[str] = []

class PluginListResponse(BaseResponse):
    """Plugin list response"""
    status: Status = Status.SUCCESS
    plugins: List[PluginInfo]

# Configuration Models
class ConfigUpdate(BaseModel):
    """Configuration update"""
    section: str
    key: str
    value: Any
    description: Optional[str] = None

class ConfigResponse(BaseResponse):
    """Configuration response"""
    status: Status = Status.SUCCESS
    configuration: Dict[str, Any]

# Health Check Models
class HealthCheck(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str
    uptime: float
    components: Dict[str, str]

class HealthResponse(BaseResponse):
    """Health response"""
    status: Status = Status.SUCCESS
    health: HealthCheck
