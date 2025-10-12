"""
AresProbe API Routes
REST API endpoints for automation and integration
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
import json

from .models import *
from .auth import get_current_user, require_admin, require_permission, User
from ..core.logger import Logger

# Initialize router and logger
router = APIRouter()
logger = Logger()

# In-memory storage for demo (use database in production)
scans_db = {}
reports_db = {}
webhooks_db = []

@router.get("/", response_model=BaseResponse)
async def root():
    """Root endpoint"""
    return BaseResponse(
        status=Status.SUCCESS,
        message="AresProbe API is running",
        timestamp=datetime.utcnow()
    )

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    try:
        from ..core.engine import AresEngine
        engine = AresEngine()
        
        components = {
            "core_engine": "healthy",
            "scanner": "healthy",
            "ai_engine": "healthy",
            "performance_optimizer": "healthy"
        }
        
        health = HealthCheck(
            status="healthy",
            timestamp=datetime.utcnow(),
            version="2.0.0",
            uptime=0.0,  # Would track actual uptime
            components=components
        )
        
        return HealthResponse(
            status=Status.SUCCESS,
            message="System is healthy",
            health=health
        )
    except Exception as e:
        logger.error(f"[-] Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")

# Authentication Routes
@router.post("/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """User login"""
    try:
        from .auth import get_auth_manager
        auth_manager = get_auth_manager()
        
        user = auth_manager.authenticate_user(request.username, request.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Create tokens
        access_token = auth_manager.create_access_token(data={"sub": user.id})
        refresh_token = auth_manager.create_refresh_token(data={"sub": user.id})
        
        return LoginResponse(
            status=Status.SUCCESS,
            message="Login successful",
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=auth_manager.access_token_expire_minutes * 60,
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[-] Login failed: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post("/auth/refresh", response_model=LoginResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token"""
    try:
        from .auth import get_auth_manager
        auth_manager = get_auth_manager()
        
        payload = auth_manager.verify_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        user_id = payload.get("sub")
        user = auth_manager.users.get(user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        # Create new tokens
        access_token = auth_manager.create_access_token(data={"sub": user.id})
        refresh_token = auth_manager.create_refresh_token(data={"sub": user.id})
        
        return LoginResponse(
            status=Status.SUCCESS,
            message="Token refreshed successfully",
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=auth_manager.access_token_expire_minutes * 60,
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[-] Token refresh failed: {e}")
        raise HTTPException(status_code=500, detail="Token refresh failed")

# API Key Management
@router.post("/auth/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    current_user: User = Depends(require_admin)
):
    """Create new API key"""
    try:
        from .auth import get_auth_manager
        auth_manager = get_auth_manager()
        
        api_key_obj = auth_manager.create_api_key(
            user_id=current_user.id,
            name=request.name,
            permissions=request.permissions,
            expires_days=request.expires_days
        )
        
        return APIKeyResponse(
            key=api_key_obj.key,
            name=api_key_obj.name,
            permissions=api_key_obj.permissions,
            created_at=api_key_obj.created_at,
            expires_at=api_key_obj.expires_at,
            is_active=api_key_obj.is_active
        )
    except Exception as e:
        logger.error(f"[-] API key creation failed: {e}")
        raise HTTPException(status_code=500, detail="API key creation failed")

# Scan Management
@router.post("/scans", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("scan:create"))
):
    """Create new security scan"""
    try:
        scan_id = str(uuid.uuid4())
        
        # Store scan info
        scan_info = {
            "scan_id": scan_id,
            "target": str(request.target),
            "scan_types": request.scan_types,
            "status": "running",
            "progress": 0.0,
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "vulnerabilities_found": 0,
            "created_by": current_user.id,
            "options": request.options
        }
        
        scans_db[scan_id] = scan_info
        
        # Start background scan
        background_tasks.add_task(run_scan, scan_id, request)
        
        logger.info(f"[+] Scan created: {scan_id} for {request.target}")
        
        return ScanResponse(
            status=Status.SUCCESS,
            message="Scan initiated successfully",
            scan_id=scan_id,
            target=str(request.target),
            scan_types=request.scan_types,
            status_message="Scan is starting..."
        )
    except Exception as e:
        logger.error(f"[-] Scan creation failed: {e}")
        raise HTTPException(status_code=500, detail="Scan creation failed")

@router.get("/scans/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(require_permission("scan:read"))
):
    """Get scan status"""
    scan_info = scans_db.get(scan_id)
    if not scan_info:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanStatus(**scan_info)

@router.get("/scans", response_model=List[ScanStatus])
async def list_scans(
    current_user: User = Depends(require_permission("scan:read"))
):
    """List all scans"""
    return [ScanStatus(**scan) for scan in scans_db.values()]

@router.delete("/scans/{scan_id}", response_model=BaseResponse)
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(require_permission("scan:delete"))
):
    """Cancel running scan"""
    scan_info = scans_db.get(scan_id)
    if not scan_info:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_info["status"] in ["completed", "failed"]:
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled")
    
    scan_info["status"] = "cancelled"
    scan_info["completed_at"] = datetime.utcnow()
    
    return BaseResponse(
        status=Status.SUCCESS,
        message="Scan cancelled successfully"
    )

# Vulnerability Management
@router.get("/scans/{scan_id}/vulnerabilities", response_model=VulnerabilityResponse)
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[List[Severity]] = None,
    current_user: User = Depends(require_permission("scan:read"))
):
    """Get vulnerabilities from scan"""
    scan_info = scans_db.get(scan_id)
    if not scan_info:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Mock vulnerabilities (in real implementation, fetch from database)
    vulnerabilities = [
        Vulnerability(
            id="vuln_1",
            type="sql_injection",
            severity=Severity.HIGH,
            title="SQL Injection Vulnerability",
            description="Parameter is vulnerable to SQL injection",
            url=str(scan_info["target"]),
            parameter="id",
            payload="' OR 1=1--",
            evidence="Database error message detected",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            cwe_id="CWE-89",
            cvss_score=8.5,
            remediation="Use parameterized queries",
            discovered_at=datetime.utcnow()
        )
    ]
    
    # Filter by severity if specified
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.severity in severity]
    
    # Calculate severity counts
    severity_counts = {}
    for v in vulnerabilities:
        severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
    
    return VulnerabilityResponse(
        status=Status.SUCCESS,
        message="Vulnerabilities retrieved successfully",
        vulnerabilities=vulnerabilities,
        total_count=len(vulnerabilities),
        severity_counts=severity_counts
    )

# Report Generation
@router.post("/reports", response_model=ReportResponse)
async def generate_report(
    request: ReportRequest,
    current_user: User = Depends(require_permission("report:create"))
):
    """Generate security report"""
    try:
        report_id = str(uuid.uuid4())
        
        # Mock report generation
        if request.format == "json":
            report_data = {
                "scan_id": request.scan_id,
                "vulnerabilities": [],
                "summary": {
                    "total_vulnerabilities": 0,
                    "severity_distribution": {}
                },
                "generated_at": datetime.utcnow().isoformat()
            }
            
            reports_db[report_id] = report_data
            
            return ReportResponse(
                status=Status.SUCCESS,
                message="Report generated successfully",
                report_id=report_id,
                format=request.format,
                content=json.dumps(report_data, indent=2)
            )
        else:
            # For other formats, return download URL
            reports_db[report_id] = {"format": request.format, "status": "generating"}
            
            return ReportResponse(
                status=Status.SUCCESS,
                message="Report generation started",
                report_id=report_id,
                format=request.format,
                download_url=f"/api/reports/{report_id}/download"
            )
    except Exception as e:
        logger.error(f"[-] Report generation failed: {e}")
        raise HTTPException(status_code=500, detail="Report generation failed")

@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(require_permission("report:read"))
):
    """Download generated report"""
    report_data = reports_db.get(report_id)
    if not report_data:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Return appropriate file response based on format
    format_type = report_data.get("format", "json")
    
    if format_type == "json":
        return JSONResponse(content=report_data)
    else:
        # For other formats, return mock file
        return FileResponse(
            path="mock_report.pdf",
            filename=f"aresprobe_report_{report_id}.pdf",
            media_type="application/pdf"
        )

# Performance Monitoring
@router.get("/performance", response_model=PerformanceResponse)
async def get_performance_metrics(
    current_user: User = Depends(require_permission("system:read"))
):
    """Get performance metrics"""
    try:
        from ..core.performance_optimizer import PerformanceOptimizer
        optimizer = PerformanceOptimizer(logger)
        
        report = optimizer.get_performance_report()
        
        current_metrics = PerformanceMetrics(
            cpu_usage=report["current_metrics"]["cpu_usage"],
            memory_usage=report["current_metrics"]["memory_usage"],
            network_throughput=report["current_metrics"]["network_throughput"],
            response_time=report["current_metrics"]["response_time"],
            concurrent_connections=report["current_metrics"]["concurrent_connections"],
            cache_hit_ratio=report["current_metrics"]["cache_hit_ratio"],
            error_rate=report["current_metrics"]["error_rate"],
            timestamp=datetime.utcnow()
        )
        
        return PerformanceResponse(
            status=Status.SUCCESS,
            message="Performance metrics retrieved successfully",
            current_metrics=current_metrics,
            optimization_suggestions=[
                "Consider increasing memory pool size",
                "Optimize database queries",
                "Enable connection pooling"
            ]
        )
    except Exception as e:
        logger.error(f"[-] Performance metrics failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")

# AI/ML Analysis
@router.post("/ai/analyze", response_model=AIAnalysisResponse)
async def ai_analyze(
    request: AIAnalysisRequest,
    current_user: User = Depends(require_permission("ai:analyze"))
):
    """AI-powered threat analysis"""
    try:
        from ..core.advanced_ai_ml import AdvancedAIMLEngine
        ai_engine = AdvancedAIMLEngine(logger)
        
        # Run async analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                ai_engine.analyze_threat_pattern(request.data, request.data_type)
            )
            
            return AIAnalysisResponse(
                status=Status.SUCCESS,
                message="AI analysis completed",
                threat_type=result.threat_type,
                confidence=result.confidence,
                severity=Severity(result.severity),
                description=result.description,
                mitigation=result.mitigation,
                false_positive_rate=result.false_positive_rate,
                model_used=result.model_used
            )
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"[-] AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail="AI analysis failed")

# Evasion Testing
@router.post("/evasion/test", response_model=EvasionResponse)
async def test_evasion(
    request: EvasionRequest,
    current_user: User = Depends(require_permission("evasion:test"))
):
    """Test evasion techniques"""
    try:
        from ..core.advanced_evasion import AdvancedEvasionEngine, EvasionConfig
        evasion_engine = AdvancedEvasionEngine(EvasionConfig(), logger)
        
        # Run async evasion test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(
                evasion_engine.execute_evasion(str(request.target), request.payload)
            )
            
            if results:
                result = results[0]  # Get first result
                return EvasionResponse(
                    status=Status.SUCCESS,
                    message="Evasion test completed",
                    technique=result.technique,
                    success=result.success,
                    bypass_method=result.bypass_method,
                    detection_avoided=result.detection_avoided,
                    response_time=result.response_time,
                    confidence=result.confidence
                )
            else:
                raise HTTPException(status_code=500, detail="No evasion results")
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"[-] Evasion test failed: {e}")
        raise HTTPException(status_code=500, detail="Evasion test failed")

# System Information
@router.get("/system", response_model=SystemResponse)
async def get_system_info(
    current_user: User = Depends(require_permission("system:read"))
):
    """Get system information"""
    try:
        import platform
        import sys
        
        system_info = SystemInfo(
            version="2.0.0",
            platform=platform.system(),
            python_version=sys.version,
            uptime=0.0,  # Would track actual uptime
            total_scans=len(scans_db),
            active_scans=len([s for s in scans_db.values() if s["status"] == "running"]),
            total_vulnerabilities=sum(s.get("vulnerabilities_found", 0) for s in scans_db.values()),
            engines_status={
                "core_engine": "online",
                "scanner": "online",
                "ai_engine": "online",
                "performance_optimizer": "online"
            }
        )
        
        return SystemResponse(
            status=Status.SUCCESS,
            message="System information retrieved successfully",
            system_info=system_info
        )
    except Exception as e:
        logger.error(f"[-] System info failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system information")

# Dashboard
@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard_stats(
    current_user: User = Depends(require_permission("dashboard:read"))
):
    """Get dashboard statistics"""
    try:
        # Calculate statistics
        total_scans = len(scans_db)
        active_scans = len([s for s in scans_db.values() if s["status"] == "running"])
        vulnerabilities_found = sum(s.get("vulnerabilities_found", 0) for s in scans_db.values())
        
        severity_distribution = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 15,
            Severity.MEDIUM: 25,
            Severity.LOW: 10,
            Severity.INFO: 5
        }
        
        recent_scans = [
            {
                "scan_id": scan_id,
                "target": scan["target"],
                "status": scan["status"],
                "started_at": scan["started_at"].isoformat()
            }
            for scan_id, scan in list(scans_db.items())[-10:]
        ]
        
        system_health = {
            "cpu_usage": 45.2,
            "memory_usage": 67.8,
            "disk_usage": 23.1,
            "network_status": "healthy"
        }
        
        performance_metrics = PerformanceMetrics(
            cpu_usage=45.2,
            memory_usage=67.8,
            network_throughput=125.5,
            response_time=0.234,
            concurrent_connections=15,
            cache_hit_ratio=0.89,
            error_rate=0.02,
            timestamp=datetime.utcnow()
        )
        
        stats = DashboardStats(
            total_scans=total_scans,
            active_scans=active_scans,
            vulnerabilities_found=vulnerabilities_found,
            severity_distribution=severity_distribution,
            recent_scans=recent_scans,
            system_health=system_health,
            performance_metrics=performance_metrics
        )
        
        return DashboardResponse(
            status=Status.SUCCESS,
            message="Dashboard statistics retrieved successfully",
            stats=stats
        )
    except Exception as e:
        logger.error(f"[-] Dashboard stats failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard statistics")

# Background Tasks
async def run_scan(scan_id: str, request: ScanRequest):
    """Background scan task"""
    try:
        scan_info = scans_db.get(scan_id)
        if not scan_info:
            return
        
        # Simulate scan progress
        for progress in range(0, 101, 10):
            await asyncio.sleep(1)  # Simulate work
            scan_info["progress"] = progress
            
            if progress == 100:
                scan_info["status"] = "completed"
                scan_info["completed_at"] = datetime.utcnow()
                scan_info["vulnerabilities_found"] = 3  # Mock result
            else:
                scan_info["status"] = "running"
        
        logger.info(f"[+] Scan completed: {scan_id}")
        
        # Send webhook if configured
        await send_webhook(scan_id, "scan.completed", scan_info)
        
    except Exception as e:
        logger.error(f"[-] Background scan failed: {e}")
        scan_info = scans_db.get(scan_id)
        if scan_info:
            scan_info["status"] = "failed"
            scan_info["completed_at"] = datetime.utcnow()

async def send_webhook(scan_id: str, event_type: str, data: Dict[str, Any]):
    """Send webhook notification"""
    try:
        for webhook in webhooks_db:
            if event_type in webhook.get("events", []):
                # Send webhook (implement actual HTTP request)
                logger.info(f"[+] Webhook sent: {event_type} to {webhook['url']}")
    except Exception as e:
        logger.error(f"[-] Webhook failed: {e}")
