"""
AresProbe Web Dashboard Routes
Web interface routes for the dashboard
"""

from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

from ..api.auth import get_current_user, User
from ..core.logger import Logger

# Initialize router and templates
router = APIRouter()
logger = Logger()

# Templates directory
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Web Routes
@router.get("/", response_class=HTMLResponse)
async def dashboard_root(request: Request):
    """Redirect to dashboard"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_main(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    """Scans management page"""
    return templates.TemplateResponse("scans.html", {"request": request})

@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(request: Request):
    """Vulnerabilities page"""
    return templates.TemplateResponse("vulnerabilities.html", {"request": request})

@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Reports page"""
    return templates.TemplateResponse("reports.html", {"request": request})

@router.get("/ai", response_class=HTMLResponse)
async def ai_page(request: Request):
    """AI Analysis page"""
    return templates.TemplateResponse("ai.html", {"request": request})

@router.get("/evasion", response_class=HTMLResponse)
async def evasion_page(request: Request):
    """Evasion testing page"""
    return templates.TemplateResponse("evasion.html", {"request": request})

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page"""
    return templates.TemplateResponse("settings.html", {"request": request})

@router.get("/api-keys", response_class=HTMLResponse)
async def api_keys_page(request: Request):
    """API Keys management page"""
    return templates.TemplateResponse("api-keys.html", {"request": request})

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    return templates.TemplateResponse("login.html", {"request": request})

@router.get("/logout")
async def logout():
    """Logout endpoint"""
    # In a real implementation, you would invalidate the session/token
    return JSONResponse({"message": "Logged out successfully"})

# API endpoints for web dashboard
@router.get("/api/dashboard/stats")
async def get_dashboard_stats_api():
    """Get dashboard statistics for web interface"""
    try:
        # Mock data - in production, fetch from actual API
        stats = {
            "total_scans": 156,
            "active_scans": 3,
            "vulnerabilities_found": 89,
            "severity_distribution": {
                "critical": 5,
                "high": 15,
                "medium": 25,
                "low": 10,
                "info": 5
            },
            "recent_scans": [
                {
                    "scan_id": "scan_001",
                    "target": "https://example.com",
                    "status": "completed",
                    "started_at": "2025-01-01T10:00:00Z"
                },
                {
                    "scan_id": "scan_002",
                    "target": "https://test.com",
                    "status": "running",
                    "started_at": "2025-01-01T11:00:00Z"
                }
            ],
            "system_health": {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "disk_usage": 23.1,
                "network_status": "healthy"
            },
            "performance_metrics": {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "network_throughput": 125.5,
                "response_time": 0.234,
                "concurrent_connections": 15,
                "cache_hit_ratio": 0.89,
                "error_rate": 0.02,
                "timestamp": "2025-01-01T12:00:00Z"
            }
        }
        
        return JSONResponse(stats)
    except Exception as e:
        logger.error(f"[-] Failed to get dashboard stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard statistics")

@router.get("/api/scans")
async def get_scans_api():
    """Get scans list for web interface"""
    try:
        # Mock data - in production, fetch from actual API
        scans = [
            {
                "scan_id": "scan_001",
                "target": "https://example.com",
                "status": "completed",
                "progress": 100.0,
                "started_at": "2025-01-01T10:00:00Z",
                "completed_at": "2025-01-01T10:30:00Z",
                "vulnerabilities_found": 12,
                "scan_types": ["comprehensive"]
            },
            {
                "scan_id": "scan_002",
                "target": "https://test.com",
                "status": "running",
                "progress": 65.0,
                "started_at": "2025-01-01T11:00:00Z",
                "completed_at": None,
                "vulnerabilities_found": 3,
                "scan_types": ["sql_injection", "xss"]
            }
        ]
        
        return JSONResponse(scans)
    except Exception as e:
        logger.error(f"[-] Failed to get scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scans")

@router.get("/api/vulnerabilities")
async def get_vulnerabilities_api():
    """Get vulnerabilities for web interface"""
    try:
        # Mock data - in production, fetch from actual API
        vulnerabilities = [
            {
                "id": "vuln_001",
                "type": "sql_injection",
                "severity": "high",
                "title": "SQL Injection Vulnerability",
                "description": "Parameter is vulnerable to SQL injection attacks",
                "url": "https://example.com/login",
                "parameter": "username",
                "payload": "' OR 1=1--",
                "evidence": "Database error message detected",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "cwe_id": "CWE-89",
                "cvss_score": 8.5,
                "remediation": "Use parameterized queries",
                "discovered_at": "2025-01-01T10:15:00Z"
            },
            {
                "id": "vuln_002",
                "type": "xss",
                "severity": "medium",
                "title": "Cross-Site Scripting (XSS)",
                "description": "Reflected XSS vulnerability in search parameter",
                "url": "https://example.com/search",
                "parameter": "q",
                "payload": "<script>alert('XSS')</script>",
                "evidence": "Script execution confirmed",
                "references": ["https://owasp.org/www-community/attacks/xss/"],
                "cwe_id": "CWE-79",
                "cvss_score": 6.1,
                "remediation": "Implement proper input validation and output encoding",
                "discovered_at": "2025-01-01T10:20:00Z"
            }
        ]
        
        return JSONResponse(vulnerabilities)
    except Exception as e:
        logger.error(f"[-] Failed to get vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Failed to get vulnerabilities")

@router.get("/api/performance")
async def get_performance_api():
    """Get performance metrics for web interface"""
    try:
        # Mock data - in production, fetch from actual API
        performance = {
            "current_metrics": {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "network_throughput": 125.5,
                "response_time": 0.234,
                "concurrent_connections": 15,
                "cache_hit_ratio": 0.89,
                "error_rate": 0.02,
                "timestamp": "2025-01-01T12:00:00Z"
            },
            "average_metrics": {
                "cpu_usage": 42.1,
                "memory_usage": 65.3,
                "network_throughput": 118.2,
                "response_time": 0.198,
                "concurrent_connections": 12,
                "cache_hit_ratio": 0.91,
                "error_rate": 0.015,
                "timestamp": "2025-01-01T12:00:00Z"
            },
            "optimization_suggestions": [
                "Consider increasing memory pool size",
                "Optimize database queries",
                "Enable connection pooling",
                "Implement caching for frequently accessed data"
            ]
        }
        
        return JSONResponse(performance)
    except Exception as e:
        logger.error(f"[-] Failed to get performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")

@router.get("/api/system")
async def get_system_info_api():
    """Get system information for web interface"""
    try:
        import platform
        import sys
        
        system_info = {
            "version": "2.0.0",
            "platform": platform.system(),
            "python_version": sys.version,
            "uptime": "2 days, 14 hours, 32 minutes",
            "total_scans": 156,
            "active_scans": 3,
            "total_vulnerabilities": 89,
            "engines_status": {
                "core_engine": "online",
                "scanner": "online",
                "ai_engine": "online",
                "performance_optimizer": "online",
                "evasion_engine": "online",
                "plugin_manager": "online"
            }
        }
        
        return JSONResponse(system_info)
    except Exception as e:
        logger.error(f"[-] Failed to get system info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system information")

# WebSocket endpoints for real-time updates
@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket):
    """WebSocket endpoint for real-time dashboard updates"""
    await websocket.accept()
    
    try:
        while True:
            # Send real-time data
            data = {
                "type": "dashboard_update",
                "timestamp": "2025-01-01T12:00:00Z",
                "metrics": {
                    "cpu_usage": 45.2,
                    "memory_usage": 67.8,
                    "active_scans": 3,
                    "vulnerabilities_found": 89
                }
            }
            
            await websocket.send_json(data)
            await asyncio.sleep(5)  # Update every 5 seconds
            
    except Exception as e:
        logger.error(f"[-] WebSocket error: {e}")
    finally:
        await websocket.close()

@router.websocket("/ws/scans")
async def websocket_scans(websocket):
    """WebSocket endpoint for real-time scan updates"""
    await websocket.accept()
    
    try:
        while True:
            # Send real-time scan data
            data = {
                "type": "scan_update",
                "timestamp": "2025-01-01T12:00:00Z",
                "scans": [
                    {
                        "scan_id": "scan_002",
                        "progress": 75.0,
                        "status": "running"
                    }
                ]
            }
            
            await websocket.send_json(data)
            await asyncio.sleep(2)  # Update every 2 seconds
            
    except Exception as e:
        logger.error(f"[-] WebSocket error: {e}")
    finally:
        await websocket.close()
