"""
AresProbe API Main Application
FastAPI application with all routes and middleware
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
import time
import logging

from .routes import router
from .auth import get_auth_manager
from ..core.logger import Logger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = Logger()

# Create FastAPI app
app = FastAPI(
    title="AresProbe API",
    description="Advanced Web Security Testing Framework API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests"""
    start_time = time.time()
    
    # Log request
    logger.info(f"[*] {request.method} {request.url.path} - {request.client.host}")
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    # Log response
    logger.info(f"[+] {response.status_code} - {process_time:.3f}s")
    
    # Add processing time header
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# Add error handling middleware
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "error_code": str(exc.status_code),
            "timestamp": time.time()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"[-] Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error",
            "error_code": "INTERNAL_ERROR",
            "timestamp": time.time()
        }
    )

# Include API routes
app.include_router(router, prefix="/api/v1", tags=["API"])

# Static files for web dashboard
try:
    app.mount("/static", StaticFiles(directory="aresprobe/web/static"), name="static")
except:
    pass  # Static files directory might not exist yet

# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="AresProbe API",
        version="2.0.0",
        description="""
        ## AresProbe API Documentation
        
        Advanced Web Security Testing Framework API for automation and integration.
        
        ### Authentication
        
        The API supports two authentication methods:
        1. **JWT Tokens** - For web dashboard and temporary access
        2. **API Keys** - For programmatic access and automation
        
        ### Features
        
        - **Security Scanning** - Comprehensive vulnerability testing
        - **AI Analysis** - Machine learning-powered threat detection
        - **Performance Monitoring** - Real-time system metrics
        - **Evasion Testing** - Advanced bypass techniques
        - **Report Generation** - Multiple format support
        - **Webhook Integration** - Real-time notifications
        
        ### Rate Limiting
        
        API requests are rate limited to prevent abuse:
        - **Authenticated users**: 1000 requests/hour
        - **API keys**: 5000 requests/hour
        
        ### Error Handling
        
        All errors follow a consistent format:
        ```json
        {
            "status": "error",
            "message": "Error description",
            "error_code": "ERROR_CODE",
            "timestamp": 1234567890
        }
        ```
        """,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization"
        }
    }
    
    # Add security requirements
    openapi_schema["security"] = [
        {"BearerAuth": []},
        {"ApiKeyAuth": []}
    ]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup"""
    logger.info("[*] Starting AresProbe API...")
    
    # Initialize auth manager
    auth_manager = get_auth_manager()
    logger.info("[+] Authentication system initialized")
    
    # Log API information
    logger.info(f"[+] API Documentation: /docs")
    logger.info(f"[+] API Schema: /openapi.json")
    logger.info(f"[+] Default admin credentials: admin/admin")
    
    # Get default API key
    admin_user = auth_manager.users.get("admin")
    if admin_user and admin_user.api_keys:
        api_key = admin_user.api_keys[0]
        logger.info(f"[+] Default API key: {api_key}")
    
    logger.success("[+] AresProbe API started successfully")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown"""
    logger.info("[*] Shutting down AresProbe API...")
    logger.success("[+] AresProbe API shutdown complete")

# Root endpoints
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "AresProbe API",
        "version": "2.0.0",
        "description": "Advanced Web Security Testing Framework API",
        "documentation": "/docs",
        "health_check": "/health",
        "api_endpoints": "/api/v1/",
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "2.0.0",
        "uptime": "0s"  # Would track actual uptime
    }

# Custom documentation endpoint
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Custom Swagger UI with AresProbe branding"""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="AresProbe API Documentation",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
        swagger_favicon_url="/static/favicon.ico"
    )

# Webhook endpoints
@app.post("/webhooks")
async def register_webhook(request: dict):
    """Register webhook for notifications"""
    try:
        # Validate webhook configuration
        required_fields = ["url", "events"]
        for field in required_fields:
            if field not in request:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Store webhook configuration
        webhook_id = f"webhook_{int(time.time())}"
        webhook_config = {
            "id": webhook_id,
            "url": request["url"],
            "events": request["events"],
            "secret": request.get("secret"),
            "active": request.get("active", True),
            "created_at": time.time()
        }
        
        # In production, store in database
        # webhooks_db.append(webhook_config)
        
        logger.info(f"[+] Webhook registered: {webhook_config['url']}")
        
        return {
            "status": "success",
            "message": "Webhook registered successfully",
            "webhook_id": webhook_id
        }
    except Exception as e:
        logger.error(f"[-] Webhook registration failed: {e}")
        raise HTTPException(status_code=500, detail="Webhook registration failed")

# API usage statistics
@app.get("/stats")
async def api_stats():
    """Get API usage statistics"""
    try:
        # In production, get from database
        stats = {
            "total_requests": 0,
            "requests_per_hour": 0,
            "active_scans": 0,
            "total_vulnerabilities": 0,
            "api_keys_active": 0,
            "uptime": "0s"
        }
        
        return {
            "status": "success",
            "stats": stats
        }
    except Exception as e:
        logger.error(f"[-] Stats retrieval failed: {e}")
        raise HTTPException(status_code=500, detail="Stats retrieval failed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "aresprobe.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
