"""
AresProbe Web Dashboard Main Application
FastAPI web application with dashboard and API integration
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os

from .routes import router as web_router
from ..api.main import app as api_app
from ..core.logger import Logger

# Initialize logger
logger = Logger()

# Create FastAPI app for web dashboard
app = FastAPI(
    title="AresProbe Web Dashboard",
    description="Advanced Web Security Testing Framework - Web Interface",
    version="2.0.0",
    docs_url=None,  # Disable docs for web interface
    redoc_url=None
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Include web routes
app.include_router(web_router, tags=["Web Dashboard"])

# Mount API app
app.mount("/api", api_app, name="api")

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - redirect to dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AresProbe Web Dashboard</title>
        <meta http-equiv="refresh" content="0; url=/dashboard">
    </head>
    <body>
        <p>Redirecting to dashboard... <a href="/dashboard">Click here if not redirected</a></p>
    </body>
    </html>
    """

# Health check
@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "AresProbe Web Dashboard",
        "version": "2.0.0"
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup"""
    logger.info("[*] Starting AresProbe Web Dashboard...")
    logger.info("[+] Web Dashboard: http://localhost:8080")
    logger.info("[+] API Documentation: http://localhost:8080/api/docs")
    logger.success("[+] AresProbe Web Dashboard started successfully")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown"""
    logger.info("[*] Shutting down AresProbe Web Dashboard...")
    logger.success("[+] AresProbe Web Dashboard shutdown complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "aresprobe.web.main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )
