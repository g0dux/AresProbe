#!/usr/bin/env python3
"""
AresProbe Web Dashboard Launcher
Start the web dashboard and API server
"""

import os
import sys
import platform
import subprocess
import time
from pathlib import Path

def print_banner():
    """Print startup banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    █████╗ ██████╗ ███████╗███████╗██████╗ ██████╗ ██████╗ ███████╗██████╗ ███████╗
    ║   ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
    ║   ███████║██████╔╝███████╗█████╗  ██████╔╝██████╔╝██████╔╝█████╗  ██████╔╝█████╗  
    ║   ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔═══╝ ██╔═══╝ ██╔══██╗██╔══╝  ██╔═══╝ ██╔══╝  
    ║   ██║  ██║██║  ██║███████║███████╗██║     ██║     ██║  ██║███████╗██║     ███████╗
    ║   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝
    ║                                                              ║
    ║                    Web Dashboard & API Server                ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check Python version compatibility"""
    if sys.version_info < (3, 8):
        print("[-] Error: Python 3.8 or higher is required")
        print(f"[-] Current version: {sys.version}")
        sys.exit(1)
    print(f"[+] Python version: {sys.version.split()[0]}")

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'fastapi',
        'uvicorn',
        'jinja2',
        'pydantic',
        'passlib',
        'python-jose'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"[+] {package} is installed")
        except ImportError:
            missing_packages.append(package)
            print(f"[-] {package} is missing")
    
    if missing_packages:
        print(f"\n[-] Missing packages: {', '.join(missing_packages)}")
        print("[*] Installing missing packages...")
        
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 
                *missing_packages
            ])
            print("[+] Missing packages installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install missing packages")
            print("[*] Please install them manually:")
            print(f"pip install {' '.join(missing_packages)}")
            sys.exit(1)

def setup_environment():
    """Setup environment variables"""
    os.environ['ARESPROBE_ENV'] = 'web'
    os.environ['PYTHONPATH'] = str(Path(__file__).parent)
    
    # Set platform-specific variables
    if platform.system() == 'Windows':
        os.environ['ARESPROBE_PLATFORM'] = 'windows'
    else:
        os.environ['ARESPROBE_PLATFORM'] = 'unix'
    
    print(f"[+] Environment setup complete")
    print(f"[+] Platform: {platform.system()}")

def start_web_server():
    """Start the web dashboard server"""
    print("\n[*] Starting AresProbe Web Dashboard...")
    
    try:
        # Import and start the web application
        from aresprobe.web.main import app
        
        import uvicorn
        
        print("[+] Web Dashboard: http://localhost:8080")
        print("[+] API Documentation: http://localhost:8080/api/docs")
        print("[+] API Base URL: http://localhost:8080/api/v1")
        print("\n[*] Press Ctrl+C to stop the server")
        print("=" * 60)
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8080,
            log_level="info",
            access_log=True
        )
        
    except KeyboardInterrupt:
        print("\n[*] Shutting down AresProbe Web Dashboard...")
        print("[+] Shutdown complete")
    except Exception as e:
        print(f"[-] Error starting web server: {e}")
        print("\n[*] Troubleshooting:")
        print("1. Make sure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check if port 8080 is available")
        print("3. Ensure you're in the correct directory")
        sys.exit(1)

def main():
    """Main function"""
    print_banner()
    
    print("[*] AresProbe Web Dashboard Launcher")
    print("[*] Checking system requirements...")
    
    # Check Python version
    check_python_version()
    
    # Setup environment
    setup_environment()
    
    # Check dependencies
    check_dependencies()
    
    # Start web server
    start_web_server()

if __name__ == "__main__":
    main()
