#!/usr/bin/env python3
"""
AresProbe Windows Installation Script
Automated installation script for Windows systems
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("[-] Python 3.8 or higher is required")
        print(f"[!] Current version: {sys.version}")
        return False
    return True

def check_pip():
    """Check if pip is available"""
    try:
        import pip
        return True
    except ImportError:
        print("[-] pip is not available. Please install pip first.")
        return False

def install_requirements():
    """Install requirements for Windows"""
    print("[*] Installing Windows-compatible requirements...")
    
    # Try different requirement files in order of preference
    requirement_files = [
        "requirements-windows-minimal.txt",
        "requirements-windows.txt", 
        "requirements.txt"
    ]
    
    for req_file in requirement_files:
        if Path(req_file).exists():
            print(f"[*] Using {req_file}")
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", req_file
                ], check=True)
                print(f"[+] Requirements installed successfully from {req_file}")
                return True
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to install from {req_file}: {e}")
                continue
    
    print("[-] All requirement files failed to install")
    return False

def setup_directories():
    """Create necessary directories"""
    print("[*] Setting up directories...")
    
    directories = [
        "plugins",
        "custom_plugins", 
        "reports",
        "cache",
        "aresprobe/web/static",
        "aresprobe/web/templates"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"[+] Created directory: {directory}")

def test_installation():
    """Test if installation was successful"""
    print("[*] Testing installation...")
    
    try:
        # Test basic imports
        import requests
        import aiohttp
        import rich
        import pyfiglet
        import colorama
        
        print("[+] Core dependencies imported successfully")
        
        # Test AresProbe import
        sys.path.insert(0, str(Path.cwd()))
        from aresprobe.cli.interface import AresCLI
        from aresprobe.core.logger import Logger
        
        print("[+] AresProbe modules imported successfully")
        return True
        
    except ImportError as e:
        print(f"[-] Import test failed: {e}")
        return False

def create_shortcut():
    """Create desktop shortcut for Windows"""
    if platform.system() == "Windows":
        print("[*] Creating desktop shortcut...")
        
        try:
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            path = os.path.join(desktop, "AresProbe.lnk")
            target = sys.executable
            wDir = str(Path.cwd())
            icon = target
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(path)
            shortcut.Targetpath = target
            shortcut.Arguments = f'"{Path.cwd() / "main.py"}"'
            shortcut.WorkingDirectory = wDir
            shortcut.IconLocation = icon
            shortcut.save()
            
            print(f"[+] Desktop shortcut created: {path}")
            
        except ImportError:
            print("[!] Could not create desktop shortcut (missing winshell/pywin32)")
        except Exception as e:
            print(f"[!] Could not create desktop shortcut: {e}")

def main():
    """Main installation function"""
    print("=" * 60)
    print("ARESPROBE WINDOWS INSTALLATION")
    print("=" * 60)
    print()
    
    # Check system requirements
    if not check_python_version():
        return False
    
    if not check_pip():
        return False
    
    print(f"[*] Python version: {sys.version}")
    print(f"[*] Platform: {platform.system()} {platform.release()}")
    print()
    
    # Install requirements
    if not install_requirements():
        print("[-] Installation failed during requirements installation")
        return False
    
    # Setup directories
    setup_directories()
    
    # Test installation
    if not test_installation():
        print("[-] Installation test failed")
        return False
    
    # Create shortcut
    create_shortcut()
    
    print()
    print("=" * 60)
    print("INSTALLATION COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print()
    print("To start AresProbe:")
    print("  python main.py")
    print()
    print("Or double-click the desktop shortcut (if created)")
    print()
    print("For help:")
    print("  python main.py --help")
    print()
    print("Enjoy using AresProbe!")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[*] Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Installation failed: {e}")
        sys.exit(1)
