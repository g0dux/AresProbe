#!/usr/bin/env python3
"""
AresProbe - Shadow Penetration Framework
Cross-platform main entry point for Linux and Windows
"""

import sys
import os
import argparse
import platform
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from aresprobe.cli.interface import AresCLI
from aresprobe.core.logger import Logger


def detect_platform():
    """Detect the current platform and return platform info"""
    system = platform.system().lower()
    is_windows = system == 'windows'
    is_linux = system == 'linux'
    is_macos = system == 'darwin'
    
    return {
        'system': system,
        'is_windows': is_windows,
        'is_linux': is_linux,
        'is_macos': is_macos,
        'version': platform.version(),
        'architecture': platform.architecture()[0]
    }


def main():
    """Cross-platform main entry point for AresProbe"""
    platform_info = detect_platform()
    
    parser = argparse.ArgumentParser(
        description="AresProbe - Shadow Penetration Framework (Cross-Platform)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Platform: {platform_info['system'].upper()} {platform_info['architecture']}
Examples:
  python main.py                    # Start interactive CLI
  python main.py --scan http://example.com  # Quick scan
  python main.py --proxy 8080       # Start proxy only
  python main.py --info             # Show platform information
        """
    )
    
    parser.add_argument(
        '--scan', 
        metavar='URL', 
        help='Quick scan target URL and exit'
    )
    parser.add_argument(
        '--proxy', 
        type=int, 
        metavar='PORT', 
        help='Start proxy server on specified port'
    )
    parser.add_argument(
        '--threads', 
        type=int, 
        default=10, 
        help='Number of threads for scanning (default: 10)'
    )
    parser.add_argument(
        '--timeout', 
        type=int, 
        default=30, 
        help='Request timeout in seconds (default: 30)'
    )
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true', 
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--version', 
        action='version', 
        version='AresProbe 2.0.0'
    )
    parser.add_argument(
        '--info',
        action='store_true',
        help='Show platform and system information'
    )
    
    args = parser.parse_args()
    
    # Show platform info if requested
    if args.info:
        print("=" * 60)
        print("ARESPROBE - PLATFORM INFORMATION")
        print("=" * 60)
        print(f"Operating System: {platform_info['system'].upper()}")
        print(f"Architecture: {platform_info['architecture']}")
        print(f"Python Version: {sys.version}")
        print(f"Platform Version: {platform_info['version']}")
        print("=" * 60)
        return
    
    # Initialize logger
    logger = Logger()
    if args.verbose:
        logger.set_level('DEBUG')
    
    # Platform-specific startup message
    if platform_info['is_windows']:
        logger.info("[*] Windows compatibility mode activated")
        logger.info("[*] Auto-completion disabled for Windows compatibility")
    elif platform_info['is_linux']:
        logger.info("[*] Linux mode activated")
        logger.info("[*] Full feature set available")
    elif platform_info['is_macos']:
        logger.info("[*] macOS mode activated")
        logger.info("[*] Full feature set available")
    
    try:
        # Quick scan mode
        if args.scan:
            from aresprobe.core.engine import AresEngine, ScanConfig, ScanType
            
            logger.info("[*] Starting quick scan mode...")
            
            engine = AresEngine()
            if not engine.initialize():
                logger.error("[-] Failed to initialize AresProbe engine")
                sys.exit(1)
            
            config = ScanConfig(
                target_url=args.scan,
                scan_types=[ScanType.SQL_INJECTION, ScanType.XSS, ScanType.DIRECTORY_TRAVERSAL],
                threads=args.threads,
                timeout=args.timeout
            )
            
            results = engine.run_scan(config)
            
            if results.get('status') == 'completed':
                logger.success("[+] Quick scan completed")
                print("\n" + "="*60)
                print("ARESPROBE QUICK SCAN RESULTS")
                print("="*60)
                print(f"Target: {results.get('target', 'N/A')}")
                print(f"Duration: {results.get('duration', 0):.2f} seconds")
                print(f"Status: {results.get('status', 'N/A')}")
                
                if results.get('results'):
                    total_vulns = 0
                    for scan_type, scan_results in results['results'].items():
                        if isinstance(scan_results, dict) and scan_results.get('vulnerabilities'):
                            vuln_count = len(scan_results['vulnerabilities'])
                            total_vulns += vuln_count
                            print(f"{scan_type.upper()}: {vuln_count} vulnerabilities")
                    
                    print(f"Total Vulnerabilities: {total_vulns}")
                
                print("="*60)
            else:
                logger.error(f"[-] Quick scan failed: {results.get('error', 'Unknown error')}")
                sys.exit(1)
            
            engine.cleanup()
        
        # Proxy only mode
        elif args.proxy:
            from aresprobe.core.engine import AresEngine
            
            logger.info(f"[*] Starting proxy server on port {args.proxy}...")
            
            engine = AresEngine()
            if not engine.initialize():
                logger.error("[-] Failed to initialize AresProbe engine")
                sys.exit(1)
            
            if engine.start_proxy(args.proxy):
                logger.success(f"[+] Proxy server started on port {args.proxy}")
                logger.info("[*] Press Ctrl+C to stop the proxy server")
                
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logger.info("\n[*] Stopping proxy server...")
                    engine.stop_proxy()
                    logger.success("[+] Proxy server stopped")
            else:
                logger.error("[-] Failed to start proxy server")
                sys.exit(1)
            
            engine.cleanup()
        
        # Interactive CLI mode
        else:
            if platform_info['is_windows']:
                print("Starting AresProbe Shadow Edition (Windows Compatible)...")
            else:
                print("Starting AresProbe Shadow Edition...")
            print("=" * 60)
            cli = AresCLI()
            cli.cmdloop()
    
    except KeyboardInterrupt:
        logger.info("\n[*] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[-] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
