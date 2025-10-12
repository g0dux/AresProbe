"""
AresProbe CLI Commands
Command implementations for the CLI interface
"""

import argparse
import json
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from ..core.engine import AresEngine, ScanConfig, ScanType
from ..core.logger import Logger


class BaseCommand:
    """Base class for CLI commands"""
    
    def __init__(self, engine: AresEngine, logger: Logger):
        self.engine = engine
        self.logger = logger
    
    def execute(self, args: str):
        """Execute the command with given arguments"""
        raise NotImplementedError


class ScanCommand(BaseCommand):
    """Scan command implementation"""
    
    def execute(self, args: str):
        """Execute scan command"""
        parser = argparse.ArgumentParser(prog='scan', add_help=False)
        parser.add_argument('url', help='Target URL to scan')
        parser.add_argument('--type', choices=['sql', 'xss', 'comprehensive'], 
                          default='comprehensive', help='Scan type')
        parser.add_argument('--proxy', action='store_true', help='Enable proxy mode')
        parser.add_argument('--threads', type=int, default=10, help='Number of threads')
        parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
        parser.add_argument('--port', type=int, default=8080, help='Proxy port')
        
        try:
            parsed_args = parser.parse_args(args.split())
        except SystemExit:
            return
        
        # Validate URL
        if not self._validate_url(parsed_args.url):
            self.logger.error("[-] Invalid URL format")
            return
        
        # Create scan configuration
        scan_types = self._get_scan_types(parsed_args.type)
        
        config = ScanConfig(
            target_url=parsed_args.url,
            scan_types=scan_types,
            proxy_enabled=parsed_args.proxy,
            proxy_port=parsed_args.port,
            threads=parsed_args.threads,
            timeout=parsed_args.timeout
        )
        
        # Start scan
        self.logger.info(f"[*] Starting {parsed_args.type} scan on {parsed_args.url}")
        
        try:
            results = self.engine.run_scan(config)
            
            if results.get('status') == 'completed':
                self.logger.success("[+] Scan completed successfully")
                self._display_scan_results(results)
            else:
                self.logger.error(f"[-] Scan failed: {results.get('error', 'Unknown error')}")
                
        except Exception as e:
            self.logger.error(f"[-] Scan execution failed: {e}")
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _get_scan_types(self, scan_type: str) -> List[ScanType]:
        """Get scan types based on input"""
        if scan_type == 'sql':
            return [ScanType.SQL_INJECTION]
        elif scan_type == 'xss':
            return [ScanType.XSS]
        elif scan_type == 'comprehensive':
            return [ScanType.SQL_INJECTION, ScanType.XSS, ScanType.DIRECTORY_TRAVERSAL, 
                   ScanType.COMMAND_INJECTION, ScanType.XXE, ScanType.SSRF]
        return []
    
    def _display_scan_results(self, results: Dict[str, Any]):
        """Display scan results in a formatted table"""
        if not results.get('results'):
            self.logger.warning("[!] No scan results to display")
            return
        
        self.logger.section("SCAN RESULTS")
        
        for scan_type, scan_results in results['results'].items():
            if isinstance(scan_results, dict) and scan_results.get('vulnerabilities'):
                self.logger.info(f"[*] {scan_type.upper()} Vulnerabilities Found:")
                
                for vuln in scan_results['vulnerabilities']:
                    self.logger.warning(f"[!] {vuln.get('description', 'Unknown vulnerability')}")
                    self.logger.info(f"    Parameter: {vuln.get('parameter', 'N/A')}")
                    self.logger.info(f"    Payload: {vuln.get('payload', 'N/A')}")
                    self.logger.info(f"    Severity: {vuln.get('severity', 'N/A')}")
                    self.logger.info("")


class ProxyCommand(BaseCommand):
    """Proxy command implementation"""
    
    def execute(self, args: str):
        """Execute proxy command"""
        if not args:
            self.logger.error("[-] Please specify a proxy command")
            self.logger.info("[*] Usage: proxy <start|stop|status|requests|clear>")
            return
        
        command = args.split()[0].lower()
        
        if command == 'start':
            self._start_proxy(args)
        elif command == 'stop':
            self._stop_proxy()
        elif command == 'status':
            self._show_proxy_status()
        elif command == 'requests':
            self._show_intercepted_requests()
        elif command == 'clear':
            self._clear_intercepted_data()
        else:
            self.logger.error(f"[-] Unknown proxy command: {command}")
    
    def _start_proxy(self, args: str):
        """Start proxy server"""
        port = 8080
        if len(args.split()) > 1:
            try:
                port = int(args.split()[1])
            except ValueError:
                self.logger.error("[-] Invalid port number")
                return
        
        if self.engine.start_proxy(port):
            self.logger.success(f"[+] Proxy server started on port {port}")
        else:
            self.logger.error("[-] Failed to start proxy server")
    
    def _stop_proxy(self):
        """Stop proxy server"""
        self.engine.stop_proxy()
        self.logger.success("[+] Proxy server stopped")
    
    def _show_proxy_status(self):
        """Show proxy server status"""
        if self.engine.proxy_server and self.engine.proxy_server.is_running():
            self.logger.success(f"[+] Proxy server is running on port {self.engine.proxy_server.port}")
        else:
            self.logger.warning("[!] Proxy server is not running")
    
    def _show_intercepted_requests(self):
        """Show intercepted requests"""
        if not self.engine.proxy_server:
            self.logger.warning("[!] Proxy server is not running")
            return
        
        requests = self.engine.proxy_server.get_intercepted_requests()
        
        if not requests:
            self.logger.info("[*] No intercepted requests")
            return
        
        self.logger.info(f"[*] Intercepted {len(requests)} requests:")
        
        for i, req in enumerate(requests[:10], 1):  # Show first 10
            self.logger.info(f"  {i}. {req.method} {req.url}")
        
        if len(requests) > 10:
            self.logger.info(f"  ... and {len(requests) - 10} more")
    
    def _clear_intercepted_data(self):
        """Clear intercepted data"""
        if self.engine.proxy_server:
            self.engine.proxy_server.clear_intercepted_data()
            self.logger.success("[+] Intercepted data cleared")
        else:
            self.logger.warning("[!] Proxy server is not running")


class ReportCommand(BaseCommand):
    """Report command implementation"""
    
    def execute(self, args: str):
        """Execute report command"""
        if not args:
            self.logger.error("[-] Please specify a report command")
            self.logger.info("[*] Usage: report <generate|show|export>")
            return
        
        command = args.split()[0].lower()
        
        if command == 'generate':
            self._generate_report(args)
        elif command == 'show':
            self._show_results()
        elif command == 'export':
            self._export_report(args)
        else:
            self.logger.error(f"[-] Unknown report command: {command}")
    
    def _generate_report(self, args: str):
        """Generate security report"""
        filename = None
        if len(args.split()) > 1:
            filename = args.split()[1]
        
        report = self.engine.generate_report(filename)
        
        if report:
            self.logger.success("[+] Report generated successfully")
            if filename:
                self.logger.info(f"[*] Report saved to: {filename}")
        else:
            self.logger.warning("[!] No scan results available for report generation")
    
    def _show_results(self):
        """Show last scan results"""
        results = self.engine.get_scan_results()
        
        if not results:
            self.logger.warning("[!] No scan results available")
            return
        
        self.logger.section("LAST SCAN RESULTS")
        self.logger.info(f"Target: {results.get('target', 'N/A')}")
        self.logger.info(f"Status: {results.get('status', 'N/A')}")
        self.logger.info(f"Duration: {results.get('duration', 0):.2f} seconds")
        
        if results.get('results'):
            total_vulns = 0
            for scan_type, scan_results in results['results'].items():
                if isinstance(scan_results, dict) and scan_results.get('vulnerabilities'):
                    vuln_count = len(scan_results['vulnerabilities'])
                    total_vulns += vuln_count
                    self.logger.info(f"{scan_type.upper()}: {vuln_count} vulnerabilities")
            
            self.logger.info(f"Total Vulnerabilities: {total_vulns}")
    
    def _export_report(self, args: str):
        """Export report in different formats"""
        if len(args.split()) < 2:
            self.logger.error("[-] Please specify export format")
            self.logger.info("[*] Usage: report export <json|html|txt>")
            return
        
        format_type = args.split()[1].lower()
        
        if format_type not in ['json', 'html', 'txt']:
            self.logger.error("[-] Invalid export format. Use: json, html, or txt")
            return
        
        results = self.engine.get_scan_results()
        
        if not results:
            self.logger.warning("[!] No scan results available for export")
            return
        
        filename = f"aresprobe_report.{format_type}"
        
        try:
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
            elif format_type == 'html':
                html_content = self._generate_html_report(results)
                with open(filename, 'w') as f:
                    f.write(html_content)
            elif format_type == 'txt':
                with open(filename, 'w') as f:
                    f.write(self.engine.generate_report())
            
            self.logger.success(f"[+] Report exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to export report: {e}")
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AresProbe Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ background-color: #ffe6e6; padding: 10px; margin: 10px 0; border-radius: 3px; }}
                .info {{ background-color: #e6f3ff; padding: 10px; margin: 10px 0; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>AresProbe Security Report</h1>
                <p>Target: {results.get('target', 'N/A')}</p>
                <p>Status: {results.get('status', 'N/A')}</p>
                <p>Duration: {results.get('duration', 0):.2f} seconds</p>
            </div>
        """
        
        if results.get('results'):
            for scan_type, scan_results in results['results'].items():
                if isinstance(scan_results, dict) and scan_results.get('vulnerabilities'):
                    html += f"<h2>{scan_type.upper()} Vulnerabilities</h2>"
                    for vuln in scan_results['vulnerabilities']:
                        html += f"""
                        <div class="vulnerability">
                            <h3>{vuln.get('description', 'Unknown vulnerability')}</h3>
                            <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                            <p><strong>Payload:</strong> {vuln.get('payload', 'N/A')}</p>
                            <p><strong>Severity:</strong> {vuln.get('severity', 'N/A')}</p>
                        </div>
                        """
        
        html += "</body></html>"
        return html
