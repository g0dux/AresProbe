"""
AresProbe Advanced Security Commands
Commands for new advanced security features
"""

import asyncio
import json
from typing import List, Optional, Dict, Any
from pathlib import Path

from ..core.logger import Logger
from ..core.async_engine import AsyncEngine
from ..core.ai_security_engine import AISecurityEngine
from ..core.security_testing_engines import SecurityTestingEngines
from ..core.advanced_reconnaissance import AdvancedReconnaissance


class AdvancedSecurityCommand:
    """Advanced security testing commands"""
    
    def __init__(self, engine, logger: Logger):
        self.engine = engine
        self.logger = logger
        
        # Initialize advanced engines if available
        self.async_engine = getattr(engine, 'async_engine', None)
        self.ai_security_engine = getattr(engine, 'ai_security_engine', None)
        self.security_testing_engines = getattr(engine, 'security_testing_engines', None)
        self.advanced_reconnaissance = getattr(engine, 'advanced_reconnaissance', None)
    
    def execute(self, args: str):
        """Execute advanced security command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        try:
            if command == 'ai_analyze':
                self._ai_analyze(parts[1:])
            elif command == 'sast':
                self._sast_scan(parts[1:])
            elif command == 'dast':
                self._dast_scan(parts[1:])
            elif command == 'iast':
                self._iast_scan(parts[1:])
            elif command == 'sca':
                self._sca_scan(parts[1:])
            elif command == 'recon':
                self._reconnaissance(parts[1:])
            elif command == 'subdomains':
                self._subdomain_enum(parts[1:])
            elif command == 'ports':
                self._port_scan(parts[1:])
            elif command == 'fingerprint':
                self._technology_fingerprint(parts[1:])
            elif command == 'ssl':
                self._ssl_analysis(parts[1:])
            elif command == 'comprehensive':
                self._comprehensive_scan(parts[1:])
            elif command == 'help':
                self._show_help()
            else:
                self.logger.error(f"[-] Unknown advanced security command: {command}")
                self._show_help()
        
        except Exception as e:
            self.logger.error(f"[-] Error executing advanced security command: {e}")
    
    def _ai_analyze(self, args: List[str]):
        """AI-powered security analysis"""
        if not args:
            self.logger.error("[-] Usage: advanced ai_analyze <url>")
            return
        
        if not self.ai_security_engine:
            self.logger.error("[-] AI Security Engine not available")
            return
        
        if not self.async_engine:
            self.logger.error("[-] Async Engine not available")
            return
        
        url = args[0]
        self.logger.info(f"[*] Starting AI-powered analysis of {url}")
        
        async def run_analysis():
            try:
                result = await self.ai_security_engine.analyze_target(url, self.async_engine)
                
                if result:
                    self.logger.success("[+] AI Analysis completed")
                    self._display_ai_results(result)
                else:
                    self.logger.error("[-] AI Analysis failed")
            
            except Exception as e:
                self.logger.error(f"[-] AI Analysis error: {e}")
        
        asyncio.run(run_analysis())
    
    def _sast_scan(self, args: List[str]):
        """Static Application Security Testing"""
        if not args:
            self.logger.error("[-] Usage: advanced sast <directory_path>")
            return
        
        if not self.security_testing_engines:
            self.logger.error("[-] Security Testing Engines not available")
            return
        
        directory = args[0]
        self.logger.info(f"[*] Starting SAST scan of {directory}")
        
        async def run_sast():
            try:
                results = await self.security_testing_engines.run_comprehensive_scan(
                    directory, ['sast']
                )
                
                if 'sast' in results:
                    findings = results['sast']
                    self.logger.success(f"[+] SAST scan completed: {len(findings)} findings")
                    self._display_sast_results(findings)
                else:
                    self.logger.error("[-] SAST scan failed")
            
            except Exception as e:
                self.logger.error(f"[-] SAST scan error: {e}")
        
        asyncio.run(run_sast())
    
    def _dast_scan(self, args: List[str]):
        """Dynamic Application Security Testing"""
        if not args:
            self.logger.error("[-] Usage: advanced dast <url>")
            return
        
        if not self.security_testing_engines:
            self.logger.error("[-] Security Testing Engines not available")
            return
        
        url = args[0]
        self.logger.info(f"[*] Starting DAST scan of {url}")
        
        async def run_dast():
            try:
                results = await self.security_testing_engines.run_comprehensive_scan(
                    url, ['dast']
                )
                
                if 'dast' in results:
                    findings = results['dast']
                    self.logger.success(f"[+] DAST scan completed: {len(findings)} findings")
                    self._display_dast_results(findings)
                else:
                    self.logger.error("[-] DAST scan failed")
            
            except Exception as e:
                self.logger.error(f"[-] DAST scan error: {e}")
        
        asyncio.run(run_dast())
    
    def _iast_scan(self, args: List[str]):
        """Interactive Application Security Testing"""
        if not args:
            self.logger.error("[-] Usage: advanced iast <url>")
            return
        
        if not self.security_testing_engines:
            self.logger.error("[-] Security Testing Engines not available")
            return
        
        url = args[0]
        self.logger.info(f"[*] Starting IAST analysis of {url}")
        
        async def run_iast():
            try:
                results = await self.security_testing_engines.run_comprehensive_scan(
                    url, ['iast']
                )
                
                if 'iast' in results:
                    findings = results['iast']
                    self.logger.success(f"[+] IAST analysis completed: {len(findings)} findings")
                    self._display_iast_results(findings)
                else:
                    self.logger.error("[-] IAST analysis failed")
            
            except Exception as e:
                self.logger.error(f"[-] IAST analysis error: {e}")
        
        asyncio.run(run_iast())
    
    def _sca_scan(self, args: List[str]):
        """Software Composition Analysis"""
        if not args:
            self.logger.error("[-] Usage: advanced sca <project_path>")
            return
        
        if not self.security_testing_engines:
            self.logger.error("[-] Security Testing Engines not available")
            return
        
        project_path = args[0]
        self.logger.info(f"[*] Starting SCA scan of {project_path}")
        
        async def run_sca():
            try:
                results = await self.security_testing_engines.run_comprehensive_scan(
                    project_path, ['sca']
                )
                
                if 'sca' in results:
                    findings = results['sca']
                    self.logger.success(f"[+] SCA scan completed: {len(findings)} findings")
                    self._display_sca_results(findings)
                else:
                    self.logger.error("[-] SCA scan failed")
            
            except Exception as e:
                self.logger.error(f"[-] SCA scan error: {e}")
        
        asyncio.run(run_sca())
    
    def _reconnaissance(self, args: List[str]):
        """Advanced reconnaissance"""
        if not args:
            self.logger.error("[-] Usage: advanced recon <target>")
            return
        
        if not self.advanced_reconnaissance:
            self.logger.error("[-] Advanced Reconnaissance not available")
            return
        
        target = args[0]
        self.logger.info(f"[*] Starting comprehensive reconnaissance of {target}")
        
        async def run_recon():
            try:
                results = await self.advanced_reconnaissance.comprehensive_reconnaissance(target)
                
                self.logger.success("[+] Reconnaissance completed")
                self._display_recon_results(results)
            
            except Exception as e:
                self.logger.error(f"[-] Reconnaissance error: {e}")
        
        asyncio.run(run_recon())
    
    def _subdomain_enum(self, args: List[str]):
        """Subdomain enumeration"""
        if not args:
            self.logger.error("[-] Usage: advanced subdomains <domain> [wordlist_size]")
            return
        
        if not self.advanced_reconnaissance:
            self.logger.error("[-] Advanced Reconnaissance not available")
            return
        
        domain = args[0]
        wordlist_size = args[1] if len(args) > 1 else 'common'
        
        self.logger.info(f"[*] Starting subdomain enumeration for {domain}")
        
        async def run_subdomains():
            try:
                results = await self.advanced_reconnaissance.subdomain_enumerator.enumerate_subdomains(
                    domain, wordlist_size=wordlist_size
                )
                
                self.logger.success(f"[+] Subdomain enumeration completed: {len(results)} subdomains found")
                self._display_subdomain_results(results)
            
            except Exception as e:
                self.logger.error(f"[-] Subdomain enumeration error: {e}")
        
        asyncio.run(run_subdomains())
    
    def _port_scan(self, args: List[str]):
        """Port scanning"""
        if not args:
            self.logger.error("[-] Usage: advanced ports <host> [scan_type]")
            return
        
        if not self.advanced_reconnaissance:
            self.logger.error("[-] Advanced Reconnaissance not available")
            return
        
        host = args[0]
        scan_type = args[1] if len(args) > 1 else 'tcp_connect'
        
        self.logger.info(f"[*] Starting port scan of {host}")
        
        async def run_port_scan():
            try:
                results = await self.advanced_reconnaissance.port_scanner.scan_host(
                    host, scan_type=scan_type
                )
                
                open_ports = [r for r in results if r.state == 'open']
                self.logger.success(f"[+] Port scan completed: {len(open_ports)} open ports")
                self._display_port_results(results)
            
            except Exception as e:
                self.logger.error(f"[-] Port scan error: {e}")
        
        asyncio.run(run_port_scan())
    
    def _technology_fingerprint(self, args: List[str]):
        """Technology fingerprinting"""
        if not args:
            self.logger.error("[-] Usage: advanced fingerprint <url>")
            return
        
        if not self.advanced_reconnaissance:
            self.logger.error("[-] Advanced Reconnaissance not available")
            return
        
        url = args[0]
        self.logger.info(f"[*] Starting technology fingerprinting for {url}")
        
        async def run_fingerprint():
            try:
                results = await self.advanced_reconnaissance.technology_fingerprinter.fingerprint_target(url)
                
                self.logger.success(f"[+] Technology fingerprinting completed: {len(results)} technologies detected")
                self._display_technology_results(results)
            
            except Exception as e:
                self.logger.error(f"[-] Technology fingerprinting error: {e}")
        
        asyncio.run(run_fingerprint())
    
    def _ssl_analysis(self, args: List[str]):
        """SSL/TLS analysis"""
        if not args:
            self.logger.error("[-] Usage: advanced ssl <host> [port]")
            return
        
        if not self.advanced_reconnaissance:
            self.logger.error("[-] Advanced Reconnaissance not available")
            return
        
        host = args[0]
        port = int(args[1]) if len(args) > 1 else 443
        
        self.logger.info(f"[*] Starting SSL analysis for {host}:{port}")
        
        async def run_ssl_analysis():
            try:
                result = await self.advanced_reconnaissance.ssl_analyzer.analyze_ssl(host, port)
                
                self.logger.success("[+] SSL analysis completed")
                self._display_ssl_results(result)
            
            except Exception as e:
                self.logger.error(f"[-] SSL analysis error: {e}")
        
        asyncio.run(run_ssl_analysis())
    
    def _comprehensive_scan(self, args: List[str]):
        """Comprehensive security scan"""
        if not args:
            self.logger.error("[-] Usage: advanced comprehensive <target> [scan_types]")
            return
        
        target = args[0]
        scan_types = args[1:] if len(args) > 1 else ['sast', 'dast', 'sca']
        
        self.logger.info(f"[*] Starting comprehensive security scan of {target}")
        
        async def run_comprehensive():
            try:
                if self.security_testing_engines:
                    results = await self.security_testing_engines.run_comprehensive_scan(
                        target, scan_types
                    )
                    
                    total_findings = sum(len(findings) for findings in results.values())
                    self.logger.success(f"[+] Comprehensive scan completed: {total_findings} total findings")
                    
                    # Display results for each scan type
                    for scan_type, findings in results.items():
                        if findings:
                            self.logger.info(f"[*] {scan_type.upper()}: {len(findings)} findings")
                else:
                    self.logger.error("[-] Security Testing Engines not available")
            
            except Exception as e:
                self.logger.error(f"[-] Comprehensive scan error: {e}")
        
        asyncio.run(run_comprehensive())
    
    def _display_ai_results(self, results: Dict[str, Any]):
        """Display AI analysis results"""
        self.logger.info(f"[*] Target: {results.get('target_url', 'N/A')}")
        
        predictions = results.get('predictions', {})
        for vuln_type, prediction in predictions.items():
            confidence = prediction.get('confidence', 0)
            risk_score = prediction.get('risk_score', 0)
            self.logger.info(f"[*] {vuln_type.upper()}: Confidence={confidence:.2f}, Risk={risk_score:.2f}")
        
        adaptive_payloads = results.get('adaptive_payloads', {})
        for vuln_type, payloads in adaptive_payloads.items():
            if payloads:
                self.logger.info(f"[*] {vuln_type.upper()} Payloads: {len(payloads)} generated")
    
    def _display_sast_results(self, findings: List[Any]):
        """Display SAST results"""
        if not findings:
            self.logger.info("[*] No SAST findings")
            return
        
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.logger.info("[*] SAST Findings Summary:")
        for severity, count in severity_counts.items():
            self.logger.info(f"  {severity.upper()}: {count}")
        
        # Show first few findings
        for i, finding in enumerate(findings[:5]):
            self.logger.info(f"[*] {finding.title} ({finding.severity}) - {finding.file_path}:{finding.line_number}")
    
    def _display_dast_results(self, findings: List[Any]):
        """Display DAST results"""
        if not findings:
            self.logger.info("[*] No DAST findings")
            return
        
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.logger.info("[*] DAST Findings Summary:")
        for severity, count in severity_counts.items():
            self.logger.info(f"  {severity.upper()}: {count}")
        
        # Show first few findings
        for i, finding in enumerate(findings[:5]):
            self.logger.info(f"[*] {finding.title} ({finding.severity}) - {finding.url}")
    
    def _display_iast_results(self, findings: List[Any]):
        """Display IAST results"""
        if not findings:
            self.logger.info("[*] No IAST findings")
            return
        
        self.logger.info(f"[*] IAST Findings: {len(findings)}")
        for finding in findings[:5]:
            self.logger.info(f"[*] {finding.title} ({finding.severity})")
    
    def _display_sca_results(self, findings: List[Any]):
        """Display SCA results"""
        if not findings:
            self.logger.info("[*] No SCA findings")
            return
        
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.logger.info("[*] SCA Findings Summary:")
        for severity, count in severity_counts.items():
            self.logger.info(f"  {severity.upper()}: {count}")
        
        # Show first few findings
        for i, finding in enumerate(findings[:5]):
            self.logger.info(f"[*] {finding.title} ({finding.severity})")
    
    def _display_recon_results(self, results: Dict[str, Any]):
        """Display reconnaissance results"""
        self.logger.info("[*] Reconnaissance Results:")
        self.logger.info(f"  Subdomains: {len(results.get('subdomains', []))}")
        self.logger.info(f"  Open Ports: {len(results.get('ports', []))}")
        self.logger.info(f"  Technologies: {len(results.get('technologies', []))}")
        
        if results.get('ssl_info'):
            ssl_info = results['ssl_info']
            self.logger.info(f"  SSL Grade: {ssl_info.get('grade', 'N/A')}")
            self.logger.info(f"  SSL Score: {ssl_info.get('score', 'N/A')}")
    
    def _display_subdomain_results(self, results: List[Any]):
        """Display subdomain enumeration results"""
        if not results:
            self.logger.info("[*] No subdomains found")
            return
        
        active_subdomains = [r for r in results if r.status == 'active']
        self.logger.info(f"[*] Active Subdomains: {len(active_subdomains)}")
        
        for result in active_subdomains[:10]:
            self.logger.info(f"  {result.subdomain} ({result.ip_address})")
    
    def _display_port_results(self, results: List[Any]):
        """Display port scan results"""
        open_ports = [r for r in results if r.state == 'open']
        if not open_ports:
            self.logger.info("[*] No open ports found")
            return
        
        self.logger.info(f"[*] Open Ports: {len(open_ports)}")
        for port in open_ports:
            service_info = f" - {port.service}" if port.service else ""
            version_info = f" ({port.version})" if port.version else ""
            self.logger.info(f"  {port.port}/tcp{service_info}{version_info}")
    
    def _display_technology_results(self, results: List[Any]):
        """Display technology fingerprinting results"""
        if not results:
            self.logger.info("[*] No technologies detected")
            return
        
        categories = {}
        for tech in results:
            category = tech.category
            if category not in categories:
                categories[category] = []
            categories[category].append(tech)
        
        for category, techs in categories.items():
            self.logger.info(f"[*] {category.upper()}:")
            for tech in techs:
                version_info = f" {tech.version}" if tech.version else ""
                self.logger.info(f"  {tech.name}{version_info} (confidence: {tech.confidence:.2f})")
    
    def _display_ssl_results(self, result: Any):
        """Display SSL analysis results"""
        self.logger.info(f"[*] SSL Grade: {result.grade}")
        self.logger.info(f"[*] SSL Score: {result.score}")
        self.logger.info(f"[*] Protocol: {result.version}")
        self.logger.info(f"[*] Cipher Suite: {result.cipher_suite}")
        
        if result.vulnerabilities:
            self.logger.info(f"[*] Vulnerabilities: {len(result.vulnerabilities)}")
            for vuln in result.vulnerabilities[:5]:
                self.logger.info(f"  {vuln}")
        
        cert_info = result.certificate_info
        if cert_info:
            self.logger.info(f"[*] Certificate Expires: {cert_info.get('not_after', 'N/A')}")
            self.logger.info(f"[*] Days Until Expiry: {cert_info.get('days_until_expiry', 'N/A')}")
    
    def _show_help(self):
        """Show advanced security commands help"""
        help_text = """
[bold green]ADVANCED SECURITY COMMANDS:[/bold green]

[bold white]AI-Powered Analysis:[/bold white]
[green]•[/green] [bold white]ai_analyze <url>[/bold white] - [green]AI-powered vulnerability prediction and analysis[/green]

[bold white]Security Testing:[/bold white]
[green]•[/green] [bold white]sast <directory>[/bold white] - [green]Static Application Security Testing[/green]
[green]•[/green] [bold white]dast <url>[/bold white] - [green]Dynamic Application Security Testing[/green]
[green]•[/green] [bold white]iast <url>[/bold white] - [green]Interactive Application Security Testing[/green]
[green]•[/green] [bold white]sca <project_path>[/bold white] - [green]Software Composition Analysis[/green]

[bold white]Reconnaissance:[/bold white]
[green]•[/green] [bold white]recon <target>[/bold white] - [green]Comprehensive reconnaissance[/green]
[green]•[/green] [bold white]subdomains <domain> [wordlist_size][/bold white] - [green]Subdomain enumeration[/green]
[green]•[/green] [bold white]ports <host> [scan_type][/bold white] - [green]Port scanning[/green]
[green]•[/green] [bold white]fingerprint <url>[/bold white] - [green]Technology fingerprinting[/green]
[green]•[/green] [bold white]ssl <host> [port][/bold white] - [green]SSL/TLS analysis[/green]

[bold white]Comprehensive Testing:[/bold white]
[green]•[/green] [bold white]comprehensive <target> [scan_types][/bold white] - [green]Multi-engine security testing[/green]

[bold white]Examples:[/bold white]
[green]advanced ai_analyze http://example.com[/green]
[green]advanced sast /path/to/project[/green]
[green]advanced dast http://example.com[/green]
[green]advanced recon example.com[/green]
[green]advanced subdomains example.com extended[/green]
[green]advanced comprehensive http://example.com sast dast[/green]

[bold red]Note: Advanced features require additional dependencies[/bold red]
        """
        
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel(help_text, border_style="green", title="[bold green]ADVANCED SECURITY HELP[/bold green]"))
