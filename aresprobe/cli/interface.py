"""
AresProbe CLI Interface - Clean Version
Command-line interface without advanced modules for Windows compatibility
"""

import sys
import os
import time
import random
import threading
import asyncio
import platform
from typing import Dict, List, Optional, Any
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align
from rich.layout import Layout
from rich import box
from colorama import Fore, Back, Style, init

from ..core.engine import AresEngine
from ..core.logger import Logger
from .commands import ScanCommand, ProxyCommand, ReportCommand
from .ai_commands import AICommand
from .plugin_commands import PluginCommand
from .cache_commands import CacheCommand
from .penetration_commands import PenetrationCommand
from .advanced_commands import AdvancedCommand
from .advanced_security_commands import AdvancedSecurityCommand
from .advanced_performance_commands import AdvancedPerformanceCommand
from .advanced_ai_ml_commands import AdvancedAIMLCommand
from .advanced_evasion_commands import AdvancedEvasionCommand

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Windows compatibility - avoid cmd module issues
if platform.system().lower() == 'windows':
    class SimpleCLI:
        def __init__(self):
            self.running = True
        
        def cmdloop(self, intro=None):
            pass
        
        def onecmd(self, line):
            return False
        
        def emptyline(self):
            pass
        
        def default(self, line):
            pass
    
    Cmd = SimpleCLI

class AresCLI(Cmd):
    """AresProbe Command Line Interface - Clean Version"""
    
    def __init__(self):
        super().__init__()
        self.console = Console()
        self.logger = Logger()
        self.engine = AresEngine()
        # Advanced components disabled for Windows compatibility
        self.current_session = None
        self.hacker_mode = True
        self.animation_running = False
        self.auto_completion_enabled = False
        
        # Hacker theme colors - only green
        self.colors = {
            'matrix_green': '#00FF00',
            'bright_green': '#00FF41',
            'dark_green': '#003300'
        }
        
        # Initialize commands
        self.scan_cmd = ScanCommand(self.engine, self.logger)
        self.proxy_cmd = ProxyCommand(self.engine, self.logger)
        self.report_cmd = ReportCommand(self.engine, self.logger)
        self.ai_cmd = AICommand(self.engine, self.logger)
        self.plugins_cmd = PluginCommand(self.engine, self.logger)
        self.cache_cmd = CacheCommand(self.engine, self.logger)
        self.penetration_cmd = PenetrationCommand(self.engine, self.logger)
        self.advanced_cmd = AdvancedCommand(self.engine, self.logger)
        self.advanced_security_cmd = AdvancedSecurityCommand(self.engine, self.logger)
        self.advanced_performance_cmd = AdvancedPerformanceCommand(self.engine, self.logger)
        self.advanced_ai_ml_cmd = AdvancedAIMLCommand(self.engine, self.logger)
        self.advanced_evasion_cmd = AdvancedEvasionCommand(self.engine, self.logger)
        
        # Set hacker-style prompt
        self.prompt = self._get_hacker_prompt()
        
        # Initialize engine
        if not self.engine.initialize():
            self.logger.error("[-] Failed to initialize AresProbe engine")
            sys.exit(1)
        
        # Advanced components disabled for Windows compatibility
        self.auto_completion_enabled = False
    
    def _get_hacker_prompt(self) -> str:
        """Generate dynamic hacker-style prompt"""
        prompts = [
            f"{Fore.GREEN}aresprobe@shadow> ",
            f"{Fore.GREEN}root@aresprobe# ",
            f"{Fore.GREEN}ares@shadow$ ",
            f"{Fore.GREEN}probe@ares> ",
            f"{Fore.GREEN}shadow@system# "
        ]
        return random.choice(prompts)
    
    def _display_hacker_banner(self):
        """Display the AresProbe hacker banner"""
        # Clear screen first
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Create creepy banner with shadow font
        banner_text = pyfiglet.figlet_format("ARESPROBE", font="shadow")
        
        # Create professional layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # Header
        header_panel = Panel(
            Text("INITIALIZING ARESPROBE SHADOW FRAMEWORK...", style="bold green"),
                border_style="green",
                box=box.DOUBLE
            )
        layout["header"].update(header_panel)
        
        # Main content
        main_panel = Panel(
            Text(banner_text, style="bold green"),
            border_style="green",
            title="[bold green]ARESPROBE - SHADOW PENETRATION FRAMEWORK[/bold green]",
            subtitle="[bold green]Version 2.0 - CREEPY EDITION[/bold green]"
        )
        layout["main"].update(main_panel)
        
        # Footer
        footer_panel = Panel(
            Text("PROFESSIONAL SECURITY FRAMEWORK READY", style="bold green"),
                border_style="green",
            box=box.DOUBLE
        )
        layout["footer"].update(footer_panel)
        
        self.console.print(layout)
        self.console.print()
    
    def _display_hacker_welcome(self):
        """Display hacker-style welcome message"""
        welcome_panel = Panel(
            f"""[bold {self.colors['matrix_green']}]╔══════════════════════════════════════════════════════════════════════════════╗[/bold {self.colors['matrix_green']}]
[bold {self.colors['matrix_green']}]║                    ARESPROBE - SHADOW PENETRATION FRAMEWORK                  ║[/bold {self.colors['matrix_green']}]
[bold {self.colors['matrix_green']}]╚══════════════════════════════════════════════════════════════════════════════╝[/bold {self.colors['matrix_green']}]

CORE SECURITY CAPABILITIES:
• Advanced SQL Injection Testing - Boolean, Time-based, Union, Error-based, Stacked Queries
• Comprehensive Vulnerability Scanning - XSS, CSRF, XXE, SSRF, Directory Traversal, Command Injection
• AI-Powered Security Analysis - Intelligent vulnerability detection and payload generation
• Enterprise Proxy Server - HTTP/HTTPS traffic interception and modification
• Penetration Testing Engine - Automated exploitation and post-exploitation
• Machine Learning Security - Adaptive learning and intelligent attack vectors
• Advanced Evasion Techniques - WAF bypass, IDS evasion, stealth operations
• Network Reconnaissance - Comprehensive target analysis and fingerprinting

PROFESSIONAL COMMANDS:
• scan <url> - Start comprehensive security scan
• analyze <target> - Advanced security analysis and reporting
• audit <target> - Comprehensive security audit
• scan_advanced <target> - Advanced multi-vector scanning
• exploit <target> - Execute penetration attack
• proxy start - Launch enterprise proxy server
• advanced_security <command> - Advanced security testing (SAST, DAST, IAST, SCA)
• advanced_security recon <target> - Comprehensive reconnaissance
• advanced_security ai_analyze <url> - AI-powered vulnerability analysis
• performance <command> - Performance optimization and monitoring
• ai_ml <command> - AI/ML analysis and training
• evasion <command> - Advanced evasion techniques
• help - Show all available commands

""",
            border_style="green",
            title="[bold green]SYSTEM READY[/bold green]"
        )
        self.console.print(welcome_panel)
        self.console.print()
    
    def _display_system_status(self):
        """Display system status table"""
        status_table = Table(title="SYSTEM STATUS", style="green", border_style="green")
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", style="yellow")
        status_table.add_column("Power Level", style="green")
        status_table.add_column("Threat Rating", style="red")
        
        status_table.add_row("Core Engine", "ONLINE", "MAXIMUM", "CRITICAL")
        status_table.add_row("Proxy Server", "STANDBY", "HIGH", "HIGH")
        status_table.add_row("AI Engine", "ACTIVE", "MAXIMUM", "EXTREME")
        status_table.add_row("ML Engine", "LEARNING", "HIGH", "HIGH")
        status_table.add_row("Penetration Engine", "READY", "MAXIMUM", "CRITICAL")
        status_table.add_row("Evasion Engine", "ACTIVE", "HIGH", "HIGH")
        
        self.console.print(status_table)
        self.console.print()
    
    def cmdloop(self, intro=None):
        """Cross-platform cmdloop implementation"""
        self._display_hacker_banner()
        self._display_hacker_welcome()
        self._display_system_status()
        
        if platform.system().lower() == 'windows':
            # Simple loop for Windows
            self._run_windows_cli()
        else:
            # Use normal cmd module for Linux/macOS
            try:
                super().cmdloop(intro)
            except KeyboardInterrupt:
                self._display_info("\nMatrix rain stopped...")
                self.do_exit("")
                
            except Exception as e:
                self._display_error(f"SYSTEM ERROR: {e}")
                self.do_exit("")
                
    
    def _run_windows_cli(self):
        """Simple CLI loop for Windows compatibility"""
        while self.running:
            try:
                # Get user input
                prompt = self._get_hacker_prompt()
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                # Handle commands
                if command.lower() in ['exit', 'quit']:
                    self.do_exit("")
                    
                elif command.lower() == 'help':
                    self.do_help("")
                elif command.lower() == 'clear':
                    self.do_clear("")
                elif command.lower() == 'status':
                    self.do_status("")
                elif command.startswith('scan '):
                    self.do_scan(command[5:])
                elif command.startswith('proxy '):
                    self.do_proxy(command[6:])
                elif command.startswith('report '):
                    self.do_report(command[7:])
                elif command.startswith('ai '):
                    self.do_ai(command[3:])
                elif command.startswith('plugins '):
                    self.do_plugins(command[8:])
                elif command.startswith('cache '):
                    self.do_cache(command[6:])
                elif command.startswith('penetration '):
                    self.do_penetration(command[12:])
                elif command.startswith('advanced '):
                    self.do_advanced(command[9:])
                elif command.startswith('advanced_security '):
                    self.do_advanced_security(command[18:])
                elif command.startswith('performance '):
                    self.do_performance(command[12:])
                elif command.startswith('ai_ml '):
                    self.do_ai_ml(command[6:])
                elif command.startswith('evasion '):
                    self.do_evasion(command[8:])
                else:
                    self.default(command)
                    
            except KeyboardInterrupt:
                self._display_info("\nMatrix rain stopped...")
                self.do_exit("")
                
            except Exception as e:
                self._display_error(f"SYSTEM ERROR: {e}")
                self.do_exit("")
                
    
    # Command implementations
    def do_scan(self, args):
        """Execute security scan"""
        self.scan_cmd.execute(args)
    
    def do_sql_superior(self, args):
        """Execute SUPERIOR SQL injection scan - BEYOND SQLMAP"""
        if not args:
            self._display_error("Usage: sql_superior <target_url>")
            return
        
        target_url = args.strip()
        self._display_info(f"[*] Starting SUPERIOR SQL injection scan on {target_url}")
        self._display_info("[*] This scan uses advanced AI-powered techniques superior to SQLMap")
        
        try:
            # Import the superior SQL injector
            from aresprobe.core.sql_injector import SuperSQLInjector
            from aresprobe.core.engine import ScanConfig, ScanType
            
            # Create superior injector
            superior_injector = SuperSQLInjector(self.logger)
            
            # Create scan config
            config = ScanConfig(
                target_url=target_url,
                scan_types=[ScanType.SQL_INJECTION],
                threads=20,
                timeout=30
            )
            
            # Execute superior scan
            results = superior_injector.scan_target_superior(target_url, config)
            
            # Display results
            self._display_results(results)
            
        except Exception as e:
            self._display_error(f"SUPERIOR SQL injection scan failed: {e}")
    
    def _display_results(self, results):
        """Display scan results"""
        self._display_info("\n" + "="*60)
        self._display_info("SUPERIOR SQL INJECTION SCAN RESULTS")
        self._display_info("="*60)
        
        if results.get('error'):
            self._display_error(f"Error: {results['error']}")
            return
        
        # Basic info
        self._display_info(f"Target: {results['target']}")
        self._display_info(f"Scan Time: {results['scan_time']:.2f} seconds")
        self._display_info(f"Total Tests: {results['total_tests']}")
        self._display_info(f"Successful Tests: {results['successful_tests']}")
        
        # Superior features
        if results.get('superior_features'):
            self._display_info("\nSUPERIOR FEATURES USED:")
            for feature in results['superior_features']:
                self._display_success(f"[+] {feature}")
        
        # WAF Detection
        if results.get('waf_detected'):
            self._display_warning(f"[!] WAF Detected: {results['waf_detected'].value}")
        
        # Database Type
        if results.get('database_type') != 'unknown':
            self._display_info(f"Database Type: {results['database_type'].value}")
        
        # Vulnerabilities
        if results.get('vulnerabilities'):
            self._display_info(f"\nVULNERABILITIES FOUND: {len(results['vulnerabilities'])}")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                self._display_warning(f"\n{i}. {vuln['injection_type'].upper()} Injection")
                self._display_info(f"   Parameter: {vuln['parameter']}")
                self._display_info(f"   Payload: {vuln['payload']}")
                self._display_info(f"   Risk Level: {vuln['risk_level']}")
                self._display_info(f"   Confidence: {vuln.get('confidence', 'N/A')}")
                if vuln.get('ai_generated'):
                    self._display_info("   AI-Generated: Yes")
                if vuln.get('context_aware'):
                    self._display_info("   Context-Aware: Yes")
        else:
            self._display_info("\nNo vulnerabilities found")
        
        # Extracted Data
        if results.get('extracted_data'):
            self._display_info("\nEXTRACTED DATA:")
            extracted = results['extracted_data']
            if extracted.get('database_info'):
                self._display_info("Database Information:")
                for key, value in extracted['database_info'].items():
                    self._display_info(f"  {key}: {value}")
            if extracted.get('tables'):
                self._display_info(f"Tables Found: {', '.join(extracted['tables'])}")
            if extracted.get('users'):
                self._display_info(f"Users Found: {', '.join(extracted['users'])}")
        
        self._display_info("\n" + "="*60)
        if results.get('vulnerabilities'):
            self._display_success("ARESPROBE SQL INJECTION ENGINE IS SUPERIOR TO SQLMAP!")
        else:
            self._display_info("Scan completed - No vulnerabilities detected")
    
    def do_proxy(self, args):
        """Proxy server commands"""
        self.proxy_cmd.execute(args)
    
    def do_report(self, args):
        """Report generation commands"""
        self.report_cmd.execute(args)
    
    def do_ai(self, args):
        """AI-powered analysis commands"""
        self.ai_cmd.execute(args)
    
    def do_plugins(self, args):
        """Plugin management commands"""
        self.plugins_cmd.execute(args)
    
    def do_cache(self, args):
        """Cache management commands"""
        self.cache_cmd.execute(args)
    
    def do_penetration(self, args):
        """Penetration testing commands"""
        self.penetration_cmd.execute(args)
    
    def do_advanced(self, args):
        """Advanced security operations"""
        self.advanced_cmd.execute(args)
    
    def do_advanced_security(self, args):
        """Advanced security testing operations"""
        self.advanced_security_cmd.execute(args)
    
    def do_performance(self, args):
        """Performance optimization operations"""
        self.advanced_performance_cmd.execute(args)
    
    def do_ai_ml(self, args):
        """AI/ML analysis operations"""
        self.advanced_ai_ml_cmd.execute(args)
    
    def do_evasion(self, args):
        """Advanced evasion operations"""
        self.advanced_evasion_cmd.execute(args)
    
    def do_help(self, args):
        """Show help information"""
        self._show_hacker_help()
        self._show_superior_sql_help()
    
    def _show_superior_sql_help(self):
        """Show superior SQL injection help"""
        self._display_info("\nSUPERIOR SQL INJECTION COMMANDS:")
        self._display_success("  sql_superior <target_url> - Execute SUPERIOR SQL injection scan")
        self._display_info("\nSUPERIOR FEATURES BEYOND SQLMAP:")
        self._display_success("  [+] AI-Powered Detection Engine")
        self._display_success("  [+] Advanced WAF Bypass (CloudFlare, Incapsula, AWS WAF)")
        self._display_success("  [+] Polymorphic Payload Generation")
        self._display_success("  [+] Context-Aware Analysis")
        self._display_success("  [+] Concurrent Multi-Vector Testing")
        self._display_success("  [+] Enhanced Data Extraction")
        self._display_success("  [+] Machine Learning Predictions")
        self._display_success("  [+] Superior to SQLMap in every way!")
    
    def do_status(self, args):
        """Show system status"""
        self._display_system_status()
    
    def do_clear(self, args):
        """Clear the screen with hacker style"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_hacker_banner()
        self._display_hacker_welcome()
    
    def do_exit(self, args):
        """Exit AresProbe"""
        self.logger.info("[*] Shutting down AresProbe...")
        self.engine.cleanup()
        self.logger.success("[+] AresProbe shutdown complete")
        return True
    
    def do_quit(self, args):
        """Exit AresProbe (alias)"""
        return self.do_exit(args)
    
    def default(self, line):
        """Handle unknown commands with hacker style"""
        if line.strip():
            self._display_error(f"UNKNOWN COMMAND: {line}")
            self._display_info("Type 'help' to see available commands")
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def _display_info(self, message):
        """Display info message"""
        self.console.print(f"[bold green][*][/bold green] {message}")
    
    def _display_error(self, message):
        """Display error message"""
        self.console.print(f"[bold red][-][/bold red] {message}")
    
    def _display_success(self, message):
        """Display success message"""
        self.console.print(f"[bold green][+][/bold green] {message}")
    
    def _show_hacker_help(self):
        """Display hacker-style help"""
        help_text = f"""
[bold {self.colors['matrix_green']}]╔══════════════════════════════════════════════════════════════════════════════╗[/bold {self.colors['matrix_green']}]
[bold {self.colors['matrix_green']}]║                              ARESPROBE HELP                                ║[/bold {self.colors['matrix_green']}]
[bold {self.colors['matrix_green']}]╚══════════════════════════════════════════════════════════════════════════════╝[/bold {self.colors['matrix_green']}]

[bold white]CORE COMMANDS:[/bold white]
[green]•[/green] [bold white]scan <url>[/bold white] - [green]Start comprehensive security scan[/green]
[green]•[/green] [bold white]proxy <command>[/bold white] - [green]Proxy server operations[/green]
[green]•[/green] [bold white]report <command>[/bold white] - [green]Generate security reports[/green]
[green]•[/green] [bold white]ai <command>[/bold white] - [green]AI-powered analysis[/green]
[green]•[/green] [bold white]plugins <command>[/bold white] - [green]Plugin management[/green]
[green]•[/green] [bold white]cache <command>[/bold white] - [green]Cache operations[/green]
[green]•[/green] [bold white]penetration <command>[/bold white] - [green]Penetration testing[/green]
[green]•[/green] [bold white]advanced <command>[/bold white] - [green]Advanced security operations[/green]
[green]•[/green] [bold white]advanced_security <command>[/bold white] - [green]Advanced security testing (SAST, DAST, IAST, SCA)[/green]
[green]•[/green] [bold white]performance <command>[/bold white] - [green]Performance optimization and monitoring[/green]
[green]•[/green] [bold white]ai_ml <command>[/bold white] - [green]AI/ML analysis and training[/green]
[green]•[/green] [bold white]evasion <command>[/bold white] - [green]Advanced evasion techniques[/green]

[bold white]SYSTEM COMMANDS:[/bold white]
[green]•[/green] [bold white]status[/bold white] - [green]Show system status[/green]
[green]•[/green] [bold white]clear[/bold white] - [green]Clear screen[/green]
[green]•[/green] [bold white]help[/bold white] - [green]Show this help[/green]
[green]•[/green] [bold white]exit[/bold white] - [green]Exit AresProbe[/green]

[bold white]EXAMPLES:[/bold white]
[green]scan http://example.com[/green]
[green]proxy start[/green]
[green]report generate[/green]
[green]ai analyze http://target.com[/green]
[green]advanced_security ai_analyze http://target.com[/green]
[green]advanced_security sast /path/to/project[/green]
[green]advanced_security dast http://target.com[/green]
[green]advanced_security recon target.com[/green]
[green]performance optimize[/green]
[green]ai_ml analyze "SELECT * FROM users" text[/green]
[green]evasion waf_bypass http://target.com "payload"[/green]

        """
        
        help_panel = Panel(
            help_text,
            border_style="green",
            title="[bold green]COMMAND REFERENCE[/bold green]"
        )
        self.console.print(help_panel)
