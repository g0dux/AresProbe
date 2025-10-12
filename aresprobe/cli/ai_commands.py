"""
AresProbe AI Commands
AI-powered analysis and payload generation commands
"""

import sys
from typing import List, Optional
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core.logger import Logger


class AICommand:
    """AI-related commands for AresProbe CLI"""
    
    def __init__(self, engine, logger: Logger = None):
        self.engine = engine
        self.logger = logger or Logger()
        self.console = Console()
    
    def execute(self, args: str):
        """Execute AI command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        if command == "analyze":
            self._analyze_url(parts[1] if len(parts) > 1 else None)
        elif command == "payloads":
            self._generate_payloads(parts[1] if len(parts) > 1 else None)
        elif command == "status":
            self._show_status()
        else:
            self.logger.error(f"[-] Unknown AI command: {command}")
            self._show_help()
    
    def _analyze_url(self, url: Optional[str]):
        """Analyze URL with AI"""
        if not url:
            self.logger.error("[-] Please provide a URL to analyze")
            return
        
        try:
            self.logger.info(f"[*] Analyzing URL with AI: {url}")
            
            # Make request to get response
            response = requests.get(url, timeout=30)
            
            # Get AI analysis
            analysis_results = self.engine.get_ai_analysis(
                response.text, 
                dict(response.headers), 
                url, 
                "GET"
            )
            
            if analysis_results:
                self._display_analysis_results(analysis_results)
            else:
                self.logger.info("[*] No vulnerabilities detected by AI analysis")
                
        except Exception as e:
            self.logger.error(f"[-] Error analyzing URL: {e}")
    
    def _generate_payloads(self, vuln_type: Optional[str]):
        """Generate smart payloads"""
        if not vuln_type:
            self.logger.error("[-] Please provide vulnerability type")
            self.logger.info("[*] Available types: sql_injection, xss, directory_traversal, command_injection, xxe, ssrf")
            return
        
        try:
            self.logger.info(f"[*] Generating smart payloads for: {vuln_type}")
            
            context = {
                'has_parameters': True,
                'is_form_submission': False,
                'has_user_input': True,
                'encoding_type': 'html'
            }
            
            payloads = self.engine.generate_smart_payloads(vuln_type, context, 10)
            
            if payloads:
                self._display_payloads(payloads, vuln_type)
            else:
                self.logger.warning("[!] No payloads generated")
                
        except Exception as e:
            self.logger.error(f"[-] Error generating payloads: {e}")
    
    def _show_status(self):
        """Show AI engine status"""
        status_panel = Panel(
            "[bold green]AI Engine Status[/bold green]\n\n"
            "[bold cyan]Status:[/bold cyan] Active\n"
            "[bold cyan]Patterns Loaded:[/bold cyan] Multiple vulnerability patterns\n"
            "[bold cyan]Payload Templates:[/bold cyan] Available\n"
            "[bold cyan]Context Analysis:[/bold cyan] Enabled\n"
            "[bold cyan]Smart Generation:[/bold cyan] Enabled",
            title="[bold blue]AresProbe AI Engine[/bold blue]",
            border_style="blue"
        )
        self.console.print(status_panel)
    
    def _display_analysis_results(self, results: List):
        """Display AI analysis results"""
        if not results:
            return
        
        table = Table(title="[bold red]AI Analysis Results[/bold red]")
        table.add_column("Type", style="bold yellow")
        table.add_column("Confidence", style="bold green")
        table.add_column("Threat Level", style="bold red")
        table.add_column("Description", style="white")
        
        for result in results:
            threat_color = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "green"
            }.get(result.threat_level.value, "white")
            
            table.add_row(
                result.vulnerability_type,
                f"{result.confidence:.2f}",
                f"[{threat_color}]{result.threat_level.value.upper()}[/{threat_color}]",
                result.description
            )
        
        self.console.print(table)
        
        # Show recommendations
        for result in results:
            if result.recommendations:
                rec_panel = Panel(
                    "\n".join(f"• {rec}" for rec in result.recommendations),
                    title=f"[bold blue]Recommendations for {result.vulnerability_type}[/bold blue]",
                    border_style="blue"
                )
                self.console.print(rec_panel)
    
    def _display_payloads(self, payloads: List[str], vuln_type: str):
        """Display generated payloads"""
        payload_panel = Panel(
            "\n".join(f"{i+1:2d}. {payload}" for i, payload in enumerate(payloads)),
            title=f"[bold green]Smart Payloads for {vuln_type}[/bold green]",
            border_style="green"
        )
        self.console.print(payload_panel)
    
    def _show_help(self):
        """Show AI command help"""
        help_text = """
[bold cyan]AI Commands Help[/bold cyan]

[bold yellow]analyze <url>[/bold yellow]
    Analyze a URL using AI-powered vulnerability detection
    Example: ai analyze http://example.com/page?id=1

[bold yellow]payloads <type>[/bold yellow]
    Generate smart payloads for specific vulnerability type
    Types: sql_injection, xss, directory_traversal, command_injection, xxe, ssrf
    Example: ai payloads sql_injection

[bold yellow]status[/bold yellow]
    Show AI engine status and capabilities
    Example: ai status
        """
        
        help_panel = Panel(
            help_text,
            title="[bold blue]AresProbe AI Commands[/bold blue]",
            border_style="blue"
        )
        self.console.print(help_panel)
