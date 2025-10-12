"""
AresProbe Penetration Commands
Advanced penetration testing and aggressive attack commands
"""

import os
import json
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.prompt import Confirm, Prompt

from ..core.logger import Logger
from ..core.aggressive_config import AggressiveConfig, AttackMode, AggressiveConfigManager
from ..core.penetration_engine import PenetrationEngine


class PenetrationCommand:
    """Penetration testing commands for AresProbe CLI"""
    
    def __init__(self, engine, logger: Logger = None):
        self.engine = engine
        self.logger = logger or Logger()
        self.console = Console()
        self.config_manager = AggressiveConfigManager(logger)
        self.config = self.config_manager.load_config()
        self.penetration_engine = PenetrationEngine(self.config, logger)
    
    def execute(self, args: str):
        """Execute penetration command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        if command == "attack":
            self._execute_attack(parts[1] if len(parts) > 1 else None)
        elif command == "config":
            self._manage_config(parts[1] if len(parts) > 1 else None)
        elif command == "exploits":
            self._list_exploits()
        elif command == "mode":
            self._set_attack_mode(parts[1] if len(parts) > 1 else None)
        elif command == "destructive":
            self._toggle_destructive_mode()
        elif command == "status":
            self._show_status()
        else:
            self.logger.error(f"[-] Unknown penetration command: {command}")
            self._show_help()
    
    def _execute_attack(self, target: Optional[str]):
        """Execute aggressive penetration attack"""
        if not target:
            target = Prompt.ask("Enter target URL")
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Confirm destructive mode if enabled
        if self.config.allow_destructive:
            if not Confirm.ask("[bold red]DESTRUCTIVE MODE ENABLED - Continue?"):
                self.logger.info("[*] Attack cancelled by user")
                return
        
        try:
            self.logger.info(f"[*] Starting aggressive penetration attack on {target}")
            
            # Show attack configuration
            self._show_attack_config()
            
            # Execute penetration test
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Executing penetration attack...", total=100)
                
                result = self.penetration_engine.execute_penetration_test(target)
                
                progress.update(task, completed=100)
            
            # Display results
            self._display_penetration_results(result)
            
        except Exception as e:
            self.logger.error(f"[-] Penetration attack failed: {e}")
    
    def _manage_config(self, action: Optional[str]):
        """Manage penetration configuration"""
        if not action:
            self._show_config_help()
            return
        
        if action == "show":
            self._show_current_config()
        elif action == "load":
            config_file = Prompt.ask("Enter config file path", default="aggressive_config.json")
            self.config = self.config_manager.load_config(config_file)
            self.logger.success(f"[+] Configuration loaded from {config_file}")
        elif action == "save":
            config_file = Prompt.ask("Enter config file path", default="aggressive_config.json")
            if self.config_manager.save_config(config_file):
                self.logger.success(f"[+] Configuration saved to {config_file}")
        elif action == "reset":
            if Confirm.ask("Reset to default configuration?"):
                self.config = AggressiveConfig()
                self.logger.success("[+] Configuration reset to defaults")
        else:
            self.logger.error(f"[-] Unknown config action: {action}")
            self._show_config_help()
    
    def _list_exploits(self):
        """List available exploits"""
        exploits = self.penetration_engine.exploits
        
        table = Table(title="[bold red]Available Exploits[/bold red]")
        table.add_column("ID", style="bold yellow")
        table.add_column("Name", style="bold green")
        table.add_column("Type", style="bold cyan")
        table.add_column("Severity", style="bold red")
        table.add_column("Success Rate", style="bold white")
        
        for exploit in exploits:
            severity_color = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "green"
            }.get(exploit.severity, "white")
            
            table.add_row(
                exploit.id,
                exploit.name,
                exploit.type.value,
                f"[{severity_color}]{exploit.severity.upper()}[/{severity_color}]",
                f"{exploit.success_rate:.1%}"
            )
        
        self.console.print(table)
        
        # Show exploit details
        if Confirm.ask("Show detailed exploit information?"):
            for exploit in exploits:
                self._show_exploit_details(exploit)
    
    def _set_attack_mode(self, mode: Optional[str]):
        """Set attack mode"""
        if not mode:
            self._show_attack_modes()
            return
        
        try:
            attack_mode = AttackMode(mode.lower())
            self.config_manager.set_attack_mode(attack_mode)
            self.logger.success(f"[+] Attack mode set to: {attack_mode.value}")
        except ValueError:
            self.logger.error(f"[-] Invalid attack mode: {mode}")
            self._show_attack_modes()
    
    def _toggle_destructive_mode(self):
        """Toggle destructive mode"""
        if self.config.allow_destructive:
            self.config_manager.disable_destructive_mode()
        else:
            if Confirm.ask("[bold red]Enable destructive mode? This can cause damage!"):
                self.config_manager.enable_destructive_mode()
    
    def _show_status(self):
        """Show penetration engine status"""
        config_summary = self.config_manager.get_config_summary()
        
        status_panel = Panel(
            f"[bold cyan]Attack Mode:[/bold cyan] {config_summary['attack_mode']}\n"
            f"[bold cyan]Injection Techniques:[/bold cyan] {len(config_summary['injection_techniques'])}\n"
            f"[bold cyan]Max Payloads:[/bold cyan] {config_summary['max_payloads']}\n"
            f"[bold cyan]Concurrent Requests:[/bold cyan] {config_summary['concurrent_requests']}\n"
            f"[bold cyan]Timeout:[/bold cyan] {config_summary['timeout']}s\n"
            f"[bold red]Destructive Mode:[/bold red] {'ENABLED' if config_summary['destructive_mode'] else 'DISABLED'}\n"
            f"[bold cyan]Available Exploits:[/bold cyan] {len(self.penetration_engine.exploits)}",
            title="[bold blue]Penetration Engine Status[/bold blue]",
            border_style="blue"
        )
        self.console.print(status_panel)
    
    def _show_attack_config(self):
        """Show current attack configuration"""
        config_summary = self.config_manager.get_config_summary()
        
        config_panel = Panel(
            f"[bold yellow]Target:[/bold yellow] {config_summary.get('target', 'Not set')}\n"
            f"[bold yellow]Mode:[/bold yellow] {config_summary['attack_mode']}\n"
            f"[bold yellow]Techniques:[/bold yellow] {', '.join(config_summary['injection_techniques'])}\n"
            f"[bold yellow]Payloads:[/bold yellow] {config_summary['max_payloads']} per technique\n"
            f"[bold yellow]Threads:[/bold yellow] {config_summary['concurrent_requests']}\n"
            f"[bold red]Destructive:[/bold red] {'YES' if config_summary['destructive_mode'] else 'NO'}",
            title="[bold red]Attack Configuration[/bold red]",
            border_style="red"
        )
        self.console.print(config_panel)
    
    def _display_penetration_results(self, result):
        """Display penetration test results"""
        # Summary
        summary_panel = Panel(
            f"[bold cyan]Target:[/bold cyan] {result.target}\n"
            f"[bold cyan]Duration:[/bold cyan] {result.duration:.2f} seconds\n"
            f"[bold cyan]Vulnerabilities:[/bold cyan] {result.vulnerabilities_found}\n"
            f"[bold cyan]Exploits:[/bold cyan] {result.exploits_successful}\n"
            f"[bold red]System Compromised:[/bold red] {'YES' if result.system_compromised else 'NO'}\n"
            f"[bold yellow]Access Level:[/bold yellow] {result.access_level}",
            title="[bold red]Penetration Test Results[/bold red]",
            border_style="red"
        )
        self.console.print(summary_panel)
        
        # Detailed results
        if result.results:
            for i, attack_result in enumerate(result.results, 1):
                if attack_result.get('vulnerabilities'):
                    vuln_table = Table(title=f"[bold yellow]Attack Vector {i} - Vulnerabilities[/bold yellow]")
                    vuln_table.add_column("Parameter", style="bold green")
                    vuln_table.add_column("Technique", style="bold cyan")
                    vuln_table.add_column("Confidence", style="bold white")
                    
                    for vuln in attack_result['vulnerabilities']:
                        vuln_table.add_row(
                            vuln.get('parameter', 'Unknown'),
                            vuln.get('technique', 'Unknown'),
                            f"{vuln.get('confidence', 0):.2f}"
                        )
                    
                    self.console.print(vuln_table)
                
                if attack_result.get('data_extracted'):
                    data_panel = Panel(
                        f"[bold green]Data Extracted:[/bold green]\n"
                        f"Databases: {len(attack_result['data_extracted'].get('databases', []))}\n"
                        f"Tables: {len(attack_result['data_extracted'].get('tables', []))}\n"
                        f"Columns: {len(attack_result['data_extracted'].get('columns', {}))}",
                        title="[bold green]Data Extraction Results[/bold green]",
                        border_style="green"
                    )
                    self.console.print(data_panel)
    
    def _show_exploit_details(self, exploit):
        """Show detailed exploit information"""
        details_panel = Panel(
            f"[bold cyan]Name:[/bold cyan] {exploit.name}\n"
            f"[bold cyan]Type:[/bold cyan] {exploit.type.value}\n"
            f"[bold cyan]Description:[/bold cyan] {exploit.description}\n"
            f"[bold cyan]Severity:[/bold cyan] {exploit.severity}\n"
            f"[bold cyan]Confidence:[/bold cyan] {exploit.confidence:.2f}\n"
            f"[bold cyan]Success Rate:[/bold cyan] {exploit.success_rate:.1%}\n"
            f"[bold cyan]Impact:[/bold cyan] {exploit.impact}\n"
            f"[bold cyan]Prerequisites:[/bold cyan] {', '.join(exploit.prerequisites)}\n"
            f"[bold cyan]Steps:[/bold cyan]\n" + "\n".join(f"  {step}" for step in exploit.steps),
            title=f"[bold red]Exploit: {exploit.id}[/bold red]",
            border_style="red"
        )
        self.console.print(details_panel)
    
    def _show_attack_modes(self):
        """Show available attack modes"""
        modes_panel = Panel(
            "[bold cyan]Available Attack Modes:[/bold cyan]\n\n"
            "[bold green]stealth[/bold green] - Silent, undetected attacks\n"
            "[bold yellow]aggressive[/bold yellow] - Fast, multiple payloads\n"
            "[bold red]bruteforce[/bold red] - Maximum payloads, high speed\n"
            "[bold blue]persistent[/bold blue] - Long-term, sustained attacks\n"
            "[bold magenta]destructive[/bold magenta] - High-risk, potentially damaging",
            title="[bold blue]Attack Modes[/bold blue]",
            border_style="blue"
        )
        self.console.print(modes_panel)
    
    def _show_current_config(self):
        """Show current configuration"""
        config_summary = self.config_manager.get_config_summary()
        
        config_table = Table(title="[bold blue]Current Configuration[/bold blue]")
        config_table.add_column("Setting", style="bold green")
        config_table.add_column("Value", style="bold white")
        
        for key, value in config_summary.items():
            if isinstance(value, list):
                value = ', '.join(value)
            config_table.add_row(key.replace('_', ' ').title(), str(value))
        
        self.console.print(config_table)
    
    def _show_config_help(self):
        """Show configuration help"""
        help_panel = Panel(
            "[bold cyan]Configuration Commands:[/bold cyan]\n\n"
            "[bold yellow]show[/bold yellow] - Show current configuration\n"
            "[bold yellow]load <file>[/bold yellow] - Load configuration from file\n"
            "[bold yellow]save <file>[/bold yellow] - Save configuration to file\n"
            "[bold yellow]reset[/bold yellow] - Reset to default configuration",
            title="[bold blue]Configuration Help[/bold blue]",
            border_style="blue"
        )
        self.console.print(help_panel)
    
    def _show_help(self):
        """Show penetration command help"""
        help_text = """
[bold cyan]Penetration Commands Help[/bold cyan]

[bold red]attack <url>[/bold red]
    Execute aggressive penetration attack on target
    Example: penetration attack http://example.com

[bold yellow]config <action>[/bold yellow]
    Manage penetration configuration
    Actions: show, load, save, reset
    Example: penetration config show

[bold yellow]exploits[/bold yellow]
    List available exploits and techniques
    Example: penetration exploits

[bold yellow]mode <mode>[/bold yellow]
    Set attack mode (stealth, aggressive, bruteforce, persistent, destructive)
    Example: penetration mode aggressive

[bold yellow]destructive[/bold yellow]
    Toggle destructive mode (can cause damage!)
    Example: penetration destructive

[bold yellow]status[/bold yellow]
    Show penetration engine status
    Example: penetration status
        """
        
        help_panel = Panel(
            help_text,
            title="[bold red]AresProbe Penetration Commands[/bold red]",
            border_style="red"
        )
        self.console.print(help_panel)
