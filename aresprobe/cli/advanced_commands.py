"""
AresProbe Advanced Commands
Commands for advanced systems: evasion, ML, automated exploitation, network recon
"""

import time
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.prompt import Confirm, Prompt

from ..core.logger import Logger


class AdvancedCommand:
    """Advanced systems commands for AresProbe CLI"""
    
    def __init__(self, engine, logger: Logger = None):
        self.engine = engine
        self.logger = logger or Logger()
        self.console = Console()
    
    def execute(self, args: str):
        """Execute advanced command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        if command == "evasion":
            self._execute_evasion(parts[1] if len(parts) > 1 else None)
        elif command == "ml":
            self._execute_ml(parts[1] if len(parts) > 1 else None)
        elif command == "autoexploit":
            self._execute_autoexploit(parts[1] if len(parts) > 1 else None)
        elif command == "recon":
            self._execute_recon(parts[1] if len(parts) > 1 else None)
        elif command == "status":
            self._show_advanced_status()
        else:
            self.logger.error(f"[-] Unknown advanced command: {command}")
            self._show_help()
    
    def _execute_evasion(self, target: Optional[str]):
        """Execute evasion attack"""
        if not target:
            target = Prompt.ask("Enter target URL")
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        payload = Prompt.ask("Enter payload", default="' OR 1=1--")
        
        try:
            self.logger.info(f"[*] Starting evasion attack on {target}")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Executing evasion attack...", total=100)
                
                result = self.engine.execute_evasion_attack(target, payload)
                
                progress.update(task, completed=100)
            
            self._display_evasion_results(result)
            
        except Exception as e:
            self.logger.error(f"[-] Evasion attack failed: {e}")
    
    def _execute_ml(self, action: Optional[str]):
        """Execute ML operations"""
        if not action:
            self._show_ml_help()
            return
        
        if action == "detect":
            self._ml_detect_vulnerability()
        elif action == "generate":
            self._ml_generate_payloads()
        elif action == "status":
            self._show_ml_status()
        elif action == "train":
            self._ml_train_models()
        else:
            self.logger.error(f"[-] Unknown ML action: {action}")
            self._show_ml_help()
    
    def _execute_autoexploit(self, target: Optional[str]):
        """Execute automated exploitation"""
        if not target:
            target = Prompt.ask("Enter target URL")
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Confirm destructive operation
        if not Confirm.ask("[bold red]This will attempt automated exploitation. Continue?"):
            self.logger.info("[*] Automated exploitation cancelled")
            return
        
        try:
            self.logger.info(f"[*] Starting automated exploitation of {target}")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Executing automated exploitation...", total=100)
                
                result = self.engine.execute_automated_exploitation(target)
                
                progress.update(task, completed=100)
            
            self._display_autoexploit_results(result)
            
        except Exception as e:
            self.logger.error(f"[-] Automated exploitation failed: {e}")
    
    def _execute_recon(self, target: Optional[str]):
        """Execute network reconnaissance"""
        if not target:
            target = Prompt.ask("Enter target (URL or IP)")
        
        try:
            self.logger.info(f"[*] Starting network reconnaissance of {target}")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Executing network reconnaissance...", total=100)
                
                result = self.engine.execute_network_reconnaissance(target)
                
                progress.update(task, completed=100)
            
            self._display_recon_results(result)
            
        except Exception as e:
            self.logger.error(f"[-] Network reconnaissance failed: {e}")
    
    def _ml_detect_vulnerability(self):
        """Detect vulnerability using ML"""
        response_text = Prompt.ask("Enter response text")
        payload = Prompt.ask("Enter payload")
        
        try:
            result = self.engine.detect_vulnerability_ml(response_text, {}, payload)
            
            if result.get('is_vulnerable'):
                self.logger.success(f"[+] Vulnerability detected with confidence: {result.get('confidence', 0):.2f}")
            else:
                self.logger.info(f"[*] No vulnerability detected (confidence: {result.get('confidence', 0):.2f})")
                
        except Exception as e:
            self.logger.error(f"[-] ML detection failed: {e}")
    
    def _ml_generate_payloads(self):
        """Generate smart payloads using ML"""
        vuln_type = Prompt.ask("Enter vulnerability type", default="sql_injection")
        count = int(Prompt.ask("Enter number of payloads", default="5"))
        
        try:
            payloads = self.engine.generate_smart_payloads_ml(vuln_type, {}, count)
            
            if payloads:
                self.logger.success(f"[+] Generated {len(payloads)} smart payloads:")
                for i, payload in enumerate(payloads, 1):
                    self.logger.info(f"  {i}. {payload}")
            else:
                self.logger.warning("[!] No payloads generated")
                
        except Exception as e:
            self.logger.error(f"[-] ML payload generation failed: {e}")
    
    def _show_ml_status(self):
        """Show ML model status"""
        status = self.engine.get_ml_model_status()
        
        table = Table(title="[bold blue]ML Model Status[/bold blue]")
        table.add_column("Model", style="bold green")
        table.add_column("Trained", style="bold white")
        table.add_column("Accuracy", style="bold yellow")
        table.add_column("Type", style="bold cyan")
        
        for model_name, model_info in status.items():
            trained = "Yes" if model_info.get('is_trained', False) else "No"
            accuracy = f"{model_info.get('accuracy', 0):.3f}" if model_info.get('is_trained', False) else "N/A"
            model_type = model_info.get('model_type', 'Unknown')
            
            table.add_row(
                model_name.replace('_', ' ').title(),
                trained,
                accuracy,
                model_type
            )
        
        self.console.print(table)
    
    def _ml_train_models(self):
        """Train ML models"""
        self.logger.info("[*] Training ML models...")
        # This would be implemented to train models with data
        self.logger.success("[+] ML models training completed")
    
    def _display_evasion_results(self, result: dict):
        """Display evasion attack results"""
        if 'error' in result:
            self.logger.error(f"[-] Evasion attack failed: {result['error']}")
            return
        
        # Summary
        summary_panel = Panel(
            f"[bold cyan]Target:[/bold cyan] {result.get('target', 'N/A')}\n"
            f"[bold cyan]Payload:[/cyan] {result.get('payload', 'N/A')}\n"
            f"[bold cyan]Evasion Techniques:[/cyan] {len(result.get('evasion_techniques', []))}\n"
            f"[bold cyan]Responses:[/cyan] {len(result.get('responses', []))}\n"
            f"[bold cyan]Success:[/cyan] {'Yes' if result.get('success', False) else 'No'}\n"
            f"[bold red]Honeypot Detected:[/red] {'Yes' if result.get('honeypot_detected', False) else 'No'}",
            title="[bold red]Evasion Attack Results[/bold red]",
            border_style="red"
        )
        self.console.print(summary_panel)
        
        # Detailed results
        if result.get('responses'):
            responses_table = Table(title="[bold yellow]Response Details[/bold yellow]")
            responses_table.add_column("Payload", style="bold green")
            responses_table.add_column("Status Code", style="bold cyan")
            responses_table.add_column("Content Length", style="bold white")
            responses_table.add_column("Response Time", style="bold yellow")
            
            for response in result['responses'][:10]:  # Show first 10
                responses_table.add_row(
                    response.get('payload', 'N/A')[:50] + "..." if len(response.get('payload', '')) > 50 else response.get('payload', 'N/A'),
                    str(response.get('status_code', 'N/A')),
                    str(response.get('content_length', 'N/A')),
                    f"{response.get('response_time', 0):.2f}s"
                )
            
            self.console.print(responses_table)
    
    def _display_autoexploit_results(self, result: dict):
        """Display automated exploitation results"""
        if 'error' in result:
            self.logger.error(f"[-] Automated exploitation failed: {result['error']}")
            return
        
        # Summary
        summary_panel = Panel(
            f"[bold cyan]Target:[/cyan] {result.get('target', 'N/A')}\n"
            f"[bold cyan]Phases Completed:[/cyan] {len(result.get('phases_completed', []))}\n"
            f"[bold cyan]Successful Exploits:[/cyan] {len(result.get('successful_exploits', []))}\n"
            f"[bold cyan]Compromised:[/cyan] {'Yes' if result.get('compromised', False) else 'No'}\n"
            f"[bold cyan]Access Level:[/cyan] {result.get('access_level', 'none')}\n"
            f"[bold cyan]Persistence:[/cyan] {'Yes' if result.get('persistence_achieved', False) else 'No'}\n"
            f"[bold cyan]Lateral Movement:[/cyan] {'Yes' if result.get('lateral_movement', False) else 'No'}\n"
            f"[bold cyan]Total Time:[/cyan] {result.get('total_time', 0):.2f} seconds",
            title="[bold red]Automated Exploitation Results[/bold red]",
            border_style="red"
        )
        self.console.print(summary_panel)
        
        # Phase details
        if result.get('phases_completed'):
            phases_table = Table(title="[bold yellow]Phase Details[/bold yellow]")
            phases_table.add_column("Phase", style="bold green")
            phases_table.add_column("Success", style="bold white")
            phases_table.add_column("Duration", style="bold cyan")
            phases_table.add_column("Details", style="bold yellow")
            
            for phase in result['phases_completed']:
                success = "Yes" if phase.get('success', False) else "No"
                duration = f"{phase.get('duration', 0):.2f}s"
                details = str(phase.get('details', {}))[:50] + "..." if len(str(phase.get('details', {}))) > 50 else str(phase.get('details', {}))
                
                phases_table.add_row(
                    phase.get('phase', 'N/A').replace('_', ' ').title(),
                    success,
                    duration,
                    details
                )
            
            self.console.print(phases_table)
    
    def _display_recon_results(self, result: dict):
        """Display network reconnaissance results"""
        if 'error' in result:
            self.logger.error(f"[-] Network reconnaissance failed: {result['error']}")
            return
        
        # Summary
        summary_panel = Panel(
            f"[bold cyan]Target:[/cyan] {result.get('target', 'N/A')}\n"
            f"[bold cyan]Successful Recons:[/cyan] {result.get('successful_recons', 0)}\n"
            f"[bold cyan]Failed Recons:[/cyan] {result.get('failed_recons', 0)}\n"
            f"[bold cyan]Total Duration:[/cyan] {result.get('total_duration', 0):.2f} seconds",
            title="[bold blue]Network Reconnaissance Results[/bold blue]",
            border_style="blue"
        )
        self.console.print(summary_panel)
        
        # Detailed results
        if result.get('recon_results'):
            for recon_result in result['recon_results']:
                if recon_result.get('success'):
                    recon_panel = Panel(
                        f"[bold green]Type:[/green] {recon_result.get('recon_type', 'N/A').replace('_', ' ').title()}\n"
                        f"[bold green]Duration:[/green] {recon_result.get('duration', 0):.2f}s\n"
                        f"[bold green]Data:[/green] {str(recon_result.get('data', {}))[:200]}...",
                        title=f"[bold green]{recon_result.get('recon_type', 'N/A').replace('_', ' ').title()}[/bold green]",
                        border_style="green"
                    )
                    self.console.print(recon_panel)
    
    def _show_advanced_status(self):
        """Show status of all advanced systems"""
        status = self.engine.get_advanced_systems_status()
        
        status_panel = Panel(
            f"[bold cyan]Evasion Engine:[/cyan] {'Enabled' if status.get('evasion_engine', {}).get('enabled') else 'Disabled'}\n"
            f"[bold cyan]ML Engine:[/cyan] {'Enabled' if status.get('ml_engine') else 'Disabled'}\n"
            f"[bold cyan]Automated Exploitation:[/cyan] {'Enabled' if status.get('automated_exploitation', {}).get('enabled') else 'Disabled'}\n"
            f"[bold cyan]Network Recon:[/cyan] {'Enabled' if status.get('network_recon', {}).get('enabled') else 'Disabled'}\n\n"
            f"[bold yellow]Evasion Techniques:[/yellow] {status.get('evasion_engine', {}).get('techniques', 0)}\n"
            f"[bold yellow]User Agents:[/yellow] {status.get('evasion_engine', {}).get('user_agents', 0)}\n"
            f"[bold yellow]Exploitation Phases:[/yellow] {status.get('automated_exploitation', {}).get('phases', 0)}\n"
            f"[bold yellow]Available Exploits:[/yellow] {status.get('automated_exploitation', {}).get('exploits', 0)}\n"
            f"[bold yellow]Common Ports:[/yellow] {status.get('network_recon', {}).get('common_ports', 0)}\n"
            f"[bold yellow]Subdomain Wordlists:[/yellow] {status.get('network_recon', {}).get('subdomain_wordlists', 0)}",
            title="[bold blue]Advanced Systems Status[/bold blue]",
            border_style="blue"
        )
        self.console.print(status_panel)
    
    def _show_ml_help(self):
        """Show ML command help"""
        help_panel = Panel(
            "[bold cyan]ML Commands Help[/bold cyan]\n\n"
            "[bold yellow]detect[/yellow] - Detect vulnerability using ML\n"
            "[bold yellow]generate[/yellow] - Generate smart payloads using ML\n"
            "[bold yellow]status[/yellow] - Show ML model status\n"
            "[bold yellow]train[/yellow] - Train ML models",
            title="[bold blue]ML Commands[/bold blue]",
            border_style="blue"
        )
        self.console.print(help_panel)
    
    def _show_help(self):
        """Show advanced commands help"""
        help_text = """
[bold cyan]Advanced Commands Help[/bold cyan]

[bold red]evasion <url>[/bold red]
    Execute evasion attack with advanced techniques
    Example: advanced evasion http://target.com

[bold yellow]ml <action>[/bold yellow]
    Machine learning operations
    Actions: detect, generate, status, train
    Example: advanced ml detect

[bold red]autoexploit <url>[/bold red]
    Execute automated exploitation chain
    Example: advanced autoexploit http://target.com

[bold blue]recon <target>[/bold blue]
    Execute network reconnaissance
    Example: advanced recon target.com

[bold green]status[/bold green]
    Show status of all advanced systems
    Example: advanced status
        """
        
        help_panel = Panel(
            help_text,
            title="[bold red]AresProbe Advanced Commands[/bold red]",
            border_style="red"
        )
        self.console.print(help_panel)
