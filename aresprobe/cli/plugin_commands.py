"""
AresProbe Plugin Commands
Plugin management commands for AresProbe CLI
"""

from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core.logger import Logger


class PluginCommand:
    """Plugin management commands for AresProbe CLI"""
    
    def __init__(self, engine, logger: Logger = None):
        self.engine = engine
        self.logger = logger or Logger()
        self.console = Console()
    
    def execute(self, args: str):
        """Execute plugin command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        if command == "list":
            self._list_plugins()
        elif command == "enable":
            self._enable_plugin(parts[1] if len(parts) > 1 else None)
        elif command == "disable":
            self._disable_plugin(parts[1] if len(parts) > 1 else None)
        elif command == "reload":
            self._reload_plugin(parts[1] if len(parts) > 1 else None)
        elif command == "status":
            self._show_status()
        else:
            self.logger.error(f"[-] Unknown plugin command: {command}")
            self._show_help()
    
    def _list_plugins(self):
        """List all available plugins"""
        try:
            status = self.engine.get_plugin_status()
            
            table = Table(title="[bold blue]Available Plugins[/bold blue]")
            table.add_column("Name", style="bold green")
            table.add_column("Type", style="bold yellow")
            table.add_column("Status", style="bold cyan")
            table.add_column("Initialized", style="bold white")
            table.add_column("Errors", style="bold red")
            
            for plugin_name, plugin_info in status['plugins'].items():
                status_color = "green" if plugin_info['enabled'] else "red"
                init_color = "green" if plugin_info['initialized'] else "red"
                error_color = "red" if plugin_info['error_count'] > 0 else "green"
                
                table.add_row(
                    plugin_name,
                    plugin_info['type'],
                    f"[{status_color}]{'Enabled' if plugin_info['enabled'] else 'Disabled'}[/{status_color}]",
                    f"[{init_color}]{'Yes' if plugin_info['initialized'] else 'No'}[/{init_color}]",
                    f"[{error_color}]{plugin_info['error_count']}[/{error_color}]"
                )
            
            self.console.print(table)
            
            # Show summary
            summary_panel = Panel(
                f"[bold cyan]Total Plugins:[/bold cyan] {status['total_plugins']}\n"
                f"[bold green]Enabled:[/bold green] {status['enabled_plugins']}\n"
                f"[bold red]Disabled:[/bold red] {status['disabled_plugins']}",
                title="[bold blue]Plugin Summary[/bold blue]",
                border_style="blue"
            )
            self.console.print(summary_panel)
            
        except Exception as e:
            self.logger.error(f"[-] Error listing plugins: {e}")
    
    def _enable_plugin(self, plugin_name: Optional[str]):
        """Enable a plugin"""
        if not plugin_name:
            self.logger.error("[-] Please provide plugin name")
            return
        
        try:
            if self.engine.enable_plugin(plugin_name):
                self.logger.success(f"[+] Plugin '{plugin_name}' enabled")
            else:
                self.logger.error(f"[-] Failed to enable plugin '{plugin_name}'")
        except Exception as e:
            self.logger.error(f"[-] Error enabling plugin: {e}")
    
    def _disable_plugin(self, plugin_name: Optional[str]):
        """Disable a plugin"""
        if not plugin_name:
            self.logger.error("[-] Please provide plugin name")
            return
        
        try:
            if self.engine.disable_plugin(plugin_name):
                self.logger.success(f"[+] Plugin '{plugin_name}' disabled")
            else:
                self.logger.error(f"[-] Failed to disable plugin '{plugin_name}'")
        except Exception as e:
            self.logger.error(f"[-] Error disabling plugin: {e}")
    
    def _reload_plugin(self, plugin_name: Optional[str]):
        """Reload a plugin"""
        if not plugin_name:
            self.logger.error("[-] Please provide plugin name")
            return
        
        try:
            if self.engine.reload_plugin(plugin_name):
                self.logger.success(f"[+] Plugin '{plugin_name}' reloaded")
            else:
                self.logger.error(f"[-] Failed to reload plugin '{plugin_name}'")
        except Exception as e:
            self.logger.error(f"[-] Error reloading plugin: {e}")
    
    def _show_status(self):
        """Show plugin system status"""
        try:
            status = self.engine.get_plugin_status()
            
            status_panel = Panel(
                f"[bold cyan]Total Plugins:[/bold cyan] {status['total_plugins']}\n"
                f"[bold green]Enabled:[/bold green] {status['enabled_plugins']}\n"
                f"[bold red]Disabled:[/bold red] {status['disabled_plugins']}\n"
                f"[bold yellow]Hot Reload:[/bold yellow] Enabled\n"
                f"[bold blue]Plugin Directories:[/bold blue] Multiple",
                title="[bold blue]Plugin System Status[/bold blue]",
                border_style="blue"
            )
            self.console.print(status_panel)
            
        except Exception as e:
            self.logger.error(f"[-] Error getting plugin status: {e}")
    
    def _show_help(self):
        """Show plugin command help"""
        help_text = """
[bold cyan]Plugin Commands Help[/bold cyan]

[bold yellow]list[/bold yellow]
    List all available plugins with their status
    Example: plugins list

[bold yellow]enable <name>[/bold yellow]
    Enable a specific plugin
    Example: plugins enable custom_scanner

[bold yellow]disable <name>[/bold yellow]
    Disable a specific plugin
    Example: plugins disable custom_scanner

[bold yellow]reload <name>[/bold yellow]
    Reload a specific plugin (hot reload)
    Example: plugins reload custom_scanner

[bold yellow]status[/bold yellow]
    Show plugin system status
    Example: plugins status
        """
        
        help_panel = Panel(
            help_text,
            title="[bold blue]AresProbe Plugin Commands[/bold blue]",
            border_style="blue"
        )
        self.console.print(help_panel)
