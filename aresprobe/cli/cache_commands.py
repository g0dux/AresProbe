"""
AresProbe Cache Commands
Cache management commands for AresProbe CLI
"""

from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn

from ..core.logger import Logger


class CacheCommand:
    """Cache management commands for AresProbe CLI"""
    
    def __init__(self, engine, logger: Logger = None):
        self.engine = engine
        self.logger = logger or Logger()
        self.console = Console()
    
    def execute(self, args: str):
        """Execute cache command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        if command == "stats":
            self._show_stats()
        elif command == "clear":
            self._clear_cache()
        elif command == "memory":
            self._show_memory_usage()
        else:
            self.logger.error(f"[-] Unknown cache command: {command}")
            self._show_help()
    
    def _show_stats(self):
        """Show cache statistics"""
        try:
            stats = self.engine.get_cache_stats()
            
            # Create statistics table
            table = Table(title="[bold blue]Cache Statistics[/bold blue]")
            table.add_column("Metric", style="bold green")
            table.add_column("Value", style="bold white")
            
            table.add_row("Cache Size", f"{stats['size']} entries")
            table.add_row("Max Size", f"{stats['max_size']} entries")
            table.add_row("Memory Used", f"{stats['memory_used_mb']:.2f} MB")
            table.add_row("Max Memory", f"{stats['max_memory_mb']:.2f} MB")
            table.add_row("Hit Rate", f"{stats['hit_rate']:.2f}%")
            table.add_row("Total Hits", str(stats['hits']))
            table.add_row("Total Misses", str(stats['misses']))
            table.add_row("Evictions", str(stats['evictions']))
            table.add_row("Insertions", str(stats['insertions']))
            table.add_row("Updates", str(stats['updates']))
            table.add_row("Policy", stats['policy'].upper())
            
            self.console.print(table)
            
            # Show hit rate progress bar
            hit_rate = stats['hit_rate']
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Hit Rate", total=100)
                progress.update(task, completed=hit_rate)
            
            # Memory usage progress bar
            memory_usage = (stats['memory_used_mb'] / stats['max_memory_mb']) * 100
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Memory Usage", total=100)
                progress.update(task, completed=memory_usage)
            
        except Exception as e:
            self.logger.error(f"[-] Error getting cache stats: {e}")
    
    def _clear_cache(self):
        """Clear all cache"""
        try:
            self.engine.clear_cache()
            self.logger.success("[+] Cache cleared successfully")
        except Exception as e:
            self.logger.error(f"[-] Error clearing cache: {e}")
    
    def _show_memory_usage(self):
        """Show detailed memory usage"""
        try:
            memory_info = self.engine.get_memory_usage()
            
            memory_panel = Panel(
                f"[bold cyan]Used Memory:[/bold cyan] {memory_info['used_mb']:.2f} MB\n"
                f"[bold cyan]Max Memory:[/bold cyan] {memory_info['max_mb']:.2f} MB\n"
                f"[bold cyan]Usage Percentage:[/bold cyan] {memory_info['usage_percent']:.2f}%\n"
                f"[bold cyan]Entry Count:[/bold cyan] {memory_info['entry_count']}\n"
                f"[bold cyan]Average Entry Size:[/bold cyan] {memory_info['average_entry_size']:.2f} bytes",
                title="[bold blue]Memory Usage Details[/bold blue]",
                border_style="blue"
            )
            self.console.print(memory_panel)
            
            # Memory usage visualization
            usage_percent = memory_info['usage_percent']
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ) as progress:
                task = progress.add_task("Memory Usage", total=100)
                progress.update(task, completed=usage_percent)
            
        except Exception as e:
            self.logger.error(f"[-] Error getting memory usage: {e}")
    
    def _show_help(self):
        """Show cache command help"""
        help_text = """
[bold cyan]Cache Commands Help[/bold cyan]

[bold yellow]stats[/bold yellow]
    Show detailed cache statistics including hit rate and memory usage
    Example: cache stats

[bold yellow]clear[/bold yellow]
    Clear all cached data
    Example: cache clear

[bold yellow]memory[/bold yellow]
    Show detailed memory usage information
    Example: cache memory
        """
        
        help_panel = Panel(
            help_text,
            title="[bold blue]AresProbe Cache Commands[/bold blue]",
            border_style="blue"
        )
        self.console.print(help_panel)
