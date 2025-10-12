"""
AresProbe Advanced Performance Commands
CLI commands for performance optimization and monitoring
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.logger import Logger

class AdvancedPerformanceCommand:
    """Advanced performance optimization commands"""
    
    def __init__(self, engine, logger: Logger):
        self.engine = engine
        self.logger = logger
        self.console = Console()
    
    def execute(self, args: str):
        """Execute performance command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        try:
            if command == "optimize":
                self._optimize_performance(parts[1:])
            elif command == "monitor":
                self._monitor_performance()
            elif command == "report":
                self._generate_performance_report()
            elif command == "stats":
                self._show_performance_stats()
            elif command == "memory":
                self._optimize_memory()
            elif command == "cpu":
                self._optimize_cpu()
            elif command == "network":
                self._optimize_network()
            elif command == "help":
                self._show_help()
            else:
                self.logger.error(f"[-] Unknown performance command: {command}")
                self._show_help()
                
        except Exception as e:
            self.logger.error(f"[-] Performance command failed: {e}")
    
    def _optimize_performance(self, args: List[str]):
        """Optimize overall performance"""
        self.logger.info("[*] Starting performance optimization...")
        
        # Memory optimization
        memory_result = self.engine.performance_optimizer.optimize_memory()
        self.logger.success(f"[+] Memory optimization: {memory_result['objects_collected']} objects collected")
        
        # CPU optimization
        cpu_result = self.engine.performance_optimizer.optimize_cpu()
        self.logger.success(f"[+] CPU optimization: {cpu_result['optimal_threads']} threads configured")
        
        # Network optimization
        network_result = self.engine.performance_optimizer.optimize_network()
        self.logger.success(f"[+] Network optimization: {network_result['connection_stats']['active_connections']} connections optimized")
        
        # Display results
        self._display_optimization_results(memory_result, cpu_result, network_result)
    
    def _monitor_performance(self):
        """Monitor real-time performance"""
        self.logger.info("[*] Starting performance monitoring...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Monitoring performance...", total=None)
            
            for _ in range(10):  # Monitor for 10 iterations
                report = self.engine.performance_optimizer.get_performance_report()
                
                # Update progress with current metrics
                progress.update(task, description=f"CPU: {report['current_metrics']['cpu_usage']:.1f}% | Memory: {report['current_metrics']['memory_usage']:.1f}%")
                
                # Display metrics table
                self._display_performance_metrics(report)
                
                asyncio.sleep(2)
    
    def _generate_performance_report(self):
        """Generate comprehensive performance report"""
        self.logger.info("[*] Generating performance report...")
        
        report = self.engine.performance_optimizer.get_performance_report()
        
        # Create detailed report panel
        report_text = f"""
[bold green]PERFORMANCE REPORT[/bold green]

[bold cyan]Current Metrics:[/bold cyan]
• CPU Usage: {report['current_metrics']['cpu_usage']:.1f}%
• Memory Usage: {report['current_metrics']['memory_usage']:.1f}%
• Network Throughput: {report['current_metrics']['network_throughput']:.2f} MB
• Response Time: {report['current_metrics']['response_time']:.3f}s
• Concurrent Connections: {report['current_metrics']['concurrent_connections']}
• Cache Hit Ratio: {report['current_metrics']['cache_hit_ratio']:.2f}
• Error Rate: {report['current_metrics']['error_rate']:.2f}

[bold cyan]Average Metrics:[/bold cyan]
• Average CPU: {report['average_metrics']['cpu_usage']:.1f}%
• Average Memory: {report['average_metrics']['memory_usage']:.1f}%
• Average Response Time: {report['average_metrics']['response_time']:.3f}s
• Average Cache Hit Ratio: {report['average_metrics']['cache_hit_ratio']:.2f}

[bold cyan]System Information:[/bold cyan]
• CPU Cores: {report['system_info']['cpu_count']}
• Total Memory: {report['system_info']['memory_total'] / (1024**3):.1f} GB
• Available Memory: {report['system_info']['memory_available'] / (1024**3):.1f} GB
• Disk Usage: {report['system_info']['disk_usage']:.1f}%

[bold cyan]Optimization Statistics:[/bold cyan]
• Uptime: {report['optimization_stats']['uptime']:.1f}s
• Total Operations: {report['optimization_stats']['total_operations']}
• Queue Size: {report['optimization_stats']['queue_size']}
        """
        
        report_panel = Panel(
            report_text,
            title="[bold green]ARESPROBE PERFORMANCE REPORT[/bold green]",
            border_style="green"
        )
        
        self.console.print(report_panel)
    
    def _show_performance_stats(self):
        """Show performance statistics"""
        report = self.engine.performance_optimizer.get_performance_report()
        
        # Create statistics table
        stats_table = Table(title="Performance Statistics", style="green", border_style="green")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Current", style="yellow")
        stats_table.add_column("Average", style="green")
        stats_table.add_column("Status", style="red")
        
        # Add rows
        stats_table.add_row(
            "CPU Usage (%)",
            f"{report['current_metrics']['cpu_usage']:.1f}",
            f"{report['average_metrics']['cpu_usage']:.1f}",
            "🟢 Good" if report['current_metrics']['cpu_usage'] < 70 else "🟡 High"
        )
        
        stats_table.add_row(
            "Memory Usage (%)",
            f"{report['current_metrics']['memory_usage']:.1f}",
            f"{report['average_metrics']['memory_usage']:.1f}",
            "🟢 Good" if report['current_metrics']['memory_usage'] < 80 else "🟡 High"
        )
        
        stats_table.add_row(
            "Response Time (s)",
            f"{report['current_metrics']['response_time']:.3f}",
            f"{report['average_metrics']['response_time']:.3f}",
            "🟢 Fast" if report['current_metrics']['response_time'] < 1.0 else "🟡 Slow"
        )
        
        stats_table.add_row(
            "Cache Hit Ratio",
            f"{report['current_metrics']['cache_hit_ratio']:.2f}",
            f"{report['average_metrics']['cache_hit_ratio']:.2f}",
            "🟢 Good" if report['current_metrics']['cache_hit_ratio'] > 0.8 else "🟡 Low"
        )
        
        self.console.print(stats_table)
    
    def _optimize_memory(self):
        """Optimize memory usage"""
        self.logger.info("[*] Optimizing memory usage...")
        
        result = self.engine.performance_optimizer.optimize_memory()
        
        # Display results
        memory_panel = Panel(
            f"""
[bold green]MEMORY OPTIMIZATION RESULTS[/bold green]

• Objects Collected: {result['objects_collected']}
• Weak References Cleaned: {result['weakrefs_cleaned']}
• Memory Pool Stats: {json.dumps(result['memory_pool_stats'], indent=2)}
• Optimization Time: {result['optimization_time']:.2f}s
            """,
            title="[bold green]Memory Optimization[/bold green]",
            border_style="green"
        )
        
        self.console.print(memory_panel)
    
    def _optimize_cpu(self):
        """Optimize CPU usage"""
        self.logger.info("[*] Optimizing CPU usage...")
        
        result = self.engine.performance_optimizer.optimize_cpu()
        
        # Display results
        cpu_panel = Panel(
            f"""
[bold green]CPU OPTIMIZATION RESULTS[/bold green]

• CPU Cores: {result['cpu_count']}
• CPU Usage: {result['cpu_percent']:.1f}%
• Optimal Threads: {result['optimal_threads']}
• High Priority Tasks: {result['high_priority_tasks']}
• Queue Size: {result['queue_size']}
            """,
            title="[bold green]CPU Optimization[/bold green]",
            border_style="green"
        )
        
        self.console.print(cpu_panel)
    
    def _optimize_network(self):
        """Optimize network usage"""
        self.logger.info("[*] Optimizing network usage...")
        
        result = self.engine.performance_optimizer.optimize_network()
        
        # Display results
        network_panel = Panel(
            f"""
[bold green]NETWORK OPTIMIZATION RESULTS[/bold green]

• Active Connections: {result['connection_stats']['active_connections']}
• Max Connections: {result['connection_stats']['max_connections']}
• Bytes Sent: {result['connection_stats']['bytes_sent'] / (1024**2):.2f} MB
• Bytes Received: {result['connection_stats']['bytes_recv'] / (1024**2):.2f} MB
• Optimization Time: {result['optimization_time']:.2f}s
            """,
            title="[bold green]Network Optimization[/bold green]",
            border_style="green"
        )
        
        self.console.print(network_panel)
    
    def _display_optimization_results(self, memory_result: Dict, cpu_result: Dict, network_result: Dict):
        """Display optimization results"""
        results_table = Table(title="Optimization Results", style="green", border_style="green")
        results_table.add_column("Component", style="cyan")
        results_table.add_column("Status", style="green")
        results_table.add_column("Details", style="yellow")
        
        results_table.add_row(
            "Memory",
            "✅ Optimized",
            f"{memory_result['objects_collected']} objects collected"
        )
        
        results_table.add_row(
            "CPU",
            "✅ Optimized",
            f"{cpu_result['optimal_threads']} threads configured"
        )
        
        results_table.add_row(
            "Network",
            "✅ Optimized",
            f"{network_result['connection_stats']['active_connections']} connections active"
        )
        
        self.console.print(results_table)
    
    def _display_performance_metrics(self, report: Dict):
        """Display real-time performance metrics"""
        metrics_table = Table(title="Real-time Performance Metrics", style="green", border_style="green")
        metrics_table.add_column("Metric", style="cyan")
        metrics_table.add_column("Value", style="yellow")
        metrics_table.add_column("Status", style="red")
        
        current = report['current_metrics']
        
        metrics_table.add_row(
            "CPU Usage",
            f"{current['cpu_usage']:.1f}%",
            "🟢" if current['cpu_usage'] < 70 else "🟡" if current['cpu_usage'] < 90 else "🔴"
        )
        
        metrics_table.add_row(
            "Memory Usage",
            f"{current['memory_usage']:.1f}%",
            "🟢" if current['memory_usage'] < 80 else "🟡" if current['memory_usage'] < 95 else "🔴"
        )
        
        metrics_table.add_row(
            "Response Time",
            f"{current['response_time']:.3f}s",
            "🟢" if current['response_time'] < 1.0 else "🟡" if current['response_time'] < 3.0 else "🔴"
        )
        
        metrics_table.add_row(
            "Connections",
            str(current['concurrent_connections']),
            "🟢" if current['concurrent_connections'] < 100 else "🟡" if current['concurrent_connections'] < 500 else "🔴"
        )
        
        self.console.print(metrics_table)
    
    def _show_help(self):
        """Show performance command help"""
        help_text = """
[bold green]ADVANCED PERFORMANCE COMMANDS[/bold green]

[bold cyan]Available Commands:[/bold cyan]
• optimize - Optimize overall performance (memory, CPU, network)
• monitor - Monitor real-time performance metrics
• report - Generate comprehensive performance report
• stats - Show current performance statistics
• memory - Optimize memory usage specifically
• cpu - Optimize CPU usage specifically
• network - Optimize network usage specifically
• help - Show this help message

[bold cyan]Examples:[/bold cyan]
• performance optimize
• performance monitor
• performance report
• performance memory
• performance cpu
• performance network

[bold cyan]Features:[/bold cyan]
• Real-time performance monitoring
• Memory pool optimization
• CPU thread optimization
• Network connection pooling
• Resource usage statistics
• Performance trend analysis
        """
        
        help_panel = Panel(
            help_text,
            title="[bold green]Performance Command Help[/bold green]",
            border_style="green"
        )
        
        self.console.print(help_panel)
