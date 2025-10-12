"""
AresProbe Advanced AI/ML Commands
CLI commands for AI/ML analysis and training
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.logger import Logger

class AdvancedAIMLCommand:
    """Advanced AI/ML commands"""
    
    def __init__(self, engine, logger: Logger):
        self.engine = engine
        self.logger = logger
        self.console = Console()
    
    def execute(self, args: str):
        """Execute AI/ML command"""
        if not args:
            self._show_help()
            return
        
        parts = args.split()
        command = parts[0].lower()
        
        try:
            if command == "analyze":
                self._analyze_threat_pattern(parts[1:])
            elif command == "predict":
                self._predict_threat(parts[1:])
            elif command == "train":
                self._train_model(parts[1:])
            elif command == "stats":
                self._show_model_stats()
            elif command == "models":
                self._list_models()
            elif command == "save":
                self._save_models(parts[1:])
            elif command == "load":
                self._load_models(parts[1:])
            elif command == "test":
                self._test_model(parts[1:])
            elif command == "help":
                self._show_help()
            else:
                self.logger.error(f"[-] Unknown AI/ML command: {command}")
                self._show_help()
                
        except Exception as e:
            self.logger.error(f"[-] AI/ML command failed: {e}")
    
    def _analyze_threat_pattern(self, args: List[str]):
        """Analyze threat pattern using AI/ML"""
        if len(args) < 2:
            self.logger.error("[-] Usage: ai_ml analyze <data> <data_type>")
            return
        
        data = args[0]
        data_type = args[1]
        
        self.logger.info(f"[*] Analyzing threat pattern: {data_type}")
        
        # Run async analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                self.engine.advanced_ai_ml.analyze_threat_pattern(data, data_type)
            )
            
            self._display_threat_analysis(result)
            
        finally:
            loop.close()
    
    def _predict_threat(self, args: List[str]):
        """Predict threat using AI models"""
        if len(args) < 1:
            self.logger.error("[-] Usage: ai_ml predict <data>")
            return
        
        data = args[0]
        
        self.logger.info("[*] Predicting threat using AI models...")
        
        # Run async prediction
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                self.engine.advanced_ai_ml.analyze_threat_pattern(data, "text")
            )
            
            self._display_threat_prediction(result)
            
        finally:
            loop.close()
    
    def _train_model(self, args: List[str]):
        """Train AI model with data"""
        if len(args) < 1:
            self.logger.error("[-] Usage: ai_ml train <model_name>")
            return
        
        model_name = args[0]
        
        self.logger.info(f"[*] Training model: {model_name}")
        
        # Generate sample training data (in real implementation, this would be real data)
        training_data = self._generate_sample_training_data()
        
        # Run async training
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                self.engine.advanced_ai_ml.train_model(model_name, training_data)
            )
            
            self._display_training_result(result)
            
        finally:
            loop.close()
    
    def _show_model_stats(self):
        """Show AI model statistics"""
        stats = self.engine.advanced_ai_ml.get_model_stats()
        
        # Create statistics table
        stats_table = Table(title="AI/ML Model Statistics", style="green", border_style="green")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")
        
        stats_table.add_row("Models Loaded", str(stats['models_loaded']))
        stats_table.add_row("Model Types", ", ".join(stats['model_types']))
        stats_table.add_row("Scalers Available", ", ".join(stats['scalers_available']))
        stats_table.add_row("Tokenizers Available", ", ".join(stats['tokenizers_available']))
        stats_table.add_row("Training Data Samples", str(stats['training_data_samples']))
        stats_table.add_row("Prediction Cache Size", str(stats['prediction_cache_size']))
        
        # Add model-specific stats
        for key, value in stats.items():
            if key.endswith('_parameters'):
                stats_table.add_row(f"{key.replace('_parameters', '')} Parameters", str(value))
            elif key.endswith('_estimators'):
                stats_table.add_row(f"{key.replace('_estimators', '')} Estimators", str(value))
        
        self.console.print(stats_table)
    
    def _list_models(self):
        """List available AI models"""
        stats = self.engine.advanced_ai_ml.get_model_stats()
        
        models_panel = Panel(
            f"""
[bold green]AVAILABLE AI/ML MODELS[/bold green]

[bold cyan]Loaded Models:[/bold cyan]
{chr(10).join(f"• {model}" for model in stats['model_types'])}

[bold cyan]Available Scalers:[/bold cyan]
{chr(10).join(f"• {scaler}" for scaler in stats['scalers_available'])}

[bold cyan]Available Tokenizers:[/bold cyan]
{chr(10).join(f"• {tokenizer}" for tokenizer in stats['tokenizers_available'])}

[bold cyan]Training Data:[/bold cyan]
• Samples: {stats['training_data_samples']}
• Cache Size: {stats['prediction_cache_size']}
            """,
            title="[bold green]AI/ML Models[/bold green]",
            border_style="green"
        )
        
        self.console.print(models_panel)
    
    def _save_models(self, args: List[str]):
        """Save trained models"""
        if len(args) < 1:
            self.logger.error("[-] Usage: ai_ml save <path>")
            return
        
        path = args[0]
        
        self.logger.info(f"[*] Saving models to: {path}")
        
        try:
            self.engine.advanced_ai_ml.save_models(path)
            self.logger.success(f"[+] Models saved successfully to {path}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to save models: {e}")
    
    def _load_models(self, args: List[str]):
        """Load trained models"""
        if len(args) < 1:
            self.logger.error("[-] Usage: ai_ml load <path>")
            return
        
        path = args[0]
        
        self.logger.info(f"[*] Loading models from: {path}")
        
        try:
            self.engine.advanced_ai_ml.load_models(path)
            self.logger.success(f"[+] Models loaded successfully from {path}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to load models: {e}")
    
    def _test_model(self, args: List[str]):
        """Test AI model with sample data"""
        if len(args) < 1:
            self.logger.error("[-] Usage: ai_ml test <model_name>")
            return
        
        model_name = args[0]
        
        self.logger.info(f"[*] Testing model: {model_name}")
        
        # Test with sample data
        test_data = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "admin'--",
            "'; DROP TABLE users; --"
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Testing model...", total=len(test_data))
            
            results = []
            for i, data in enumerate(test_data):
                progress.update(task, description=f"Testing sample {i+1}/{len(test_data)}")
                
                # Run async analysis
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(
                        self.engine.advanced_ai_ml.analyze_threat_pattern(data, "text")
                    )
                    results.append((data, result))
                finally:
                    loop.close()
                
                progress.advance(task)
        
        self._display_test_results(results)
    
    def _display_threat_analysis(self, result):
        """Display threat analysis results"""
        analysis_panel = Panel(
            f"""
[bold green]THREAT ANALYSIS RESULTS[/bold green]

[bold cyan]Threat Type:[/bold cyan] {result.threat_type}
[bold cyan]Confidence:[/bold cyan] {result.confidence:.2f}
[bold cyan]Severity:[/bold cyan] {result.severity.upper()}
[bold cyan]Description:[/bold cyan] {result.description}
[bold cyan]Mitigation:[/bold cyan] {result.mitigation}
[bold cyan]False Positive Rate:[/bold cyan] {result.false_positive_rate:.2f}
[bold cyan]Model Used:[/bold cyan] {result.model_used}
            """,
            title="[bold green]AI Threat Analysis[/bold green]",
            border_style="green"
        )
        
        self.console.print(analysis_panel)
    
    def _display_threat_prediction(self, result):
        """Display threat prediction results"""
        # Create threat prediction table
        prediction_table = Table(title="Threat Prediction", style="green", border_style="green")
        prediction_table.add_column("Attribute", style="cyan")
        prediction_table.add_column("Value", style="yellow")
        prediction_table.add_column("Status", style="red")
        
        # Determine status color
        severity_colors = {
            "critical": "🔴",
            "high": "🟡",
            "medium": "🟠",
            "low": "🟢"
        }
        
        prediction_table.add_row("Threat Type", result.threat_type, "")
        prediction_table.add_row("Confidence", f"{result.confidence:.2f}", 
                                "🟢 High" if result.confidence > 0.8 else "🟡 Medium" if result.confidence > 0.5 else "🔴 Low")
        prediction_table.add_row("Severity", result.severity.upper(), severity_colors.get(result.severity, "⚪"))
        prediction_table.add_row("Model", result.model_used, "")
        
        self.console.print(prediction_table)
        
        # Show description and mitigation
        details_panel = Panel(
            f"""
[bold cyan]Description:[/bold cyan] {result.description}

[bold cyan]Mitigation:[/bold cyan] {result.mitigation}
            """,
            title="[bold green]Details[/bold green]",
            border_style="green"
        )
        
        self.console.print(details_panel)
    
    def _display_training_result(self, result):
        """Display training results"""
        if "error" in result:
            self.logger.error(f"[-] Training failed: {result['error']}")
            return
        
        training_panel = Panel(
            f"""
[bold green]MODEL TRAINING RESULTS[/bold green]

[bold cyan]Status:[/bold cyan] {result.get('status', 'Unknown')}
[bold cyan]Epochs:[/bold cyan] {result.get('epochs', 'N/A')}
[bold cyan]Final Loss:[/bold cyan] {result.get('final_loss', 'N/A')}
[bold cyan]Estimators:[/bold cyan] {result.get('n_estimators', 'N/A')}
[bold cyan]Contamination:[/bold cyan] {result.get('contamination', 'N/A')}
            """,
            title="[bold green]Training Results[/bold green]",
            border_style="green"
        )
        
        self.console.print(training_panel)
    
    def _display_test_results(self, results):
        """Display model test results"""
        test_table = Table(title="Model Test Results", style="green", border_style="green")
        test_table.add_column("Sample Data", style="cyan", max_width=30)
        test_table.add_column("Threat Type", style="yellow")
        test_table.add_column("Confidence", style="green")
        test_table.add_column("Severity", style="red")
        
        for data, result in results:
            test_table.add_row(
                data[:30] + "..." if len(data) > 30 else data,
                result.threat_type,
                f"{result.confidence:.2f}",
                result.severity.upper()
            )
        
        self.console.print(test_table)
    
    def _generate_sample_training_data(self):
        """Generate sample training data for demonstration"""
        return [
            {
                "features": [1, 2, 3, 4, 5] * 20,  # 100 features
                "label": 0  # SQL Injection
            },
            {
                "features": [6, 7, 8, 9, 10] * 20,  # 100 features
                "label": 1  # XSS
            },
            {
                "features": [11, 12, 13, 14, 15] * 20,  # 100 features
                "label": 2  # Directory Traversal
            }
        ]
    
    def _show_help(self):
        """Show AI/ML command help"""
        help_text = """
[bold green]ADVANCED AI/ML COMMANDS[/bold green]

[bold cyan]Available Commands:[/bold cyan]
• analyze <data> <type> - Analyze threat pattern using AI/ML
• predict <data> - Predict threat using AI models
• train <model> - Train AI model with data
• stats - Show AI model statistics
• models - List available AI models
• save <path> - Save trained models to path
• load <path> - Load trained models from path
• test <model> - Test AI model with sample data
• help - Show this help message

[bold cyan]Examples:[/bold cyan]
• ai_ml analyze "SELECT * FROM users" text
• ai_ml predict "<script>alert(1)</script>"
• ai_ml train neural_network
• ai_ml stats
• ai_ml models
• ai_ml save ./models
• ai_ml load ./models
• ai_ml test threat_classifier

[bold cyan]Supported Models:[/bold cyan]
• Neural Network - Deep learning threat classification
• LSTM - Sequence analysis for patterns
• CNN - Pattern recognition
• Transformer - Natural language processing
• Random Forest - Traditional ML classification
• Isolation Forest - Anomaly detection
• DBSCAN - Clustering analysis

[bold cyan]Data Types:[/bold cyan]
• text - Text data analysis
• sequence - Sequence data analysis
• network - Network data analysis
• generic - Generic data analysis
        """
        
        help_panel = Panel(
            help_text,
            title="[bold green]AI/ML Command Help[/bold green]",
            border_style="green"
        )
        
        self.console.print(help_panel)
