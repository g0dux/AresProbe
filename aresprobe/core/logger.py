"""
AresProbe Logger
Advanced logging system with multiple output formats and levels
"""

import logging
import sys
import time
from typing import Optional, Dict, Any
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)


class Logger:
    """
    Advanced logger with colored output and multiple levels
    """
    
    def __init__(self, name: str = "AresProbe", level: int = logging.INFO):
        self.name = name
        self.level = level
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(console_handler)
        
        # Log levels
        self.levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
    
    def success(self, message: str):
        """Log success message"""
        self.logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(f"{Fore.RED}{Back.YELLOW}[CRITICAL]{Style.RESET_ALL} {message}")
    
    def banner(self, message: str):
        """Log banner message"""
        banner = f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n"
        banner += f"{Fore.RED}{message.center(60)}{Style.RESET_ALL}\n"
        banner += f"{Fore.RED}{'='*60}{Style.RESET_ALL}"
        print(banner)
    
    def section(self, message: str):
        """Log section header"""
        section = f"{Fore.CYAN}{'─'*40}{Style.RESET_ALL}\n"
        section += f"{Fore.CYAN}{message.center(40)}{Style.RESET_ALL}\n"
        section += f"{Fore.CYAN}{'─'*40}{Style.RESET_ALL}"
        print(section)
    
    def table(self, headers: list, rows: list):
        """Log data in table format"""
        if not headers or not rows:
            return
        
        # Calculate column widths
        col_widths = [len(str(header)) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_line = "│"
        for i, header in enumerate(headers):
            header_line += f" {str(header).ljust(col_widths[i])} │"
        print(f"{Fore.CYAN}{header_line}{Style.RESET_ALL}")
        
        # Print separator
        separator = "├"
        for width in col_widths:
            separator += "─" * (width + 2) + "┼"
        separator = separator[:-1] + "┤"
        print(f"{Fore.CYAN}{separator}{Style.RESET_ALL}")
        
        # Print rows
        for row in rows:
            row_line = "│"
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    row_line += f" {str(cell).ljust(col_widths[i])} │"
            print(f"{Fore.WHITE}{row_line}{Style.RESET_ALL}")
    
    def progress(self, current: int, total: int, message: str = ""):
        """Log progress bar"""
        if total == 0:
            return
        
        percentage = (current / total) * 100
        bar_length = 30
        filled_length = int(bar_length * current // total)
        
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        
        progress_text = f"\r{Fore.CYAN}[{bar}]{Style.RESET_ALL} {percentage:.1f}% {message}"
        print(progress_text, end="", flush=True)
        
        if current == total:
            print()  # New line when complete
    
    def set_level(self, level: str):
        """Set logging level"""
        if level.upper() in self.levels:
            self.level = self.levels[level.upper()]
            self.logger.setLevel(self.level)
            self.logger.info(f"[*] Log level set to {level.upper()}")
        else:
            self.error(f"Invalid log level: {level}")
    
    def get_level(self) -> str:
        """Get current logging level"""
        for level_name, level_value in self.levels.items():
            if level_value == self.level:
                return level_name
        return "INFO"
