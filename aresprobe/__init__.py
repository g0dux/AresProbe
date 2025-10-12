"""
AresProbe - Advanced Web Security Testing Framework
A powerful tool that combines Burp Suite and SQLMap capabilities
with an efficient terminal interface for penetration testing.
"""

__version__ = "1.0.0"
__author__ = "AresProbe Team"
__description__ = "Advanced Web Security Testing Framework"

from .core.engine import AresEngine
from .core.proxy import ProxyServer
from .core.scanner import VulnerabilityScanner
from .core.sql_injector import SuperSQLInjector
from .cli.interface import AresCLI

__all__ = [
    'AresEngine',
    'ProxyServer', 
    'VulnerabilityScanner',
    'SuperSQLInjector',
    'AresCLI'
]
