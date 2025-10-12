"""
AresProbe Plugin Manager
Advanced plugin system for dynamic vulnerability scanning modules
"""

import os
import sys
import importlib
import inspect
import threading
import time
from typing import Dict, List, Optional, Any, Type, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import json
import yaml

from .logger import Logger


class PluginType(Enum):
    """Types of plugins"""
    SCANNER = "scanner"
    PAYLOAD_GENERATOR = "payload_generator"
    REPORT_GENERATOR = "report_generator"
    PROXY_HANDLER = "proxy_handler"
    AI_ANALYZER = "ai_analyzer"
    CUSTOM = "custom"


class PluginPriority(Enum):
    """Plugin execution priority"""
    LOWEST = 0
    LOW = 1
    NORMAL = 2
    HIGH = 3
    HIGHEST = 4


@dataclass
class PluginInfo:
    """Plugin information"""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    priority: PluginPriority
    dependencies: List[str]
    enabled: bool = True
    loaded: bool = False
    error_count: int = 0
    last_error: Optional[str] = None


class PluginBase(ABC):
    """Base class for all AresProbe plugins"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.info = self.get_plugin_info()
        self.initialized = False
    
    @abstractmethod
    def get_plugin_info(self) -> PluginInfo:
        """Return plugin information"""
        pass
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin"""
        pass
    
    @abstractmethod
    def cleanup(self):
        """Cleanup plugin resources"""
        pass
    
    def is_initialized(self) -> bool:
        """Check if plugin is initialized"""
        return self.initialized
    
    def get_name(self) -> str:
        """Get plugin name"""
        return self.info.name
    
    def get_version(self) -> str:
        """Get plugin version"""
        return self.info.version


class ScannerPlugin(PluginBase):
    """Base class for scanner plugins"""
    
    @abstractmethod
    def scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform vulnerability scan"""
        pass
    
    @abstractmethod
    def get_supported_vulnerabilities(self) -> List[str]:
        """Get list of supported vulnerability types"""
        pass


class PayloadGeneratorPlugin(PluginBase):
    """Base class for payload generator plugins"""
    
    @abstractmethod
    def generate_payloads(self, vulnerability_type: str, context: Dict[str, Any], 
                         count: int = 10) -> List[str]:
        """Generate payloads for specific vulnerability type"""
        pass
    
    @abstractmethod
    def get_supported_types(self) -> List[str]:
        """Get list of supported vulnerability types"""
        pass


class ReportGeneratorPlugin(PluginBase):
    """Base class for report generator plugins"""
    
    @abstractmethod
    def generate_report(self, scan_results: Dict[str, Any], 
                       output_format: str = "html") -> str:
        """Generate security report"""
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported output formats"""
        pass


class ProxyHandlerPlugin(PluginBase):
    """Base class for proxy handler plugins"""
    
    @abstractmethod
    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle intercepted request"""
        pass
    
    @abstractmethod
    def handle_response(self, response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle intercepted response"""
        pass


class AIAnalyzerPlugin(PluginBase):
    """Base class for AI analyzer plugins"""
    
    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data using AI"""
        pass
    
    @abstractmethod
    def get_analysis_types(self) -> List[str]:
        """Get list of supported analysis types"""
        pass


class PluginManager:
    """
    Advanced plugin manager for AresProbe
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.plugins: Dict[str, PluginBase] = {}
        self.plugin_info: Dict[str, PluginInfo] = {}
        self.plugin_directories = [
            "aresprobe/plugins",
            "plugins",
            "custom_plugins"
        ]
        self.hot_reload_enabled = True
        self.hot_reload_thread = None
        self.file_watchers = {}
        
    def initialize(self) -> bool:
        """Initialize the plugin manager"""
        try:
            self.logger.info("[*] Initializing Plugin Manager...")
            
            # Create plugin directories if they don't exist
            for directory in self.plugin_directories:
                os.makedirs(directory, exist_ok=True)
            
            # Load all plugins
            self._load_all_plugins()
            
            # Start hot reload if enabled
            if self.hot_reload_enabled:
                self._start_hot_reload()
            
            self.logger.success("[+] Plugin Manager initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to initialize Plugin Manager: {e}")
            return False
    
    def _load_all_plugins(self):
        """Load all available plugins"""
        for directory in self.plugin_directories:
            if os.path.exists(directory):
                self._load_plugins_from_directory(directory)
    
    def _load_plugins_from_directory(self, directory: str):
        """Load plugins from a specific directory"""
        try:
            for filename in os.listdir(directory):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]
                    module_path = os.path.join(directory, filename)
                    
                    # Add directory to Python path
                    if directory not in sys.path:
                        sys.path.insert(0, directory)
                    
                    try:
                        # Import the module
                        spec = importlib.util.spec_from_file_location(module_name, module_path)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find plugin classes
                        self._register_plugins_from_module(module, module_name)
                        
                    except Exception as e:
                        self.logger.debug(f"[-] Error loading plugin {module_name}: {e}")
                        
        except Exception as e:
            self.logger.error(f"[-] Error loading plugins from {directory}: {e}")
    
    def _register_plugins_from_module(self, module, module_name: str):
        """Register plugins found in a module"""
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, PluginBase) and 
                obj != PluginBase and
                not inspect.isabstract(obj)):
                
                try:
                    # Create plugin instance
                    plugin = obj(self.logger)
                    plugin_name = plugin.get_name()
                    
                    # Check for conflicts
                    if plugin_name in self.plugins:
                        self.logger.warning(f"[!] Plugin {plugin_name} already loaded, skipping")
                        continue
                    
                    # Initialize plugin
                    if plugin.initialize():
                        self.plugins[plugin_name] = plugin
                        self.plugin_info[plugin_name] = plugin.info
                        self.logger.success(f"[+] Loaded plugin: {plugin_name} v{plugin.get_version()}")
                    else:
                        self.logger.error(f"[-] Failed to initialize plugin: {plugin_name}")
                        
                except Exception as e:
                    self.logger.error(f"[-] Error registering plugin {name}: {e}")
    
    def register_plugin(self, plugin: PluginBase) -> bool:
        """Register a plugin instance"""
        try:
            plugin_name = plugin.get_name()
            
            if plugin_name in self.plugins:
                self.logger.warning(f"[!] Plugin {plugin_name} already registered")
                return False
            
            if plugin.initialize():
                self.plugins[plugin_name] = plugin
                self.plugin_info[plugin_name] = plugin.info
                self.logger.success(f"[+] Registered plugin: {plugin_name}")
                return True
            else:
                self.logger.error(f"[-] Failed to initialize plugin: {plugin_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"[-] Error registering plugin: {e}")
            return False
    
    def unregister_plugin(self, plugin_name: str) -> bool:
        """Unregister a plugin"""
        try:
            if plugin_name not in self.plugins:
                self.logger.warning(f"[!] Plugin {plugin_name} not found")
                return False
            
            plugin = self.plugins[plugin_name]
            plugin.cleanup()
            
            del self.plugins[plugin_name]
            del self.plugin_info[plugin_name]
            
            self.logger.success(f"[+] Unregistered plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error unregistering plugin {plugin_name}: {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginBase]:
        """Get a plugin by name"""
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginBase]:
        """Get all plugins of a specific type"""
        return [
            plugin for plugin in self.plugins.values()
            if plugin.info.plugin_type == plugin_type and plugin.info.enabled
        ]
    
    def get_enabled_plugins(self) -> List[PluginBase]:
        """Get all enabled plugins"""
        return [
            plugin for plugin in self.plugins.values()
            if plugin.info.enabled
        ]
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        if plugin_name in self.plugin_info:
            self.plugin_info[plugin_name].enabled = True
            self.logger.success(f"[+] Enabled plugin: {plugin_name}")
            return True
        else:
            self.logger.error(f"[-] Plugin {plugin_name} not found")
            return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        if plugin_name in self.plugin_info:
            self.plugin_info[plugin_name].enabled = False
            self.logger.success(f"[+] Disabled plugin: {plugin_name}")
            return True
        else:
            self.logger.error(f"[-] Plugin {plugin_name} not found")
            return False
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin"""
        try:
            if plugin_name not in self.plugins:
                self.logger.error(f"[-] Plugin {plugin_name} not found")
                return False
            
            # Unregister and reload
            self.unregister_plugin(plugin_name)
            
            # Find and reload the module
            for directory in self.plugin_directories:
                plugin_file = os.path.join(directory, f"{plugin_name}.py")
                if os.path.exists(plugin_file):
                    self._load_plugins_from_directory(directory)
                    break
            
            self.logger.success(f"[+] Reloaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error reloading plugin {plugin_name}: {e}")
            return False
    
    def _start_hot_reload(self):
        """Start hot reload monitoring"""
        if self.hot_reload_thread and self.hot_reload_thread.is_alive():
            return
        
        self.hot_reload_thread = threading.Thread(target=self._hot_reload_loop, daemon=True)
        self.hot_reload_thread.start()
        self.logger.info("[*] Hot reload monitoring started")
    
    def _hot_reload_loop(self):
        """Hot reload monitoring loop"""
        while True:
            try:
                time.sleep(2)  # Check every 2 seconds
                
                for directory in self.plugin_directories:
                    if os.path.exists(directory):
                        for filename in os.listdir(directory):
                            if filename.endswith('.py') and not filename.startswith('__'):
                                file_path = os.path.join(directory, filename)
                                mtime = os.path.getmtime(file_path)
                                
                                if file_path not in self.file_watchers:
                                    self.file_watchers[file_path] = mtime
                                elif self.file_watchers[file_path] != mtime:
                                    # File modified, reload
                                    self.file_watchers[file_path] = mtime
                                    plugin_name = filename[:-3]
                                    self.logger.info(f"[*] Detected changes in {plugin_name}, reloading...")
                                    self.reload_plugin(plugin_name)
                                    
            except Exception as e:
                self.logger.error(f"[-] Error in hot reload loop: {e}")
                time.sleep(5)
    
    def get_plugin_status(self) -> Dict[str, Any]:
        """Get status of all plugins"""
        status = {
            'total_plugins': len(self.plugins),
            'enabled_plugins': len(self.get_enabled_plugins()),
            'disabled_plugins': len(self.plugins) - len(self.get_enabled_plugins()),
            'plugins': {}
        }
        
        for name, plugin in self.plugins.items():
            status['plugins'][name] = {
                'name': plugin.get_name(),
                'version': plugin.get_version(),
                'type': plugin.info.plugin_type.value,
                'enabled': plugin.info.enabled,
                'initialized': plugin.is_initialized(),
                'error_count': plugin.info.error_count,
                'last_error': plugin.info.last_error
            }
        
        return status
    
    def cleanup(self):
        """Cleanup plugin manager"""
        self.logger.info("[*] Cleaning up Plugin Manager...")
        
        # Stop hot reload
        self.hot_reload_enabled = False
        
        # Cleanup all plugins
        for plugin in self.plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                self.logger.error(f"[-] Error cleaning up plugin {plugin.get_name()}: {e}")
        
        self.plugins.clear()
        self.plugin_info.clear()
        
        self.logger.success("[+] Plugin Manager cleanup completed")
