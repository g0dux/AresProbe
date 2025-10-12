"""
AresProbe Plugin Base Classes
Base classes for creating custom security testing plugins
"""

import abc
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from ..core.logger import Logger


class PluginType(Enum):
    """Types of plugins available"""
    SCANNER = "scanner"
    INJECTOR = "injector"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    UTILITY = "utility"


@dataclass
class PluginInfo:
    """Plugin information and metadata"""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    dependencies: List[str] = None
    config_schema: Dict[str, Any] = None


class BasePlugin(abc.ABC):
    """
    Base class for all AresProbe plugins
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.info = self.get_info()
        self.config = {}
        self.enabled = True
    
    @abc.abstractmethod
    def get_info(self) -> PluginInfo:
        """Get plugin information"""
        pass
    
    @abc.abstractmethod
    def initialize(self, config: Dict[str, Any] = None) -> bool:
        """Initialize the plugin with configuration"""
        pass
    
    @abc.abstractmethod
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin's main functionality"""
        pass
    
    def cleanup(self):
        """Cleanup plugin resources"""
        pass
    
    def configure(self, config: Dict[str, Any]):
        """Configure the plugin with new settings"""
        self.config.update(config)
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled
    
    def enable(self):
        """Enable the plugin"""
        self.enabled = True
    
    def disable(self):
        """Disable the plugin"""
        self.enabled = False


class ScannerPlugin(BasePlugin):
    """
    Base class for scanner plugins
    """
    
    def __init__(self, logger: Logger = None):
        super().__init__(logger)
        self.vulnerabilities = []
    
    @abc.abstractmethod
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform security scan on target"""
        pass
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute scanner plugin"""
        if not self.is_enabled():
            return {'status': 'disabled', 'vulnerabilities': []}
        
        try:
            self.logger.info(f"[*] Running {self.info.name} scan on {target}")
            vulnerabilities = self.scan(target, **kwargs)
            
            return {
                'status': 'completed',
                'plugin': self.info.name,
                'target': target,
                'vulnerabilities': vulnerabilities,
                'count': len(vulnerabilities)
            }
        except Exception as e:
            self.logger.error(f"[-] {self.info.name} scan failed: {e}")
            return {
                'status': 'failed',
                'plugin': self.info.name,
                'target': target,
                'error': str(e),
                'vulnerabilities': []
            }


class InjectorPlugin(BasePlugin):
    """
    Base class for injection testing plugins
    """
    
    def __init__(self, logger: Logger = None):
        super().__init__(logger)
        self.payloads = []
    
    @abc.abstractmethod
    def get_payloads(self) -> List[str]:
        """Get injection payloads"""
        pass
    
    @abc.abstractmethod
    def test_payload(self, target: str, payload: str, **kwargs) -> bool:
        """Test a specific payload"""
        pass
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute injector plugin"""
        if not self.is_enabled():
            return {'status': 'disabled', 'results': []}
        
        try:
            self.logger.info(f"[*] Running {self.info.name} injection test on {target}")
            payloads = self.get_payloads()
            results = []
            
            for payload in payloads:
                if self.test_payload(target, payload, **kwargs):
                    results.append({
                        'payload': payload,
                        'success': True,
                        'description': f"Successful injection with {self.info.name}"
                    })
            
            return {
                'status': 'completed',
                'plugin': self.info.name,
                'target': target,
                'results': results,
                'successful': len(results)
            }
        except Exception as e:
            self.logger.error(f"[-] {self.info.name} injection test failed: {e}")
            return {
                'status': 'failed',
                'plugin': self.info.name,
                'target': target,
                'error': str(e),
                'results': []
            }


class PluginManager:
    """
    Manages plugin loading, execution, and lifecycle
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_types = {
            PluginType.SCANNER: [],
            PluginType.INJECTOR: [],
            PluginType.ANALYZER: [],
            PluginType.REPORTER: [],
            PluginType.UTILITY: []
        }
    
    def register_plugin(self, plugin: BasePlugin) -> bool:
        """Register a plugin with the manager"""
        try:
            plugin_name = plugin.info.name
            
            if plugin_name in self.plugins:
                self.logger.warning(f"[!] Plugin {plugin_name} is already registered")
                return False
            
            # Initialize plugin
            if not plugin.initialize():
                self.logger.error(f"[-] Failed to initialize plugin {plugin_name}")
                return False
            
            # Register plugin
            self.plugins[plugin_name] = plugin
            self.plugin_types[plugin.info.plugin_type].append(plugin)
            
            self.logger.success(f"[+] Registered plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to register plugin: {e}")
            return False
    
    def unregister_plugin(self, plugin_name: str) -> bool:
        """Unregister a plugin"""
        try:
            if plugin_name not in self.plugins:
                self.logger.warning(f"[!] Plugin {plugin_name} is not registered")
                return False
            
            plugin = self.plugins[plugin_name]
            plugin.cleanup()
            
            # Remove from type-specific lists
            self.plugin_types[plugin.info.plugin_type].remove(plugin)
            del self.plugins[plugin_name]
            
            self.logger.success(f"[+] Unregistered plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to unregister plugin: {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """Get all plugins of a specific type"""
        return self.plugin_types.get(plugin_type, [])
    
    def get_all_plugins(self) -> Dict[str, BasePlugin]:
        """Get all registered plugins"""
        return self.plugins.copy()
    
    def execute_plugin(self, plugin_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Execute a specific plugin"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return {'status': 'error', 'message': f'Plugin {plugin_name} not found'}
        
        if not plugin.is_enabled():
            return {'status': 'disabled', 'message': f'Plugin {plugin_name} is disabled'}
        
        return plugin.execute(target, **kwargs)
    
    def execute_plugins_by_type(self, plugin_type: PluginType, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Execute all plugins of a specific type"""
        results = []
        plugins = self.get_plugins_by_type(plugin_type)
        
        for plugin in plugins:
            if plugin.is_enabled():
                result = plugin.execute(target, **kwargs)
                results.append(result)
        
        return results
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.enable()
            self.logger.success(f"[+] Enabled plugin: {plugin_name}")
            return True
        return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.disable()
            self.logger.success(f"[+] Disabled plugin: {plugin_name}")
            return True
        return False
    
    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """List all registered plugins with their information"""
        plugin_list = {}
        for name, plugin in self.plugins.items():
            plugin_list[name] = {
                'info': plugin.info.__dict__,
                'enabled': plugin.is_enabled(),
                'type': plugin.info.plugin_type.value
            }
        return plugin_list
    
    def cleanup_all(self):
        """Cleanup all plugins"""
        for plugin in self.plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                self.logger.error(f"[-] Error cleaning up plugin {plugin.info.name}: {e}")
        
        self.plugins.clear()
        for plugin_type in self.plugin_types:
            self.plugin_types[plugin_type].clear()
        
        self.logger.info("[*] All plugins cleaned up")
