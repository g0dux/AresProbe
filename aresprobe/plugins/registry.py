"""
AresProbe Plugin Registry
Plugin discovery and registration system
"""

import os
import sys
import importlib
import inspect
from typing import Dict, List, Optional, Type
from pathlib import Path

from .base import BasePlugin, PluginType, PluginInfo
from ..core.logger import Logger


class PluginRegistry:
    """
    Plugin discovery and registration system
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.plugin_paths = []
        self.discovered_plugins = {}
        self.loaded_plugins = {}
    
    def add_plugin_path(self, path: str):
        """Add a path to search for plugins"""
        if os.path.exists(path):
            self.plugin_paths.append(path)
            self.logger.info(f"[*] Added plugin path: {path}")
        else:
            self.logger.warning(f"[!] Plugin path does not exist: {path}")
    
    def discover_plugins(self, path: str = None) -> Dict[str, Type[BasePlugin]]:
        """Discover plugins in the given path or all registered paths"""
        if path:
            paths_to_search = [path]
        else:
            paths_to_search = self.plugin_paths
        
        discovered = {}
        
        for search_path in paths_to_search:
            self.logger.info(f"[*] Discovering plugins in: {search_path}")
            
            # Add path to Python path if not already there
            if search_path not in sys.path:
                sys.path.insert(0, search_path)
            
            # Search for Python files
            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if file.endswith('.py') and not file.startswith('__'):
                        module_path = os.path.join(root, file)
                        relative_path = os.path.relpath(module_path, search_path)
                        module_name = relative_path.replace(os.sep, '.').replace('.py', '')
                        
                        try:
                            # Import the module
                            module = importlib.import_module(module_name)
                            
                            # Find plugin classes
                            for name, obj in inspect.getmembers(module):
                                if (inspect.isclass(obj) and 
                                    issubclass(obj, BasePlugin) and 
                                    obj != BasePlugin):
                                    
                                    # Create a temporary instance to get plugin info
                                    try:
                                        temp_instance = obj()
                                        plugin_info = temp_instance.get_info()
                                        
                                        discovered[plugin_info.name] = obj
                                        self.logger.success(f"[+] Discovered plugin: {plugin_info.name}")
                                        
                                    except Exception as e:
                                        self.logger.error(f"[-] Error getting info for plugin {name}: {e}")
                        
                        except Exception as e:
                            self.logger.error(f"[-] Error importing module {module_name}: {e}")
        
        self.discovered_plugins.update(discovered)
        return discovered
    
    def load_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Load a specific plugin by name"""
        if plugin_name not in self.discovered_plugins:
            self.logger.error(f"[-] Plugin {plugin_name} not found in discovered plugins")
            return None
        
        try:
            plugin_class = self.discovered_plugins[plugin_name]
            plugin_instance = plugin_class()
            
            if plugin_instance.initialize():
                self.loaded_plugins[plugin_name] = plugin_instance
                self.logger.success(f"[+] Loaded plugin: {plugin_name}")
                return plugin_instance
            else:
                self.logger.error(f"[-] Failed to initialize plugin: {plugin_name}")
                return None
                
        except Exception as e:
            self.logger.error(f"[-] Error loading plugin {plugin_name}: {e}")
            return None
    
    def load_all_plugins(self) -> Dict[str, BasePlugin]:
        """Load all discovered plugins"""
        loaded = {}
        
        for plugin_name in self.discovered_plugins:
            plugin = self.load_plugin(plugin_name)
            if plugin:
                loaded[plugin_name] = plugin
        
        return loaded
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a specific plugin"""
        if plugin_name not in self.loaded_plugins:
            self.logger.warning(f"[!] Plugin {plugin_name} is not loaded")
            return False
        
        try:
            plugin = self.loaded_plugins[plugin_name]
            plugin.cleanup()
            del self.loaded_plugins[plugin_name]
            self.logger.success(f"[+] Unloaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error unloading plugin {plugin_name}: {e}")
            return False
    
    def get_loaded_plugins(self) -> Dict[str, BasePlugin]:
        """Get all loaded plugins"""
        return self.loaded_plugins.copy()
    
    def get_discovered_plugins(self) -> Dict[str, Type[BasePlugin]]:
        """Get all discovered plugins"""
        return self.discovered_plugins.copy()
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """Get plugin information"""
        if plugin_name in self.loaded_plugins:
            return self.loaded_plugins[plugin_name].get_info()
        elif plugin_name in self.discovered_plugins:
            try:
                temp_instance = self.discovered_plugins[plugin_name]()
                return temp_instance.get_info()
            except:
                return None
        return None
    
    def list_available_plugins(self) -> List[Dict[str, Any]]:
        """List all available plugins with their information"""
        plugins = []
        
        # Add discovered plugins
        for name, plugin_class in self.discovered_plugins.items():
            try:
                temp_instance = plugin_class()
                info = temp_instance.get_info()
                plugins.append({
                    'name': name,
                    'info': info.__dict__,
                    'status': 'discovered',
                    'loaded': name in self.loaded_plugins
                })
            except Exception as e:
                self.logger.error(f"[-] Error getting info for plugin {name}: {e}")
        
        return plugins
    
    def reload_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Reload a plugin"""
        # Unload if currently loaded
        if plugin_name in self.loaded_plugins:
            self.unload_plugin(plugin_name)
        
        # Reload the module
        if plugin_name in self.discovered_plugins:
            module = self.discovered_plugins[plugin_name].__module__
            if module in sys.modules:
                importlib.reload(sys.modules[module])
        
        # Load the plugin again
        return self.load_plugin(plugin_name)
    
    def cleanup(self):
        """Cleanup all loaded plugins"""
        for plugin_name in list(self.loaded_plugins.keys()):
            self.unload_plugin(plugin_name)
        
        self.discovered_plugins.clear()
        self.loaded_plugins.clear()
        self.logger.info("[*] Plugin registry cleaned up")
