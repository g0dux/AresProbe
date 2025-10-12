"""
AresProbe Advanced Plugin System
Hot-reload, dependency injection, and advanced plugin management
"""

import os
import sys
import importlib
import importlib.util
import inspect
import asyncio
import threading
import time
from typing import Dict, List, Optional, Any, Type, Callable, Union
from dataclasses import dataclass, field
from pathlib import Path
import json
import zipfile
import tempfile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

from .logger import Logger
from .async_engine import AsyncEngine


@dataclass
class PluginMetadata:
    """Plugin metadata"""
    name: str
    version: str
    description: str
    author: str
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    api_version: str = "1.0"
    category: str = "general"
    tags: List[str] = field(default_factory=list)


@dataclass
class PluginConfig:
    """Plugin configuration"""
    enabled: bool = True
    auto_reload: bool = True
    timeout: float = 30.0
    max_memory: int = 100 * 1024 * 1024  # 100MB
    sandbox_mode: bool = True
    log_level: str = "INFO"


class DependencyInjector:
    """Advanced dependency injection system"""
    
    def __init__(self):
        self.services: Dict[str, Any] = {}
        self.singletons: Dict[str, Any] = {}
        self.factories: Dict[str, Callable] = {}
    
    def register_service(self, name: str, service: Any, singleton: bool = False):
        """Register a service"""
        if singleton:
            self.singletons[name] = service
        else:
            self.services[name] = service
    
    def register_factory(self, name: str, factory: Callable):
        """Register a factory function"""
        self.factories[name] = factory
    
    def get_service(self, name: str, *args, **kwargs):
        """Get a service instance"""
        # Check singletons first
        if name in self.singletons:
            return self.singletons[name]
        
        # Check factories
        if name in self.factories:
            return self.factories[name](*args, **kwargs)
        
        # Check regular services
        if name in self.services:
            return self.services[name]
        
        raise ValueError(f"Service '{name}' not found")
    
    def inject_dependencies(self, cls: Type) -> Type:
        """Inject dependencies into a class"""
        if not hasattr(cls, '__init__'):
            return cls
        
        original_init = cls.__init__
        signature = inspect.signature(original_init)
        
        def new_init(self, *args, **kwargs):
            # Get parameter names from signature
            params = list(signature.parameters.keys())[1:]  # Skip 'self'
            
            # Inject dependencies
            for param in params:
                if param not in kwargs and param in self.services:
                    kwargs[param] = self.get_service(param)
            
            original_init(self, *args, **kwargs)
        
        cls.__init__ = new_init
        return cls


class PluginFileHandler(FileSystemEventHandler):
    """File system event handler for plugin hot-reload"""
    
    def __init__(self, plugin_manager):
        self.plugin_manager = plugin_manager
        self.logger = plugin_manager.logger
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.suffix == '.py':
            plugin_name = self._get_plugin_name_from_path(file_path)
            if plugin_name:
                self.logger.info(f"[*] Plugin file modified: {plugin_name}")
                asyncio.create_task(self.plugin_manager.reload_plugin(plugin_name))
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.suffix == '.py':
            plugin_name = self._get_plugin_name_from_path(file_path)
            if plugin_name:
                self.logger.info(f"[*] New plugin file created: {plugin_name}")
                asyncio.create_task(self.plugin_manager.load_plugin(plugin_name))
    
    def _get_plugin_name_from_path(self, file_path: Path) -> Optional[str]:
        """Extract plugin name from file path"""
        try:
            # Find plugin directory
            parts = file_path.parts
            for i, part in enumerate(parts):
                if part == 'plugins':
                    if i + 1 < len(parts):
                        return parts[i + 1]
            return None
        except Exception:
            return None


class PluginSandbox:
    """Sandbox environment for plugin execution"""
    
    def __init__(self, config: PluginConfig, logger: Logger):
        self.config = config
        self.logger = logger
        self.restricted_imports = {
            'os', 'sys', 'subprocess', 'socket', 'urllib', 'http',
            'threading', 'multiprocessing', 'ctypes', '__import__'
        }
        self.allowed_imports = {
            'json', 'time', 'datetime', 'collections', 'itertools',
            're', 'math', 'random', 'string', 'hashlib', 'base64'
        }
    
    def create_sandbox(self, plugin_name: str):
        """Create a sandbox environment for plugin"""
        # Create restricted globals
        sandbox_globals = {
            '__builtins__': {
                'len': len, 'str': str, 'int': int, 'float': float,
                'bool': bool, 'list': list, 'dict': dict, 'tuple': tuple,
                'set': set, 'range': range, 'enumerate': enumerate,
                'zip': zip, 'map': map, 'filter': filter, 'sorted': sorted,
                'print': print, 'input': input, 'open': self._safe_open
            }
        }
        
        return sandbox_globals
    
    def _safe_open(self, *args, **kwargs):
        """Safe file opening with restrictions"""
        if not self.config.sandbox_mode:
            return open(*args, **kwargs)
        
        # Restrict file access in sandbox mode
        raise PermissionError("File access restricted in sandbox mode")


class AdvancedPlugin:
    """Base class for advanced plugins"""
    
    def __init__(self, metadata: PluginMetadata, config: PluginConfig, logger: Logger):
        self.metadata = metadata
        self.config = config
        self.logger = logger
        self.dependencies = {}
        self.is_loaded = False
        self.is_running = False
    
    async def initialize(self, injector: DependencyInjector):
        """Initialize plugin with dependency injection"""
        try:
            # Inject dependencies
            for dep_name in self.metadata.dependencies:
                self.dependencies[dep_name] = injector.get_service(dep_name)
            
            # Call plugin-specific initialization
            await self.on_initialize()
            self.is_loaded = True
            self.logger.info(f"[+] Plugin '{self.metadata.name}' initialized")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to initialize plugin '{self.metadata.name}': {e}")
            raise
    
    async def start(self):
        """Start plugin execution"""
        if not self.is_loaded:
            raise RuntimeError("Plugin not initialized")
        
        self.is_running = True
        await self.on_start()
        self.logger.info(f"[+] Plugin '{self.metadata.name}' started")
    
    async def stop(self):
        """Stop plugin execution"""
        self.is_running = False
        await self.on_stop()
        self.logger.info(f"[+] Plugin '{self.metadata.name}' stopped")
    
    async def cleanup(self):
        """Cleanup plugin resources"""
        await self.on_cleanup()
        self.is_loaded = False
        self.logger.info(f"[+] Plugin '{self.metadata.name}' cleaned up")
    
    # Plugin lifecycle hooks (to be overridden)
    async def on_initialize(self):
        """Called during plugin initialization"""
        pass
    
    async def on_start(self):
        """Called when plugin starts"""
        pass
    
    async def on_stop(self):
        """Called when plugin stops"""
        pass
    
    async def on_cleanup(self):
        """Called during plugin cleanup"""
        pass
    
    # Plugin execution hooks
    async def execute(self, *args, **kwargs):
        """Execute plugin main functionality"""
        raise NotImplementedError("Plugin must implement execute method")


class AdvancedPluginManager:
    """Advanced plugin manager with hot-reload and dependency injection"""
    
    def __init__(self, plugins_dir: str = "plugins", logger: Optional[Logger] = None):
        self.plugins_dir = Path(plugins_dir)
        self.logger = logger or Logger()
        self.plugins: Dict[str, AdvancedPlugin] = {}
        self.plugin_configs: Dict[str, PluginConfig] = {}
        self.dependency_injector = DependencyInjector()
        self.sandbox = PluginSandbox(PluginConfig(), self.logger)
        self.file_observer = None
        self.is_watching = False
        
        # Create plugins directory if it doesn't exist
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Register core services
        self._register_core_services()
    
    def _register_core_services(self):
        """Register core AresProbe services"""
        self.dependency_injector.register_service('logger', self.logger, singleton=True)
        self.dependency_injector.register_service('plugin_manager', self, singleton=True)
        
        # Register async engine factory
        self.dependency_injector.register_factory('async_engine', self._create_async_engine)
    
    def _create_async_engine(self) -> AsyncEngine:
        """Factory for creating async engine instances"""
        from .async_engine import AsyncEngine
        return AsyncEngine()
    
    def start_file_watching(self):
        """Start watching plugin files for changes"""
        if self.is_watching:
            return
        
        self.file_observer = Observer()
        event_handler = PluginFileHandler(self)
        self.file_observer.schedule(event_handler, str(self.plugins_dir), recursive=True)
        self.file_observer.start()
        self.is_watching = True
        self.logger.info("[*] Plugin file watching started")
    
    def stop_file_watching(self):
        """Stop watching plugin files"""
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            self.is_watching = False
            self.logger.info("[*] Plugin file watching stopped")
    
    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a plugin"""
        try:
            plugin_path = self.plugins_dir / plugin_name
            
            if not plugin_path.exists():
                self.logger.error(f"[-] Plugin directory not found: {plugin_name}")
                return False
            
            # Load plugin metadata
            metadata = await self._load_plugin_metadata(plugin_path)
            if not metadata:
                return False
            
            # Create plugin instance
            plugin_class = await self._load_plugin_class(plugin_path, metadata.name)
            if not plugin_class:
                return False
            
            config = self.plugin_configs.get(plugin_name, PluginConfig())
            plugin_instance = plugin_class(metadata, config, self.logger)
            
            # Initialize plugin
            await plugin_instance.initialize(self.dependency_injector)
            
            # Store plugin
            self.plugins[plugin_name] = plugin_instance
            
            # Auto-start if enabled
            if config.enabled:
                await plugin_instance.start()
            
            self.logger.success(f"[+] Plugin '{plugin_name}' loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to load plugin '{plugin_name}': {e}")
            return False
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Hot-reload a plugin"""
        if plugin_name not in self.plugins:
            return await self.load_plugin(plugin_name)
        
        try:
            plugin = self.plugins[plugin_name]
            
            # Stop plugin if running
            if plugin.is_running:
                await plugin.stop()
            
            # Cleanup old plugin
            await plugin.cleanup()
            
            # Remove from memory
            del self.plugins[plugin_name]
            
            # Reload plugin
            return await self.load_plugin(plugin_name)
            
        except Exception as e:
            self.logger.error(f"[-] Failed to reload plugin '{plugin_name}': {e}")
            return False
    
    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name not in self.plugins:
            return False
        
        try:
            plugin = self.plugins[plugin_name]
            
            # Stop plugin if running
            if plugin.is_running:
                await plugin.stop()
            
            # Cleanup plugin
            await plugin.cleanup()
            
            # Remove from memory
            del self.plugins[plugin_name]
            
            self.logger.info(f"[*] Plugin '{plugin_name}' unloaded")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to unload plugin '{plugin_name}': {e}")
            return False
    
    async def load_all_plugins(self):
        """Load all plugins from the plugins directory"""
        self.logger.info("[*] Loading all plugins...")
        
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir() and not plugin_dir.name.startswith('.'):
                await self.load_plugin(plugin_dir.name)
        
        self.logger.info(f"[+] Loaded {len(self.plugins)} plugins")
    
    async def _load_plugin_metadata(self, plugin_path: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from plugin.json"""
        metadata_file = plugin_path / "plugin.json"
        
        if not metadata_file.exists():
            # Create default metadata
            return PluginMetadata(
                name=plugin_path.name,
                version="1.0.0",
                description="No description provided",
                author="Unknown"
            )
        
        try:
            with open(metadata_file, 'r') as f:
                data = json.load(f)
            
            return PluginMetadata(**data)
            
        except Exception as e:
            self.logger.error(f"[-] Failed to load metadata for {plugin_path.name}: {e}")
            return None
    
    async def _load_plugin_class(self, plugin_path: Path, plugin_name: str) -> Optional[Type[AdvancedPlugin]]:
        """Load plugin class from Python file"""
        plugin_file = plugin_path / f"{plugin_name}.py"
        
        if not plugin_file.exists():
            self.logger.error(f"[-] Plugin file not found: {plugin_file}")
            return None
        
        try:
            # Create module spec
            spec = importlib.util.spec_from_file_location(
                f"plugins.{plugin_name}",
                plugin_file
            )
            
            if not spec or not spec.loader:
                self.logger.error(f"[-] Failed to create module spec for {plugin_name}")
                return None
            
            # Load module
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"plugins.{plugin_name}"] = module
            spec.loader.exec_module(module)
            
            # Find plugin class
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, AdvancedPlugin) and 
                    obj != AdvancedPlugin):
                    return obj
            
            self.logger.error(f"[-] No plugin class found in {plugin_name}")
            return None
            
        except Exception as e:
            self.logger.error(f"[-] Failed to load plugin class for {plugin_name}: {e}")
            return None
    
    async def install_plugin_from_zip(self, zip_path: str) -> bool:
        """Install plugin from ZIP file"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                # Extract to temporary directory
                with tempfile.TemporaryDirectory() as temp_dir:
                    zip_file.extractall(temp_dir)
                    
                    # Find plugin.json
                    plugin_json = None
                    for root, dirs, files in os.walk(temp_dir):
                        if 'plugin.json' in files:
                            plugin_json = Path(root) / 'plugin.json'
                            break
                    
                    if not plugin_json:
                        self.logger.error("[-] plugin.json not found in ZIP file")
                        return False
                    
                    # Load metadata
                    with open(plugin_json, 'r') as f:
                        metadata = json.load(f)
                    
                    plugin_name = metadata['name']
                    plugin_dir = self.plugins_dir / plugin_name
                    
                    # Remove existing plugin if exists
                    if plugin_dir.exists():
                        import shutil
                        shutil.rmtree(plugin_dir)
                    
                    # Extract plugin files
                    zip_file.extractall(self.plugins_dir)
                    
                    # Load the new plugin
                    return await self.load_plugin(plugin_name)
                    
        except Exception as e:
            self.logger.error(f"[-] Failed to install plugin from ZIP: {e}")
            return False
    
    async def execute_plugin(self, plugin_name: str, *args, **kwargs):
        """Execute a plugin"""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin '{plugin_name}' not found")
        
        plugin = self.plugins[plugin_name]
        if not plugin.is_running:
            raise RuntimeError(f"Plugin '{plugin_name}' is not running")
        
        return await plugin.execute(*args, **kwargs)
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get plugin information"""
        if plugin_name not in self.plugins:
            return None
        
        plugin = self.plugins[plugin_name]
        return {
            'name': plugin.metadata.name,
            'version': plugin.metadata.version,
            'description': plugin.metadata.description,
            'author': plugin.metadata.author,
            'is_loaded': plugin.is_loaded,
            'is_running': plugin.is_running,
            'dependencies': plugin.metadata.dependencies,
            'permissions': plugin.metadata.permissions
        }
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins"""
        return [self.get_plugin_info(name) for name in self.plugins.keys()]
    
    async def cleanup(self):
        """Cleanup plugin manager"""
        # Stop file watching
        self.stop_file_watching()
        
        # Stop and cleanup all plugins
        for plugin_name, plugin in self.plugins.items():
            try:
                if plugin.is_running:
                    await plugin.stop()
                await plugin.cleanup()
            except Exception as e:
                self.logger.error(f"[-] Error cleaning up plugin '{plugin_name}': {e}")
        
        self.plugins.clear()
        self.logger.info("[*] Plugin manager cleaned up")
