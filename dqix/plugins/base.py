"""Base classes and interfaces for DQIX plugins.

This module provides the foundation for creating plugins that extend DQIX's functionality.
Plugins can add new probes, output formats, or custom scoring algorithms.

Example:
    To create a new probe plugin:

    ```python
    from dqix.plugins.base import ProbePlugin, register_plugin

    @register_plugin
    class MyProbePlugin(ProbePlugin):
        name = "my_probe"
        version = "1.0.0"
        description = "A custom probe for DQIX"
        
        def get_probes(self):
            return [MyProbe()]
    ```
"""

from __future__ import annotations
from typing import Dict, List, Optional, Type, Any
from abc import ABC, abstractmethod
import importlib
import pkg_resources
import logging

from ..core.probes import Probe
from ..core.output import OutputFormatter

logger = logging.getLogger(__name__)

class Plugin(ABC):
    """Base class for all DQIX plugins."""
    
    name: str
    version: str
    description: str
    
    @abstractmethod
    def initialize(self) -> None:
        """Initialize the plugin.
        
        This method is called when the plugin is loaded.
        Use it to set up any resources needed by the plugin.
        """
        pass
        
    @abstractmethod
    def cleanup(self) -> None:
        """Clean up plugin resources.
        
        This method is called when the plugin is unloaded.
        Use it to clean up any resources used by the plugin.
        """
        pass

class ProbePlugin(Plugin):
    """Plugin that provides additional probes."""
    
    @abstractmethod
    def get_probes(self) -> List[Type[Probe]]:
        """Get the probes provided by this plugin.
        
        Returns:
            List of probe classes
        """
        pass

class OutputPlugin(Plugin):
    """Plugin that provides additional output formats."""
    
    @abstractmethod
    def get_formatters(self) -> List[Type[OutputFormatter]]:
        """Get the output formatters provided by this plugin.
        
        Returns:
            List of output formatter classes
        """
        pass

class ScoringPlugin(Plugin):
    """Plugin that provides custom scoring algorithms."""
    
    @abstractmethod
    def get_scoring_methods(self) -> Dict[str, Any]:
        """Get the scoring methods provided by this plugin.
        
        Returns:
            Dictionary mapping method names to scoring functions
        """
        pass

# Plugin registry
PLUGINS: Dict[str, Plugin] = {}

def register_plugin(cls: Type[Plugin]) -> Type[Plugin]:
    """Register a plugin class.
    
    Args:
        cls: Plugin class to register
        
    Returns:
        The registered plugin class
    """
    if not hasattr(cls, 'name'):
        raise ValueError(f"Plugin class {cls.__name__} must define 'name' attribute")
    PLUGINS[cls.name] = cls()
    return cls

def load_plugins() -> None:
    """Load all installed plugins.
    
    This function discovers and loads plugins using Python's entry points.
    Plugins should define their entry points in their setup.py or pyproject.toml.
    """
    for entry_point in pkg_resources.iter_entry_points('dqix.plugins'):
        try:
            plugin_class = entry_point.load()
            plugin = plugin_class()
            PLUGINS[plugin.name] = plugin
            plugin.initialize()
            logger.info(f"Loaded plugin: {plugin.name} v{plugin.version}")
        except Exception as e:
            logger.error(f"Failed to load plugin {entry_point.name}: {e}")

def unload_plugins() -> None:
    """Unload all loaded plugins."""
    for plugin in PLUGINS.values():
        try:
            plugin.cleanup()
        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin.name}: {e}")
    PLUGINS.clear() 