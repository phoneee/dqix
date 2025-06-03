"""Plugin loader for DQIX.

This module provides functionality to discover and load plugins using Python's
entry points system. It handles loading of probe, output, and scoring plugins.
"""

import importlib
import logging
from typing import Dict, List, Optional, Type

from .base import Plugin, ProbePlugin, OutputPlugin, ScoringPlugin

logger = logging.getLogger(__name__)

def discover_plugins() -> Dict[str, Type[Plugin]]:
    """Discover all available plugins using entry points.
    
    Returns:
        Dict mapping plugin names to their classes
    """
    try:
        import pkg_resources
    except ImportError:
        logger.warning("pkg_resources not available, no plugins will be loaded")
        return {}
        
    plugins = {}
    
    for entry_point in pkg_resources.iter_entry_points('dqix.plugins'):
        try:
            plugin_class = entry_point.load()
            plugins[entry_point.name] = plugin_class
            logger.info(f"Loaded plugin: {entry_point.name}")
        except Exception as e:
            logger.error(f"Failed to load plugin {entry_point.name}: {e}")
            
    return plugins

def load_plugin(name: str) -> Optional[Plugin]:
    """Load a specific plugin by name.
    
    Args:
        name: Name of the plugin to load
        
    Returns:
        Plugin instance if found and loaded successfully, None otherwise
    """
    plugins = discover_plugins()
    
    if name not in plugins:
        logger.error(f"Plugin not found: {name}")
        return None
        
    try:
        plugin_class = plugins[name]
        plugin = plugin_class()
        plugin.initialize()
        return plugin
    except Exception as e:
        logger.error(f"Failed to initialize plugin {name}: {e}")
        return None

def get_probe_plugins() -> List[ProbePlugin]:
    """Get all available probe plugins.
    
    Returns:
        List of initialized probe plugins
    """
    plugins = discover_plugins()
    probe_plugins = []
    
    for name, plugin_class in plugins.items():
        if issubclass(plugin_class, ProbePlugin):
            try:
                plugin = plugin_class()
                plugin.initialize()
                probe_plugins.append(plugin)
            except Exception as e:
                logger.error(f"Failed to initialize probe plugin {name}: {e}")
                
    return probe_plugins

def get_output_plugins() -> List[OutputPlugin]:
    """Get all available output plugins.
    
    Returns:
        List of initialized output plugins
    """
    plugins = discover_plugins()
    output_plugins = []
    
    for name, plugin_class in plugins.items():
        if issubclass(plugin_class, OutputPlugin):
            try:
                plugin = plugin_class()
                plugin.initialize()
                output_plugins.append(plugin)
            except Exception as e:
                logger.error(f"Failed to initialize output plugin {name}: {e}")
                
    return output_plugins

def get_scoring_plugins() -> List[ScoringPlugin]:
    """Get all available scoring plugins.
    
    Returns:
        List of initialized scoring plugins
    """
    plugins = discover_plugins()
    scoring_plugins = []
    
    for name, plugin_class in plugins.items():
        if issubclass(plugin_class, ScoringPlugin):
            try:
                plugin = plugin_class()
                plugin.initialize()
                scoring_plugins.append(plugin)
            except Exception as e:
                logger.error(f"Failed to initialize scoring plugin {name}: {e}")
                
    return scoring_plugins 