"""DQIX Plugin System.

This package provides the plugin system for DQIX, allowing for extensibility
through plugins that can add new probes, output formats, and scoring methods.
"""

from .base import Plugin, ProbePlugin, OutputPlugin, ScoringPlugin
from .loader import (
    discover_plugins,
    load_plugin,
    get_probe_plugins,
    get_output_plugins,
    get_scoring_plugins,
)

__all__ = [
    'Plugin',
    'ProbePlugin',
    'OutputPlugin',
    'ScoringPlugin',
    'discover_plugins',
    'load_plugin',
    'get_probe_plugins',
    'get_output_plugins',
    'get_scoring_plugins',
] 