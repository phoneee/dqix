"""
DQIX - Domain Quality Index
Modern Internet Observability Platform with Modular Architecture

Core Principles:
- Lightweight core with optional enhancements
- Lazy loading of dependencies
- Graceful degradation when features unavailable
"""

import importlib.util
import warnings
from typing import Any, Dict, Optional

__version__ = "2.0.0"
__author__ = "DQIX Team"

# Feature availability tracking
_feature_cache: dict[str, bool] = {}

def _check_feature_available(feature: str, dependencies: list) -> bool:
    """Check if an optional feature is available by testing its dependencies."""
    if feature in _feature_cache:
        return _feature_cache[feature]

    try:
        for dep in dependencies:
            if importlib.util.find_spec(dep) is None:
                _feature_cache[feature] = False
                return False
        _feature_cache[feature] = True
        return True
    except Exception:
        _feature_cache[feature] = False
        return False

def _lazy_import(module_name: str, feature_name: str, install_hint: str = None):
    """Lazy import with helpful error messages."""
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        hint = install_hint or f"pip install dqix[{feature_name}]"
        raise ImportError(
            f"Feature '{feature_name}' requires additional dependencies. "
            f"Install with: {hint}"
        ) from e

# Feature availability checks
def has_dashboard() -> bool:
    """Check if dashboard feature is available."""
    return _check_feature_available('dashboard', ['fastapi', 'uvicorn', 'jinja2'])

def has_export() -> bool:
    """Check if export feature is available."""
    return _check_feature_available('export', ['weasyprint', 'reportlab'])

def has_visualization() -> bool:
    """Check if visualization features are available."""
    return _check_feature_available('visualization', ['plotly', 'matplotlib'])

def has_realtime() -> bool:
    """Check if real-time features are available."""
    return _check_feature_available('realtime', ['websockets', 'sse_starlette'])

def has_analysis() -> bool:
    """Check if data analysis features are available."""
    return _check_feature_available('analysis', ['pandas', 'numpy'])

# Lazy importers for optional features
def get_dashboard():
    """Get dashboard module with lazy loading."""
    if not has_dashboard():
        raise ImportError("Dashboard feature not available. Install with: pip install dqix[dashboard]")

    from .interfaces.dashboard import InternetObservabilityDashboard
    return InternetObservabilityDashboard

def get_export():
    """Get export module with lazy loading."""
    if not has_export():
        raise ImportError("Export feature not available. Install with: pip install dqix[export]")

    from .interfaces.export import ExportManager
    return ExportManager

def get_charts():
    """Get visualization module with lazy loading."""
    if not has_visualization():
        raise ImportError("Visualization feature not available. Install with: pip install dqix[charts]")

    try:
        # Import visualization components
        import plotly.express as px
        import plotly.graph_objects as go
        from plotly.subplots import make_subplots

        class ChartGenerator:
            """Chart generation utilities for DQIX reports."""

            @staticmethod
            def create_security_radar(probe_results: list) -> go.Figure:
                """Create radar chart for security assessment."""
                categories = []
                scores = []

                for probe in probe_results:
                    categories.append(probe['probe_id'].replace('_', ' ').title())
                    scores.append(probe['score'] * 100)

                fig = go.Figure()

                fig.add_trace(go.Scatterpolar(
                    r=scores,
                    theta=categories,
                    fill='toself',
                    name='Security Score',
                    line_color='rgb(99, 110, 250)'
                ))

                fig.update_layout(
                    polar={
                        "radialaxis": {
                            "visible": True,
                            "range": [0, 100]
                        }},
                    showlegend=True,
                    title="Security Assessment Radar Chart"
                )

                return fig

            @staticmethod
            def create_score_timeline(assessments: list) -> go.Figure:
                """Create timeline chart for score evolution."""
                dates = []
                scores = []

                for assessment in assessments:
                    dates.append(assessment['timestamp'])
                    scores.append(assessment['overall_score'] * 100)

                fig = go.Figure()

                fig.add_trace(go.Scatter(
                    x=dates,
                    y=scores,
                    mode='lines+markers',
                    name='Security Score',
                    line={"color": 'rgb(99, 110, 250)', "width": 3},
                    marker={"size": 8}
                ))

                fig.update_layout(
                    title="Security Score Timeline",
                    xaxis_title="Date",
                    yaxis_title="Score (%)",
                    yaxis={"range": [0, 100]}
                )

                return fig

            @staticmethod
            def create_comparison_bar(domains_results: list) -> go.Figure:
                """Create bar chart for domain comparison."""
                domains = []
                scores = []
                colors = []

                for result in domains_results:
                    domains.append(result['domain'])
                    score = result['overall_score'] * 100
                    scores.append(score)

                    # Color coding based on score
                    if score >= 90:
                        colors.append('rgb(76, 175, 80)')  # Green
                    elif score >= 70:
                        colors.append('rgb(255, 193, 7)')  # Yellow
                    else:
                        colors.append('rgb(244, 67, 54)')  # Red

                fig = go.Figure()

                fig.add_trace(go.Bar(
                    x=domains,
                    y=scores,
                    marker_color=colors,
                    text=[f"{score:.1f}%" for score in scores],
                    textposition='auto',
                ))

                fig.update_layout(
                    title="Domain Security Comparison",
                    xaxis_title="Domains",
                    yaxis_title="Security Score (%)",
                    yaxis={"range": [0, 100]}
                )

                return fig

            @staticmethod
            def create_probe_breakdown(probe_results: list) -> go.Figure:
                """Create pie chart for probe score breakdown."""
                labels = []
                values = []
                colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']

                for probe in probe_results:
                    labels.append(probe['probe_id'].replace('_', ' ').title())
                    values.append(probe['score'])

                fig = go.Figure()

                fig.add_trace(go.Pie(
                    labels=labels,
                    values=values,
                    marker_colors=colors[:len(labels)],
                    textinfo='label+percent',
                    textposition='auto'
                ))

                fig.update_layout(
                    title="Security Assessment Breakdown"
                )

                return fig

        return ChartGenerator

    except ImportError as e:
        raise ImportError(
            "Charts feature requires plotly. Install with: pip install dqix[charts] or pip install plotly"
        ) from e

# Core imports - always available
from .application.use_cases import DomainAssessmentUseCase
from .domain.entities import AssessmentResult, Domain, ProbeResult
from .infrastructure.factory import create_infrastructure

# Public API
__all__ = [
    # Core classes
    'Domain',
    'ProbeResult',
    'AssessmentResult',
    'DomainAssessmentUseCase',
    'create_infrastructure',

    # Feature detection
    'has_dashboard',
    'has_export',
    'has_visualization',
    'has_realtime',
    'has_analysis',

    # Lazy loaders
    'get_dashboard',
    'get_export',
    'get_charts',

    # Metadata
    '__version__',
    '__author__',
]

# Feature warnings for graceful degradation
def _warn_missing_feature(feature: str, fallback: str = None):
    """Warn about missing optional features."""
    fallback_msg = f" Using {fallback} instead." if fallback else ""
    warnings.warn(
        f"Optional feature '{feature}' not available.{fallback_msg} "
        f"Install with: pip install dqix[{feature}]",
        UserWarning,
        stacklevel=2
    )
