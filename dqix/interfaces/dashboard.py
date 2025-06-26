"""
DQIX Modern Web Dashboard

Real-time Internet Observability Dashboard implementing modern design principles:
- Clear visual hierarchy with purposeful color usage
- Simplified interface focusing on key metrics
- Interactive elements with visual cues
- Responsive design optimized for all screen sizes
- Progressive disclosure of complex information
"""

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

# Modern web framework imports with graceful degradation
try:
    import plotly.graph_objs as go
    import plotly.utils
    from flask import Flask, jsonify, render_template, request, send_from_directory
    from flask_socketio import SocketIO, emit
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False


# Initialize console
console = Console()

class ModernInternetObservabilityDashboard:
    """
    Modern Internet Observability Dashboard implementing best practices:

    Design Principles (based on Qlik Dashboard Design Guide):
    1. Visual Hierarchy - Most important metrics prominently displayed
    2. Color Psychology - Strategic use of color to guide attention
    3. Simplified Interface - Minimal clutter, maximum insight
    4. Interactive Elements - Clear visual cues for user actions
    5. Responsive Design - Optimized for desktop, tablet, mobile
    6. Progressive Disclosure - Complex details available on demand
    """

    def __init__(
        self,
        port: int = 8000,
        host: str = "localhost",
        theme: str = "professional",
        auto_refresh: int = 0,
        demo_mode: bool = False
    ):
        if not WEB_AVAILABLE:
            raise ImportError(
                "Dashboard dependencies missing. Install with:\n"
                "pip install flask flask-socketio plotly dash dash-bootstrap-components"
            )

        self.port = port
        self.host = host
        self.theme = theme
        self.auto_refresh = auto_refresh
        self.demo_mode = demo_mode
        self.console = Console()

        # Dashboard state
        self.assessment_cache = {}
        self.monitoring_domains = []
        self.active_scans = {}
        self.dashboard_stats = {
            "total_scans": 0,
            "avg_score": 0.0,
            "last_scan": None,
            "top_domains": []
        }

        # Create Flask app with modern configuration
        self.app = Flask(
            __name__,
            template_folder=str(Path(__file__).parent.parent / "templates"),
            static_folder=str(Path(__file__).parent.parent / "static")
        )

        # Configure Flask for production readiness
        self.app.config.update(
            SECRET_KEY='dqix-dashboard-key',
            JSON_SORT_KEYS=False,
            JSONIFY_PRETTYPRINT_REGULAR=True
        )

        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(
            self.app,
            cors_allowed_origins="*",
            async_mode='threading'
        )

        self._setup_routes()
        self._setup_websocket_handlers()
        self._create_dashboard_template()

    def _setup_routes(self):
        """Setup modern RESTful API routes with proper error handling."""

        @self.app.route('/')
        def dashboard_home():
            """Main dashboard interface with modern design."""
            return render_template(
                'modern_dashboard.html',
                theme=self.theme,
                auto_refresh=self.auto_refresh,
                demo_mode=self.demo_mode,
                stats=self.dashboard_stats
            )

        @self.app.route('/api/scan', methods=['POST'])
        def api_scan_domain():
            """Enhanced domain scanning API with real-time updates."""
            try:
                data = request.get_json()
                domain = data.get('domain', '').strip()
                options = data.get('options', {})

                if not domain:
                    return jsonify({'error': 'Domain required'}), 400

                # Start async scan with WebSocket updates
                scan_id = f"scan_{int(time.time())}"
                self.active_scans[scan_id] = {
                    'domain': domain,
                    'status': 'starting',
                    'progress': 0
                }

                # Emit scan started event
                self.socketio.emit('scan_started', {
                    'scan_id': scan_id,
                    'domain': domain
                })

                # Start background scan
                threading.Thread(
                    target=self._perform_background_scan,
                    args=(scan_id, domain, options),
                    daemon=True
                ).start()

                return jsonify({
                    'scan_id': scan_id,
                    'status': 'started',
                    'domain': domain
                })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/scan/<scan_id>')
        def api_get_scan_status(scan_id):
            """Get real-time scan status and results."""
            if scan_id not in self.active_scans:
                return jsonify({'error': 'Scan not found'}), 404

            return jsonify(self.active_scans[scan_id])

        @self.app.route('/api/stats')
        def api_get_dashboard_stats():
            """Get dashboard statistics and metrics."""
            return jsonify(self.dashboard_stats)

        @self.app.route('/api/health')
        def api_health_check():
            """Health check endpoint for monitoring."""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '2.0.0',
                'active_scans': len(self.active_scans)
            })

    def _setup_websocket_handlers(self):
        """Setup WebSocket handlers for real-time communication."""

        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection."""
            emit('connected', {'message': 'Connected to DQIX Dashboard'})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection."""
            pass

        @self.socketio.on('request_scan')
        def handle_scan_request(data):
            """Handle real-time scan requests."""
            domain = data.get('domain')
            if domain:
                # Emit immediate acknowledgment
                emit('scan_queued', {'domain': domain})

    def _perform_background_scan(self, scan_id: str, domain: str, options: dict[str, Any]):
        """Perform domain scan in background with progress updates."""
        try:
            # Update scan status
            self.active_scans[scan_id].update({
                'status': 'scanning',
                'progress': 10
            })
            self.socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 10,
                'message': 'Starting security assessment...'
            })

            # Simulate comprehensive scan (replace with actual implementation)
            if self.demo_mode:
                result = self._generate_demo_result(domain)
            else:
                result = self._perform_real_scan(domain, options)

            # Update progress
            self.active_scans[scan_id].update({
                'status': 'completed',
                'progress': 100,
                'result': result
            })

            # Cache result
            self.assessment_cache[domain] = result

            # Update dashboard stats
            self._update_dashboard_stats(result)

            # Emit completion
            self.socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'domain': domain,
                'result': result
            })

        except Exception as e:
            self.active_scans[scan_id].update({
                'status': 'failed',
                'progress': 0,
                'error': str(e)
            })

            self.socketio.emit('scan_failed', {
                'scan_id': scan_id,
                'error': str(e)
            })

    def _generate_demo_result(self, domain: str) -> dict[str, Any]:
        """Generate realistic demo data for dashboard testing."""
        import random

        # Demo domains with realistic scores
        demo_scores = {
            'github.com': {'overall': 0.92, 'tls': 0.95, 'https': 0.90, 'dns': 0.88, 'headers': 0.94},
            'google.com': {'overall': 0.88, 'tls': 0.85, 'https': 0.92, 'dns': 0.95, 'headers': 0.82},
            'cloudflare.com': {'overall': 0.96, 'tls': 0.98, 'https': 0.95, 'dns': 0.98, 'headers': 0.92},
            'microsoft.com': {'overall': 0.85, 'tls': 0.88, 'https': 0.85, 'dns': 0.82, 'headers': 0.86}
        }

        scores = demo_scores.get(domain, {
            'overall': random.uniform(0.6, 0.95),
            'tls': random.uniform(0.7, 0.98),
            'https': random.uniform(0.6, 0.95),
            'dns': random.uniform(0.5, 0.92),
            'headers': random.uniform(0.4, 0.90)
        })

        return {
            'domain': domain,
            'overall_score': scores['overall'],
            'security_grade': self._calculate_grade(scores['overall']),
            'compliance_level': self._calculate_compliance_level(scores['overall']),
            'timestamp': datetime.now().isoformat(),
            'probe_results': [
                {
                    'probe_id': 'tls',
                    'category': 'security',
                    'score': scores['tls'],
                    'status': 'pass' if scores['tls'] > 0.7 else 'warning',
                    'details': {
                        'version': 'TLS 1.3',
                        'cipher_strength': 'Strong',
                        'certificate_valid': True
                    }
                },
                {
                    'probe_id': 'https',
                    'category': 'security',
                    'score': scores['https'],
                    'status': 'pass' if scores['https'] > 0.7 else 'warning',
                    'details': {
                        'redirect_https': True,
                        'hsts_enabled': True,
                        'secure_cookies': True
                    }
                },
                {
                    'probe_id': 'dns',
                    'category': 'infrastructure',
                    'score': scores['dns'],
                    'status': 'pass' if scores['dns'] > 0.6 else 'warning',
                    'details': {
                        'dnssec_enabled': scores['dns'] > 0.8,
                        'response_time': f"{random.randint(10, 50)}ms",
                        'authoritative': True
                    }
                },
                {
                    'probe_id': 'security_headers',
                    'category': 'application',
                    'score': scores['headers'],
                    'status': 'pass' if scores['headers'] > 0.6 else 'warning',
                    'details': {
                        'csp_enabled': scores['headers'] > 0.7,
                        'xss_protection': True,
                        'frame_options': 'DENY'
                    }
                }
            ],
            'recommendations': self._generate_recommendations(scores),
            'execution_time': random.uniform(2.5, 8.2)
        }

    def _perform_real_scan(self, domain: str, options: dict[str, Any]) -> dict[str, Any]:
        """Perform actual domain assessment (placeholder for real implementation)."""
        # This would integrate with the actual DQIX assessment engine
        # For now, return demo data
        return self._generate_demo_result(domain)

    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade from score."""
        if score >= 0.9:
            return 'A+'
        elif score >= 0.8:
            return 'A'
        elif score >= 0.7:
            return 'B+'
        elif score >= 0.6:
            return 'B'
        elif score >= 0.5:
            return 'C'
        else:
            return 'F'

    def _calculate_compliance_level(self, score: float) -> str:
        """Calculate compliance level from score."""
        if score >= 0.9:
            return 'excellent'
        elif score >= 0.8:
            return 'good'
        elif score >= 0.6:
            return 'fair'
        else:
            return 'poor'

    def _generate_recommendations(self, scores: dict[str, float]) -> list[str]:
        """Generate actionable recommendations based on scores."""
        recommendations = []

        if scores['tls'] < 0.8:
            recommendations.append("Upgrade to TLS 1.3 for enhanced security")
        if scores['https'] < 0.8:
            recommendations.append("Enable HSTS to prevent protocol downgrade attacks")
        if scores['dns'] < 0.7:
            recommendations.append("Implement DNSSEC for DNS integrity protection")
        if scores['headers'] < 0.7:
            recommendations.append("Add Content Security Policy headers")

        return recommendations

    def _update_dashboard_stats(self, result: dict[str, Any]):
        """Update dashboard statistics with new scan result."""
        self.dashboard_stats['total_scans'] += 1
        self.dashboard_stats['last_scan'] = result['timestamp']

        # Update average score
        current_avg = self.dashboard_stats['avg_score']
        total_scans = self.dashboard_stats['total_scans']
        new_score = result['overall_score']

        self.dashboard_stats['avg_score'] = (
            (current_avg * (total_scans - 1) + new_score) / total_scans
        )

        # Update top domains
        domain_entry = {
            'domain': result['domain'],
            'score': result['overall_score'],
            'grade': result['security_grade']
        }

        self.dashboard_stats['top_domains'].append(domain_entry)
        self.dashboard_stats['top_domains'] = sorted(
            self.dashboard_stats['top_domains'],
            key=lambda x: x['score'],
            reverse=True
        )[:10]  # Keep top 10

    def _create_dashboard_template(self):
        """Create modern dashboard template with enhanced design."""

        templates_dir = Path(__file__).parent.parent / "templates"
        templates_dir.mkdir(exist_ok=True)

        template_file = templates_dir / "modern_dashboard.html"

        # Create enhanced template based on modern design principles
        template_content = '''<!DOCTYPE html>
<html lang="en" data-theme="{{ theme }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DQIX - Internet Observability Platform</title>

    <!-- Modern CSS Framework -->
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>

    <!-- Icons and Fonts -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">

    <!-- Vue.js for Interactivity -->
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>

    <!-- Socket.IO for Real-time Updates -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>

    <style>
        body { font-family: 'Inter', sans-serif; }
        .gradient-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-hover { transition: all 0.3s ease; }
        .card-hover:hover { transform: translateY(-2px); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); }
        .pulse-dot { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body class="bg-base-200 min-h-screen">
    <div id="app">
        <!-- Enhanced Navigation -->
        <div class="navbar bg-base-100 shadow-lg sticky top-0 z-50">
            <div class="navbar-start">
                <a class="btn btn-ghost text-xl font-bold">
                    <i class="fas fa-globe text-primary"></i>
                    <span>DQIX</span>
                </a>
            </div>

            <div class="navbar-center hidden lg:flex">
                <ul class="menu menu-horizontal px-1">
                    <li><a @click="currentView = 'scanner'" :class="currentView === 'scanner' ? 'active' : ''">
                        <i class="fas fa-search"></i> Internet Scanner
                    </a></li>
                    <li><a @click="currentView = 'monitor'" :class="currentView === 'monitor' ? 'active' : ''">
                        <i class="fas fa-chart-line"></i> Monitor
                    </a></li>
                </ul>
            </div>

            <div class="navbar-end">
                <div class="flex items-center mr-4">
                    <span class="pulse-dot bg-success w-2 h-2 rounded-full mr-2" v-if="isConnected"></span>
                    <span class="text-sm opacity-70">{{ isConnected ? 'Connected' : 'Disconnected' }}</span>
                </div>
            </div>
        </div>

        <!-- Dashboard Stats Bar -->
        <div class="bg-gradient-primary text-white p-4">
            <div class="container mx-auto">
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                    <div>
                        <div class="text-2xl font-bold">{{ dashboardStats.total_scans }}</div>
                        <div class="text-sm opacity-80">Total Scans</div>
                    </div>
                    <div>
                        <div class="text-2xl font-bold">{{ Math.round(dashboardStats.avg_score * 100) }}%</div>
                        <div class="text-sm opacity-80">Average Score</div>
                    </div>
                    <div>
                        <div class="text-2xl font-bold">{{ activeScans }}</div>
                        <div class="text-sm opacity-80">Active Scans</div>
                    </div>
                    <div>
                        <div class="text-2xl font-bold">Online</div>
                        <div class="text-sm opacity-80">Status</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="container mx-auto p-6">

            <!-- Scanner View -->
            <div v-if="currentView === 'scanner'">

                <!-- Quick Scan Card -->
                <div class="card bg-base-100 shadow-xl mb-6 card-hover">
                    <div class="card-body">
                        <h2 class="card-title text-2xl mb-4">
                            <i class="fas fa-search-location text-primary"></i>
                            Internet Security Scanner
                        </h2>

                        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            <div class="lg:col-span-2">
                                <div class="form-control">
                                    <label class="label">
                                        <span class="label-text font-semibold">Domain to analyze</span>
                                        <span class="label-text-alt">Enter without protocol</span>
                                    </label>
                                    <div class="input-group">
                                        <input
                                            v-model="scanDomain"
                                            type="text"
                                            placeholder="github.com"
                                            class="input input-bordered flex-1"
                                            @keyup.enter="startScan"
                                            :disabled="isScanning"
                                        >
                                        <button
                                            @click="startScan"
                                            class="btn btn-primary"
                                            :class="{ 'loading': isScanning }"
                                            :disabled="!scanDomain || isScanning"
                                        >
                                            <i v-if="!isScanning" class="fas fa-search mr-2"></i>
                                            {{ isScanning ? 'Scanning...' : 'Analyze' }}
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div class="space-y-2">
                                <label class="label">
                                    <span class="label-text font-semibold">Quick Tests</span>
                                </label>
                                <div class="flex flex-wrap gap-2">
                                    <button @click="quickTest('github.com')" class="btn btn-outline btn-sm">
                                        <i class="fab fa-github"></i> GitHub
                                    </button>
                                    <button @click="quickTest('google.com')" class="btn btn-outline btn-sm">
                                        <i class="fab fa-google"></i> Google
                                    </button>
                                    <button @click="quickTest('cloudflare.com')" class="btn btn-outline btn-sm">
                                        <i class="fas fa-cloud"></i> Cloudflare
                                    </button>
                                </div>
                            </div>
                        </div>

                        <!-- Scan Progress -->
                        <div v-if="scanProgress > 0 && scanProgress < 100" class="mt-4">
                            <div class="flex justify-between text-sm mb-1">
                                <span>{{ scanMessage }}</span>
                                <span>{{ scanProgress }}%</span>
                            </div>
                            <progress class="progress progress-primary w-full" :value="scanProgress" max="100"></progress>
                        </div>
                    </div>
                </div>

                <!-- Results Display -->
                <div v-if="latestResult" class="grid grid-cols-1 xl:grid-cols-3 gap-6">

                    <!-- Overall Score Card -->
                    <div class="card bg-base-100 shadow-xl card-hover">
                        <div class="card-body text-center">
                            <h3 class="card-title justify-center mb-4">
                                <i class="fas fa-trophy text-warning"></i>
                                Internet Health Score
                            </h3>

                            <div class="mb-4">
                                <div class="text-5xl font-bold mb-2" :class="getScoreColorClass(latestResult.overall_score)">
                                    {{ Math.round(latestResult.overall_score * 100) }}%
                                </div>
                                <div class="badge badge-lg" :class="getGradeBadgeClass(latestResult.security_grade)">
                                    Grade {{ latestResult.security_grade }}
                                </div>
                            </div>

                            <div class="w-full">
                                <div class="text-sm mb-2">{{ latestResult.compliance_level.toUpperCase() }} Compliance</div>
                                <progress
                                    class="progress progress-primary w-full"
                                    :value="latestResult.overall_score * 100"
                                    max="100"
                                ></progress>
                            </div>
                        </div>
                    </div>

                    <!-- Probe Results -->
                    <div class="xl:col-span-2">
                        <div class="card bg-base-100 shadow-xl card-hover">
                            <div class="card-body">
                                <h3 class="card-title mb-4">
                                    <i class="fas fa-shield-alt text-primary"></i>
                                    Security Assessment Details
                                </h3>

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div v-for="probe in latestResult.probe_results" :key="probe.probe_id"
                                         class="p-4 rounded-lg border border-base-300">
                                        <div class="flex items-center justify-between mb-2">
                                            <div class="flex items-center">
                                                <i :class="getProbeIcon(probe.probe_id)" class="mr-3 text-lg"></i>
                                                <span class="font-semibold">{{ formatProbeName(probe.probe_id) }}</span>
                                            </div>
                                            <div class="text-right">
                                                <div class="text-lg font-bold" :class="getScoreColorClass(probe.score)">
                                                    {{ Math.round(probe.score * 100) }}%
                                                </div>
                                                <div class="badge badge-sm" :class="getStatusBadgeClass(probe.status)">
                                                    {{ probe.status }}
                                                </div>
                                            </div>
                                        </div>

                                        <!-- Probe Details -->
                                        <div class="text-sm opacity-70">
                                            <div v-for="(value, key) in probe.details" :key="key" class="flex justify-between">
                                                <span>{{ formatDetailKey(key) }}:</span>
                                                <span>{{ formatDetailValue(value) }}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Recommendations -->
                                <div v-if="latestResult.recommendations && latestResult.recommendations.length > 0" class="mt-6">
                                    <h4 class="font-semibold mb-3 flex items-center">
                                        <i class="fas fa-lightbulb text-warning mr-2"></i>
                                        Recommendations
                                    </h4>
                                    <ul class="space-y-2">
                                        <li v-for="rec in latestResult.recommendations" :key="rec"
                                            class="flex items-start">
                                            <i class="fas fa-arrow-right text-primary mr-2 mt-1"></i>
                                            <span class="text-sm">{{ rec }}</span>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Monitor View -->
            <div v-if="currentView === 'monitor'" class="space-y-6">
                <div class="text-center py-12">
                    <i class="fas fa-chart-line text-6xl text-primary opacity-50"></i>
                    <h2 class="text-2xl font-bold mt-4">Real-time Monitoring</h2>
                    <p class="text-base-content/70 mt-2">Continuous domain monitoring coming soon</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const { createApp } = Vue;

        createApp({
            data() {
                return {
                    // App State
                    currentView: 'scanner',
                    isConnected: false,

                    // Scan State
                    scanDomain: '',
                    isScanning: false,
                    scanProgress: 0,
                    scanMessage: '',
                    latestResult: null,

                    // Dashboard Stats
                    dashboardStats: {{ stats | tojson }},
                    activeScans: 0
                }
            },

            mounted() {
                this.initializeSocketConnection();
                this.loadDashboardStats();
            },

            methods: {
                initializeSocketConnection() {
                    this.socket = io();

                    this.socket.on('connect', () => {
                        this.isConnected = true;
                    });

                    this.socket.on('disconnect', () => {
                        this.isConnected = false;
                    });

                    this.socket.on('scan_progress', (data) => {
                        this.scanProgress = data.progress;
                        this.scanMessage = data.message;
                    });

                    this.socket.on('scan_completed', (data) => {
                        this.latestResult = data.result;
                        this.isScanning = false;
                        this.scanProgress = 0;
                        this.loadDashboardStats();
                    });

                    this.socket.on('scan_failed', (data) => {
                        this.isScanning = false;
                        this.scanProgress = 0;
                        alert('Scan failed: ' + data.error);
                    });
                },

                async startScan() {
                    if (!this.scanDomain.trim()) return;

                    this.isScanning = true;
                    this.scanProgress = 5;
                    this.scanMessage = 'Initializing scan...';

                    try {
                        const response = await fetch('/api/scan', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                domain: this.scanDomain.trim(),
                                options: {}
                            })
                        });

                        if (!response.ok) {
                            throw new Error('Scan request failed');
                        }

                        const result = await response.json();
                        // Progress will be updated via WebSocket

                    } catch (error) {
                        this.isScanning = false;
                        this.scanProgress = 0;
                        alert('Failed to start scan: ' + error.message);
                    }
                },

                quickTest(domain) {
                    this.scanDomain = domain;
                    this.startScan();
                },

                async loadDashboardStats() {
                    try {
                        const response = await fetch('/api/stats');
                        if (response.ok) {
                            this.dashboardStats = await response.json();
                        }
                    } catch (error) {
                        console.error('Failed to load dashboard stats:', error);
                    }
                },

                getScoreColorClass(score) {
                    if (score >= 0.9) return 'text-success';
                    if (score >= 0.8) return 'text-info';
                    if (score >= 0.6) return 'text-warning';
                    return 'text-error';
                },

                getGradeBadgeClass(grade) {
                    const gradeClasses = {
                        'A+': 'badge-success',
                        'A': 'badge-success',
                        'B+': 'badge-info',
                        'B': 'badge-info',
                        'C': 'badge-warning',
                        'F': 'badge-error'
                    };
                    return gradeClasses[grade] || 'badge-neutral';
                },

                getStatusBadgeClass(status) {
                    const statusClasses = {
                        'pass': 'badge-success',
                        'warning': 'badge-warning',
                        'fail': 'badge-error'
                    };
                    return statusClasses[status] || 'badge-neutral';
                },

                getProbeIcon(probeId) {
                    const icons = {
                        'tls': 'fas fa-lock text-success',
                        'https': 'fas fa-shield-alt text-info',
                        'dns': 'fas fa-server text-primary',
                        'security_headers': 'fas fa-helmet-safety text-warning'
                    };
                    return icons[probeId] || 'fas fa-check-circle';
                },

                formatProbeName(probeId) {
                    const names = {
                        'tls': 'TLS/SSL Security',
                        'https': 'HTTPS Implementation',
                        'dns': 'DNS Configuration',
                        'security_headers': 'Security Headers'
                    };
                    return names[probeId] || probeId.toUpperCase();
                },

                formatDetailKey(key) {
                    return key.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase());
                },

                formatDetailValue(value) {
                    if (typeof value === 'boolean') {
                        return value ? '✓' : '✗';
                    }
                    return value;
                }
            }
        }).mount('#app');
    </script>
</body>
</html>'''

        with open(template_file, 'w', encoding='utf-8') as f:
            f.write(template_content)

    def run(self):
        """Run the modern dashboard with enhanced error handling."""
        try:
            self.console.print(f"[green]🚀 Dashboard running at http://{self.host}:{self.port}[/green]")

            # Run with SocketIO support
            self.socketio.run(
                self.app,
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                log_output=False
            )

        except Exception as e:
            self.console.print(f"[red]❌ Dashboard failed to start: {e}[/red]")
            raise

# ============================================================================
# CLI Commands for Dashboard Management
# ============================================================================

app = typer.Typer(
    name="dqix-dashboard",
    help="🌐 DQIX Modern Web Dashboard",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

@app.command("start")
def start_dashboard(
    port: int = typer.Option(8000, "--port", "-p", help="Dashboard port"),
    host: str = typer.Option("localhost", "--host", help="Host to bind to"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Auto-open browser"),
    theme: str = typer.Option("professional", "--theme", help="Dashboard theme"),
    demo_mode: bool = typer.Option(False, "--demo", help="Demo mode with sample data"),
):
    """🚀 Start the modern DQIX dashboard server."""

    try:
        dashboard = ModernInternetObservabilityDashboard(
            port=port,
            host=host,
            theme=theme,
            demo_mode=demo_mode
        )
        dashboard.run()
    except ImportError:
        console.print("❌ [red]Web dependencies missing[/red]")
        console.print("💡 [yellow]Install with: pip install flask flask-socketio plotly[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ [red]Dashboard failed to start: {e}[/red]")
        raise typer.Exit(1)


def main():
    """Main entry point for dashboard CLI."""
    app()


if __name__ == "__main__":
    main()
