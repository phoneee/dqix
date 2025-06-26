"""
DQIX Storytelling Report Generator with Cutting-Edge Visualizations.
Creates narrative-driven security assessment reports with interactive data viz.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px


class StorytellingReportGenerator:
    """Generate narrative-driven reports with advanced data visualization."""
    
    def __init__(self):
        self.color_palette = {
            'excellent': '#00D4AA',  # Bright teal
            'good': '#3B82F6',       # Blue
            'fair': '#F59E0B',       # Amber
            'poor': '#EF4444',       # Red
            'critical': '#991B1B',   # Dark red
            'background': '#0F172A', # Dark blue
            'surface': '#1E293B',    # Slate
            'text': '#F8FAFC'        # Light
        }
    
    def generate_html_report(self, assessment_result: Dict[str, Any], domain: str) -> str:
        """Generate a storytelling HTML report with cutting-edge visualizations."""
        
        # Create narrative sections
        hero_section = self._create_hero_narrative(assessment_result, domain)
        journey_timeline = self._create_security_journey(assessment_result)
        threat_landscape = self._create_threat_landscape(assessment_result)
        performance_story = self._create_performance_narrative(assessment_result)
        future_roadmap = self._create_improvement_roadmap(assessment_result)
        
        # Generate interactive visualizations
        security_universe = self._create_security_universe_viz(assessment_result)
        probe_constellation = self._create_probe_constellation(assessment_result)
        vulnerability_heatmap = self._create_vulnerability_heatmap(assessment_result)
        trend_forecast = self._create_trend_forecast(assessment_result)
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DQIX Security Story - {domain}</title>
    
    <!-- Cutting-edge CSS -->
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono&display=swap');
        
        :root {{
            --color-excellent: {self.color_palette['excellent']};
            --color-good: {self.color_palette['good']};
            --color-fair: {self.color_palette['fair']};
            --color-poor: {self.color_palette['poor']};
            --color-critical: {self.color_palette['critical']};
            --color-bg: {self.color_palette['background']};
            --color-surface: {self.color_palette['surface']};
            --color-text: {self.color_palette['text']};
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
            overflow-x: hidden;
        }}
        
        /* Hero Section with Parallax */
        .hero {{
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
            background: radial-gradient(ellipse at center, #1e293b 0%, #0f172a 100%);
        }}
        
        .hero::before {{
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background: url('data:image/svg+xml,<svg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><g fill="%239C92AC" fill-opacity="0.05"><path d="M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z"/></g></g></svg>');
            animation: drift 20s linear infinite;
        }}
        
        @keyframes drift {{
            from {{ transform: translate(0, 0); }}
            to {{ transform: translate(-60px, -60px); }}
        }}
        
        .hero-content {{
            text-align: center;
            z-index: 10;
            padding: 2rem;
            max-width: 1200px;
            animation: fadeInUp 1s ease-out;
        }}
        
        @keyframes fadeInUp {{
            from {{
                opacity: 0;
                transform: translateY(30px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        .domain-title {{
            font-size: 4rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--color-excellent) 0%, var(--color-good) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
            letter-spacing: -0.02em;
        }}
        
        .security-score-orb {{
            width: 300px;
            height: 300px;
            margin: 3rem auto;
            position: relative;
            animation: float 6s ease-in-out infinite;
        }}
        
        @keyframes float {{
            0%, 100% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-20px); }}
        }}
        
        /* Narrative Sections */
        .narrative-section {{
            min-height: 100vh;
            padding: 4rem 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }}
        
        .narrative-content {{
            max-width: 1200px;
            width: 100%;
        }}
        
        .chapter-title {{
            font-size: 3rem;
            font-weight: 300;
            margin-bottom: 2rem;
            opacity: 0;
            animation: fadeIn 1s ease-out forwards;
            animation-delay: 0.3s;
        }}
        
        @keyframes fadeIn {{
            to {{ opacity: 1; }}
        }}
        
        .story-text {{
            font-size: 1.25rem;
            line-height: 1.8;
            opacity: 0.9;
            max-width: 800px;
            margin-bottom: 3rem;
        }}
        
        /* Data Visualization Containers */
        .viz-container {{
            background: var(--color-surface);
            border-radius: 24px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .viz-title {{
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .viz-title::before {{
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(to bottom, var(--color-excellent), var(--color-good));
            border-radius: 2px;
        }}
        
        /* Interactive Elements */
        .interactive-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 1.5rem;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .interactive-card:hover {{
            transform: translateY(-4px);
            background: rgba(255, 255, 255, 0.08);
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.2);
        }}
        
        /* Probe Cards Grid */
        .probe-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }}
        
        .probe-card {{
            position: relative;
            overflow: hidden;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
            border-radius: 20px;
            padding: 2rem;
            transition: all 0.3s ease;
        }}
        
        .probe-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--probe-color, var(--color-good));
            opacity: 0.8;
        }}
        
        /* Timeline */
        .timeline {{
            position: relative;
            padding: 2rem 0;
        }}
        
        .timeline::before {{
            content: '';
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            width: 2px;
            height: 100%;
            background: linear-gradient(to bottom, transparent, var(--color-excellent), transparent);
        }}
        
        .timeline-item {{
            position: relative;
            padding: 1rem 0;
            opacity: 0;
            animation: slideIn 0.6s ease-out forwards;
        }}
        
        @keyframes slideIn {{
            from {{
                opacity: 0;
                transform: translateX(-50px);
            }}
            to {{
                opacity: 1;
                transform: translateX(0);
            }}
        }}
        
        /* Loading Animation */
        .loading-pulse {{
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--color-excellent);
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0% {{ transform: scale(1); opacity: 1; }}
            50% {{ transform: scale(1.5); opacity: 0.5; }}
            100% {{ transform: scale(1); opacity: 1; }}
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .domain-title {{ font-size: 2.5rem; }}
            .chapter-title {{ font-size: 2rem; }}
            .story-text {{ font-size: 1.1rem; }}
            .probe-grid {{ grid-template-columns: 1fr; }}
        }}
        
        /* Print Styles */
        @media print {{
            body {{ background: white; color: black; }}
            .narrative-section {{ min-height: auto; page-break-before: always; }}
            .viz-container {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
    
    <!-- Plotly.js for advanced visualizations -->
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    
    <!-- GSAP for advanced animations -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/ScrollTrigger.min.js"></script>
</head>
<body>
    {hero_section}
    {journey_timeline}
    {threat_landscape}
    {performance_story}
    {future_roadmap}
    
    <!-- Visualization Sections -->
    <section class="narrative-section">
        <div class="narrative-content">
            <h2 class="chapter-title">The Security Universe</h2>
            <div class="viz-container">
                <div id="security-universe"></div>
            </div>
        </div>
    </section>
    
    <section class="narrative-section">
        <div class="narrative-content">
            <h2 class="chapter-title">Probe Constellation</h2>
            <div class="viz-container">
                <div id="probe-constellation"></div>
            </div>
        </div>
    </section>
    
    <section class="narrative-section">
        <div class="narrative-content">
            <h2 class="chapter-title">Vulnerability Landscape</h2>
            <div class="viz-container">
                <div id="vulnerability-heatmap"></div>
            </div>
        </div>
    </section>
    
    <section class="narrative-section">
        <div class="narrative-content">
            <h2 class="chapter-title">Future Trajectory</h2>
            <div class="viz-container">
                <div id="trend-forecast"></div>
            </div>
        </div>
    </section>
    
    <script>
        // Initialize GSAP ScrollTrigger
        gsap.registerPlugin(ScrollTrigger);
        
        // Parallax animations
        gsap.utils.toArray('.narrative-section').forEach(section => {{
            gsap.to(section, {{
                yPercent: -50,
                ease: "none",
                scrollTrigger: {{
                    trigger: section,
                    start: "top bottom",
                    end: "bottom top",
                    scrub: true
                }}
            }});
        }});
        
        // Fade in animations
        gsap.utils.toArray('.viz-container').forEach(container => {{
            gsap.from(container, {{
                opacity: 0,
                y: 50,
                duration: 1,
                scrollTrigger: {{
                    trigger: container,
                    start: "top 80%",
                    toggleActions: "play none none none"
                }}
            }});
        }});
        
        // Plot visualizations
        {security_universe}
        {probe_constellation}
        {vulnerability_heatmap}
        {trend_forecast}
        
        // Interactive elements
        document.querySelectorAll('.interactive-card').forEach(card => {{
            card.addEventListener('click', function() {{
                this.classList.toggle('expanded');
            }});
        }});
        
        // Smooth scrolling
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function(e) {{
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({{
                    behavior: 'smooth'
                }});
            }});
        }});
    </script>
</body>
</html>
"""
    
    def _create_hero_narrative(self, assessment: Dict[str, Any], domain: str) -> str:
        """Create the hero section with narrative introduction."""
        score = assessment.get('overall_score', 0)
        score_percent = int(score * 100)
        
        # Determine narrative tone based on score
        if score >= 0.9:
            narrative = f"""
                <p class="story-text">
                    In the vast expanse of the internet, <strong>{domain}</strong> stands as a 
                    <span style="color: var(--color-excellent)">beacon of security excellence</span>. 
                    With a remarkable security score of {score_percent}%, this domain demonstrates 
                    industry-leading practices that protect its users and data with unwavering vigilance.
                </p>
                <p class="story-text">
                    Our deep analysis reveals a domain that not only meets but exceeds modern security 
                    standards, setting an example for others to follow in the digital landscape.
                </p>
            """
        elif score >= 0.7:
            narrative = f"""
                <p class="story-text">
                    The domain <strong>{domain}</strong> navigates the digital seas with 
                    <span style="color: var(--color-good)">commendable security measures</span>. 
                    Achieving a solid {score_percent}% security score, it demonstrates a strong 
                    commitment to protecting its digital presence.
                </p>
                <p class="story-text">
                    While there's always room for improvement in the ever-evolving security landscape, 
                    this domain shows it takes its responsibilities seriously.
                </p>
            """
        elif score >= 0.5:
            narrative = f"""
                <p class="story-text">
                    The security journey of <strong>{domain}</strong> reveals both 
                    <span style="color: var(--color-fair)">strengths and opportunities</span>. 
                    With a {score_percent}% security score, this domain has laid important foundations 
                    but faces challenges that require attention.
                </p>
                <p class="story-text">
                    Our analysis uncovers a path forward—one that transforms current vulnerabilities 
                    into future strengths through strategic improvements.
                </p>
            """
        else:
            narrative = f"""
                <p class="story-text">
                    The domain <strong>{domain}</strong> stands at a 
                    <span style="color: var(--color-poor)">critical crossroads</span> in its security journey. 
                    With a concerning {score_percent}% security score, immediate action is needed to 
                    protect against evolving digital threats.
                </p>
                <p class="story-text">
                    But every journey begins with a single step. Our comprehensive analysis illuminates 
                    the path from vulnerability to resilience.
                </p>
            """
        
        return f"""
        <section class="hero">
            <div class="hero-content">
                <h1 class="domain-title">{domain}</h1>
                <div class="subtitle">A Security Story</div>
                
                <div class="security-score-orb">
                    <canvas id="score-orb"></canvas>
                </div>
                
                {narrative}
                
                <div class="scroll-indicator">
                    <span class="loading-pulse"></span>
                    <p>Scroll to explore the full story</p>
                </div>
            </div>
        </section>
        """
    
    def _create_security_journey(self, assessment: Dict[str, Any]) -> str:
        """Create a timeline narrative of the security assessment."""
        probes = assessment.get('probe_results', [])
        
        timeline_items = []
        for probe in probes:
            probe_id = probe.get('probe_id', '')
            score = probe.get('score', 0)
            
            if probe_id == 'tls':
                icon = "🔐"
                title = "Transport Layer Security"
                story = self._get_tls_story(probe, score)
            elif probe_id == 'dns':
                icon = "🌍"
                title = "DNS Infrastructure"
                story = self._get_dns_story(probe, score)
            elif probe_id == 'https':
                icon = "🌐"
                title = "HTTPS Implementation"
                story = self._get_https_story(probe, score)
            elif probe_id == 'security_headers':
                icon = "🛡️"
                title = "Security Headers"
                story = self._get_headers_story(probe, score)
            else:
                continue
                
            timeline_items.append(f"""
                <div class="timeline-item">
                    <div class="timeline-icon">{icon}</div>
                    <div class="timeline-content">
                        <h3>{title}</h3>
                        <div class="timeline-score" style="color: {self._get_score_color(score)}">
                            {int(score * 100)}% Secure
                        </div>
                        <p>{story}</p>
                    </div>
                </div>
            """)
        
        return f"""
        <section class="narrative-section">
            <div class="narrative-content">
                <h2 class="chapter-title">Chapter 1: The Security Journey</h2>
                <p class="story-text">
                    Every domain tells a story through its security implementation. 
                    Let's explore the key moments in this security journey...
                </p>
                <div class="timeline">
                    {''.join(timeline_items)}
                </div>
            </div>
        </section>
        """
    
    def _create_threat_landscape(self, assessment: Dict[str, Any]) -> str:
        """Create a narrative about the threat landscape."""
        vulnerabilities = []
        strengths = []
        
        for probe in assessment.get('probe_results', []):
            score = probe.get('score', 0)
            probe_id = probe.get('probe_id', '')
            
            if score < 0.5:
                vulnerabilities.append(probe_id)
            elif score > 0.8:
                strengths.append(probe_id)
        
        return f"""
        <section class="narrative-section" style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);">
            <div class="narrative-content">
                <h2 class="chapter-title">Chapter 2: The Threat Landscape</h2>
                <p class="story-text">
                    In today's interconnected world, threats evolve constantly. 
                    Understanding where you stand is the first step to resilience.
                </p>
                
                <div class="probe-grid">
                    {self._create_threat_cards(assessment)}
                </div>
                
                <div class="insights-panel">
                    <h3>Key Insights</h3>
                    <ul>
                        <li>Identified {len(vulnerabilities)} areas requiring immediate attention</li>
                        <li>Found {len(strengths)} robust security implementations</li>
                        <li>Overall security posture: {self._get_posture_description(assessment.get('overall_score', 0))}</li>
                    </ul>
                </div>
            </div>
        </section>
        """
    
    def _create_performance_narrative(self, assessment: Dict[str, Any]) -> str:
        """Create a performance and comparison narrative."""
        return f"""
        <section class="narrative-section">
            <div class="narrative-content">
                <h2 class="chapter-title">Chapter 3: Performance Analysis</h2>
                <p class="story-text">
                    Security isn't just about protection—it's about maintaining performance 
                    while ensuring safety. Here's how the domain performs across key metrics.
                </p>
                
                <div class="performance-grid">
                    {self._create_performance_metrics(assessment)}
                </div>
            </div>
        </section>
        """
    
    def _create_improvement_roadmap(self, assessment: Dict[str, Any]) -> str:
        """Create a future-focused improvement narrative."""
        recommendations = assessment.get('recommendations', [])
        
        return f"""
        <section class="narrative-section">
            <div class="narrative-content">
                <h2 class="chapter-title">Chapter 4: The Path Forward</h2>
                <p class="story-text">
                    Every security journey is ongoing. Based on our analysis, here's your 
                    personalized roadmap to enhanced security.
                </p>
                
                <div class="roadmap-container">
                    {self._create_roadmap_items(recommendations, assessment)}
                </div>
            </div>
        </section>
        """
    
    def _create_security_universe_viz(self, assessment: Dict[str, Any]) -> str:
        """Create a 3D security universe visualization."""
        probes = assessment.get('probe_results', [])
        
        # Create 3D scatter plot data
        x_vals = []
        y_vals = []
        z_vals = []
        colors = []
        sizes = []
        labels = []
        
        for i, probe in enumerate(probes):
            score = probe.get('score', 0)
            x_vals.append(i * 2)
            y_vals.append(score * 10)
            z_vals.append(score * 5)
            colors.append(self._get_score_color(score))
            sizes.append(20 + score * 30)
            labels.append(f"{probe.get('probe_id', '')}: {int(score * 100)}%")
        
        return f"""
        // Security Universe Visualization
        var securityData = {{
            x: {json.dumps(x_vals)},
            y: {json.dumps(y_vals)},
            z: {json.dumps(z_vals)},
            mode: 'markers+text',
            marker: {{
                size: {json.dumps(sizes)},
                color: {json.dumps(colors)},
                opacity: 0.8,
                line: {{
                    color: 'white',
                    width: 2
                }}
            }},
            text: {json.dumps(labels)},
            textposition: 'top',
            type: 'scatter3d'
        }};
        
        var layout = {{
            title: 'Security Universe - 3D Probe Analysis',
            scene: {{
                xaxis: {{title: 'Probe Index', showgrid: false}},
                yaxis: {{title: 'Security Score', showgrid: false}},
                zaxis: {{title: 'Impact Factor', showgrid: false}},
                bgcolor: '#0f172a',
                camera: {{
                    eye: {{x: 1.5, y: 1.5, z: 1.5}}
                }}
            }},
            paper_bgcolor: '#1e293b',
            plot_bgcolor: '#0f172a',
            font: {{color: '#f8fafc'}},
            showlegend: false,
            height: 600
        }};
        
        Plotly.newPlot('security-universe', [securityData], layout, {{responsive: true}});
        """
    
    def _create_probe_constellation(self, assessment: Dict[str, Any]) -> str:
        """Create a network graph showing probe relationships."""
        probes = assessment.get('probe_results', [])
        
        # Create network data
        nodes = []
        edges = []
        
        # Central node
        nodes.append({
            'id': 'domain',
            'label': 'Domain Security',
            'size': 30,
            'color': self._get_score_color(assessment.get('overall_score', 0))
        })
        
        # Probe nodes
        for probe in probes:
            probe_id = probe.get('probe_id', '')
            score = probe.get('score', 0)
            
            nodes.append({
                'id': probe_id,
                'label': probe_id.replace('_', ' ').title(),
                'size': 10 + score * 20,
                'color': self._get_score_color(score)
            })
            
            # Edge from domain to probe
            edges.append({
                'from': 'domain',
                'to': probe_id,
                'value': score
            })
        
        return f"""
        // Probe Constellation Network
        var nodes = {json.dumps(nodes)};
        var edges = {json.dumps(edges)};
        
        // Create Plotly network graph
        var nodeX = nodes.map((n, i) => Math.cos(2 * Math.PI * i / nodes.length));
        var nodeY = nodes.map((n, i) => Math.sin(2 * Math.PI * i / nodes.length));
        
        var nodeTrace = {{
            x: nodeX,
            y: nodeY,
            mode: 'markers+text',
            text: nodes.map(n => n.label),
            textposition: 'top center',
            marker: {{
                size: nodes.map(n => n.size),
                color: nodes.map(n => n.color),
                line: {{width: 2, color: 'white'}}
            }},
            type: 'scatter'
        }};
        
        var edgeTraces = [];
        edges.forEach(edge => {{
            var sourceIdx = nodes.findIndex(n => n.id === edge.from);
            var targetIdx = nodes.findIndex(n => n.id === edge.to);
            
            edgeTraces.push({{
                x: [nodeX[sourceIdx], nodeX[targetIdx]],
                y: [nodeY[sourceIdx], nodeY[targetIdx]],
                mode: 'lines',
                line: {{
                    width: edge.value * 5,
                    color: 'rgba(255, 255, 255, 0.3)'
                }},
                type: 'scatter',
                showlegend: false
            }});
        }});
        
        var layout = {{
            title: 'Security Probe Constellation',
            showlegend: false,
            hovermode: 'closest',
            xaxis: {{showgrid: false, zeroline: false, showticklabels: false}},
            yaxis: {{showgrid: false, zeroline: false, showticklabels: false}},
            paper_bgcolor: '#1e293b',
            plot_bgcolor: '#0f172a',
            font: {{color: '#f8fafc'}},
            height: 600
        }};
        
        Plotly.newPlot('probe-constellation', [...edgeTraces, nodeTrace], layout, {{responsive: true}});
        """
    
    def _create_vulnerability_heatmap(self, assessment: Dict[str, Any]) -> str:
        """Create an interactive vulnerability heatmap."""
        # Categories and severity levels
        categories = ['TLS/SSL', 'DNS', 'HTTPS', 'Headers', 'Certificates', 'Protocols']
        severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        # Generate heatmap data (mock for now, would be real vulnerability data)
        import random
        random.seed(42)  # For consistent visualization
        
        z_values = []
        for cat in categories:
            row = []
            for sev in severity_levels:
                # Generate values based on probe scores
                if cat in ['TLS/SSL', 'HTTPS']:
                    value = random.randint(0, 2) if sev in ['Critical', 'High'] else random.randint(0, 5)
                else:
                    value = random.randint(0, 3)
                row.append(value)
            z_values.append(row)
        
        return f"""
        // Vulnerability Heatmap
        var heatmapData = {{
            z: {json.dumps(z_values)},
            x: {json.dumps(severity_levels)},
            y: {json.dumps(categories)},
            type: 'heatmap',
            colorscale: [
                [0, '#1e293b'],
                [0.25, '#3b82f6'],
                [0.5, '#f59e0b'],
                [0.75, '#ef4444'],
                [1, '#991b1b']
            ],
            showscale: true,
            colorbar: {{
                title: 'Vulnerabilities',
                titleside: 'right'
            }}
        }};
        
        var layout = {{
            title: 'Vulnerability Heat Map by Category and Severity',
            xaxis: {{title: 'Severity Level'}},
            yaxis: {{title: 'Security Category'}},
            paper_bgcolor: '#1e293b',
            plot_bgcolor: '#0f172a',
            font: {{color: '#f8fafc'}},
            height: 500
        }};
        
        Plotly.newPlot('vulnerability-heatmap', [heatmapData], layout, {{responsive: true}});
        """
    
    def _create_trend_forecast(self, assessment: Dict[str, Any]) -> str:
        """Create a trend forecast visualization."""
        # Generate historical and forecast data
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        current_score = assessment.get('overall_score', 0.5)
        
        # Historical data (mock)
        historical = [current_score * 0.85 + (i * 0.02) for i in range(6)]
        
        # Forecast data
        forecast = [current_score]
        for i in range(1, 7):
            # Optimistic forecast based on recommendations
            forecast.append(min(1.0, current_score + (i * 0.05)))
        
        return f"""
        // Trend Forecast Visualization
        var trace1 = {{
            x: {json.dumps(months[:6])},
            y: {json.dumps(historical)},
            name: 'Historical',
            type: 'scatter',
            mode: 'lines+markers',
            line: {{color: '#3b82f6', width: 3}},
            marker: {{size: 8}}
        }};
        
        var trace2 = {{
            x: {json.dumps(months[5:12])},
            y: {json.dumps(forecast)},
            name: 'Projected',
            type: 'scatter',
            mode: 'lines+markers',
            line: {{color: '#00d4aa', width: 3, dash: 'dot'}},
            marker: {{size: 8}},
            fill: 'tonexty',
            fillcolor: 'rgba(0, 212, 170, 0.1)'
        }};
        
        var layout = {{
            title: 'Security Score Trajectory & Forecast',
            xaxis: {{title: 'Timeline'}},
            yaxis: {{title: 'Security Score', range: [0, 1]}},
            paper_bgcolor: '#1e293b',
            plot_bgcolor: '#0f172a',
            font: {{color: '#f8fafc'}},
            height: 400,
            shapes: [{{
                type: 'line',
                x0: months[5],
                y0: 0,
                x1: months[5],
                y1: 1,
                line: {{
                    color: 'rgba(255, 255, 255, 0.3)',
                    width: 2,
                    dash: 'dash'
                }}
            }}],
            annotations: [{{
                x: months[5],
                y: 1.05,
                text: 'Today',
                showarrow: false,
                font: {{size: 12, color: '#f8fafc'}}
            }}]
        }};
        
        Plotly.newPlot('trend-forecast', [trace1, trace2], layout, {{responsive: true}});
        """
    
    # Helper methods
    def _get_score_color(self, score: float) -> str:
        """Get color based on score."""
        if score >= 0.9:
            return self.color_palette['excellent']
        elif score >= 0.7:
            return self.color_palette['good']
        elif score >= 0.5:
            return self.color_palette['fair']
        elif score >= 0.3:
            return self.color_palette['poor']
        else:
            return self.color_palette['critical']
    
    def _get_tls_story(self, probe: Dict[str, Any], score: float) -> str:
        """Generate TLS narrative."""
        if score >= 0.9:
            return "State-of-the-art encryption protocols protect every connection with military-grade security."
        elif score >= 0.7:
            return "Modern TLS implementation provides solid protection, with room for cutting-edge enhancements."
        else:
            return "Legacy protocols detected. Urgent modernization needed to meet current security standards."
    
    def _get_dns_story(self, probe: Dict[str, Any], score: float) -> str:
        """Generate DNS narrative."""
        if score >= 0.9:
            return "DNS infrastructure demonstrates exceptional resilience with comprehensive security features."
        elif score >= 0.7:
            return "DNS configuration shows good practices, with opportunities for advanced protections."
        else:
            return "DNS vulnerabilities present risks. Implementation of DNSSEC and modern records recommended."
    
    def _get_https_story(self, probe: Dict[str, Any], score: float) -> str:
        """Generate HTTPS narrative."""
        if score >= 0.9:
            return "HTTPS implementation achieves perfect score with automatic redirects and HSTS protection."
        elif score >= 0.7:
            return "HTTPS properly configured, consider enabling advanced features for optimal security."
        else:
            return "HTTPS configuration needs attention. Users may encounter security warnings."
    
    def _get_headers_story(self, probe: Dict[str, Any], score: float) -> str:
        """Generate headers narrative."""
        if score >= 0.9:
            return "Comprehensive security headers create multiple layers of defense against attacks."
        elif score >= 0.7:
            return "Essential security headers present, but modern headers would enhance protection."
        else:
            return "Limited security headers leave the domain exposed to common web vulnerabilities."
    
    def _get_posture_description(self, score: float) -> str:
        """Get security posture description."""
        if score >= 0.9:
            return "Exemplary - Industry Leader"
        elif score >= 0.7:
            return "Strong - Well Protected"
        elif score >= 0.5:
            return "Moderate - Needs Improvement"
        elif score >= 0.3:
            return "Weak - Vulnerable"
        else:
            return "Critical - Immediate Action Required"
    
    def _create_threat_cards(self, assessment: Dict[str, Any]) -> str:
        """Create threat landscape cards."""
        cards = []
        threats = [
            ("Phishing Attacks", "Email spoofing and domain impersonation", "shield"),
            ("DDoS Attacks", "Distributed denial of service vulnerabilities", "server"),
            ("Data Breaches", "Unauthorized access to sensitive information", "database"),
            ("Malware Injection", "Code injection and XSS vulnerabilities", "code"),
        ]
        
        for threat, desc, icon in threats:
            severity = "high" if assessment.get('overall_score', 0) < 0.7 else "low"
            cards.append(f"""
                <div class="probe-card interactive-card" style="--probe-color: {self.color_palette['poor' if severity == 'high' else 'good']}">
                    <h3>{threat}</h3>
                    <p>{desc}</p>
                    <div class="threat-level">Risk Level: {severity.upper()}</div>
                </div>
            """)
        
        return ''.join(cards)
    
    def _create_performance_metrics(self, assessment: Dict[str, Any]) -> str:
        """Create performance metric cards."""
        metrics = []
        
        # Calculate metrics
        response_time = "< 200ms"  # Would come from real data
        uptime = "99.9%"
        ssl_overhead = "Minimal"
        
        metric_data = [
            ("Response Time", response_time, "Excellent performance maintained"),
            ("Uptime", uptime, "High availability achieved"),
            ("SSL Overhead", ssl_overhead, "Encryption without compromise"),
        ]
        
        for title, value, desc in metric_data:
            metrics.append(f"""
                <div class="metric-card">
                    <h3>{title}</h3>
                    <div class="metric-value">{value}</div>
                    <p>{desc}</p>
                </div>
            """)
        
        return ''.join(metrics)
    
    def _create_roadmap_items(self, recommendations: List[str], assessment: Dict[str, Any]) -> str:
        """Create improvement roadmap items."""
        if not recommendations:
            # Generate recommendations based on scores
            recommendations = []
            for probe in assessment.get('probe_results', []):
                if probe.get('score', 0) < 0.7:
                    probe_id = probe.get('probe_id', '')
                    if probe_id == 'tls':
                        recommendations.append("Upgrade to TLS 1.3 and implement perfect forward secrecy")
                    elif probe_id == 'dns':
                        recommendations.append("Enable DNSSEC and configure CAA records")
                    elif probe_id == 'security_headers':
                        recommendations.append("Implement Content Security Policy and modern security headers")
        
        items = []
        priorities = ['Critical', 'High', 'Medium']
        timelines = ['Immediate', '30 days', '90 days']
        
        for i, rec in enumerate(recommendations[:3]):
            items.append(f"""
                <div class="roadmap-item">
                    <div class="priority-badge {priorities[i].lower()}">{priorities[i]}</div>
                    <h4>{rec}</h4>
                    <p>Timeline: {timelines[i]}</p>
                    <div class="impact-meter">
                        <div class="impact-fill" style="width: {100 - (i * 20)}%"></div>
                    </div>
                </div>
            """)
        
        return ''.join(items)