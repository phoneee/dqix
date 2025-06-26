"""
Modern, compact report templates for DQIX.
"""

def generate_compact_html_report(result: dict, domain: str) -> str:
    """Generate a modern, compact HTML report."""
    
    score = result['overall_score']
    score_color = "#4CAF50" if score >= 0.8 else "#FF9800" if score >= 0.6 else "#F44336"
    score_percent = int(score * 100)
    
    # Probe summary
    probe_html = ""
    for probe in result['probe_results']:
        probe_score = probe['score']
        probe_color = "#4CAF50" if probe_score >= 0.8 else "#FF9800" if probe_score >= 0.6 else "#F44336"
        probe_icon = {
            "tls": "🔐",
            "https": "🌐",
            "dns": "🌍",
            "security_headers": "🛡️"
        }.get(probe['probe_id'], "📊")
        
        details = probe.get('details', {})
        key_details = []
        
        if probe['probe_id'] == 'tls':
            if details.get('version'): key_details.append(f"Protocol: {details['version']}")
            if details.get('certificate_valid'): key_details.append("Valid Certificate")
        elif probe['probe_id'] == 'https':
            if details.get('hsts'): key_details.append("HSTS Enabled")
            if details.get('redirect'): key_details.append("HTTPS Redirect")
        elif probe['probe_id'] == 'dns':
            if details.get('dnssec'): key_details.append("DNSSEC")
            if details.get('spf'): key_details.append("SPF Record")
        elif probe['probe_id'] == 'security_headers':
            headers_count = sum(1 for k, v in details.items() if v and k != 'score')
            key_details.append(f"{headers_count} Security Headers")
        
        probe_html += f"""
        <div class="probe-card">
            <div class="probe-header">
                <span class="probe-icon">{probe_icon}</span>
                <span class="probe-name">{probe['probe_id'].replace('_', ' ').title()}</span>
                <div class="probe-score" style="background: {probe_color}">
                    {int(probe_score * 100)}%
                </div>
            </div>
            <div class="probe-details">
                {' • '.join(key_details) if key_details else 'Checked'}
            </div>
        </div>
        """
    
    # Recommendations
    recommendations_html = ""
    if result.get('recommendations'):
        for i, rec in enumerate(result['recommendations'][:3], 1):
            recommendations_html += f"<li>{rec}</li>"
    
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DQIX Report - {domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #6B73FF 0%, #000DFF 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            font-weight: 300;
            margin-bottom: 10px;
        }}
        
        .header .domain {{
            font-size: 1.8em;
            font-weight: 600;
            margin-bottom: 20px;
        }}
        
        .score-display {{
            display: inline-block;
            position: relative;
            width: 150px;
            height: 150px;
            margin: 20px 0;
        }}
        
        .score-circle {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient({score_color} {score_percent * 3.6}deg, #e0e0e0 0deg);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }}
        
        .score-inner {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: white;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
        }}
        
        .score-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: {score_color};
        }}
        
        .score-label {{
            font-size: 0.9em;
            color: #666;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .section-title {{
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 20px;
            color: #333;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 10px;
        }}
        
        .probes-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .probe-card {{
            background: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #ddd;
            transition: all 0.3s ease;
        }}
        
        .probe-card:hover {{
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }}
        
        .probe-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
        }}
        
        .probe-icon {{
            font-size: 1.5em;
            margin-right: 10px;
        }}
        
        .probe-name {{
            flex: 1;
            font-weight: 600;
        }}
        
        .probe-score {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .probe-details {{
            color: #666;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        
        .recommendations {{
            background: #FFF3CD;
            border: 1px solid #FFE69C;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}
        
        .recommendations h3 {{
            color: #856404;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
            color: #856404;
        }}
        
        .recommendations li {{
            margin-bottom: 8px;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        .timestamp {{
            margin-top: 10px;
            color: #999;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
            
            .probe-card:hover {{
                box-shadow: none;
                transform: none;
            }}
        }}
        
        @media (max-width: 600px) {{
            .header {{
                padding: 30px 20px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .content {{
                padding: 20px;
            }}
            
            .probes-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DQIX Security Report</h1>
            <div class="domain">{domain}</div>
            <div class="score-display">
                <div class="score-circle">
                    <div class="score-inner">
                        <div class="score-value">{score_percent}%</div>
                        <div class="score-label">Security Score</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2 class="section-title">🔍 Security Assessment</h2>
                <div class="probes-grid">
                    {probe_html}
                </div>
            </div>
            
            {f'''
            <div class="recommendations">
                <h3>💡 Recommendations</h3>
                <ul>
                    {recommendations_html}
                </ul>
            </div>
            ''' if recommendations_html else ''}
        </div>
        
        <div class="footer">
            <div>Generated by DQIX Internet Observability Platform</div>
            <div class="timestamp">Report created on {result.get('timestamp', 'N/A')}</div>
        </div>
    </div>
</body>
</html>
"""