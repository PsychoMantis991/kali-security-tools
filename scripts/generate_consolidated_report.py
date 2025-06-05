#!/usr/bin/env python3

import json
import argparse
import os
from datetime import datetime
import jinja2
import sys

def load_json_file(file_path):
    """Load and parse a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")
        sys.exit(1)

def format_timestamp(timestamp):
    """Format timestamp for display."""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return timestamp

def calculate_risk_score(enum_risk, enhanced_risk):
    """Calculate combined risk score."""
    risk_weights = {
        'high': 3,
        'medium': 2,
        'low': 1
    }
    
    total_risk = 0
    for risk_type in ['high_risk', 'medium_risk', 'low_risk']:
        enum_value = enum_risk.get(risk_type, 0)
        enhanced_value = enhanced_risk.get(risk_type, 0)
        weight = risk_weights[risk_type.split('_')[0]]
        total_risk += (enum_value + enhanced_value) * weight
    
    return total_risk

def generate_html_report(workflow_id, enum_data, enhanced_data, output_path):
    """Generate HTML report using Jinja2 template."""
    # Prepare template data
    template_data = {
        'workflow_id': workflow_id,
        'timestamp': format_timestamp(datetime.now().isoformat()),
        'target': enum_data.get('target', 'Unknown'),
        
        # Summary section
        'summary': {
            'enumeration': {
                'open_ports': enum_data.get('summary', {}).get('open_ports', 0),
                'services_found': enum_data.get('summary', {}).get('services_found', 0),
                'vulnerabilities_found': enum_data.get('summary', {}).get('vulnerabilities_found', 0)
            },
            'enhanced': {
                'total_hosts': enhanced_data.get('scan_summary', {}).get('total_hosts', 0),
                'exploited_hosts': len(enhanced_data.get('scan_summary', {}).get('exploited_hosts', [])),
                'vulnerabilities_found': enhanced_data.get('scan_summary', {}).get('vulnerabilities_found', 0),
                'credentials_found': enhanced_data.get('scan_summary', {}).get('credentials_found', 0)
            }
        },
        
        # Findings section
        'findings': {
            'enumeration': enum_data.get('findings', {}),
            'enhanced': enhanced_data.get('details', [])
        },
        
        # Risk assessment
        'risk_assessment': {
            'enumeration': enum_data.get('risk_assessment', {}),
            'enhanced': enhanced_data.get('risk_assessment', {}),
            'combined_score': calculate_risk_score(
                enum_data.get('risk_assessment', {}),
                enhanced_data.get('risk_assessment', {})
            )
        },
        
        # Recommendations
        'recommendations': list(set(
            enum_data.get('recommendations', []) +
            enhanced_data.get('recommendations', [])
        )),
        
        # Detailed results
        'detailed_results': {
            'enumeration': enum_data.get('detailed_results', {}),
            'enhanced': enhanced_data.get('detailed_results', {})
        }
    }

    # HTML template
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Audit Report - {{ workflow_id }}</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                background-color: #2c3e50;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 5px;
            }
            .section {
                background-color: #f8f9fa;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .subsection {
                margin-left: 20px;
                margin-bottom: 15px;
            }
            .risk-high { color: #dc3545; }
            .risk-medium { color: #ffc107; }
            .risk-low { color: #28a745; }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #f8f9fa;
            }
            .recommendation {
                background-color: #e9ecef;
                padding: 10px;
                margin-bottom: 10px;
                border-radius: 3px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Audit Report</h1>
                <p>Workflow ID: {{ workflow_id }}</p>
                <p>Target: {{ target }}</p>
                <p>Generated: {{ timestamp }}</p>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <div class="subsection">
                    <h3>Enumeration Results</h3>
                    <ul>
                        <li>Open Ports: {{ summary.enumeration.open_ports }}</li>
                        <li>Services Found: {{ summary.enumeration.services_found }}</li>
                        <li>Vulnerabilities Found: {{ summary.enumeration.vulnerabilities_found }}</li>
                    </ul>
                </div>
                <div class="subsection">
                    <h3>Enhanced Analysis Results</h3>
                    <ul>
                        <li>Total Hosts: {{ summary.enhanced.total_hosts }}</li>
                        <li>Exploited Hosts: {{ summary.enhanced.exploited_hosts }}</li>
                        <li>Vulnerabilities Found: {{ summary.enhanced.vulnerabilities_found }}</li>
                        <li>Credentials Found: {{ summary.enhanced.credentials_found }}</li>
                    </ul>
                </div>
            </div>

            <div class="section">
                <h2>Risk Assessment</h2>
                <div class="subsection">
                    <h3>Combined Risk Score: {{ risk_assessment.combined_score }}</h3>
                    <h4>Enumeration Risks</h4>
                    <ul>
                        <li class="risk-high">High Risk: {{ risk_assessment.enumeration.high_risk }}</li>
                        <li class="risk-medium">Medium Risk: {{ risk_assessment.enumeration.medium_risk }}</li>
                        <li class="risk-low">Low Risk: {{ risk_assessment.enumeration.low_risk }}</li>
                    </ul>
                </div>
            </div>

            <div class="section">
                <h2>Findings</h2>
                <div class="subsection">
                    <h3>Web Services</h3>
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                        {% for service in findings.enumeration.web_services %}
                        <tr>
                            <td>{{ service.port }}</td>
                            <td>{{ service.service }}</td>
                            <td>{{ service.version }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>

                <div class="subsection">
                    <h3>Critical Services</h3>
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                        {% for service in findings.enumeration.critical_services %}
                        <tr>
                            <td>{{ service.port }}</td>
                            <td>{{ service.service }}</td>
                            <td>{{ service.version }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                {% for recommendation in recommendations %}
                <div class="recommendation">
                    {{ recommendation }}
                </div>
                {% endfor %}
            </div>

            <div class="section">
                <h2>Detailed Results</h2>
                <div class="subsection">
                    <h3>Service Enumeration</h3>
                    <pre>{{ detailed_results.enumeration | tojson(indent=2) }}</pre>
                </div>
                <div class="subsection">
                    <h3>Enhanced Analysis</h3>
                    <pre>{{ detailed_results.enhanced | tojson(indent=2) }}</pre>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    # Create Jinja2 environment and render template
    env = jinja2.Environment()
    template = env.from_string(template)
    html_content = template.render(**template_data)

    # Write to file
    try:
        with open(output_path, 'w') as f:
            f.write(html_content)
        print(f"Report generated successfully: {output_path}")
    except Exception as e:
        print(f"Error writing report: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Generate consolidated security audit report')
    parser.add_argument('--workflow-id', required=True, help='Workflow ID')
    parser.add_argument('--enum-data', required=True, help='Path to enumeration results JSON')
    parser.add_argument('--enhanced-data', required=True, help='Path to enhanced analysis results JSON')
    parser.add_argument('--output', required=True, help='Output HTML report path')
    
    args = parser.parse_args()
    
    # Load data
    enum_data = load_json_file(args.enum_data)
    enhanced_data = load_json_file(args.enhanced_data)
    
    # Generate report
    generate_html_report(
        args.workflow_id,
        enum_data,
        enhanced_data,
        args.output
    )

if __name__ == '__main__':
    main() 