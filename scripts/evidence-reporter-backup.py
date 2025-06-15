#!/usr/bin/env python3
"""
Enhanced Evidence Reporter
=========================

Generates comprehensive HTML and JSON reports from collected exploitation evidence.
Includes executive summary, detailed findings, and automated recommendations.

Author: Security Framework Team
Version: 2.1.0 - Optimized for n8n workflows
"""

import json
import argparse
import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from jinja2 import Template
import base64

# Report templates
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .subtitle { margin-top: 10px; opacity: 0.9; }
        .content { padding: 30px; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; text-align: center; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { color: #6c757d; font-size: 0.9em; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #495057; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }
        .service-group { background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .service-header { display: flex; justify-content: between; align-items: center; margin-bottom: 15px; }
        .service-title { font-size: 1.3em; font-weight: bold; color: #495057; }
        .service-port { background: #6c757d; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .evidence-item { background: white; border: 1px solid #dee2e6; border-radius: 4px; margin-bottom: 10px; }
        .evidence-header { background: #e9ecef; padding: 10px 15px; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
        .evidence-header:hover { background: #dee2e6; }
        .evidence-content { padding: 15px; display: none; }
        .evidence-content.active { display: block; }
        .status-success { color: #28a745; font-weight: bold; }
        .status-failure { color: #dc3545; font-weight: bold; }
        .command { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 0.9em; margin: 10px 0; }
        .output { background: #2d3748; color: #e2e8f0; border-radius: 4px; padding: 15px; font-family: monospace; font-size: 0.8em; max-height: 300px; overflow-y: auto; white-space: pre-wrap; }
        .vulnerability { border-left: 4px solid #dc3545; background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 0 4px 4px 0; }
        .vuln-title { font-weight: bold; margin-bottom: 5px; }
        .vuln-severity { padding: 2px 6px; border-radius: 3px; font-size: 0.8em; color: white; }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #000; }
        .severity-low { background: #28a745; }
        .recommendations { background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 8px; padding: 20px; }
        .recommendations h3 { color: #0c5460; margin-top: 0; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .recommendations li { margin-bottom: 8px; }
        .footer { background: #6c757d; color: white; padding: 20px; text-align: center; border-radius: 0 0 8px 8px; }
        .collapsible-toggle { background: none; border: none; font-size: 1.2em; cursor: pointer; }
        .risk-level { padding: 5px 10px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }
        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #fd7e14; color: white; }
        .risk-medium { background: #ffc107; color: #000; }
        .risk-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">
                Target: {{ target }} | Generated: {{ timestamp }} | Risk Level: 
                <span class="risk-level risk-{{ executive_summary.risk_level.lower() }}">{{ executive_summary.risk_level }}</span>
            </div>
        </div>
        
        <div class="content">
            <!-- Executive Dashboard -->
            <div class="section">
                <h2>Executive Dashboard</h2>
                <div class="dashboard">
                    <div class="metric">
                        <div class="metric-value critical">{{ executive_summary.total_vulnerabilities }}</div>
                        <div class="metric-label">Total Vulnerabilities</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value high">{{ executive_summary.services_tested }}</div>
                        <div class="metric-label">Services Tested</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value medium">{{ executive_summary.evidence_files }}</div>
                        <div class="metric-label">Evidence Files</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value low">{{ executive_summary.credentials_found }}</div>
                        <div class="metric-label">Credentials Found</div>
                    </div>
                </div>
            </div>

            <!-- Vulnerability Breakdown -->
            <div class="section">
                <h2>Vulnerability Summary</h2>
                <div class="dashboard">
                    <div class="metric">
                        <div class="metric-value critical">{{ vulnerability_breakdown.critical }}</div>
                        <div class="metric-label">Critical</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value high">{{ vulnerability_breakdown.high }}</div>
                        <div class="metric-label">High</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value medium">{{ vulnerability_breakdown.medium }}</div>
                        <div class="metric-label">Medium</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value low">{{ vulnerability_breakdown.low }}</div>
                        <div class="metric-label">Low</div>
                    </div>
                </div>
            </div>

            <!-- Services and Evidence -->
            <div class="section">
                <h2>Services and Evidence</h2>
                {% for service_name, service_data in services.items() %}
                <div class="service-group">
                    <div class="service-header">
                        <div class="service-title">{{ service_name.replace('_', ' ').title() }}</div>
                        <div class="service-port">Port {{ service_data.port }}</div>
                    </div>
                    
                    {% for evidence in service_data.evidence %}
                    <div class="evidence-item">
                        <div class="evidence-header" onclick="toggleEvidence(this)">
                            <div>
                                <strong>{{ evidence.tool }}</strong> - {{ evidence.test_name }}
                                <span class="status-{{ 'success' if evidence.success else 'failure' }}">
                                    {{ 'SUCCESS' if evidence.success else 'FAILED' }}
                                </span>
                            </div>
                            <button class="collapsible-toggle">▼</button>
                        </div>
                        <div class="evidence-content">
                            <div class="command">{{ evidence.command }}</div>
                            
                            {% if evidence.vulnerabilities %}
                            <h4>Vulnerabilities Found:</h4>
                            {% for vuln in evidence.vulnerabilities %}
                            <div class="vulnerability">
                                <div class="vuln-title">{{ vuln.template_id or vuln.name or 'Unknown' }}</div>
                                <span class="vuln-severity severity-{{ vuln.severity or 'medium' }}">
                                    {{ vuln.severity or 'medium' }}
                                </span>
                                <p>{{ vuln.description or vuln.name or 'No description available' }}</p>
                            </div>
                            {% endfor %}
                            {% endif %}
                            
                            <h4>Command Output:</h4>
                            <div class="output">{{ evidence.output[:2000] }}{% if evidence.output|length > 2000 %}... (truncated){% endif %}</div>
                            
                            {% if evidence.metadata %}
                            <h4>Metadata:</h4>
                            <div class="command">{{ evidence.metadata }}</div>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% endfor %}
            </div>

            <!-- Recommendations -->
            <div class="section">
                <div class="recommendations">
                    <h3>Security Recommendations</h3>
                    <ul>
                        {% for recommendation in recommendations %}
                        <li>{{ recommendation }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Enhanced Evidence Reporter v2.1.0 | {{ timestamp }}</p>
        </div>
    </div>
    
    <script>
        function toggleEvidence(header) {
            const content = header.nextElementSibling;
            const toggle = header.querySelector('.collapsible-toggle');
            
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                toggle.textContent = '▼';
            } else {
                content.classList.add('active');
                toggle.textContent = '▲';
            }
        }
    </script>
</body>
</html>
"""

class EvidenceReporter:
    """Enhanced Evidence Reporter with n8n optimization"""
    
    def __init__(self, evidence_dir: str, target_ip: str):
        self.evidence_path = Path(evidence_dir)
        self.target_ip = target_ip
        # Use null handler to suppress logging output to stdout
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(logging.NullHandler())
        self.logger.setLevel(logging.ERROR)  # Only log errors
    
    def load_evidence_files(self) -> List[Dict]:
        """Load all evidence files for the target"""
        evidence_files = []
        
        if not self.evidence_path.exists():
            return evidence_files
        
        # First try to load from target-specific subdirectory
        target_subdir = self.evidence_path / self.target_ip
        search_paths = []
        
        if target_subdir.exists():
            search_paths.append(target_subdir)
        
        # Also search the main evidence directory
        search_paths.append(self.evidence_path)
        
        # If target is "unknown", search all subdirectories
        if self.target_ip == "unknown":
            for subdir in self.evidence_path.iterdir():
                if subdir.is_dir():
                    search_paths.append(subdir)
        
        # Load JSON files from all search paths
        for search_path in search_paths:
            for file_path in search_path.glob("*.json"):
                try:
                    with open(file_path, 'r') as f:
                        evidence = json.load(f)
                        evidence['file_path'] = str(file_path)
                        # Truncate large outputs to prevent buffer overflow
                        if 'output' in evidence and len(evidence['output']) > 5000:
                            evidence['output'] = evidence['output'][:5000] + "... [TRUNCATED]"
                        evidence_files.append(evidence)
                except Exception as e:
                    continue  # Skip problematic files silently
                
        return evidence_files
    
    def analyze_evidence(self, evidence_files: List[Dict]) -> Dict:
        """Analyze evidence files and generate insights"""
        analysis = {
            'services': {},
            'vulnerabilities': [],
            'credentials': [],
            'statistics': {
                'total_tests': len(evidence_files),
                'successful_tests': 0,
                'failed_tests': 0,
                'services_tested': set(),
                'tools_used': set()
            }
        }
        
        for evidence in evidence_files:
            # Update statistics
            if evidence.get('success'):
                analysis['statistics']['successful_tests'] += 1
            else:
                analysis['statistics']['failed_tests'] += 1
                
            analysis['statistics']['tools_used'].add(evidence.get('tool', 'unknown'))
            
            # Group by service/port
            port = evidence.get('metadata', {}).get('port', 'unknown')
            tool = evidence.get('tool', 'unknown')
            service_key = f"{tool}_{port}" if port != 'unknown' else tool
            
            if service_key not in analysis['services']:
                analysis['services'][service_key] = {
                    'port': port,
                    'evidence': [],
                    'vulnerabilities': [],
                    'success_count': 0
                }
            
            # Create truncated evidence for analysis (keep full data in files)
            truncated_evidence = evidence.copy()
            if 'output' in truncated_evidence and len(truncated_evidence['output']) > 1000:
                truncated_evidence['output'] = truncated_evidence['output'][:1000] + "... [TRUNCATED]"
            
            # Add evidence to service
            analysis['services'][service_key]['evidence'].append(truncated_evidence)
            if evidence.get('success'):
                analysis['services'][service_key]['success_count'] += 1
                
            # Extract vulnerabilities from nuclei results
            if evidence.get('tool') == 'nuclei' and evidence.get('success'):
                try:
                    output_lines = evidence.get('output', '').strip().split('\n')
                    for line in output_lines[:50]:  # Limit to first 50 lines
                        if line:
                            try:
                                vuln_data = json.loads(line)
                                analysis['vulnerabilities'].append(vuln_data)
                                analysis['services'][service_key]['vulnerabilities'].append(vuln_data)
                            except json.JSONDecodeError:
                                continue
                except Exception:
                    continue
            
            # Extract credentials (truncated)
            output_lower = evidence.get('output', '').lower()
            if 'login:' in output_lower or 'password' in output_lower:
                analysis['credentials'].append({
                    'service': service_key,
                    'tool': evidence.get('tool'),
                    'evidence_file': evidence.get('file_path'),
                    'details': evidence.get('output', '')[:200]  # Truncate details
                })
                
            # Track service
            if port != 'unknown':
                analysis['statistics']['services_tested'].add(f"{port}")
        
        # Convert sets to counts
        analysis['statistics']['services_tested'] = len(analysis['statistics']['services_tested'])
        analysis['statistics']['tools_used'] = len(analysis['statistics']['tools_used'])
        
        return analysis
    
    def generate_executive_summary(self, analysis: Dict) -> Dict:
        """Generate executive summary from analysis"""
        total_vulns = len(analysis['vulnerabilities'])
        
        # Calculate vulnerability breakdown
        vuln_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in analysis['vulnerabilities']:
            severity = vuln.get('info', {}).get('severity', 'medium').lower()
            if severity in vuln_breakdown:
                vuln_breakdown[severity] += 1
            else:
                vuln_breakdown['medium'] += 1
        
        # Calculate risk score
        risk_score = (
            vuln_breakdown['critical'] * 10 +
            vuln_breakdown['high'] * 7 +
            vuln_breakdown['medium'] * 4 +
            vuln_breakdown['low'] * 1 +
            len(analysis['credentials']) * 8
        )
        
        # Determine risk level
        if risk_score >= 30:
            risk_level = 'CRITICAL'
        elif risk_score >= 20:
            risk_level = 'HIGH'
        elif risk_score >= 10:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_vulnerabilities': total_vulns,
            'services_tested': analysis['statistics']['services_tested'],
            'evidence_files': analysis['statistics']['total_tests'],
            'credentials_found': len(analysis['credentials']),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'vulnerability_breakdown': vuln_breakdown,
            'success_rate': round(
                (analysis['statistics']['successful_tests'] / max(analysis['statistics']['total_tests'], 1)) * 100, 1
            )
        }
    
    def generate_recommendations(self, analysis: Dict, executive_summary: Dict) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Critical vulnerabilities
        if executive_summary['vulnerability_breakdown']['critical'] > 0:
            recommendations.append(
                f"URGENT: Address {executive_summary['vulnerability_breakdown']['critical']} critical vulnerabilities immediately"
            )
        
        # High vulnerabilities
        if executive_summary['vulnerability_breakdown']['high'] > 0:
            recommendations.append(
                f"High Priority: Remediate {executive_summary['vulnerability_breakdown']['high']} high-severity vulnerabilities"
            )
        
        # Credentials found
        if len(analysis['credentials']) > 0:
            recommendations.append(
                f"Credential Security: {len(analysis['credentials'])} credential exposures detected - review authentication mechanisms"
            )
        
        # Service-specific recommendations
        for service_name, service_data in analysis['services'].items():
            if 'http' in service_name.lower():
                if service_data['vulnerabilities']:
                    recommendations.append(
                        f"Web Security: Secure web service on port {service_data['port']} - {len(service_data['vulnerabilities'])} vulnerabilities found"
                    )
            elif 'ssh' in service_name.lower():
                recommendations.append(
                    f"SSH Security: Review SSH configuration on port {service_data['port']} - ensure key-based authentication"
                )
            elif 'smb' in service_name.lower():
                recommendations.append(
                    f"SMB Security: Secure SMB service on port {service_data['port']} - disable unnecessary shares"
                )
        
        # General recommendations
        recommendations.extend([
            "Network Segmentation: Implement proper network segmentation to limit exposure",
            "Patch Management: Ensure all systems are updated with latest security patches",
            "Access Control: Implement principle of least privilege for all accounts",
            "Monitoring: Deploy comprehensive security monitoring and alerting",
            "Regular Assessments: Schedule regular security assessments and penetration testing"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def generate_html_report(self, analysis: Dict, executive_summary: Dict, 
                           recommendations: List[str], output_path: str) -> bool:
        """Generate HTML report"""
        try:
            template = Template(HTML_TEMPLATE)
            
            html_content = template.render(
                target=self.target_ip,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                executive_summary=executive_summary,
                vulnerability_breakdown=executive_summary['vulnerability_breakdown'],
                services=analysis['services'],
                recommendations=recommendations
            )
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            return True
            
        except Exception:
            return False
    
    def generate_json_report(self, analysis: Dict, executive_summary: Dict, 
                           recommendations: List[str], output_path: str) -> bool:
        """Generate JSON report with minimal data"""
        try:
            # Create minimal report data to prevent buffer overflow
            report_data = {
                'metadata': {
                    'target': self.target_ip,
                    'timestamp': datetime.now().isoformat(),
                    'generator': 'Enhanced Evidence Reporter v2.1.0',
                    'evidence_directory': str(self.evidence_path)
                },
                'executive_summary': executive_summary,
                'recommendations': recommendations,
                # Include only summary statistics, not full analysis
                'statistics': analysis['statistics'],
                'service_summary': {
                    service_name: {
                        'port': service_data['port'],
                        'evidence_count': len(service_data['evidence']),
                        'vulnerability_count': len(service_data['vulnerabilities']),
                        'success_count': service_data['success_count']
                    }
                    for service_name, service_data in analysis['services'].items()
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
                
            return True
            
        except Exception:
            return False
    
    def generate_reports(self, output_dir: str = None) -> Dict[str, str]:
        """Generate both HTML and JSON reports"""
        output_dir = Path(output_dir or 'results/reports')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_path = output_dir / f"evidence_report_{self.target_ip}_{timestamp}.html"
        json_path = output_dir / f"evidence_report_{self.target_ip}_{timestamp}.json"
        
        # Load and analyze evidence
        evidence_files = self.load_evidence_files()
        if not evidence_files:
            return {}
        
        analysis = self.analyze_evidence(evidence_files)
        executive_summary = self.generate_executive_summary(analysis)
        recommendations = self.generate_recommendations(analysis, executive_summary)
        
        # Generate reports
        results = {}
        
        if self.generate_html_report(analysis, executive_summary, recommendations, html_path):
            results['html'] = str(html_path)
        
        if self.generate_json_report(analysis, executive_summary, recommendations, json_path):
            results['json'] = str(json_path)
        
        # Print ONLY essential summary to stdout (minimal output)
        print(f"Evidence Files Analyzed: {len(evidence_files)}")
        print(f"Total Vulnerabilities: {executive_summary['total_vulnerabilities']}")
        print(f"Risk Level: {executive_summary['risk_level']}")
        print(f"Services Tested: {executive_summary['services_tested']}")
        print(f"Credentials Found: {executive_summary['credentials_found']}")
        if results.get('html'):
            print(f"HTML: {results['html']}")
        if results.get('json'):
            print(f"JSON: {results['json']}")
        
        return results

def setup_logging(level: str = 'ERROR') -> None:
    """Configure minimal logging to prevent stdout overflow"""
    # Only log to stderr and only errors
    logging.basicConfig(
        level=logging.ERROR,
        format='%(levelname)s: %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Enhanced Evidence Reporter')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--evidence-dir', default='results/evidence', 
                       help='Evidence directory path')
    parser.add_argument('--output-dir', default='results/reports',
                       help='Output directory for reports')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='ERROR', help='Logging level')
    
    args = parser.parse_args()
    
    # Setup minimal logging
    setup_logging(args.log_level)
    
    try:
        # Generate reports
        reporter = EvidenceReporter(args.evidence_dir, args.target)
        results = reporter.generate_reports(args.output_dir)
        
        if not results:
            print("No evidence files found")
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 