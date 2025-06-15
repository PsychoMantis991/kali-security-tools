#!/usr/bin/env python3
"""
Enhanced Evidence Reporter - Fixed Version
==========================================

Generates comprehensive HTML and JSON reports from collected exploitation evidence.
Includes executive summary, detailed findings, and automated recommendations.
Fixed to properly extract target IP from enumeration JSON files.

Author: Security Framework Team
Version: 2.1.1 - Fixed IP extraction for n8n workflows
"""

import json
import argparse
import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Minimal HTML template to prevent buffer overflow
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>Security Report - {target}</title></head>
<body>
<h1>Security Assessment Report</h1>
<p><strong>Target:</strong> {target}</p>
<p><strong>Generated:</strong> {timestamp}</p>
<p><strong>Risk Level:</strong> {risk_level}</p>
<h2>Summary</h2>
<ul>
<li>Total Vulnerabilities: {total_vulnerabilities}</li>
<li>Services Tested: {services_tested}</li>
<li>Evidence Files: {evidence_files}</li>
<li>Credentials Found: {credentials_found}</li>
</ul>
<h2>Recommendations</h2>
<ul>
{recommendations_html}
</ul>
</body>
</html>"""

class EvidenceReporter:
    """Enhanced Evidence Reporter with proper IP extraction"""
    
    def __init__(self, evidence_dir: str, target_ip: str):
        self.evidence_path = Path(evidence_dir)
        self.target_ip = target_ip
        self.logger = logging.getLogger(__name__)
    
    def load_evidence_files(self) -> List[Dict]:
        """Load evidence files with size limits to prevent memory issues"""
        evidence_files = []
        
        if not self.evidence_path.exists():
            return evidence_files
        
        # Search target-specific directory first
        target_subdir = self.evidence_path / self.target_ip
        search_paths = [target_subdir] if target_subdir.exists() else [self.evidence_path]
        
        # Also search in subdirectories
        for search_path in search_paths:
            for file_path in search_path.rglob("*.json"):
                try:
                    with open(file_path, 'r') as f:
                        evidence = json.load(f)
                        
                        # Truncate large outputs to prevent memory issues
                        if 'output' in evidence and len(evidence['output']) > 5000:
                            evidence['output'] = evidence['output'][:5000] + "...[TRUNCATED]"
                        
                        evidence_files.append(evidence)
                        
                except Exception as e:
                    self.logger.debug(f"Failed to load {file_path}: {e}")
                    continue
                
        return evidence_files
    
    def analyze_evidence(self, evidence_files: List[Dict]) -> Dict:
        """Analyze evidence files and extract key information"""
        analysis = {
            'services': {},
            'vulnerabilities': [],
            'credentials': [],
            'statistics': {
                'total_tests': len(evidence_files),
                'successful_tests': 0,
                'services_tested': set(),
                'tools_used': set()
            }
        }
        
        for evidence in evidence_files:
            # Track statistics
            if evidence.get('success'):
                analysis['statistics']['successful_tests'] += 1
            
            tool = evidence.get('tool', 'unknown')
            analysis['statistics']['tools_used'].add(tool)
            
            # Extract service information
            port = evidence.get('metadata', {}).get('port', 'unknown')
            service_key = f"{tool}_{port}"
            
            if service_key not in analysis['services']:
                analysis['services'][service_key] = {
                    'port': port,
                    'tool': tool,
                    'evidence': [],
                    'vulnerabilities': [],
                    'success_count': 0
                }
            
            # Add evidence (truncated)
            evidence_summary = {
                'tool': tool,
                'success': evidence.get('success', False),
                'command': evidence.get('command', '')[:1000],  # Truncate
                'output': evidence.get('output', '')[:1000],    # Truncate
                'metadata': str(evidence.get('metadata', {}))[:200]  # Truncate
            }
            
            analysis['services'][service_key]['evidence'].append(evidence_summary)
            
            if evidence.get('success'):
                analysis['services'][service_key]['success_count'] += 1
            
            # Extract vulnerabilities (nuclei)
            if tool == 'nuclei' and evidence.get('success'):
                try:
                    output_lines = evidence.get('output', '').strip().split('\n')
                    for line in output_lines[:50]:  # Limit processing
                        if line.strip():
                            try:
                                vuln_data = json.loads(line)
                                vuln = {
                                    'template_id': vuln_data.get('template-id', 'unknown'),
                                    'name': vuln_data.get('info', {}).get('name', 'Unknown'),
                                    'severity': vuln_data.get('info', {}).get('severity', 'medium'),
                                    'description': vuln_data.get('info', {}).get('description', '')[:500],  # Truncate
                                    'service': service_key
                                }
                                analysis['vulnerabilities'].append(vuln)
                                analysis['services'][service_key]['vulnerabilities'].append(vuln)
                            except:
                                continue
                except:
                    continue
            
            # Extract credentials
            output_lower = evidence.get('output', '').lower()
            if 'login:' in output_lower or 'password' in output_lower:
                analysis['credentials'].append({
                    'service': service_key,
                    'tool': tool,
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
            severity = vuln.get('severity', 'medium').lower()
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
        """Generate minimal HTML report to prevent buffer overflow"""
        try:
            recommendations_html = '\n'.join(f'<li>{rec}</li>' for rec in recommendations[:5])
            
            html_content = HTML_TEMPLATE.format(
                target=self.target_ip,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                risk_level=executive_summary['risk_level'],
                total_vulnerabilities=executive_summary['total_vulnerabilities'],
                services_tested=executive_summary['services_tested'],
                evidence_files=executive_summary['evidence_files'],
                credentials_found=executive_summary['credentials_found'],
                recommendations_html=recommendations_html
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
                    'generator': 'Enhanced Evidence Reporter v2.1.1',
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
        
        # Print ONLY essential summary to stdout (ultra-minimal output)
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
    """Main entry point with proper IP extraction"""
    parser = argparse.ArgumentParser(description='Enhanced Evidence Reporter - Fixed')
    parser.add_argument('target', help='Target IP address or enumeration file path')
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
        # Extract target IP from enumeration file if provided
        target_ip = args.target
        
        # Check if target is a JSON file path (enumeration results)
        if args.target.endswith('.json') and os.path.exists(args.target):
            try:
                with open(args.target, 'r') as f:
                    enum_data = json.load(f)
                    # Try different possible field names for target IP
                    if 'target_ip' in enum_data:
                        target_ip = enum_data['target_ip']
                        print(f"Extracted target IP: {target_ip} from enumeration file: {args.target}", file=sys.stderr)
                    elif 'target' in enum_data:
                        target_ip = enum_data['target']
                        print(f"Extracted target IP: {target_ip} from enumeration file: {args.target}", file=sys.stderr)
                    else:
                        print(f"Warning: No target field found in {args.target}, using filename as target", file=sys.stderr)
            except Exception as e:
                print(f"Warning: Could not parse enumeration file {args.target}: {e}", file=sys.stderr)
        
        # Generate reports
        reporter = EvidenceReporter(args.evidence_dir, target_ip)
        results = reporter.generate_reports(args.output_dir)
        
        if not results:
            print("No evidence files found")
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 