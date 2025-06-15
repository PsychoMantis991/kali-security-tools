#!/usr/bin/env python3
"""
Minimal Evidence Reporter for n8n workflows
===========================================

Ultra-lightweight version to prevent buffer overflow issues.
Generates basic HTML and JSON reports with minimal stdout output.

Author: Security Framework Team
Version: 2.2.0 - Ultra-minimal for n8n
"""

import json
import argparse
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

class MinimalEvidenceReporter:
    """Ultra-minimal Evidence Reporter for n8n workflows"""
    
    def __init__(self, evidence_dir: str, target_ip: str):
        self.evidence_path = Path(evidence_dir)
        self.target_ip = target_ip
    
    def load_evidence_files(self) -> List[Dict]:
        """Load evidence files with minimal processing"""
        evidence_files = []
        
        if not self.evidence_path.exists():
            return evidence_files
        
        # Search target-specific directory first
        target_subdir = self.evidence_path / self.target_ip
        search_paths = [target_subdir] if target_subdir.exists() else [self.evidence_path]
        
        # Load JSON files
        for search_path in search_paths:
            for file_path in search_path.glob("*.json"):
                try:
                    with open(file_path, 'r') as f:
                        evidence = json.load(f)
                        # Truncate large outputs immediately
                        if 'output' in evidence and len(evidence['output']) > 1000:
                            evidence['output'] = evidence['output'][:1000] + "...[TRUNCATED]"
                        evidence_files.append(evidence)
                except:
                    continue  # Skip problematic files silently
                
        return evidence_files
    
    def analyze_evidence(self, evidence_files: List[Dict]) -> Dict:
        """Minimal analysis to extract key metrics"""
        total_vulns = 0
        services_tested = set()
        credentials_found = 0
        successful_tests = 0
        
        for evidence in evidence_files:
            if evidence.get('success'):
                successful_tests += 1
                
            # Count vulnerabilities from nuclei
            if evidence.get('tool') == 'nuclei' and evidence.get('success'):
                try:
                    output_lines = evidence.get('output', '').strip().split('\n')
                    for line in output_lines[:20]:  # Limit processing
                        if line.strip():
                            try:
                                json.loads(line)
                                total_vulns += 1
                            except:
                                continue
                except:
                    continue
            
            # Count credentials
            output_lower = evidence.get('output', '').lower()
            if 'login:' in output_lower or 'password' in output_lower:
                credentials_found += 1
                
            # Track services
            port = evidence.get('metadata', {}).get('port', 'unknown')
            if port != 'unknown':
                services_tested.add(str(port))
        
        # Determine risk level
        if total_vulns >= 5:
            risk_level = 'HIGH'
        elif total_vulns >= 2:
            risk_level = 'MEDIUM'
        elif total_vulns > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'LOW'
        
        return {
            'total_vulnerabilities': total_vulns,
            'services_tested': len(services_tested),
            'credentials_found': credentials_found,
            'evidence_files': len(evidence_files),
            'successful_tests': successful_tests,
            'risk_level': risk_level
        }
    
    def generate_minimal_html(self, analysis: Dict, output_path: str) -> bool:
        """Generate ultra-minimal HTML report"""
        try:
            html_content = f"""<!DOCTYPE html>
<html>
<head><title>Security Report - {self.target_ip}</title></head>
<body>
<h1>Security Assessment Report</h1>
<p><strong>Target:</strong> {self.target_ip}</p>
<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Summary</h2>
<ul>
<li>Total Vulnerabilities: {analysis['total_vulnerabilities']}</li>
<li>Risk Level: {analysis['risk_level']}</li>
<li>Services Tested: {analysis['services_tested']}</li>
<li>Credentials Found: {analysis['credentials_found']}</li>
<li>Evidence Files: {analysis['evidence_files']}</li>
</ul>
</body>
</html>"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except:
            return False
    
    def generate_minimal_json(self, analysis: Dict, output_path: str) -> bool:
        """Generate ultra-minimal JSON report"""
        try:
            report_data = {
                'target': self.target_ip,
                'timestamp': datetime.now().isoformat(),
                'summary': analysis
            }
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            return True
        except:
            return False
    
    def generate_reports(self, output_dir: str = None) -> Dict[str, str]:
        """Generate minimal reports with ultra-minimal stdout output"""
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
        
        # Generate reports
        results = {}
        if self.generate_minimal_html(analysis, html_path):
            results['html'] = str(html_path)
        if self.generate_minimal_json(analysis, json_path):
            results['json'] = str(json_path)
        
        # Ultra-minimal stdout output (only essential metrics)
        print(f"Evidence Files Analyzed: {analysis['evidence_files']}")
        print(f"Total Vulnerabilities: {analysis['total_vulnerabilities']}")
        print(f"Risk Level: {analysis['risk_level']}")
        print(f"Services Tested: {analysis['services_tested']}")
        print(f"Credentials Found: {analysis['credentials_found']}")
        if results.get('html'):
            print(f"HTML: {results['html']}")
        if results.get('json'):
            print(f"JSON: {results['json']}")
        
        return results

def main():
    """Main entry point with minimal error handling"""
    parser = argparse.ArgumentParser(description='Minimal Evidence Reporter')
    parser.add_argument('target', help='Target IP address or enumeration file path')
    parser.add_argument('--evidence-dir', default='results/evidence', help='Evidence directory')
    parser.add_argument('--output-dir', default='results/reports', help='Output directory')
    parser.add_argument('--log-level', default='ERROR', help='Logging level (ignored)')
    
    args = parser.parse_args()
    
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
        
        reporter = MinimalEvidenceReporter(args.evidence_dir, target_ip)
        results = reporter.generate_reports(args.output_dir)
        
        if not results:
            print("No evidence files found")
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 