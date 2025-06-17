#!/usr/bin/env python3
"""
Generate Corrected Evidence Report
==================================

Generates a corrected evidence report with proper port extraction from command strings.
"""

import json
import re
from pathlib import Path
from datetime import datetime

def extract_port_from_command(command):
    """Extract port from command string"""
    patterns = [
        r'(\d+)\s+\(',              # "88 (kerberos)"
        r'\s(\d+)$',                # ending with port
        r':(\d+)',                  # ":port"
        r'\s(\d+)\s',               # space-port-space
        r'-p\s*(\d+)',              # -p port
    ]
    
    for pattern in patterns:
        match = re.search(pattern, command)
        if match:
            port = match.group(1)
            try:
                if 1 <= int(port) <= 65535:
                    return port
            except:
                continue
    return 'unknown'

def analyze_evidence_corrected(target_ip):
    """Analyze evidence files with corrected port extraction"""
    
    evidence_path = Path(f"results/evidence/{target_ip}")
    if not evidence_path.exists():
        print(f"❌ No evidence directory found: {evidence_path}")
        return None
    
    services = {}
    statistics = {
        'total_tests': 0,
        'successful_tests': 0,
        'services_tested': set(),
        'tools_used': set()
    }
    
    credentials = []
    vulnerabilities = []
    
    for file_path in evidence_path.rglob("*.json"):
        try:
            with open(file_path, 'r') as f:
                evidence = json.load(f)
                statistics['total_tests'] += 1
                
                tool = evidence.get('tool', 'unknown')
                statistics['tools_used'].add(tool)
                
                # Extract port with corrected logic
                port = evidence.get('metadata', {}).get('port', 'unknown')
                
                if port == 'unknown':
                    command = evidence.get('command', '')
                    if command:
                        extracted_port = extract_port_from_command(command)
                        if extracted_port != 'unknown':
                            port = extracted_port
                        else:
                            output = evidence.get('output', '')
                            if output:
                                output_port = extract_port_from_command(output)
                                if output_port != 'unknown':
                                    port = output_port
                
                service_key = f"{tool}_{port}"
                
                if service_key not in services:
                    services[service_key] = {
                        'port': port,
                        'evidence_count': 0,
                        'vulnerability_count': 0,
                        'success_count': 0
                    }
                
                services[service_key]['evidence_count'] += 1
                
                if evidence.get('success'):
                    services[service_key]['success_count'] += 1
                    statistics['successful_tests'] += 1
                
                # Track service ports
                if port != 'unknown':
                    statistics['services_tested'].add(port)
                
                # Extract credentials
                output_lower = evidence.get('output', '').lower()
                if 'login:' in output_lower or 'password' in output_lower or 'credential' in output_lower:
                    credentials.append({
                        'service': service_key,
                        'tool': tool,
                        'port': port
                    })
                
        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
            continue
    
    # Convert sets to counts
    statistics['services_tested'] = len(statistics['services_tested'])
    statistics['tools_used'] = len(statistics['tools_used'])
    
    return {
        'services': services,
        'statistics': statistics,
        'credentials': credentials,
        'vulnerabilities': vulnerabilities
    }

def generate_corrected_report(target_ip):
    """Generate corrected evidence report"""
    
    print(f"🔧 Generating corrected evidence report for: {target_ip}")
    
    analysis = analyze_evidence_corrected(target_ip)
    if not analysis:
        return None
    
    # Calculate metrics
    services = analysis['services']
    known_ports = [s for s in services.keys() if not s.endswith('_unknown')]
    unknown_ports = [s for s in services.keys() if s.endswith('_unknown')]
    
    # Calculate risk score
    risk_score = len(analysis['credentials']) * 8 + len(analysis['vulnerabilities']) * 5
    
    if risk_score >= 30:
        risk_level = 'CRITICAL'
    elif risk_score >= 20:
        risk_level = 'HIGH'
    elif risk_score >= 10:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    # Generate corrected report
    corrected_report = {
        "metadata": {
            "target": target_ip,
            "timestamp": datetime.now().isoformat(),
            "generator": "Corrected Evidence Reporter v1.0",
            "evidence_directory": "results/evidence"
        },
        "executive_summary": {
            "total_vulnerabilities": len(analysis['vulnerabilities']),
            "services_tested": analysis['statistics']['services_tested'],
            "evidence_files": analysis['statistics']['total_tests'],
            "credentials_found": len(analysis['credentials']),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "vulnerability_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "success_rate": round((analysis['statistics']['successful_tests'] / max(analysis['statistics']['total_tests'], 1)) * 100, 1)
        },
        "service_summary": {
            service_key: {
                "port": data['port'],
                "evidence_count": data['evidence_count'],
                "vulnerability_count": data['vulnerability_count'],
                "success_count": data['success_count']
            }
            for service_key, data in services.items()
        },
        "port_extraction_results": {
            "services_with_known_ports": len(known_ports),
            "services_with_unknown_ports": len(unknown_ports),
            "port_extraction_success_rate": round((len(known_ports) / len(services)) * 100, 1) if services else 0
        },
        "statistics": analysis['statistics'],
        "recommendations": [
            f"Port Detection: Successfully identified {len(known_ports)} services with specific ports",
            f"Credential Security: {len(analysis['credentials'])} credential exposures detected - review authentication mechanisms",
            "Network Segmentation: Implement proper network segmentation to limit exposure",
            "Patch Management: Ensure all systems are updated with latest security patches",
            "Access Control: Implement principle of least privilege for all accounts",
            "Regular Assessments: Schedule regular security assessments and penetration testing"
        ]
    }
    
    # Save corrected report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"results/reports/evidence_report_corrected_{target_ip}_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(corrected_report, f, indent=2)
    
    print(f"✅ Corrected report saved: {output_file}")
    
    # Print summary
    print(f"\n📊 CORRECTED REPORT SUMMARY:")
    print(f"- Target: {target_ip}")
    print(f"- Total evidence files: {analysis['statistics']['total_tests']}")
    print(f"- Services with known ports: {len(known_ports)}")
    print(f"- Services with unknown ports: {len(unknown_ports)}")
    print(f"- Port extraction success rate: {corrected_report['port_extraction_results']['port_extraction_success_rate']}%")
    print(f"- Services tested: {analysis['statistics']['services_tested']}")
    print(f"- Credentials found: {len(analysis['credentials'])}")
    print(f"- Risk level: {risk_level}")
    
    if known_ports:
        print(f"\n🎯 Services with identified ports:")
        for service in known_ports:
            port = services[service]['port']
            count = services[service]['evidence_count']
            print(f"   {service} ({count} evidence files)")
    
    return corrected_report

if __name__ == "__main__":
    target_ip = "10.129.236.153"
    corrected_report = generate_corrected_report(target_ip)
    
    if corrected_report:
        print(f"\n✅ SUCCESS: Corrected evidence report generated with proper port extraction!")
    else:
        print(f"\n❌ ERROR: Failed to generate corrected report") 