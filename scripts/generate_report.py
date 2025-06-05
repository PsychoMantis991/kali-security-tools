#!/usr/bin/env python3

import json
import sys
import os
import redis
import psycopg2
from datetime import datetime
from typing import Dict, Any, List
import jinja2
import pdfkit
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path

class ReportGenerator:
    def __init__(self):
        # Redis connection
        self.redis_client = redis.Redis(
            host='localhost',
            port=6379,
            db=0,
            decode_responses=True
        )
        
        # PostgreSQL connection
        self.pg_conn = psycopg2.connect(
            dbname='security_audit',
            user='postgres',
            password='postgres',
            host='localhost',
            port=5432
        )
        
        # Initialize Jinja2 environment
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('templates')
        )
    
    def get_audit_data(self, workflow_id: str) -> Dict[str, Any]:
        """Retrieve all audit data from databases."""
        with self.pg_conn.cursor() as cur:
            # Get basic audit info
            cur.execute("""
                SELECT target, intensity, start_time, end_time, status, report_path
                FROM audits
                WHERE workflow_id = %s
            """, (workflow_id,))
            audit_info = cur.fetchone()
            
            if not audit_info:
                raise ValueError(f"Audit {workflow_id} not found")
            
            # Get all hosts and their services
            cur.execute("""
                SELECT h.ip, h.status, h.discovery_time,
                       s.port, s.name, s.version, s.state, s.discovery_time
                FROM hosts h
                LEFT JOIN services s ON s.host_id = h.id
                WHERE h.audit_id = (SELECT id FROM audits WHERE workflow_id = %s)
                ORDER BY h.ip, s.port
            """, (workflow_id,))
            hosts_data = {}
            for row in cur.fetchall():
                host_ip = row[0]
                if host_ip not in hosts_data:
                    hosts_data[host_ip] = {
                        'ip': host_ip,
                        'status': row[1],
                        'discovery_time': row[2].isoformat(),
                        'services': []
                    }
                if row[3]:  # port
                    hosts_data[host_ip]['services'].append({
                        'port': row[3],
                        'name': row[4],
                        'version': row[5],
                        'state': row[6],
                        'discovery_time': row[7].isoformat()
                    })
            
            # Get vulnerabilities
            cur.execute("""
                SELECT h.ip, s.port, v.type, v.description,
                       v.severity, v.discovery_time, v.exploited
                FROM vulnerabilities v
                JOIN hosts h ON h.id = v.host_id
                LEFT JOIN services s ON s.id = v.service_id
                WHERE h.audit_id = (SELECT id FROM audits WHERE workflow_id = %s)
                ORDER BY v.severity DESC, h.ip
            """, (workflow_id,))
            vulnerabilities = []
            for row in cur.fetchall():
                vulnerabilities.append({
                    'host': row[0],
                    'port': row[1],
                    'type': row[2],
                    'description': row[3],
                    'severity': row[4],
                    'discovery_time': row[5].isoformat(),
                    'exploited': row[6]
                })
            
            # Get credentials
            cur.execute("""
                SELECT h.ip, s.port, c.username, c.password,
                       c.hash, c.type, c.discovery_time
                FROM credentials c
                JOIN hosts h ON h.id = c.host_id
                LEFT JOIN services s ON s.id = c.service_id
                WHERE h.audit_id = (SELECT id FROM audits WHERE workflow_id = %s)
                ORDER BY h.ip, s.port
            """, (workflow_id,))
            credentials = []
            for row in cur.fetchall():
                credentials.append({
                    'host': row[0],
                    'port': row[1],
                    'username': row[2],
                    'password': row[3],
                    'hash': row[4],
                    'type': row[5],
                    'discovery_time': row[6].isoformat()
                })
            
            # Get statistics
            cur.execute("""
                SELECT
                    COUNT(DISTINCT h.id) as total_hosts,
                    COUNT(DISTINCT CASE WHEN v.exploited THEN h.id END) as exploited_hosts,
                    COUNT(DISTINCT v.id) as total_vulns,
                    COUNT(DISTINCT c.id) as total_creds,
                    COUNT(DISTINCT CASE WHEN v.severity = 'critical' THEN v.id END) as critical_vulns,
                    COUNT(DISTINCT CASE WHEN v.severity = 'high' THEN v.id END) as high_vulns,
                    COUNT(DISTINCT CASE WHEN v.severity = 'medium' THEN v.id END) as medium_vulns,
                    COUNT(DISTINCT CASE WHEN v.severity = 'low' THEN v.id END) as low_vulns
                FROM audits a
                JOIN hosts h ON h.audit_id = a.id
                LEFT JOIN vulnerabilities v ON v.host_id = h.id
                LEFT JOIN credentials c ON c.host_id = h.id
                WHERE a.workflow_id = %s
            """, (workflow_id,))
            stats = cur.fetchone()
            
            return {
                'workflow_id': workflow_id,
                'target': audit_info[0],
                'intensity': audit_info[1],
                'start_time': audit_info[2].isoformat(),
                'end_time': audit_info[3].isoformat() if audit_info[3] else None,
                'status': audit_info[4],
                'hosts': list(hosts_data.values()),
                'vulnerabilities': vulnerabilities,
                'credentials': credentials,
                'statistics': {
                    'total_hosts': stats[0],
                    'exploited_hosts': stats[1],
                    'total_vulnerabilities': stats[2],
                    'total_credentials': stats[3],
                    'critical_vulnerabilities': stats[4],
                    'high_vulnerabilities': stats[5],
                    'medium_vulnerabilities': stats[6],
                    'low_vulnerabilities': stats[7]
                }
            }
    
    def generate_network_graph(self, audit_data: Dict[str, Any], output_path: str) -> None:
        """Generate a network graph visualization."""
        G = nx.Graph()
        
        # Add nodes for each host
        for host in audit_data['hosts']:
            G.add_node(host['ip'], type='host', status=host['status'])
            
            # Add edges for services
            for service in host['services']:
                service_name = f"{service['name']}:{service['port']}"
                G.add_node(service_name, type='service')
                G.add_edge(host['ip'], service_name)
        
        # Add edges for exploited paths
        exploited_hosts = set()
        for vuln in audit_data['vulnerabilities']:
            if vuln['exploited']:
                exploited_hosts.add(vuln['host'])
        
        # Draw the graph
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G)
        
        # Draw nodes
        nx.draw_networkx_nodes(G, pos,
                             nodelist=[n for n in G.nodes() if G.nodes[n]['type'] == 'host'],
                             node_color='lightblue',
                             node_size=1000)
        nx.draw_networkx_nodes(G, pos,
                             nodelist=[n for n in G.nodes() if G.nodes[n]['type'] == 'service'],
                             node_color='lightgreen',
                             node_size=500)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos)
        
        # Draw labels
        nx.draw_networkx_labels(G, pos)
        
        plt.title("Network Topology and Service Discovery")
        plt.axis('off')
        plt.savefig(output_path)
        plt.close()
    
    def generate_html_report(self, audit_data: Dict[str, Any], output_path: str) -> None:
        """Generate an HTML report using Jinja2 template."""
        template = self.template_env.get_template('audit_report.html')
        
        # Generate network graph
        graph_path = os.path.join(os.path.dirname(output_path), 'network_graph.png')
        self.generate_network_graph(audit_data, graph_path)
        
        # Render template
        html_content = template.render(
            audit=audit_data,
            graph_path=os.path.basename(graph_path),
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Write HTML file
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def generate_pdf_report(self, html_path: str, output_path: str) -> None:
        """Convert HTML report to PDF."""
        options = {
            'page-size': 'A4',
            'margin-top': '20mm',
            'margin-right': '20mm',
            'margin-bottom': '20mm',
            'margin-left': '20mm',
            'encoding': 'UTF-8',
            'no-outline': None
        }
        pdfkit.from_file(html_path, output_path, options=options)
    
    def generate_report(self, workflow_id: str, output_format: str = 'html') -> str:
        """Generate a complete security audit report."""
        # Get audit data
        audit_data = self.get_audit_data(workflow_id)
        
        # Create output directory if it doesn't exist
        output_dir = Path('reports')
        output_dir.mkdir(exist_ok=True)
        
        # Generate HTML report
        html_path = output_dir / f'audit_{workflow_id}.html'
        self.generate_html_report(audit_data, str(html_path))
        
        # Generate PDF if requested
        if 'pdf' in output_format.lower():
            pdf_path = output_dir / f'audit_{workflow_id}.pdf'
            self.generate_pdf_report(str(html_path), str(pdf_path))
            return str(pdf_path)
        
        return str(html_path)

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_report.py <workflow_id> [output_format]")
        print("output_format: html (default) or pdf")
        sys.exit(1)
    
    workflow_id = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else 'html'
    
    try:
        generator = ReportGenerator()
        report_path = generator.generate_report(workflow_id, output_format)
        print(f"Report generated successfully: {report_path}")
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()