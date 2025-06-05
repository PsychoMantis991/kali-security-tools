#!/usr/bin/env python3

import json
import sys
import os
import redis
import psycopg2
from datetime import datetime
from typing import Dict, Any, List, Optional

class DatabaseManager:
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
        self.pg_conn.autocommit = True
        
        # Initialize database schema if needed
        self._init_schema()
    
    def _init_schema(self):
        """Initialize database schema if it doesn't exist."""
        with self.pg_conn.cursor() as cur:
            # Create audits table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    id SERIAL PRIMARY KEY,
                    workflow_id VARCHAR(50) UNIQUE,
                    target VARCHAR(255),
                    intensity VARCHAR(50),
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    status VARCHAR(50),
                    report_path TEXT
                )
            """)
            
            # Create hosts table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id SERIAL PRIMARY KEY,
                    audit_id INTEGER REFERENCES audits(id),
                    ip VARCHAR(45),
                    status VARCHAR(50),
                    discovery_time TIMESTAMP,
                    UNIQUE(audit_id, ip)
                )
            """)
            
            # Create services table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS services (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER REFERENCES hosts(id),
                    port INTEGER,
                    name VARCHAR(100),
                    version TEXT,
                    state VARCHAR(50),
                    discovery_time TIMESTAMP,
                    UNIQUE(host_id, port)
                )
            """)
            
            # Create vulnerabilities table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER REFERENCES hosts(id),
                    service_id INTEGER REFERENCES services(id),
                    type VARCHAR(100),
                    description TEXT,
                    severity VARCHAR(50),
                    discovery_time TIMESTAMP,
                    exploited BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Create credentials table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER REFERENCES hosts(id),
                    service_id INTEGER REFERENCES services(id),
                    username TEXT,
                    password TEXT,
                    hash TEXT,
                    type VARCHAR(50),
                    discovery_time TIMESTAMP
                )
            """)
    
    def init_audit(self, workflow_id: str, target: str, intensity: str) -> None:
        """Initialize a new security audit."""
        with self.pg_conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audits (workflow_id, target, intensity, start_time, status)
                VALUES (%s, %s, %s, %s, 'running')
            """, (workflow_id, target, intensity, datetime.now()))
        
        # Store audit info in Redis for quick access
        self.redis_client.hset(
            f"audit:{workflow_id}",
            mapping={
                "target": target,
                "intensity": intensity,
                "status": "running",
                "start_time": datetime.now().isoformat()
            }
        )
    
    def store_discovery(self, workflow_id: str, discovery_file: str) -> None:
        """Store network discovery results."""
        with open(discovery_file, 'r') as f:
            discovery_data = json.load(f)
        
        with self.pg_conn.cursor() as cur:
            # Get audit ID
            cur.execute("SELECT id FROM audits WHERE workflow_id = %s", (workflow_id,))
            audit_id = cur.fetchone()[0]
            
            # Store hosts
            for host in discovery_data.get('active_hosts', []):
                cur.execute("""
                    INSERT INTO hosts (audit_id, ip, status, discovery_time)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (audit_id, ip) DO UPDATE
                    SET status = EXCLUDED.status
                    RETURNING id
                """, (audit_id, host['ip'], host['status'], datetime.now()))
                host_id = cur.fetchone()[0]
                
                # Store services
                for service in host.get('services', []):
                    cur.execute("""
                        INSERT INTO services (host_id, port, name, version, state, discovery_time)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (host_id, port) DO UPDATE
                        SET name = EXCLUDED.name, version = EXCLUDED.version, state = EXCLUDED.state
                    """, (
                        host_id,
                        service['port'],
                        service.get('name', 'unknown'),
                        service.get('version', ''),
                        service.get('state', 'unknown'),
                        datetime.now()
                    ))
        
        # Cache discovery results in Redis
        self.redis_client.setex(
            f"discovery:{workflow_id}",
            3600,  # 1 hour TTL
            json.dumps(discovery_data)
        )
    
    def store_enumeration(self, workflow_id: str, host_ip: str, enum_file: str) -> None:
        """Store service enumeration results."""
        with open(enum_file, 'r') as f:
            enum_data = json.load(f)
        
        with self.pg_conn.cursor() as cur:
            # Get host ID
            cur.execute("""
                SELECT h.id FROM hosts h
                JOIN audits a ON h.audit_id = a.id
                WHERE a.workflow_id = %s AND h.ip = %s
            """, (workflow_id, host_ip))
            host_id = cur.fetchone()[0]
            
            # Update services with detailed information
            for port, service in enum_data.get('services', {}).items():
                cur.execute("""
                    UPDATE services
                    SET name = %s, version = %s, state = %s
                    WHERE host_id = %s AND port = %s
                """, (
                    service.get('name', 'unknown'),
                    service.get('version', ''),
                    service.get('state', 'unknown'),
                    host_id,
                    int(port)
                ))
        
        # Cache enumeration results in Redis
        self.redis_client.setex(
            f"enum:{workflow_id}:{host_ip}",
            3600,  # 1 hour TTL
            json.dumps(enum_data)
        )
    
    def store_exploitation(self, workflow_id: str, host_ip: str, exploit_file: str) -> None:
        """Store exploitation results."""
        with open(exploit_file, 'r') as f:
            exploit_data = json.load(f)
        
        with self.pg_conn.cursor() as cur:
            # Get host ID
            cur.execute("""
                SELECT h.id FROM hosts h
                JOIN audits a ON h.audit_id = a.id
                WHERE a.workflow_id = %s AND h.ip = %s
            """, (workflow_id, host_ip))
            host_id = cur.fetchone()[0]
            
            # Store vulnerabilities
            for vuln in exploit_data.get('vulnerabilities', []):
                service_id = None
                if 'port' in vuln:
                    cur.execute("""
                        SELECT id FROM services
                        WHERE host_id = %s AND port = %s
                    """, (host_id, vuln['port']))
                    result = cur.fetchone()
                    if result:
                        service_id = result[0]
                
                cur.execute("""
                    INSERT INTO vulnerabilities (
                        host_id, service_id, type, description,
                        severity, discovery_time, exploited
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    host_id,
                    service_id,
                    vuln.get('type', 'unknown'),
                    vuln.get('description', ''),
                    vuln.get('severity', 'medium'),
                    datetime.now(),
                    vuln.get('exploited', False)
                ))
            
            # Store credentials
            for cred in exploit_data.get('credentials', []):
                service_id = None
                if 'port' in cred:
                    cur.execute("""
                        SELECT id FROM services
                        WHERE host_id = %s AND port = %s
                    """, (host_id, cred['port']))
                    result = cur.fetchone()
                    if result:
                        service_id = result[0]
                
                cur.execute("""
                    INSERT INTO credentials (
                        host_id, service_id, username, password,
                        hash, type, discovery_time
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    host_id,
                    service_id,
                    cred.get('username', ''),
                    cred.get('password', ''),
                    cred.get('hash', ''),
                    cred.get('type', 'unknown'),
                    datetime.now()
                ))
        
        # Cache exploitation results in Redis
        self.redis_client.setex(
            f"exploit:{workflow_id}:{host_ip}",
            3600,  # 1 hour TTL
            json.dumps(exploit_data)
        )
    
    def finalize_audit(self, workflow_id: str, report_path: str) -> None:
        """Finalize the security audit and store the report path."""
        with self.pg_conn.cursor() as cur:
            cur.execute("""
                UPDATE audits
                SET end_time = %s, status = 'completed', report_path = %s
                WHERE workflow_id = %s
            """, (datetime.now(), report_path, workflow_id))
        
        # Update Redis cache
        self.redis_client.hset(
            f"audit:{workflow_id}",
            mapping={
                "status": "completed",
                "end_time": datetime.now().isoformat(),
                "report_path": report_path
            }
        )
    
    def get_audit_summary(self, workflow_id: str) -> Dict[str, Any]:
        """Get a summary of the audit results."""
        with self.pg_conn.cursor() as cur:
            # Get basic audit info
            cur.execute("""
                SELECT target, intensity, start_time, end_time, status, report_path
                FROM audits
                WHERE workflow_id = %s
            """, (workflow_id,))
            audit_info = cur.fetchone()
            
            if not audit_info:
                return {"error": "Audit not found"}
            
            # Get statistics
            cur.execute("""
                SELECT
                    COUNT(DISTINCT h.id) as total_hosts,
                    COUNT(DISTINCT CASE WHEN v.exploited THEN h.id END) as exploited_hosts,
                    COUNT(DISTINCT v.id) as total_vulns,
                    COUNT(DISTINCT c.id) as total_creds
                FROM audits a
                JOIN hosts h ON h.audit_id = a.id
                LEFT JOIN vulnerabilities v ON v.host_id = h.id
                LEFT JOIN credentials c ON c.host_id = h.id
                WHERE a.workflow_id = %s
            """, (workflow_id,))
            stats = cur.fetchone()
            
            return {
                "workflow_id": workflow_id,
                "target": audit_info[0],
                "intensity": audit_info[1],
                "start_time": audit_info[2].isoformat() if audit_info[2] else None,
                "end_time": audit_info[3].isoformat() if audit_info[3] else None,
                "status": audit_info[4],
                "report_path": audit_info[5],
                "statistics": {
                    "total_hosts": stats[0],
                    "exploited_hosts": stats[1],
                    "total_vulnerabilities": stats[2],
                    "total_credentials": stats[3]
                }
            }

def main():
    if len(sys.argv) < 3:
        print("Usage: db_manager.py <command> <workflow_id> [args...]")
        sys.exit(1)
    
    command = sys.argv[1]
    workflow_id = sys.argv[2]
    
    db = DatabaseManager()
    
    try:
        if command == "init_audit":
            if len(sys.argv) < 5:
                print("Usage: db_manager.py init_audit <workflow_id> <target> <intensity>")
                sys.exit(1)
            db.init_audit(workflow_id, sys.argv[3], sys.argv[4])
        
        elif command == "store_discovery":
            if len(sys.argv) < 4:
                print("Usage: db_manager.py store_discovery <workflow_id> <discovery_file>")
                sys.exit(1)
            db.store_discovery(workflow_id, sys.argv[3])
        
        elif command == "store_enumeration":
            if len(sys.argv) < 5:
                print("Usage: db_manager.py store_enumeration <workflow_id> <host_ip> <enum_file>")
                sys.exit(1)
            db.store_enumeration(workflow_id, sys.argv[3], sys.argv[4])
        
        elif command == "store_exploitation":
            if len(sys.argv) < 5:
                print("Usage: db_manager.py store_exploitation <workflow_id> <host_ip> <exploit_file>")
                sys.exit(1)
            db.store_exploitation(workflow_id, sys.argv[3], sys.argv[4])
        
        elif command == "finalize_audit":
            if len(sys.argv) < 4:
                print("Usage: db_manager.py finalize_audit <workflow_id> <report_path>")
                sys.exit(1)
            db.finalize_audit(workflow_id, sys.argv[3])
        
        elif command == "get_summary":
            summary = db.get_audit_summary(workflow_id)
            print(json.dumps(summary, indent=2))
        
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 