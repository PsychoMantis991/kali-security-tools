#!/usr/bin/env python3

import logging
import json
import redis
import psycopg2
from psycopg2.extras import Json
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, config: Dict):
        self.config = config
        self.redis_client = self._init_redis()
        self.pg_conn = self._init_postgres()
    
    def _init_redis(self) -> redis.Redis:
        """Inicializa la conexión con Redis"""
        try:
            redis_config = self.config.get('redis', {})
            return redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                password=redis_config.get('password', None),
                decode_responses=True
            )
        except Exception as e:
            logger.error(f"Error al conectar con Redis: {str(e)}")
            return None
    
    def _init_postgres(self) -> psycopg2.extensions.connection:
        """Inicializa la conexión con PostgreSQL"""
        try:
            pg_config = self.config.get('postgres', {})
            return psycopg2.connect(
                host=pg_config.get('host', 'localhost'),
                port=pg_config.get('port', 5432),
                database=pg_config.get('database', 'security_audit'),
                user=pg_config.get('user', 'postgres'),
                password=pg_config.get('password', '')
            )
        except Exception as e:
            logger.error(f"Error al conectar con PostgreSQL: {str(e)}")
            return None
    
    def store_network_discovery(self, results: Dict) -> bool:
        """Almacena los resultados del descubrimiento de redes"""
        try:
            # Almacenar en Redis para acceso rápido
            if self.redis_client:
                # Almacenar redes descubiertas
                for network, info in results.get('networks', {}).items():
                    key = f"network:{network}"
                    self.redis_client.hmset(key, {
                        'hosts': json.dumps(list(info.get('hosts', []))),
                        'routes': json.dumps(list(info.get('routes', []))),
                        'services': json.dumps(info.get('services', [])),
                        'subnets': json.dumps(list(info.get('subnets', []))),
                        'last_updated': datetime.now().isoformat()
                    })
                
                # Almacenar objetivos escaneados
                for target, info in results.get('targets', {}).items():
                    key = f"target:{target}"
                    self.redis_client.hmset(key, {
                        'info': json.dumps(info),
                        'last_updated': datetime.now().isoformat()
                    })
            
            # Almacenar en PostgreSQL para persistencia
            if self.pg_conn:
                with self.pg_conn.cursor() as cur:
                    # Insertar redes
                    for network, info in results.get('networks', {}).items():
                        cur.execute("""
                            INSERT INTO networks (network_id, hosts, routes, services, subnets, last_updated)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (network_id) DO UPDATE
                            SET hosts = EXCLUDED.hosts,
                                routes = EXCLUDED.routes,
                                services = EXCLUDED.services,
                                subnets = EXCLUDED.subnets,
                                last_updated = EXCLUDED.last_updated
                        """, (
                            network,
                            Json(list(info.get('hosts', []))),
                            Json(list(info.get('routes', []))),
                            Json(info.get('services', [])),
                            Json(list(info.get('subnets', []))),
                            datetime.now()
                        ))
                    
                    # Insertar objetivos
                    for target, info in results.get('targets', {}).items():
                        cur.execute("""
                            INSERT INTO targets (target_id, info, last_updated)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (target_id) DO UPDATE
                            SET info = EXCLUDED.info,
                                last_updated = EXCLUDED.last_updated
                        """, (
                            target,
                            Json(info),
                            datetime.now()
                        ))
                
                self.pg_conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error al almacenar resultados: {str(e)}")
            if self.pg_conn:
                self.pg_conn.rollback()
            return False
    
    def store_vulnerabilities(self, vulnerabilities: List[Dict]) -> bool:
        """Almacena las vulnerabilidades descubiertas"""
        try:
            # Almacenar en Redis
            if self.redis_client:
                for vuln in vulnerabilities:
                    key = f"vuln:{vuln.get('id')}"
                    self.redis_client.hmset(key, {
                        'title': vuln.get('title'),
                        'description': vuln.get('description'),
                        'severity': vuln.get('severity'),
                        'cvss': vuln.get('cvss'),
                        'target': vuln.get('target'),
                        'discovered_at': datetime.now().isoformat()
                    })
            
            # Almacenar en PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cur:
                    for vuln in vulnerabilities:
                        cur.execute("""
                            INSERT INTO vulnerabilities (
                                vuln_id, title, description, severity, cvss, target, discovered_at
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (vuln_id) DO UPDATE
                            SET title = EXCLUDED.title,
                                description = EXCLUDED.description,
                                severity = EXCLUDED.severity,
                                cvss = EXCLUDED.cvss,
                                target = EXCLUDED.target,
                                discovered_at = EXCLUDED.discovered_at
                        """, (
                            vuln.get('id'),
                            vuln.get('title'),
                            vuln.get('description'),
                            vuln.get('severity'),
                            vuln.get('cvss'),
                            vuln.get('target'),
                            datetime.now()
                        ))
                
                self.pg_conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error al almacenar vulnerabilidades: {str(e)}")
            if self.pg_conn:
                self.pg_conn.rollback()
            return False
    
    def store_credentials(self, credentials: List[Dict]) -> bool:
        """Almacena las credenciales descubiertas"""
        try:
            # Almacenar en Redis
            if self.redis_client:
                for cred in credentials:
                    key = f"cred:{cred.get('id')}"
                    self.redis_client.hmset(key, {
                        'username': cred.get('username'),
                        'password': cred.get('password'),
                        'service': cred.get('service'),
                        'target': cred.get('target'),
                        'discovered_at': datetime.now().isoformat()
                    })
            
            # Almacenar en PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cur:
                    for cred in credentials:
                        cur.execute("""
                            INSERT INTO credentials (
                                cred_id, username, password, service, target, discovered_at
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (cred_id) DO UPDATE
                            SET username = EXCLUDED.username,
                                password = EXCLUDED.password,
                                service = EXCLUDED.service,
                                target = EXCLUDED.target,
                                discovered_at = EXCLUDED.discovered_at
                        """, (
                            cred.get('id'),
                            cred.get('username'),
                            cred.get('password'),
                            cred.get('service'),
                            cred.get('target'),
                            datetime.now()
                        ))
                
                self.pg_conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error al almacenar credenciales: {str(e)}")
            if self.pg_conn:
                self.pg_conn.rollback()
            return False
    
    def get_network_info(self, network_id: str) -> Optional[Dict]:
        """Obtiene información de una red específica"""
        try:
            # Intentar obtener de Redis primero
            if self.redis_client:
                key = f"network:{network_id}"
                if self.redis_client.exists(key):
                    return {
                        'hosts': json.loads(self.redis_client.hget(key, 'hosts')),
                        'routes': json.loads(self.redis_client.hget(key, 'routes')),
                        'services': json.loads(self.redis_client.hget(key, 'services')),
                        'subnets': json.loads(self.redis_client.hget(key, 'subnets')),
                        'last_updated': self.redis_client.hget(key, 'last_updated')
                    }
            
            # Si no está en Redis, obtener de PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cur:
                    cur.execute("""
                        SELECT hosts, routes, services, subnets, last_updated
                        FROM networks
                        WHERE network_id = %s
                    """, (network_id,))
                    
                    result = cur.fetchone()
                    if result:
                        return {
                            'hosts': result[0],
                            'routes': result[1],
                            'services': result[2],
                            'subnets': result[3],
                            'last_updated': result[4].isoformat()
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Error al obtener información de red: {str(e)}")
            return None
    
    def get_target_info(self, target_id: str) -> Optional[Dict]:
        """Obtiene información de un objetivo específico"""
        try:
            # Intentar obtener de Redis primero
            if self.redis_client:
                key = f"target:{target_id}"
                if self.redis_client.exists(key):
                    return {
                        'info': json.loads(self.redis_client.hget(key, 'info')),
                        'last_updated': self.redis_client.hget(key, 'last_updated')
                    }
            
            # Si no está en Redis, obtener de PostgreSQL
            if self.pg_conn:
                with self.pg_conn.cursor() as cur:
                    cur.execute("""
                        SELECT info, last_updated
                        FROM targets
                        WHERE target_id = %s
                    """, (target_id,))
                    
                    result = cur.fetchone()
                    if result:
                        return {
                            'info': result[0],
                            'last_updated': result[1].isoformat()
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Error al obtener información de objetivo: {str(e)}")
            return None
    
    def close(self):
        """Cierra las conexiones a las bases de datos"""
        try:
            if self.redis_client:
                self.redis_client.close()
            
            if self.pg_conn:
                self.pg_conn.close()
                
        except Exception as e:
            logger.error(f"Error al cerrar conexiones: {str(e)}") 