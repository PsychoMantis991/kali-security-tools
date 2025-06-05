#!/usr/bin/env python3

import json
import subprocess
import logging
import argparse
from datetime import datetime
import os
import requests
import ftplib
import socket
import paramiko
import dns.resolver
from impacket.smbconnection import SMBConnection
from ldap3 import Server, Connection, ALL
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ServiceEnumerator:
    def __init__(self, config_file='config/service-enum-config.json'):
        self.config = self.load_config(config_file)
        self.results = {}
        self.timeout = self.config.get("timeout", 30)
        
    def load_config(self, config_file):
        """Carga la configuración desde el archivo JSON"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Archivo de configuración {config_file} no encontrado. Usando configuración por defecto.")
            return {
                "timeout": 30,
                "max_threads": 5,
                "wordlists": {
                    "directories": "/usr/share/wordlists/dirb/common.txt",
                    "subdomains": "/usr/share/wordlists/dns/subdomains-top1million-5000.txt"
                }
            }
    
    def enumerate_web_service(self, target, port, is_ssl=False):
        """Enumera un servicio web (HTTP/HTTPS)"""
        result = {
            "directories": [],
            "technologies": [],
            "headers": {},
            "vulnerabilities": []
        }
        
        try:
            protocol = "https" if is_ssl else "http"
            target_url = f"{protocol}://{target}:{port}"
            
            # 1. Análisis de headers
            response = requests.get(target_url, verify=False, timeout=self.timeout)
            result["headers"] = dict(response.headers)
            
            # 2. Detección de tecnologías
            if "Server" in response.headers:
                result["technologies"].append(response.headers["Server"])
            if "X-Powered-By" in response.headers:
                result["technologies"].append(response.headers["X-Powered-By"])
            
            # 3. Búsqueda de directorios con gobuster
            wordlist = self.config.get("wordlists", {}).get("directories", "/usr/share/wordlists/dirb/common.txt")
            temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            cmd = [
                "gobuster", "dir",
                "-u", target_url,
                "-w", wordlist,
                "-q", "-n",
                "-t", "10",
                "-o", os.path.join(temp_dir, f"{target}_{port}_dirs.txt")
            ]
            
            if is_ssl:
                cmd.extend(["-k"])
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            dirs_file = os.path.join(temp_dir, f"{target}_{port}_dirs.txt")
            if os.path.exists(dirs_file):
                with open(dirs_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            result["directories"].append(line.strip())
            
            # 4. Escaneo de vulnerabilidades con Nuclei
            cmd = [
                "nuclei",
                "-u", target_url,
                "-silent",
                "-json",
                "-o", os.path.join(temp_dir, f"{target}_{port}_nuclei.json")
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            nuclei_file = os.path.join(temp_dir, f"{target}_{port}_nuclei.json")
            if os.path.exists(nuclei_file):
                with open(nuclei_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                result["vulnerabilities"].append(vuln)
                            except json.JSONDecodeError:
                                continue
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio web: {str(e)}")
        
        return result
    
    def enumerate_ssh_service(self, target, port):
        """Enumera un servicio SSH"""
        result = {
            "version": "",
            "algorithms": [],
            "vulnerabilities": []
        }
        
        try:
            # 1. Detección de versión y algoritmos
            cmd = [
                "nmap",
                "-p", str(port),
                "--script", "ssh-hostkey,ssh-auth-methods",
                "-T2",
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0 and process.stdout:
                for line in process.stdout.splitlines():
                    if "SSH server version:" in line:
                        result["version"] = line.split("SSH server version:")[1].strip()
                    if "Supported authentication methods:" in line:
                        result["algorithms"] = line.split("Supported authentication methods:")[1].strip().split(", ")
            
            # 2. Escaneo de vulnerabilidades con Nuclei
            cmd = [
                "nuclei",
                "-target", f"ssh://{target}:{port}",
                "-silent",
                "-json",
                "-o", f"/opt/pentest/temp/{target}_{port}_nuclei.json"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(f"/opt/pentest/temp/{target}_{port}_nuclei.json"):
                with open(f"/opt/pentest/temp/{target}_{port}_nuclei.json", 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                result["vulnerabilities"].append(vuln)
                            except json.JSONDecodeError:
                                continue
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio SSH: {str(e)}")
        
        return result
    
    def enumerate_smb_service(self, target, port):
        """Enumera un servicio SMB"""
        result = {
            "shares": [],
            "os_info": "",
            "domain": "",
            "vulnerabilities": []
        }
        
        try:
            # 1. Detección de información básica SMB
            cmd = [
                "nmap",
                "-p", str(port),
                "--script", "smb-os-discovery,smb-enum-shares,smb-protocols",
                "-T2",
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0 and process.stdout:
                for line in process.stdout.splitlines():
                    if "OS:" in line:
                        result["os_info"] = line.split("OS:")[1].strip()
                    if "Domain name:" in line:
                        result["domain"] = line.split("Domain name:")[1].strip()
                    if "\\\\" in line and "Accessible" in line:
                        share_line = line.strip()
                        result["shares"].append(share_line)
            
            # 2. Escaneo de vulnerabilidades con Nuclei
            cmd = [
                "nuclei",
                "-target", f"smb://{target}:{port}",
                "-silent",
                "-json",
                "-o", f"/opt/pentest/temp/{target}_{port}_nuclei.json"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(f"/opt/pentest/temp/{target}_{port}_nuclei.json"):
                with open(f"/opt/pentest/temp/{target}_{port}_nuclei.json", 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                result["vulnerabilities"].append(vuln)
                            except json.JSONDecodeError:
                                continue
            
        except Exception as e:
            logger.error(f"Error al enumerar servicio SMB: {str(e)}")
        
        return result
    
    def enumerate_service(self, target, port, service_info):
        """Enumera un servicio según su tipo"""
        service_name = service_info.get('service', '').lower()
        
        if service_name in ['http', 'https', 'http-proxy', 'ssl/http']:
            return self.enumerate_web_service(target, port, service_name in ['https', 'ssl/http'])
        
        elif service_name == 'ssh':
            return self.enumerate_ssh_service(target, port)
        
        elif service_name in ['microsoft-ds', 'netbios-ssn']:
            return self.enumerate_smb_service(target, port)
        
        else:
            # Servicio genérico, usar Nuclei para detectar vulnerabilidades
            result = {
                "service": service_name,
                "product": service_info.get('product', ''),
                "version": service_info.get('version', ''),
                "vulnerabilities": []
            }
            
            cmd = [
                "nuclei",
                "-target", f"{service_name}://{target}:{port}",
                "-silent",
                "-json",
                "-o", f"/opt/pentest/temp/{target}_{port}_nuclei.json"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(f"/opt/pentest/temp/{target}_{port}_nuclei.json"):
                with open(f"/opt/pentest/temp/{target}_{port}_nuclei.json", 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                vuln = json.loads(line)
                                result["vulnerabilities"].append(vuln)
                            except json.JSONDecodeError:
                                continue
            
            return result
    
    def enumerate_target(self, target: str, port_data: Dict) -> Dict:
        """Enumera los servicios en el objetivo especificado"""
        results = {
            "services": {},
            "vulnerabilities": []
        }
        
        try:
            # Procesar cada puerto abierto
            for port in port_data.get("open_ports", []):
                port = int(port)
                service = port_data.get("services", {}).get(str(port), {})
                
                # Determinar el tipo de servicio
                service_name = service.get("service", "").lower()
                service_version = service.get("version", "")
                
                # Enumerar según el tipo de servicio
                if "http" in service_name or "ssl/http" in service_name:
                    results["services"][str(port)] = self.enumerate_web_service(target, port, "ssl" in service_name)
                elif "ftp" in service_name:
                    results["services"][str(port)] = self.enumerate_ftp_service(target, port)
                elif "ssh" in service_name:
                    results["services"][str(port)] = self.enumerate_ssh_service(target, port)
                elif "telnet" in service_name:
                    results["services"][str(port)] = self._check_telnet(target, port)
                elif "dns" in service_name:
                    results["services"][str(port)] = self.enumerate_dns_service(target)
                elif "smb" in service_name or "netbios" in service_name:
                    results["services"][str(port)] = self.enumerate_smb_service(target, port)
                elif "ldap" in service_name:
                    results["services"][str(port)] = self.enumerate_ldap_service(target)
                else:
                    # Servicio genérico
                    results["services"][str(port)] = {
                        "service": service_name,
                        "version": service_version,
                        "banner": service.get("banner", "")
                    }
                
                # Añadir información básica del servicio
                if str(port) in results["services"]:
                    results["services"][str(port)]["service"] = service_name
                    results["services"][str(port)]["version"] = service_version
            
            # Consolidar vulnerabilidades
            for port, service_data in results["services"].items():
                if "vulnerabilities" in service_data:
                    results["vulnerabilities"].extend(service_data["vulnerabilities"])
                    del service_data["vulnerabilities"]
            
        except Exception as e:
            logger.error(f"Error en enumeración de {target}: {str(e)}")
        
        return results

    def _check_telnet(self, target: str, port: int) -> Dict:
        """Verifica un servicio Telnet usando socket"""
        result = {
            "banner": "",
            "vulnerabilities": []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Intentar leer el banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            result["banner"] = banner.strip()
            
            # Verificar vulnerabilidades comunes
            if "SSH" in banner:
                result["vulnerabilities"].append({
                    "name": "SSH Service Detected",
                    "severity": "info",
                    "description": "SSH service detected on Telnet port"
                })
            
            sock.close()
            
        except Exception as e:
            logger.error(f"Error al verificar Telnet: {str(e)}")
        
        return result

def main():
    parser = argparse.ArgumentParser(description='Herramienta de enumeración de servicios')
    parser.add_argument('target', help='IP o rango de IPs a escanear')
    parser.add_argument('--ports', help='Archivo JSON con los puertos descubiertos')
    parser.add_argument('--config', help='Archivo de configuración JSON')
    parser.add_argument('--output', help='Archivo de salida JSON')
    parser.add_argument('--intensity', type=str, choices=['low', 'medium', 'high', 'stealth', 'full'],
                      default='medium', help='Intensidad del escaneo')
    args = parser.parse_args()
    
    # Inicializar el enumerador
    enumerator = ServiceEnumerator(args.config if args.config else 'config/service-enum-config.json')
    
    # Cargar datos de puertos
    try:
        with open(args.ports, 'r') as f:
            port_data = json.load(f)
    except Exception as e:
        logger.error(f"Error al cargar datos de puertos: {str(e)}")
        return
    
    # Ejecutar enumeración
    results = enumerator.enumerate_target(args.target, port_data)
    
    # Preparar resultados para stdout
    output = {
        'target': args.target,
        'scan_info': {
            'intensity': args.intensity,
            'timestamp': datetime.now().isoformat()
        },
        'open_ports': port_data.get('open_ports', []),
        'services': results.get('services', {}),
        'vulnerabilities': results.get('vulnerabilities', [])
    }
    
    # Imprimir resultados en formato JSON a stdout
    print(json.dumps(output, indent=2))
    
    # Guardar resultados en archivo si se especificó
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        logger.info(f"Resultados guardados en {args.output}")

if __name__ == '__main__':
    main() 