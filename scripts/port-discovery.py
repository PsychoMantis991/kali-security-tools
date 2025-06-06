#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import json
import random
import logging
from datetime import datetime
import xml.etree.ElementTree as ET
import subprocess
import re

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/kali/kali-security-tools/temp/port-discovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('port-discovery')

class PortDiscovery:
    def __init__(self, config_file='/home/kali/kali-security-tools/config/port-discovery-config.json'):
        """Inicializa el descubridor con configuración desde archivo"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            # Configuración por defecto
            self.config = {
                "default_ports": {
                    "light": "20,21,22,23,25,53,80,110,143,443,445,993,995,1723,3306,3389,5900,8080",
                    "medium": "20-25,53,80,110-111,135-139,143,443,445,993,995,1723,3306,3389,5900,8080",
                    "full": "1-65535"
                },
                "timing_templates": {
                    "light": "3",
                    "medium": "4",
                    "full": "5"
                },
                "scan_options": {
                    "light": "-sS -sV --version-intensity 1",
                    "medium": "-sS -sV --version-intensity 3",
                    "full": "-sS -sV --version-intensity 5"
                },
                "evasion_techniques": ["ttl_manipulation", "random_agent"],
                "localhost_optimization": {
                    "enabled": True,
                    "timing": "3",
                    "options": "-sS -sV --version-intensity 1"
                }
            }
        
        # Cargar mapeo de servicios
        try:
            service_mapping_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'service-mapping.json')
            with open(service_mapping_file, 'r') as f:
                self.service_mapping = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de mapeo de servicios no encontrado: {service_mapping_file}")
            self.service_mapping = {}
    
    def load_config(self, config_file):
        """Carga configuración desde archivo"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            logger.error(f"Archivo de configuración no encontrado: {config_file}")
            return False
        return True
    
    def get_random_agent(self):
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
        ]
        return random.choice(agents)
    
    def is_localhost(self, target):
        return target in ['127.0.0.1', 'localhost']
    
    def get_scan_config(self, target, intensity='medium'):
        is_local = self.is_localhost(target)
        if is_local and self.config.get('localhost_optimization', {}).get('enabled', True):
            return {
                'options': self.config['localhost_optimization']['options'],
                'timing': self.config['localhost_optimization']['timing']
            }
        
        return {
            'options': self.config['scan_options'][intensity],
            'timing': self.config['timing_templates'][intensity]
        }
    
    def run_nmap_scan(self, target, scan_args):
        try:
            # Generar nombre de archivo único
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            execution_id = f"nmap_scan_{timestamp}"
            output_file = f"/home/kali/kali-security-tools/temp/{execution_id}.json"
            
            # Asegurarse de que no hay parámetros duplicados
            args_list = scan_args.split()
            args_list = list(dict.fromkeys(args_list))  # Eliminar duplicados
            scan_args = ' '.join(args_list)
            
            # Añadir salida XML y guardar en archivo
            scan_args += f" -oX {output_file}"
            cmd = ['nmap'] + scan_args.split() + [target]
            logger.info(f"Ejecutando comando: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Leer el archivo XML generado
            with open(output_file, 'r') as f:
                xml_output = f.read()
            
            # Convertir XML a JSON y guardar
            open_ports, services, os_info, host_info = self.parse_nmap_xml(xml_output)
            json_output = {
                'execution_id': execution_id,
                'timestamp': timestamp,
                'target': target,
                'command': ' '.join(cmd),
                'open_ports': open_ports,
                'services': services,
                'os_info': os_info,
                'host_info': host_info
            }
            
            with open(output_file, 'w') as f:
                json.dump(json_output, f, indent=2)
            
            logger.info(f"Resultados guardados en: {output_file}")
            return xml_output
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error ejecutando nmap: {e.stderr}")
            return None
        except Exception as e:
            logger.error(f"Error procesando resultados: {str(e)}")
            return None
    
    def correct_service_identification(self, service_info, os_info):
        """Corrige la identificación de servicios basado en el mapeo y el sistema operativo"""
        if not service_info or not os_info:
            return service_info

        service_name = service_info.get('service', '').lower()
        port = service_info.get('port')
        os_name = os_info.get('name', '').lower()

        # Verificar si el servicio necesita corrección
        if service_name in self.service_mapping.get('service_corrections', {}):
            correction = self.service_mapping['service_corrections'][service_name]
            
            # Verificar si la corrección aplica para el sistema operativo
            if any(os_req.lower() in os_name for os_req in correction.get('os_requirements', [])):
                service_info['service'] = correction['correct_service']
                service_info['port'] = correction['correct_port']
                service_info['exploitation_tool'] = correction['exploitation_tool']
                service_info['protocol'] = correction['protocol']
                logger.info(f"Servicio corregido: {service_name} -> {correction['correct_service']}")

        # Verificar servicios específicos del sistema operativo
        for os_type, services in self.service_mapping.get('os_specific_services', {}).items():
            if os_type.lower() in os_name:
                for service, details in services.items():
                    if port in details.get('ports', []):
                        service_info['service'] = service
                        service_info['exploitation_tool'] = details['exploitation_tool']
                        service_info['protocol'] = details['protocol']
                        logger.info(f"Servicio mapeado por OS: {service_name} -> {service}")

        return service_info

    def parse_nmap_xml(self, xml_output):
        if not xml_output:
            return [], {}, {}, {}
        try:
            root = ET.fromstring(xml_output)
            open_ports = []
            services = {}
            os_info = {}
            host_info = {}
            
            for host in root.findall('.//host'):
                # Extraer información del sistema operativo
                os_match = host.find('.//osmatch')
                if os_match is not None:
                    os_info = {
                        'name': os_match.get('name', ''),
                        'accuracy': os_match.get('accuracy', ''),
                        'line': os_match.get('line', '')
                    }
                
                # Extraer información del host
                hostnames = host.findall('.//hostname')
                if hostnames:
                    host_info['hostnames'] = [h.get('name', '') for h in hostnames]
                
                # Extraer puertos y servicios
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        open_ports.append(int(port_id))
                        service = port.find('service')
                        if service is not None:
                            service_info = {
                                'protocol': port.get('protocol'),
                                'state': state.get('state'),
                                'service': service.get('name', ''),
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', ''),
                                'port': int(port_id)
                            }
                            
                            # Corregir identificación del servicio
                            service_info = self.correct_service_identification(service_info, os_info)
                            
                            services[port_id] = service_info
            
            return open_ports, services, os_info, host_info
        except ET.ParseError as e:
            logger.error(f"Error parseando XML de nmap: {str(e)}")
            return [], {}, {}, {}
    
    def run_service_detection(self, target, ports, intensity='medium'):
        if not ports:
            logger.info("No hay puertos para escanear con nmap.")
            return {}
        try:
            scan_config = self.get_scan_config(target, intensity)
            
            # Usar las opciones directamente del archivo de configuración
            scan_args = scan_config['options']
            
            # Añadir el parámetro de puertos según la configuración
            if intensity in self.config.get('default_ports', {}):
                scan_args += f" {self.config['default_ports'][intensity]}"
            
            logger.info(f"Ejecutando detección de servicios con argumentos: {scan_args}")
            xml_output = self.run_nmap_scan(target, scan_args)
            open_ports, services, os_info, host_info = self.parse_nmap_xml(xml_output)
            
            # Añadir información de OS y host a los servicios
            for port in services:
                services[port]['os_info'] = os_info
                services[port]['host_info'] = host_info
            
            return services
        except Exception as e:
            logger.error(f"Error en detección de servicios: {str(e)}")
            return {}
    
    def scan_target(self, target, output_file=None, intensity='medium'):
        start_time = datetime.now()
        logger.info(f"Iniciando escaneo de {target} a las {start_time.strftime('%H:%M:%S')}")
        result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_info': {
                'duration': None,
                'intensity': intensity,
                'is_localhost': self.is_localhost(target),
                'techniques_used': self.config.get("evasion_techniques", [])
            },
            'open_ports': [],
            'services': {},
            'os_info': {},
            'host_info': {}
        }
        
        try:
            # 1. Escaneo inicial de puertos
            scan_config = self.get_scan_config(target, intensity)
            scan_args = scan_config['options']
            
            # Añadir el parámetro de puertos según la configuración
            if intensity in self.config.get('default_ports', {}):
                scan_args += f" {self.config['default_ports'][intensity]}"
            
            xml_output = self.run_nmap_scan(target, scan_args)
            open_ports, services, os_info, host_info = self.parse_nmap_xml(xml_output)
            
            # 2. Detección de servicios en puertos abiertos
            services = self.run_service_detection(target, open_ports, intensity)
            
            # Actualizar resultado
            result['open_ports'] = open_ports
            result['services'] = services
            result['os_info'] = os_info
            result['host_info'] = host_info
            
            # Calcular duración
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            result['scan_info']['duration'] = duration
            
            # Guardar resultado si se especificó archivo
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
            
            return result
            
        except Exception as e:
            logger.error(f"Error en escaneo de {target}: {str(e)}")
            return result

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 port-discovery.py <target> [output_file] [intensity]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    intensity = sys.argv[3] if len(sys.argv) > 3 else 'medium'
    
    discovery = PortDiscovery()
    result = discovery.scan_target(target, output_file, intensity)
    
    # Imprimir resultado en formato JSON
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main() 