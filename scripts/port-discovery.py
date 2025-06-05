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

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/pentest/temp/port-discovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('port-discovery')

class PortDiscovery:
    def __init__(self, config_file='config/port-discovery-config.json'):
        self.config = self.load_config(config_file)
        
    def load_config(self, config_file):
        """Carga la configuración desde el archivo JSON"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Archivo de configuración {config_file} no encontrado. Usando configuración por defecto.")
            return {
                "scan_type": "syn",
                "evasion_techniques": [
                    "ttl_manipulation",
                    "timing",
                    "fragmentation",
                    "spoof_mac",
                    "random_ports",
                    "decoy_ips"
                ],
                "random_agent": True,
                "default_ports": {
                    "low": "20,21,22,23,25,53,80,110,143,443,445,993,995,1723,3306,3389,5900,8080",
                    "medium": "20-25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
                    "high": "1-1024,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017",
                    "full": "1-65535"
                },
                "timing_templates": {
                    "low": 3,
                    "medium": 4,
                    "high": 4,
                    "stealth": 2
                },
                "scan_options": {
                    "low": "-sS -Pn -n --open --max-retries 2 --min-rate 100",
                    "medium": "-sS -Pn -n --open --max-retries 3 --min-rate 200",
                    "high": "-sS -Pn -n --open --max-retries 4 --min-rate 500",
                    "stealth": "-sS -Pn -n --open --max-retries 1 --min-rate 50 --max-rate 100"
                },
                "service_detection": {
                    "low": "-sV --version-intensity 2",
                    "medium": "-sV --version-intensity 5",
                    "high": "-sV --version-intensity 9 --max-retries 4",
                    "stealth": "-sV --version-intensity 2 --max-retries 1",
                    "full": "-sV --version-intensity 9 --max-retries 4"
                },
                "evasion_options": {
                    "ttl_manipulation": "--ttl 64",
                    "fragmentation": "-f",
                    "spoof_mac": "--spoof-mac 0",
                    "random_ports": "--randomize-hosts",
                    "decoy_ips": "-D RND:5"
                },
                "localhost_optimization": {
                    "enabled": True,
                    "timing": 4,
                    "options": "-sS -Pn -n --open --max-retries 2"
                }
            }
    
    def get_random_agent(self):
        """Retorna un User-Agent aleatorio para evasión"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
        return random.choice(agents)
    
    def is_localhost(self, target):
        """Detecta si el objetivo es localhost"""
        return target in ['127.0.0.1', 'localhost']
    
    def get_scan_config(self, target, intensity='medium'):
        """Obtiene la configuración de escaneo según la intensidad y el objetivo"""
        is_local = self.is_localhost(target)
        
        if is_local and self.config.get('localhost_optimization', {}).get('enabled', True):
            return {
                'ports': '20,21,22,23,25,53,80,110,143,443,445,993,995,1723,3306,3389,5900,8080',
                'timing': self.config['localhost_optimization']['timing'],
                'options': self.config['localhost_optimization']['options']
            }
        
        # Configuración para diferentes intensidades en máquinas remotas
        intensity_configs = {
            'low': {
                'timing': 2,
                'options': '-sS -Pn -n --open --max-retries 1 --min-rate 100'
            },
            'medium': {
                'timing': 3,
                'options': '-sS -Pn -n --open --max-retries 2 --min-rate 200'
            },
            'high': {
                'timing': 4,
                'options': '-sS -Pn -n --open --max-retries 3 --min-rate 500'
            },
            'stealth': {
                'timing': 1,
                'options': '-sS -Pn -n --open --max-retries 1 --min-rate 50 --max-rate 100'
            },
            'full': {
                'timing': 5,
                'options': '-sS -Pn -n --open --max-retries 4 --min-rate 1000'
            }
        }
        
        config = intensity_configs.get(intensity, intensity_configs['medium'])
        return {
            'ports': '-p-',  # Escanear todos los puertos
            'timing': config['timing'],
            'options': config['options']
        }
    
    def get_evasion_args(self, target):
        if self.is_localhost(target):
            return []
        
        evasion_args = []
        evasion_techniques = self.config.get("evasion_techniques", [])
        evasion_options = self.config.get("evasion_options", {})
        
        for technique in evasion_techniques:
            if technique in evasion_options:
                if technique == "decoy_ips":
                    # Generar IPs aleatorias para los decoys
                    decoy_count = random.randint(3, 7)
                    evasion_args.append(f"-D RND:{decoy_count}")
                else:
                    evasion_args.append(evasion_options[technique])
        
        if self.config.get("random_agent", True):
            evasion_args.append(f"--script-args http.useragent='{self.get_random_agent()}'")
        
        return evasion_args
    
    def run_nmap_scan(self, target, scan_args):
        """Ejecuta un escaneo nmap y retorna el resultado en formato XML"""
        try:
            # Añadir formato XML a los argumentos
            scan_args += " -oX -"
            
            # Ejecutar nmap
            cmd = ['nmap'] + scan_args.split() + [target]
            cmd_str = ' '.join(cmd)
            logger.info(f"Ejecutando comando nmap: {cmd_str}")
            
            # Ejecutar el comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=3600  # 1 hora de timeout máximo
            )
            
            # Verificar la salida
            if not result.stdout:
                logger.error("Nmap no produjo ninguna salida")
                logger.error(f"stderr: {result.stderr}")
                return None
            
            # Verificar si hay errores en la salida
            if "WARNING" in result.stdout or "ERROR" in result.stdout:
                logger.warning("Nmap reportó advertencias o errores:")
                logger.warning(result.stdout)
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error ejecutando nmap: {e.stderr}")
            logger.error(f"Comando que falló: {cmd_str}")
            return None
        except subprocess.TimeoutExpired:
            logger.error("El escaneo de nmap excedió el tiempo máximo permitido")
            return None
        except Exception as e:
            logger.error(f"Error inesperado ejecutando nmap: {str(e)}")
            return None
    
    def parse_nmap_xml(self, xml_output):
        """Parsea la salida XML de nmap y retorna los puertos abiertos y servicios"""
        if not xml_output:
            logger.warning("No hay salida XML para parsear")
            return [], {}
        
        try:
            root = ET.fromstring(xml_output)
            open_ports = []
            services = {}
            
            # Verificar si hay hosts en la salida
            hosts = root.findall('.//host')
            if not hosts:
                logger.warning("No se encontraron hosts en la salida de nmap")
                return [], {}
            
            for host in hosts:
                # Verificar si el host está activo
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    logger.info(f"Host {host.find('address').get('addr')} está activo")
                    
                    # Buscar puertos en el host
                    ports = host.findall('.//port')
                    logger.info(f"Encontrados {len(ports)} puertos para analizar")
                    
                    for port in ports:
                        port_id = port.get('portid')
                        state = port.find('state')
                        
                        if state is not None:
                            port_state = state.get('state')
                            logger.info(f"Puerto {port_id}: {port_state}")
                            
                            if port_state == 'open':
                                open_ports.append(int(port_id))
                                logger.info(f"Puerto {port_id} está abierto")
                                
                                # Obtener información del servicio
                                service = port.find('service')
                                if service is not None:
                                    service_info = {
                                        'protocol': port.get('protocol'),
                                        'state': port_state,
                                        'service': service.get('name', ''),
                                        'product': service.get('product', ''),
                                        'version': service.get('version', ''),
                                        'extrainfo': service.get('extrainfo', '')
                                    }
                                    services[port_id] = service_info
                                    logger.info(f"Servicio detectado en puerto {port_id}: {service_info['service']} {service_info['product']} {service_info['version']}")
                else:
                    logger.warning(f"Host {host.find('address').get('addr')} está inactivo")
            
            logger.info(f"Total de puertos abiertos encontrados: {len(open_ports)}")
            logger.info(f"Total de servicios detectados: {len(services)}")
            
            return open_ports, services
            
        except ET.ParseError as e:
            logger.error(f"Error parseando XML de nmap: {str(e)}")
            logger.debug(f"Contenido XML: {xml_output}")
            return [], {}
        except Exception as e:
            logger.error(f"Error inesperado parseando XML: {str(e)}")
            return [], {}
    
    def run_initial_scan(self, target, intensity='medium'):
        """Ejecuta el escaneo inicial de puertos"""
        try:
            # Obtener configuración según intensidad
            timing = self.config['timing_templates'].get(intensity, 3)
            scan_options = self.config['scan_options'].get(intensity, '')
            
            # Construir argumentos del escaneo
            scan_args = f"-T{timing} {scan_options}"
            
            # Aplicar técnicas de evasión
            if intensity != 'stealth':
                scan_args = self.apply_evasion_techniques(scan_args)
            
            # Ejecutar nmap
            logger.info(f"Iniciando escaneo inicial con intensidad {intensity}")
            xml_output = self.run_nmap_scan(target, scan_args)
            
            if not xml_output:
                logger.error("No se pudo obtener salida del escaneo inicial")
                return []
            
            # Parsear resultados
            open_ports, _ = self.parse_nmap_xml(xml_output)
            logger.info(f"Escaneo inicial completado. Puertos abiertos: {len(open_ports)}")
            
            return open_ports
            
        except Exception as e:
            logger.error(f"Error en escaneo inicial: {str(e)}")
            return []
    
    def run_service_detection(self, target, open_ports, intensity='medium'):
        """Ejecuta la detección de servicios en los puertos abiertos"""
        try:
            if not open_ports:
                logger.warning("No hay puertos abiertos para detectar servicios")
                return {}
            
            # Obtener configuración según intensidad
            timing = self.config['timing_templates'].get(intensity, 3)
            service_options = self.config['service_detection'].get(intensity, '')
            
            # Construir argumentos del escaneo
            ports_str = ','.join(map(str, open_ports))
            scan_args = f"-T{timing} {service_options} -p{ports_str}"
            
            # Aplicar técnicas de evasión
            if intensity != 'stealth':
                scan_args = self.apply_evasion_techniques(scan_args)
            
            # Ejecutar nmap
            logger.info(f"Iniciando detección de servicios con intensidad {intensity}")
            xml_output = self.run_nmap_scan(target, scan_args)
            
            if not xml_output:
                logger.error("No se pudo obtener salida de la detección de servicios")
                return {}
            
            # Parsear resultados
            _, services = self.parse_nmap_xml(xml_output)
            logger.info(f"Detección de servicios completada. Servicios detectados: {len(services)}")
            
            return services
            
        except Exception as e:
            logger.error(f"Error en detección de servicios: {str(e)}")
            return {}
    
    def ensure_output_dir(self, output_file):
        if output_file:
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir)
                    logger.info(f"Directorio creado: {output_dir}")
                except Exception as e:
                    logger.error(f"Error creando directorio {output_dir}: {str(e)}")
                    return False
        return True
    
    def scan(self, target, intensity='medium'):
        """Ejecuta el escaneo completo de puertos y servicios"""
        try:
            logger.info(f"Iniciando escaneo de {target} con intensidad {intensity}")
            
            # Escaneo inicial de puertos
            open_ports = self.run_initial_scan(target, intensity)
            logger.info(f"Puertos abiertos encontrados: {len(open_ports)}")
            
            if not open_ports:
                logger.warning("No se encontraron puertos abiertos")
                self.save_results(target, [], {})
                return [], {}
            
            # Detección de servicios
            logger.info("Ejecutando detección de servicios...")
            services = self.run_service_detection(target, open_ports, intensity)
            logger.info(f"Servicios detectados: {len(services)}")
            
            # Guardar resultados
            self.save_results(target, open_ports, services)
            
            return open_ports, services
            
        except Exception as e:
            logger.error(f"Error en el escaneo: {str(e)}")
            return [], {}
    
    def apply_evasion_techniques(self, scan_args):
        """Aplica técnicas de evasión a los argumentos de nmap"""
        try:
            # Obtener técnicas de evasión de la configuración
            evasion = self.config.get('evasion_options', {})
            
            # Aplicar técnicas básicas
            if evasion.get('fragment_packets'):
                scan_args += " -f"
            if evasion.get('use_decoy_hosts'):
                scan_args += " -D RND:5"
            if evasion.get('spoof_mac'):
                scan_args += " --spoof-mac 0"
            if evasion.get('randomize_hosts'):
                scan_args += " --randomize-hosts"
            if evasion.get('send_ethernet'):
                scan_args += " --send-eth"
            if evasion.get('use_proxies'):
                scan_args += " --proxies http://proxy.example.com:8080"
            
            return scan_args
            
        except Exception as e:
            logger.error(f"Error aplicando técnicas de evasión: {str(e)}")
            return scan_args

    def save_results(self, target, open_ports, services):
        """Guarda los resultados del escaneo en un archivo JSON"""
        try:
            # Crear directorio temp si no existe
            os.makedirs('temp', exist_ok=True)
            
            # Preparar resultados
            results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'open_ports': open_ports,
                'services': services
            }
            
            # Guardar resultados
            output_file = 'temp/port_scan_results.json'
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            logger.info(f"Resultados guardados en {output_file}")
            
            # Verificar que los resultados se guardaron correctamente
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    saved_results = json.load(f)
                    if saved_results.get('open_ports') == open_ports and saved_results.get('services') == services:
                        logger.info(f"Verificación exitosa: {len(open_ports)} puertos y {len(services)} servicios guardados correctamente")
                    else:
                        logger.error("Error: Los resultados guardados no coinciden con los esperados")
            else:
                logger.error(f"Error: No se pudo encontrar el archivo {output_file}")
            
        except Exception as e:
            logger.error(f"Error guardando resultados: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Herramienta de descubrimiento de puertos')
    parser.add_argument('target', help='IP o rango de IPs a escanear')
    parser.add_argument('--config', help='Archivo de configuración JSON')
    parser.add_argument('--output', help='Archivo de salida JSON')
    parser.add_argument('--intensity', type=str, choices=['low', 'medium', 'high', 'stealth', 'full'],
                      default='medium', help='Intensidad del escaneo')
    parser.add_argument('--service-detection', action='store_true',
                      help='Habilitar detección de servicios')
    args = parser.parse_args()
    
    # Inicializar el escáner
    scanner = PortDiscovery(args.config if args.config else 'config/port-discovery-config.json')
    
    # Ejecutar el escaneo
    open_ports, services = scanner.scan(args.target, args.intensity)
    
    # Preparar resultados para stdout en el formato esperado
    results = {
        'target': args.target,
        'scan_info': {
            'intensity': args.intensity,
            'service_detection': args.service_detection,
            'timestamp': datetime.now().isoformat()
        },
        'open_ports': open_ports,
        'services': {
            str(port): {
                'state': 'open',
                'service': services.get(str(port), {}).get('service', 'unknown'),
                'product': services.get(str(port), {}).get('product', ''),
                'version': services.get(str(port), {}).get('version', ''),
                'extrainfo': services.get(str(port), {}).get('extrainfo', '')
            } for port in open_ports
        }
    }
    
    # Imprimir resultados en formato JSON a stdout
    print(json.dumps(results, indent=2))
    
    # Guardar resultados en archivo si se especificó
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Resultados guardados en {args.output}")

if __name__ == '__main__':
    main() 