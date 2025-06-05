#!/usr/bin/env python3

import argparse
import logging
import json
import os
from typing import Dict
from pymetasploit3.msfrpc import MsfRpcClient
from exploit.user_enumeration import UserEnumeration
from exploit.active_directory import ActiveDirectory
from exploit.stealth_techniques import StealthTechniques
from exploit.service_enumeration import ServiceEnumeration
from exploit.network_pivoting import NetworkPivoting
from exploit.lateral_movement import LateralMovement

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config() -> Dict:
    """Carga la configuración desde el archivo config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error al cargar la configuración: {str(e)}")
        return {}

def save_results(results: Dict, output_file: str):
    """Guarda los resultados en un archivo JSON"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Resultados guardados en {output_file}")
    except Exception as e:
        logger.error(f"Error al guardar los resultados: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Herramienta de enumeración de seguridad')
    parser.add_argument('target', help='Objetivo a enumerar (IP o hostname)')
    parser.add_argument('--username', help='Nombre de usuario para autenticación')
    parser.add_argument('--password', help='Contraseña para autenticación')
    parser.add_argument('--domain', help='Dominio para autenticación')
    parser.add_argument('--output', help='Archivo de salida para los resultados', default='enumeracion.json')
    parser.add_argument('--mode', choices=['users', 'ad', 'services', 'pivot', 'lateral', 'all'], default='all',
                      help='Modo de enumeración: users (usuarios), ad (Active Directory), services (servicios), pivot (pivoting), lateral (movimiento lateral), all (todo)')
    parser.add_argument('--stealth', action='store_true',
                      help='Activar técnicas sigilosas')
    
    args = parser.parse_args()
    
    # Cargar configuración
    config = load_config()
    
    # Configurar credenciales
    credentials = {}
    if args.username:
        credentials['username'] = args.username
    if args.password:
        credentials['password'] = args.password
    if args.domain:
        credentials['domain'] = args.domain
    
    # Inicializar cliente Metasploit
    try:
        msf_client = MsfRpcClient(config.get('metasploit', {}).get('password', ''))
    except Exception as e:
        logger.error(f"Error al conectar con Metasploit: {str(e)}")
        msf_client = None
    
    results = {}
    
    # Aplicar técnicas sigilosas si se solicita
    if args.stealth:
        logger.info("Aplicando técnicas sigilosas...")
        stealth = StealthTechniques(msf_client, config)
        results['stealth'] = stealth.apply_stealth_techniques(args.target, credentials)
    
    # Ejecutar enumeración según el modo seleccionado
    if args.mode in ['users', 'all']:
        logger.info("Iniciando enumeración de usuarios...")
        user_enum = UserEnumeration(msf_client, config)
        results['users'] = user_enum.enumerate_users(args.target, credentials)
    
    if args.mode in ['ad', 'all']:
        logger.info("Iniciando enumeración de Active Directory...")
        ad_enum = ActiveDirectory(msf_client, config)
        results['active_directory'] = ad_enum.enumerate_ad(args.target, credentials)
    
    if args.mode in ['services', 'all']:
        logger.info("Iniciando enumeración de servicios...")
        service_enum = ServiceEnumeration(msf_client, config)
        results['services'] = service_enum.enumerate_services(args.target, credentials)
    
    if args.mode in ['pivot', 'all']:
        logger.info("Iniciando pivoting de red...")
        network_pivot = NetworkPivoting(msf_client, config)
        results['pivoting'] = network_pivot.perform_pivoting(args.target, credentials)
    
    if args.mode in ['lateral', 'all']:
        logger.info("Iniciando movimiento lateral...")
        lateral_move = LateralMovement(msf_client, config)
        results['lateral_movement'] = lateral_move.perform_lateral_movement(args.target, credentials)
    
    # Guardar resultados
    save_results(results, args.output)

if __name__ == '__main__':
    main() 