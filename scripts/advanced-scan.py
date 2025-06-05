#!/usr/bin/env python3

import argparse
import logging
import json
import os
from typing import Dict, List
from pymetasploit3.msfrpc import MsfRpcClient
from advanced_workflow_orchestrator import AdvancedWorkflowOrchestrator
from generate_advanced_report import AdvancedReportGenerator

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config() -> Dict:
    """Carga la configuración desde el archivo config.json"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "orchestrator-config.json")
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error al cargar la configuración: {str(e)}")
        return {}

def load_targets(targets_file: str) -> List[str]:
    """Carga los objetivos desde un archivo"""
    try:
        with open(targets_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error al cargar objetivos: {str(e)}")
        return []

def load_credentials(creds_file: str) -> Dict:
    """Carga las credenciales desde un archivo"""
    try:
        with open(creds_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error al cargar credenciales: {str(e)}")
        return {}

def main():
    parser = argparse.ArgumentParser(description='Herramienta avanzada de pentest')
    parser.add_argument('targets_file', help='Archivo con lista de objetivos')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium',
                      help='Intensidad del escaneo')
    parser.add_argument('--creds', help='Archivo de credenciales en formato JSON')
    parser.add_argument('--output', help='Directorio de salida para los reportes',
                      default=os.path.join(os.path.dirname(__file__), "..", "reports"))
    parser.add_argument('--report-type', choices=['executive', 'technical', 'vulnerabilities', 'network', 'full'],
                      default='full', help='Tipo de reporte a generar')
    
    args = parser.parse_args()
    
    try:
        # Cargar configuración
        config = load_config()
        
        # Cargar objetivos
        targets = load_targets(args.targets_file)
        if not targets:
            logger.error("No se encontraron objetivos")
            return
        
        # Cargar credenciales si se proporcionan
        credentials = load_credentials(args.creds) if args.creds else None
        
        # Inicializar cliente Metasploit
        try:
            msf_client = MsfRpcClient(config.get('metasploit', {}).get('password', ''))
        except Exception as e:
            logger.error(f"Error al conectar con Metasploit: {str(e)}")
            msf_client = None
        
        # Crear directorio de salida
        os.makedirs(args.output, exist_ok=True)
        
        # Inicializar orquestador
        orchestrator = AdvancedWorkflowOrchestrator(msf_client, config)
        
        # Ejecutar workflow
        logger.info(f"Iniciando escaneo con intensidad {args.intensity}")
        results = orchestrator.execute_workflow(targets, args.intensity, credentials)
        
        # Generar reportes
        logger.info("Generando reportes")
        report_generator = AdvancedReportGenerator(msf_client, config)
        report = report_generator.generate_report(results, args.report_type)
        
        # Guardar resultados
        results_file = os.path.join(args.output, "scan_results.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        logger.info(f"Escaneo completado. Resultados guardados en {results_file}")
        logger.info(f"Reportes generados en {args.output}")
    
    except Exception as e:
        logger.error(f"Error en el escaneo: {str(e)}")

if __name__ == '__main__':
    main() 