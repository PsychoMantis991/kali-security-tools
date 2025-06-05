#!/usr/bin/env python3

import logging
import json
import os
import time
from typing import Dict, List, Set
from concurrent.futures import ThreadPoolExecutor
from pymetasploit3.msfrpc import MsfRpcClient
from advanced_workflow_orchestrator import AdvancedWorkflowOrchestrator
from generate_advanced_report import AdvancedReportGenerator

logger = logging.getLogger(__name__)

class NetworkDiscoveryWorkflow:
    def __init__(self, msf_client: MsfRpcClient, config: Dict):
        self.msf_client = msf_client
        self.config = config
        self.orchestrator = AdvancedWorkflowOrchestrator(msf_client, config)
        self.report_generator = AdvancedReportGenerator(msf_client, config)
        self.discovered_networks = set()
        self.scanned_targets = set()
        self.results = {
            'networks': {},
            'targets': {},
            'vulnerabilities': [],
            'credentials': [],
            'timestamps': {
                'start': time.time(),
                'end': None
            }
        }
    
    def execute_workflow(self, initial_targets: List[str], intensity: str, credentials: Optional[Dict] = None) -> Dict:
        """Ejecuta el workflow completo de descubrimiento y análisis de redes"""
        try:
            # Configurar parámetros según intensidad
            settings = self.config.get('intensity_settings', {}).get(intensity, {})
            max_threads = settings.get('max_threads', 5)
            scan_delay = settings.get('scan_delay', 2)
            
            # Procesar objetivos iniciales
            self._process_targets(initial_targets, settings, credentials)
            
            # Bucle principal de descubrimiento
            while True:
                new_targets = self._discover_new_targets()
                if not new_targets:
                    break
                
                logger.info(f"Descubiertos {len(new_targets)} nuevos objetivos")
                self._process_targets(new_targets, settings, credentials)
            
            # Finalizar workflow
            self.results['timestamps']['end'] = time.time()
            
            # Generar reportes
            self._generate_reports()
            
            return self.results
            
        except Exception as e:
            logger.error(f"Error en el workflow: {str(e)}")
            return self.results
    
    def _process_targets(self, targets: List[str], settings: Dict, credentials: Optional[Dict]) -> None:
        """Procesa un conjunto de objetivos"""
        try:
            with ThreadPoolExecutor(max_workers=settings.get('max_threads', 5)) as executor:
                futures = []
                for target in targets:
                    if target not in self.scanned_targets:
                        futures.append(executor.submit(
                            self._scan_target,
                            target,
                            settings,
                            credentials
                        ))
                        time.sleep(settings.get('scan_delay', 2))
                
                # Recolectar resultados
                for future in futures:
                    target_result = future.result()
                    if target_result:
                        self._update_results(target_result)
        
        except Exception as e:
            logger.error(f"Error al procesar objetivos: {str(e)}")
    
    def _scan_target(self, target: str, settings: Dict, credentials: Optional[Dict]) -> Dict:
        """Escanea un objetivo individual"""
        try:
            # Marcar objetivo como escaneado
            self.scanned_targets.add(target)
            
            # Ejecutar escaneo
            result = self.orchestrator._scan_target(target, settings, credentials)
            
            # Extraer información de red
            network_info = result.get(target, {}).get('network', {})
            if network_info:
                self._update_network_info(target, network_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error al escanear {target}: {str(e)}")
            return {}
    
    def _discover_new_targets(self) -> Set[str]:
        """Descubre nuevos objetivos basados en la información de red"""
        new_targets = set()
        
        try:
            for network, info in self.results['networks'].items():
                # Verificar si la red ya fue procesada
                if network in self.discovered_networks:
                    continue
                
                # Marcar red como descubierta
                self.discovered_networks.add(network)
                
                # Extraer nuevos objetivos
                for target in info.get('hosts', []):
                    if target not in self.scanned_targets:
                        new_targets.add(target)
                
                # Verificar rutas y gateways
                for route in info.get('routes', []):
                    if route not in self.scanned_targets:
                        new_targets.add(route)
                
                # Verificar servicios descubiertos
                for service in info.get('services', []):
                    if service.get('target') and service['target'] not in self.scanned_targets:
                        new_targets.add(service['target'])
        
        except Exception as e:
            logger.error(f"Error al descubrir nuevos objetivos: {str(e)}")
        
        return new_targets
    
    def _update_network_info(self, target: str, network_info: Dict) -> None:
        """Actualiza la información de red con nuevos descubrimientos"""
        try:
            # Extraer información de red
            network = network_info.get('network')
            if not network:
                return
            
            # Inicializar información de red si no existe
            if network not in self.results['networks']:
                self.results['networks'][network] = {
                    'hosts': set(),
                    'routes': set(),
                    'services': [],
                    'subnets': set()
                }
            
            # Actualizar hosts
            self.results['networks'][network]['hosts'].add(target)
            
            # Actualizar rutas
            for route in network_info.get('routes', []):
                self.results['networks'][network]['routes'].add(route)
            
            # Actualizar servicios
            for service in network_info.get('services', []):
                if service not in self.results['networks'][network]['services']:
                    self.results['networks'][network]['services'].append(service)
            
            # Actualizar subnets
            for subnet in network_info.get('subnets', []):
                self.results['networks'][network]['subnets'].add(subnet)
        
        except Exception as e:
            logger.error(f"Error al actualizar información de red: {str(e)}")
    
    def _update_results(self, target_result: Dict) -> None:
        """Actualiza los resultados globales con nueva información"""
        try:
            # Actualizar objetivos
            self.results['targets'].update(target_result)
            
            # Actualizar vulnerabilidades
            for target, info in target_result.items():
                if 'vulnerabilities' in info:
                    self.results['vulnerabilities'].extend(info['vulnerabilities'])
            
            # Actualizar credenciales
            for target, info in target_result.items():
                if 'credentials' in info:
                    self.results['credentials'].extend(info['credentials'])
        
        except Exception as e:
            logger.error(f"Error al actualizar resultados: {str(e)}")
    
    def _generate_reports(self) -> None:
        """Genera los reportes finales"""
        try:
            # Generar reporte completo
            report = self.report_generator.generate_report(self.results, 'full')
            
            # Guardar resultados en JSON
            output_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
            os.makedirs(output_dir, exist_ok=True)
            
            results_file = os.path.join(output_dir, "network_discovery_results.json")
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            
            logger.info(f"Resultados guardados en {results_file}")
        
        except Exception as e:
            logger.error(f"Error al generar reportes: {str(e)}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Workflow de descubrimiento de redes')
    parser.add_argument('targets_file', help='Archivo con lista de objetivos iniciales')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium',
                      help='Intensidad del escaneo')
    parser.add_argument('--creds', help='Archivo de credenciales en formato JSON')
    parser.add_argument('--output', help='Directorio de salida para los reportes',
                      default=os.path.join(os.path.dirname(__file__), "..", "reports"))
    
    args = parser.parse_args()
    
    try:
        # Cargar configuración
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "orchestrator-config.json")
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Cargar objetivos iniciales
        with open(args.targets_file, 'r') as f:
            initial_targets = [line.strip() for line in f if line.strip()]
        
        # Cargar credenciales si se proporcionan
        credentials = None
        if args.creds:
            with open(args.creds, 'r') as f:
                credentials = json.load(f)
        
        # Inicializar cliente Metasploit
        try:
            msf_client = MsfRpcClient(config.get('metasploit', {}).get('password', ''))
        except Exception as e:
            logger.error(f"Error al conectar con Metasploit: {str(e)}")
            msf_client = None
        
        # Crear directorio de salida
        os.makedirs(args.output, exist_ok=True)
        
        # Inicializar y ejecutar workflow
        workflow = NetworkDiscoveryWorkflow(msf_client, config)
        results = workflow.execute_workflow(initial_targets, args.intensity, credentials)
        
        logger.info("Workflow completado exitosamente")
    
    except Exception as e:
        logger.error(f"Error en el workflow: {str(e)}")

if __name__ == '__main__':
    main() 