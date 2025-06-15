#!/usr/bin/env python3

def generate_fixed_node_code():
    """Generate the correct JavaScript code for the 'Convert to Exploitation Format' node"""
    
    js_code = '''// FIXED: Convert to Exploitation Format - Preserva datos DC correctamente
const enumResult = items[0].json;

console.log('🔄 Convert to Exploitation Format - Datos recibidos:', JSON.stringify(enumResult, null, 2));

// PRIORIDAD 1: Preservar datos DC del análisis previo
const dcClassification = enumResult.machine_classification || {};
const dcAnalysis = enumResult.dc_analysis || {};
const exploitationStrategy = enumResult.exploitation_strategy || 'standard';

console.log('📊 Datos DC preservados:');
console.log('- machine_classification:', dcClassification);
console.log('- dc_analysis:', dcAnalysis);
console.log('- exploitation_strategy:', exploitationStrategy);

// Extraer servicios de los datos de enumeración originales
const services = {};
let sourceServices = null;

// Buscar servicios en detailed_results (datos originales de enumeración)
if (enumResult.detailed_results?.service_enumeration?.services) {
  sourceServices = enumResult.detailed_results.service_enumeration.services;
  console.log('✅ Servicios encontrados en detailed_results.service_enumeration.services:', Object.keys(sourceServices).length);
} else if (enumResult.detailed_results?.services) {
  sourceServices = enumResult.detailed_results.services;
  console.log('✅ Servicios encontrados en detailed_results.services:', Object.keys(sourceServices).length);
} else if (enumResult.services) {
  sourceServices = enumResult.services;
  console.log('✅ Servicios encontrados en enumResult.services:', Object.keys(sourceServices).length);
} else {
  console.log('❌ No se encontraron servicios en ubicaciones esperadas');
}

// Procesar servicios si se encontraron
if (sourceServices && typeof sourceServices === 'object') {
  Object.entries(sourceServices).forEach(([key, serviceData]) => {
    let port, serviceName;
    
    if (key.includes(':')) {
      [serviceName, port] = key.split(':');
    } else {
      port = key;
      serviceName = serviceData.service || serviceData.service_name || serviceData.name || 'unknown';
    }
    
    const serviceKey = `${serviceName}:${port}`;
    
    services[serviceKey] = {
      service_name: serviceName,
      port: parseInt(port),
      state: serviceData.state || 'open',
      protocol: serviceData.protocol || 'tcp',
      details: {
        version: serviceData.version || serviceData.details?.version || '',
        product: serviceData.product || serviceData.details?.product || '',
        extra_info: serviceData.extrainfo || serviceData.extra_info || serviceData.details?.extra_info || ''
      }
    };
  });
}

// Extraer target
const target = enumResult.target || 
               enumResult.enumeration_results?.target ||
               enumResult.detailed_results?.service_enumeration?.target ||
               'unknown';

console.log('🎯 Target determinado:', target);
console.log('📈 Servicios procesados:', Object.keys(services).length);

// CRÍTICO: Preservar TODOS los datos DC del análisis previo
const exploitationData = {
  enumeration_results: {
    target: target,
    hostname: enumResult.hostname || null,
    scan_timestamp: enumResult.scan_timestamp || enumResult.timestamp || new Date().toISOString(),
    detailed_results: {
      service_enumeration: {
        services: services,
        target: target,
        open_ports: Object.values(services).map(s => s.port),
        vulnerability_count: 0,
        exploit_count: 0
      }
    },
    // PRESERVAR información crítica de clasificación DC
    machine_classification: dcClassification,
    dc_analysis: dcAnalysis,
    vulnerabilities: [],
    exploits: []
  },
  intensity: enumResult.intensity || enumResult.scan_intensity || 'medium',
  safe_mode: true,
  enabled_tools: ['nuclei', 'gobuster', 'nikto', 'hydra', 'enum4linux'],
  // PRESERVAR estrategia determinada por el análisis DC
  exploitation_strategy: exploitationStrategy,
  // PRESERVAR información adicional DC
  machine_type: dcClassification.type || 'unknown',
  is_domain_controller: dcClassification.is_domain_controller || dcAnalysis.is_domain_controller || false,
  confidence_level: dcClassification.confidence || dcAnalysis.confidence || 'low'
};

console.log('🚀 Datos finales para explotación:');
console.log('- Target:', exploitationData.enumeration_results.target);
console.log('- Estrategia de explotación:', exploitationData.exploitation_strategy);
console.log('- Tipo de máquina:', exploitationData.machine_type);
console.log('- Es DC:', exploitationData.is_domain_controller);
console.log('- Confianza:', exploitationData.confidence_level);
console.log('- Servicios:', Object.keys(services).length);
console.log('- Puertos abiertos:', exploitationData.enumeration_results.detailed_results.service_enumeration.open_ports);

// VALIDACIÓN FINAL
if (exploitationData.exploitation_strategy === 'active_directory') {
  console.log('✅ SUCCESS: Workflow tomará rama AD (TRUE)');
} else {
  console.log('❌ WARNING: Workflow tomará rama estándar (FALSE)');
}

return [{ json: exploitationData }];'''

    return js_code

def main():
    print("🔧 GENERANDO CÓDIGO CORREGIDO PARA EL NODO")
    print("=" * 50)
    
    js_code = generate_fixed_node_code()
    
    print("📝 Código JavaScript generado:")
    print("=" * 50)
    print(js_code)
    print("=" * 50)
    
    # Save to file for easy copying
    with open('temp/fixed_node_code.js', 'w') as f:
        f.write(js_code)
    
    print("✅ Código guardado en: temp/fixed_node_code.js")
    print("\n🔧 INSTRUCCIONES:")
    print("1. Copia este código JavaScript")
    print("2. Reemplaza el código del nodo 'Convert to Exploitation Format' en el workflow")
    print("3. Guarda el workflow")
    print("4. Ejecuta una prueba")

if __name__ == "__main__":
    main() 