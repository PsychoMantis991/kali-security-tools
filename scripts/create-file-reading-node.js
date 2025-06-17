// IMPROVED: Convert to Exploitation Format - Lee archivo DC directamente del filesystem
const enumResult = items[0].json;

console.log('🔄 Convert to Exploitation Format - NUEVA VERSIÓN con lectura directa de archivo');
console.log('📦 Datos recibidos:', JSON.stringify(enumResult, null, 2));

// ESTRATEGIA NUEVA: Leer directamente el archivo de análisis DC del filesystem
let dcAnalysis = {};
let machineClassification = {};
let exploitationStrategy = 'standard';

// Extraer target de múltiples fuentes posibles
const target = enumResult.target || 
               enumResult.enumeration_results?.target || 
               enumResult.detailed_results?.service_enumeration?.target || 
               'unknown';

console.log('🎯 Target identificado:', target);

// Leer archivo de análisis DC directamente desde temp/
if (target !== 'unknown') {
  const fs = require('fs');
  const dcAnalysisFile = `temp/dc_analysis_${target.replace(/\./g, '_')}.json`;
  
  console.log('📂 Intentando leer archivo DC:', dcAnalysisFile);
  
  try {
    if (fs.existsSync(dcAnalysisFile)) {
      const dcFileContent = fs.readFileSync(dcAnalysisFile, 'utf8');
      const dcData = JSON.parse(dcFileContent);
      
      console.log('✅ Archivo DC leído exitosamente');
      console.log('📊 Contenido del archivo DC:', JSON.stringify(dcData, null, 2));
      
      // Extraer datos de DC del archivo
      if (dcData.dc_analysis) {
        dcAnalysis = dcData.dc_analysis;
        console.log('✅ dc_analysis extraído del archivo:', dcAnalysis);
      }
      
      if (dcData.machine_classification) {
        machineClassification = dcData.machine_classification;
        console.log('✅ machine_classification extraído del archivo:', machineClassification);
      }
      
      // Determinar estrategia de explotación basada en archivo
      const isDC = dcAnalysis.is_domain_controller || 
                   machineClassification.is_domain_controller ||
                   dcData.exploitation_strategy === 'active_directory';
      
      if (isDC) {
        exploitationStrategy = 'active_directory';
        console.log('🎯 ESTRATEGIA DETERMINADA: active_directory (desde archivo)');
      } else {
        exploitationStrategy = 'standard';
        console.log('🎯 ESTRATEGIA DETERMINADA: standard (desde archivo)');
      }
      
    } else {
      console.log('⚠️ Archivo DC no encontrado, usando datos del flujo del workflow');
      // Fallback a datos del workflow si no hay archivo
      dcAnalysis = enumResult.dc_analysis || {};
      machineClassification = enumResult.machine_classification || {};
      exploitationStrategy = enumResult.exploitation_strategy || 'standard';
    }
    
  } catch (e) {
    console.error('❌ Error leyendo archivo DC:', e.message);
    console.log('🔄 Fallback a datos del workflow');
    // Fallback a datos del workflow en caso de error
    dcAnalysis = enumResult.dc_analysis || {};
    machineClassification = enumResult.machine_classification || {};
    exploitationStrategy = enumResult.exploitation_strategy || 'standard';
  }
} else {
  console.log('⚠️ Target unknown, usando datos del workflow');
  dcAnalysis = enumResult.dc_analysis || {};
  machineClassification = enumResult.machine_classification || {};
  exploitationStrategy = enumResult.exploitation_strategy || 'standard';
}

console.log('📊 DATOS FINALES DE DC:');
console.log('- dc_analysis:', dcAnalysis);
console.log('- machine_classification:', machineClassification);
console.log('- exploitation_strategy:', exploitationStrategy);
console.log('- is_domain_controller:', dcAnalysis.is_domain_controller || machineClassification.is_domain_controller);
console.log('- machine_type:', dcAnalysis.machine_type || machineClassification.type);

// Procesamiento de servicios (mantener lógica existente)
const services = {};
let sourceServices = null;

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

console.log('📈 Servicios procesados:', Object.keys(services).length);

// Construir datos de explotación con información de DC leída del archivo
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
    machine_classification: machineClassification,
    dc_analysis: dcAnalysis,
    vulnerabilities: [],
    exploits: []
  },
  intensity: enumResult.intensity || enumResult.scan_intensity || 'medium',
  safe_mode: true,
  enabled_tools: ['nuclei', 'gobuster', 'nikto', 'hydra', 'enum4linux'],
  exploitation_strategy: exploitationStrategy,
  machine_type: machineClassification.type || dcAnalysis.machine_type || 'unknown',
  is_domain_controller: dcAnalysis.is_domain_controller || machineClassification.is_domain_controller || false,
  confidence_level: machineClassification.confidence || dcAnalysis.confidence || 'low'
};

console.log('🚀 DATOS FINALES PARA EXPLOTACIÓN:');
console.log('- Target:', exploitationData.enumeration_results.target);
console.log('- Estrategia de explotación:', exploitationData.exploitation_strategy);
console.log('- Tipo de máquina:', exploitationData.machine_type);
console.log('- Es DC:', exploitationData.is_domain_controller);
console.log('- Confianza:', exploitationData.confidence_level);
console.log('- Servicios:', Object.keys(services).length);
console.log('- Puertos abiertos:', exploitationData.enumeration_results.detailed_results.service_enumeration.open_ports);

// VALIDACIÓN CRÍTICA FINAL
if (exploitationData.exploitation_strategy === 'active_directory') {
  console.log('✅ SUCCESS: Workflow tomará rama AD (TRUE) - Archivo DC leído correctamente');
  console.log('🎯 Se ejecutarán herramientas AD: autobloody, ldapsearch, enum4linux, smbclient');
} else {
  console.log('❌ WARNING: Workflow tomará rama estándar (FALSE)');
  console.log('🔍 Verificar: archivo DC existe, target correcto, análisis DC válido');
}

return [{ json: exploitationData }]; 