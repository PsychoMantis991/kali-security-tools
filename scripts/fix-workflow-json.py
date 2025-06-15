#!/usr/bin/env python3

import json
import os

def fix_workflow_node():
    """Fix the 'Convert to Exploitation Format' node in the workflow"""
    
    workflow_file = "workflows/Enumeracion___Explotacion.json"
    backup_file = "workflows/Enumeracion___Explotacion_before_fix.json"
    
    print("🔧 FIXING WORKFLOW NODE")
    print("=" * 50)
    
    # Create backup
    if os.path.exists(workflow_file):
        with open(workflow_file, 'r') as f:
            workflow_data = json.load(f)
        
        with open(backup_file, 'w') as f:
            json.dump(workflow_data, f, indent=2)
        print(f"✅ Backup created: {backup_file}")
    else:
        print(f"❌ Workflow file not found: {workflow_file}")
        return False
    
    # New corrected JavaScript code (single line to avoid escaping issues)
    new_js_code = "const enumResult = items[0].json; console.log('🔄 Convert to Exploitation Format - Datos recibidos:', JSON.stringify(enumResult, null, 2)); const dcClassification = enumResult.machine_classification || {}; const dcAnalysis = enumResult.dc_analysis || {}; const exploitationStrategy = enumResult.exploitation_strategy || 'standard'; console.log('📊 Datos DC preservados:'); console.log('- machine_classification:', dcClassification); console.log('- dc_analysis:', dcAnalysis); console.log('- exploitation_strategy:', exploitationStrategy); const services = {}; let sourceServices = null; if (enumResult.detailed_results?.service_enumeration?.services) { sourceServices = enumResult.detailed_results.service_enumeration.services; console.log('✅ Servicios encontrados en detailed_results.service_enumeration.services:', Object.keys(sourceServices).length); } else if (enumResult.detailed_results?.services) { sourceServices = enumResult.detailed_results.services; console.log('✅ Servicios encontrados en detailed_results.services:', Object.keys(sourceServices).length); } else if (enumResult.services) { sourceServices = enumResult.services; console.log('✅ Servicios encontrados en enumResult.services:', Object.keys(sourceServices).length); } else { console.log('❌ No se encontraron servicios en ubicaciones esperadas'); } if (sourceServices && typeof sourceServices === 'object') { Object.entries(sourceServices).forEach(([key, serviceData]) => { let port, serviceName; if (key.includes(':')) { [serviceName, port] = key.split(':'); } else { port = key; serviceName = serviceData.service || serviceData.service_name || serviceData.name || 'unknown'; } const serviceKey = `${serviceName}:${port}`; services[serviceKey] = { service_name: serviceName, port: parseInt(port), state: serviceData.state || 'open', protocol: serviceData.protocol || 'tcp', details: { version: serviceData.version || serviceData.details?.version || '', product: serviceData.product || serviceData.details?.product || '', extra_info: serviceData.extrainfo || serviceData.extra_info || serviceData.details?.extra_info || '' } }; }); } const target = enumResult.target || enumResult.enumeration_results?.target || enumResult.detailed_results?.service_enumeration?.target || 'unknown'; console.log('🎯 Target determinado:', target); console.log('📈 Servicios procesados:', Object.keys(services).length); const exploitationData = { enumeration_results: { target: target, hostname: enumResult.hostname || null, scan_timestamp: enumResult.scan_timestamp || enumResult.timestamp || new Date().toISOString(), detailed_results: { service_enumeration: { services: services, target: target, open_ports: Object.values(services).map(s => s.port), vulnerability_count: 0, exploit_count: 0 } }, machine_classification: dcClassification, dc_analysis: dcAnalysis, vulnerabilities: [], exploits: [] }, intensity: enumResult.intensity || enumResult.scan_intensity || 'medium', safe_mode: true, enabled_tools: ['nuclei', 'gobuster', 'nikto', 'hydra', 'enum4linux'], exploitation_strategy: exploitationStrategy, machine_type: dcClassification.type || 'unknown', is_domain_controller: dcClassification.is_domain_controller || dcAnalysis.is_domain_controller || false, confidence_level: dcClassification.confidence || dcAnalysis.confidence || 'low' }; console.log('🚀 Datos finales para explotación:'); console.log('- Target:', exploitationData.enumeration_results.target); console.log('- Estrategia de explotación:', exploitationData.exploitation_strategy); console.log('- Tipo de máquina:', exploitationData.machine_type); console.log('- Es DC:', exploitationData.is_domain_controller); console.log('- Confianza:', exploitationData.confidence_level); console.log('- Servicios:', Object.keys(services).length); console.log('- Puertos abiertos:', exploitationData.enumeration_results.detailed_results.service_enumeration.open_ports); if (exploitationData.exploitation_strategy === 'active_directory') { console.log('✅ SUCCESS: Workflow tomará rama AD (TRUE)'); } else { console.log('❌ WARNING: Workflow tomará rama estándar (FALSE)'); } return [{ json: exploitationData }];"
    
    # Find and update the node
    node_found = False
    for node in workflow_data.get('nodes', []):
        if node.get('name') == 'Convert to Exploitation Format':
            print(f"🎯 Found node: {node['name']}")
            print(f"   - ID: {node['id']}")
            print(f"   - Current code length: {len(node['parameters']['jsCode'])} chars")
            
            # Update the JavaScript code
            node['parameters']['jsCode'] = new_js_code
            
            print(f"   - New code length: {len(new_js_code)} chars")
            print("✅ Node updated successfully")
            node_found = True
            break
    
    if not node_found:
        print("❌ Node 'Convert to Exploitation Format' not found")
        return False
    
    # Save the updated workflow
    try:
        with open(workflow_file, 'w') as f:
            json.dump(workflow_data, f, indent=2)
        print(f"✅ Workflow saved: {workflow_file}")
        return True
    except Exception as e:
        print(f"❌ Error saving workflow: {e}")
        return False

def main():
    success = fix_workflow_node()
    
    if success:
        print("\n" + "=" * 50)
        print("🎉 WORKFLOW FIXED SUCCESSFULLY!")
        print("=" * 50)
        print("✅ El nodo 'Convert to Exploitation Format' ha sido corregido")
        print("✅ Ahora preserva correctamente los datos DC")
        print("✅ El workflow debería identificar el DC correctamente")
        print("\n🔧 PRÓXIMOS PASOS:")
        print("1. Reinicia n8n si está ejecutándose")
        print("2. Ejecuta una prueba del workflow")
        print("3. Verifica que tome la rama AD (TRUE)")
    else:
        print("\n❌ FAILED TO FIX WORKFLOW")
        print("Please check the error messages above")

if __name__ == "__main__":
    main() 