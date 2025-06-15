#!/usr/bin/env python3

import json
import os

def simulate_analyze_dc_classification():
    """Simulate the exact behavior of the 'Analyze DC Classification' node"""
    
    # Simulate input data (like what comes from previous nodes)
    input_data = {
        "enumeration_data": {
            "target": "10.129.95.210",
            "detailed_results": {
                "service_enumeration": {
                    "services": {
                        "dns:53": {"service_name": "dns", "port": 53},
                        "msrpc:135": {"service_name": "msrpc", "port": 135},
                        "netbios-ssn:139": {"service_name": "netbios-ssn", "port": 139},
                        "service-389:389": {"service_name": "service-389", "port": 389},
                        "microsoft-ds:445": {"service_name": "microsoft-ds", "port": 445},
                        "service-3268:3268": {"service_name": "service-3268", "port": 3268}
                    },
                    "open_ports": [53, 135, 139, 389, 445, 3268]
                }
            }
        }
    }
    
    print("🔍 Simulating 'Analyze DC Classification' node...")
    print(f"📥 Input target: {input_data['enumeration_data']['target']}")
    
    # Extract data like the node does
    result = input_data
    originalEnumerationData = result.get('enumeration_data', {})
    target = originalEnumerationData.get('target', 'unknown')
    
    print(f"🎯 Extracted target: {target}")
    
    enhanced_data = None
    
    # STRATEGY 1: Try to read existing DC analysis file (PRIORITY)
    if target != 'unknown':
        dc_analysis_file = f"temp/dc_analysis_{target.replace('.', '_')}.json"
        
        try:
            print(f"📁 Checking for file: {dc_analysis_file}")
            if os.path.exists(dc_analysis_file):
                with open(dc_analysis_file, 'r') as f:
                    enhanced_data = json.load(f)
                print("✅ SUCCESS: DC data loaded from existing file")
                print(f"✅ Exploitation strategy: {enhanced_data.get('exploitation_strategy')}")
                print(f"✅ Machine type: {enhanced_data.get('machine_classification', {}).get('type')}")
                print(f"✅ Is DC: {enhanced_data.get('dc_analysis', {}).get('is_domain_controller')}")
            else:
                print(f"❌ File does not exist: {dc_analysis_file}")
        except Exception as e:
            print(f"❌ Error reading file: {e}")
    
    # STRATEGY 2: Intelligent analysis based on detected services (fallback)
    if not enhanced_data:
        print("🔍 Performing intelligent DC analysis based on services...")
        
        services = originalEnumerationData.get('detailed_results', {}).get('service_enumeration', {}).get('services', {})
        open_ports = originalEnumerationData.get('detailed_results', {}).get('service_enumeration', {}).get('open_ports', [])
        
        print(f"📊 Available services: {list(services.keys())}")
        print(f"📊 Open ports: {open_ports}")
        
        # DC port analysis
        dc_ports = {
            389: {"service": "LDAP", "weight": 25, "critical": True},
            636: {"service": "LDAPS", "weight": 25, "critical": True},
            3268: {"service": "Global Catalog", "weight": 30, "critical": True},
            3269: {"service": "Global Catalog SSL", "weight": 30, "critical": True},
            88: {"service": "Kerberos", "weight": 25, "critical": True},
            464: {"service": "Kerberos Change Password", "weight": 20, "critical": True},
            53: {"service": "DNS", "weight": 10, "critical": False},
            9389: {"service": "AD Web Services", "weight": 15, "critical": True}
        }
        
        dc_score = 0
        indicators = []
        reasons = []
        ad_services = {}
        
        # Analyze each open port
        for port in open_ports:
            if port in dc_ports:
                port_info = dc_ports[port]
                dc_score += port_info["weight"]
                indicators.append(f"{port_info['service']} ({port}) detected")
                reasons.append(f"{port_info['service']} service indicates DC functionality")
                
                # Mark specific AD services
                if port in [389, 636]:
                    ad_services["ldap"] = True
                if port in [88, 464]:
                    ad_services["kerberos"] = True
                if port in [3268, 3269]:
                    ad_services["global_catalog"] = True
                if port == 53:
                    ad_services["dns"] = True
                if port == 9389:
                    ad_services["ad_web_services"] = True
        
        # Special detection: LDAP + Global Catalog combination
        if 389 in open_ports and 3268 in open_ports:
            dc_score += 50  # Bonus for LDAP + Global Catalog
            reasons.append("LDAP + Global Catalog combination (strong DC indicator)")
        
        # Determine classification
        machine_type = 'unknown'
        confidence = 'low'
        is_domain_controller = False
        
        if dc_score >= 80:  # Reduced threshold
            machine_type = 'domain_controller'
            confidence = 'high'
            is_domain_controller = True
            reasons.append('High confidence DC classification based on service analysis')
        elif dc_score >= 40:  # Reduced threshold
            machine_type = 'likely_domain_controller'
            confidence = 'medium'
            is_domain_controller = True
            reasons.append('Medium confidence DC classification')
        elif dc_score >= 20:  # Reduced threshold
            machine_type = 'possible_domain_controller'
            confidence = 'low'
            is_domain_controller = False
            reasons.append('Low confidence DC classification')
        
        print(f"🎯 DC analysis completed: {machine_type} (score: {dc_score}, confidence: {confidence})")
        
        # Create enhanced data with DC analysis
        enhanced_data = {
            **originalEnumerationData,
            "dc_analysis": {
                "target": target,
                "is_domain_controller": is_domain_controller,
                "confidence": confidence,
                "machine_type": machine_type,
                "score": dc_score,
                "indicators": indicators,
                "reasons": reasons,
                "ad_services": ad_services,
                "timestamp": "2025-06-15T17:25:06.106002"
            },
            "machine_classification": {
                "type": machine_type,
                "is_domain_controller": is_domain_controller,
                "confidence": confidence,
                "score": dc_score,
                "analysis_timestamp": "2025-06-15T17:25:06.106002"
            },
            "exploitation_strategy": "active_directory" if (machine_type == 'domain_controller' or machine_type == 'likely_domain_controller') else "standard"
        }
    
    # Final validation and output
    if enhanced_data:
        print("\n📊 ===== FINAL DC ANALYSIS RESULTS =====")
        print(f"🎯 Target: {enhanced_data.get('target', target)}")
        print(f"🏷️  Machine type: {enhanced_data.get('machine_classification', {}).get('type')}")
        print(f"🔒 Is DC: {enhanced_data.get('machine_classification', {}).get('is_domain_controller')}")
        print(f"⚡ Strategy: {enhanced_data.get('exploitation_strategy')}")
        print(f"📈 Confidence: {enhanced_data.get('machine_classification', {}).get('confidence')}")
        print(f"🔢 Score: {enhanced_data.get('machine_classification', {}).get('score')}")
        print("==========================================")
        
        # Check if it would trigger AD workflow
        strategy = enhanced_data.get('exploitation_strategy')
        if strategy == 'active_directory':
            print("✅ SUCCESS: Would trigger AD workflow (TRUE branch)")
        else:
            print("❌ FAILURE: Would trigger standard workflow (FALSE branch)")
            
        return enhanced_data
    else:
        print("❌ ERROR: Could not generate DC analysis")
        return None

if __name__ == "__main__":
    result = simulate_analyze_dc_classification()
    
    if result and result.get('exploitation_strategy') == 'active_directory':
        print("\n🎉 SIMULATION SUCCESSFUL - DC would be detected correctly!")
    else:
        print("\n💥 SIMULATION FAILED - DC detection not working") 