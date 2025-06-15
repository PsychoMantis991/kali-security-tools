#!/usr/bin/env python3

import json
import os

def test_complete_workflow_flow():
    """Test the complete workflow flow to identify where DC data is lost"""
    
    print("🔍 TESTING COMPLETE WORKFLOW FLOW")
    print("=" * 50)
    
    # Step 1: Simulate "Analyze DC Classification" output
    print("\n1️⃣ STEP 1: Analyze DC Classification Output")
    dc_classification_output = {
        "target": "10.129.95.210",
        "detailed_results": {
            "service_enumeration": {
                "services": {
                    "dns:53": {"service_name": "dns", "port": 53},
                    "kerberos-sec:88": {"service_name": "kerberos-sec", "port": 88},
                    "msrpc:135": {"service_name": "msrpc", "port": 135},
                    "netbios-ssn:139": {"service_name": "netbios-ssn", "port": 139},
                    "ldap:389": {"service_name": "ldap", "port": 389},
                    "microsoft-ds:445": {"service_name": "microsoft-ds", "port": 445},
                    "kpasswd5:464": {"service_name": "kpasswd5", "port": 464},
                    "ldaps:636": {"service_name": "ldaps", "port": 636},
                    "global-catalog:3268": {"service_name": "global-catalog", "port": 3268},
                    "global-catalog-ssl:3269": {"service_name": "global-catalog-ssl", "port": 3269},
                    "winrm:5985": {"service_name": "winrm", "port": 5985},
                    "ad-web-services:9389": {"service_name": "ad-web-services", "port": 9389}
                },
                "open_ports": [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5985, 9389]
            }
        },
        "dc_analysis": {
            "target": "10.129.95.210",
            "is_domain_controller": True,
            "confidence": "high",
            "machine_type": "domain_controller",
            "score": 290
        },
        "machine_classification": {
            "type": "domain_controller",
            "is_domain_controller": True,
            "confidence": "high",
            "score": 290
        },
        "exploitation_strategy": "active_directory"
    }
    
    print(f"✅ DC Analysis Output:")
    print(f"   - Target: {dc_classification_output['target']}")
    print(f"   - Exploitation Strategy: {dc_classification_output['exploitation_strategy']}")
    print(f"   - Machine Type: {dc_classification_output['machine_classification']['type']}")
    print(f"   - Is DC: {dc_classification_output['machine_classification']['is_domain_controller']}")
    print(f"   - Services: {len(dc_classification_output['detailed_results']['service_enumeration']['services'])}")
    
    # Step 2: Simulate "Convert to Exploitation Format" processing
    print("\n2️⃣ STEP 2: Convert to Exploitation Format Processing")
    
    # This is what the current node does (WRONG)
    enumResult = dc_classification_output
    
    # Extract services
    services = {}
    sourceServices = enumResult.get('detailed_results', {}).get('service_enumeration', {}).get('services', {})
    
    for key, serviceData in sourceServices.items():
        if ':' in key:
            serviceName, port = key.split(':')
        else:
            port = key
            serviceName = serviceData.get('service', serviceData.get('service_name', 'unknown'))
        
        serviceKey = f"{serviceName}:{port}"
        services[serviceKey] = {
            "service_name": serviceName,
            "port": int(port),
            "state": serviceData.get("state", "open"),
            "protocol": serviceData.get("protocol", "tcp"),
            "details": {
                "version": serviceData.get("version", ""),
                "product": serviceData.get("product", ""),
                "extra_info": serviceData.get("extra_info", "")
            }
        }
    
    # CRITICAL: Preserve DC data (FIXED VERSION)
    dcClassification = enumResult.get('machine_classification', {})
    dcAnalysis = enumResult.get('dc_analysis', {})
    exploitationStrategy = enumResult.get('exploitation_strategy', 'standard')
    
    target = enumResult.get('target', 'unknown')
    
    # Create exploitation data with PRESERVED DC info
    exploitationData = {
        "enumeration_results": {
            "target": target,
            "hostname": enumResult.get('hostname'),
            "scan_timestamp": enumResult.get('scan_timestamp', enumResult.get('timestamp')),
            "detailed_results": {
                "service_enumeration": {
                    "services": services,
                    "target": target,
                    "open_ports": [s["port"] for s in services.values()],
                    "vulnerability_count": 0,
                    "exploit_count": 0
                }
            },
            # PRESERVE DC information
            "machine_classification": dcClassification,
            "dc_analysis": dcAnalysis,
            "vulnerabilities": [],
            "exploits": []
        },
        "intensity": enumResult.get('intensity', 'medium'),
        "safe_mode": True,
        "enabled_tools": ['nuclei', 'gobuster', 'nikto', 'hydra', 'enum4linux'],
        # PRESERVE exploitation strategy
        "exploitation_strategy": exploitationStrategy,
        "machine_type": dcClassification.get('type', 'unknown'),
        "is_domain_controller": dcClassification.get('is_domain_controller', False),
        "confidence_level": dcClassification.get('confidence', 'low')
    }
    
    print(f"✅ Exploitation Format Output:")
    print(f"   - Target: {exploitationData['enumeration_results']['target']}")
    print(f"   - Exploitation Strategy: {exploitationData['exploitation_strategy']}")
    print(f"   - Machine Type: {exploitationData['machine_type']}")
    print(f"   - Is DC: {exploitationData['is_domain_controller']}")
    print(f"   - Services: {len(exploitationData['enumeration_results']['detailed_results']['service_enumeration']['services'])}")
    print(f"   - Open Ports: {exploitationData['enumeration_results']['detailed_results']['service_enumeration']['open_ports']}")
    
    # Step 3: Simulate "Check AD Environment" condition
    print("\n3️⃣ STEP 3: Check AD Environment Condition")
    
    condition_result = exploitationData['exploitation_strategy'] == 'active_directory'
    
    print(f"✅ Condition Check:")
    print(f"   - exploitation_strategy: '{exploitationData['exploitation_strategy']}'")
    print(f"   - exploitation_strategy === 'active_directory': {condition_result}")
    
    if condition_result:
        print("   - 🎯 RESULT: Would take TRUE branch (AD workflow)")
        workflow_branch = "AD"
    else:
        print("   - ❌ RESULT: Would take FALSE branch (standard workflow)")
        workflow_branch = "STANDARD"
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 WORKFLOW FLOW SUMMARY")
    print("=" * 50)
    print(f"Target: {target}")
    print(f"Services Detected: {len(services)}")
    print(f"DC Classification: {dcClassification.get('type', 'unknown')}")
    print(f"Exploitation Strategy: {exploitationStrategy}")
    print(f"Workflow Branch: {workflow_branch}")
    
    if workflow_branch == "AD":
        print("✅ SUCCESS: Workflow correctly identifies DC and takes AD branch")
        return True
    else:
        print("❌ FAILURE: Workflow fails to identify DC correctly")
        return False

if __name__ == "__main__":
    success = test_complete_workflow_flow()
    exit(0 if success else 1) 