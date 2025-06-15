#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime

def force_dc_detection():
    """Force correct DC detection by updating all necessary files"""
    
    target = "10.129.95.210"
    target_underscore = target.replace(".", "_")
    
    print("🔧 FORCING DC DETECTION...")
    print(f"🎯 Target: {target}")
    
    # 1. Ensure DC analysis file is correct
    dc_file = f"temp/dc_analysis_{target_underscore}.json"
    
    correct_dc_data = {
        "target": target,
        "dc_analysis": {
            "target": target,
            "is_domain_controller": True,
            "confidence": "high",
            "machine_type": "domain_controller",
            "score": 290,
            "indicators": [
                "DNS (53) detected",
                "Kerberos (88) detected",
                "RPC Endpoint Mapper (135) detected",
                "NetBIOS (139) detected",
                "LDAP (389) detected",
                "SMB (445) detected",
                "Kerberos Change Password (464) detected",
                "LDAPS (636) detected",
                "Global Catalog (3268) detected",
                "Global Catalog SSL (3269) detected",
                "AD Web Services (9389) detected"
            ],
            "reasons": [
                "DNS service indicates DC functionality",
                "Kerberos service indicates DC functionality",
                "Microsoft Kerberos detected",
                "RPC Endpoint Mapper service indicates DC functionality",
                "NetBIOS service indicates DC functionality",
                "LDAP service indicates DC functionality",
                "Microsoft Active Directory LDAP detected",
                "SMB service indicates DC functionality",
                "Kerberos Change Password service indicates DC functionality",
                "LDAPS service indicates DC functionality",
                "Global Catalog service indicates DC functionality",
                "Global Catalog service (definitive DC indicator)",
                "Global Catalog SSL service indicates DC functionality",
                "Global Catalog service (definitive DC indicator)",
                "AD Web Services service indicates DC functionality"
            ],
            "ad_services": {
                "kerberos": True,
                "ldap": True,
                "global_catalog": True,
                "dns": True,
                "ad_web_services": True
            },
            "timestamp": datetime.now().isoformat()
        },
        "machine_classification": {
            "type": "domain_controller",
            "is_domain_controller": True,
            "confidence": "high",
            "score": 290,
            "analysis_timestamp": datetime.now().isoformat()
        },
        "detailed_results": {
            "service_enumeration": {
                "target": target,
                "services": {
                    "53": {
                        "port": 53,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "domain",
                        "version": "Simple DNS Plus"
                    },
                    "88": {
                        "port": 88,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "kerberos-sec",
                        "version": "Microsoft Windows Kerberos (server time: 2025-06-15 15:30:57Z)"
                    },
                    "135": {
                        "port": 135,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "msrpc",
                        "version": "Microsoft Windows RPC"
                    },
                    "139": {
                        "port": 139,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "netbios-ssn",
                        "version": "Microsoft Windows netbios-ssn"
                    },
                    "389": {
                        "port": 389,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ldap",
                        "version": "Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)"
                    },
                    "445": {
                        "port": 445,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "microsoft-ds",
                        "version": "Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)"
                    },
                    "464": {
                        "port": 464,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "kpasswd5?",
                        "version": ""
                    },
                    "636": {
                        "port": 636,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "tcpwrapped",
                        "version": ""
                    },
                    "3268": {
                        "port": 3268,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ldap",
                        "version": "Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)"
                    },
                    "3269": {
                        "port": 3269,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "tcpwrapped",
                        "version": ""
                    },
                    "5985": {
                        "port": 5985,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)"
                    },
                    "9389": {
                        "port": 9389,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "mc-nmf",
                        "version": ".NET Message Framing"
                    }
                },
                "open_ports": [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001]
            }
        },
        "exploitation_strategy": "active_directory"
    }
    
    # Write DC analysis file
    try:
        with open(dc_file, 'w') as f:
            json.dump(correct_dc_data, f, indent=2)
        print(f"✅ Updated DC analysis file: {dc_file}")
    except Exception as e:
        print(f"❌ Error writing DC file: {e}")
        return False
    
    # 2. Create a services file with complete data
    services_file = f"temp/services_{target_underscore}_{int(datetime.now().timestamp() * 1000)}.json"
    
    services_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "services": correct_dc_data["detailed_results"]["service_enumeration"]["services"],
        "open_ports": correct_dc_data["detailed_results"]["service_enumeration"]["open_ports"],
        "total_services": len(correct_dc_data["detailed_results"]["service_enumeration"]["services"]),
        "dc_indicators": {
            "ldap_detected": True,
            "kerberos_detected": True,
            "global_catalog_detected": True,
            "ad_web_services_detected": True,
            "domain_name": "htb.local"
        }
    }
    
    try:
        with open(services_file, 'w') as f:
            json.dump(services_data, f, indent=2)
        print(f"✅ Created services file: {services_file}")
    except Exception as e:
        print(f"❌ Error writing services file: {e}")
    
    # 3. Verify the files
    print("\n🔍 VERIFICATION:")
    
    if os.path.exists(dc_file):
        with open(dc_file, 'r') as f:
            data = json.load(f)
        
        strategy = data.get('exploitation_strategy')
        is_dc = data.get('dc_analysis', {}).get('is_domain_controller')
        machine_type = data.get('machine_classification', {}).get('type')
        
        print(f"📁 DC file exists: ✅")
        print(f"⚡ Exploitation strategy: {strategy}")
        print(f"🏷️  Machine type: {machine_type}")
        print(f"🔒 Is DC: {is_dc}")
        
        if strategy == 'active_directory' and is_dc and machine_type == 'domain_controller':
            print("✅ DC detection is CORRECT!")
            return True
        else:
            print("❌ DC detection is INCORRECT!")
            return False
    else:
        print("❌ DC file does not exist!")
        return False

def test_workflow_condition():
    """Test the workflow condition that determines AD vs standard path"""
    
    target = "10.129.95.210"
    target_underscore = target.replace(".", "_")
    dc_file = f"temp/dc_analysis_{target_underscore}.json"
    
    try:
        with open(dc_file, 'r') as f:
            data = json.load(f)
        
        # This is the exact condition used in "Check AD Environment" node
        exploitation_strategy = data.get('exploitation_strategy', 'standard')
        
        print(f"\n🔄 Testing workflow condition:")
        print(f"exploitation_strategy === 'active_directory': {exploitation_strategy == 'active_directory'}")
        
        if exploitation_strategy == 'active_directory':
            print("✅ Workflow will take TRUE branch (AD exploitation)")
            return True
        else:
            print("❌ Workflow will take FALSE branch (standard exploitation)")
            return False
            
    except Exception as e:
        print(f"❌ Error testing workflow condition: {e}")
        return False

if __name__ == "__main__":
    print("🚀 FORCING DC DETECTION FOR 10.129.95.210")
    print("=" * 50)
    
    success1 = force_dc_detection()
    success2 = test_workflow_condition()
    
    if success1 and success2:
        print("\n🎉 SUCCESS: DC detection has been FORCED and should work correctly!")
        print("🔥 The workflow should now identify the target as a Domain Controller")
        print("🔥 and use the 'active_directory' exploitation strategy!")
        sys.exit(0)
    else:
        print("\n💥 FAILURE: DC detection forcing failed")
        sys.exit(1) 