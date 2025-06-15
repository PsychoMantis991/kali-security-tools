#!/usr/bin/env python3
"""
Active Directory Enumeration Script
Comprehensive AD enumeration using multiple tools and techniques
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import re
import time

class ADEnumerator:
    def __init__(self, target, output_dir="results/ad_enumeration", log_level="INFO"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Results storage
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "enumeration_results": {},
            "summary": {
                "is_domain_controller": False,
                "services_found": 0,
                "vulnerabilities": 0,
                "users_found": 0,
                "groups_found": 0,
                "shares_found": 0,
                "autobloody_success": False
            },
            "tools_used": [],
            "evidence_files": []
        }
        
        self.logger.info(f"Initialized AD enumeration for target: {target}")

    def run_command(self, command, timeout=300, capture_output=True):
        """Execute a command and return the result"""
        try:
            self.logger.debug(f"Executing: {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out: {command}")
            return None
        except Exception as e:
            self.logger.error(f"Command failed: {command} - {e}")
            return None

    def save_evidence(self, tool_name, data, file_extension="json"):
        """Save evidence to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{tool_name}_{self.target.replace('.', '_')}_{timestamp}.{file_extension}"
        filepath = self.output_dir / filename
        
        try:
            if file_extension == "json":
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filepath, 'w') as f:
                    f.write(str(data))
            
            self.results["evidence_files"].append(str(filepath))
            self.logger.info(f"Evidence saved: {filepath}")
            return str(filepath)
        except Exception as e:
            self.logger.error(f"Failed to save evidence: {e}")
            return None

    def enumerate_smb(self):
        """SMB enumeration using multiple tools"""
        self.logger.info("Starting SMB enumeration")
        smb_results = {
            "shares": [],
            "users": [],
            "groups": [],
            "policies": {},
            "null_session": False
        }
        
        # enum4linux enumeration
        self.logger.info("Running enum4linux")
        cmd = f"enum4linux -a {self.target}"
        result = self.run_command(cmd, timeout=600)
        
        if result and result.returncode == 0:
            self.results["tools_used"].append("enum4linux")
            enum4_output = result.stdout
            
            # Parse shares
            shares = re.findall(r'Sharename\s+Type\s+Comment\s*\n\s*-+\s*\n(.*?)(?=\n\n|\nS-|\nGot|\nUse|\nDone|\Z)', enum4_output, re.DOTALL)
            if shares:
                for share_block in shares:
                    share_lines = [line.strip() for line in share_block.split('\n') if line.strip()]
                    for line in share_lines:
                        if not line.startswith('-') and '|' not in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                smb_results["shares"].append({
                                    "name": parts[0],
                                    "type": parts[1],
                                    "comment": " ".join(parts[2:]) if len(parts) > 2 else ""
                                })
            
            # Parse users
            users = re.findall(r'user:\[([^\]]+)\]', enum4_output)
            smb_results["users"] = list(set(users))
            
            # Parse groups
            groups = re.findall(r'group:\[([^\]]+)\]', enum4_output)
            smb_results["groups"] = list(set(groups))
            
            # Check for null session
            if "Got domain/workgroup name" in enum4_output:
                smb_results["null_session"] = True
            
            self.save_evidence("enum4linux", {"output": enum4_output, "parsed": smb_results}, "json")
        
        # smbclient enumeration
        self.logger.info("Running smbclient")
        cmd = f"smbclient -L //{self.target} -N"
        result = self.run_command(cmd)
        
        if result and result.returncode == 0:
            self.results["tools_used"].append("smbclient")
            smbclient_output = result.stdout
            
            # Parse additional shares
            share_lines = re.findall(r'\s+(\w+)\s+Disk\s+(.*)', smbclient_output)
            for share_name, comment in share_lines:
                if not any(s["name"] == share_name for s in smb_results["shares"]):
                    smb_results["shares"].append({
                        "name": share_name,
                        "type": "Disk",
                        "comment": comment.strip()
                    })
            
            self.save_evidence("smbclient", {"output": smbclient_output}, "json")
        
        # rpcclient enumeration
        self.logger.info("Running rpcclient")
        rpc_commands = [
            "enumdomusers",
            "enumdomgroups",
            "querydominfo",
            "getdompwinfo"
        ]
        
        for rpc_cmd in rpc_commands:
            cmd = f"echo '{rpc_cmd}' | rpcclient -N {self.target}"
            result = self.run_command(cmd)
            
            if result and result.returncode == 0:
                self.results["tools_used"].append("rpcclient")
                rpc_output = result.stdout
                
                if rpc_cmd == "enumdomusers":
                    users = re.findall(r'user:\[([^\]]+)\]', rpc_output)
                    smb_results["users"].extend(users)
                elif rpc_cmd == "enumdomgroups":
                    groups = re.findall(r'group:\[([^\]]+)\]', rpc_output)
                    smb_results["groups"].extend(groups)
                
                self.save_evidence(f"rpcclient_{rpc_cmd}", {"output": rpc_output}, "json")
        
        # Remove duplicates
        smb_results["users"] = list(set(smb_results["users"]))
        smb_results["groups"] = list(set(smb_results["groups"]))
        
        self.results["enumeration_results"]["smb"] = smb_results
        self.results["summary"]["users_found"] = len(smb_results["users"])
        self.results["summary"]["groups_found"] = len(smb_results["groups"])
        self.results["summary"]["shares_found"] = len(smb_results["shares"])
        
        self.logger.info(f"SMB enumeration complete: {len(smb_results['shares'])} shares, {len(smb_results['users'])} users, {len(smb_results['groups'])} groups")

    def enumerate_ldap(self):
        """LDAP enumeration"""
        self.logger.info("Starting LDAP enumeration")
        ldap_results = {
            "base_dn": "",
            "naming_contexts": [],
            "users": [],
            "computers": [],
            "domain_info": {}
        }
        
        # ldapsearch for base information
        cmd = f"ldapsearch -x -h {self.target} -s base namingcontexts"
        result = self.run_command(cmd)
        
        if result and result.returncode == 0:
            self.results["tools_used"].append("ldapsearch")
            ldap_output = result.stdout
            
            # Extract naming contexts
            contexts = re.findall(r'namingContexts:\s*(.+)', ldap_output)
            ldap_results["naming_contexts"] = contexts
            
            if contexts:
                ldap_results["base_dn"] = contexts[0]
                
                # Enumerate users
                user_cmd = f"ldapsearch -x -h {self.target} -b '{contexts[0]}' '(objectClass=user)' sAMAccountName"
                user_result = self.run_command(user_cmd)
                
                if user_result and user_result.returncode == 0:
                    users = re.findall(r'sAMAccountName:\s*(.+)', user_result.stdout)
                    ldap_results["users"] = users
                
                # Enumerate computers
                comp_cmd = f"ldapsearch -x -h {self.target} -b '{contexts[0]}' '(objectClass=computer)' name"
                comp_result = self.run_command(comp_cmd)
                
                if comp_result and comp_result.returncode == 0:
                    computers = re.findall(r'name:\s*(.+)', comp_result.stdout)
                    ldap_results["computers"] = computers
            
            self.save_evidence("ldapsearch", {"output": ldap_output, "parsed": ldap_results}, "json")
        
        self.results["enumeration_results"]["ldap"] = ldap_results
        self.logger.info(f"LDAP enumeration complete: {len(ldap_results['users'])} users, {len(ldap_results['computers'])} computers")

    def enumerate_kerberos(self):
        """Kerberos enumeration"""
        self.logger.info("Starting Kerberos enumeration")
        kerberos_results = {
            "realm": "",
            "users": [],
            "spns": [],
            "asrep_roastable": []
        }
        
        # Try to get realm information
        cmd = f"nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='{self.target}' {self.target}"
        result = self.run_command(cmd, timeout=300)
        
        if result and result.returncode == 0:
            self.results["tools_used"].append("nmap-kerberos")
            nmap_output = result.stdout
            
            # Extract realm
            realm_match = re.search(r'Realm:\s*(.+)', nmap_output)
            if realm_match:
                kerberos_results["realm"] = realm_match.group(1).strip()
            
            self.save_evidence("nmap_kerberos", {"output": nmap_output, "parsed": kerberos_results}, "json")
        
        self.results["enumeration_results"]["kerberos"] = kerberos_results
        self.logger.info("Kerberos enumeration complete")

    def run_autobloody(self):
        """Run autobloody for AD exploitation"""
        self.logger.info("Starting autobloody enumeration")
        autobloody_results = {
            "success": False,
            "vulnerabilities": [],
            "output": ""
        }
        
        # Check if autobloody is available
        check_cmd = "which autobloody"
        check_result = self.run_command(check_cmd)
        
        if not check_result or check_result.returncode != 0:
            self.logger.warning("autobloody not found, skipping")
            return
        
        # Run autobloody
        cmd = f"autobloody -u guest -p '' -d {self.target} --host {self.target}"
        result = self.run_command(cmd, timeout=600)
        
        if result:
            self.results["tools_used"].append("autobloody")
            autobloody_output = result.stdout + result.stderr
            autobloody_results["output"] = autobloody_output
            
            if result.returncode == 0:
                autobloody_results["success"] = True
                self.results["summary"]["autobloody_success"] = True
                
                # Parse vulnerabilities (basic parsing)
                if "VULNERABLE" in autobloody_output.upper():
                    vulns = re.findall(r'(CVE-\d{4}-\d+)', autobloody_output)
                    autobloody_results["vulnerabilities"] = vulns
                    self.results["summary"]["vulnerabilities"] += len(vulns)
            
            self.save_evidence("autobloody", autobloody_results, "json")
        
        self.results["enumeration_results"]["autobloody"] = autobloody_results
        self.logger.info(f"Autobloody enumeration complete: {'Success' if autobloody_results['success'] else 'Failed'}")

    def detect_domain_controller(self):
        """Detect if target is a Domain Controller"""
        self.logger.info("Detecting Domain Controller status")
        
        # First, try to read existing DC analysis file
        dc_analysis_file = f"temp/dc_analysis_{self.target.replace('.', '_')}.json"
        
        if os.path.exists(dc_analysis_file):
            try:
                with open(dc_analysis_file, 'r') as f:
                    dc_data = json.load(f)
                
                # Check multiple possible locations for DC status
                is_dc = False
                confidence = "unknown"
                
                # Check dc_analysis section
                if "dc_analysis" in dc_data:
                    is_dc = dc_data["dc_analysis"].get("is_domain_controller", False)
                    confidence = dc_data["dc_analysis"].get("confidence", "unknown")
                
                # Check machine_classification section as backup
                elif "machine_classification" in dc_data:
                    is_dc = dc_data["machine_classification"].get("is_domain_controller", False)
                    confidence = dc_data["machine_classification"].get("confidence", "unknown")
                
                # Check root level as final backup
                else:
                    is_dc = dc_data.get("is_domain_controller", False)
                
                self.results["summary"]["is_domain_controller"] = is_dc
                self.logger.info(f"DC status from analysis file: {'YES' if is_dc else 'NO'} (confidence: {confidence})")
                
                if is_dc:
                    # Extract additional DC info if available
                    if "dc_analysis" in dc_data and "domain_info" in dc_data["dc_analysis"]:
                        domain_info = dc_data["dc_analysis"]["domain_info"]
                        self.results["summary"]["domain_name"] = domain_info.get("domain_name", "unknown")
                        self.logger.info(f"Domain detected: {domain_info.get('domain_name', 'unknown')}")
                
                return is_dc
                
            except Exception as e:
                self.logger.warning(f"Failed to read DC analysis file: {e}")
                # Fall back to manual detection
        
        # Fallback: Manual DC detection if no analysis file exists
        self.logger.info("No DC analysis file found, performing manual detection")
        
        # Check for DC-specific services
        dc_indicators = 0
        
        # Check for common DC ports
        dc_ports = [53, 88, 389, 636, 3268, 3269]
        for port in dc_ports:
            cmd = f"nmap -p {port} {self.target} | grep -q 'open'"
            result = self.run_command(cmd)
            if result and result.returncode == 0:
                dc_indicators += 1
        
        # Check LDAP for DC-specific attributes
        cmd = f"ldapsearch -x -h {self.target} -s base '(objectClass=*)' serverName"
        result = self.run_command(cmd)
        if result and result.returncode == 0 and "serverName" in result.stdout:
            dc_indicators += 2
        
        # Determine if it's a DC (lowered threshold for better detection)
        is_dc = dc_indicators >= 2  # Lowered from 3 to 2 for better detection
        self.results["summary"]["is_domain_controller"] = is_dc
        
        self.logger.info(f"Manual DC detection: {'YES' if is_dc else 'NO'} (indicators: {dc_indicators})")
        return is_dc

    def run_general_exploitation(self):
        """Run general exploitation using exploit-automation.py"""
        self.logger.info("Starting general exploitation of all services")
        
        # Create a temporary DC analysis file if it doesn't exist
        dc_analysis_file = f"temp/dc_analysis_{self.target.replace('.', '_')}.json"
        
        if not os.path.exists(dc_analysis_file):
            self.logger.warning(f"DC analysis file not found: {dc_analysis_file}")
            self.logger.info("Running port discovery first...")
            
            # Run port discovery
            port_cmd = f"python3 scripts/port-discovery.py \"{self.target}\" --intensity medium --service-detection --output \"temp/ports_{self.target.replace('.', '_')}.json\""
            port_result = self.run_command(port_cmd, timeout=300)
            
            if port_result and port_result.returncode == 0:
                self.logger.info("Port discovery completed")
                
                # Run DC detection
                dc_cmd = f"python3 scripts/dc-detection.py \"{self.target}\" --output \"{dc_analysis_file}\""
                dc_result = self.run_command(dc_cmd, timeout=180)
                
                if dc_result and dc_result.returncode == 0:
                    self.logger.info(f"DC analysis file created: {dc_analysis_file}")
                else:
                    self.logger.error("Failed to create DC analysis file")
                    return False
            else:
                self.logger.error("Port discovery failed")
                return False
        
        # Run exploit-automation.py
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exploit_output = f"temp/ad_exploitation_{self.target.replace('.', '_')}_{timestamp}.json"
        
        exploit_cmd = f"python3 scripts/exploit-automation.py \"{dc_analysis_file}\" --intensity medium --log-level INFO --output \"{exploit_output}\""
        
        self.logger.info(f"Running general exploitation: {exploit_cmd}")
        exploit_result = self.run_command(exploit_cmd, timeout=1800)  # 30 minutes timeout
        
        if exploit_result:
            self.results["tools_used"].append("exploit-automation")
            
            # Parse exploitation results
            try:
                if os.path.exists(exploit_output):
                    with open(exploit_output, 'r') as f:
                        exploit_data = json.load(f)
                    
                    self.results["general_exploitation"] = exploit_data
                    
                    # Update summary with exploitation results
                    if "summary" in exploit_data:
                        summary = exploit_data["summary"]
                        self.results["summary"]["vulnerabilities"] += summary.get("vulnerabilities_found", 0)
                        self.results["summary"]["services_found"] += summary.get("total_services", 0)
                        
                        # Add credentials if found
                        if summary.get("credentials_discovered", 0) > 0:
                            self.results["summary"]["credentials_found"] = summary.get("credentials_discovered", 0)
                    
                    self.logger.info(f"General exploitation completed. Results saved to: {exploit_output}")
                    return True
                else:
                    self.logger.warning("Exploitation output file not found, but command completed")
                    self.results["general_exploitation"] = {
                        "status": "completed_no_output",
                        "stdout": exploit_result.stdout,
                        "stderr": exploit_result.stderr
                    }
                    return True
                    
            except Exception as e:
                self.logger.error(f"Failed to parse exploitation results: {e}")
                self.results["general_exploitation"] = {
                    "status": "parse_error",
                    "error": str(e),
                    "stdout": exploit_result.stdout if exploit_result else "",
                    "stderr": exploit_result.stderr if exploit_result else ""
                }
                return False
        else:
            self.logger.error("General exploitation failed")
            return False

    def run_comprehensive_enumeration(self):
        """Run all enumeration techniques"""
        self.logger.info("Starting comprehensive AD enumeration and exploitation")
        
        try:
            # Step 1: Detect DC first
            self.detect_domain_controller()
            
            # Step 2: Run general exploitation of ALL services
            self.logger.info("=== PHASE 1: General Service Exploitation ===")
            general_exploit_success = self.run_general_exploitation()
            
            # Step 3: Run AD-specific enumeration
            self.logger.info("=== PHASE 2: AD-Specific Enumeration ===")
            self.enumerate_smb()
            self.enumerate_ldap()
            self.enumerate_kerberos()
            
            # Step 4: Run autobloody for AD-specific exploitation
            self.logger.info("=== PHASE 3: AD-Specific Exploitation ===")
            self.run_autobloody()
            
            # Update services count
            self.results["summary"]["services_found"] = len(self.results["tools_used"])
            
            # Add phase completion status
            self.results["phases"] = {
                "general_exploitation": general_exploit_success,
                "ad_enumeration": True,
                "ad_exploitation": True
            }
            
            # Save final results
            final_report = self.output_dir / f"ad_comprehensive_report_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(final_report, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            self.logger.info(f"Comprehensive enumeration and exploitation complete. Report saved: {final_report}")
            
            # Print summary
            self.print_summary()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Comprehensive enumeration failed: {e}")
            return False

    def print_summary(self):
        """Print enumeration summary"""
        print("\n" + "="*50)
        print("=== AD Enumeration Summary ===")
        print("="*50)
        print(f"Target: {self.target}")
        print(f"Domain Controller: {'YES' if self.results['summary']['is_domain_controller'] else 'NO'}")
        print(f"Services Found: {self.results['summary']['services_found']}")
        print(f"Users Found: {self.results['summary']['users_found']}")
        print(f"Groups Found: {self.results['summary']['groups_found']}")
        print(f"Shares Found: {self.results['summary']['shares_found']}")
        print(f"Vulnerabilities: {self.results['summary']['vulnerabilities']}")
        print(f"Autobloody Success: {'YES' if self.results['summary']['autobloody_success'] else 'NO'}")
        print(f"Tools Used: {', '.join(self.results["tools_used"])}")
        print(f"Evidence Files: {len(self.results['evidence_files'])}")
        print(f"Output Directory: {self.output_dir}")
        print("="*50)

def main():
    parser = argparse.ArgumentParser(description="Active Directory Enumeration Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--output-dir", default="results/ad_enumeration", 
                       help="Output directory for results")
    parser.add_argument("--log-level", default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging level")
    parser.add_argument("--timeout", type=int, default=300,
                       help="Command timeout in seconds")
    
    args = parser.parse_args()
    
    # Create enumerator
    enumerator = ADEnumerator(args.target, args.output_dir, args.log_level)
    
    # Run enumeration
    success = enumerator.run_comprehensive_enumeration()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
