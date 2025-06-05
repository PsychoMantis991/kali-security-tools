#!/usr/bin/env python3

import json
import sys
import re
from datetime import datetime

def parse_nmap_output(output):
    """Parse nmap output and extract relevant information."""
    result = {
        "target": "",
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "intensity": "full"
        },
        "open_ports": [],
        "services": {},
        "os_info": {},
        "host_info": {}
    }
    
    print("Parsing nmap output...", file=sys.stderr)
    print(f"Output length: {len(output)}", file=sys.stderr)
    
    # Try to parse as JSON first
    try:
        data = json.loads(output)
        print("Input is JSON format", file=sys.stderr)
        
        # Copy basic data from JSON
        result["target"] = data.get("target", "")
        result["scan_info"] = data.get("scan_info", result["scan_info"])
        result["open_ports"] = data.get("open_ports", [])
        
        # Process services to keep only basic info
        services = data.get("services", {})
        for port, service in services.items():
            result["services"][port] = {
                "state": service.get("state", "open"),
                "service": service.get("service", ""),
                "product": service.get("product", ""),
                "version": service.get("version", "")
            }
        
        # Extract OS and host info from nmap output
        os_match = re.search(r'Running: ([^\n]+)', output)
        if os_match:
            result["os_info"]["os"] = os_match.group(1)
            print(f"Found OS: {result['os_info']['os']}", file=sys.stderr)
        
        os_details_match = re.search(r'OS details: ([^\n]+)', output)
        if os_details_match:
            result["os_info"]["details"] = os_details_match.group(1)
            print(f"Found OS details: {result['os_info']['details']}", file=sys.stderr)
        
        # Extract host information
        host_match = re.search(r'Service Info: Host: ([^;]+)', output)
        if host_match:
            result["host_info"]["hostname"] = host_match.group(1)
            print(f"Found hostname: {result['host_info']['hostname']}", file=sys.stderr)
        
        # Extract SMB information if available
        smb_os_match = re.search(r'smb-os-discovery:.*?OS: ([^\n]+)', output, re.DOTALL)
        if smb_os_match:
            result["os_info"]["smb_os"] = smb_os_match.group(1)
            print(f"Found SMB OS: {result['os_info']['smb_os']}", file=sys.stderr)
        
        smb_computer_match = re.search(r'Computer name: ([^\n]+)', output)
        if smb_computer_match:
            result["host_info"]["computer_name"] = smb_computer_match.group(1)
            print(f"Found SMB computer name: {result['host_info']['computer_name']}", file=sys.stderr)
        
        smb_domain_match = re.search(r'Domain name: ([^\n]+)', output)
        if smb_domain_match:
            result["host_info"]["domain"] = smb_domain_match.group(1)
            print(f"Found SMB domain: {result['host_info']['domain']}", file=sys.stderr)
        
        print(f"Found target: {result['target']}", file=sys.stderr)
        print(f"Found {len(result['open_ports'])} ports", file=sys.stderr)
        return result
        
    except json.JSONDecodeError:
        print("Input is raw nmap output", file=sys.stderr)
    
    # Extract target IP
    target_match = re.search(r'Nmap scan report for ([^\n]+)', output)
    if target_match:
        result["target"] = target_match.group(1)
        print(f"Found target: {result['target']}", file=sys.stderr)
    else:
        print("Warning: Could not find target in nmap output", file=sys.stderr)
    
    # Extract OS information
    os_match = re.search(r'Running: ([^\n]+)', output)
    if os_match:
        result["os_info"]["os"] = os_match.group(1)
        print(f"Found OS: {result['os_info']['os']}", file=sys.stderr)
    
    os_details_match = re.search(r'OS details: ([^\n]+)', output)
    if os_details_match:
        result["os_info"]["details"] = os_details_match.group(1)
        print(f"Found OS details: {result['os_info']['details']}", file=sys.stderr)
    
    # Extract host information
    host_match = re.search(r'Service Info: Host: ([^;]+)', output)
    if host_match:
        result["host_info"]["hostname"] = host_match.group(1)
        print(f"Found hostname: {result['host_info']['hostname']}", file=sys.stderr)
    
    # Extract port information
    port_pattern = r'(\d+)/tcp\s+open\s+([^\s]+)(?:\s+(.+))?'
    matches = list(re.finditer(port_pattern, output))
    print(f"Found {len(matches)} port matches", file=sys.stderr)
    
    for match in matches:
        try:
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3) if match.group(3) else ""
            
            print(f"Processing port {port}: {service} {version}", file=sys.stderr)
            
            result["open_ports"].append(port)
            result["services"][str(port)] = {
                "state": "open",
                "service": service,
                "product": version.split("(")[0].strip() if "(" in version else version,
                "version": ""
            }
        except Exception as e:
            print(f"Error processing port match: {str(e)}", file=sys.stderr)
            continue
    
    print(f"Final result: {json.dumps(result, indent=2)}", file=sys.stderr)
    return result

def main():
    if len(sys.argv) != 3:
        print("Usage: process-nmap-output.py <nmap_output_file> <output_json_file>", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    print(f"Processing file: {input_file}", file=sys.stderr)
    print(f"Output will be written to: {output_file}", file=sys.stderr)
    
    try:
        with open(input_file, 'r') as f:
            content = f.read()
            
        if not content:
            print("Error: Input file is empty", file=sys.stderr)
            sys.exit(1)
        
        # Parse nmap output
        result = parse_nmap_output(content)
        
        # Write results to output file
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        # Print result to stdout for n8n
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error processing nmap output: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 