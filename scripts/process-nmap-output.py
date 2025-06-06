#!/usr/bin/env python3

import json
import sys
import re
import os
import glob
from datetime import datetime

def find_latest_nmap_output():
    """Find the most recent nmap output file in the temp directory."""
    temp_dir = "/home/kali/kali-security-tools/temp"
    pattern = os.path.join(temp_dir, "nmap_scan_*.json")
    files = glob.glob(pattern)
    
    if not files:
        return None
    
    # Sort files by modification time, newest first
    latest_file = max(files, key=os.path.getmtime)
    return latest_file

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
        result["scan_info"] = {
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
            "intensity": data.get("scan_info", {}).get("intensity", "full"),
            "execution_id": data.get("execution_id", "")
        }
        result["open_ports"] = data.get("open_ports", [])
        
        # Process services
        services = data.get("services", {})
        for port, service in services.items():
            result["services"][port] = {
                "state": service.get("state", "open"),
                "service": service.get("service", ""),
                "product": service.get("product", ""),
                "version": service.get("version", "")
            }
        
        # Copy OS and host info
        result["os_info"] = data.get("os_info", {})
        result["host_info"] = data.get("host_info", {})
        
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
    if len(sys.argv) < 2:
        print("Usage: process-nmap-output.py <nmap_output_file> [output_json_file]", file=sys.stderr)
        print("If <nmap_output_file> is 'auto', it will use the most recent nmap scan file", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Si el archivo de entrada es "auto", buscar el más reciente
    if input_file == "auto":
        input_file = find_latest_nmap_output()
        if not input_file:
            print("Error: No nmap output files found in temp directory", file=sys.stderr)
            sys.exit(1)
        print(f"Using latest nmap output file: {input_file}", file=sys.stderr)
        
        # Generar nombre de archivo de salida basado en el archivo de entrada
        input_filename = os.path.basename(input_file)
        output_filename = f"final-{input_filename}"
        output_file = os.path.join(os.path.dirname(input_file), output_filename)
    else:
        # Si no es auto, usar el segundo argumento como archivo de salida
        if len(sys.argv) != 3:
            print("Error: output_json_file is required when not using 'auto'", file=sys.stderr)
            sys.exit(1)
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