#!/usr/bin/env python3

import json
import sys
import re
from datetime import datetime

def parse_nmap_output(output):
    """Parse nmap output and extract relevant information."""
    result = {
        "target": "",
        "open_ports": [],
        "services": {}
    }
    
    # Extract target IP
    target_match = re.search(r'Nmap scan report for ([^\n]+)', output)
    if target_match:
        result["target"] = target_match.group(1)
    
    # Extract open ports and services
    port_pattern = r'(\d+)/tcp\s+open\s+([^\s]+)(?:\s+(.+))?'
    for match in re.finditer(port_pattern, output):
        port = int(match.group(1))
        service = match.group(2)
        version = match.group(3) if match.group(3) else ""
        
        result["open_ports"].append(port)
        result["services"][str(port)] = {
            "name": service,
            "version": version.strip() if version else "unknown"
        }
    
    return result

def main():
    if len(sys.argv) != 3:
        print("Usage: process-nmap-output.py <nmap_output_file> <output_json_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(input_file, 'r') as f:
            nmap_output = f.read()
        
        # Parse nmap output
        result = parse_nmap_output(nmap_output)
        
        # Add timestamp
        result["timestamp"] = datetime.now().isoformat()
        
        # Write results to output file
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error processing nmap output: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 