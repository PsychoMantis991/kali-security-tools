#!/usr/bin/env python3
"""
Evidence Reporter Wrapper - Ultra minimal output for n8n
"""
import subprocess
import sys
import os

def main():
    # Run the original evidence reporter but capture and limit output
    try:
        # Run the original script with all arguments
        cmd = ['python3', 'scripts/evidence-reporter.py'] + sys.argv[1:]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd='/home/kali/kali-security-tools')
        
        # Extract only essential lines from stdout
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            essential_lines = []
            for line in lines:
                if any(keyword in line for keyword in ['Evidence Files Analyzed:', 'Total Vulnerabilities:', 'Risk Level:', 'Services Tested:', 'Credentials Found:', 'HTML:', 'JSON:']):
                    essential_lines.append(line)
            
            # Print only essential output
            for line in essential_lines:
                print(line)
        
        # Exit with same code as original script
        sys.exit(result.returncode)
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main() 