#!/usr/bin/env python3
"""
Domain Controller Detection Script
Analyzes services and determines if a target is a Domain Controller
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

class DCDetector:
    def __init__(self, target, log_level="INFO"):
        self.target = target
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # DC detection criteria
        self.dc_ports = {
            53: {"service": "DNS", "weight": 10, "critical": False},
            88: {"service": "Kerberos", "weight": 25, "critical": True},
            389: {"service": "LDAP", "weight": 25, "critical": True},
            445: {"service": "SMB", "weight": 5, "critical": False},
            464: {"service": "Kerberos Password Change", "weight": 15, "critical": False},
            593: {"service": "RPC over HTTP", "weight": 5, "critical": False},
            636: {"service": "LDAPS", "weight": 20, "critical": False},
            3268: {"service": "Global Catalog", "weight": 30, "critical": True},
            3269: {"service": "Global Catalog SSL", "weight": 30, "critical": True},
            5985: {"service": "WinRM", "weight": 5, "critical": False},
            9389: {"service": "AD Web Services", "weight": 15, "critical": False}
        }
        
        self.logger.info(f"Initialized DC detection for target: {target}")

    def analyze_services(self, services_data):
        """Analyze services to determine if target is a DC"""
        self.logger.info("Starting DC analysis")
        
        score = 0
        indicators = []
        detected_services = {}
        
        # Analyze each service
        for port_str, service_info in services_data.items():
            port = int(port_str)
            
            if port in self.dc_ports:
                dc_service = self.dc_ports[port]
                weight = dc_service["weight"]
                expected_service = dc_service["service"]
                
                score += weight
                indicators.append(f"{expected_service} ({port}) detected")
                
                detected_services[port_str] = {
                    "port": port,
                    "expected_service": expected_service,
                    "detected_service": service_info.get("service", "unknown"),
                    "version": service_info.get("version", ""),
                    "weight": weight,
                    "critical": dc_service["critical"]
                }
                
                self.logger.info(f"DC service detected: {expected_service} on port {port} (weight: {weight})")
        
        # Determine confidence level
        if score >= 100:
            confidence = "high"
            is_dc = True
        elif score >= 50:
            confidence = "medium"
            is_dc = True
        elif score >= 25:
            confidence = "low"
            is_dc = True
        else:
            confidence = "none"
            is_dc = False
        
        # Extract domain information
        domain_info = self.extract_domain_info(services_data)
        
        # Generate reasons
        reasons = self.generate_reasons(detected_services, score)
        
        dc_analysis = {
            "target": self.target,
            "is_domain_controller": is_dc,
            "confidence": confidence,
            "machine_type": "domain_controller" if is_dc else "workstation",
            "score": score,
            "indicators": indicators,
            "domain_info": domain_info,
            "reasons": reasons,
            "ad_services": {
                "ldap": any(p in ["389", "636", "3268", "3269"] for p in services_data.keys()),
                "kerberos": any(p in ["88", "464"] for p in services_data.keys()),
                "global_catalog": any(p in ["3268", "3269"] for p in services_data.keys()),
                "dns": "53" in services_data,
                "detected_services": detected_services
            },
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.info(f"DC analysis complete: {'DC' if is_dc else 'Not DC'} (confidence: {confidence}, score: {score})")
        return dc_analysis

    def extract_domain_info(self, services_data):
        """Extract domain information from service versions"""
        domain_info = {
            "domain_name": "unknown",
            "forest_name": "unknown",
            "domain_controller": False
        }
        
        # Look for domain information in LDAP services
        for port_str, service_info in services_data.items():
            version = service_info.get("version", "").lower()
            
            # Extract domain from LDAP version strings
            if "domain:" in version:
                try:
                    domain_part = version.split("domain:")[1].split(",")[0].strip()
                    if domain_part and domain_part != "unknown":
                        domain_info["domain_name"] = domain_part
                        domain_info["forest_name"] = domain_part
                        domain_info["domain_controller"] = True
                        self.logger.info(f"Domain extracted from LDAP: {domain_part}")
                except:
                    pass
            
            # Look for other domain indicators
            if any(keyword in version for keyword in ["active directory", "kerberos", "ldap"]):
                domain_info["domain_controller"] = True
        
        return domain_info

    def generate_reasons(self, detected_services, score):
        """Generate human-readable reasons for DC classification"""
        reasons = []
        
        for port_str, service_info in detected_services.items():
            service_name = service_info["expected_service"]
            if service_info["critical"]:
                reasons.append(f"{service_name} service indicates DC functionality")
        
        if score >= 100:
            reasons.append("High confidence DC classification based on service analysis")
        elif score >= 50:
            reasons.append("Medium confidence DC classification based on service analysis")
        elif score >= 25:
            reasons.append("Low confidence DC classification based on service analysis")
        else:
            reasons.append("Insufficient evidence for DC classification")
        
        return reasons

    def create_full_analysis(self, dc_analysis, services_data, open_ports):
        """Create complete analysis structure matching expected format"""
        
        # Convert services data to expected format
        formatted_services = {}
        for port_str, service_info in services_data.items():
            formatted_services[port_str] = {
                "port": int(port_str),
                "protocol": service_info.get("protocol", "tcp"),
                "state": service_info.get("state", "open"),
                "service": service_info.get("service", "unknown"),
                "version": service_info.get("version", "")
            }
        
        full_analysis = {
            "target": self.target,
            "dc_analysis": dc_analysis,
            "machine_classification": {
                "type": dc_analysis["machine_type"],
                "is_domain_controller": dc_analysis["is_domain_controller"],
                "confidence": dc_analysis["confidence"],
                "score": dc_analysis["score"],
                "analysis_timestamp": dc_analysis["timestamp"]
            },
            "detailed_results": {
                "service_enumeration": {
                    "target": self.target,
                    "services": formatted_services,
                    "open_ports": [int(p) for p in open_ports] if open_ports else list(formatted_services.keys())
                }
            },
            "exploitation_strategy": "active_directory" if dc_analysis["is_domain_controller"] else "standard"
        }
        
        return full_analysis

def main():
    parser = argparse.ArgumentParser(description="Domain Controller Detection Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--ports", help="Comma-separated list of open ports")
    parser.add_argument("--services", help="Path to services JSON file")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--log-level", default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging level")
    
    args = parser.parse_args()
    
    # Create detector
    detector = DCDetector(args.target, args.log_level)
    
    try:
        # Load services data
        if args.services:
            with open(args.services, 'r') as f:
                services_data = json.load(f)
        else:
            # Create minimal services data from ports
            services_data = {}
            if args.ports:
                for port in args.ports.split(','):
                    port = port.strip()
                    services_data[port] = {
                        "port": int(port),
                        "protocol": "tcp",
                        "state": "open",
                        "service": "unknown",
                        "version": ""
                    }
        
        if not services_data:
            detector.logger.error("No services data provided")
            sys.exit(1)
        
        # Perform DC analysis
        dc_analysis = detector.analyze_services(services_data)
        
        # Create full analysis structure
        open_ports = args.ports.split(',') if args.ports else None
        full_analysis = detector.create_full_analysis(dc_analysis, services_data, open_ports)
        
        # Save results
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(full_analysis, f, indent=2)
        
        detector.logger.info(f"DC analysis saved to: {output_path}")
        
        # Print summary
        print(f"Target: {args.target}")
        print(f"Domain Controller: {'YES' if dc_analysis['is_domain_controller'] else 'NO'}")
        print(f"Confidence: {dc_analysis['confidence']}")
        print(f"Score: {dc_analysis['score']}")
        print(f"Services analyzed: {len(services_data)}")
        print(f"Output: {output_path}")
        
        sys.exit(0)
        
    except Exception as e:
        detector.logger.error(f"DC detection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 