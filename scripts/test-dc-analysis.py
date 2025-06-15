#!/usr/bin/env python3

import json
import sys
import os

def test_dc_analysis():
    """Test DC analysis with the corrected file"""
    
    # Read the DC analysis file
    dc_file = "temp/dc_analysis_10_129_95_210.json"
    
    if not os.path.exists(dc_file):
        print(f"❌ ERROR: File {dc_file} does not exist")
        return False
    
    try:
        with open(dc_file, 'r') as f:
            dc_data = json.load(f)
        
        print("📊 DC Analysis File Content:")
        print(f"🎯 Target: {dc_data.get('target', 'unknown')}")
        print(f"⚡ Exploitation Strategy: {dc_data.get('exploitation_strategy', 'unknown')}")
        print(f"🏷️  Machine Type: {dc_data.get('machine_classification', {}).get('type', 'unknown')}")
        print(f"🔒 Is DC: {dc_data.get('dc_analysis', {}).get('is_domain_controller', False)}")
        print(f"📈 Confidence: {dc_data.get('dc_analysis', {}).get('confidence', 'unknown')}")
        print(f"🔢 Score: {dc_data.get('dc_analysis', {}).get('score', 0)}")
        
        # Check if it should trigger AD workflow
        exploitation_strategy = dc_data.get('exploitation_strategy', 'standard')
        is_dc = dc_data.get('dc_analysis', {}).get('is_domain_controller', False)
        
        print("\n🔍 Analysis Results:")
        print(f"Should use AD workflow: {exploitation_strategy == 'active_directory'}")
        print(f"DC detected: {is_dc}")
        
        if exploitation_strategy == 'active_directory' and is_dc:
            print("✅ SUCCESS: DC correctly identified, should trigger AD workflow")
            return True
        else:
            print("❌ FAILURE: DC not correctly identified")
            return False
            
    except Exception as e:
        print(f"❌ ERROR reading DC file: {e}")
        return False

def simulate_workflow_check():
    """Simulate the workflow check condition"""
    
    dc_file = "temp/dc_analysis_10_129_95_210.json"
    
    try:
        with open(dc_file, 'r') as f:
            data = json.load(f)
        
        # Simulate the "Check AD Environment" node condition
        exploitation_strategy = data.get('exploitation_strategy', 'standard')
        
        print(f"\n🔄 Simulating workflow condition:")
        print(f"exploitation_strategy === 'active_directory': {exploitation_strategy == 'active_directory'}")
        
        if exploitation_strategy == 'active_directory':
            print("✅ Would take TRUE branch (AD workflow)")
        else:
            print("❌ Would take FALSE branch (standard workflow)")
            
        return exploitation_strategy == 'active_directory'
        
    except Exception as e:
        print(f"❌ ERROR in workflow simulation: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing DC Analysis...")
    
    success1 = test_dc_analysis()
    success2 = simulate_workflow_check()
    
    if success1 and success2:
        print("\n🎉 ALL TESTS PASSED - DC analysis is working correctly!")
        sys.exit(0)
    else:
        print("\n💥 TESTS FAILED - DC analysis needs fixing")
        sys.exit(1) 