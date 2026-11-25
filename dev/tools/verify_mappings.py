#!/usr/bin/env python3
"""
Verify all test-to-obligation mappings by printing each one with full obligation text.
This allows manual review to catch ID/text mismatches.
"""

import json
import sys

def verify_mappings():
    """Print all mappings with full obligation text for manual review."""
    
    # Load requirements
    with open('/workspace/spec/requirements-atomic.json', 'r') as f:
        data = json.load(f)
    
    # Build obligation lookup
    obligations = {req['id']: req for req in data['atomic_requirements']}
    
    # Load mappings by executing the mapping file
    import importlib.util
    spec = importlib.util.spec_from_file_location("mappings", "/workspace/tools/hand_verified_mappings.py")
    mappings_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mappings_module)
    MAPPINGS = mappings_module.MAPPINGS
    
    print("=" * 120)
    print("MAPPING VERIFICATION")
    print("=" * 120)
    print()
    
    errors = []
    verified = 0
    
    for test_name, mappings_list in sorted(MAPPINGS.items()):
        for obligation_id, note in mappings_list:
            if obligation_id not in obligations:
                errors.append(f"ERROR: {test_name} -> {obligation_id}: ID NOT FOUND in requirements-atomic.json")
                print(f"❌ {test_name}")
                print(f"   ID: {obligation_id}")
                print(f"   ERROR: ID NOT FOUND")
                print(f"   Note: {note}")
                print()
            else:
                req = obligations[obligation_id]
                print(f"✓ {test_name}")
                print(f"  ID: {obligation_id}")
                print(f"  Obligation: {req['obligation_text'][:100]}...")
                print(f"  Note: {note}")
                print()
                verified += 1
    
    print("=" * 120)
    print(f"SUMMARY: {verified} mappings verified, {len(errors)} errors")
    print("=" * 120)
    
    if errors:
        print("\nERRORS:")
        for error in errors:
            print(f"  {error}")
        sys.exit(1)
    
    return verified

if __name__ == '__main__':
    verify_mappings()
