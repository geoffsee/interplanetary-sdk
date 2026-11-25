#!/usr/bin/env python3
"""
List the top 10 unmapped sections by obligation count.
"""

import json
from collections import defaultdict

def main():
    with open('spec/requirements-atomic.json', 'r') as f:
        data = json.load(f)
    
    # Count unmapped obligations by section
    section_counts = defaultdict(int)
    
    for r in data['atomic_requirements']:
        if not r.get('test_evidence'):
            locator = r.get('locator', 'Unknown')
            # Extract main section (e.g., "§4.2.1" -> "§4.2")
            if '§' in locator:
                parts = locator.split('§')[1].split()[0] if '§' in locator else locator
                # Take first two numbers (e.g., "4.2.1" -> "4.2")
                nums = parts.split('.')
                if len(nums) >= 2:
                    section = f"§{nums[0]}.{nums[1]}"
                else:
                    section = f"§{nums[0]}"
                
                # Add RFC prefix
                rfc_id = r['id'].split('-')[0]
                full_section = f"{rfc_id} {section} {locator.split('§')[1].split('(')[1].split(')')[0] if '(' in locator else ''}"
                section_counts[full_section] += 1
    
    # Sort by count
    sorted_sections = sorted(section_counts.items(), key=lambda x: x[1], reverse=True)
    
    print("Top 10 Unmapped Sections by Obligation Count:")
    print("=" * 70)
    for i, (section, count) in enumerate(sorted_sections[:10], 1):
        print(f"{i:2}. {section:50} {count:3} unmapped")
    
    print()
    print(f"Total unmapped sections: {len(section_counts)}")

if __name__ == "__main__":
    main()
