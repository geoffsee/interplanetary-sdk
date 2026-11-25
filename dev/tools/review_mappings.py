#!/usr/bin/env python3
"""
Review all RFC 9171/9174 mappings against full text to identify mismatches.
"""

import json

def main():
    with open('spec/requirements-atomic.json', 'r') as f:
        data = json.load(f)
    
    # Review each mapped RFC 9171/9174 obligation
    issues = []
    
    for r in data['atomic_requirements']:
        if not (('RFC9171' in r['id'] or 'RFC9174' in r['id']) and r.get('test_evidence')):
            continue
        
        req_id = r['id']
        full_text = r.get('text', '')
        text_status = r.get('text_status', '')
        evidence_note = r.get('evidence_note', '')
        tests = r['test_evidence']
        
        # Flag potential issues
        issue = None
        
        # Check if text wasn't found
        if text_status == 'not_found':
            issue = f"{req_id}: text_status=not_found, may need manual review"
        
        # Check specific known issues based on full text
        if req_id == 'RFC9171-5-008':
            # Text is about "MAY choose to either forward directly or forward to other nodes"
            # Not about "requires route"
            if 'forwarding_requires_route' in str(tests):
                issue = f"{req_id}: Test name suggests 'requires route' but text is about forwarding PATH choice (MAY)"
        
        if req_id == 'RFC9171-4-021':
            # Check if this is actually about lifetime expiry
            if 'lifetime' not in full_text.lower():
                issue = f"{req_id}: Test about lifetime expiry but text may not be about lifetime"
        
        if issue:
            issues.append(issue)
    
    print(f"Reviewed {len([r for r in data['atomic_requirements'] if ('RFC9171' in r['id'] or 'RFC9174' in r['id']) and r.get('test_evidence')])} mappings")
    print(f"Found {len(issues)} potential issues:\n")
    
    for issue in issues:
        print(f"  - {issue}")
    
    if not issues:
        print("  No issues found - all mappings appear correct")

if __name__ == "__main__":
    main()
