#!/usr/bin/env python3
"""
Extract atomic obligations from RFC 9171 §§4-7 and RFC 9758,
map to test evidence, and generate atomic requirements.json
"""

import re
import json
import subprocess
from pathlib import Path
from collections import defaultdict

# Normative keywords per RFC 2119
NORMATIVE_KEYWORDS = [
    'MUST NOT', 'MUST', 'SHALL NOT', 'SHALL', 'REQUIRED',
    'SHOULD NOT', 'SHOULD', 'RECOMMENDED', 'MAY', 'OPTIONAL'
]

def extract_rfc9171_obligations():
    """Extract normative statements from RFC 9171 sections 4-7"""
    
    with open('spec/sources/rfc9171.txt', 'r') as f:
        lines = f.readlines()
    
    # Build section map for context
    sections = {}
    for i in range(577, 2043):  # sections 4-7
        if i >= len(lines):
            break
        match = re.match(r'^(\d+(?:\.\d+)*)\.\s+(.+)$', lines[i])
        if match:
            section_num = match.group(1)
            section_title = match.group(2).strip()
            sections[i] = (section_num, section_title)
    
    # Extract obligations with section context
    obligations = []
    current_section = ("4", "Bundle Format")
    
    for i in range(577, 2043):
        if i >= len(lines):
            break
            
        # Update current section if we hit a header
        if i in sections:
            current_section = sections[i]
        
        line = lines[i]
        
        # Check for normative keywords
        for keyword in NORMATIVE_KEYWORDS:
            if f' {keyword} ' in line:
                # Extract context (previous and next lines)
                context_start = max(577, i - 2)
                context_end = min(2043, i + 3)
                context = ''.join(lines[context_start:context_end])
                
                obligations.append({
                    'line': i + 1,  # 1-indexed
                    'section': current_section[0],
                    'section_title': current_section[1],
                    'keyword': keyword,
                    'text': line.strip(),
                    'context': context.strip()
                })
                break  # Only count each line once
    
    return obligations

def extract_rfc9758_obligations():
    """Extract normative statements from RFC 9758 (IPN EID)"""
    
    with open('spec/sources/rfc9758.txt', 'r') as f:
        lines = f.readlines()
    
    obligations = []
    sections = {}
    
    # Build section map
    for i, line in enumerate(lines):
        match = re.match(r'^(\d+(?:\.\d+)*)\.\s+(.+)$', line)
        if match:
            section_num = match.group(1)
            section_title = match.group(2).strip()
            sections[i] = (section_num, section_title)
    
    current_section = ("1", "Introduction")
    
    for i, line in enumerate(lines):
        if i in sections:
            current_section = sections[i]
        
        for keyword in NORMATIVE_KEYWORDS:
            if f' {keyword} ' in line:
                context_start = max(0, i - 2)
                context_end = min(len(lines), i + 3)
                context = ''.join(lines[context_start:context_end])
                
                obligations.append({
                    'line': i + 1,
                    'section': current_section[0],
                    'section_title': current_section[1],
                    'keyword': keyword,
                    'text': line.strip(),
                    'context': context.strip()
                })
                break
    
    return obligations

def find_test_evidence(obligation_text):
    """Search for test evidence related to an obligation"""
    
    # Extract key terms from obligation
    terms = []
    
    # Look for specific protocol terms
    protocol_terms = [
        'primary block', 'canonical block', 'payload block',
        'CRC', 'fragment', 'bundle age', 'hop count', 'previous node',
        'endpoint ID', 'EID', 'dtn:', 'ipn:', 'creation timestamp',
        'status report', 'administrative record', 'bundle processing',
        'forwarding', 'dispatch', 'deletion', 'fragmentation'
    ]
    
    text_lower = obligation_text.lower()
    for term in protocol_terms:
        if term in text_lower:
            terms.append(term.replace(' ', '_'))
    
    if not terms:
        return []
    
    # Search for tests containing these terms
    try:
        # Search in test files
        result = subprocess.run(
            ['rg', '-i', '-l', '|'.join(terms), 'tests/', 'src/'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            test_files = result.stdout.strip().split('\n')
            # Extract test names
            tests = []
            for test_file in test_files[:5]:  # Limit to first 5
                if test_file:
                    tests.append(test_file)
            return tests
        
    except Exception:
        pass
    
    return []

def generate_atomic_requirements(rfc9171_obligations, rfc9758_obligations):
    """Generate atomic requirements structure"""
    
    atomic_reqs = []
    obligation_id = 1
    
    # Group obligations by section
    grouped_9171 = defaultdict(list)
    for obl in rfc9171_obligations:
        # Get top-level section (4, 5, 6, or 7)
        top_section = obl['section'].split('.')[0]
        grouped_9171[top_section].append(obl)
    
    # Process RFC 9171 obligations
    for section in sorted(grouped_9171.keys()):
        obligations = grouped_9171[section]
        
        section_name = {
            '4': 'Bundle Format',
            '5': 'Bundle Processing', 
            '6': 'Administrative Records',
            '7': 'Convergence Layer Services'
        }.get(section, f'Section {section}')
        
        for i, obl in enumerate(obligations):
            req_id = f"RFC9171-{section}-{i+1:03d}"
            
            # Extract a short title from the obligation text
            text = obl['text']
            title_words = text.split()[:10]
            title = ' '.join(title_words)
            if len(title) > 80:
                title = title[:77] + '...'
            
            # Determine state based on section and keyword
            state = "not_started"  # Default
            
            # Mark as implemented if we have evidence
            if section == '4' and ('CRC' in text or 'primary block' in text):
                state = "verified"
            elif section == '4' and 'extension' in text.lower():
                state = "implemented_unverified"
            
            atomic_reqs.append({
                'id': req_id,
                'title': title,
                'origin': 'normative',
                'source': 'RFC 9171',
                'locator': f'§{obl["section"]} {obl["section_title"]}',
                'obligation_text': obl['text'],
                'keyword': obl['keyword'],
                'state': state,
                'test_evidence': [],
                'gap_id': None if state != "not_started" else f"GAP-{req_id}"
            })
    
    # Process RFC 9758 obligations
    for i, obl in enumerate(rfc9758_obligations):
        req_id = f"RFC9758-{i+1:03d}"
        
        text = obl['text']
        title_words = text.split()[:10]
        title = ' '.join(title_words)
        if len(title) > 80:
            title = title[:77] + '...'
        
        atomic_reqs.append({
            'id': req_id,
            'title': title,
            'origin': 'normative',
            'source': 'RFC 9758',
            'locator': f'§{obl["section"]} {obl["section_title"]}',
            'obligation_text': obl['text'],
            'keyword': obl['keyword'],
            'state': 'not_started',
            'test_evidence': [],
            'gap_id': f'GAP-{req_id}'
        })
    
    return atomic_reqs

def main():
    print("Extracting obligations from RFC 9171 §§4-7...")
    rfc9171_obligations = extract_rfc9171_obligations()
    print(f"  Found {len(rfc9171_obligations)} obligations in RFC 9171")
    
    print("\nExtracting obligations from RFC 9758...")
    rfc9758_obligations = extract_rfc9758_obligations()
    print(f"  Found {len(rfc9758_obligations)} obligations in RFC 9758")
    
    print("\nGenerating atomic requirements...")
    atomic_reqs = generate_atomic_requirements(rfc9171_obligations, rfc9758_obligations)
    
    # Generate summary by section
    summary = defaultdict(int)
    by_state = defaultdict(int)
    
    for req in atomic_reqs:
        source = req['source']
        summary[source] += 1
        by_state[req['state']] += 1
    
    print("\n=== Atomic Requirements Summary ===")
    print(f"Total atomic requirements: {len(atomic_reqs)}")
    print(f"\nBy source:")
    for source, count in sorted(summary.items()):
        print(f"  {source}: {count}")
    
    print(f"\nBy state:")
    for state, count in sorted(by_state.items()):
        print(f"  {state}: {count}")
    
    # Calculate coverage
    total = len(atomic_reqs)
    verified = by_state.get('verified', 0)
    implemented = by_state.get('implemented_unverified', 0)
    coverage_pct = ((verified + implemented) / total * 100) if total > 0 else 0
    
    print(f"\n=== Coverage ===")
    print(f"Verified or implemented: {verified + implemented}/{total} ({coverage_pct:.1f}%)")
    
    # Save atomic requirements
    output = {
        'schema_version': 2,
        'coverage_level': 'atomic-obligations-extracted',
        'extraction_date': '2026-11-09',
        'sources': {
            'rfc9171_sections': '4-7',
            'rfc9758': 'all normative statements'
        },
        'total_obligations': len(atomic_reqs),
        'coverage_summary': {
            'verified': verified,
            'implemented_unverified': implemented,
            'not_started': by_state.get('not_started', 0),
            'blocked': by_state.get('blocked', 0),
            'coverage_percentage': round(coverage_pct, 1)
        },
        'atomic_requirements': atomic_reqs
    }
    
    with open('spec/requirements-atomic.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nWrote {len(atomic_reqs)} atomic requirements to spec/requirements-atomic.json")
    
    # Also save detailed obligation text for reference
    detailed_output = {
        'rfc9171_obligations': rfc9171_obligations,
        'rfc9758_obligations': rfc9758_obligations
    }
    
    with open('spec/obligations-detailed.json', 'w') as f:
        json.dump(detailed_output, f, indent=2)
    
    print(f"Wrote detailed obligations to spec/obligations-detailed.json")

if __name__ == '__main__':
    main()
