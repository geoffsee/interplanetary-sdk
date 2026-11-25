#!/usr/bin/env python3
"""Extract atomic obligations from RFC 9174."""

import json
import re

def extract_rfc9174_obligations():
    """Extract all normative statements from RFC 9174."""
    obligations = []
    
    with open('/tmp/rfc9174.txt', 'r') as f:
        lines = f.readlines()
    
    # Track sections
    current_section = None
    section_title = None
    
    # Keywords that indicate normative statements
    keywords = ['MUST', 'MUST NOT', 'SHALL', 'SHALL NOT', 'SHOULD', 'SHOULD NOT', 'REQUIRED', 'RECOMMENDED', 'NOT RECOMMENDED']
    
    obligation_id = 1
    
    for i, line in enumerate(lines):
        # Track section headers (format: "4.2.  Contact Header")
        section_match = re.match(r'^(\d+(?:\.\d+)*)\.\s+(.+)$', line.strip())
        if section_match:
            current_section = section_match.group(1)
            section_title = section_match.group(2).strip()
            continue
        
        # Skip before section 3 (intro/boilerplate)
        if not current_section or not current_section.startswith(('3', '4', '5', '6', '7', '8')):
            continue
        
        # Skip security considerations (section 7) - these are advisory
        if current_section.startswith('7'):
            continue
        
        # Look for normative keywords
        for keyword in keywords:
            if keyword in line:
                # Extract sentence context (look back and forward for complete sentence)
                context_start = max(0, i - 2)
                context_end = min(len(lines), i + 3)
                context = ' '.join(lines[context_start:context_end])
                
                # Clean up whitespace
                context = re.sub(r'\s+', ' ', context).strip()
                
                # Extract the sentence containing the keyword
                sentences = re.split(r'[.!?]\s+', context)
                obligation_text = None
                for sentence in sentences:
                    if keyword in sentence:
                        obligation_text = sentence.strip()
                        break
                
                if not obligation_text or len(obligation_text) < 20:
                    continue
                
                # Truncate if too long
                if len(obligation_text) > 200:
                    obligation_text = obligation_text[:197] + "..."
                
                # Create locator
                locator = f"§{current_section}"
                if section_title:
                    locator += f" {section_title}"
                
                # Determine if this is a registry/table entry (informational) vs normative
                state = "not_started"
                if current_section.startswith('8') and 'Table' in context:
                    # Registry entries - only add if they specify a requirement
                    if not any(kw in obligation_text for kw in ['SHALL', 'MUST', 'REQUIRED']):
                        continue  # Skip informational registry descriptions
                
                obligation = {
                    "id": f"RFC9174-{current_section.replace('.', '-')}-{obligation_id:03d}",
                    "title": obligation_text[:80] + "..." if len(obligation_text) > 80 else obligation_text,
                    "origin": "normative",
                    "source": "RFC 9174",
                    "locator": locator,
                    "obligation_text": obligation_text,
                    "keyword": keyword,
                    "state": state,
                    "test_evidence": [],
                    "gap_id": None
                }
                
                obligations.append(obligation)
                obligation_id += 1
    
    # Deduplicate by obligation_text
    seen = set()
    unique_obligations = []
    for ob in obligations:
        key = (ob['locator'], ob['obligation_text'])
        if key not in seen:
            seen.add(key)
            unique_obligations.append(ob)
    
    return unique_obligations

def main():
    print("Extracting RFC 9174 obligations...")
    obligations = extract_rfc9174_obligations()
    
    print(f"Extracted {len(obligations)} unique normative statements")
    
    # Load existing requirements
    with open('/workspace/spec/requirements-atomic.json', 'r') as f:
        data = json.load(f)
    
    # Remove my cherry-picked RFC 9174 obligations
    print("Removing cherry-picked RFC 9174 obligations...")
    data['atomic_requirements'] = [r for r in data['atomic_requirements'] if not r['id'].startswith('RFC9174-')]
    
    # Add all extracted obligations
    print(f"Adding {len(obligations)} complete RFC 9174 obligations...")
    data['atomic_requirements'].extend(obligations)
    
    # Update totals
    data['total_obligations'] = len(data['atomic_requirements'])
    
    # Recalculate coverage
    implemented = sum(1 for r in data['atomic_requirements'] if r['state'] == 'implemented_unverified')
    verified = sum(1 for r in data['atomic_requirements'] if r['state'] == 'verified')
    covered = implemented + verified
    
    data['coverage_summary'] = {
        'verified': verified,
        'implemented_unverified': implemented,
        'not_started': sum(1 for r in data['atomic_requirements'] if r['state'] == 'not_started'),
        'blocked': 0,
        'coverage_percentage': round(covered / data['total_obligations'] * 100, 1)
    }
    
    print(f"\nNew totals:")
    print(f"  Total obligations: {data['total_obligations']}")
    print(f"  Covered: {covered}/{data['total_obligations']} ({data['coverage_summary']['coverage_percentage']}%)")
    
    # Save
    with open('/workspace/spec/requirements-atomic.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    print("\nUpdated spec/requirements-atomic.json with full RFC 9174 extraction")

if __name__ == '__main__':
    main()
