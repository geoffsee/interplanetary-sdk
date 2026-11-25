#!/usr/bin/env python3
"""
Add full normative sentence text to each obligation in requirements-atomic.json.
The text field should contain the complete RFC sentence, copied verbatim.
"""

import json
import re
from pathlib import Path

def load_rfc_text(rfc_num):
    """Load RFC text file if it exists."""
    rfc_file = Path(f"spec/rfc{rfc_num}.txt")
    if rfc_file.exists():
        return rfc_file.read_text()
    return None

def extract_sentence_from_rfc(rfc_text, obligation_text, locator):
    """
    Try to find the full sentence containing obligation_text in the RFC.
    Returns the full sentence or None if not found.
    """
    if not rfc_text:
        return None
    
    # Clean up the obligation text for searching
    search_text = obligation_text.strip()
    
    # Try to find it in the RFC text
    if search_text in rfc_text:
        # Find sentence boundaries
        idx = rfc_text.find(search_text)
        
        # Search backward for sentence start (. or beginning)
        start = idx
        while start > 0:
            if rfc_text[start-1] in '.!?\n':
                break
            start -= 1
        
        # Search forward for sentence end
        end = idx + len(search_text)
        while end < len(rfc_text):
            if rfc_text[end] in '.!?':
                end += 1
                break
            end += 1
        
        sentence = rfc_text[start:end].strip()
        
        # Clean up whitespace
        sentence = re.sub(r'\s+', ' ', sentence)
        
        return sentence
    
    return None

def main():
    # Load requirements
    req_file = Path("spec/requirements-atomic.json")
    with open(req_file) as f:
        data = json.load(f)
    
    # Load RFC texts
    rfc_texts = {}
    for rfc_num in [9171, 9174, 9758]:
        text = load_rfc_text(rfc_num)
        if text:
            rfc_texts[rfc_num] = text
            print(f"Loaded RFC {rfc_num} text ({len(text)} chars)")
        else:
            print(f"Warning: RFC {rfc_num} text file not found")
    
    # Process each obligation
    found_count = 0
    not_found_count = 0
    not_found_list = []
    
    for req in data['atomic_requirements']:
        req_id = req['id']
        obligation_text = req['obligation_text']
        locator = req.get('locator', '')
        
        # Extract RFC number from ID
        if 'RFC9171' in req_id:
            rfc_num = 9171
        elif 'RFC9174' in req_id:
            rfc_num = 9174
        elif 'RFC9758' in req_id:
            rfc_num = 9758
        else:
            continue
        
        # Try to find full sentence
        if rfc_num in rfc_texts:
            sentence = extract_sentence_from_rfc(
                rfc_texts[rfc_num], 
                obligation_text, 
                locator
            )
            
            if sentence:
                req['text'] = sentence
                found_count += 1
            else:
                # For now, use obligation_text as fallback
                req['text'] = obligation_text
                not_found_count += 1
                not_found_list.append(req_id)
        else:
            # No RFC text available, use obligation_text
            req['text'] = obligation_text
            not_found_count += 1
            not_found_list.append(req_id)
    
    # Save updated requirements
    with open(req_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nProcessed {len(data['atomic_requirements'])} obligations")
    print(f"Found full sentences: {found_count}")
    print(f"Could not find full sentence: {not_found_count}")
    
    if not_found_list:
        print(f"\nObligations where sentence could not be found (using obligation_text as fallback):")
        for req_id in not_found_list[:20]:  # Show first 20
            print(f"  - {req_id}")
        if len(not_found_list) > 20:
            print(f"  ... and {len(not_found_list) - 20} more")
    
    print(f"\nUpdated {req_file}")

if __name__ == "__main__":
    main()
