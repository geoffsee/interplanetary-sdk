#!/usr/bin/env python3
"""
Update text field for RFC 9171 and 9174 obligations with verbatim RFC sentences.
"""

import json
import re
from pathlib import Path

def load_rfc_text(rfc_num):
    """Load RFC text file."""
    rfc_file = Path(f"spec/rfc/rfc{rfc_num}.txt")
    if not rfc_file.exists():
        return None
    
    text = rfc_file.read_text(encoding='utf-8', errors='ignore')
    
    # Remove page headers/footers (RFC format: page breaks with form feed, headers with RFC number)
    # Common pattern: lines with just "RFC 9171" or page numbers
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Skip page headers/footers (lines with just RFC number, page numbers, or form feeds)
        if line.strip() in ['', '\f']:
            continue
        if re.match(r'^RFC \d{4}.*\d{4}$', line.strip()):
            continue
        if re.match(r'^[A-Z][a-z]+.*[A-Z][a-z]+\s+Standards Track\s+\[Page \d+\]$', line.strip()):
            continue
        if re.match(r'^\[Page \d+\]$', line.strip()):
            continue
        
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def unwrap_paragraphs(text):
    """Unwrap line breaks within paragraphs."""
    # Join lines that are part of the same sentence
    lines = text.split('\n')
    unwrapped = []
    current_para = []
    
    for line in lines:
        stripped = line.strip()
        
        # Empty line = paragraph break
        if not stripped:
            if current_para:
                unwrapped.append(' '.join(current_para))
                current_para = []
            continue
        
        # Section headers (numbers at start)
        if re.match(r'^\d+\.', stripped):
            if current_para:
                unwrapped.append(' '.join(current_para))
                current_para = []
            unwrapped.append(stripped)
            continue
        
        current_para.append(stripped)
    
    if current_para:
        unwrapped.append(' '.join(current_para))
    
    return '\n'.join(unwrapped)

def find_sentence_in_rfc(rfc_text, obligation_fragment, locator):
    """
    Find the full sentence containing obligation_fragment in the RFC.
    Returns (sentence, confidence) or (None, 'not_found')
    """
    if not rfc_text:
        return None, 'no_rfc_text'
    
    # Unwrap paragraphs
    unwrapped = unwrap_paragraphs(rfc_text)
    
    # Clean up the obligation fragment for searching
    search_fragment = obligation_fragment.strip()
    
    # Normalize whitespace
    search_fragment_normalized = re.sub(r'\s+', ' ', search_fragment)
    unwrapped_normalized = re.sub(r'\s+', ' ', unwrapped)
    
    # Try to find the fragment
    if search_fragment_normalized.lower() in unwrapped_normalized.lower():
        # Find position
        idx = unwrapped_normalized.lower().find(search_fragment_normalized.lower())
        
        # Extract surrounding context
        start = max(0, idx - 500)
        end = min(len(unwrapped_normalized), idx + len(search_fragment_normalized) + 500)
        context = unwrapped_normalized[start:end]
        
        # Find sentence boundaries
        # Look for sentence start (after . or beginning)
        sentence_start = start
        for i in range(idx, start - 1, -1):
            if unwrapped_normalized[i] in '.!?':
                sentence_start = i + 1
                break
        
        # Look for sentence end
        sentence_end = end
        for i in range(idx + len(search_fragment_normalized), end):
            if unwrapped_normalized[i] in '.!?':
                sentence_end = i + 1
                break
        
        sentence = unwrapped_normalized[sentence_start:sentence_end].strip()
        
        # Clean up sentence
        sentence = re.sub(r'\s+', ' ', sentence)
        
        return sentence, 'found'
    
    return None, 'not_found'

def main():
    # Load requirements
    req_file = Path("spec/requirements-atomic.json")
    with open(req_file) as f:
        data = json.load(f)
    
    # Load RFC texts
    rfc_texts = {}
    for rfc_num in [9171, 9174]:
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
        
        # Only process RFC 9171 and 9174
        if 'RFC9171' in req_id:
            rfc_num = 9171
        elif 'RFC9174' in req_id:
            rfc_num = 9174
        else:
            continue
        
        # Try to find full sentence
        if rfc_num in rfc_texts:
            sentence, status = find_sentence_in_rfc(
                rfc_texts[rfc_num], 
                obligation_text, 
                locator
            )
            
            if status == 'found' and sentence:
                req['text'] = sentence
                if 'text_status' in req:
                    del req['text_status']
                found_count += 1
            else:
                # Mark as not found
                req['text_status'] = 'not_found'
                if req.get('text') == obligation_text:
                    # Keep existing fallback
                    pass
                not_found_count += 1
                not_found_list.append(req_id)
        else:
            req['text_status'] = 'no_rfc_text'
            not_found_count += 1
            not_found_list.append(req_id)
    
    # Save updated requirements
    with open(req_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nProcessed RFC 9171 and 9174 obligations")
    print(f"Found full sentences: {found_count}")
    print(f"Could not find full sentence: {not_found_count}")
    
    if not_found_list:
        print(f"\nObligations where sentence could not be found:")
        for req_id in not_found_list[:50]:
            print(f"  - {req_id}")
        if len(not_found_list) > 50:
            print(f"  ... and {len(not_found_list) - 50} more")
    
    print(f"\nUpdated {req_file}")

if __name__ == "__main__":
    main()
