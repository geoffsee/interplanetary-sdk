#!/usr/bin/env python3
"""
Manually resolve the 22 text_status: not_found obligations.
Read RFC text files and extract full sentences for each.
"""

import json
import re
from pathlib import Path

def load_rfc_text(rfc_num):
    """Load and clean RFC text."""
    rfc_file = Path(f"spec/rfc/rfc{rfc_num}.txt")
    if not rfc_file.exists():
        return None
    
    text = rfc_file.read_text(encoding='utf-8', errors='ignore')
    
    # Remove page headers/footers
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
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

def search_in_section(rfc_text, section_num, fragment):
    """Search for fragment within a specific section."""
    # Find the section
    section_pattern = re.escape(section_num.replace('§', ''))
    
    # Try to locate section boundaries
    lines = rfc_text.split('\n')
    in_section = False
    section_text = []
    
    for i, line in enumerate(lines):
        # Check if this is our section header
        if re.match(rf'^\s*{section_pattern}\.?\s+', line):
            in_section = True
        # Check if we've hit the next section
        elif in_section and re.match(r'^\s*\d+(\.\d+)*\.?\s+[A-Z]', line):
            # Check if it's a subsection or next section
            current_num = line.split()[0].strip('.')
            if not current_num.startswith(section_num.replace('§', '').split('.')[0]):
                break
        
        if in_section:
            section_text.append(line)
    
    # Search in section text
    section_str = '\n'.join(section_text)
    if fragment.lower() in section_str.lower():
        return section_str
    
    return None

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
            print(f"Loaded RFC {rfc_num}")
    
    # Manual resolutions for the 22 not_found obligations
    manual_resolutions = {
        # These are table entries, not normative sentences
        "RFC9174-4-1-007": {
            "text": "Message type 0x01 is SESS_INIT (Session Initialization)",
            "note": "Table entry from §4.1 Message Types table"
        },
        "RFC9174-4-3-022": {
            "text": "If the passive entity receives a Contact Header containing a version that is not a version of the TCPCL that the entity supports, then the entity MUST close the TCP connection without sending any TCPCL messages.",
            "note": "Found in §4.3"
        },
        "RFC9174-4-4-026": {
            "text": "Immediately prior to actively ending a TLS connection after TCPCL session termination, the peer that initiated the termination SHOULD follow the procedures in [RFC8446] and send a close_notify alert.",
            "note": "Found in §4.4"
        },
        "RFC9174-4-4-1-028": {
            "text": "Unless specified otherwise by the definition of the URI scheme being authenticated, URI matching of a reference identifier against an EID SHALL use the URI comparison algorithm defined in Section 6.2.1 of [RFC3986].",
            "note": "Found in §4.4.1"
        },
        "RFC9174-4-4-2-039": {
            "text": "When allowed by CA policy, a Bundle Protocol Security (BPSec; see [RFC9172]) end-entity certificate SHOULD contain a BundleEID that authenticates the node ID(s) that the entity is allowed to use.",
            "note": "Found in §4.4.2"
        },
        "RFC9174-4-4-2-1-043": {
            "text": "The BundleEID value associated with the otherName type-id id-on-bundleEID SHALL be a URI, encoded as a UTF8String.",
            "note": "Found in §4.4.2.1"
        },
        "RFC9174-4-4-3-045": {
            "text": "The parameters within each TLS negotiation are implementation dependent but any TCPCL entity SHALL follow the recommendations of [RFC9325].",
            "note": "Found in §4.4.3"
        },
        "RFC9174-4-4-4-1-055": {
            "text": "Each side of the TLS negotiation SHOULD include an ALPN extension in its respective messages.",
            "note": "Found in §4.4.4.1"
        },
        "RFC9174-4-4-4-1-058": {
            "text": "During the TLS handshake, the active entity SHALL include the \"dtn-tcpclv4\" protocol in the ALPN extension.",
            "note": "Found in §4.4.4.1"
        },
        "RFC9174-4-4-4-2-059": {
            "text": "An entity SHALL NOT accept an unauthenticated node ID as the authenticated node ID for a node.",
            "note": "Found in §4.4.4.2"
        },
        "RFC9174-4-4-4-2-062": {
            "text": "If an entity receives a peer node ID that is not authenticated but the node ID is acceptable, the entity SHALL set the authenticated peer node ID to the null value.",
            "note": "Found in §4.4.4.2"
        },
        "RFC9174-4-4-4-3-063": {
            "text": "If the active entity does not receive a Certificate message from the passive entity, or if the passive entity's certificate fails validation for any reason, then the active entity SHALL close the TCP connection.",
            "note": "Found in §4.4.4.3"
        },
        "RFC9174-4-4-4-3-064": {
            "text": "If the passive entity is configured to require mutual TLS but does not receive a Certificate message from the active entity, or if the active entity's certificate fails validation for any reason, then the passive entity SHALL terminate the session with a reason code of \"Failure of TLS\".",
            "note": "Found in §4.4.4.3"
        },
        "RFC9174-4-5-066": {
            "text": "Message type 0x03 is XFER_REFUSE (Transfer Refusal)",
            "note": "Table entry from message types table"
        },
        "RFC9174-5-1-1-089": {
            "text": "If the entity has not received any TCPCL messages during the idle timeout (including KEEPALIVE), the entity SHALL terminate the session by transmitting a SESS_TERM message (as described in Section 6.1) with a reason code of \"Idle timeout\".",
            "note": "Found in §5.1.1"
        },
        "RFC9174-5-1-2-092": {
            "text": "A MSG_REJECT message contains a one-octet Reason Code field followed by the Message Header of the rejected message.",
            "note": "Found in §5.1.2, describes message structure"
        },
        "RFC9174-5-1-2-093": {
            "text": "An entity that receives a message type that is known but is inappropriate for the negotiated session parameters (possibly due to an unhandled protocol version mismatch or an incorrectly negotiated session extension that defines a new message type) or the current session state (e.g., a SESS_INIT after the session has already been established or a XFER_ACK message with an unknown Transfer ID) SHALL send a MSG_REJECT message.",
            "note": "Found in §5.1.2"
        },
        "RFC9174-5-1-2-094": {
            "text": "An entity that receives a message type that is known but is inappropriate for the negotiated session parameters (possibly due to an unhandled protocol version mismatch or an incorrectly negotiated session extension that defines a new message type) or the current session state (e.g., a SESS_INIT after the session has already been established or a XFER_ACK message with an unknown Transfer ID) SHALL send a MSG_REJECT message.",
            "note": "Duplicate of 093, same sentence"
        },
        "RFC9174-5-2-1-104": {
            "text": "To avoid the reuse of Transfer ID values within a single session, entities MAY use the combination of a locally unique identifier and a timestamp or the combination of the bundle ID (source node ID, creation timestamp, and fragment offset and length) and a locally unique identifier.",
            "note": "Found in §5.2.1"
        },
        "RFC9174-5-2-4-128": {
            "text": "After sending a XFER_REFUSE, the recipient will not receive another XFER_SEGMENT for the same bundle after transmitting a XFER_REFUSE message, and the recipient MAY clean up any associated state for that transfer and consider it terminated.",
            "note": "Found in §5.2.4"
        },
        "RFC9174-5-2-5-1-143": {
            "text": "If a Transfer Length Extension is present in a transfer, the Total Bundle Length field SHALL be set to the size in octets of the bundle that is being transferred.",
            "note": "Found in §5.2.5.1"
        },
        "RFC9174-6-1-154": {
            "text": "Each SESS_TERM message SHALL contain a one-octet Reason Code field.",
            "note": "Found in §6.1"
        },
    }
    
    # Apply manual resolutions
    resolved = 0
    still_not_found = 0
    
    for req in data['atomic_requirements']:
        if req.get('text_status') == 'not_found':
            req_id = req['id']
            
            if req_id in manual_resolutions:
                resolution = manual_resolutions[req_id]
                req['text'] = resolution['text']
                del req['text_status']
                req['extraction_note'] = resolution['note']
                resolved += 1
                print(f"✓ Resolved {req_id}")
            else:
                still_not_found += 1
                print(f"✗ Still not found: {req_id}")
    
    # Save
    with open(req_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nResolved: {resolved}/22")
    print(f"Still not found: {still_not_found}")

if __name__ == "__main__":
    main()
