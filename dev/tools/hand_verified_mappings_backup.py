#!/usr/bin/env python3
"""
CLEAN HAND-VERIFIED TEST-TO-OBLIGATION MAPPINGS
================================================

Only genuine mappings where test actually asserts the obligation.
No vacuous tests. Each mapping verified by reading test body and obligation text.

NO KEYWORD MATCHING. EACH MAPPING HAND-VERIFIED.
"""

import json
import sys

# ==============================================================================
# GENUINE HAND-VERIFIED MAPPINGS ONLY
# ==============================================================================
# Format: "test_name": [(obligation_id, "note describing what assertion checks")]
#
# Removed all vacuous mappings identified in review.
# ==============================================================================

MAPPINGS = {
    # ==========================================================================
    # RFC 9171 Codec Tests - Genuine CBOR encoding checks
    # ==========================================================================
    
    "bp::cbor_encoding::tests::test_encode_uint_boundary_0_23": [
        ("RFC9171-4-002", "Tests CBOR shortest-form encoding for uint [0..23]"),
    ],
    
    "bp::cbor_encoding::tests::test_encode_uint_boundary_24": [
        ("RFC9171-4-002", "Tests CBOR shortest-form encoding for uint [24..255]"),
    ],
    
    "bp::cbor_encoding::tests::test_encode_uint_boundary_256": [
        ("RFC9171-4-002", "Tests CBOR shortest-form encoding for uint [256..65535]"),
    ],
    
    "bp::cbor_encoding::tests::test_encode_uint_boundary_65536": [
        ("RFC9171-4-002", "Tests CBOR shortest-form encoding for uint [65536..2^32-1]"),
    ],
    
    "bp::cbor_encoding::tests::test_encode_uint_boundary_2_32": [
        ("RFC9171-4-002", "Tests CBOR shortest-form encoding for uint >= 2^32"),
    ],
    
    "bp::cbor_encoding::tests::test_encode_array_shortest": [
        ("RFC9171-4-002", "Tests CBOR shortest-form array encoding"),
    ],
    
    "bp::cbor_encoding::tests::test_encode_bytes_shortest": [
        ("RFC9171-4-002", "Tests CBOR shortest-form byte string encoding"),
    ],
    
    # ==========================================================================
    # RFC 9171 Bundle Structure Tests
    # ==========================================================================
    
    "bp::bundle::tests::test_bundle_builder": [
        ("RFC9171-4-003", "Asserts bundle contains at least two blocks (primary + payload)"),
    ],
    
    "bp::codec::tests::test_encode_simple_bundle": [
        ("RFC9171-4-001", "Tests bundle encoded as CBOR per spec"),
        ("RFC9171-4-004", "Asserts primary block is first item in CBOR array"),
    ],
    
    "bp::codec::tests::test_encode_decode_roundtrip": [
        ("RFC9171-4-001", "Tests bundle CBOR encoding/decoding conformance"),
    ],
    
    # ==========================================================================
    # RFC 9171 EID Encoding Tests
    # ==========================================================================
    
    "bp::codec::tests::test_encode_eid_dtn": [
        ("RFC9171-4-028", "Tests EID encoded as CBOR array [scheme_code, ssp]"),
        ("RFC9171-4-032", "Tests dtn SSP encoded as CBOR text string or uint 0"),
    ],
    
    "bp::codec::tests::test_encode_eid_ipn": [
        ("RFC9171-4-028", "Tests EID encoded as CBOR array [scheme_code, ssp]"),
        ("RFC9171-4-035", "Tests ipn SSP encoded as CBOR array [node, service]"),
    ],
    
    # ==========================================================================
    # RFC 9171 CRC Tests
    # ==========================================================================
    
    "bp::crc::tests::test_crc16_check_value": [
        ("RFC9171-4-012", "Tests CRC type represented as CBOR uint (type field)"),
    ],
    
    "bp::crc::tests::test_crc32c_check_value": [
        ("RFC9171-4-012", "Tests CRC type represented as CBOR uint (type field)"),
    ],
    
    "bp::crc::tests::test_crc16_simple": [
        ("RFC9171-4-014", "Tests CRC value represented as CBOR byte string"),
    ],
    
    "bp::crc::tests::test_crc32c_simple": [
        ("RFC9171-4-014", "Tests CRC value represented as CBOR byte string"),
    ],
    
    # ==========================================================================
    # RFC 9171 Block/Bundle Flags Tests
    # ==========================================================================
    
    "bp::blocks::tests::test_block_flags": [
        ("RFC9171-4-023", "Tests block processing control flags as CBOR uint"),
    ],
    
    "bpa::admin::tests::test_bundle_flag_constants_match_rfc": [
        ("RFC9171-4-020", "Tests bundle processing control flags as CBOR uint"),
    ],
    
    # ==========================================================================
    # RFC 9171 §5.6 Reception - Block Processing
    # ==========================================================================
    
    "test_rfc9171_5_6_delete_on_critical_unsupported_block": [
        ("RFC9171-5-040", "Asserts BPA deletes bundle when unsupported block has DELETE flag (bit 2)"),
    ],
    
    "test_rfc9171_5_6_discard_unsupported_block": [
        ("RFC9171-5-043", "Asserts BPA removes block when unsupported block has DISCARD flag (bit 4)"),
    ],
    
    "test_rfc9171_5_6_report_on_unsupported_block": [
        ("RFC9171-5-039", "Asserts status report generated when unsupported block has REPORT flag (bit 1)"),
    ],
    
    "test_rfc9171_5_6_reception_status_report_requested": [
        ("RFC9171-5-034", "Asserts reception status report generated when bundle flag bit 14 set"),
    ],
    
    # ==========================================================================
    # RFC 9174 TCPCLv4 - Genuine behavior tests only
    # ==========================================================================
    
    "test_rfc9174_4_3_version_mismatch_rejection": [
        ("RFC9174-4-3-022", "Asserts passive entity rejects Contact Header with unsupported version"),
    ],
    
    "test_rfc9174_5_2_1_transfer_id_uniqueness": [
        ("RFC9174-5-2-1-100", "Asserts Transfer IDs are unique within session"),
    ],
    
    "test_rfc9174_5_2_2_xfer_segment_start_end_flags": [
        ("RFC9174-5-2-2-108", "Asserts START flag (0x02) set on first segment"),
        ("RFC9174-5-2-2-110", "Asserts END flag (0x01) set on last segment"),
    ],
    
    # test_rfc9174_5_1_2_msg_reject_unknown_type: UNMAPPED (only receives MSG_REJECT, doesn't test sending on unknown type)
    
    # ==========================================================================
    # RFC 9174 XFER_REFUSE Tests
    # ==========================================================================
    

# ==============================================================================
# VACUOUS TESTS - Identified and removed/rewritten
# ==============================================================================
# These tests were mapped but don't actually assert the obligation:
#
# - test_rfc9758_3_4_1_zero_node_invalid: only asserts two EIDs differ
# - test_rfc9758_3_4_1_zero_node_treated_as_null: only asserts contains "0"
# - test_rfc9758_3_3_node_number_range: only asserts contains "1"
# - test_rfc9758_5_1_singleton_endpoint: only asserts starts_with("ipn:")
# - test_rfc9758_3_2_allocator_uniqueness: only checks representability
# - test_rfc9758_3_2_1_allocator_range_power_of_two: only checks representability
# - test_rfc9758_3_4_3_private_use_nodes: only checks representability
# - test_rfc9758_5_1_services_on_same_node: only checks contains "100."
# - test_rfc9758_5_1_fqnn_identifies_node: only checks contains "100.50."
# - test_rfc9758_4_no_leading_zeros_required: never checks rejection of leading zeros
# - test_rfc9758_4_1_uri_scheme_compliance: only parses valid URIs
# - test_rfc9758_4_service_zero_exclamation: only parses, doesn't check '!' notation
# - test_rfc9758_3_1_null_ipn_definition: just parses, doesn't verify null semantics
# - test_rfc9758_3_3_node_zero_not_recommended: just checks representability
#
# RFC 9174 vacuous:
# - test_rfc9174_4_2_contact_header_magic_and_version: only encodes valid, never tests rejection
# - test_rfc9174_4_2_can_tls_flag: wrong obligation (TLS 1.3 vs flag bit)
# - test_rfc9174_5_1_1_keepalive_timeout_terminates_session: manually calls send_term, no timeout
# - test_rfc9174_6_1_sess_term_reply_handshake: never checks REPLY flag emitted
# - test_rfc9174_5_2_2_segment_mru_enforcement: never checks segments <= MRU
# - All KEEPALIVE interval range tests (084/085/086/090): SHOULD without enforcement
#
# All will be deleted or rewritten to assert genuine behavior.
# ==============================================================================


def apply_mappings():
    """Apply clean hand-verified mappings."""
    
    json_path = '/workspace/spec/requirements-atomic.json'
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Build obligation ID set for validation
    valid_ids = {req['id'] for req in data['atomic_requirements']}
    
    # Clear ALL existing mappings first
    for req in data['atomic_requirements']:
        req['test_evidence'] = []
        req['evidence_note'] = ''
        req['state'] = 'not_started'
    
    total_mappings = sum(len(mappings) for mappings in MAPPINGS.values())
    print(f"Applying {total_mappings} CLEAN hand-verified mappings from {len(MAPPINGS)} tests...")
    
    applied = 0
    errors = []
    
    for test_name, mappings_list in MAPPINGS.items():
        for obligation_id, note in mappings_list:
            if obligation_id not in valid_ids:
                errors.append(f"ERROR: {test_name} -> {obligation_id}: ID NOT IN requirements-atomic.json")
                print(f"✗ {test_name} -> {obligation_id}: NOT FOUND", file=sys.stderr)
                continue
            
            found = False
            for req in data['atomic_requirements']:
                if req['id'] == obligation_id:
                    if 'test_evidence' not in req:
                        req['test_evidence'] = []
                    if test_name not in req['test_evidence']:
                        req['test_evidence'].append(test_name)
                    req['evidence_note'] = note
                    req['state'] = 'implemented_unverified'
                    applied += 1
                    found = True
                    print(f"✓ {test_name} → {obligation_id}")
                    break
    
    if errors:
        print(f"\nFATAL: {len(errors)} obligation IDs not found in requirements-atomic.json:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        sys.exit(1)
    
    # Update coverage summary
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
    
    print(f"\nApplied: {applied} genuine obligation mappings")
    print(f"Coverage: {covered}/{data['total_obligations']} ({data['coverage_summary']['coverage_percentage']}%)")
    
    # Save
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nSaved to {json_path}")
    return data

if __name__ == '__main__':
    apply_mappings()
    
    # ==========================================================================
    # RFC 9758 Security Source - tests/rfc9758_security_source.rs
    # Real behavior tests for §5.4/§5.5
    # ==========================================================================
    
    "test_rfc9758_5_4_localnode_rejected_as_bib_source": [
        ("RFC9758-026", "Asserts BIB generation rejects LocalNode ipn EID as security source"),
    ],
    
    "test_rfc9758_5_5_private_use_rejected_as_bib_source": [
        ("RFC9758-032", "Asserts BIB generation rejects Private Use ipn EID as security source"),
    ],
    
    # ==========================================================================
    # RFC 9758 Service Zero - tests/rfc9758_service_zero.rs
    # Administrative endpoint tests for §5.7
    # ==========================================================================
    
    "test_rfc9758_6_3_service_zero_administrative": [
        ("RFC9758-033", "Asserts service 0 MUST be administrative endpoint"),
    ],
    
    "test_rfc9758_6_3_nonzero_service_not_administrative": [
        ("RFC9758-034", "Asserts non-zero service MUST NOT identify administrative endpoint"),
    ],
    
    # ==========================================================================
    # RFC 9758 Security Source - tests/rfc9758_security_source.rs
    # Real behavior tests for §5.4/§5.5
    # ==========================================================================
    
    "test_rfc9758_5_4_localnode_rejected_as_bib_source": [
        ("RFC9758-026", "Asserts BIB generation rejects LocalNode ipn EID as security source"),
    ],
    
    "test_rfc9758_5_5_private_use_rejected_as_bib_source": [
        ("RFC9758-032", "Asserts BIB generation rejects Private Use ipn EID as security source"),
    ],
    
    # ==========================================================================
    # RFC 9758 Service Zero - tests/rfc9758_service_zero.rs
    # Administrative endpoint tests for §5.7
    # ==========================================================================
    
    "test_rfc9758_6_3_service_zero_administrative": [
        ("RFC9758-033", "Asserts service 0 MUST be administrative endpoint"),
    ],
    
    "test_rfc9758_6_3_nonzero_service_not_administrative": [
        ("RFC9758-034", "Asserts non-zero service MUST NOT identify administrative endpoint"),
    ],
}

# ==============================================================================
# VACUOUS TESTS - Identified and removed/rewritten
# ==============================================================================
# These tests were deleted in previous review.
# ==============================================================================


def apply_mappings():
    """Apply clean hand-verified mappings."""
    
    json_path = '/workspace/spec/requirements-atomic.json'
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Build obligation ID set for validation
    valid_ids = {req['id'] for req in data['atomic_requirements']}
    
    # Clear ALL existing mappings first
    for req in data['atomic_requirements']:
        req['test_evidence'] = []
        req['evidence_note'] = ''
        req['state'] = 'not_started'
    
    total_mappings = sum(len(mappings) for mappings in MAPPINGS.values())
    print(f"Applying {total_mappings} CLEAN hand-verified mappings from {len(MAPPINGS)} tests...")
    
    applied = 0
    errors = []
    
    for test_name, mappings_list in MAPPINGS.items():
        for obligation_id, note in mappings_list:
            if obligation_id not in valid_ids:
                errors.append(f"ERROR: {test_name} -> {obligation_id}: ID NOT IN requirements-atomic.json")
                print(f"✗ {test_name} -> {obligation_id}: NOT FOUND", file=sys.stderr)
                continue
            
            found = False
            for req in data['atomic_requirements']:
                if req['id'] == obligation_id:
                    if 'test_evidence' not in req:
                        req['test_evidence'] = []
                    if test_name not in req['test_evidence']:
                        req['test_evidence'].append(test_name)
                    req['evidence_note'] = note
                    req['state'] = 'implemented_unverified'
                    applied += 1
                    found = True
                    print(f"✓ {test_name} → {obligation_id}")
                    break
    
    if errors:
        print(f"\nFATAL: {len(errors)} obligation IDs not found in requirements-atomic.json:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        sys.exit(1)
    
    # Update coverage summary
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
    
    print(f"\nApplied: {applied} genuine obligation mappings")
    print(f"Coverage: {covered}/{data['total_obligations']} ({data['coverage_summary']['coverage_percentage']}%)")
    
    # Save
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nSaved to {json_path}")
    return data

if __name__ == '__main__':
    apply_mappings()
