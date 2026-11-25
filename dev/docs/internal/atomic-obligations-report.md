# Atomic Obligation Audit Report

**Date:** 2026-11-09
**Total Obligations (extracted):** 630
**Duplicates:** 86
**Out of Scope:** 82
**Permissive (MAY/implementation choice, cannot be violated):** 36
**In-Scope Obligations (deduplicated, excluding permissive):** 426
**Coverage:** 426/630 (67.6% total, 100.0% in-scope)

## Summary by RFC Section

| Section | Total | Covered | Coverage % |
|---------|-------|---------|------------|
| RFC 9171 §4.1 | 11 | 8 | 72.7% |
| RFC 9171 §4.2.1 | 1 | 1 | 100.0% |
| RFC 9171 §4.2.2 | 3 | 2 | 66.7% |
| RFC 9171 §4.2.3 | 6 | 4 | 66.7% |
| RFC 9171 §4.2.4 | 4 | 3 | 75.0% |
| RFC 9171 §4.2.5.1 | 5 | 3 | 60.0% |
| RFC 9171 §4.2.5.1.1 | 2 | 1 | 50.0% |
| RFC 9171 §4.2.5.1.2 | 4 | 3 | 75.0% |
| RFC 9171 §4.2.6 | 1 | 1 | 100.0% |
| RFC 9171 §4.2.7 | 4 | 3 | 75.0% |
| RFC 9171 §4.2.8 | 1 | 1 | 100.0% |
| RFC 9171 §4.3.1 | 23 | 16 | 69.6% |
| RFC 9171 §4.3.2 | 8 | 5 | 62.5% |
| RFC 9171 §4.4 | 2 | 1 | 50.0% |
| RFC 9171 §4.4.1 | 4 | 3 | 75.0% |
| RFC 9171 §4.4.2 | 3 | 3 | 100.0% |
| RFC 9171 §4.4.3 | 7 | 6 | 85.7% |
| RFC 9171 §5.1 | 1 | 1 | 100.0% |
| RFC 9171 §5.10 | 2 | 2 | 100.0% |
| RFC 9171 §5.11 | 1 | 0 | 0.0% |
| RFC 9171 §5.12 | 2 | 2 | 100.0% |
| RFC 9171 §5.2 | 1 | 1 | 100.0% |
| RFC 9171 §5.3 | 2 | 2 | 100.0% |
| RFC 9171 §5.4 | 13 | 12 | 92.3% |
| RFC 9171 §5.4.1 | 2 | 2 | 100.0% |
| RFC 9171 §5.4.2 | 6 | 5 | 83.3% |
| RFC 9171 §5.5 | 5 | 2 | 40.0% |
| RFC 9171 §5.6 | 11 | 8 | 72.7% |
| RFC 9171 §5.7 | 7 | 5 | 71.4% |
| RFC 9171 §5.8 | 9 | 6 | 66.7% |
| RFC 9171 §5.9 | 3 | 2 | 66.7% |
| RFC 9171 §6.1 | 3 | 3 | 100.0% |
| RFC 9171 §6.1.1 | 15 | 14 | 93.3% |
| RFC 9171 §6.2 | 2 | 2 | 100.0% |
| RFC 9171 §7.2 | 1 | 1 | 100.0% |
| RFC 9172 §1.4. | 2 | 1 | 50.0% |
| RFC 9172 §10. | 2 | 0 | 0.0% |
| RFC 9172 §2.2. | 3 | 1 | 33.3% |
| RFC 9172 §3. | 1 | 1 | 100.0% |
| RFC 9172 §3.1. | 1 | 0 | 0.0% |
| RFC 9172 §3.11.1. | 1 | 1 | 100.0% |
| RFC 9172 §3.11.2. | 2 | 2 | 100.0% |
| RFC 9172 §3.2. | 5 | 4 | 80.0% |
| RFC 9172 §3.3. | 2 | 1 | 50.0% |
| RFC 9172 §3.4. | 1 | 1 | 100.0% |
| RFC 9172 §3.6. | 22 | 17 | 77.3% |
| RFC 9172 §3.7. | 6 | 4 | 66.7% |
| RFC 9172 §3.8. | 6 | 5 | 83.3% |
| RFC 9172 §3.9. | 11 | 10 | 90.9% |
| RFC 9172 §4. | 6 | 5 | 83.3% |
| RFC 9172 §5.1. | 1 | 1 | 100.0% |
| RFC 9172 §5.1.1. | 15 | 12 | 80.0% |
| RFC 9172 §5.1.2. | 14 | 10 | 71.4% |
| RFC 9172 §5.2. | 2 | 2 | 100.0% |
| RFC 9172 §7. | 2 | 2 | 100.0% |
| RFC 9172 §7.1. | 1 | 1 | 100.0% |
| RFC 9172 §9.1. | 1 | 1 | 100.0% |
| RFC 9172 §9.2. | 1 | 1 | 100.0% |
| RFC 9172 §9.3. | 1 | 0 | 0.0% |
| RFC 9173 §1. | 1 | 1 | 100.0% |
| RFC 9173 §2. | 6 | 4 | 66.7% |
| RFC 9173 §3. | 2 | 2 | 100.0% |
| RFC 9173 §3.2. | 2 | 2 | 100.0% |
| RFC 9173 §3.3.1. | 2 | 2 | 100.0% |
| RFC 9173 §3.3.2. | 2 | 2 | 100.0% |
| RFC 9173 §3.3.3. | 6 | 3 | 50.0% |
| RFC 9173 §3.5. | 1 | 1 | 100.0% |
| RFC 9173 §3.6. | 1 | 1 | 100.0% |
| RFC 9173 §3.7. | 2 | 2 | 100.0% |
| RFC 9173 §3.8.1. | 14 | 11 | 78.6% |
| RFC 9173 §3.8.2. | 10 | 6 | 60.0% |
| RFC 9173 §4. | 3 | 3 | 100.0% |
| RFC 9173 §4.2. | 2 | 1 | 50.0% |
| RFC 9173 §4.3.1. | 4 | 2 | 50.0% |
| RFC 9173 §4.3.2. | 3 | 2 | 66.7% |
| RFC 9173 §4.3.3. | 2 | 0 | 0.0% |
| RFC 9173 §4.3.4. | 6 | 0 | 0.0% |
| RFC 9173 §4.4. | 2 | 1 | 50.0% |
| RFC 9173 §4.4.1. | 3 | 2 | 66.7% |
| RFC 9173 §4.5. | 1 | 1 | 100.0% |
| RFC 9173 §4.6. | 7 | 6 | 85.7% |
| RFC 9173 §4.7. | 1 | 0 | 0.0% |
| RFC 9173 §4.7.1. | 3 | 3 | 100.0% |
| RFC 9173 §4.7.2. | 1 | 1 | 100.0% |
| RFC 9173 §4.8.1. | 23 | 16 | 69.6% |
| RFC 9173 §4.8.2. | 15 | 9 | 60.0% |
| RFC 9173 §5. | 1 | 1 | 100.0% |
| RFC 9173 §6.2. | 7 | 6 | 85.7% |
| RFC 9173 §6.3. | 2 | 1 | 50.0% |
| RFC 9174 §4 | 1 | 1 | 100.0% |
| RFC 9174 §4.1 | 9 | 9 | 100.0% |
| RFC 9174 §4.2 | 1 | 0 | 0.0% |
| RFC 9174 §4.3 | 5 | 5 | 100.0% |
| RFC 9174 §4.5 | 1 | 1 | 100.0% |
| RFC 9174 §4.6 | 6 | 6 | 100.0% |
| RFC 9174 §4.7 | 3 | 3 | 100.0% |
| RFC 9174 §4.8 | 4 | 4 | 100.0% |
| RFC 9174 §5.1.1 | 7 | 6 | 85.7% |
| RFC 9174 §5.1.2 | 3 | 2 | 66.7% |
| RFC 9174 §5.2 | 3 | 3 | 100.0% |
| RFC 9174 §5.2.1 | 3 | 3 | 100.0% |
| RFC 9174 §5.2.2 | 5 | 4 | 80.0% |
| RFC 9174 §5.2.3 | 3 | 2 | 66.7% |
| RFC 9174 §5.2.4 | 10 | 9 | 90.0% |
| RFC 9174 §5.2.5 | 4 | 2 | 50.0% |
| RFC 9174 §5.2.5.1 | 5 | 5 | 100.0% |
| RFC 9174 §6.1 | 14 | 12 | 85.7% |
| RFC 9758 §3 | 1 | 1 | 100.0% |
| RFC 9758 §3.3 | 1 | 1 | 100.0% |
| RFC 9758 §3.4.1 | 2 | 2 | 100.0% |
| RFC 9758 §3.4.3 | 1 | 1 | 100.0% |
| RFC 9758 §4 | 3 | 2 | 66.7% |
| RFC 9758 §4.1 | 1 | 1 | 100.0% |
| RFC 9758 §5 | 1 | 1 | 100.0% |
| RFC 9758 §5.1 | 5 | 4 | 80.0% |
| RFC 9758 §5.4 | 7 | 7 | 100.0% |
| RFC 9758 §5.5 | 4 | 4 | 100.0% |
| RFC 9758 §5.7 | 2 | 2 | 100.0% |
| RFC 9758 §6.1 | 2 | 2 | 100.0% |
| RFC 9758 §6.1.1 | 3 | 3 | 100.0% |
| RFC 9758 §6.1.2 | 2 | 2 | 100.0% |
| RFC 9758 §6.3 | 1 | 1 | 100.0% |
| RFC 9758 §6.4 | 3 | 3 | 100.0% |
| RFC 9758 §7.1 | 2 | 2 | 100.0% |
| RFC 9758 §7.5 | 1 | 1 | 100.0% |

## Obligations with Test Coverage

### RFC 9171 §4.1

**Covered:** 8

- `RFC9171-4-001`: Bundle Structure The format of bundles SHALL conform to the ......
  - Tests: test_rfc9171_4_001_agent_emitted_is_cbor
  - Note: Agent-emitted wire bytes are CBOR indefinite array (0x9F…0xFF); each block element parses via cibori
- `RFC9171-4-002`: To ensure that blocks are always in canonical representation......
  - Tests: test_rfc9171_4_002_deterministic_encoding_via_agent
  - Note: Decode+re-encode of agent cla_tx_queue bundle yields byte-identical CBOR. Would FAIL if field encodi
- `RFC9171-4-003`: Each bundle SHALL be a concatenated sequence of at least two......
  - Tests: test_rfc9171_4_003_bundle_as_indefinite_array_min_two_blocks
  - Note: CBOR decode verifies bundle is indefinite-length array with at least 2 blocks
- `RFC9171-4-005`: The first block in the sequence (the first item of the array......
  - Tests: test_rfc9171_4_005_first_block_is_primary, test_rfc9171_4_005_006_decoder_rejects_primary_not_first
  - Note: Test verifies BundleCodec::encode() produces indefinite-length CBOR array (0x9F) with first item bei
- `RFC9171-4-006`: The first block in the sequence (the first item of the array......
  - Tests: test_rfc9171_4_006_007_primary_then_canonicals_via_agent
  - Note: Agent-emitted cla_tx_queue bytes: indefinite CBOR array; first element is primary (version 7, length
- `RFC9171-4-007`: Every block following the primary block SHALL be the CBOR en......
  - Tests: test_rfc9171_4_006_007_primary_then_canonicals_via_agent
  - Note: Same agent wire parse: every block after primary is a 5-or-6-element CBOR array (canonical). Would F
- `RFC9171-4-008`: The last such block MUST be a payload block; the bundle MUST......
  - Tests: test_rfc9171_4_008_last_block_is_payload, test_rfc9171_4_008_decoder_rejects_payload_not_last
  - Note: Test verifies bundle.blocks.last() is payload block (block_type.is_payload() and type code 1) per RF
- `RFC9171-4-009`: The payload block SHALL be followed by a CBOR "break" stop c......
  - Tests: test_rfc9171_4_009_exactly_one_payload_block, test_rfc9171_4_009_decoder_rejects_no_payload, test_rfc9171_4_009_decoder_rejects_two_payloads
  - Note: Test counts payload blocks in Bundle.blocks and asserts exactly 1 per RFC 9171 §4.1 MUST. Verifies B

### RFC 9171 §4.2.1

**Covered:** 1

- `RFC9171-4-012`: " [RFC4960] CRC type SHALL be represented as a CBOR unsigned......
  - Tests: test_rfc9171_4_012_crc_type_as_cbor_unsigned
  - Note: CBOR decode verifies crc_type is unsigned integer

### RFC 9171 §4.2.2

**Covered:** 2

- `RFC9171-4-013`: CRC The CRC SHALL be omitted from a block if and only if the......
  - Tests: test_rfc9171_4_2_1_crc_present_when_nonzero
  - Note: CRC omission test validates if-and-only-if semantics with hand-built CBOR
- `RFC9171-4-015`: When not omitted, the CRC SHALL be represented as a CBOR byt......
  - Tests: test_rfc9171_4_2_015_crc_as_byte_string
  - Note: CRC byte string test validates 2-byte (CRC16) or 4-byte (CRC32) CBOR byte string

### RFC 9171 §4.2.3

**Covered:** 4

- `RFC9171-4-017`: , the source node ID is the ID of the null endpoint, which h......
  - Tests: test_rfc9171_4_017_null_source_constraints
  - Note: Null source constraint test validates must-not-fragment and zero status flags
- `RFC9171-4-018`: If the bundle processing control flags indicate that the bun......
  - Tests: test_rfc9171_4_018_admin_record_has_zero_status_flags, test_admin_record_valid_with_zero_status_flags, test_decoder_rejects_admin_record_with_status_flags (+ 1 more)
  - Note: Builder and decoder validate that bundles with IS_ADMIN_RECORD flag (bit 1) MUST have all status rep
- `RFC9171-4-019`: Bundle processing control flags that are unrecognized MUST b......
  - Tests: test_rfc9171_4_019_unrecognized_flags_ignored
  - Note: Unrecognized flags test validates flags are ignored per RFC requirement
- `RFC9171-4-021`: The bundle processing control flags SHALL be represented as ......
  - Tests: test_rfc9171_4_2_021_bundle_flags_as_cbor_unsigned
  - Note: Bundle flags CBOR test validates represented as CBOR unsigned integer

### RFC 9171 §4.2.4

**Covered:** 3

- `RFC9171-4-022`: Block processing control flags that are unrecognized MUST be......
  - Tests: test_rfc9171_4_022_unrecognized_block_flags_ignored_at_agent
  - Note: BundleAgent receive_bytes_from_cla+poll delivers a bundle whose payload block_flags include unassign
- `RFC9171-4-023`: The block processing control flags SHALL be represented as a......
  - Tests: bp::blocks::tests::test_block_flags, test_rfc9171_4_3_2_045_block_processing_control_flags_unsigned
  - Note: CBOR decode verifies block_flags is unsigned integer
- `RFC9171-4-025`: For each bundle whose bundle processing control flags indica......
  - Tests: test_rfc9171_4_025_admin_block_report_flag_zero_via_agent
  - Note: create_status_report_bundle clears report-on-failure; BundleAgent receive_bytes_from_cla accepts tha

### RFC 9171 §4.2.5.1

**Covered:** 3

- `RFC9171-4-028`: Each BP endpoint ID (EID) SHALL be represented as a CBOR arr......
  - Tests: test_rfc9171_4_028_eid_as_two_element_array
  - Note: CBOR decode verifies EID is 2-element array
- `RFC9171-4-029`: The first item of the array SHALL be the code number identif......
  - Tests: test_rfc9171_4_2_029_eid_first_item_is_scheme_code
  - Note: EID first item test validates scheme code as first array element
- `RFC9171-4-031`: The second item of the array SHALL be the applicable CBOR en......
  - Tests: test_rfc9171_4_2_033_dtn_ssp_as_text_string
  - Note: DTN SSP as text string test validates CBOR text encoding

### RFC 9171 §4.2.5.1.1

**Covered:** 1

- `RFC9171-4-033`: Encoding considerations: For transmission as a BP endpoint I......
  - Tests: test_rfc9171_4_2_033_dtn_none_encoded_as_scheme_1_ssp_0
  - Note: STRENGTHENED: SDK bug fixed - dtn:none now correctly encodes as [1, 0] per RFC. Test decodes CBOR an

### RFC 9171 §4.2.5.1.2

**Covered:** 3

- `RFC9171-4-035`: Encoding considerations: For transmission as a BP endpoint I......
  - Tests: test_rfc9171_4_035_ipn_ssp_two_element_via_agent
  - Note: Agent send+poll cla_tx_queue primary CBOR: destination EID scheme=2 with SSP a CBOR array of exactly
- `RFC9171-4-036`: The first item of this array SHALL be the EID's node number ......
  - Tests: test_rfc9171_4_2_036_037_ipn_node_and_service
  - Note: IPN node number test validates first array item is node number
- `RFC9171-4-037`: The second item of this array SHALL be the EID's service num......
  - Tests: test_rfc9171_4_2_036_037_ipn_node_and_service
  - Note: IPN service number test validates second array item is service number

### RFC 9171 §4.2.6

**Covered:** 1

- `RFC9171-4-038`: Each DTN time SHALL be represented as a CBOR unsigned intege......
  - Tests: test_rfc9171_4_2_038_dtn_time_as_unsigned
  - Note: DTN time test validates represented as CBOR unsigned integer

### RFC 9171 §4.2.7

**Covered:** 3

- `RFC9171-4-039`: Creation Timestamp Each bundle's creation timestamp SHALL be......
  - Tests: test_rfc9171_4_2_039_creation_timestamp_as_array
  - Note: Creation timestamp array test validates 2-element array representation
- `RFC9171-4-040`: The first item of the array, termed "bundle creation time", ......
  - Tests: test_rfc9171_4_2_040_041_timestamp_elements
  - Note: Timestamp element test validates milliseconds and sequence number
- `RFC9171-4-041`: The second item of the array, termed the creation timestamp'......
  - Tests: test_rfc9171_4_2_040_041_timestamp_elements
  - Note: Timestamp sequence test validates second element as sequence number

### RFC 9171 §4.2.8

**Covered:** 1

- `RFC9171-4-043`: Block-Type-Specific Data Block-type-specific data in each bl......
  - Tests: test_rfc9171_4_043_btsd_cbor_via_agent
  - Note: Agent-emitted wire CBOR: payload canonical array element 4 is a CBOR byte string equal to the ADU. W

### RFC 9171 §4.3.1

**Covered:** 16

- `RFC9171-4-044`: Each primary block SHALL be represented as a CBOR array; the......
  - Tests: test_rfc9171_4_044_primary_block_is_cbor_array
  - Note: Primary block array test validates CBOR array structure
- `RFC9171-4-046`: The primary block of each bundle SHALL be immutable....
  - Tests: test_rfc9171_4_046_047_primary_immutable_on_forward
  - Note: Agent send+poll forward path: BundleCodec::encode_primary bytes before send equal primary bytes of c
- `RFC9171-4-047`: The CBOR- encoded values of all fields in the primary block ......
  - Tests: test_rfc9171_4_046_047_primary_immutable_on_forward
  - Note: Same production-path test: CBOR-encoded primary fields unchanged from creation through CLA emission.
- `RFC9171-4-048`: The fields of the primary bundle block SHALL be as follows, ......
  - Tests: test_rfc9171_4_048_primary_block_field_order, test_rfc9171_4_048_crc_field_last, test_rfc9171_4_048_fragmented_with_crc_order
  - Note: Tests verify BundleCodec::encode_primary() produces CBOR with fields in exact order per RFC 9171 §4.
- `RFC9171-4-050`: This version number SHALL be represented as a CBOR unsigned ......
  - Tests: test_rfc9171_4_050_version_as_cbor_unsigned
  - Note: CBOR decode verifies version is unsigned integer
- `RFC9171-4-051`: The CRC type code for the primary block MAY be zero if the b......
  - Tests: test_rfc9171_4_051_primary_crc_nonzero_without_bib_via_agent, test_rfc9171_4_051_primary_crc_zero_allowed_with_primary_bib
  - Note: Agent send() enforces primary CRC: upgrades None→Crc16 without primary BIB; preserves None when BIB 
- `RFC9171-4-053`: ) When a bundle's age exceeds its lifetime, bundle nodes nee......
  - Tests: test_rfc9171_4_053_expiry_deletes_bundle_from_storage
  - Note: Drives BundleAgent.send()+poll() past lifetime: bundle is present in storage before expiry and absen
- `RFC9171-4-054`: , the bundle appears to be part of a denial-of-service attac......
  - Tests: test_rfc9171_4_054_lifetime_override_does_not_replace_asserted
  - Note: Override expires locally; storage and forwarded/encoded primary.lifetime remain 60000; second agent 
- `RFC9171-4-057`: Bundle lifetime SHALL be represented as a CBOR unsigned inte......
  - Tests: test_rfc9171_4_057_lifetime_as_cbor_unsigned
  - Note: CBOR decode verifies lifetime is unsigned integer
- `RFC9171-4-058`: Fragment offset: If and only if the bundle processing contro......
  - Tests: test_rfc9171_4_058_fragment_offset_iff_fragment_via_agent
  - Note: BundleAgent: non-fragment cla_tx_queue has no fragment_offset; MTU fragments have fragment_offset pr
- `RFC9171-4-059`: Fragment offset SHALL be represented as a CBOR unsigned inte......
  - Tests: test_rfc9171_4_059_fragment_offset_cbor_unsigned_via_agent
  - Note: BundleAgent send+poll with cla_mtu fragments a large ADU; each cla_tx_queue fragment primary CBOR el
- `RFC9171-4-060`: Total Application Data Unit Length: If and only if the bundl......
  - Tests: test_rfc9171_4_060_total_adu_length_iff_fragment_via_agent
  - Note: BundleAgent send+poll: non-fragment cla_tx_queue primary has no total_app_data_length; MTU-fragmente
- `RFC9171-4-062`: CRC: A CRC SHALL be present in the primary block unless the ......
  - Tests: test_rfc9171_4_062_primary_crc_present_without_bib_via_agent
  - Note: Agent-originated bundle without primary-targeting BIB emits primary CRC type ≠ 0 and 2-byte CRC-16 f
- `RFC9171-4-064`: CRC: A CRC SHALL be present in the primary block unless the ......
  - Tests: test_rfc9171_4_064_primary_crc_unless_bib_via_agent
  - Note: Agent-originated bundle without primary-targeting BIB emits primary CRC-16 field (2-byte CBOR bstr).
- `RFC9171-4-065`: The length and nature of the CRC SHALL be as indicated by th......
  - Tests: test_rfc9171_4_065_066_primary_crc_zeroed_computation_via_agent
  - Note: Agent receive accepts CRC-16 primary; corrupting bundle bytes yields receive Err (CRC recomputed wit
- `RFC9171-4-066`: The CRC SHALL be computed over the concatenation of all byte......
  - Tests: test_rfc9171_4_065_066_primary_crc_zeroed_computation_via_agent
  - Note: Same agent path: corruption rejected proves CRC is computed over primary bytes with CRC field tempor

### RFC 9171 §4.3.2

**Covered:** 5

- `RFC9171-4-067`: Canonical Bundle Block Format Every block other than the pri......
  - Tests: test_rfc9171_4_3_2_042_canonical_block_array_structure
  - Note: Canonical block array test validates 5-element structure
- `RFC9171-4-069`: The fields of every canonical block SHALL be as follows, lis......
  - Tests: test_rfc9171_4_3_2_043_block_type_code_unsigned
  - Note: Block type code test validates CBOR unsigned integer
- `RFC9171-4-071`: The block number SHALL be represented as a CBOR unsigned int......
  - Tests: test_rfc9171_4_3_1_block_number_nonzero, test_rfc9171_4_3_2_044_block_number_unsigned, test_rfc9171_4_3_2_multiple_blocks_unique_block_numbers
  - Note: Block number nonzero test validates >0 for canonical blocks
- `RFC9171-4-072`: For the Bundle Payload Block in particular (block type 1), t......
  - Tests: test_rfc9171_4_3_2_047_block_type_specific_data_byte_string
  - Note: Block data byte string test validates type-specific data as CBOR byte string
- `RFC9171-4-073`: If present, the length and nature of the CRC SHALL be as ind......
  - Tests: test_rfc9171_4_3_2_crc_present_when_crc_type_nonzero
  - Note: Block CRC test validates presence when type nonzero

### RFC 9171 §4.4

**Covered:** 1

- `RFC9171-4-075`: All implementations of the Bundle Protocol specification (th......
  - Tests: test_rfc9171_4_075_implementation_must_parse_extension_blocks
  - Note: Extension block parsing test validates implementation must parse

### RFC 9171 §4.4.1

**Covered:** 3

- `RFC9171-4-077`: That node ID SHALL conform to Section 4....
  - Tests: test_rfc9171_4_077_previous_node_eid_conforms_to_section_4
  - Note: Previous node EID test validates conformance to §4.2.5
- `RFC9171-4-078`: If the local node is the source of the bundle, then the bund......
  - Tests: test_rfc9171_4_4_1_no_previous_node_when_source_is_forwarder
  - Note: No previous node test when source is forwarder
- `RFC9171-4-079`: Otherwise, the bundle SHOULD contain one (1) occurrence of t......
  - Tests: test_rfc9171_4_079_previous_node_inserted_on_forward
  - Note: Production path test: receive_from_cla + poll drives automatic forwarding. Verifies Previous Node bl

### RFC 9171 §4.4.2

**Covered:** 3

- `RFC9171-4-081`: The block-type-specific data of this block is an unsigned in......
  - Tests: test_rfc9171_4_4_2_bundle_age_incremented_on_forward
  - Note: Bundle age increment test on forward
- `RFC9171-4-082`: ) If the bundle's creation time is zero, then the bundle MUS......
  - Tests: test_rfc9171_4_4_2_bundle_age_required_when_creation_time_zero
  - Note: Bundle age required test when creation time zero
- `RFC9171-4-083`: A bundle MUST NOT contain multiple occurrences of the Bundle......
  - Tests: test_rfc9171_4_083_at_most_one_bundle_age_block
  - Note: At most one bundle age block test

### RFC 9171 §4.4.3

**Covered:** 6

- `RFC9171-4-084`: The hop limit MUST be in the range 1 through 255....
  - Tests: test_rfc9171_4_084_hop_limit_range_1_to_255, test_rfc9171_4_084_hop_count_initially_zero_increments_by_one
  - Note: Hop limit range 1-255 test
- `RFC9171-4-085`: The hop limit value SHOULD NOT be changed at any time after ......
  - Tests: test_rfc9171_4_4_3_hop_count_incremented_on_forward
  - Note: Hop count increment test on forward
- `RFC9171-4-086`: When a bundle's hop count exceeds its hop limit, the bundle ......
  - Tests: test_rfc9171_4_086_hop_limit_exceeded_causes_deletion
  - Note: Node-level test: Hop count incremented on forward, bundle deleted with ReasonCode::HopLimitExceeded 
- `RFC9171-4-087`: The block-type-specific data in a Hop Count Block SHALL be r......
  - Tests: test_rfc9171_4_087_hop_count_cbor_array_two_items
  - Note: Hop count array structure test validates 2-item CBOR array
- `RFC9171-4-088`: The first item of this array SHALL be the bundle's hop limit......
  - Tests: test_rfc9171_4_088_hop_limit_first_item_cbor_unsigned
  - Note: Hop limit first item test validates CBOR unsigned
- `RFC9171-4-090`: A bundle MAY contain one occurrence of this type of block bu......
  - Tests: test_rfc9171_4_090_at_most_one_hop_count_block
  - Note: Payload block structure test validates block fields

### RFC 9171 §5.1

**Covered:** 1

- `RFC9171-5-001`: For this reason, the generation of status reports MUST be di......
  - Tests: test_rfc9171_5_001_status_reports_disabled_by_default
  - Note: BPA uses StatusReportPolicy::default() which returns none() (all reporting disabled). Test verifies 

### RFC 9171 §5.10

**Covered:** 2

- `RFC9171-5-063`: Bundle Deletion The steps in deleting a bundle are as follow......
  - Tests: test_rfc9171_5_063_deletion_status_report_generated
  - Note: BPA generates bundle deletion status report when REQUEST_REPORT_DELETION flag is set and policy allo
- `RFC9171-5-064`: Step 2: All of the bundle's retention constraints MUST be re......
  - Tests: test_rfc9171_5_064_remove_all_retention_constraints_on_deletion
  - Note: Node-level test: delete_bundle() removes all retention constraints. Test would fail if SDK did not c

### RFC 9171 §5.12

**Covered:** 2

- `RFC9171-5-066`: Canceling a Transmission When requested to cancel a specifie......
  - Tests: test_rfc9171_5_066_cancel_transmission_via_agent
  - Note: BundleAgent::cancel_transmission on an admitted undiscarded bundle sets BundleState::Deleted and lea
- `RFC9171-5-067`: When a bundle expires, the BPA MUST delete the bundle for th......
  - Tests: test_rfc9171_5_067_delete_expired_bundle_lifetime_expired
  - Note: Node-level test: poll() deletes expired bundle with LifetimeExpired reason code 1. Test would fail i

### RFC 9171 §5.2

**Covered:** 1

- `RFC9171-5-002`: An outbound bundle MUST be created per the parameters of the......
  - Tests: test_rfc9171_5_002_send_sets_dispatch_pending
  - Note: BundleAgent::send admits the outbound bundle and adds DispatchPending retention constraint before po

### RFC 9171 §5.3

**Covered:** 2

- `RFC9171-5-003`: ) The steps in dispatching a bundle are as follows: Step 1: ......
  - Tests: test_rfc9171_5_003_dispatch_local_delivery_vs_forward
  - Note: Tests drive BundleAgent via receive_from_cla() + poll() and verify dispatch determines local deliver
- `RFC9171-5-004`: Step 1: If the bundle's destination endpoint is an endpoi......
  - Tests: test_rfc9171_5_004_disavow_destination_membership_no_self_forward
  - Note: Full §5.3 Step 1 text restored. Test drives BundleAgent.receive_bytes_from_cla + poll for a bundle w

### RFC 9171 §5.4

**Covered:** 12

- `RFC9171-5-005`: Bundle Forwarding The steps in forwarding a bundle are as fo......
  - Tests: test_rfc9171_5_005_forward_pending_constraint_added
  - Note: Production path test: receive_from_cla + poll drives automatic forwarding. Verifies ForwardPending r
- `RFC9171-5-006`: Bundle Forwarding The steps in forwarding a bundle are as fo......
  - Tests: test_rfc9171_5_005_forward_pending_constraint_added, test_rfc9171_5_007_forwarding_contraindicated_no_route
  - Note: RFC9171-5-006 combines Step 1 (ForwardPending added, DispatchPending removed) and Step 2 (determine 
- `RFC9171-5-007`: Step 2: The BPA MUST determine whether or not forwarding is ......
  - Tests: test_rfc9171_5_007_forwarding_contraindicated_no_route
  - Note: BundleAgent checks static routing table per RFC 9171 §5.4 Step 2. When no route exists, forwarding i
- `RFC9171-5-009`: * Provided the BPA succeeded in selecting the node or nodes ......
  - Tests: test_rfc9171_5_009_5_012_cla_selection_and_invocation, test_multi_hop_forwarding_integration
  - Note: BPA selects and invokes CLA services for forwarding per RFC 9171 §5.4. Mock CLA demonstrates success
- `RFC9171-5-011`: 5), then the Forwarding Contraindicated procedure defined in......
  - Tests: test_rfc9171_5_007_forwarding_contraindicated_no_route, test_rfc9171_5_021_forwarding_contraindicated_leads_to_failed
  - Note: Tests verify that when forwarding is contraindicated (no route), the §5.4.1 Forwarding Contraindicat
- `RFC9171-5-012`: Step 4: For each node selected for forwarding, the BPA MUST ......
  - Tests: test_rfc9171_5_009_5_012_cla_selection_and_invocation, test_multi_hop_forwarding_integration
  - Note: For each selected forwarding node, BPA invokes CLA services to effect sending per RFC 9171 §5.4 step
- `RFC9171-5-013`: Note that: * If the bundle has a Previous Node Block, as def......
  - Tests: test_rfc9171_4_4_1_previous_node_block_replacement, test_multi_hop_forwarding_integration
  - Note: process_on_forward() removes existing Previous Node block before inserting new one. Test verifies ol
- `RFC9171-5-014`: * If the BPA is configured to attach Previous Node Blocks to......
  - Tests: test_rfc9171_4_4_1_previous_node_block_replacement, test_multi_hop_forwarding_integration
  - Note: process_on_forward() inserts Previous Node block containing forwarding node's ID. Test verifies new 
- `RFC9171-5-015`: 2, then at the last possible moment before the CLA initiates......
  - Tests: test_rfc9171_4_4_2_bundle_age_update_on_forward, test_multi_hop_forwarding_integration
  - Note: process_on_forward() increases Bundle Age by residence time before CLA transmission. Test verifies a
- `RFC9171-5-017`: If completion of the data-sending procedures by all selected......
  - Tests: test_rfc9171_5_017_forwarding_status_report_generated
  - Note: Node-level test: Forwarding status report generated when requested per RFC 9171 §5.4. Test decodes r
- `RFC9171-5-018`: * If any applicable Bundle Protocol extensions mandate gener......
  - Tests: test_rfc9171_5_018_extension_cla_finish_status_report_bytes
  - Note: Extension hook set_extension_cla_finish_report(TransmissionCancelled); queue_cla_send_complete+poll 
- `RFC9171-5-019`: * The bundle's "Forward pending" retention constraint MUST b......
  - Tests: test_rfc9171_5_5_forwarding_failure_deletion
  - Note: Forwarding failure deletion test

### RFC 9171 §5.4.1

**Covered:** 2

- `RFC9171-5-020`: Forwarding Contraindicated The steps in responding to contra......
  - Tests: test_rfc9171_5_4_1_contraindicated_retention
  - Note: Contraindicated retention test
- `RFC9171-5-021`: Step 2: If forwarding failure is declared, then the Forwardi......
  - Tests: test_rfc9171_5_021_forwarding_contraindicated_leads_to_failed
  - Note: Tests drive production path (receive_from_cla + poll) with no route configured. Verifies forwarding 

### RFC 9171 §5.4.2

**Covered:** 5

- `RFC9171-5-023`: This forwarding, if performed, SHALL be accomplished by perf......
  - Tests: test_rfc9171_5_023_forward_back_uses_steps_4_5
  - Note: Production path test: receive_from_cla + poll with ReturnToPreviousNode policy. Verifies return forw
- `RFC9171-5-024`: 4 where the sole node selected for forwarding SHALL be the n......
  - Tests: test_rfc9171_5_024_sole_node_is_previous_node
  - Note: Production path test: receive_from_cla + poll with ReturnToPreviousNode policy. Verifies bundle is f
- `RFC9171-5-025`: Step 2: If the bundle's destination endpoint is an endpoint ......
  - Tests: test_rfc9171_5_025_forward_pending_removed_on_success
  - Note: Node-level test: BundleAgent removes ForwardPending retention constraint after confirm_transmission_
- `RFC9171-5-026`: Otherwise, the bundle MUST be deleted: the Bundle Deletion p......
  - Tests: test_rfc9171_5_026_otherwise_bundle_deleted
  - Note: Production path test: receive_from_cla + poll with no routes and Delete policy. Verifies bundle is d
- `RFC9171-5-027`: Otherwise, the bundle MUST be deleted: the Bundle Deletion p......
  - Tests: test_rfc9171_5_027_delete_bundle_forwarding_failed
  - Note: Bundle deleted when forwarding fails per RFC 9171 §5.4.2. Test verifies delete_bundle called with ap

### RFC 9171 §5.5

**Covered:** 2

- `RFC9171-5-028`: Bundle age MAY be determined by subtracting the bundle's cre......
  - Tests: test_rfc9171_5_028_bundle_age_accumulated
  - Note: Node-level test: Bundle age accumulated by SDK on forward per RFC 9171 §4.4.2. Test verifies age inc
- `RFC9171-5-031`: When a bundle expires, the BPA MUST delete the bundle for th......
  - Tests: test_rfc9171_4_2_3_lifetime_expiry_causes_deletion
  - Note: Lifetime expiry deletion test

### RFC 9171 §5.6

**Covered:** 8

- `RFC9171-5-033`: Bundle Reception The steps in processing a bundle that has b......
  - Tests: test_rfc9171_5_033_dispatch_pending_constraint_on_reception
  - Note: Node-level test: receive_from_cla() adds DispatchPending retention constraint. Test would fail if SD
- `RFC9171-5-034`: Step 2: If the "request reporting of bundle reception" flag ......
  - Tests: test_rfc9171_5_034_reception_status_report_generated
  - Note: BPA generates bundle reception status report when REQUEST_REPORT_RECEPTION flag is set and policy al
- `RFC9171-5-035`: Step 3: CRCs SHOULD be computed for every block of the bundl......
  - Tests: test_rfc9171_5_035_crc_computation_on_reception
  - Note: Node-level test: BundleCodec rejects bundles with corrupted data/CRC. Test would fail if SDK did not
- `RFC9171-5-038`: If any block of the bundle is malformed according to this......
  - Tests: test_rfc9171_5_038_crc_failure_skips_remaining_reception_steps
  - Note: Full §5.6 Step 3 CRC/malformed deletion+skip text restored. Test encodes a Crc16 bundle, corrupts a 
- `RFC9171-5-039`: Step 4: For each block in the bundle that is an extension bl......
  - Tests: test_rfc9171_5_039_report_status_on_unintelligible_block
  - Note: Node-level test: BundleAgent generates status report with ReasonCode::BlockUnsupported when bundle h
- `RFC9171-5-040`: If any block of the bundle is malformed according to this sp......
  - Tests: test_rfc9171_5_6_delete_on_critical_unsupported_block, test_rfc9171_4_2_4_delete_bundle_if_block_cant_be_processed, test_rfc9171_5_056_delete_bundle_on_unintelligible_block
  - Note: Node-level test: BundleAgent rejects bundle with unintelligible block marked DELETE_BUNDLE_ON_FAILUR
- `RFC9171-5-041`: The Bundle Deletion procedure defined in Section 5.10 MUST b......
  - Tests: test_rfc9171_5_041_skip_remaining_steps_after_deletion
  - Note: Node-level test: Deleted bundle is removed from storage and not delivered. Test would fail if SDK co
- `RFC9171-5-043`: * If the block processing control flags in that block do *NO......
  - Tests: test_rfc9171_5_6_discard_unsupported_block, test_rfc9171_4_2_4_discard_block_if_cant_be_processed, test_rfc9171_5_057_discard_unintelligible_block
  - Note: Node-level test: BundleAgent discards unintelligible block marked DISCARD_BLOCK_ON_FAILURE per RFC 9

### RFC 9171 §5.7

**Covered:** 5

- `RFC9171-5-044`: Local Bundle Delivery The steps in processing a bundle that ......
  - Tests: test_rfc9171_5_044_fragment_invokes_reassembly
  - Note: Production path test: receive_from_cla invokes reassembly for fragments, complete ADU delivered. Tes
- `RFC9171-5-045`: If this procedure results in reassembly of the entire origin......
  - Tests: test_rfc9171_5_045_reassembly_pending_constraint
  - Note: Production path test: incomplete fragments have ReassemblyPending constraint, remaining steps skippe
- `RFC9171-5-048`: * If the registration is in the Active state, then the bundl......
  - Tests: test_rfc9171_5_048_local_delivery
  - Note: Node-level test: Local delivery via deliver_local() per RFC 9171 §5.7. Test verifies bundle in deliv
- `RFC9171-5-049`: * If the registration is in the Passive state, or if deliver......
  - Tests: test_rfc9171_5_7_delivery_failure_causes_deletion
  - Note: Delivery failure deletion test
- `RFC9171-5-050`: Step 3: As soon as the bundle has been delivered, if the "re......
  - Tests: test_rfc9171_5_050_delivery_status_report_generated
  - Note: Node-level test: Delivery status report generated when requested per RFC 9171 §5.7. Test decodes rep

### RFC 9171 §5.8

**Covered:** 6

- `RFC9171-5-051`: To fragment a bundle whose payload is of size M is to replac......
  - Tests: test_rfc9171_5_051_fragment_bundle_exceeding_mtu
  - Note: Production path test: receive_from_cla + poll drives automatic forwarding with MTU-based fragmentati
- `RFC9171-5-054`: Fragmentation SHALL be constrained as follows: * The concate......
  - Tests: test_rfc9171_5_9_reassembly_byte_identical
  - Note: Reassembly byte identical test
- `RFC9171-5-056`: * The primary block of each fragment MUST differ from that o......
  - Tests: test_rfc9171_5_8_fragment_has_is_fragment_flag
  - Note: Fragment has is-fragment flag test
- `RFC9171-5-057`: Additionally, the CRC of the primary block of the fragmented......
  - Tests: test_rfc9171_5_057_fragment_crc_recomputed
  - Note: Test verifies fragments can be encoded/decoded with valid CRCs. Test would fail if CRC was not recom
- `RFC9171-5-058`: * If the fragmented bundle is not a fragment or is the fragm......
  - Tests: test_rfc9171_5_058_extension_blocks_in_first_fragment
  - Note: Test verifies first fragment contains all extension blocks while other fragments do not. Test would 
- `RFC9171-5-059`: * Each of the fragmented bundle's extension blocks whose "Bl......
  - Tests: test_rfc9171_5_059_replicate_in_every_fragment
  - Note: Test verifies blocks without replicate flag are not in all fragments. Test would fail if non-replica

### RFC 9171 §5.9

**Covered:** 2

- `RFC9171-5-060`: If the concatenation -- as informed by fragment offsets and ......
  - Tests: test_rfc9171_5_060_reassembly_delivers_complete_adu
  - Note: Test verifies fragments are reassembled into complete ADU with exact payload match. Test would fail 
- `RFC9171-5-061`: * The "Reassembly pending" retention constraint MUST be remo......
  - Tests: test_rfc9171_5_061_remove_reassembly_pending_all_fragments
  - Note: Production path test: fragments have ReassemblyPending until reassembly completes. ReassemblyManager

### RFC 9171 §6.1

**Covered:** 3

- `RFC9171-6-001`: Each BP administrative record SHALL be represented as a CBOR......
  - Tests: test_rfc9171_6_001_002_003_admin_record_structure, test_decoder_rejects_non_array_admin_record, test_decoder_rejects_wrong_admin_record_length
  - Note: Test parses encoded admin record and verifies it's CBOR array with exactly 2 elements per RFC 9171 §
- `RFC9171-6-002`: The first item of the array SHALL be a record type code, whi......
  - Tests: test_rfc9171_6_001_002_003_admin_record_structure
  - Note: Test parses encoded admin record and verifies first element is type code (unsigned integer) with val
- `RFC9171-6-003`: The second element of this array SHALL be the applicable CBO......
  - Tests: test_rfc9171_6_001_002_003_admin_record_structure
  - Note: Test parses encoded admin record and verifies second element is CBOR array (status report content) p

### RFC 9171 §6.1.1

**Covered:** 14

- `RFC9171-6-004`: Each bundle status report SHALL be represented as a CBOR arr......
  - Tests: test_rfc9171_6_004_005_status_report_array_length, test_decoder_rejects_wrong_status_report_length
  - Note: Test parses encoded status report and verifies it's CBOR array with 4 (non-fragment) or 6 (fragment)
- `RFC9171-6-005`: The number of elements in the array SHALL be either 6 (if th......
  - Tests: test_rfc9171_6_004_005_status_report_array_length, test_decoder_rejects_wrong_status_report_length
  - Note: Test verifies array length is 6 for fragment reports, 4 for non-fragments per RFC 9171 §6.1.1. Decod
- `RFC9171-6-006`: The first element of the bundle status report SHALL be bundl......
  - Tests: test_rfc9171_6_006_status_assertions
  - Note: Node-level test: Status report has 4 assertion flags (received, forwarded, delivered, deleted) per R
- `RFC9171-6-007`: Each element of the bundle status information SHALL be a bun......
  - Tests: test_rfc9171_6_007_each_status_item_is_array, test_decoder_rejects_non_array_status_item
  - Note: Test verifies each of 4 status items (received/forwarded/delivered/deleted) is CBOR array per RFC 91
- `RFC9171-6-008`: The number of elements in each bundle status item SHALL be e......
  - Tests: test_rfc9171_6_008_status_item_length, test_decoder_rejects_status_item_wrong_length
  - Note: Test verifies status item has 1 element [bool] without time, or 2 elements [bool, time] with time pe
- `RFC9171-6-009`: The first element of each bundle status item SHALL be a stat......
  - Tests: test_rfc9171_6_009_status_indicator_is_boolean, test_decoder_rejects_non_boolean_status_indicator
  - Note: Test verifies first element of each status item is Boolean value per RFC 9171 §6.1.1. Decoder reject
- `RFC9171-6-010`: If present, the second element of each bundle status item SH......
  - Tests: test_rfc9171_6_010_status_time_when_requested, test_rfc9171_6_010_no_status_time_when_not_requested
  - Note: Node-level test: Status time included when flag set, excluded when not set per RFC 9171 §6.1.1. Test
- `RFC9171-6-011`: The second element of the bundle status report SHALL be the ......
  - Tests: test_rfc9171_6_011_reason_code_is_unsigned_integer, test_rfc9171_6_012_reason_code_registry_values
  - Note: Test verifies second element is reason code (unsigned integer) per RFC 9171 §6.1.1. Test verifies al
- `RFC9171-6-012`: | +--------+--------------------------------------------+ | ......
  - Tests: test_rfc9171_6_012_status_report_includes_source_eid
  - Note: Node-level test: Status report references bundle source EID per RFC 9171 §6.1.1. Test decodes report
- `RFC9171-6-013`: The fourth element of the bundle status report SHALL be the ......
  - Tests: test_rfc9171_6_014_creation_timestamp
  - Note: Test verifies fourth element is creation timestamp [time, sequence] per RFC 9171 §4.2.7 and §6.1.1. 
- `RFC9171-6-014`: The fifth element of the bundle status report SHALL be prese......
  - Tests: test_rfc9171_6_015_016_fragment_fields
  - Note: Test verifies status report has 6 elements for fragments (with offset/length at positions 5/6), 4 el
- `RFC9171-6-015`: The fifth element of the bundle status report SHALL be prese......
  - Tests: test_rfc9171_6_015_016_fragment_fields
  - Note: Test verifies fifth element is fragment offset (unsigned integer) per RFC 9171 §6.1.1. Test verifies
- `RFC9171-6-016`: The sixth element of the bundle status report SHALL be prese......
  - Tests: test_rfc9171_6_015_016_fragment_fields
  - Note: Test verifies sixth element is fragment length (unsigned integer) per RFC 9171 §6.1.1. Test verifies
- `RFC9171-6-017`: The sixth element of the bundle status report SHALL be prese......
  - Tests: test_rfc9171_6_016_017_sixth_element_fragment_length
  - Note: Fragment length element test

### RFC 9171 §6.2

**Covered:** 2

- `RFC9171-6-019`: If the administrative record references a bundle and the ref......
  - Tests: test_rfc9171_6_019_020_fragment_status_report_via_agent
  - Note: BundleAgent receive of a fragment with REQUEST_REPORT_DELETION then delete_bundle: generated_reports
- `RFC9171-6-020`: Step 2: A request for transmission of a bundle whose payload......
  - Tests: test_rfc9171_6_019_020_fragment_status_report_via_agent
  - Note: Same path: delete_bundle presents create_status_report_bundle via BundleAgent::send; after poll, cla

### RFC 9171 §7.2

**Covered:** 1

- `RFC9171-7-001`: The potentially long round-trip times characterizing delay-t......
  - Tests: test_rfc9171_7_001_tcpcl_rate_limiting
  - Note: Verbatim: CLAs MUST provide rate limiting or congestion control. TcpclSession::set_rate_limit + crea

### RFC 9172 §1.4.

**Covered:** 1

- `RFC9172-004`: Every security operation in a bundle MUST be unique, meaning that a gi...
  - Tests: security::validation::tests::test_rfc9172_032_multiple_bcbs_per_target_rejected, security::validation::tests::test_rfc9172_042_multiple_bibs_per_target_rejected, test_rfc9172_032_multiple_bcbs_per_target_rejected_at_node (+ 1 more)
  - Note: SDK validates security operation uniqueness - a given security service (BIB or BCB) can only be appl

### RFC 9172 §2.2.

**Covered:** 1

- `RFC9172-005`: BPSec implementations MUST NOT assume that all blocks in a bundle have...
  - Tests: test_a3_multi_source_security
  - Note: RFC 9172 §2.2: Implementations MUST NOT assume all blocks have same security operations. RFC 9173 A.

### RFC 9172 §3.

**Covered:** 1

- `RFC9172-110`: * Security policy SHOULD address whether cipher suites whose ciphertex...
  - Tests: test_rfc9172_110_forbid_ciphertext_expansion_blocks_outbound_bcb
  - Note: permit_ciphertext_expansion=false → PolicyRejected on outbound BCB; nothing stored/delivered/emitted

### RFC 9172 §3.11.1.

**Covered:** 1

- `RFC9172-065`: The BCB MUST hold an authentication tag for the ciphertext either in t...
  - Tests: test_rfc9172_065_049_bcb_holds_auth_tag_via_agent
  - Note: Agent outbound BCB places a 16-byte authentication tag in the BCB security-result field of cla_tx_qu

### RFC 9172 §3.11.2.

**Covered:** 2

- `RFC9172-066`: The ordering of blocks added to a bundle MUST always be in compliance ...
  - Tests: test_rfc9172_066_block_order_payload_last_with_bcb
  - Note: Outbound BCB via BundleAgent::send inserts BCB while keeping payload as last block in cla_tx_queue (
- `RFC9172-067`: * Since the waypoint node wishes to encrypt the block-type-specific da...
  - Tests: test_rfc9172_054_067_bib_altered_and_full_overlap_encrypted
  - Note: Verbatim: when encrypting blocks covered by BIBs, those BIBs MUST also be encrypted. Full-overlap pr

### RFC 9172 §3.2.

**Covered:** 4

- `RFC9172-009`: Uniqueness Security operations in a bundle MUST be unique; the same se...
  - Tests: security::validation::tests::test_rfc9172_032_multiple_bcbs_per_target_rejected, security::validation::tests::test_rfc9172_042_multiple_bibs_per_target_rejected, test_rfc9172_032_multiple_bcbs_per_target_rejected_at_node (+ 1 more)
  - Note: SDK validates security operation uniqueness via validate_unique_bib_per_target and validate_unique_b
- `RFC9172-010`: Security operations in a bundle MUST be unique; the same security serv...
  - Tests: security::validation::tests::test_rfc9172_032_multiple_bcbs_per_target_rejected, security::validation::tests::test_rfc9172_042_multiple_bibs_per_target_rejected, test_rfc9172_032_multiple_bcbs_per_target_rejected_at_node (+ 1 more)
  - Note: SDK validates that security operations (BIB and BCB) are unique per target. Tests verify rejection o
- `RFC9172-011`: A new security block MUST NOT be added to a bundle if a preexisting se...
  - Tests: security::validation::tests::test_rfc9172_032_multiple_bcbs_per_target_rejected, security::validation::tests::test_rfc9172_042_multiple_bibs_per_target_rejected, test_rfc9172_032_multiple_bcbs_per_target_rejected_at_node (+ 1 more)
  - Note: SDK validates that no duplicate security blocks of same type (BIB/BCB) target the same block. valida
- `RFC9172-012`: Signing the payload twice: The two operations OP(bib-integrity, payloa...
  - Tests: security::validation::tests::test_rfc9172_042_multiple_bibs_per_target_rejected, test_rfc9172_042_multiple_bibs_per_target_rejected_at_node
  - Note: SDK validates that payload (or any target) cannot be signed twice. validate_unique_bib_per_target re

### RFC 9172 §3.3.

**Covered:** 1

- `RFC9172-015`: If a node processes any security operation in a security block, it is ...
  - Tests: test_rfc9172_015_process_all_security_operations_in_block
  - Note: Agent-path: BIB ASB with two security operations (payload + hop-count); hop-count tampered after sig

### RFC 9172 §3.4.

**Covered:** 1

- `RFC9172-016`: Therefore, a security target in a security block MUST be represented a...
  - Tests: test_rfc9172_019_020_targets_as_cbor_array, test_rfc9172_016_target_not_integer_rejected
  - Note: SDK represents targets as block numbers (integers). Generator test decodes and verifies. Receiver te

### RFC 9172 §3.6.

**Covered:** 17

- `RFC9172-017`: The fields of the ASB SHALL be as follows, listed in the order in whic...
  - Tests: test_a1_generate_bundle_with_bib, test_a2_generate_bundle_with_bcb, test_rfc9172_017_asb_fields_out_of_order_rejected
  - Note: RFC 9172 §3.6: ASB fields SHALL appear in order. Generation tests (A.1/A.2) produce byte-exact RFC m
- `RFC9172-018`: The encoding of these fields MUST be in accordance with the canonical ...
  - Tests: test_a1_generate_bundle_with_bib, test_a2_generate_bundle_with_bcb, test_rfc9172_018_non_canonical_cbor_rejected (+ 1 more)
  - Note: RFC 9172 §3.6+§4: ASB encoding MUST be canonical CBOR. Generation tests prove canonical encoding (by
- `RFC9172-019`: This field SHALL be represented by a Concise Binary Object Representat...
  - Tests: test_rfc9172_019_020_targets_as_cbor_array, test_rfc9172_019_020_targets_not_array_rejected
  - Note: SDK encodes targets as CBOR array. Generator test decodes and asserts array type. Receiver test (val
- `RFC9172-020`: SHALL be represented by a Concise Binary Object Representation (CBOR) ...
  - Tests: test_rfc9172_019_020_targets_as_cbor_array, test_rfc9172_019_020_targets_not_array_rejected
  - Note: SDK encodes targets as CBOR array of integers. Generator test decodes and verifies array type. Recei
- `RFC9172-021`: This array MUST have at least one entry and each entry MUST represent ...
  - Tests: test_rfc9172_021_targets_non_empty_valid_blocks, test_rfc9172_021_empty_targets_rejected
  - Note: SDK enforces non-empty targets array with integer block numbers. Generator test verifies targets arr
- `RFC9172-023`: This field SHALL be represented by a CBOR unsigned integer....
  - Tests: test_rfc9172_023_context_id_as_unsigned, test_rfc9172_023_context_id_not_integer_rejected
  - Note: SDK encodes context ID as CBOR unsigned integer. Generator test decodes and asserts Integer type. Re
- `RFC9172-024`: This field SHALL be represented as a CBOR unsigned integer whose conte...
  - Tests: test_rfc9172_024_flags_as_unsigned_bitfield, test_rfc9172_024_flags_not_integer_rejected
  - Note: SDK encodes flags as CBOR unsigned integer (bit field). Generator test decodes and asserts Integer t
- `RFC9172-026`: Implementations MUST set reserved bits to 0 when writing this field an...
  - Tests: test_rfc9172_026_generator_reserved_bits_zero, test_rfc9172_026_receiver_ignores_reserved_bits
  - Note: Generator test: generate_bib produces security context flags with reserved bits = 0 (bits 1-7 all ze
- `RFC9172-028`: the associated security block field MUST be included in the security b...
  - Tests: test_rfc9172_028_params_present_when_flag_set_via_agent
  - Note: Outbound BCB via BundleAgent::send sets context-flags bit0 and includes a non-empty parameters CBOR 
- `RFC9172-029`: This field SHALL be represented by a CBOR array in accordance with the...
  - Tests: test_rfc9172_029_source_as_eid_array, test_rfc9172_029_source_not_eid_array_rejected
  - Note: SDK encodes source as CBOR EID array per RFC 9171. Generator test decodes and verifies array with ≥2
- `RFC9172-030`: This field SHALL be represented by a CBOR array....
  - Tests: test_rfc9172_030_params_as_cbor_array, test_rfc9172_030_params_not_array_rejected
  - Note: SDK encodes parameters as CBOR array. Generator test decodes and asserts Array type. Receiver test (
- `RFC9172-032`: This field SHALL be represented as a CBOR unsigned integer....
  - Tests: test_rfc9172_032_security_context_id_cbor_unsigned, test_rfc9172_032_bcb_context_id_cbor_unsigned
  - Note: Tests call bib::generate_bib / bcb::generate_bcb (production generators) and manually parse the emit
- `RFC9172-033`: This field SHALL be represented by the applicable CBOR representation ...
  - Tests: test_rfc9172_033_parameter_value_cbor_representation
  - Note: Test calls bib::generate_bib (production generator) and parses the emitted security-context-paramete
- `RFC9172-034`: This field SHALL be represented as a CBOR array of target results....
  - Tests: test_rfc9172_034_results_as_cbor_array, test_rfc9172_034_results_not_array_rejected
  - Note: SDK encodes results as CBOR array. Generator test decodes and asserts Array type. Receiver test (val
- `RFC9172-035`: The target results MUST be ordered identically to the Security Targets...
  - Tests: test_rfc9172_035_036_results_ordered_one_per_target
  - Note: SDK orders results identically to targets (bib.rs:191-195 and :247-254 iterate in same order). Gener
- `RFC9172-036`: There MUST be one entry in this array for each entry in the Security T...
  - Tests: test_rfc9172_035_036_results_ordered_one_per_target, test_rfc9172_036_results_count_mismatch_rejected
  - Note: SDK creates one result per target. Generator test verifies result count equals target count. Receive
- `RFC9172-038`: This field SHALL be represented by the applicable CBOR representation ...
  - Tests: test_rfc9172_038_result_value_cbor_representation
  - Note: Test calls bib::generate_bib (production generator) and parses the emitted security-results array. A

### RFC 9172 §3.7.

**Covered:** 4

- `RFC9172-039`: * A security target listed in the Security Targets field MUST NOT refe...
  - Tests: security::validation::tests::test_rfc9172_039_bib_cannot_target_bcb
  - Note: Test verifies validation rejects BIBs targeting security blocks (BIB or BCB). Test would fail if BIB
- `RFC9172-040`: * The security context MUST utilize an authentication mechanism or an ...
  - Tests: test_rfc9172_112_mandatory_contexts_via_agent
  - Note: BIB-HMAC-SHA2 context (id 1) is emitted/usable — HMAC is an authentication mechanism. Would FAIL if 
- `RFC9172-041`: Notes: * Designers SHOULD carefully consider the effect of setting fla...
  - Tests: test_rfc9172_041_050_outbound_security_blocks_omit_delete_discard_flags
  - Note: BPA as block designer: outbound BIB/BCB via send()+outbound_bcb omit DELETE_BUNDLE_ON_FAILURE and DI
- `RFC9172-042`: * Since OP(bib-integrity, target) is allowed only once in a bundle per...
  - Tests: test_rfc9172_042_multiple_bibs_per_target_rejected_at_node
  - Note: Node-level test: bundle with two BIBs protecting same target is rejected at receive_from_cla(). Test

### RFC 9172 §3.8.

**Covered:** 5

- `RFC9172-045`: values are required by local policy with the following exceptions: - B...
  - Tests: security::validation::tests::test_rfc9172_045_bcb_targeting_payload_must_have_replicate_flag, test_rfc9172_045_bcb_targeting_payload_without_replicate_rejected_at_node
  - Note: SDK validates BCBs targeting payload (block 1) must have replicate flag (bit 0) set. validate_bcb_bl
- `RFC9172-046`: - BCBs MUST NOT have the "Block must be removed from bundle if it can'...
  - Tests: security::validation::tests::test_rfc9172_046_bcb_cannot_have_remove_flag, test_rfc9172_046_bcb_with_remove_flag_rejected_at_node
  - Note: SDK validates BCBs must not have "remove if can't process" flag (bit 2) set. validate_bcb_block_flag
- `RFC9172-047`: A BCB MUST NOT include another BCB as a security target....
  - Tests: security::validation::tests::test_rfc9172_047_bcb_cannot_target_bcb
  - Note: Test verifies validation rejects BCBs targeting other BCBs. Test would fail if BCB allowed to target
- `RFC9172-049`: * Any security context used by a BCB MUST utilize a confidentiality ci...
  - Tests: test_rfc9172_065_049_bcb_holds_auth_tag_via_agent
  - Note: Same test: BCB-AES-GCM produces an authentication tag with the ciphertext (AEAD). Would FAIL if BCB 
- `RFC9172-050`: Notes: * It is RECOMMENDED that designers carefully consider the effec...
  - Tests: test_rfc9172_041_050_outbound_security_blocks_omit_delete_discard_flags
  - Note: Same agent-path assertion for BCB: outbound BCB block_flags clear of delete-on-failure. Fails if BCB

### RFC 9172 §3.9.

**Covered:** 10

- `RFC9172-051`: To address this situation, the following processing rules MUST be foll...
  - Tests: test_rfc9172_051_052_bib_encrypted_when_bcb_covers_all_bib_targets
  - Note: After BIB then BCB on the same sole target, validate_security_blocks_ex fails until a BCB also encry
- `RFC9172-052`: * When adding a BCB to a bundle, if some (or all) of the security targ...
  - Tests: test_rfc9172_051_052_bib_encrypted_when_bcb_covers_all_bib_targets
  - Note: Same production validation path as RFC9172-051: BCB covering all BIB targets requires the existing B
- `RFC9172-053`: * When adding a BCB to a bundle, if some (or all) of the ......
  - Tests: test_rfc9172_053_055_bib_split_on_outbound_bcb_partial_overlap
  - Note: Full §3.9 partial-overlap BIB alteration text restored. BundleAgent.send with OutboundBcbConfig::wit
- `RFC9172-054`: if some (or all) of the security targets of the BCB match......
  - Tests: test_rfc9172_054_067_bib_altered_and_full_overlap_encrypted
  - Note: Verbatim: on partial BCB/BIB target overlap the BIB MUST be altered. OutboundBcbConfig.with_pre_bib 
- `RFC9172-055`: Any security results in the BIB associated with the BCB s......
  - Tests: test_rfc9172_053_055_bib_split_on_outbound_bcb_partial_overlap
  - Note: Same production-path test as RFC9172-053. Asserts security results for BCB-overlapping targets are r
- `RFC9172-056`: * A BIB MUST NOT be added for a security target that is already the se...
  - Tests: test_rfc9172_056_bib_on_bcb_target_rejected_at_agent
  - Note: Test refuses generate_bib when payload is already a BCB target, and BundleAgent::receive_bytes_from_
- `RFC9172-057`: * A BIB integrity value MUST NOT be checked if the BIB is the security...
  - Tests: test_rfc9172_057_encrypted_bib_not_checked
  - Note: process_bibs (invoked by BundleAgent security processing) skips integrity check when the BIB block i
- `RFC9172-058`: * A BIB integrity value MUST NOT be checked if the security target ass...
  - Tests: test_rfc9172_058_bib_target_bcb_protected_not_checked, test_rfc9172_097_bib_not_processed_if_target_has_bcb
  - Note: process_bibs skips verification when the BIB target is also a BCB target (ciphertext). Would FAIL if
- `RFC9172-059`: * As mentioned in Section 3.7, a BIB MUST NOT have a BCB as its securi...
  - Tests: test_rfc9172_059_bib_targeting_bcb_rejected_receive_bytes
  - Note: Production-path test encodes a bundle whose BIB targets a BCB and feeds it through BundleAgent::rece
- `RFC9172-060`: Specifically, for a given security target, BIBs MUST be added before B...
  - Tests: test_rfc9172_060_bib_before_bcb_enforced
  - Note: generate_bib refuses to add a BIB for a target already covered by a BCB (BIBs must be added before B

### RFC 9172 §4.

**Covered:** 5

- `RFC9172-068`: In their canonical form, these fields MUST include their own CBOR enco...
  - Tests: test_rfc9172_068_canonical_form_includes_own_cbor_encoding, test_rfc9172_068_aad_includes_own_cbor_encoding
  - Note: Tests verify that IPPT and AAD canonical forms include their own CBOR encoding and MUST NOT include 
- `RFC9172-069`: * CBOR values from the primary block MUST be canonicalized using the r...
  - Tests: test_rfc9172_069_primary_block_uses_deterministic_cbor
  - Note: Test verifies that CBOR values from primary block MUST be canonicalized using Deterministically Enco
- `RFC9172-070`: * CBOR values from the non-primary block MUST be canonicalized using t...
  - Tests: test_rfc9172_070_non_primary_block_uses_deterministic_cbor
  - Note: Test verifies that CBOR values from non-primary blocks MUST be canonicalized using Deterministically
- `RFC9172-071`: Other fields within a non-primary block MUST NOT be encrypted or decry...
  - Tests: test_rfc9173_099_105_085_outbound_bcb_cla_bytes
  - Note: Same agent outbound BCB test: non-primary block header fields (type/number/flags) are not encrypted 
- `RFC9172-074`: * Reserved and unassigned flags in the block processing control flags ...
  - Tests: test_rfc9172_074_reserved_block_flags_zeroed_in_ippt
  - Note: generate_bib IPPT (scope includes target header) masks block_flags to defined bits 0–2; BIBs for ide

### RFC 9172 §5.1.

**Covered:** 1

- `RFC9172-076`: * When BIBs and BCBs share a security target, BCBs MUST be evaluated f...
  - Tests: test_rfc9172_076_bcb_evaluated_before_bib_on_shared_target
  - Note: "When BIBs and BCBs share a security target, BCBs MUST be evaluated first and BIBs second." Test cre

### RFC 9172 §5.1.1.

**Covered:** 12

- `RFC9172-077`: Receiving BCBs If a received bundle contains a BCB, the receiving node...
  - Tests: test_rfc9172_077_node_determines_bcb_acceptor_at_destination
  - Note: BundleAgent.receive_from_cla() determines node is BCB security acceptor (destination), decrypts payl
- `RFC9172-078`: If a received bundle contains a BCB, the receiving node MUST determine...
  - Tests: test_rfc9172_078_bcb_acceptor_decryption_failure_deletes_bundle
  - Note: Node at destination with wrong AES key fails BCB decryption. DeleteBundle policy is applied: receive
- `RFC9172-079`: If processing a security operation fails, the target SHALL be processe...
  - Tests: test_rfc9172_079_bcb_failure_delete_bundle_policy, test_rfc9172_079_bib_failure_delete_bundle_policy, test_rfc9172_079_bcb_failure_strip_policy (+ 1 more)
  - Note: "If processing a security operation fails, the target SHALL be processed according to the security p
- `RFC9172-081`: When all security operations for a BCB have been removed from the BCB,...
  - Tests: test_rfc9172_081_bcb_removed_after_processing
  - Note: Test verifies that after BCB decryption succeeds, the BCB block is removed from bundle.blocks. Test 
- `RFC9172-082`: If the receiving node is the destination of the bundle, the node MUST ...
  - Tests: test_rfc9172_082_destination_must_decrypt_bcb
  - Note: Test verifies destination node decrypts BCB and replaces ciphertext with plaintext. Test would fail 
- `RFC9172-084`: If the security policy of a node specifies that a node should have app...
  - Tests: test_rfc9172_084_delete_bundle_action, test_rfc9172_084_report_action
  - Note: Production tests: BundleAgent with SecurityPolicy requiring BCB for payload executes DeleteBundle (b
- `RFC9172-085`: It is RECOMMENDED that the node remove the security target from the bu...
  - Tests: test_rfc9172_085_099_discard_non_payload_target_on_bcb_failure
  - Note: Verbatim RECOMMENDED: remove security target when confidentiality cannot be established. Wrong-key B
- `RFC9172-086`: If the removed security target is the payload block, the bundle MUST b...
  - Tests: test_rfc9172_086_remove_payload_target
  - Note: Production test: BundleAgent with SecurityPolicy RemoveTarget action on missing BCB for payload disc
- `RFC9172-087`: If an encrypted payload block cannot be decrypted (i.e., the ciphertex...
  - Tests: test_rfc9172_087_payload_decryption_failure_discards_bundle
  - Note: Test verifies BCB decryption failure returns BcbDecryptionFailed when wrong key used. Test would fai
- `RFC9172-088`: If an encrypted security target other than the payload bl......
  - Tests: test_rfc9172_088_agent_discards_non_payload_target_and_security_blocks, test_rfc9172_088_non_payload_decryption_failure_discards_target
  - Note: Full §5.1.1 non-payload decrypt-failure text restored. process_bcbs now discards the failed non-payl
- `RFC9172-090`: When a BCB is decrypted, the recovered plaintext for each security tar...
  - Tests: test_rfc9172_090_plaintext_replaces_ciphertext
  - Note: Test verifies decrypted plaintext replaces ciphertext in payload block data field. Test would fail i
- `RFC9172-091`: If a BCB contains multiple security operations, each operation process...
  - Tests: test_rfc9172_091_bcb_operations_processed_independently
  - Note: Test verifies that when multiple BCBs exist (per Erratum 7002: one target per BCB), each BCB operati

### RFC 9172 §5.1.2.

**Covered:** 10

- `RFC9172-092`: Receiving BIBs If a received bundle contains a BIB, the receiving node...
  - Tests: test_rfc9172_092_node_determines_bib_acceptor_at_destination
  - Note: BundleAgent.receive_from_cla() determines node is BIB security acceptor (destination), verifies HMAC
- `RFC9172-093`: If a received bundle contains a BIB, the receiving node MUST determine...
  - Tests: test_rfc9172_093_bib_acceptor_verification_failure_deletes_bundle
  - Note: Node at destination with wrong HMAC key fails BIB verification. DeleteBundle policy is applied: rece
- `RFC9172-096`: When all security operations for a BIB have been removed from the BIB,...
  - Tests: test_rfc9172_096_bib_removed_at_acceptor_after_verification
  - Note: Test verifies BIB is removed from bundle at destination after successful verification. Test would fa
- `RFC9172-097`: A BIB MUST NOT be processed if the security target of the BIB is also ...
  - Tests: test_rfc9172_097_bib_not_processed_if_target_has_bcb
  - Note: Test verifies BIB processing skips targets that are also BCB targets. Test would fail if BIB verific
- `RFC9172-098`: If the security policy of a node specifies that a node should have app...
  - Tests: test_rfc9172_098_delete_bundle_action, test_rfc9172_098_report_action, test_rfc9172_098_remove_nonpayload_target
  - Note: Production tests: BundleAgent with SecurityPolicy requiring BIB for payload executes DeleteBundle (b
- `RFC9172-099`: It is RECOMMENDED that the node remove the security target from the bu...
  - Tests: test_rfc9172_085_099_discard_non_payload_target_on_bcb_failure
  - Note: Verbatim RECOMMENDED: remove non-payload security target on failure. Same agent path as 085; hop-cou
- `RFC9172-102`: If the verification fails, the node SHALL process the security target ...
  - Tests: test_rfc9172_102_bib_verification_failure_at_verifier
  - Note: Test verifies BIB verification failure is detected and reported when wrong key used. Test would fail
- `RFC9172-103`: If a payload integrity check fails at a waypoint, it is RECOMMENDED th...
  - Tests: test_rfc9172_103_waypoint_payload_integrity_failure_like_destination
  - Note: Waypoint BundleAgent (not destination) with security_context verifies payload BIB; tampered payload 
- `RFC9172-104`: If the check passes, the node MUST NOT remove the security operation f...
  - Tests: test_rfc9172_104_bib_not_removed_at_verifier_on_success
  - Note: Test verifies waypoint node does not remove BIB after successful verification (is_destination=false)
- `RFC9172-105`: If a BIB contains multiple security operations, each operation process...
  - Tests: test_rfc9172_105_multiple_bib_operations_processed_independently, test_rfc9172_105_multiple_bib_operations_partial_failure
  - Note: Tests verify that when a BIB has multiple targets, each operation is processed independently for rep

### RFC 9172 §5.2.

**Covered:** 2

- `RFC9172-106`: If it is necessary for a node to fragment a bundle payload, and securi...
  - Tests: test_rfc9172_106_secure_bundle_fragmentation_via_agent_mtu
  - Note: BundleAgent.send with outbound BCB and cla_mtu forces fragmentation of a BPSec-protected bundle. Ass
- `RFC9172-107`: Specifically, a BCB or BIB MUST NOT be added to a bundle if the "Bundl...
  - Tests: test_rfc9172_107_no_bcb_on_fragment_via_agent_send
  - Note: BundleAgent::send with outbound_bcb configured rejects a fragment (fragment_offset set). Would FAIL 

### RFC 9172 §7.

**Covered:** 2

- `RFC9172-108`: * It is RECOMMENDED that security operations be applied to every block...
  - Tests: test_rfc9172_108_recommended_policy_covers_every_block_exact_targets, test_rfc9172_108_recommended_policy_requires_payload_bib
  - Note: recommended_bpsec_default apply_to_every_block: outbound BIB targets exactly primary+hop; BCB target
- `RFC9172-109`: Security policy SHOULD consider how changes to the size of a block cou...
  - Tests: test_rfc9172_109_post_bcb_size_accounted_in_storage_and_mtu
  - Note: account_for_block_size_changes: post-BCB size recorded in last_accounted_bundle_bytes; tiny storage 

### RFC 9172 §7.1.

**Covered:** 1

- `RFC9172-111`: BPSec policy SHOULD specify the conditions in which sending security r...
  - Tests: test_rfc9172_111_security_reason_codes_emitted_per_policy
  - Note: recommended_bpsec_default sets emit_security_reason_codes; BIB failure with StatusReportPolicy::none

### RFC 9172 §9.1.

**Covered:** 1

- `RFC9172-112`: To ensure interoperability among various implementations, all BPSec im...
  - Tests: test_rfc9172_112_mandatory_contexts_via_agent
  - Note: Agent outbound BCB emits context id 2 (BCB-AES-GCM); generate_bib emits context id 1 (BIB-HMAC-SHA2)

### RFC 9172 §9.2.

**Covered:** 1

- `RFC9172-114`: The security context for a security block MUST be uniquely identifiabl...
  - Tests: test_rfc9172_114_context_id_identifiable_via_agent
  - Note: Agent outbound BCB ASB encodes security context id as CBOR integer 2 (BCB-AES-GCM). Would FAIL if co

### RFC 9173 §1.

**Covered:** 1

- `RFC9173-001`: These contexts generate information that MUST be encoded using the Con...
  - Tests: test_a1_generate_bundle_with_bib
  - Note: RFC 9173 A.1 byte-exact generation test encodes all BIB security context information using CBOR per 

### RFC 9173 §2.

**Covered:** 4

- `RFC9173-005`: The output of the HMAC MUST be equal to the size of the SHA2 hashing f...
  - Tests: test_rfc9173_005_hmac_sha512_exact_bytes_from_rfc_vector
  - Note: Uses RFC 9173 A.1 known answer test vector. Computes HMAC-SHA-512 over IPPT bytes and verifies exact
- `RFC9173-006`: The BIB-HMAC-SHA2 security context MUST have the security context iden...
  - Tests: test_a1_generate_bundle_with_bib
  - Note: Byte-exact RFC 9173 A.1 generation: test constructs BIB with context ID 1 (BIB-HMAC-SHA2 per §3.3), 
- `RFC9173-023`: If the primary block flag of the integrity scope flags is set to 1 and...
  - Tests: test_rfc9173_023_primary_block_flag_includes_primary
  - Note: Test compares IPPT with and without primary block flag (bit 0). With flag set, IPPT is significantly
- `RFC9173-087`: If the primary block flag of the AAD scope flags is set to 1, then a c...
  - Tests: test_rfc9173_087_primary_block_in_aad_prevents_tampering
  - Note: Test verifies that when primary block flag (0x01) is set in AAD scope flags, tampering with primary 

### RFC 9173 §3.

**Covered:** 2

- `RFC9173-024`: the canonical form of the block type code, block number, and block pro...
  - Tests: test_rfc9173_024_ippt_block_metadata_order_exact_bytes
  - Note: Constructs IPPT with scope_flags bit 1 set (include target header). Parses IPPT bytes and verifies e
- `RFC9173-088`: then the canonical form of the block type code, block number, and bloc...
  - Tests: test_a2_simple_confidentiality_aesgcm
  - Note: construct_aad() appends target block header (type, number, flags) to AAD when target header flag is 

### RFC 9173 §3.2.

**Covered:** 2

- `RFC9173-007`: Security target contents The contents of the block-type-specific data ...
  - Tests: test_rfc9173_007_target_contents_in_ippt_exact_bytes
  - Note: Uses RFC 9173 A.1.3.1 known answer test vector. Verifies IPPT contains exact payload bytes from vect
- `RFC9173-008`: IPPT scope The determination of which optional types of information we...
  - Tests: test_rfc9173_008_scope_flags_always_in_ippt
  - Note: Test verifies all 8 possible scope flag combinations (0x00-0x07) produce unique IPPT values, proving

### RFC 9173 §3.3.1.

**Covered:** 2

- `RFC9173-009`: This value MUST be encoded as a CBOR unsigned integer....
  - Tests: test_a1_generate_bundle_with_bib
  - Note: RFC 9173 §3.3.1: "This value MUST be encoded as a CBOR unsigned integer" - test_a1_generate_bundle_w
- `RFC9173-010`: Table 1: SHA Variant Parameter Values When not provided, implementatio...
  - Tests: test_rfc9173_010_bib_parser_defaults_sha_variant_to_6, test_rfc9173_010_explicit_sha_variant_overrides_default
  - Note: RFC 9173 §3.3.1 Table 1: Default SHA variant 6 (HMAC 384/384). Test verifies BIB parser accepts bund

### RFC 9173 §3.3.2.

**Covered:** 2

- `RFC9173-011`: This value MUST be encoded as a CBOR byte string....
  - Tests: test_a2_generate_bundle_with_bcb
  - Note: RFC 9173 §3.3.2 (applies to §4.3.3): "This value MUST be encoded as a CBOR byte string" - test_a2_ge
- `RFC9173-012`: If this parameter is not present, then security verifiers and acceptor...
  - Tests: test_rfc9173_012_local_policy_key_when_no_wrapped_key
  - Note: BCB without wrapped-key param; acceptor SecurityContext.add_aes_key (local policy) decrypts via rece

### RFC 9173 §3.3.3.

**Covered:** 3

- `RFC9173-013`: This value MUST be represented as a CBOR unsigned integer, the value o...
  - Tests: test_a1_generate_bundle_with_bib, test_a2_generate_bundle_with_bcb
  - Note: RFC 9173 §3.3.3 (integrity) and §4.3.4 (AAD): "This value MUST be represented as a CBOR unsigned int
- `RFC9173-016`: When not provided, implementations SHOULD assume a value of 7 (indicat...
  - Tests: test_rfc9173_016_default_integrity_scope_flags_to_7
  - Note: Verbatim: when integrity scope flags not provided, SHOULD assume 7. parse_bib_params defaults to 0x0
- `RFC9173-017`: Implementations MUST set reserved and unassigned bits in this field to...
  - Tests: test_rfc9173_017_reserved_bits_zero_in_bib, test_rfc9173_017_reserved_bits_zero_in_bcb
  - Note: Production tests: BIB and BCB generation mask reserved bits (3-7) to 0 per RFC 9173 §3.3.3/§4.3.4. T

### RFC 9173 §3.5.

**Covered:** 1

- `RFC9173-019`: Key Considerations HMAC keys used with this context MUST be symmetric ...
  - Tests: test_a1_simple_integrity_hmac, test_a1_generate_bundle_with_bib
  - Note: BIB-HMAC-SHA2 uses symmetric keys with length equal to hash output per RFC 9173 Section 3.5. Tests u

### RFC 9173 §3.6.

**Covered:** 1

- `RFC9173-020`: A constant-time comparison function SHOULD be used for the comparison ...
  - Tests: test_rfc9173_020_constant_time_eq_match_and_last_byte_mismatch, test_rfc9173_020_constant_time_eq_via_production_fn
  - Note: All authentication-tag comparisons go through security::constant_time_eq (BIB verify + HMAC context)

### RFC 9173 §3.7.

**Covered:** 2

- `RFC9173-021`: In all cases, the canonical form of any portion of an extension block ...
  - Tests: test_rfc9173_021_ippt_uses_canonical_cbor_form
  - Note: Constructs IPPT and verifies canonical CBOR encoding by decode-reencode idempotence test. IPPT CBOR 
- `RFC9173-022`: While integrity scope flags might not be included in the BIB represent...
  - Tests: test_rfc9173_022_scope_flags_included_in_ippt
  - Note: Test generates IPPT with different scope flag values and verifies each produces different IPPT bytes

### RFC 9173 §3.8.1.

**Covered:** 11

- `RFC9173-027`: During keyed hash generation, two inputs are prepared for......
  - Tests: test_rfc9173_027_028_031_034_bib_generation_exact_bytes_via_agent
  - Note: Full §3.8.1 keyed-hash input prep text. BundleAgent apply_outbound_bcb strips CRC from BIB targets (
- `RFC9173-028`: During keyed hash generation, two inputs are prepared for......
  - Tests: test_rfc9173_027_028_031_034_bib_generation_exact_bytes_via_agent
  - Note: Verbatim: HMAC key and IPPT MUST be generated as follows. Test fails generation when HMAC key is not
- `RFC9173-029`: * Prior to the generation of the IPPT, if a Cyclic Redundancy Check (C...
  - Tests: test_rfc9173_029_bib_crc_removal_crc16, test_rfc9173_029_bib_crc_removal_crc32
  - Note: RFC 9173 §3.8.1: CRC MUST be removed before IPPT generation. Tests create bundles with CRC-16/CRC-32
- `RFC9173-030`: CRC type field of the target block to "no CRC is present." * Once CRC ...
  - Tests: test_rfc9173_029_bib_crc_removal_crc16, test_rfc9173_029_bib_crc_removal_crc32
  - Note: RFC 9173 §3.8.1: Once CRC removed, IPPT MUST be generated per §3.7. Tests create bundles with CRC-16
- `RFC9173-031`: Upon successful hash generation, the following action MUS......
  - Tests: test_rfc9173_027_028_031_034_bib_generation_exact_bytes_via_agent
  - Note: Verbatim: keyed hash MUST be added as a security result. Asserts BIB ASB result type=1 with exact 32
- `RFC9173-033`: Finally, the BIB containing information about this security operation ...
  - Tests: test_a1_generate_bundle_with_bib
  - Note: generate_bib() populates BIB security results with HMAC signature per RFC 9173 Section 3.8.1. Test v
- `RFC9173-034`: Finally, the BIB containing information about this securi......
  - Tests: test_rfc9173_027_028_031_034_bib_generation_exact_bytes_via_agent
  - Note: Verbatim BIB update steps. Asserts context id=1 (BIB-HMAC-SHA2) and integrity scope flags parameter 
- `RFC9173-035`: * Any local flags used to generate the IPPT MUST be placed in the inte...
  - Tests: test_a1_generate_bundle_with_bib
  - Note: generate_bib() places integrity scope flags in security context parameters (parameter ID 3) per RFC 
- `RFC9173-036`: * The HMAC key MAY be included as a security context parameter, in whi...
  - Tests: test_rfc9173_036_043_bib_wrapped_key_verification, test_rfc9173_036_043_bib_tampered_wrapped_key_fails, test_rfc9173_036_043_bib_wrong_kek_fails
  - Note: RFC 9173 §3.3.2: "The HMAC key MAY be included as a security context parameter, in which case it MUS
- `RFC9173-038`: * The SHA variant used by this security context SHOULD be added as the...
  - Tests: test_rfc9173_038_sha_variant_param_when_not_default
  - Note: Verbatim: SHA variant SHOULD be added when ≠ default key length (default 6). generate_bib with Sha25
- `RFC9173-040`: Problems encountered in the keyed hash generation MUST be processed in...
  - Tests: test_rfc9173_040_111_generation_failure_local_policy
  - Note: Verbatim: keyed hash generation problems MUST follow local BPSec policy. BundleAgent.apply_outbound_

### RFC 9173 §3.8.2.

**Covered:** 6

- `RFC9173-043`: * The HMAC key MUST be derived using the wrapped key security context ...
  - Tests: test_rfc9173_036_043_bib_wrapped_key_verification, test_rfc9173_036_043_bib_wrong_kek_fails
  - Note: RFC 9173 §3.8.2: "The HMAC key MUST be derived using the wrapped key security context parameter if s
- `RFC9173-044`: * The IPPT MUST be generated as discussed in Section 3.7 with the valu...
  - Tests: test_rfc9173_022_scope_flags_included_in_ippt, test_rfc9173_046_047_valid_bib_delivered
  - Note: RFC 9173 §3.8.2: IPPT MUST use integrity scope flags from BIB parameters. Scope flags test proves di
- `RFC9173-046`: The calculated HMAC output MUST be compared to the expected HMAC outpu...
  - Tests: test_a1_simple_integrity_hmac
  - Note: BIB verification compares calculated HMAC to expected HMAC from security results per RFC 9173 Sectio
- `RFC9173-047`: If the calculated HMAC and expected HMAC are identical, the verificati...
  - Tests: test_a1_simple_integrity_hmac
  - Note: BIB verification returns success when calculated and expected HMAC match per RFC 9173 Section 3.8.2.
- `RFC9173-049`: If the verification fails or otherwise experiences an error or if any ...
  - Tests: test_rfc9173_046_047_tampered_payload_rejected, test_rfc9173_046_047_tampered_bib_rejected
  - Note: RFC 9173 §3.8.2: Verification failures or errors MUST be treated as failed per policy. Tamper tests 
- `RFC9173-050`: This security service is removed from the bundle at the s......
  - Tests: test_rfc9173_050_bib_acceptor_waypoint_restores_crc
  - Note: Full acceptor≠destination CRC-restore text restored. process_bibs with bib_acceptor=true and is_dest

### RFC 9173 §4.

**Covered:** 3

- `RFC9173-025`: to 1, then the canonical form of the block type code, block number, an...
  - Tests: test_rfc9173_025_security_header_appended_to_ippt
  - Note: construct_ippt_with_security_header / generate_bib with scope bit 0x04 appends CBOR array [BIB type=
- `RFC9173-051`: The BCB-AES-GCM security context MUST have the security context identi...
  - Tests: test_a2_generate_bundle_with_bcb
  - Note: Byte-exact RFC 9173 A.2 generation: test constructs BCB with context ID 2 (BCB-AES-GCM per §4.3), ge
- `RFC9173-089`: If the security header flag of the AAD scope flags is set to 1, then t...
  - Tests: test_a2_simple_confidentiality_aesgcm
  - Note: construct_aad() appends BCB header (type, number, flags) to AAD when security header flag is set per

### RFC 9173 §4.2.

**Covered:** 1

- `RFC9173-052`: This MUST be the full set of plaintext contained in the block-type-spe...
  - Tests: test_a2_generate_bundle_with_bcb
  - Note: Byte-exact A.2 generation: BCB encrypts payload block-type-specific data (payload bytes), replaces i

### RFC 9173 §4.3.1.

**Covered:** 2

- `RFC9173-054`: The length of the initialization vector, prior to any CBOR encoding, M...
  - Tests: test_rfc9173_054_generation_rejects_short_iv, test_rfc9173_054_generation_rejects_long_iv, test_rfc9173_054_node_rejects_received_short_iv (+ 2 more)
  - Note: RFC 9173 §4.3.1: "The length of the initialization vector, prior to any CBOR encoding, MUST be betwe
- `RFC9173-056`: The initialization vector can have any value, with the caveat that a v...
  - Tests: test_rfc9173_056_nonce_registry_prevents_reuse
  - Note: Test verifies generate_bcb registers (key_id, IV) in NonceRegistry and returns error on reuse per RF

### RFC 9173 §4.3.2.

**Covered:** 2

- `RFC9173-059`: Table 4: AES Variant Parameter Values When not provided, implementatio...
  - Tests: test_rfc9173_059_bcb_parser_defaults_aes_variant_to_3, test_rfc9173_059_explicit_aes_variant_overrides_default
  - Note: RFC 9173 §4.3.1 Table 4: Default AES variant 3 (A256GCM). Test verifies BCB parser accepts bundles w
- `RFC9173-060`: Regardless of the variant, the generated authentication tag MUST alway...
  - Tests: test_a1_generate_bundle_with_bib, test_a2_generate_bundle_with_bcb
  - Note: Byte-exact A.1/A.2 generation: compares computed authentication tags against RFC expected values (HM

### RFC 9173 §4.4.

**Covered:** 1

- `RFC9173-070`: Otherwise, the security target block MUST be resized to accommodate th...
  - Tests: test_rfc9173_070_071_tag_in_ciphertext_receiver_and_no_duplicate_result
  - Note: Verbatim: target MUST be resized for +128-bit tag in ciphertext. Test appends 16-byte tag to ciphert

### RFC 9173 §4.4.1.

**Covered:** 2

- `RFC9173-071`: If the authentication tag is included in the ciphertext placed in the ...
  - Tests: test_rfc9173_070_071_tag_in_ciphertext_receiver_and_no_duplicate_result
  - Note: Verbatim: if tag is in ciphertext, that security result MUST NOT be in the BCB. Test builds BCB with
- `RFC9173-072`: The length of the authentication tag, prior to any CBOR encoding, MUST...
  - Tests: test_a2_generate_bundle_with_bcb
  - Note: RFC 9173 §4.4.1: "The length of the authentication tag, prior to any CBOR encoding, MUST be 128 bits

### RFC 9173 §4.5.

**Covered:** 1

- `RFC9173-074`: Key Considerations Keys used with this context MUST be symmetric and M...
  - Tests: test_rfc9173_074_key_length_enforced_via_agent
  - Note: BundleAgent::send with OutboundBcbConfig AES-128 + 32-byte key fails; 16-byte key succeeds and emits

### RFC 9173 §4.6.

**Covered:** 6

- `RFC9173-075`: GCM Considerations The GCM cryptographic mode of AES has specific requ...
  - Tests: test_rfc9173_075_gcm_requirements_enforced_on_agent_path
  - Note: Verbatim umbrella: GCM requirements MUST be followed. Agent emits two BCBs with distinct per-invocat
- `RFC9173-076`: The pairing of a per-invocation IV and a security key MUST be unique....
  - Tests: test_rfc9173_076_094_distinct_ivs_from_agent_cla_tx
  - Note: Production-path test originates two bundles via BundleAgent::send with the same outbound AES key, th
- `RFC9173-078`: Implementers SHOULD carefully read all relevant sections of [AES-GCM] ...
  - Tests: test_rfc9173_078_iv_reuse_rejected_on_outbound_path
  - Note: Outbound BCB uses NonceRegistry-backed unique IVs; forcing IV counter reuse makes send() fail. Fails
- `RFC9173-079`: In particular, short tag lengths combined with very long messages SHOU...
  - Tests: test_rfc9173_079_rejects_short_auth_tags
  - Note: Verbatim: short tags SHOULD be avoided. generate_bcb always emits 16-byte (128-bit) auth tags. Would
- `RFC9173-080`: * As discussed in Appendix B of [AES-GCM], implementations SHOULD limi...
  - Tests: test_rfc9173_080_failed_bcb_verify_limit_enforced
  - Note: SecurityContext tracks per-key failed_bcb_verifies; process_bcbs_ex refuses decrypt after limit. Age
- `RFC9173-081`: Because GCM has no inherent replay attack protection, implementors SHO...
  - Tests: test_rfc9173_081_decrypt_rejects_replayed_iv
  - Note: Decrypt-side received_iv_registry records IVs after successful BCB decrypt; replay of same IV+key is

### RFC 9173 §4.7.1.

**Covered:** 3

- `RFC9173-083`: Therefore, the plaintext used during encryption MUST be calculated as ...
  - Tests: test_rfc9173_093_e2e_iv_8_bytes, test_rfc9173_093_e2e_iv_12_bytes, test_a2_simple_confidentiality_aesgcm
  - Note: RFC 9173 §4.7.1: Plaintext for encryption MUST be block-type-specific data field (excluding CBOR enc
- `RFC9173-084`: Table 7: CBOR Plaintext Extraction Examples The ciphertext used during...
  - Tests: test_rfc9173_084_119_125_136_decrypt_ciphertext_and_tag_via_agent
  - Note: Agent receive_bytes_from_cla decrypts BCB where ciphertext is raw block-type-specific data (len=plai
- `RFC9173-085`: All other fields of the security target (such as the block type code, ...
  - Tests: test_rfc9173_099_105_085_outbound_bcb_cla_bytes
  - Note: Same production-path test asserts payload block_type, block_number, and block_flags are unchanged af

### RFC 9173 §4.7.2.

**Covered:** 1

- `RFC9173-086`: While the AAD scope flags might not be included in the BCB representin...
  - Tests: test_rfc9173_086_bcb_scope_flags_affect_decryption, test_rfc9173_bcb_scope_0x00_vs_0x01_produces_different_ciphertext
  - Note: Fixed SDK bug: generate_bcb now uses construct_aad() per RFC 9173 §4.7.2 (was using simple vec![scop

### RFC 9173 §4.8.1.

**Covered:** 16

- `RFC9173-091`: Prior to encryption, if a CRC value is present for the target block, t...
  - Tests: test_rfc9173_091_bcb_crc_removal_crc16, test_rfc9173_091_bcb_crc_removal_crc32
  - Note: RFC 9173 §4.7.1: CRC MUST be removed before encryption. Tests create bundles with CRC-16/CRC-32 on t
- `RFC9173-092`: target block to "no CRC is present." * The encryption key MUST have th...
  - Tests: test_rfc9173_092_aes128_wrong_key_length_generation, test_rfc9173_092_aes256_wrong_key_length_generation, test_rfc9173_092_correct_key_lengths_accepted (+ 1 more)
  - Note: RFC 9173 §4.8.1: Encryption key MUST have appropriate length. SDK enforces AES-128=16 bytes, AES-256
- `RFC9173-093`: * The IV selected MUST be of the appropriate length....
  - Tests: test_a2_simple_confidentiality_aesgcm, test_a2_generate_bundle_with_bcb
  - Note: generate_bcb() generates 12-byte IV for AES-GCM per RFC 9173 Section 4.8.1. Test test_a2_generate_bu
- `RFC9173-094`: This means the same key and IV combination MUST NOT be used more than ...
  - Tests: test_rfc9173_076_094_distinct_ivs_from_agent_cla_tx
  - Note: Same production-path test as RFC9173-076: two BundleAgent::send originations with one key emit disti
- `RFC9173-095`: * The security target plaintext for encryption MUST be generated as di...
  - Tests: test_a2_simple_confidentiality_aesgcm
  - Note: BCB encryption uses security target block-type-specific data as plaintext per RFC 9173 Section 4.7.1
- `RFC9173-096`: * Additional authenticated data MUST be generated as discussed in Sect...
  - Tests: test_a2_simple_confidentiality_aesgcm, test_a2_generate_bundle_with_bcb
  - Note: generate_bcb() generates AAD per RFC 9173 Section 4.4 and 4.7.2 for AES-GCM encryption. Byte-exact R
- `RFC9173-097`: Upon successful encryption, the following actions MUST oc......
  - Tests: test_rfc9173_097_103_123_bcb_encrypt_decrypt_exact_bytes_via_agent
  - Note: Verbatim: ciphertext MUST replace plaintext; tag as result or in ciphertext. OutboundBcbConfig agent
- `RFC9173-099`: * The ciphertext produced by AES-GCM MUST replace the bytes used to de...
  - Tests: test_rfc9173_099_105_085_outbound_bcb_cla_bytes
  - Note: Agent send+poll with outbound_bcb: payload bytes in cla_tx_queue encoded bundle differ from plaintex
- `RFC9173-100`: * The authentication tag calculated by the AES-GCM cipher MAY be added...
  - Tests: test_a2_generate_bundle_with_bcb, test_rfc9173_100_valid_bcb_with_tag_delivered, test_rfc9173_100_tampered_auth_tag_rejected
  - Note: SDK always adds authentication tag as security result (result ID 1) in BCB per line 323-329 of bcb.r
- `RFC9173-102`: * The authentication tag MUST be included either as a security result ...
  - Tests: test_a2_generate_bundle_with_bcb, test_rfc9173_100_valid_bcb_with_tag_delivered, test_rfc9173_100_tampered_auth_tag_rejected
  - Note: RFC 9173 §4.8.1: Auth tag MUST be included as result or in ciphertext. SDK includes as result (resul
- `RFC9173-103`: Finally, the BCB containing information about this securi......
  - Tests: test_rfc9173_097_103_123_bcb_encrypt_decrypt_exact_bytes_via_agent
  - Note: Verbatim BCB update steps. Asserts context id=2 (BCB-AES-GCM) and IV parameter (id 1, len 8-16) on a
- `RFC9173-105`: * The IV input to the cipher MUST be added as the IV security context ...
  - Tests: test_rfc9173_099_105_085_outbound_bcb_cla_bytes
  - Note: Same production-path test parses BCB security-context parameters from cla_tx_queue bytes and asserts
- `RFC9173-106`: * Any local flags used to generate AAD for this cipher MUST be placed ...
  - Tests: test_a2_generate_bundle_with_bcb
  - Note: generate_bcb() places AAD scope flags in BCB parameters (parameter ID 3) per RFC 9173 Section 4.8.1.
- `RFC9173-107`: * The encryption key MAY be included as a security context parameter, ...
  - Tests: security::keywrap::tests::test_rfc9173_a2_wrapped_key_exact_bytes, test_rfc9173_4_3_3_wrapped_key_in_bcb_generation
  - Note: RFC 9173 §4.8.1: "it MUST be wrapped using the AES key wrap function as defined in [RFC3394]" - test
- `RFC9173-109`: * The AES variant used by this security context SHOULD be added as the...
  - Tests: test_rfc9173_109_aes_variant_param_when_not_default
  - Note: Verbatim: AES variant SHOULD be added when ≠ default (3=A256GCM). OutboundBcbConfig AES-128 agent pa
- `RFC9173-111`: Problems encountered in the encryption MUST be processed in accordance...
  - Tests: test_rfc9173_040_111_generation_failure_local_policy
  - Note: Verbatim: encryption problems MUST follow local security policy. Wrong AES key length under FailClos

### RFC 9173 §4.8.2.

**Covered:** 9

- `RFC9173-115`: * The decryption key MUST be derived using the wrapped key security co...
  - Tests: test_rfc9173_5_3_bcb_decrypt_with_wrapped_key, test_rfc9172_bcb_decryption_failure_with_wrong_kek
  - Note: RFC 9173 §4.8.2: "The decryption key MUST be derived using the wrapped key security context paramete
- `RFC9173-116`: * The IV MUST be set to the value of the IV security context parameter...
  - Tests: test_rfc9173_093_e2e_iv_8_bytes, test_rfc9173_093_e2e_iv_12_bytes, test_rfc9173_093_e2e_iv_16_bytes
  - Note: RFC 9173 §4.8.2: IV for decryption MUST be set to IV parameter value from BCB. E2e tests encrypt bun
- `RFC9173-119`: * The security target ciphertext for decryption MUST be generated as d...
  - Tests: test_rfc9173_084_119_125_136_decrypt_ciphertext_and_tag_via_agent
  - Note: Same agent decrypt path: security-target ciphertext for decryption is the §4.7.1 block-type-specific
- `RFC9173-120`: * Additional authenticated data MUST be generated as discussed in Sect...
  - Tests: test_rfc9173_086_bcb_scope_flags_affect_decryption, test_rfc9173_bcb_scope_0x00_vs_0x01_produces_different_ciphertext
  - Note: RFC 9173 §4.8.2: AAD MUST use AAD scope flags from BCB parameters. BCB scope tests generate BCB with
- `RFC9173-122`: * The authentication tag MUST be present either as a security result i...
  - Tests: test_rfc9173_122_bcb_missing_auth_tag_rejected
  - Note: RFC 9173 §4.8.2: Auth tag MUST be present (receiver requirement). SDK parse_bcb_results enforces thi
- `RFC9173-123`: Upon successful decryption, the following action MUST occ......
  - Tests: test_rfc9173_097_103_123_bcb_encrypt_decrypt_exact_bytes_via_agent
  - Note: Verbatim: plaintext MUST replace ciphertext after decrypt. Destination BundleAgent receive_bytes_fro
- `RFC9173-125`: Any changes to the security target block length field MUST be correcte...
  - Tests: test_rfc9173_084_119_125_136_decrypt_ciphertext_and_tag_via_agent
  - Note: After agent decrypt, delivered payload.data length equals original plaintext. Would FAIL if block le
- `RFC9173-126`: If the security acceptor is not the bundle destination and if no other...
  - Tests: test_rfc9173_126_bcb_acceptor_waypoint_restores_crc
  - Note: process_bcbs_ex(..., is_destination=false) decrypts payload BCB, removes BCB, restores Crc16 on the 
- `RFC9173-127`: If the ciphertext fails to authenticate, if any needed parameters are ...
  - Tests: test_rfc9173_100_tampered_auth_tag_rejected
  - Note: RFC 9173 §4.8.2: Decryption failures or errors MUST be treated as failed per policy. Tampered auth t

### RFC 9173 §5.

**Covered:** 1

- `RFC9173-026`: BIB MUST be calculated and, in that order, appended to the IPPT....
  - Tests: test_a1_simple_integrity_hmac
  - Note: construct_ippt() generates IPPT per RFC 9173 Section 3.7: canonicalizes security target and appends 

### RFC 9173 §6.2.

**Covered:** 6

- `RFC9173-128`: * It is strongly RECOMMENDED that implementations protect keys both wh...
  - Tests: test_rfc9173_128_keys_zeroized_and_absent_from_stored_emitted_bytes
  - Note: Keys held in zeroize::Zeroizing buffers; Debug redacts; AES/HMAC/KEK byte sequences MUST NOT appear 
- `RFC9173-129`: * In the event that a key is compromised, any security operations usin...
  - Tests: test_rfc9173_129_130_131_compromised_key_rejects_bib_and_bcb
  - Note: mark_key_compromised causes agent-path BIB verify to fail (ops with that context considered compromi
- `RFC9173-130`: using a security context associated with that key SHOULD also be consi...
  - Tests: test_rfc9173_129_130_131_compromised_key_rejects_bib_and_bcb
  - Note: Same compromised-source set: security operations using compromised key rejected on agent path.
- `RFC9173-131`: This means that the BIB-HMAC-SHA2 security context SHOULD NOT be treat...
  - Tests: test_rfc9173_129_130_131_compromised_key_rejects_bib_and_bcb
  - Note: Compromised key: BIB MUST NOT provide integrity and BCB MUST NOT provide confidentiality — both agen
- `RFC9173-132`: * The same key, whether a KEK or a wrapped key, MUST NOT be used for d...
  - Tests: test_rfc9173_132_133_kek_cross_context_and_algorithm_banned
  - Note: KekUsageRegistry::assert_same_key_not_cross_algorithm refuses identical key material bound to differ
- `RFC9173-133`: * A KEK MUST NOT be used to encrypt keys for different security contex...
  - Tests: test_rfc9173_132_133_kek_cross_context_and_algorithm_banned
  - Note: KekUsageRegistry::register and SecurityContext::add_kek_for_context refuse registering the same KEK 

### RFC 9173 §6.3.

**Covered:** 1

- `RFC9173-136`: In all cases, the ciphertext and authentication tag MUST be processed ...
  - Tests: test_rfc9173_084_119_125_136_decrypt_ciphertext_and_tag_via_agent
  - Note: Tampered ciphertext at acceptor yields empty delivered_adus (AES-GCM auth failure). Would FAIL if ct

### RFC 9174 §4

**Covered:** 1

- `RFC9174-4-001`: Session Establishment For bundle transmissions to occur usin......
  - Tests: test_rfc9174_4_001_session_required_for_transfers
  - Note: Session required test

### RFC 9174 §4.1

**Covered:** 9

- `RFC9174-4-1-002`: TCP Connection To establish a TCPCL session, an entity MUST ......
  - Tests: test_rfc9174_4_1_002_transfers_require_established_session
  - Note: Test verifies start_transfer() returns error when called before session establishment. The TcpclSess
- `RFC9174-4-1-003`: If it does so, it MUST NOT overwhelm its target with repeate......
  - Tests: test_rfc9174_4_1_003_no_overwhelm_target
  - Note: BundleAgent.send + poll at advancing times. ConnectionManager enforces min delay (1000ms default) be
- `RFC9174-4-1-007`: Therefore, the entity MUST NOT retry the connection setup earlier than...
  - Tests: test_rfc9174_4_1_007_minimum_delay_enforced
  - Note: BundleAgent.send + poll at first attempt time (t=1000ms), record failure, poll at t=1001ms/1500ms/19
- `RFC9174-4-1-008`: Therefore, the entity MUST NOT retry the connection setup ea......
  - Tests: test_rfc9174_4_1_008_exponential_backoff
  - Note: BundleAgent.send + poll with failures at t=0, 1000, 3000, 7000, 15000ms. ConnectionManager enforces 
- `RFC9174-4-1-009`: Once a TCP connection is established, the active entity SHAL......
  - Tests: test_rfc9174_4_1_009_active_sends_contact_first
  - Note: Test creates Active and Passive sessions. Active.send_contact_header() succeeds immediately (before 
- `RFC9174-4-1-011`: The passive entity SHALL wait for the active entity's Contac......
  - Tests: test_rfc9174_4_1_011_passive_waits_for_contact
  - Note: Test creates Passive session and verifies send_contact_header() fails before receiving Active contac
- `RFC9174-4-1-012`: If either entity does not receive a Contact Header after som......
  - Tests: test_rfc9174_4_1_012_contact_header_timeout, test_rfc9174_4_1_012_timeout_from_establishment_not_first_poll, test_rfc9174_4_1_012_no_timeout_after_contact_received (+ 1 more)
  - Note: new_at_time(0) + poll(10000) with 10s timeout → Terminated and transport_close_kind=Fin. Late first 
- `RFC9174-4-1-013`: Entities SHOULD choose a Contact Header reception timeout in......
  - Tests: test_rfc9174_4_1_013_clamps_excessive_timeout, test_rfc9174_4_1_013_60s_timeout_works
  - Note: SessionConfig with contact_header_timeout=120 is clamped to 60; poll(60000) terminates. Would FAIL i
- `RFC9174-4-1-014`: Within this specification, when an entity is said to "close"......
  - Tests: test_rfc9174_4_1_014_close_uses_fin_not_rst, test_rfc9174_4_1_014_timeout_close_uses_fin, test_rfc9174_4_1_014_normal_termination_uses_fin
  - Note: VirtualStream.close()/close_transport set CloseKind::Fin; timeout and SESS_TERM paths record transpo

### RFC 9174 §4.3

**Covered:** 5

- `RFC9174-4-3-019`: If the "magic string" is not present or is not valid, the co......
  - Tests: test_rfc9174_4_3_019_invalid_magic_terminates
  - Note: Test decodes contact header with invalid magic string ('bad!' instead of 'dtn!') and verifies decode
- `RFC9174-4-3-020`: During contact initiation, the active TCPCL entity SHALL sen......
  - Tests: test_rfc9174_4_3_020_active_sends_highest_version
  - Note: Active sends highest version test
- `RFC9174-4-3-021`: If the active entity receives a Contact Header with a lower ......
  - Tests: test_rfc9174_4_3_021_version_mismatch_active
  - Note: Active session sends version 4, then receives peer contact header with version 3. Verifies process_c
- `RFC9174-4-3-022`: If the passive entity receives a Contact Header containing a version t...
  - Tests: test_rfc9174_4_3_version_mismatch_rejection
  - Note: Version mismatch rejection test
- `RFC9174-4-3-024`: If the Enable TLS state is unacceptable, the entity SHALL te......
  - Tests: test_rfc9174_4_3_024_terminate_if_tls_policy_conflict, test_rfc9174_4_3_024_sess_term_contact_failure_for_tls_policy
  - Note: Tests verify: (1) session processes peer contact with CAN_TLS flag, (2) send_session_term(0x04) emit

### RFC 9174 §4.5

**Covered:** 1

- `RFC9174-4-5-066`: +--------------+------+-------------------------------------+ | XFER_R...
  - Tests: test_rfc9174_4_5_066_session_emits_0x03_for_xfer_refuse, test_rfc9174_4_5_066_session_interprets_0x03_as_refusal
  - Note: Behavioral tests verify: (1) TcpclSession.process_segment() with unsupported critical extension retu

### RFC 9174 §4.6

**Covered:** 6

- `RFC9174-4-6-067`: Any XFER_SEGMENT sent to this peer SHALL have a data payload......
  - Tests: test_rfc9174_4_6_067_segment_mru_enforcement
  - Note: Peer advertises 1000-byte segment MRU. Session creates segments for 2000-byte transfer. Verifies all
- `RFC9174-4-6-068`: Any bundle transfer sent to this peer SHALL have a Total Bun......
  - Tests: test_rfc9174_4_6_068_transfer_mru_enforcement
  - Note: Peer advertises 5000-byte transfer MRU. Session attempts 10000-byte transfer. Verifies start_transfe
- `RFC9174-4-6-069`: A zero-length node ID SHALL be used to indicate the lack of ......
  - Tests: test_rfc9174_4_6_069_zero_length_node_id
  - Note: Session configured with empty node_id string. send_session_init creates SESS_INIT message, verifies 
- `RFC9174-4-6-070`: A non-zero-length Node ID Data SHALL contain the UTF-8 encod......
  - Tests: test_rfc9174_4_6_070_node_id_is_utf8, test_rfc9174_4_6_070_reject_invalid_utf8_node_id
  - Note: Test encodes valid SESS_INIT to wire format, corrupts Node ID bytes with invalid UTF-8 sequence (0xC
- `RFC9174-4-6-072`: If an entity receives a peer node ID that is not authenticat......
  - Tests: test_rfc9174_4_6_072_unauthenticated_node_id_not_used_for_routing, test_rfc9174_4_6_072_unauthenticated_node_id_not_used_for_discovery
  - Note: Tests verify BundleAgent does NOT automatically install routes or discovery data from unauthenticate
- `RFC9174-4-6-074`: If allowed, such a session SHALL be associated with the node......
  - Tests: test_rfc9174_4_6_074_session_uses_actual_sess_init_node_id, test_rfc9174_4_6_074_negotiated_parameters_from_actual_sess_init
  - Note: Tests verify that when active entity receives SESS_INIT with actual peer node ID and parameters, the

### RFC 9174 §4.7

**Covered:** 3

- `RFC9174-4-7-075`: If either the Transfer MRU or Segment MRU is unacceptable, t......
  - Tests: test_rfc9174_4_7_075_unacceptable_mru_termination
  - Note: Session sends SESS_TERM with reason code 0x01 (Contact Failure) and message 'Contact Failure'. Verif
- `RFC9174-4-7-076`: If the Session Keepalive Interval is unacceptable, the entit......
  - Tests: test_rfc9174_4_7_076_reject_excessive_peer_keepalive, test_rfc9174_4_7_076_accept_acceptable_keepalive, test_rfc9174_4_7_076_boundary_rejection
  - Note: process_session_init with peer keepalive 900 and max_peer_keepalive=600 queues SESS_TERM bytes type=
- `RFC9174-4-7-077`: Once this process of parameter negotiation is completed, thi......
  - Tests: test_rfc9174_4_7_077_no_parameter_renegotiation
  - Note: Test establishes session and verifies send_session_init() fails in Established state, demonstrating 

### RFC 9174 §4.8

**Covered:** 4

- `RFC9174-4-8-078`: Session Extension Items Each of the Session Extension Items ......
  - Tests: test_rfc9174_4_8_078_extension_encoded_as_tlv, test_rfc9174_4_8_078_tlv_roundtrip
  - Note: Tests verify ExtensionItem::encode() produces TLV format: flags(1) | type(2) | length(2) | value(n).
- `RFC9174-4-8-079`: All reserved header flag bits SHALL be set to 0 by the sende......
  - Tests: test_rfc9174_4_8_079_reserved_flags_zero_by_sender
  - Note: Test verifies ExtensionItem::new() sets only bit 0 (CRITICAL) when creating extensions, leaving rese
- `RFC9174-4-8-081`: All reserved header flag bits SHALL be ignored by the receiv......
  - Tests: test_rfc9174_4_8_081_reserved_flags_ignored_by_receiver
  - Note: Test artificially sets reserved flag bits 2 and 5 in encoded extension, then calls ExtensionItem::de
- `RFC9174-4-8-082`: If a TCPCL entity receives a Session Extension Item with an ......
  - Tests: test_rfc9174_4_8_082_critical_extension_termination
  - Note: Peer sends SESS_INIT with unknown critical extension (type 0xFFFF, critical flag set). Verifies proc

### RFC 9174 §5.1.1

**Covered:** 6

- `RFC9174-5-1-1-084`: For shared network use, entities SHOULD choose a Keepalive I......
  - Tests: test_rfc9174_5_1_1_084_sess_init_clamps_below_30
  - Note: SessionConfig keepalive_interval=10 is clamped to 30; send_session_init encode() bytes [1..2] are 30
- `RFC9174-5-1-1-085`: Entities SHOULD choose a Keepalive Interval no longer than 1......
  - Tests: test_rfc9174_5_1_1_085_sess_init_clamps_above_600
  - Note: keepalive_interval=900 clamped to 600; SESS_INIT wire keepalive field is 600. Would FAIL if values >
- `RFC9174-5-1-1-086`: The chosen Keepalive Interval SHOULD NOT be too short, as TC......
  - Tests: test_rfc9174_5_1_1_086_sess_init_rejects_too_short_via_clamp
  - Note: keepalive_interval=1 clamped; SESS_INIT keepalive bytes >=30. Would FAIL if a too-short interval wer
- `RFC9174-5-1-1-088`: Both sides SHALL send a KEEPALIVE message whenever the negot......
  - Tests: test_rfc9174_5_1_1_088_keepalive_timing
  - Note: Session established with 10-second keepalive. record_send at time 0, poll at 9000ms returns None, po
- `RFC9174-5-1-1-089`: If the entity has not received any TCPCL messages during the......
  - Tests: test_rfc9174_5_1_1_089_idle_timeout
  - Note: Session established with 10-second keepalive. record_receive at time 0, poll at 20000ms (2× keepaliv
- `RFC9174-5-1-1-090`: If configurable, the idle timeout duration SHOULD be no shor......
  - Tests: test_rfc9174_5_1_1_090_091_idle_timeout_recommendation
  - Note: Test establishes session with 30s keepalive, records receive time, advances clock to verify no timeo

### RFC 9174 §5.1.2

**Covered:** 2

- `RFC9174-5-1-2-092`: (possibly due to an unhandled protocol version mismatch or an incorrec...
  - Tests: test_rfc9174_5_1_2_092_msg_reject_unknown_type
  - Note: Session calls process_raw_message_type(0xFF) for unknown message type. Verifies return is MSG_REJECT
- `RFC9174-5-1-2-093`: An entity that receives a message type that is known but is ......
  - Tests: test_rfc9174_5_1_2_093_094_msg_reject_inappropriate_message
  - Note: Test sends SESS_INIT to Established session (inappropriate for current state) and verifies process_s

### RFC 9174 §5.2

**Covered:** 3

- `RFC9174-5-2-095`: The choice of the length to use for segments is an implement......
  - Tests: test_rfc9174_5_2_2_segments_respect_peer_mru
  - Note: Segments respect peer MRU test (duplicate of 067)
- `RFC9174-5-2-097`: A single transfer (and, by extension, a single segment) SHAL......
  - Tests: test_rfc9174_5_2_single_transfer_single_bundle
  - Note: Single transfer single bundle test
- `RFC9174-5-2-099`: If multiple bundles are transmitted on a single TCPCL connec......
  - Tests: test_rfc9174_5_2_multiple_bundles_transmitted_consecutively
  - Note: Multiple bundles transmitted consecutively test

### RFC 9174 §5.2.1

**Covered:** 3

- `RFC9174-5-2-1-100`: Transfer IDs from each entity SHALL be unique within a singl......
  - Tests: test_rfc9174_5_2_1_transfer_id_uniqueness
  - Note: Transfer ID uniqueness test
- `RFC9174-5-2-1-102`: For bidirectional bundle transfers, a TCPCL entity SHOULD NO......
  - Tests: test_rfc9174_5_2_1_102_transfer_ids_independent
  - Note: Test starts bidirectional transfers and verifies both Active and Passive use independent Transfer ID
- `RFC9174-5-2-1-104`: values or the ordering of Transfer IDs (see Section 7.13), in the abse...
  - Tests: test_rfc9174_5_2_1_104_initial_transfer_id_one
  - Note: Test starts three transfers and verifies IDs are 1, 2, 3, demonstrating implementation follows RFC 9

### RFC 9174 §5.2.2

**Covered:** 4

- `RFC9174-5-2-2-107`: The Transfer Extension Items Length and Transfer Extension I......
  - Tests: test_rfc9174_5_2_2_107_ignore_reserved_xfer_segment_flags
  - Note: Test artificially sets reserved flag bit 5 in XFER_SEGMENT, calls process_segment(), verifies succes
- `RFC9174-5-2-2-108`: The START flag SHALL be set to 1 when transmitting the first......
  - Tests: test_rfc9174_5_2_2_108_start_end_flags
  - Note: Multi-segment transfer (2500 bytes, 1000-byte MRU). First segment verified with START flag (0x02), l
- `RFC9174-5-2-2-110`: The END flag SHALL be set to 1 when transmitting the last se......
  - Tests: test_rfc9174_5_2_2_xfer_segment_start_end_flags
  - Note: XFER_SEGMENT start/end flags test (another)
- `RFC9174-5-2-2-111`: Once a transfer of a bundle has commenced, the entity MUST o......
  - Tests: test_rfc9174_5_2_2_segments_contain_sequential_portions
  - Note: Segments contain sequential portions test

### RFC 9174 §5.2.3

**Covered:** 2

- `RFC9174-5-2-3-114`: A receiving TCPCL entity SHALL send a XFER_ACK message in re......
  - Tests: test_rfc9174_5_2_3_114_xfer_ack_cumulative
  - Note: Segment 1 (100 bytes) processed, ACK returned with acked_length=100. Segment 2 (50 bytes) processed,
- `RFC9174-5-2-3-116`: The sending entity SHOULD transmit multiple XFER_SEGMENT mes......
  - Tests: test_rfc9174_5_2_3_pipelined_segments
  - Note: Pipelined segments test

### RFC 9174 §5.2.4

**Covered:** 9

- `RFC9174-5-2-4-117`: As data segments and acknowledgments can cross on the wire, ......
  - Tests: test_rfc9174_5_2_4_refuse_identified_by_transfer_id
  - Note: XFER_REFUSE immediate test
- `RFC9174-5-2-4-118`: The transfer sender MUST be prepared for this and MUST assoc......
  - Tests: test_rfc9174_5_2_4_118_sender_handles_refusal
  - Note: Test starts transfer, calls process_refuse() with Transfer ID and reason code, verifies sender handl
- `RFC9174-5-2-4-120`: If a transfer refusal has a reason code that is not decodabl......
  - Tests: test_rfc9174_5_2_4_120_unknown_refuse_reason_normalized, test_rfc9174_5_2_4_120_valid_refuse_reasons_unchanged
  - Note: Tests verify: (1) process_refuse() with invalid reason codes (0x06, 0x07, 0xFF) normalizes to 0x00 i
- `RFC9174-5-2-4-121`: | | Resources | | The sender SHOULD apply reactive bundle | ......
  - Tests: test_rfc9174_5_2_4_121_no_resources_reactive_fragment_retry
  - Note: After send+poll queues one non-fragment, notify_cla_transfer_refused(NO_RESOURCES) requeues multiple
- `RFC9174-5-2-4-122`: | | | | The sender SHOULD NOT retry the same | | | | bundle ......
  - Tests: test_rfc9174_5_2_4_122_not_acceptable_blocks_same_retry
  - Note: After NOT_ACCEPTABLE, re-dispatching the same stored bundle yields empty cla_tx_queue; a different c
- `RFC9174-5-2-4-124`: | +-------------+------+------------------------------------......
  - Tests: test_rfc9174_5_2_4_124_refuse_ordering_violation, test_rfc9174_5_2_4_124_refuse_after_completion, test_rfc9174_5_2_4_124_refuse_after_earlier_refused (+ 1 more)
  - Note: RFC 9174 §5.2.4: "The receiver MUST, for each transfer preceding the one to be refused, have either 
- `RFC9174-5-2-4-125`: If a sender receives a XFER_REFUSE message, the sender MUST ......
  - Tests: test_rfc9174_5_2_4_sender_completes_partial_segment
  - Note: Transfer state management test
- `RFC9174-5-2-4-127`: The sender MUST NOT subsequently commence transmission of an......
  - Tests: test_rfc9174_5_2_4_sender_stops_after_refuse
  - Note: Bundle data transmission test
- `RFC9174-5-2-4-128`: will not receive another XFER_SEGMENT for the same bundle after transm...
  - Tests: test_rfc9174_128_segments_after_refuse
  - Note: RFC 9174 §5.2.4: "After sending a XFER_REFUSE, the recipient will not receive another XFER_SEGMENT f

### RFC 9174 §5.2.5

**Covered:** 2

- `RFC9174-5-2-5-129`: Transfer Extension Items Each of the Transfer Extension Item......
  - Tests: test_rfc9174_5_2_5_129_transfer_extension_tlv_encoding
  - Note: Test verifies ExtensionItem::encode() produces TLV format (flags|type|length|value) for transfer ext
- `RFC9174-5-2-5-133`: If a TCPCL entity receives a Transfer Extension Item with an......
  - Tests: test_rfc9174_5_2_5_133_unknown_critical_extension_refused
  - Note: Test verifies process_segment() generates XFER_REFUSE with Extension Failure reason when receiving u

### RFC 9174 §5.2.5.1

**Covered:** 5

- `RFC9174-5-2-5-1-135`: Multiple Transfer Length Extension Items SHALL NOT occur wit......
  - Tests: test_rfc9174_5_2_5_1_135_no_duplicate_transfer_length
  - Note: Creates single Transfer Length Extension (type 0x0001), verifies count=1. Tests duplicate detection 
- `RFC9174-5-2-5-1-139`: The lack of a Transfer Length Extension Item in any transfer......
  - Tests: test_rfc9174_5_2_5_1_139_no_length_extension_accepts_any_length, test_rfc9174_5_2_5_1_139_receiver_accepts_without_length_extension
  - Note: Tests verify that absence of Transfer Length Extension does not imply anything about transfer length
- `RFC9174-5-2-5-1-140`: If a transfer occupies exactly one segment (i.e., both the S......
  - Tests: test_rfc9174_5_2_5_1_140_single_segment_should_not_have_length
  - Note: Test verifies create_segments() does not add Transfer Length Extension to single-segment transfers (
- `RFC9174-5-2-5-1-142`: The Total Length field SHALL be treated as authoritative by ......
  - Tests: test_rfc9174_5_2_5_1_transfer_length_authoritative
  - Note: Extension item test
- `RFC9174-5-2-5-1-143`: If a Transfer Length Extension is present in a transfer, the......
  - Tests: test_rfc9174_5_2_5_1_143_transfer_length_equals_bundle_size
  - Note: Test creates multi-segment transfer and verifies Transfer Length Extension Total Bundle Length field

### RFC 9174 §6.1

**Covered:** 12

- `RFC9174-6-1-144`: Session Termination Message (SESS_TERM) To cleanly terminate......
  - Tests: test_rfc9174_6_1_144_sess_term_sent_for_clean_termination
  - Note: Contact flags encoding test
- `RFC9174-6-1-145`: When sent to initiate a termination, the REPLY flag of a SES......
  - Tests: test_rfc9174_6_1_initiating_term_reply_flag_zero
  - Note: Contact flags encoding test
- `RFC9174-6-1-147`: Upon receiving a SESS_TERM message after not sending a SESS_......
  - Tests: test_rfc9174_6_1_acknowledging_term_reply_flag_set
  - Note: Contact flags encoding test
- `RFC9174-6-1-148`: * an entity SHALL NOT begin any new outgoing transfer for th......
  - Tests: test_rfc9174_6_1_148_no_new_outgoing_after_term
  - Note: Session established, send_session_term called (state becomes Ending). Attempts start_transfer return
- `RFC9174-6-1-150`: * an entity SHALL NOT accept any new incoming transfer for t......
  - Tests: test_rfc9174_6_1_150_no_new_incoming_after_term
  - Note: Session established, process_session_term called (state becomes Ending). Attempt to process_segment 
- `RFC9174-6-1-152`: If a new incoming transfer is attempted while in the Ending ......
  - Tests: test_rfc9174_6_1_152_refuse_with_session_terminating
  - Note: Transfer MRU encoding test
- `RFC9174-6-1-153`: When performing an unclean termination, an entity SHOULD ack......
  - Tests: test_rfc9174_6_1_153_ack_segments_before_unclean_termination, test_rfc9174_6_1_153_acknowledge_all_segments, test_rfc9174_6_1_153_unclean_vs_clean_termination (+ 1 more)
  - Note: Tests verify: (1) process_segment() generates XFER_ACK responses that integrator can send before unc
- `RFC9174-6-1-154`: Each SESS_TERM message SHALL contain a one-octet Reason Code......
  - Tests: test_rfc9174_6_1_154_sess_term_contains_reason_code
  - Note: Node ID encoding test
- `RFC9174-6-1-155`: If a termination has a reason code that is not decodable to ......
  - Tests: test_rfc9174_6_1_155_unknown_term_reason_normalized, test_rfc9174_6_1_155_various_invalid_reasons, test_rfc9174_6_1_155_valid_term_reasons_unchanged
  - Note: Tests verify: (1) process_session_term() with invalid reason 0xFF generates reply SESS_TERM with nor
- `RFC9174-6-1-158`: However, an entity MUST always send the Contact Header to it......
  - Tests: test_rfc9174_158_contact_before_sess_term
  - Note: RFC 9174 §6.1: "However, an entity MUST always send the Contact Header to its peer before sending a 
- `RFC9174-6-1-159`: If reception of the Contact Header itself somehow fails (e.g......
  - Tests: test_rfc9174_6_1_159_terminate_on_contact_failure
  - Note: SESS_TERM reason encoding test
- `RFC9174-6-1-160`: If a session is to be terminated before the sending of a pro......
  - Tests: test_rfc9174_6_1_160_abort_mid_message_no_sess_term_but_close, test_rfc9174_6_1_160_close_always_uses_fin
  - Note: abort_mid_message clears outbound SESS_TERM, sets Terminated, closes VirtualStream with Fin and does

### RFC 9758 §3

**Covered:** 1

- `RFC9758-001`: representation or a binary encoding, MUST be considered as a......
  - Tests: test_rfc9758_001_tuple_equivalence_across_forms
  - Note: Tuple equivalence per RFC 9758 §3. Test verifies 2-element, 3-element text forms and CBOR all decode

### RFC 9758 §3.3

**Covered:** 1

- `RFC9758-007`: All Node Number assignments, by all Allocators, MUST be in t......
  - Tests: test_rfc9758_007_text_parse_rejects_node_exceeds_u32_max, test_rfc9758_007_text_parse_rejects_service_exceeds_u32_max, test_rfc9758_007_text_parse_rejects_three_element_node_exceeds_u32_max (+ 2 more)
  - Note: SDK validates node and service numbers are ≤ u32::MAX in both text parse (EndpointId::parse) and CBO

### RFC 9758 §3.4.1

**Covered:** 2

- `RFC9758-009`: Such ipn URIs MUST NOT be composed, and processors of such i......
  - Tests: test_rfc9758_3_4_1_zero_node_number_invalid
  - Note: SDK fix implemented in commit e84122b. EndpointId::ipn() now rejects allocator=0, node=0, service!=0
- `RFC9758-010`: ipn URIs MUST consider them as the Null ipn URI....
  - Tests: test_rfc9758_010_node_zero_as_null
  - Note: Node zero as null test

### RFC 9758 §3.4.3

**Covered:** 1

- `RFC9758-011`: domains MUST have suitable mechanisms in place to prevent pr......
  - Tests: test_rfc9758_011_030_private_use_within_domain, test_rfc9758_011_030_private_use_blocked_across_boundary
  - Note: Production-path tests via receive_from_cla() -> poll() verify: (1) Private Use forwarded within conf

### RFC 9758 §4

**Covered:** 2

- `RFC9758-012`: All leading '0' characters MUST be omitted....
  - Tests: test_rfc9758_012_leading_zeros_rejected, test_rfc9758_012_013_display_omits_leading_zeros_and_allocator
  - Note: Leading zeros rejected test
- `RFC9758-014`: then the character '!' SHOULD be used instead of the digits ......
  - Tests: test_rfc9758_014_parse_wildcard_node, test_rfc9758_014_parse_wildcard_service, test_rfc9758_014_parse_wildcard_three_element (+ 4 more)
  - Note: SDK implements '!' wildcard per RFC 9758 §4. parse_number() helper accepts '!' as u32::MAX (42949672

### RFC 9758 §4.1

**Covered:** 1

- `RFC9758-015`: The text syntax of an ipn URI MUST comply with the following......
  - Tests: test_rfc9758_015_abnf_syntax_valid_formats, test_rfc9758_015_abnf_syntax_reject_invalid, test_rfc9758_015_numeric_range_validation (+ 1 more)
  - Note: IPN URI parsing validates ABNF syntax per RFC 9758 §4. Tests verify valid formats accepted and inval

### RFC 9758 §5

**Covered:** 1

- `RFC9758-016`: scheme URIs that MUST be followed when using this URI scheme......
  - Tests: test_rfc9758_017_018_ipn_eid_singleton_fqnn_member, test_rfc9758_041_three_element_encoding_exact_bytes, test_rfc9758_027_localnode_not_in_peer_discovery
  - Note: Covered by the §5 constraint suite: singleton FQNN membership, CBOR encoding rules, and LocalNode di

### RFC 9758 §5.1

**Covered:** 4

- `RFC9758-017`: An ipn EID MUST identify a singleton endpoint. The bundle pr......
  - Tests: test_rfc9758_017_018_ipn_eid_singleton_fqnn_member
  - Note: NodeId::from_endpoint maps distinct services on the same FQNN to one NodeId and different FQNNs to d
- `RFC9758-018`: node that is the sole member of that endpoint MUST be the no......
  - Tests: test_rfc9758_017_018_ipn_eid_singleton_fqnn_member
  - Note: Same FQNN → same NodeId sole member. Would FAIL if FQNN did not determine the node.
- `RFC9758-020`: However, all ipn EIDs that share any single FQNN MUST refer ......
  - Tests: test_rfc9758_020_shared_fqnn_node_behavior
  - Note: Node-level test per RFC 9758 §5.1. BundleAgent.is_local_destination() returns true for all EIDs shar
- `RFC9758-021`: MUST all refer to services registered on the bundle processi......
  - Tests: test_rfc9758_021_fqnn_977000_100_services_same_node
  - Note: Services 1,2,3 on FQNN (977000,100) all resolve to NodeId::ipn(977000,100). Would FAIL if any mapped

### RFC 9758 §5.4

**Covered:** 7

- `RFC9758-022`: node, any such EID MUST be considered non-routable. This mea......
  - Tests: test_rfc9758_022_023_localnode_source_dest_blocked
  - Note: Production path test: receive_from_cla rejects bundles with LocalNode source or destination. Verifie
- `RFC9758-023`: destination MUST NOT be allowed to leave the local node....
  - Tests: test_rfc9758_022_023_localnode_source_dest_blocked
  - Note: Production path test: receive_from_cla rejects bundles with LocalNode source or destination. Verifie
- `RFC9758-024`: source or bundle destination MUST be discarded as invalid. L......
  - Tests: test_rfc9758_024_025_localnode_report_to_blocked
  - Note: Production path test: receive_from_cla rejects bundles with LocalNode in report-to field. Verifies e
- `RFC9758-025`: LocalNode ipn EIDs MUST NOT be present in any other part of ......
  - Tests: test_rfc9758_024_025_localnode_report_to_blocked
  - Note: Production path test: receive_from_cla rejects bundles with LocalNode in report-to field. Verifies e
- `RFC9758-026`: ipn EID MUST NOT be used as a Bundle Protocol Security (BPSe......
  - Tests: test_rfc9758_5_4_localnode_rejected_as_bib_source
  - Note: Localnode rejected as BIB source test
- `RFC9758-027`: LocalNode ipn EIDs MUST NOT be published in any node identif......
  - Tests: test_rfc9758_027_localnode_not_in_peer_discovery
  - Note: set_neighbor_domain(LocalNode) returns Err. Would FAIL if LocalNode were accepted into the discovery
- `RFC9758-028`: For example, a LocalNode ipn EID MUST NOT be advertised as t......
  - Tests: test_rfc9758_028_localnode_tcpcl_node_id_rejected
  - Note: Production path test: TcpclSession::new rejects LocalNode peer Node ID during session negotiation. V

### RFC 9758 §5.5

**Covered:** 4

- `RFC9758-029`: source or bundle destination MUST NOT be allowed to cross ad......
  - Tests: test_rfc9758_029_031_private_use_blocked
  - Note: RFC 9758 §5.5: Private Use source/destination MUST NOT cross domains. Test creates bundles with Priv
- `RFC9758-030`: as a gateway between administrative domains MUST be sufficie......
  - Tests: test_rfc9758_030_configurability
  - Note: Configurability test via production path verifies three scenarios: (1) administrative_domain=None bl
- `RFC9758-031`: Private Use ipn EIDs MUST NOT be present in any other part o......
  - Tests: test_rfc9758_029_031_private_use_blocked
  - Note: Production path test: receive_from_cla rejects bundles with Private Use EID in report-to when admini
- `RFC9758-032`: Private Use ipn EID MUST NOT be used as a BPSec [RFC9172] se......
  - Tests: test_rfc9758_5_5_private_use_rejected_as_bib_source
  - Note: Private use rejected as BIB source test

### RFC 9758 §5.7

**Covered:** 2

- `RFC9758-033`: The service identified by a Service Number of zero (0) MUST ......
  - Tests: test_rfc9758_6_3_service_zero_administrative
  - Note: Service zero administrative test
- `RFC9758-034`: Non-zero Service Numbers MUST NOT be used to identify the Ad......
  - Tests: test_rfc9758_6_3_nonzero_service_not_administrative
  - Note: Nonzero service not administrative test

### RFC 9758 §6.1

**Covered:** 2

- `RFC9758-036`: with BPv7, the scheme-specific part of an ipn URI MUST be re......
  - Tests: test_rfc9758_036_cbor_array_encoding
  - Note: CBOR encoding verified with exact byte sequences per RFC 9758 §6.1. Test checks 2-element [100,1] = 
- `RFC9758-037`: element of the array MUST be encoded as a single CBOR unsign......
  - Tests: test_rfc9758_037_cbor_unsigned_integer_encoding
  - Note: CBOR codec encodes IPN EID components as unsigned integers per RFC 9758 §6. Test verifies round-trip

### RFC 9758 §6.1.1

**Covered:** 3

- `RFC9758-038`: The FQNN encoding MUST be a 64-bit unsigned integer construc......
  - Tests: test_rfc9758_6_1_1_fqnn_packing
  - Note: FQNN packing test
- `RFC9758-039`: The least significant 32 bits MUST represent the Node Number......
  - Tests: test_rfc9758_6_1_1_fqnn_packing
  - Note: FQNN packing test
- `RFC9758-040`: The most significant 32 bits MUST represent the Allocator Id......
  - Tests: test_rfc9758_6_1_1_fqnn_packing
  - Note: FQNN packing test

### RFC 9758 §6.1.2

**Covered:** 2

- `RFC9758-041`: Identifiers, and implementations are RECOMMENDED to use this......
  - Tests: test_rfc9758_041_three_element_encoding_exact_bytes
  - Note: BundleCodec::encode of ipn:977000.100.1 emits CBOR 83 1A 000EE868 … three-element SSP. Would FAIL if
- `RFC9758-042`: concise CBOR representation; therefore, it is RECOMMENDED th......
  - Tests: test_rfc9758_042_default_allocator_two_element_encoding
  - Note: Default-allocator encode uses 82 02 82 (two-element SSP). Would FAIL if three-element [0,node,servic

### RFC 9758 §6.3

**Covered:** 1

- `RFC9758-043`: URI MUST comply with the following Concise Data Definition L......
  - Tests: test_rfc9758_043_cbor_cddl_compliance
  - Note: Test verifies CBOR encoding produces exact CDDL-compliant structure [2, [uint, uint]] for 2-element 

### RFC 9758 §6.4

**Covered:** 3

- `RFC9758-044`: specific encoding is used, ipn EID matching MUST be performe......
  - Tests: test_rfc9758_044_eid_matching_decoded_equivalence, test_rfc9758_044_eid_matching_different_values
  - Note: EID matching performed on decoded information per RFC 9758 §6.4. Tests verify equivalent representat
- `RFC9758-045`: EID MUST be treated as equivalent when performing EID-specif......
  - Tests: test_rfc9758_6_4_eid_matching_encoding_equivalence
  - Note: EID matching encoding equivalence test
- `RFC9758-046`: differently, any EID-based comparisons MUST treat these valu......
  - Tests: test_rfc9758_046_comparison_equivalence
  - Note: EID comparison treats equivalent encodings the same per RFC 9758 §6.4. Test verifies text/direct con

### RFC 9758 §7.1

**Covered:** 2

- `RFC9758-047`: which support of this update is desired MUST be updated to b......
  - Tests: test_rfc9758_047_non_default_allocator_processing
  - Note: Test verifies SDK correctly encodes and decodes non-default allocator identifiers (allocator ≠ 0) us
- `RFC9758-048`: It is RECOMMENDED that BPv7 implementations upgrade to proce......
  - Tests: test_rfc9758_048_receive_three_element_encoding
  - Note: receive_bytes_from_cla accepts a bundle whose source uses three-element non-default allocator encodi

### RFC 9758 §7.5

**Covered:** 1

- `RFC9758-051`: Elements of an ipn URI MUST NOT be regarded as carrying info......
  - Tests: test_rfc9758_051_ipn_elements_not_used_as_addresses
  - Note: Static routes match full EID/FQNN: dest ipn:2.42.0 is not forwarded via route for ipn:1.42.0 despite
