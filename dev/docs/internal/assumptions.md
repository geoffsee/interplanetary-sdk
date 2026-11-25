# Implementation Assumptions and Interpretations

This document records design decisions where RFC specifications leave room for interpretation or where we make explicit choices about strictness vs. compatibility.

---

## CRC Type 0 Acceptance on Receive

**Decision:** Accept primary blocks with CRC type 0 on decode, but reject on generation unless a BIB targets the primary block.

**Rationale:**

RFC 9171 §4.3.1 states:

> "The CRC type code for the primary block MAY be zero if the bundle contains a BPSec Block Integrity Block [BPSEC] whose target is the primary block; otherwise, the CRC type code for the primary block MUST be non-zero."

This is phrased as a generation rule ("MAY be zero if...otherwise MUST be non-zero"), not a validation rule. The RFC does not explicitly mandate rejecting received bundles that violate this rule.

**Implementation:**

- **On generation** (`validate_at_generation`): Enforce the MUST by returning an error if CRC type is 0 and no BIB targets the primary block
- **On decode** (`BundleCodec::decode`): Accept CRC type 0 regardless of BIB presence for compatibility with:
  - RFC 9173 test vectors (which predate RFC 9171 finalization)
  - Implementations that interpret the rule differently
  - Historical bundles that may not have been generated with this constraint

**Evidence:**

- Generation enforcement: `src/bp/processing.rs:validate_at_generation()`
- Decode acceptance: `src/bp/codec.rs:decode()` (no rejection of CRC type 0)
- Tests: `bp::processing::tests::test_primary_crc_type_zero_rejected_without_bib`

**Related:** GAP-009 (CRC implementation) in `../spec`

---

## Hop Count "Exceeds" Interpretation

**Decision:** "Exceeds" means strictly greater than (>), not greater than or equal to (>=).

**Rationale:**

RFC 9171 §4.4.3 states:

> "When a bundle's hop count exceeds its hop limit, the bundle SHOULD be deleted"

The word "exceeds" in English means "is greater than," not "is greater than or equal to." A hop count equal to the hop limit has not yet exceeded it.

**Implementation:**

- `HopCountBlock::is_exceeded()` returns `hop_count > hop_limit`
- A bundle with hop_limit=2 can successfully forward 2 times (reaching 3 nodes)
- The 3rd forward attempt (which would make hop_count=3) fails

**Evidence:**

- `src/bp/extensions.rs:is_exceeded()`
- `src/bp/processing.rs:process_on_forward()`
- Tests: `../../../tests/hop_limit_scenario.rs`

---

*Last updated: 2026-11-09*
