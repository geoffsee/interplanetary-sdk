# RFC 9171 Implementation Gaps - Detailed Analysis

**Date:** 2026-11-09  
**Charter:** §3 standards compliance

## 1. CRC Validation (§4.2.1)

### Current State
- ✅ CRC computation implemented (`Crc::crc16`, `Crc::crc32c`)
- ✅ `CrcType` enum (None=0, Crc16=1, Crc32=2)
- ✅ Fields in `PrimaryBlock` and `CanonicalBlock`
- ❌ **NOT validated during encode/decode**

### Required
Per RFC 9171 §4.2.1:
> "The CRC Type field of a block identifies which CRC type to use... If the CRC Type of a received block is 0, then the block has no CRC and all CRC processing MUST be skipped."

**Missing:**
1. During **encode**: compute CRC over serialized block (excluding CRC field itself), append CRC value
2. During **decode**: verify CRC matches (if CRC type ≠ 0), reject bundle on mismatch
3. **CRC-type 0 eligibility rules**: When CRC may be omitted (local policy or when link-layer provides integrity)

### Implementation Plan
- Add `compute_and_append_crc()` to encoder
- Add `verify_crc()` to decoder (before returning decoded block)
- Add test coverage for CRC validation failures

---

## 2. Proactive Fragmentation (§5.4)

### Current State
- ✅ `fragment_bundle()` function exists in `../../../src/bp/fragment.rs`
- ✅ Primary block has `fragment_offset` and `total_app_data_length` fields
- ✅ Basic splitting implemented

### Required
Per RFC 9171 §5.4:
> "The size of each fragment's payload is computed by the BPA... Fragment offset and total application data unit length MUST be present in the primary block."

**Status:** ✅ **IMPLEMENTED** (basic fragmentation working)

**Enhancement needed:** Replicate blocks with `REPLICATE_IN_FRAGMENTS` flag (partially implemented).

---

## 3. Reassembly with Conflict Detection (§5.7)

### Current State
- ✅ `ReassemblyManager` exists
- ✅ Memory limits enforced
- ❌ **NO conflict detection** (overlapping ranges with different data)
- ❌ **NO quarantine mechanism**

### Required
Per RFC 9171 §5.7:
> "If... a received fragment overlaps one or more fragments previously received (in byte ranges) AND the data in the overlapping fragments is NOT IDENTICAL, then the bundle whose reassembly is being attempted MUST be abandoned."

**Missing:**
1. On `add_fragment()`: check if new fragment's byte range `[offset, offset+len)` overlaps existing fragment
2. If overlap detected: compare byte-by-byte
3. If conflict (data differs): **quarantine** bundle ID, reject all future fragments
4. Return explicit error variant: `Error::FragmentConflict`

---

## 4. Expiry and Storage Release (§5.7, §5.8)

### Current State
- ✅ `expiry_time` tracked per reassembly state
- ✅ `expire_old_fragments()` function exists
- ❌ Not called automatically (manual cleanup only)

### Required
Per RFC 9171 §5.8:
> "If the reassembly buffer for the bundle... has not been completed by the earliest expiry time... the buffer MUST be discarded."

**Status:** ✅ **Mostly Implemented** (just needs to be called periodically by BPA)

---

## 5. RFC 9172 §5.2 Constraint (BPSec + Fragments)

### Current State
- ❌ **NO enforcement**

### Required
Per RFC 9172 §5.2:
> "Security operations MUST NOT be performed on fragments. Security blocks MUST NOT be added to bundles that already have fragmentation information."

**Missing:**
1. When adding BIB/BCB to a bundle: check `primary.is_fragment()`
2. If fragment: return `Error::SecurityOperationOnFragment`
3. Add test: attempt to add BIB to fragmented bundle, expect rejection

---

## 6. CRC-Type 0 Eligibility Rules

### Current State
- ✅ CRC-type 0 parsed/encoded
- ❌ No policy guidance on when to use

### Required
Per RFC 9171 §4.2.1:
> "An implementation MAY choose to not compute CRC on a block... if the underlying convergence layer provides integrity protection."

**Policy needed:**
- Default: use CRC-16 or CRC-32
- CRC-0 only when:
  - Local loopback
  - Convergence layer guarantees integrity (TCPCLv4 has its own checksums)
  - Explicitly configured by policy

**Status:** Low priority (encoding/decoding works, just policy question)

---

## Implementation Priority

1. **High:** CRC validation during decode (security/integrity)
2. **High:** Conflict detection + quarantine (correctness)
3. **Medium:** RFC 9172 §5.2 constraint (security compliance)
4. **Low:** CRC-type 0 policy (operational, not correctness)

---

## Tests Needed

1. `test_crc_validation_primary_block`
2. `test_crc_validation_canonical_block`
3. `test_crc_mismatch_rejects_bundle`
4. `test_fragment_conflict_detection`
5. `test_fragment_quarantine`
6. `test_bpsec_on_fragment_rejected`
