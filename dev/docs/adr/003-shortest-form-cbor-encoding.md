# ADR 003: Shortest-Form CBOR Encoding for Bundle Protocol

**Date:** 2026-11-09  
**Status:** Accepted  
**Related:** RFC 9171 §4.1, RFC 8949 §4.2.1, RFC 9173 §3 (canonical forms)

## Context

Bundle Protocol v7 uses CBOR encoding for wire format. BPSec signature and MAC operations require byte-exact canonical representations. Testing revealed that our encoder was generating bundles ~6 bytes larger than RFC 9173 examples due to non-shortest integer encoding.

**Problem discovered:** RFC A.1 generation test
- Expected (RFC): 165 bytes  
- Generated:  171 bytes (+6 bytes)
- Diff at byte 22: expected `0x18` (uint8), got `0x1a` (uint32)

**Root cause:** ciborium Value API was encoding small integers (e.g., 40) as uint32 instead of uint8.

## Decision

**Generation (encoding) must use shortest-form CBOR** per RFC 8949 §4.2.1:
- 0-23: Direct in type byte (no additional bytes)
- 24-255: uint8 format (0x18 + 1 byte)
- 256-65535: uint16 format (0x19 + 2 bytes)  
- 65536-4294967295: uint32 format (0x1a + 4 bytes)
- ≥2^32: uint64 format (0x1b + 8 bytes)

This applies to:
- Major type 0 (unsigned integers)
- Major type 2/3 length arguments (byte/text strings)
- Major type 4/5 length arguments (arrays/maps)

**Decoding must accept any conforming encoding** within limits (non-shortest forms are valid CBOR but not preferred).

### Implementation

Created `../../../src/bp/cbor_encoding.rs` with:
- `encode_uint(value: u64)` - shortest integer encoding
- `encode_bytes(bytes: &[u8])` - shortest byte string
- `encode_text(text: &str)` - shortest text string
- `encode_array_header(len: u64)` - shortest array header
- Boundary value tests (23/24, 255/256, 65535/65536, 2^32)

Replace `ciborium::Value` encoding in:
- `BundleCodec::encode_primary()` - primary block
- `BundleCodec::encode_canonical()` - canonical blocks
- Security IPPT/AAD construction (already manual)

## Consequences

### Positive
- ✅ Byte-exact reproduction of RFC examples
- ✅ BIB/BCB signatures will verify correctly
- ✅ Smaller bundle sizes (6 bytes saved on A.1 example)
- ✅ RFC 8949 conformance (preferred encoding)
- ✅ Explicit boundary value tests prevent regressions

### Negative
- ⚠️  Manual CBOR construction more verbose than Value API
- ⚠️  Must maintain consistency between encode/decode
- ⚠️  Two CBOR approaches in codebase (manual + ciborium decode)

### Risks Mitigated
- **Critical:** BPSec canonical forms must match byte-for-byte or signatures fail
- **Interop:** Other implementations may expect shortest form
- **Testability:** Exact byte comparison enables regression detection

## Alternatives Considered

1. **Configure ciborium** - No configuration option for preferred encoding
2. **Custom Value serializer** - Would need to wrap entire ciborium
3. **Accept non-shortest** - Violates BPSec canonical form requirements
4. **Different CBOR library** - High migration cost, same issue likely

## Verification

Encoder tests assert exact bytes for boundary values:
```rust
encode_uint(23) => [0x17]           // direct
encode_uint(24) => [0x18, 0x18]     // uint8
encode_uint(256) => [0x19, 0x01, 0x00]    // uint16
encode_uint(65536) => [0x1a, 0x00, 0x01, 0x00, 0x00]  // uint32
```

RFC generation tests verify byte-exact reproduction of:
- RFC 9173 A.1 (BIB with HMAC)
- RFC 9173 A.2 (BCB with AES-GCM)
- RFC 9173 A.3 (Multi-source BIB+BCB)

## References

- RFC 8949 §4.2.1: "Preferred Serialization"
- RFC 9171 §4.1: "Bundle Processing Control Flags" (CBOR encoding)
- RFC 9173 §3: "Canonical Forms" (requires exact byte sequences)
- Test: `../../../src/bp/cbor_encoding.rs` boundary value tests
- Test: `../../../tests/rfc9173_generation.rs` byte-exact RFC reproduction
