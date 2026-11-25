# ADR 004: RFC 9758 IPN EID Encoding

## Status

Accepted

## Context

RFC 9758 defines two CBOR encoding schemes for IPN (Interplanetary Network) endpoint identifiers (EIDs) in Bundle Protocol v7. The choice of encoding affects both wire efficiency and interoperability with legacy implementations.

### Background

An IPN EID consists of three components:
- **Allocator Identifier**: Identifies the organization that assigned the node number (32-bit)
- **Node Number**: Identifies a specific node within the allocator's namespace (32-bit)
- **Service Number**: Identifies a service on that node (unsigned integer, typically small)

The Default Allocator uses Allocator Identifier 0.

## Decision

We implement both encoding schemes per RFC 9758 §6.1-6.2:

### Two-Element Encoding: `[FQNN, service]`

Used when **allocator = 0** (Default Allocator).

**Encoding:**
```
FQNN = (allocator << 32) | node_number
array = [FQNN, service]
```

**Rationale:** More concise for Default Allocator (most common case). For allocator=0, the FQNN is simply the node number, avoiding redundant encoding of the zero allocator.

**Example:** `ipn:1.2` (implicitly allocator=0, node=1, service=2)
```
82              # array[2] (outer EID structure)
  02            # scheme code 2 (ipn)
  82            # array[2] (two-element SSP)
    01          # FQNN = 1
    02          # service = 2
```

### Three-Element Encoding: `[allocator, node, service]`

Used when **allocator ≠ 0**.

**Encoding:**
```
array = [allocator, node, service]
```

**Rationale:** More efficient for non-default allocators with small values. Avoids encoding large FQNN values when allocator is small.

**Example:** `ipn:977000.100.1`
```
82              # array[2] (outer EID structure)
  02            # scheme code 2 (ipn)
  83            # array[3] (three-element SSP)
    1A 000EE868 # allocator = 977000
    64          # node = 100
    01          # service = 1
```

### Decoding

Per RFC 9758 §6.2, decoders **MUST accept both forms**:

```rust
if ssp_array.len() == 3 {
    // Three-element: extract directly
    allocator = ssp_array[0];
    node = ssp_array[1];
    service = ssp_array[2];
} else if ssp_array.len() == 2 {
    // Two-element: extract from FQNN
    fqnn = ssp_array[0];
    allocator = fqnn >> 32;
    node = fqnn & 0xFFFFFFFF;
    service = ssp_array[1];
}
```

### EID Matching

Per RFC 9758 §6.4, different encodings of the same IPN EID **MUST be treated as equivalent**. For example:
- Two-element: `0x821B000EE8680000006401`
- Three-element: `0x831A000EE868186401`

Both represent `ipn:977000.100.1` and must match as equal during EID comparison.

## RFC Citation

From RFC 9758 §6.1.1:

> The two-element scheme-specific encoding provides backwards compatibility with the encoding provided in Section 4.2.5.1.2 of [RFC9171]. When used in this way, the encoding of the FQNN replaces the use of the Node Number that was specified in [RFC9171]. When the Node Number is allocated by the Default Allocator (Section 3.2.2), the encoding of the FQNN and the encoding of the Node Number from [RFC9171] are identical.

From RFC 9758 §6.1.2:

> The three-element scheme-specific encoding allows for a more efficient representation of ipn EIDs using smaller Allocator Identifiers, and implementations are RECOMMENDED to use this encoding scheme unless explicitly mitigating for interoperability issues; see Section 7.1.
>
> When encoding an ipn EID using the Default Allocator (Section 3.2.2) with this encoding scheme, the first element of the array is the value zero (0). In this case, using the equivalent two-element scheme-specific encoding (Section 6.1.1) will result in a more concise CBOR representation; therefore, it is RECOMMENDED that implementations use that encoding instead.

## Implementation

- **Encoder** (`BundleCodec::encode_eid_cbor`): Chooses encoding based on allocator value
- **Decoder** (`BundleCodec::decode_eid`): Accepts both forms
- **Tests**: Verify both encoding forms decode correctly and compare equal

## Consequences

### Positive

- Complies with RFC 9758 recommendations for efficiency
- Maintains backward compatibility with RFC 9171
- Smaller wire representation for Default Allocator (most common)
- Efficient encoding for non-default allocators

### Negative

- Two code paths for encoding/decoding
- EID comparison must be semantic, not byte-exact
- BPSec canonical forms must account for encoding choice

### Testing Requirements

1. Round-trip tests for both encoding forms
2. EID equivalence tests (same logical EID, different encodings)
3. RFC 9173 test vectors use Default Allocator → expect two-element encoding
4. Boundary tests: allocator=0 vs allocator=1, large allocators, large nodes

## References

- [RFC 9758: Updated IANA Registry Rules for Bundle Protocol](https://www.rfc-editor.org/rfc/rfc9758.html)
- [RFC 9171: Bundle Protocol Version 7](https://www.rfc-editor.org/rfc/rfc9171.html)
- RFC 9173 Appendix A test vectors (use allocator=0)
- ADR 003: Shortest-Form CBOR Encoding
