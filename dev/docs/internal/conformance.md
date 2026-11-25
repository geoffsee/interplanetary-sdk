# RFC Conformance Policy

## Scope

This implementation provides a **baseline TCPCLv4 model profile** for testing and research. Not all features of the full RFC specifications are implemented.

### Out of Scope Features

The following RFC obligations are marked as **out of scope** for the current profile:

#### RFC 9174 §4.4 TLS (39 obligations)

TLS session security is **not implemented** in the `tcpclv4-model` profile. This includes:
- TLS connection establishment and lifetime management (§4.4)
- Certificate profiles and validation (§4.4.1, §4.4.2)
- TLS handshake procedures (§4.4.3)
- ALPN negotiation and authenticated node IDs (§4.4.4)
- Network-level authentication (§4.4.4.2)
- Mutual TLS requirements (§4.4.4.3)
- TLS policy recommendations (§4.4.5)

**Rationale**: The `tcpclv4-model` profile focuses on core TCPCL data transfer semantics. TLS requirements (RFC 9174 §4.4) stay out of that profile.

The `live-node` runtime performs the RFC 9174 §4.4.3 handshake: contact headers in the clear, then TLS on the same TCP connection, then `SESS_INIT`. The active entity is the TLS client. Node identity is checked against the peer certificate after `SESS_INIT` (§4.4.4.3), using a URI subjectAltName or the `id-on-bundleEID` otherName. The RFC does not define an ALPN id, and none is sent.

#### RFC 5326 LTP

`interplanetary-ltp` is a red-part subset used by `live-node`: red data, checkpoints, end of red part, end of block, reports, report acknowledgements, and gap retransmission. Green data, cancellation, cookies, security extensions, and a retransmission timer are out of scope. One segment is one UDP datagram. Client service number 1 is the Bundle Protocol. Details and the other live-node limits are in [live-node.md](live-node.md).

### Coverage Metrics

Coverage is reported in two ways:

1. **Total coverage**: `covered / total_obligations` — includes out-of-scope obligations in the denominator
2. **In-scope coverage**: `covered / (total_obligations - out_of_scope_obligations)` — measures coverage of implemented features only

**Current status** (as of last audit):
- Total: 83/361 (23.0%)
- In-scope: 83/322 (25.8%)

See `STATUS.md` for detailed per-RFC breakdowns.

### Audit Tooling

The audit scripts (`audit_obligations.py`, `../../tools`) automatically calculate and report both metrics. Out-of-scope obligations are identified by the `out_of_scope` field in `../dev/spec`.

Out-of-scope obligations are **never** counted as covered.
