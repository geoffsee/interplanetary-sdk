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

*Last updated: 2026-11-24*

---

## Wall-Clock to DTN Time

**Decision:** `DtnTimeMs::from_system_time` converts a `SystemTime` the caller supplies. It does not call the clock. The live node is the caller that reads `SystemTime::now`.

**Rationale:** The kernel step stays deterministic. A test can pass a fixed `SystemTime`. The node maps the resulting milliseconds to `SimInstant` as `dtn_ms * 1_000_000` nanoseconds, which is what `BundleAgent::poll` compares with bundle lifetime.

**Evidence:** `crates/interplanetary-types/src/time.rs`, `crates/interplanetary-node/src/node.rs` (`sim_now`).

---

## TCPCL TLS Lives Outside the Model

**Decision:** `tcpclv4-model` does not perform TLS. `interplanetary-node` performs the RFC 9174 §4.4.3 upgrade on the real socket, then feeds the same session state machine cleartext records.

**Rationale:** Putting rustls in the model crate would make every virtual-stream test depend on certificates. The RFC handshake order (contact header, TLS, `SESS_INIT`) is a property of the socket adapter. Node-id authentication is a URI subjectAltName or `id-on-bundleEID` (`1.3.6.1.5.5.7.8.11`). No ALPN identifier is defined, and none is sent.

**Evidence:** `dev/docs/internal/conformance.md`, `crates/interplanetary-node/src/tcp.rs`, `crates/interplanetary-node/src/tls.rs`.

---

## SESS_TERM Wire Length

**Decision:** `Message::decode_frame` treats `SESS_TERM` as the 3-octet header in RFC 9174 Figure 27. `Message::encode` may append a diagnostic with no length prefix. The live writer strips that suffix before it hits the socket.

**Rationale:** The diagnostic is not a framed field. Leaving it on the wire shifts the next message.

**Evidence:** `crates/interplanetary-tcpcl/src/messages.rs` (`decode_frame`), `crates/interplanetary-node/src/tcp.rs` (`encode_wire`).

---

## Private Use Ipn Numbers on a Live Node

**Decision:** The live node sets `enforce_private_use_restrictions` and copies `administrative_domain` onto every configured neighbor.

**Rationale:** With no domain, every forward is a domain crossing, and node numbers `1..=16_777_215` are refused. A single `Some(domain)` means those numbers are one administrative domain. `None` is still the kernel default.

**Evidence:** `crates/interplanetary-node/src/node.rs` (agent construction).

---

## LTP Red-Part Subset

**Decision:** The LTP engine implements red data, checkpoints, end of red part, end of block, reports, report acknowledgements, and gap fill. It does not implement green data, cancellation, cookies, security extensions, or a timer that retransmits a lost checkpoint or report.

**Rationale:** RFC 5326 is larger than a first convergence layer that can carry one bundle. End of block is set only when the segment ends at the real block length, so a gap fill cannot shrink the block.

**Evidence:** `crates/interplanetary-ltp/src/lib.rs`, `crates/interplanetary-ltp/src/engine.rs`.

---

## Live Forwarding Uses the Destination Node

**Decision:** `ClaTransmission.destination_node` is `NodeId::from_endpoint` of the bundle destination. The live node dequeues with `take_cla_transmissions_for` on nodes that have a link.

**Rationale:** The existing agent queue names the destination node, not a static-route next hop. A `Peer` must be that destination. An intermediate neighbor that is not the destination node will not be offered the bundle.

**Evidence:** `crates/interplanetary-bpa/src/agent.rs` (`take_cla_transmissions_for`), `crates/interplanetary-node/src/node.rs` (`dispatch`).
