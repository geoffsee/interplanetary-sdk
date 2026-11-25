# Interplanetary SDK Threat Model

**Version:** 1.0  
**Last Updated:** 2026-11-09  
**Scope:** Security analysis for simulation and protocol implementation

## Purpose and Scope

This threat model analyzes the Interplanetary SDK, a pure-Rust library for delay-tolerant network simulation implementing BPv7 and experimental TIPTOP profiles.

**What this is:**
- In-process simulation library
- Protocol implementation (BPv7, BPSec, TCPCLv4)
- Deterministic test and research tool

**What this is NOT:**
- Flight-qualified spacecraft software
- Operational custody service with durability guarantees
- A production QUIC stack (TIPTOP remains an experimental model)
- Network-wide key distribution system
- Production deployment without additional hardening

**Live node (2026-11-24).** `interplanetary-node` does open TCP and UDP sockets. That does not retire the limits above. The live runtime is documented in [live-node.md](live-node.md). Additions to this model:

- TCPCLv4 mutual TLS is terminated in the node, after the cleartext contact header. The active side is the TLS client. Node-id checks use a URI subjectAltName or `id-on-bundleEID` (OID `1.3.6.1.5.5.7.8.11`). There is no ALPN id in RFC 9174, and none is sent.
- `InsecurePlaintext` is rejected unless the TCP listen address and every dialed TCP peer are loopback.
- UDP datagrams and LTP segments are not encrypted. BPSec is the optional payload protection. It is off unless the node is built with the `bpsec` feature and `NodeConfig.bpsec` sets a non-zero IV counter.
- LTP is a red-part subset. It has no retransmission timer, so a lost report is not retried on its own.
- The bundle store is in memory. Restart drops bundles and any BPSec counter held only in that process.
- An independent review is still required before a node is exposed to untrusted peers. Loopback tests are not that review.

## Trust Boundaries

### Trusted Components

1. **Host Runtime**
   - Operating system
   - Rust standard library
   - Memory allocator
   - Thread scheduler (if async)

2. **Cryptographic Primitives**
   - `sha2` crate (SHA-256/384/512)
   - `hmac` crate (HMAC construction)
   - `aes-gcm` crate (AES-GCM AEAD)
   - Trust assumption: These crates correctly implement their algorithms and are reviewed

3. **Configuration and Initialization**
   - Contact plans provided by application
   - Key material provided via KeyProvider
   - Network topology configuration
   - Assumption: Configuration files are from trusted sources, not adversarial input

4. **Application Layer**
   - Bundle injection requests from local application
   - Observer/telemetry consumers
   - Assumption: Local API consumers are cooperative, not adversarial

### Untrusted Inputs

1. **Wire-Format Bundles**
   - Encoded bundle bytes from decode path
   - May be malformed, oversized, or malicious
   - Must be validated before processing

2. **TCPCL Messages**
   - Session handshake and data transfer messages
   - May contain invalid states, large lengths, or protocol violations

3. **Peer Behavior**
   - Remote nodes may send unexpected bundles
   - Timing and ordering of messages
   - Claimed EIDs and metadata

4. **Timing and Resource Exhaustion**
   - Adversary may attempt to exhaust storage, events, or computation
   - Large reassembly buffers
   - Many concurrent transfers

## Threat Categories

### T1: Memory Safety Violations

**Threat:** Buffer overflow, use-after-free, data races leading to memory corruption.

**Mitigation:**
- Pure Rust with no unsafe code in decoder/core (or minimal, audited unsafe)
- Bounds checking before allocation in CBOR decoder
- Reference-counted payload handles (Bytes)
- `#![forbid(unsafe_code)]` in sensitive modules where possible
- Fuzzing with AddressSanitizer/MemorySanitizer

**Residual Risk:** Low due to Rust's memory safety guarantees.

---

### T2: Resource Exhaustion

**Threat:** Attacker sends bundles/messages to exhaust memory, CPU, or storage.

**Attack Vectors:**
- Large bundle payloads
- Many small bundles (storage exhaustion)
- Deep CBOR nesting (stack exhaustion)
- Infinite event loops (time exhaustion)
- Reassembly buffer accumulation

**Mitigation:**
- Configurable storage capacity limits (default 10 MiB)
- Max bundle size enforced before decode (default 10 MiB)
- CBOR nesting depth limit
- Microstep budget prevents infinite loops (default 1000/time tick)
- Bounded event queue (default 100k events)
- Reassembly expiry (bounded concurrent, time-based cleanup)
- Admission rejects overflow with explicit error

**Residual Risk:** Medium. Limits are configurable but must be set appropriately for deployment.

---

### T3: Cryptographic Failures

#### T3.1: Key/Nonce Reuse

**Threat:** Reusing AES-GCM key/nonce pair breaks confidentiality.

**Attack Vectors:**
- Snapshot restore with same nonce counter
- Forked simulation instances
- Multi-target BCB with shared IV (RFC 9173 erratum 7002)

**Mitigation:**
- One target per BCB-AES-GCM block with explicit IV (design decision per erratum 7002)
- Operational NonceProvider refuses unsafe snapshot restoration
- Deterministic mode (simulation only) uses isolated fixture keys and named seed
- Never mint operational ciphertext from replayed trace
- Nonce provider tracks usage, prevents reuse

**Residual Risk:** Low if NonceProvider contract honored. High if operational keys used with deterministic mode.

#### T3.2: Authentication Bypass

**Threat:** Attacker modifies protected bundle without detection.

**Attack Vectors:**
- Incorrect IPPT/AAD construction
- Partial canonicalization
- Missing verification step
- Logic errors in BIB/BCB processing

**Mitigation:**
- Canonical form construction per RFC 9172 §§4-5
- Byte-level test vectors from RFC 9173 appendices (with errata corrections)
- Failed verification returns no unauthenticated plaintext to application
- Security policy enforces verification before delivery (default fail-closed)
- Independent security review pass (W11)

**Residual Risk:** Medium. Correct implementation critical; single-agent review is not independent.

#### T3.3: Downgrade/Stripping Attacks

**Threat:** Attacker removes security blocks or downgrades to unprotected.

**Mitigation:**
- Security policy: absent protection on expected-protected service fails delivery
- Protected-service delivery default: fail closed
- Block processing flags enforced (delete bundle if required block unsupported)
- No silent downgrade to weaker context

**Residual Risk:** Medium. Policy must be correctly configured; transit nodes may not enforce.

---

### T4: Protocol Violations

#### T4.1: Malformed Bundle Injection

**Threat:** Crafted bundle exploits parser bugs or violates protocol invariants.

**Attack Vectors:**
- Invalid CBOR structure
- Inconsistent primary block fields
- CRC mismatch
- Illegal block ordering
- Fragment identity conflicts

**Mitigation:**
- Strict CBOR validation before processing
- CRC validation before exposing contents
- Primary block constraints enforced (§4.3.1)
- Unknown block handling per flags (§4.2.4)
- Fuzzing with malformed inputs

**Residual Risk:** Low. Reject invalid input early; no partial state on failure.

#### T4.2: Fragmentation Attacks

**Threat:** Overlapping fragments, missing fragments, or fragment+security mismatches.

**Attack Vectors:**
- Conflicting fragment data for same offset
- Incomplete reassembly with resource consumption
- Adding BIB/BCB to already-fragmented bundle (RFC 9172 §5.2)

**Mitigation:**
- Bounded reassembly buffers (default 10 concurrent)
- Expiry-based cleanup
- Conflicting fragments trigger rejection/quarantine (documented policy)
- Do not add new BIB/BCB to fragmented bundle per §5.2
- Test fragment+security patterns explicitly

**Residual Risk:** Medium. Reassembly limits must be tuned; policy on conflicts must be clear.

#### T4.3: Status Report Loops

**Threat:** Status reports generate more status reports, creating amplification.

**Attack Vectors:**
- Request reports on administrative bundles
- Recursive report requests

**Mitigation:**
- RFC 9171 §6.1.2: status reports for admin records only if requested and policy permits
- Recursion prevention: do not request reports on reports (unless explicit policy)
- Status generation governed by explicit reporting policy

**Residual Risk:** Low. Bounded by policy.

---

### T5: Routing and Admission Exploits

#### T5.1: Route Injection/Spoofing

**Threat:** Attacker influences routing to divert bundles or cause denial of service.

**Attack Vectors:**
- Malicious contact plan updates
- Fake DPP advertisements (if implemented)
- Clock manipulation

**Mitigation:**
- Contact plans are trusted configuration (trust boundary)
- DPP typed boundary: no wire implementation, optional policy only
- Plan updates require explicit API call with version tracking
- No silent clock changes; DtnTime clock quality explicit

**Residual Risk:** Medium. Assumes trusted configuration source.

#### T5.2: Storage Exhaustion via Admission

**Threat:** Attacker sends bundles to fill storage, denying service.

**Mitigation:**
- Admission enforces storage capacity before accepting
- Overflow policy: reject new admission (default) or evict by policy
- Transactional: failed admit leaves no partial state
- Storage accounting includes payload, metadata, fragments, security expansion

**Residual Risk:** Low with limits. Eviction policy may cause additional denial if exploited.

---

### T6: Side Channels and Timing

**Threat:** Timing or resource-usage side channels leak information.

**Attack Vectors:**
- Crypto timing (HMAC/AES-GCM)
- Bundle size inference
- Routing decision timing

**Mitigation:**
- Use constant-time crypto where provided by primitives (aes-gcm, hmac crates)
- No explicit timing defenses in application-layer routing (simulation context)
- Deterministic simulation mode: reproducible, no real timing

**Residual Risk:** Medium. Crypto libraries provide some protection; higher-layer timing not addressed.

---

### T7: Replay Attacks

**Threat:** Attacker replays previously captured bundles.

**Attack Vectors:**
- Replaying encrypted bundles (no freshness guarantee in BPSec)
- Replaying status reports or administrative messages

**Mitigation:**
- BPSec provides authentication/confidentiality, not freshness
- Application-layer sequence numbers or timestamps for replay detection (out of scope)
- Deduplication (bounded, configurable) reduces impact of recent replays
- Nonce/IV uniqueness prevents decryption with reused keys

**Residual Risk:** High at protocol level. Replay defense is application responsibility.

---

### T8: Dependency Vulnerabilities

**Threat:** Vulnerability in third-party crate compromises security.

**Attack Vectors:**
- Crypto library bugs (sha2, hmac, aes-gcm)
- CBOR parser bugs (ciborium)
- Unsafe code in dependencies

**Mitigation:**
- Pin dependency versions after audit
- Check RustSec advisory database regularly
- Prefer pure-Rust, reviewed crates
- No custom crypto implementation
- Fuzzing with sanitizers

**Residual Risk:** Medium. Ongoing monitoring required.

---

### T9: Simulation-Specific Threats

#### T9.1: Determinism Loss

**Threat:** Non-deterministic behavior makes results unreproducible.

**Attack Vectors:**
- Hash map iteration order
- Thread scheduling
- Wall-clock reads
- Observer overflow dropping different events

**Mitigation:**
- Explicit RNG seed
- Event ordering: `(time, microstep, phase, sequence)` with stable IDs
- No `std::time::Instant::now()` in core
- Observer overflow policy explicit (drop oldest with diagnostic)
- Snapshot includes full RNG state

**Residual Risk:** Low. Determinism testable by snapshot/restore and repeated runs.

#### T9.2: Snapshot Poisoning

**Threat:** Malicious snapshot causes incorrect behavior or security failure on restore.

**Attack Vectors:**
- Replay nonces from snapshot
- Inconsistent state across components
- Expired bundles still present

**Mitigation:**
- Operational NonceProvider refuses snapshot restore with used nonces
- Snapshot format versioned; incompatible versions rejected
- Validation on restore: no expired bundles, consistent event queue

**Residual Risk:** Medium. Snapshot integrity depends on storage security.

---

### T10: Experimental Module Risks (TIPTOP)

**Threat:** Experimental IP/QUIC module claims operational properties without validation.

**Mitigation:**
- Labeled "experimental" in all outputs
- Capabilities report unsupported features
- Draft revisions pinned explicitly
- No operational QUIC crypto claim without real integration
- Separate from stable BP profile

**Residual Risk:** Low. Clear labeling prevents misuse.

---

## Out-of-Scope Threats

The following are explicitly outside this threat model:

1. **Physical Security**: Hardware tampering, side-channel attacks on CPU
2. **Network-Wide Key Distribution**: Secure key establishment between nodes
3. **Custody Durability**: Crash recovery, disk failure, distributed consensus
4. **Real Transport Security**: Actual TCP/TLS/DTLS implementation
5. **Flight Qualification**: Radiation, vibration, formal verification
6. **Application-Layer Authorization**: Which services may send to which destinations
7. **External Infrastructure**: DNS, PKI, time synchronization services

## Security Claims and Disclaimers

### What We Claim

- Correct implementation of BPv7 wire format per RFC 9171 (within tested scope)
- BPSec contexts 1 and 2 per RFC 9173 with erratum 7002 resolution
- Deterministic simulation for reproducible experiments
- Bounded resource usage with configurable limits
- No key/nonce reuse in generation mode
- Failed verification does not leak plaintext

### What We Do NOT Claim

- Operational deployment security without additional hardening
- Protection against all side channels
- Replay attack prevention (application responsibility)
- Key management or distribution
- Real-world TCP/TLS security beyond the live-node handshake described above (certificate lifecycle, revocation, and a production review are still out of scope)
- Independent third-party security audit (W11 self-review disclosed as non-independent)
- Flight or mission qualification

## Testing and Validation

Security-relevant tests include:

1. **Fuzzing**: Decoder, canonical form construction, reassembly
2. **Known-Answer Vectors**: RFC 9173 appendices (with errata corrections)
3. **Mutation Tests**: Tampered bundles, invalid signatures, wrong keys
4. **Resource Limit Tests**: Storage overflow, event exhaustion, deep nesting
5. **Nonce Uniqueness Tests**: Snapshot/restore, forked simulations
6. **Fragment Tests**: Overlapping, missing, conflicting, with security
7. **Timing Oracles**: Decoder performance, routing latency (no secrets)

## Operational Guidance

When deploying this library in a security-sensitive context:

1. **Use operational key/nonce providers**, not deterministic simulation mode
2. **Configure storage and event limits** appropriate to threat model
3. **Implement replay detection** at application layer if required
4. **Monitor for advisories** on cryptographic dependencies
5. **Perform independent security review** before production use
6. **Use `TlsMode::Mutual` for any TCP peer that is not loopback.** UDP and LTP still need BPSec or another payload protection. `InsecurePlaintext` cannot be pointed at a public address.
7. **Establish key management** separately (out of scope for this library). Do not restart a node on an AES-GCM counter that was already used.
8. **Test with adversarial inputs** before exposure to untrusted peers

## Review and Update

This threat model should be reviewed:
- After each work package with security implications (W06, W11)
- When new features are added
- After security advisories on dependencies
- Before any production deployment consideration

**Next Review:** After W06 (BPSec implementation) and W11 (independent review pass)
