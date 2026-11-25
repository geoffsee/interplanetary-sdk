# Interplanetary SDK Architecture

**Version:** 1.0  
**Last Updated:** 2026-11-09  
**Status:** Frozen for W01+

## Overview

The Interplanetary SDK is a pure-Rust library for Bundle Protocol version 7 (BPv7) per RFC 9171/9172/9173/9174/9758, plus experimental TIPTOP IP/QUIC modeling. The protocol kernel is a deterministic in-process step. A separate live runtime, `interplanetary-node`, binds TCP, UDP, and LTP sockets and calls that kernel. See [live-node.md](live-node.md).

## Design Principles

1. **Deterministic Core**: Given state + input event → bounded transition + explicit effects. The kernel does no hidden I/O, wall-clock reads, or ambient spawning. The live node reads the clock and opens sockets outside that step.
2. **Synchronous Processing**: Core is sync; optional async adapters drive transitions via channels.
3. **Explicit Ownership**: No `Arc<Mutex<_>>` in public APIs; clear ownership and borrowing.
4. **Bounded Resources**: All storage, queues, and computation are bounded and configurable.
5. **Testable Contracts**: Traits express capabilities; implementations are independently testable.
6. **Pure Rust**: No C dependencies; vetted cryptography crates only.
7. **Feature-Gated Profiles**: Core stable vs experimental clearly separated.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Facade                               │
│  NetworkBuilder, NodeBuilder, SimulationRunner, Observers   │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────▼────┐      ┌───▼────┐      ┌───▼─────┐
   │   BP    │      │  Sim   │      │  CLA    │
   │  Core   │      │ Engine │      │         │
   └────┬────┘      └───┬────┘      └───┬─────┘
        │               │               │
   ┌────▼────┐      ┌───▼────┐      ┌───▼─────┐
   │  BPSec  │      │Storage │      │ TCPCL   │
   │Contexts │      │ & Time │      │ Model   │
   └─────────┘      └───┬────┘      └─────────┘
                        │
                   ┌────▼────┐
                   │ Routing │
                   │ CgrV1   │
                   └─────────┘
```

The diagram is the kernel. `interplanetary-ltp` sits beside the TCPCL model and owns the RFC 5326 red-part engine, still without sockets. `interplanetary-node` is outside the diagram: it owns sockets, TLS, and the wall clock.

### Crate Structure

The repository is a virtual workspace. `interplanetary-sdk` is the published facade. Domain crates are `publish = false`. The W01 single-crate start was split once the kernel, the sync runner, and the async runner needed separate compile graphs. See the workspace table in the repository README.

## Module Boundaries

### `types` - Core Data Types

**Owns:**
- `EndpointId`: Parsed EID with scheme-specific representation
- `NodeId`: Validated node identity
- `BundleId`: Protocol identity (source + timestamp + fragment)
- `SimInstant`, `SimDuration`: Integer nanosecond ticks
- `DtnTimeMs`: Protocol time (2000-01-01 epoch)
- `Bytes`, `BitsPerSecond`: Typed units
- `ContactId`, `PlanVersion`, `TransferId`
- Error types: `Error`, `ErrorKind`, `Result<T>`
- Configuration bounds: limits, timeouts, budgets

**Dependencies:** Minimal (time, thiserror)

**Contracts:**
- All constructors validate inputs
- `Display`/`Debug` must not expose secrets
- Checked arithmetic for time/capacity
- No hidden normalization

### `bp` - Bundle Protocol

**Owns:**
- Wire codec: encode/decode bundles and blocks
- Block registry: primary, canonical, known extensions
- Block CRC computation and validation
- BPA state transitions: transmit, forward, deliver, expire
- Administrative records: status reports, custody signals (if added)
- Fragmentation and reassembly logic
- Bundle metadata and lifecycle

**Dependencies:** `types`, `ciborium`, security/storage/routing contracts

**Contracts:**
- `BundleCodec`: `encode(bundle) -> Vec<u8>`, `decode(bytes) -> Result<Bundle>`
- `BlockProcessor`: per-block validation and processing
- `BundleStore` trait: admit, get, update, remove, enumerate
- `Router` trait: read-only snapshot + request → proposal
- Security integration points for BIB/BCB processing

**Invariants:**
- Decoder rejects malformed input before allocation
- CRC validated before exposing bundle contents
- Unknown blocks handled per their flags
- Fragmentation preserves security integrity constraints

### `security` - BPSec Implementation

**Owns:**
- BIB/BCB encoding and decoding
- HMAC-SHA2 contexts (256/384/512)
- AES-GCM contexts (128/256)
- Optional AES key wrapping (RFC 3394)
- Canonical form construction (IPPT, AAD)
- Key and nonce provider contracts
- Security policy evaluation

**Dependencies:** `types`, `sha2`, `hmac`, `aes-gcm`, shared block views

**Contracts:**
- `SecurityContext`: context ID, apply, verify/decrypt
- `KeyProvider`: opaque key references, usage constraints
- `NonceProvider`: unique nonce allocation (deterministic for sim, operational for real)
- `SecurityPolicy`: role-based decisions (source, verifier, acceptor)

**Invariants:**
- Never reuse key/nonce pair (per RFC 9173 erratum 7002 resolution)
- Failed verification returns no unauthenticated plaintext
- Temporary secrets cleared where supported
- One target per BCB-AES-GCM block
- Operational mode refuses unsafe snapshot restoration

### `sim` - Simulation Engine

**Owns:**
- Event queue: `(time, microstep, phase, sequence)` keys
- Virtual time progression
- Scheduled contacts: directed, timed, rate, delay, resource groups
- Resource reservations and capacity tracking
- Failure injection
- Observation stream (immutable events)
- Snapshot/restore

**Dependencies:** `types`, `rand`, `rand_chacha`

**Contracts:**
- `EventScheduler`: schedule, step, run_until, quiescent check
- `ContactPlan`: directional contacts with resource constraints
- `ResourceManager`: reserve, release, check availability
- `Observer`: bounded immutable event stream
- `Snapshot`: deterministic save/restore

**Invariants:**
- Events processed in strict order
- Time never moves backward
- Microstep/event budget prevents infinite loops
- Completed emissions not revoked by late plan changes
- Deterministic given seed and inputs

### `routing` - Path Computation

**Owns:**
- `CgrApproxV1`: earliest-arrival path finder
- Static route table alternative
- Contact graph search
- Route proposal: contacts, times, charged volume, version
- Cache and invalidation
- DPP boundary (typed, no wire implementation)

**Dependencies:** `types`, immutable plan snapshots

**Contracts:**
- `Router`: `route(bundle_meta, plan_snapshot) -> Proposal | Deferral`
- `AdmissionController`: proposal + resources → commit | reject
- No ground-truth access, local knowledge only
- No state mutation during route computation

**Invariants:**
- Routes feasible under model assumptions
- Deferred ≠ failure (may succeed with future contacts)
- Version-tagged decisions invalidated on plan change
- Earliest arrival time under known contacts

### `cla` - Convergence Layers

**Owns:**
- Basic transfer model: complete-bundle handoff
- TCPCLv4: message codec, session state machine, virtual stream harness
- Transfer IDs, acknowledgments, failures
- CLA capabilities reporting

**Dependencies:** `types`, byte buffers, transport contracts

**Contracts:**
- `ConvergenceLayer`: capabilities, start/cancel transfer, consume input
- `TransportStream`: virtual reliable ordered bytes, explicit events
- Session/transfer state machines per RFC 9174
- TLS modeled as explicit auth events, not real crypto

**Invariants:**
- Basic CLA: complete transfer or none
- TCPCL: follow RFC 9174 state/message rules
- The TCPCL crate claims no socket I/O. `interplanetary-node` is the socket adapter.
- Chunking-independent framing

### `ltp` - Licklider Transmission Protocol

**Owns:**

- Red-part segment codec and a single-engine session table
- Client service id 1 for the Bundle Protocol

**Does not own:** sockets, green data, cancellation, cookies, security extensions, or a retransmission timer. The live node sends one segment per UDP datagram.

### `tiptop` - Experimental IP/QUIC Module

**Owns:**
- Separate IP packet model: IPv4/IPv6 headers, forwarding, buffers
- QUIC profile configuration: RTT estimate, timeouts, flow control
- Abstract connection/timeout experiments
- Optional in-memory QUIC engine integration (future)
- Scenario comparisons

**Dependencies:** `types`, shared contact/resource engine

**Contracts:**
- `IpForwarder`: modeled packet-level forwarding
- `QuicProfile`: transport parameters, fidelity declaration
- Separate from BP; shares physical contacts only
- Unsupported features return capability errors

**Invariants:**
- No IPv6 Hop Limit decrement merely from time
- Explicit draft revision pinned
- Labeled experimental in all outputs
- No operational QUIC crypto/recovery claim without integration

### `facade` - Public API

**Owns:**
- Builder APIs: `NetworkBuilder`, `NodeBuilder`, `SimBuilder`
- High-level operations: inject, step, run_until, snapshot
- Default configurations and validation
- Example compilation
- Documentation

**Dependencies:** All selected components

**Contracts:**
- Validated constructors: fail early, clear errors
- `Capabilities`: runtime inspection of enabled profiles
- Immutable observations, no reentrant mutations
- Tokio optional via `async-adapter` feature

**Invariants:**
- Public APIs compile-check against declared features
- Examples runnable across feature profiles

## Data Flow

### Bundle Injection and Processing

```
1. Application/Test
   ↓ inject(bundle_request)
2. Facade validates and encodes
   ↓ BundleBuilder → bytes
3. BP admits to store
   ↓ BundleStore::admit(bytes) → BundleId
4. Routing computes path
   ↓ Router::route(bundle_meta, plan) → Proposal
5. Admission reserves resources
   ↓ AdmissionController::commit(proposal) → Reservation
6. CLA schedules transmission
   ↓ ConvergenceLayer::start_transfer(bundle_id, contact)
7. Sim processes events
   ↓ EventScheduler::step() → Effects
8. Observations emitted
   ↓ Observer::drain() → Vec<Event>
```

### Security Processing (BPSec Enabled)

```
1. Bundle decode
   ↓
2. BIB/BCB blocks identified
   ↓
3. Policy evaluation
   ↓ SecurityPolicy::check_role()
4. For verifier/acceptor:
   ↓ SecurityContext::verify() or ::decrypt()
5. Failed verification → reject, no plaintext exposed
   ↓
6. Success → continue BPA processing
```

## Trait Contracts

### Core Traits

```rust
pub trait BundleStore {
    fn admit(&mut self, bytes: &[u8]) -> Result<BundleId>;
    fn get(&self, id: &BundleId) -> Result<BundleView>;
    fn update_metadata(&mut self, id: &BundleId, meta: Metadata) -> Result<()>;
    fn remove(&mut self, id: &BundleId) -> Result<()>;
    fn enumerate(&self) -> impl Iterator<Item = BundleId>;
}

pub trait Router {
    fn route(&self, req: RouteRequest, plan: &ContactPlan) -> RouteResult;
}

pub trait ConvergenceLayer {
    fn capabilities(&self) -> ClaCapabilities;
    fn start_transfer(&mut self, bundle_id: BundleId, contact: ContactId) -> Result<TransferId>;
    fn cancel_transfer(&mut self, transfer_id: TransferId) -> Result<()>;
}

pub trait SecurityContext {
    fn context_id(&self) -> u64;
    fn apply(&self, target: &[u8], params: &Parameters) -> Result<SecurityResult>;
    fn verify(&self, target: &[u8], result: &SecurityResult) -> Result<bool>;
}

pub trait Observer {
    fn on_event(&mut self, event: Event);
}
```

### Determinism Contracts

- No `std::time::Instant::now()` in core
- No `tokio::spawn` in core
- RNG from explicit seed
- Event order: `(SimInstant, u32, Phase, u64)` with stable sequence IDs
- Snapshot includes: RNG state, event queue, bundle store, plans, observations

## Resource Limits

### Configurable Bounds

| Resource | Default | Configurable | Enforced |
|----------|---------|--------------|----------|
| Bundle store capacity | 10 MiB | Yes | Admission rejects overflow |
| Event queue size | 100k events | Yes | Fail if exceeded |
| Microstep budget | 1000/time | Yes | Stop with diagnostic |
| Contact plan horizon | 1 year sim time | Yes | Reject farther |
| Observation buffer | 10k events | Yes | Policy: drop or block |
| Max bundle size | 10 MiB | Yes | Decode rejects |
| Reassembly buffers | 10 concurrent | Yes | Expire oldest |

### Memory Accounting

- Bundle payloads: reference-counted (Bytes)
- Metadata: per-bundle fixed overhead (~1 KiB)
- Event queue: per-event (~200 bytes)
- Observations: per-event (~100 bytes)
- Router cache: version-tagged, invalidated on plan change

## Security Model

See `threat-model.md` for full threat analysis.

**Assumed Trusted:**
- Host runtime (OS, Rust std)
- Crypto primitives (sha2, hmac, aes-gcm crates)
- Configuration files (not adversarial input)

**Untrusted:**
- Wire input (bundles, TCPCL messages)
- Remote peer behavior
- Timing/scheduling of events

**Protected Operations:**
- Decode: bounds-checked before allocation
- Security verification: no unauthenticated data exposed
- Admission: storage limits enforced
- Fragmentation + security: per RFC 9172 §5.2

## Live Node

`interplanetary-node` (facade feature `live-node`) is the socket runtime described in [live-node.md](live-node.md). It is not a second bundle agent. One task owns a `BundleAgent`, polls it on a wall-clock `SimInstant`, and moves bytes between that agent and TCP, UDP, or LTP. TLS for TCPCLv4 runs in this crate after the cleartext contact header. The kernel crates do not depend on it.

## Async Adapter Design (Optional Feature)

When `async-adapter` enabled:

```rust
pub struct AsyncSimulation {
    inner: Simulation,
    command_rx: mpsc::Receiver<Command>,
    event_tx: mpsc::Sender<Event>,
}

impl AsyncSimulation {
    pub async fn run(&mut self) { /* ... */ }
    pub async fn inject(&self, bundle: BundleRequest) -> Result<BundleId> { /* ... */ }
}
```

- Commands sent via channel
- Core remains sync; adapter drives it
- Bounded channel backpressure
- Observations streamed via async channel

## Toolchain and MSRV

- **Rust version:** 1.83.0
- **Target:** x86_64-unknown-linux-gnu (primary), others supported if tests pass
- **MSRV policy:** Pinned for release; may bump with minor version
- **Dependencies:** Pin after audit; check advisories

## Testing Strategy

- Unit tests: per-module contracts
- Integration tests: end-to-end bundle delivery
- Property tests: codec round-trip, time arithmetic
- Fuzzing: decoder, security canonicalization
- Benchmark suite: routing, encoding, event processing
- Known-answer vectors: RFC appendices (with errata corrections)
- Differential tests: against ION where available
- Feature matrix: test each profile independently

## Extension Points

Future additions may include:
- Additional EID schemes (register in block registry)
- Custom extension blocks (implement BlockProcessor)
- Alternative routing algorithms (implement Router)
- Custody extensions (requires selected specification)

Shipped outside the kernel, and still short of a full deployment stack:

- `interplanetary-node` binds TCPCLv4, UDP datagrams, and LTP red-part sockets
- `interplanetary-ltp` is the red-part engine those sockets use

## Frozen Decisions (W01)

1. Single crate to start; split if forced by dependencies or stability
2. Feature gates: `bpv7`, `bpsec-default`, `sim-basic`, `tcpclv4-model`, `tiptop-experimental`
3. Deterministic synchronous core; async optional
4. Trait-based contracts for store/router/CLA/security
5. Pure Rust; vetted crypto crates (sha2, hmac, aes-gcm)
6. Rust 1.83.0 toolchain
7. No real sockets/TCP/TLS in the protocol kernel; the live node is a separate crate
8. One BCB-AES-GCM target per block (erratum 7002 resolution)

## Next Steps (W02+)

- W02: Implement BP codec and EID parsing
- W03: Build simulation engine and basic CLA
- W04: BPA state machine and fragmentation
- W05: CgrApproxV1 routing
- W06: BPSec contexts and key providers
- W07: TCPCL model
- W08: TIPTOP experimental module
- W09: Facade and examples
