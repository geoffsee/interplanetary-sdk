# API Contracts

**Version:** 1.0  
**Last Updated:** 2026-11-09  
**Status:** Frozen for W01+

## Contract Principles

1. **Validated Construction**: All constructors validate inputs; invalid configuration rejected before simulation starts
2. **Explicit Errors**: Errors carry context, category, and retry disposition
3. **Bounded Operations**: All operations complete in bounded time/space
4. **No Hidden I/O**: Core is deterministic; no wall-clock, sleeps, or ambient spawning
5. **Immutable Observations**: Observers see immutable events; cannot reenter/mutate
6. **Clear Ownership**: No `Arc<Mutex<_>>` in public APIs

## Core Type Contracts

### `EndpointId`

```rust
pub struct EndpointId { /* ... */ }

impl EndpointId {
    /// Parse from URI string. Validates scheme and SSP.
    /// Returns Err for malformed, oversized, or unsupported schemes.
    pub fn parse(uri: &str) -> Result<Self>;
    
    /// Scheme-specific constructor for dtn: scheme
    pub fn dtn(ssp: &str) -> Result<Self>;
    
    /// Scheme-specific constructor for ipn: scheme (RFC 9758 semantics)
    pub fn ipn(allocator: u64, node: u64, service: u64) -> Result<Self>;
    
    /// Get scheme ("dtn", "ipn", or unknown)
    pub fn scheme(&self) -> &str;
    
    /// Encode for wire transmission (CBOR array)
    pub fn encode(&self) -> Vec<u8>;
    
    /// Decode from wire (CBOR array)
    pub fn decode(bytes: &[u8]) -> Result<Self>;
    
    /// Semantic equality (may differ from byte equality for some schemes)
    /// Security: Use canonical_bytes() for IPPT/AAD, not display form
    pub fn canonical_bytes(&self) -> &[u8];
}

// Display: human-readable URI form
// Debug: diagnostic form (does not expose if it were a key reference)
```

**Invariants:**
- Parsed EID is always valid per its scheme rules
- `canonical_bytes()` returns stable bytes for security operations
- Unknown schemes preserved but bounded
- No silent normalization that changes security meaning

---

### `NodeId`

```rust
pub struct NodeId { /* ... */ }

impl NodeId {
    /// Extract node ID from endpoint ID per scheme rules
    pub fn from_endpoint(eid: &EndpointId) -> Result<Self>;
    
    /// Parse directly if supported by scheme
    pub fn parse(s: &str) -> Result<Self>;
}
```

**Invariants:**
- Node ID is validated identity, not arbitrary service EID
- ipn: allocator + node (no service)
- dtn: node-name portion

---

### `BundleId`

```rust
pub struct BundleId {
    pub source: EndpointId,
    pub timestamp: CreationTimestamp,
    pub fragment_info: Option<FragmentInfo>,
}

pub struct CreationTimestamp {
    pub time: DtnTimeMs,
    pub sequence: u64,
}

pub struct FragmentInfo {
    pub offset: u64,
    pub total_len: u64,
}
```

**Invariants:**
- Anonymous source (null EID) bundles: ID not globally unique, needs internal copy ID
- Fragment identity: source + timestamp + fragment range
- Equality: protocol identity (same source/timestamp/fragment)

---

### `SimInstant` and `SimDuration`

```rust
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SimInstant(u64); // nanoseconds since simulation start

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SimDuration(u64); // nanoseconds

impl SimInstant {
    pub const ZERO: Self = SimInstant(0);
    pub const MAX_HORIZON: Self = SimInstant(u64::MAX); // ~584 years
    
    pub fn checked_add(self, dur: SimDuration) -> Option<Self>;
    pub fn checked_sub(self, dur: SimDuration) -> Option<Self>;
    pub fn saturating_add(self, dur: SimDuration) -> Self;
    
    pub fn duration_since(self, earlier: Self) -> Option<SimDuration>;
}

impl SimDuration {
    pub const ZERO: Self = SimDuration(0);
    pub const NANOSECOND: Self = SimDuration(1);
    pub const MICROSECOND: Self = SimDuration(1_000);
    pub const MILLISECOND: Self = SimDuration(1_000_000);
    pub const SECOND: Self = SimDuration(1_000_000_000);
    
    pub fn from_secs(s: u64) -> Self;
    pub fn from_millis(ms: u64) -> Self;
    pub fn as_secs(&self) -> u64;
    pub fn as_millis(&self) -> u64;
    
    pub fn checked_add(self, other: Self) -> Option<Self>;
    pub fn checked_mul(self, scalar: u64) -> Option<Self>;
}
```

**Invariants:**
- Integer nanosecond ticks, no floats in event queue keys
- Checked arithmetic; overflows return None
- Time never moves backward in event processing
- Max horizon ~584 years of simulated time

---

### `DtnTimeMs`

```rust
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct DtnTimeMs(u64); // milliseconds since 2000-01-01 00:00:00 UTC

impl DtnTimeMs {
    pub const EPOCH: Self = DtnTimeMs(0); // 2000-01-01 00:00:00 UTC
    pub const UNKNOWN: Self = DtnTimeMs(0); // Explicitly unknown clock
    
    pub fn from_unix_timestamp(unix_secs: i64) -> Result<Self>;
    pub fn to_unix_timestamp(&self) -> i64;

    /// Convert a caller-supplied SystemTime. Does not read the clock.
    /// Rejects instants before the Unix epoch and before 2000-01-01 UTC.
    pub fn from_system_time(time: SystemTime) -> Result<Self>;
    
    pub fn from_sim_instant(instant: SimInstant, epoch_map: &EpochMapping) -> Result<Self>;
    
    pub fn checked_add_millis(self, ms: u64) -> Option<Self>;
}

pub struct EpochMapping {
    sim_zero: SimInstant,
    dtn_zero: DtnTimeMs,
}
```

**Invariants:**
- Protocol time with DTN epoch (2000-01-01)
- Zero explicitly represents unknown clock (creation timestamp = 0)
- Epoch mapping is configuration, not implicit cast
- Clock quality tracked separately (in bundle metadata)

---

### Typed Units

```rust
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Bytes(pub u64);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct BitsPerSecond(pub u64);

impl Bytes {
    pub const ZERO: Self = Bytes(0);
    pub fn from_mib(mib: u64) -> Option<Self>; // checked
    pub fn as_u64(&self) -> u64;
}

impl BitsPerSecond {
    pub fn from_mbps(mbps: u64) -> Self;
    pub fn from_kbps(kbps: u64) -> Self;
}
```

**Invariants:**
- No untyped integers at public unit boundaries
- Text/config parsing explicit (e.g., "10 MiB", "1.5 Mbps")
- Capacity math uses checked u128 intermediates

---

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Malformed wire input: {0}")]
    MalformedInput(String),
    
    #[error("Unsupported capability: {0}")]
    UnsupportedCapability(String),
    
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
    
    #[error("Policy rejected: {0}")]
    PolicyRejected(String),
    
    #[error("Insufficient storage: requested {requested}, available {available}")]
    InsufficientStorage { requested: Bytes, available: Bytes },
    
    #[error("No route available: {reason}")]
    NoRoute { reason: String },
    
    #[error("Resource unavailable: {0}")]
    ResourceUnavailable(String),
    
    #[error("Transfer failed: {0}")]
    TransferFailed(String),
    
    #[error("Security failure: {0}")]
    SecurityFailure(String),
    
    #[error("Time overflow")]
    TimeOverflow,
    
    #[error("Snapshot incompatible: {reason}")]
    SnapshotIncompatible { reason: String },
    
    #[error("Event budget exhausted: {limit}")]
    EventBudgetExhausted { limit: u64 },
    
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, Error>;
```

**Retry Disposition:**
- `InvalidConfig`, `MalformedInput`, `ProtocolViolation`, `UnsupportedCapability`: Do not retry
- `InsufficientStorage`, `ResourceUnavailable`: May retry after resources freed
- `NoRoute`: May retry after plan update or time advancement
- `TransferFailed`: Depends on cause (ephemeral vs permanent)
- `SecurityFailure`: Do not retry with same input

---

## Trait Contracts

### `BundleStore`

```rust
pub trait BundleStore {
    /// Admit bundle from wire bytes. Validates and reserves storage atomically.
    /// Returns Err if malformed, oversized, or storage full.
    /// No partial state on failure.
    fn admit(&mut self, bytes: &[u8]) -> Result<BundleId>;
    
    /// Get immutable view of bundle. Returns Err if not found or deleted.
    fn get(&self, id: &BundleId) -> Result<BundleView>;
    
    /// Update bundle metadata (retention reasons, forwarding state).
    /// Does not modify payload or primary block.
    fn update_metadata(&mut self, id: &BundleId, meta: Metadata) -> Result<()>;
    
    /// Remove bundle and free storage. Idempotent.
    fn remove(&mut self, id: &BundleId) -> Result<()>;
    
    /// Enumerate all stored bundle IDs. Order unspecified.
    fn enumerate(&self) -> Vec<BundleId>;
    
    /// Current storage usage and capacity
    fn usage(&self) -> StorageUsage;
}

pub struct StorageUsage {
    pub used: Bytes,
    pub capacity: Bytes,
    pub bundle_count: usize,
}
```

**Invariants:**
- Admit is atomic: success = bundle stored, failure = no change
- View returned by `get` is immutable snapshot
- Remove is idempotent (OK if already removed)
- Storage includes payload, metadata, security expansion

---

### `Router`

```rust
pub trait Router {
    /// Compute route for bundle. Returns proposal with path and resources,
    /// or deferral/failure with reason.
    /// 
    /// Router sees only local knowledge, not global state.
    /// No state mutation; pure function of inputs.
    fn route(&self, request: RouteRequest, plan: &ContactPlan) -> RouteResult;
}

pub struct RouteRequest {
    pub destination: EndpointId,
    pub bundle_size: Bytes,
    pub ready_time: SimInstant,
    pub expiry: SimInstant,
    pub metadata: BundleMetadata,
}

pub enum RouteResult {
    Proposal(RouteProposal),
    Deferred { reason: String, retry_after: Option<SimInstant> },
    Failed { reason: String },
}

pub struct RouteProposal {
    pub route_id: RouteId,
    pub contacts: Vec<ContactHop>,
    pub estimated_delivery: SimInstant,
    pub charged_volume: Bytes,
    pub plan_version: PlanVersion,
}

pub struct ContactHop {
    pub contact_id: ContactId,
    pub next_node: NodeId,
    pub start: SimInstant,
    pub end: SimInstant,
}
```

**Invariants:**
- Router is pure function: same inputs → same output
- No access to global simulator ground truth
- Local knowledge only (configured plan, not actual state)
- Proposal includes plan version for invalidation
- Deferral ≠ failure (may succeed with future contacts or plan update)

---

### `AdmissionController`

```rust
pub trait AdmissionController {
    /// Commit resources for route proposal. Returns reservation or rejection.
    /// Atomic: success = resources reserved, failure = no change.
    fn commit(&mut self, proposal: RouteProposal) -> Result<Reservation>;
    
    /// Rollback reservation. Idempotent.
    fn rollback(&mut self, reservation: Reservation) -> Result<()>;
    
    /// Check if proposal still valid (plan unchanged, resources available)
    fn validate(&self, proposal: &RouteProposal) -> Result<()>;
}

pub struct Reservation {
    pub reservation_id: ReservationId,
    pub contact_id: ContactId,
    pub interval: TimeRange,
    pub volume: Bytes,
}
```

**Invariants:**
- Commit is transactional
- Rollback is idempotent
- Validate checks plan version and resource availability

---

### `ConvergenceLayer`

```rust
pub trait ConvergenceLayer {
    /// Report CLA capabilities (timing model, reliability, limits)
    fn capabilities(&self) -> ClaCapabilities;
    
    /// Start bundle transfer on contact. Returns transfer ID.
    /// Acceptance ≠ peer receipt (CLA-specific semantics)
    fn start_transfer(
        &mut self,
        bundle_id: BundleId,
        contact: ContactId,
        reservation: Reservation,
    ) -> Result<TransferId>;
    
    /// Cancel in-progress transfer. Best-effort.
    fn cancel_transfer(&mut self, transfer_id: TransferId) -> Result<()>;
    
    /// Process incoming transport data. Returns events (completions, failures)
    fn process_input(&mut self, input: &[u8]) -> Result<Vec<ClaEvent>>;
    
    /// Advance time and emit timer events
    fn tick(&mut self, now: SimInstant) -> Vec<ClaEvent>;
}

pub enum ClaEvent {
    TransferStarted { transfer_id: TransferId },
    TransferProgress { transfer_id: TransferId, bytes_sent: u64 },
    TransferCompleted { transfer_id: TransferId },
    TransferFailed { transfer_id: TransferId, reason: String },
    SessionEstablished { peer: NodeId },
    SessionTerminated { peer: NodeId, reason: String },
}
```

**Invariants:**
- Basic CLA: complete bundle or none (no partial)
- TCPCL: follows RFC 9174 state machine
- Transfer acceptance ≠ peer delivery
- Events are immutable and monotonic

---

### `SecurityContext`

```rust
pub trait SecurityContext {
    /// Context ID (e.g., 1 for HMAC-SHA-256)
    fn context_id(&self) -> u64;
    
    /// Apply security operation (generate BIB/BCB)
    fn apply(
        &self,
        target: &[u8],
        params: &SecurityParameters,
        key: &KeyReference,
    ) -> Result<SecurityResult>;
    
    /// Verify integrity (BIB)
    fn verify(
        &self,
        target: &[u8],
        result: &SecurityResult,
        key: &KeyReference,
    ) -> Result<bool>;
    
    /// Decrypt and verify (BCB)
    fn decrypt(
        &self,
        ciphertext: &[u8],
        result: &SecurityResult,
        key: &KeyReference,
    ) -> Result<Vec<u8>>;
}

pub struct SecurityResult {
    pub context_id: u64,
    pub target_results: Vec<TargetResult>,
}

pub struct TargetResult {
    pub target_id: u64,
    pub result_data: Vec<u8>, // HMAC tag, ciphertext+tag, wrapped key, etc.
}
```

**Invariants:**
- One target per BCB-AES-GCM result (erratum 7002 resolution)
- Failed verification returns false, not plaintext
- Key references opaque, validated by provider
- Nonce/IV explicitly supplied, never implicit

---

### `KeyProvider` and `NonceProvider`

```rust
pub trait KeyProvider {
    /// Resolve opaque key reference. Returns Err if key not found or usage invalid.
    fn get_key(&self, key_ref: &KeyReference) -> Result<KeyMaterial>;
    
    /// Check if key may be used for operation
    fn check_usage(&self, key_ref: &KeyReference, usage: KeyUsage) -> Result<()>;
}

pub trait NonceProvider {
    /// Allocate unique nonce/IV. Never reuses.
    /// Returns Err if provider exhausted or snapshot restore unsafe.
    fn allocate_nonce(&mut self, context: NonceContext) -> Result<Vec<u8>>;
    
    /// Check if snapshot restore is safe (no nonce reuse)
    fn can_restore_snapshot(&self, snapshot: &NonceSnapshot) -> bool;
}

pub enum KeyUsage {
    BibSign,
    BibVerify,
    BcbEncrypt,
    BcbDecrypt,
}

pub struct NonceContext {
    pub context_id: u64,
    pub key_ref: KeyReference,
    pub target_id: u64,
}
```

**Invariants:**
- Operational mode: must not reuse nonce, even across snapshots
- Deterministic mode: isolated fixture keys, explicit seed, simulation-only
- Provider tracks usage, refuses unsafe restore

---

### `Observer`

```rust
pub trait Observer {
    /// Receive immutable event. Called during event processing.
    /// Must not reenter simulator or block for long periods.
    fn on_event(&mut self, event: &Event);
}

pub enum Event {
    BundleAdmitted { id: BundleId, time: SimInstant },
    BundleForwarded { id: BundleId, next_hop: NodeId, time: SimInstant },
    BundleDelivered { id: BundleId, time: SimInstant },
    BundleExpired { id: BundleId, time: SimInstant },
    BundleDeleted { id: BundleId, reason: DeleteReason, time: SimInstant },
    TransferStarted { transfer_id: TransferId, time: SimInstant },
    TransferCompleted { transfer_id: TransferId, time: SimInstant },
    TransferFailed { transfer_id: TransferId, reason: String, time: SimInstant },
    RouteComputed { bundle_id: BundleId, route: RouteProposal, time: SimInstant },
    ContactOpened { contact_id: ContactId, time: SimInstant },
    ContactClosed { contact_id: ContactId, time: SimInstant },
    SecurityApplied { bundle_id: BundleId, operation: SecurityOp, time: SimInstant },
    SecurityVerified { bundle_id: BundleId, success: bool, time: SimInstant },
    StorageFull { requested: Bytes, available: Bytes, time: SimInstant },
    // ... more event types
}
```

**Invariants:**
- Events are immutable
- Observer cannot mutate simulator state
- Overflow policy explicit (drop oldest, block admission, etc.)
- Events monotonic in time

---

## Facade API

```rust
pub struct Simulation {
    // ... internal state
}

impl Simulation {
    pub fn builder() -> SimulationBuilder;
    
    /// Inject bundle from application
    pub fn inject(&mut self, request: BundleRequest) -> Result<BundleId>;
    
    /// Step one event (lowest time+microstep+phase+sequence)
    pub fn step(&mut self) -> Result<Option<SimInstant>>;
    
    /// Run until condition or quiescence
    pub fn run_until(&mut self, condition: RunUntil) -> Result<RunOutcome>;
    
    /// Run until event queue empty and no pending work
    pub fn run_until_quiescent(&mut self) -> Result<QuiescentReason>;
    
    /// Take snapshot for save/restore
    pub fn snapshot(&self) -> Result<Snapshot>;
    
    /// Restore from snapshot
    pub fn restore(snapshot: Snapshot) -> Result<Self>;
    
    /// Drain observations since last call
    pub fn drain_observations(&mut self) -> Vec<Event>;
    
    /// Inspect node state (storage, pending, contacts)
    pub fn inspect_node(&self, node: NodeId) -> Result<NodeState>;
    
    /// Report enabled capabilities
    pub fn capabilities(&self) -> Capabilities;
}

pub enum RunUntil {
    Time(SimInstant),
    EventCount(u64),
    Condition(Box<dyn Fn(&Simulation) -> bool>),
}

pub enum RunOutcome {
    ConditionMet,
    TimeReached(SimInstant),
    EventBudgetExhausted,
}

pub enum QuiescentReason {
    AllDelivered,
    QueueEmpty,
    WaitingBeyondHorizon(SimInstant),
    Blocked { reason: String },
}
```

**Invariants:**
- Builder validates before constructing Simulation
- `step()` returns None when queue empty
- `run_until_quiescent()` reports why it stopped (not just empty queue)
- Observations immutable, drained explicitly
- Snapshot/restore preserves determinism

---

## Construction and Configuration

```rust
pub struct SimulationBuilder {
    nodes: Vec<NodeConfig>,
    contacts: Vec<ContactConfig>,
    storage_config: StorageConfig,
    time_config: TimeConfig,
    routing_config: RoutingConfig,
    security_config: Option<SecurityConfig>,
    limits: Limits,
}

impl SimulationBuilder {
    pub fn new() -> Self;
    
    pub fn add_node(mut self, config: NodeConfig) -> Self;
    pub fn add_contact(mut self, config: ContactConfig) -> Self;
    pub fn storage(mut self, config: StorageConfig) -> Self;
    pub fn routing(mut self, config: RoutingConfig) -> Self;
    pub fn security(mut self, config: SecurityConfig) -> Self;
    pub fn limits(mut self, limits: Limits) -> Self;
    
    /// Validate and build. Returns Err if configuration invalid.
    pub fn build(self) -> Result<Simulation>;
}

pub struct Limits {
    pub max_bundle_size: Bytes,
    pub storage_capacity: Bytes,
    pub event_queue_size: usize,
    pub microstep_budget: u32,
    pub max_horizon: SimDuration,
    pub observation_buffer: usize,
    pub reassembly_buffers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bundle_size: Bytes::from_mib(10).unwrap(),
            storage_capacity: Bytes::from_mib(10).unwrap(),
            event_queue_size: 100_000,
            microstep_budget: 1000,
            max_horizon: SimDuration::from_secs(365 * 24 * 3600), // 1 year
            observation_buffer: 10_000,
            reassembly_buffers: 10,
        }
    }
}
```

**Invariants:**
- `build()` validates before returning Simulation
- Default limits are safe conservative values
- All limits configurable
- Builder is consumed by `build()`

---

## Async Adapter (Optional)

```rust
#[cfg(feature = "async-adapter")]
pub struct AsyncSimulation {
    // ... internal
}

#[cfg(feature = "async-adapter")]
impl AsyncSimulation {
    pub fn new(sim: Simulation) -> (Self, AsyncHandle);
    
    pub async fn run(&mut self);
    
    pub async fn inject(&self, request: BundleRequest) -> Result<BundleId>;
    
    pub fn event_stream(&self) -> impl Stream<Item = Event>;
    
    pub async fn shutdown(self) -> Simulation;
}
```

**Invariants:**
- Core remains sync; adapter drives it
- Commands via bounded channel (backpressure)
- Events streamed via async channel
- Can recover inner Simulation on shutdown

---

## Live Node (`live-node`)

The socket runtime is `interplanetary_sdk::live` when the `live-node` feature is on. Full behavior, limits, and the example command are in [live-node.md](live-node.md).

```rust
pub enum Transport {
    Tcp { addr: SocketAddr, dial: bool, server_name: Option<String> },
    Udp { addr: SocketAddr },
    Ltp { addr: SocketAddr },
}

pub enum TlsMode {
    Mutual { ca_pem: Vec<u8>, cert_pem: Vec<u8>, key_pem: Vec<u8> },
    InsecurePlaintext,
}

impl Node {
    pub async fn bind(config: NodeConfig) -> Result<Self>;
    pub async fn send(&self, destination: EndpointId, payload: Vec<u8>, lifetime_ms: u64) -> Result<BundleId>;
    pub async fn recv(&mut self) -> Result<DeliveredBundle>;
    pub async fn shutdown(self) -> Result<()>;
}
```

**Invariants:**

- At least one listen address is set. `InsecurePlaintext` refuses a non-loopback TCP listen or dial address.
- `send` returns after admission, not after peer acknowledgement.
- A bundle is transmitted on the link whose node id equals the destination endpoint's node id.
- UDP carries one encoded bundle per datagram. LTP carries one segment per datagram, client service id 1.
- The kernel crates gain no socket or clock dependency from this feature.
- `live-node` does not enable BPSec. The node `bpsec` feature adds `NodeConfig.bpsec`. A zero IV counter is rejected unless `allow_zero_iv_counter` is set.

Kernel helpers used only by this runtime:

- `BundleAgent::take_cla_transmissions_for(node)` removes queued transmissions for that destination node.
- `BundleAgent::take_delivered_adus()` removes bundles delivered to the local application since the last call.
- `Message::decode_frame` returns one TCPCL message, or `Ok(None)` when the buffer is short. `SESS_TERM` consumes 3 octets.

---

## Testing Contracts

- All public APIs have unit tests
- Error paths exercised
- Bounds checked (overflow, underflow, limits)
- Feature combinations tested independently
- Examples compile across feature matrix

## Next Steps

- W02: Implement types and BP codec per these contracts
- W03: Implement simulation engine
- W04: BPA state machine
- Interface changes require architecture review and ADR
