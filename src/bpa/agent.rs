//! Bundle Protocol Agent core.
//!
//! [`BundleAgent`] owns local storage, lifecycle state, and CLA/security hooks
//! for a single node. For multi-node runs prefer [`crate::sim::Scenario`].

use crate::bp::Bundle;
use crate::bpa::admin::{ReasonCode, StatusReport};
use crate::bpa::retention::{RetentionConstraint, RetentionConstraintSet};
use crate::sim::{BundleStore, StorageManager};
#[cfg(feature = "tcpclv4-model")]
use crate::tcpcl::{ConnectionManager, ConnectionResult, ReconnectConfig};
use crate::types::{BundleId, EndpointId, Error, ErrorKind, NodeId, Result, SimInstant};
use std::collections::{HashMap, HashSet, VecDeque};

/// BPA configuration
#[derive(Debug, Clone)]
pub struct BpaConfig {
    /// Local node identifier
    pub local_node: NodeId,
    /// Local endpoint ID
    pub local_eid: EndpointId,
    /// Whether forwarding is enabled
    pub enable_forwarding: bool,
    /// Whether local delivery is enabled
    pub enable_delivery: bool,
    /// Status report generation policy
    pub status_report_policy: crate::bpa::policy::StatusReportPolicy,
    /// Maximum transmission unit (MTU) for CLA links
    /// None means no fragmentation needed
    pub cla_mtu: Option<crate::types::Bytes>,
    /// Security context for BPSec operations (RFC 9172)
    #[cfg(feature = "bpsec-default")]
    pub security_context: Option<crate::bpa::security_processing::SecurityContext>,
    /// Security policy for required/expected operations (RFC 9172 §5, §8)
    #[cfg(feature = "bpsec-default")]
    pub security_policy: Option<crate::bpa::security_policy::SecurityPolicy>,
    /// Whether to enforce RFC 9758 §5.5 Private Use EID restrictions (default: true per RFC)
    /// When true, Private Use EIDs (nodes 1-16777215) cannot cross administrative domains
    /// Set to false only for single-domain deployments where Private Use is locally unique
    pub enforce_private_use_restrictions: bool,
    /// Administrative domain identifier (RFC 9758 §5.5)
    /// Used to determine when Private Use bundles cross domain boundaries
    /// None = all forwarding crosses boundaries (strictest enforcement)
    /// Some(id) = only forwarding to different domains crosses boundaries
    pub administrative_domain: Option<u32>,
    /// Static routing table: destination EID → next hop Node ID
    /// None = no routes configured (all forwarding contraindicated)
    /// Some(map) = route bundles per ION-style deterministic routing
    pub static_routes: Option<HashMap<EndpointId, NodeId>>,
    /// RFC 9171 §5.4.2: Policy when forwarding fails
    /// Delete (default): delete bundle immediately
    /// ReturnToPreviousNode: forward back to previous node if possible, else delete
    /// Retain: keep bundle in storage without deleting
    pub forwarding_failed_policy: crate::bpa::policy::ForwardingFailedPolicy,
    /// Outbound BCB configuration (RFC 9173 §4.6 / §4.8.1)
    ///
    /// When set, `send()` applies a BCB to the payload using a unique IV per
    /// invocation, tracked via NonceRegistry to prevent key/IV reuse.
    #[cfg(feature = "bpsec-default")]
    pub outbound_bcb: Option<OutboundBcbConfig>,
}

/// Outbound BCB configuration for BundleAgent origination (RFC 9173)
#[cfg(feature = "bpsec-default")]
#[derive(Clone)]
pub struct OutboundBcbConfig {
    /// Key identifier used for NonceRegistry tracking
    pub key_id: Vec<u8>,
    /// AES key bytes (16 for AES-128, 32 for AES-256) — zeroized on drop
    pub key: zeroize::Zeroizing<Vec<u8>>,
    /// AES-GCM variant
    pub aes_variant: crate::security::AesGcmVariant,
    /// Monotonic counter used to mint unique 12-byte IVs
    pub next_iv_counter: u64,
    /// Optional multi-target BIB applied before the BCB (RFC 9172 §3.9).
    /// When set, `send()` generates a BIB over these block numbers, then applies
    /// the payload BCB — splitting the BIB on partial overlap (RFC9172-053/055).
    pub pre_bib_targets: Option<Vec<u64>>,
    /// HMAC key used for `pre_bib_targets` and for regenerating split BIBs
    pub bib_hmac_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// HMAC SHA variant for pre-BIB / split regeneration
    pub bib_sha_variant: Option<crate::security::HmacVariant>,
}

#[cfg(feature = "bpsec-default")]
impl std::fmt::Debug for OutboundBcbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundBcbConfig")
            .field("key_id", &self.key_id)
            .field("key", &"[redacted]")
            .field("aes_variant", &self.aes_variant)
            .field("next_iv_counter", &self.next_iv_counter)
            .field("pre_bib_targets", &self.pre_bib_targets)
            .field(
                "bib_hmac_key",
                &self.bib_hmac_key.as_ref().map(|_| "[redacted]"),
            )
            .field("bib_sha_variant", &self.bib_sha_variant)
            .finish()
    }
}

#[cfg(feature = "bpsec-default")]
impl OutboundBcbConfig {
    /// Create outbound BCB config with AES-128 key
    pub fn aes128(key_id: Vec<u8>, key: Vec<u8>) -> Self {
        Self {
            key_id,
            key: zeroize::Zeroizing::new(key),
            aes_variant: crate::security::AesGcmVariant::Aes128,
            next_iv_counter: 0,
            pre_bib_targets: None,
            bib_hmac_key: None,
            bib_sha_variant: None,
        }
    }

    /// Attach a multi-target BIB before the outbound BCB (enables §3.9 split path).
    pub fn with_pre_bib(
        mut self,
        targets: Vec<u64>,
        hmac_key: Vec<u8>,
        sha_variant: crate::security::HmacVariant,
    ) -> Self {
        self.pre_bib_targets = Some(targets);
        self.bib_hmac_key = Some(zeroize::Zeroizing::new(hmac_key));
        self.bib_sha_variant = Some(sha_variant);
        self
    }

    /// Mint the next unique 12-byte IV (counter in last 8 bytes)
    pub fn next_iv(&mut self) -> Vec<u8> {
        self.next_iv_counter = self.next_iv_counter.saturating_add(1);
        let mut iv = vec![0u8; 12];
        iv[4..12].copy_from_slice(&self.next_iv_counter.to_be_bytes());
        iv
    }
}

impl Default for BpaConfig {
    fn default() -> Self {
        // RFC 9758 §5.5: Private Use enforcement ON BY DEFAULT
        Self {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: crate::bpa::policy::StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: true,
            administrative_domain: None, // No domain = all forwarding crosses boundaries
            static_routes: None,         // No routes = all forwarding contraindicated
            forwarding_failed_policy: crate::bpa::policy::ForwardingFailedPolicy::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        }
    }
}

/// Bundle processing state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleState {
    /// Newly admitted, awaiting routing
    Admitted,
    /// Queued for transmission on a contact
    QueuedForTransmission,
    /// Currently transmitting
    Transmitting,
    /// Waiting for next contact
    Waiting,
    /// Successfully delivered locally
    Delivered,
    /// Forwarded to next hop
    Forwarded,
    /// Deleted (expired, failed, etc)
    Deleted,
}

/// State transition record
#[derive(Debug, Clone)]
pub struct StateTransition {
    /// Bundle that transitioned
    pub bundle_id: BundleId,
    /// Previous state
    pub from_state: BundleState,
    /// New state
    pub to_state: BundleState,
    /// Reason for transition
    pub reason: String,
    /// Time of transition
    pub time: SimInstant,
}

/// Bundle metadata tracked by BPA
#[derive(Debug, Clone)]
pub struct BundleMetadata {
    state: BundleState,
    _admitted_at: SimInstant,
    _hops: u32,
    retention_constraints: RetentionConstraintSet,
}

impl BundleMetadata {
    /// Check if bundle has a specific retention constraint
    pub fn has_constraint(&self, constraint: RetentionConstraint) -> bool {
        self.retention_constraints.has(constraint)
    }
}

/// CLA transmission queue entry
#[derive(Debug, Clone)]
pub struct ClaTransmission {
    /// Bundle to transmit
    pub bundle: Bundle,
    /// Bundle ID for reference
    pub bundle_id: BundleId,
    /// Destination node for routing
    pub destination_node: NodeId,
}

/// Connection request event (RFC 9174 §4.1 compliant)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    /// Target peer node
    pub peer: NodeId,
    /// Time when request was emitted
    pub time: SimInstant,
}

/// Single-node Bundle Protocol Agent (RFC 9171 §5).
///
/// Admits bundles into bounded storage, applies forwarding/delivery policy,
/// and emits CLA transmission / status-report side effects. Construct with
/// [`BpaConfig`] + [`StorageManager`].
///
/// # Examples
///
/// ```
/// use interplanetary_sdk::bp::{BundleBuilder, CrcType};
/// use interplanetary_sdk::bpa::{BpaConfig, BundleAgent};
/// use interplanetary_sdk::sim::StorageManager;
/// use interplanetary_sdk::types::*;
///
/// # fn main() -> Result<()> {
/// let node = NodeId::ipn(0, 1);
/// let config = BpaConfig {
///     local_node: node.clone(),
///     local_eid: node.to_endpoint_id()?,
///     ..Default::default()
/// };
/// let mut agent = BundleAgent::new(config, StorageManager::new(Bytes::from_mib(1).unwrap()));
///
/// let bundle = BundleBuilder::new()
///     .source(EndpointId::ipn(0, 1, 0)?)
///     .destination(EndpointId::ipn(0, 1, 0)?) // local delivery
///     .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 1))
///     .lifetime(60_000)
///     .payload(b"local".to_vec())
///     .crc_type(CrcType::Crc16)
///     .build()?;
///
/// let id = agent.admit_bundle(bundle, SimInstant::ZERO)?;
/// assert!(agent.get_bundle(&id).is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct BundleAgent {
    config: BpaConfig,
    storage: StorageManager,
    metadata: HashMap<BundleId, BundleMetadata>,
    delivered: HashSet<BundleId>,
    deleted: HashSet<BundleId>,

    // Node-level harness outputs for testing
    /// Bundles queued for CLA transmission
    cla_tx_queue: VecDeque<ClaTransmission>,
    /// Delivered ADUs (application data units)
    delivered_adus: Vec<Bundle>,
    /// Generated status reports
    generated_reports: Vec<StatusReport>,
    /// Connection requests emitted (RFC 9174 §4.1 compliant)
    connection_requests: Vec<ConnectionRequest>,

    /// Current simulation time for poll()
    current_time: SimInstant,

    /// Fragment reassembly manager (RFC 9171 §5.9)
    reassembly: crate::bp::fragment::ReassemblyManager,

    /// Neighbor domain identities (RFC 9758 §5.5)
    neighbor_domains: HashMap<NodeId, u32>,

    /// Bundle fingerprints blocked after XFER_REFUSE Not Acceptable (RFC 9174 §5.2.4-122)
    not_acceptable_blocked: HashSet<Vec<u8>>,

    /// Bundles pending reactive fragmentation after No Resources (RFC 9174 §5.2.4-121)
    reactive_fragment_pending: HashSet<BundleId>,

    /// Connection manager for RFC 9174 §4.1 compliant retry/backoff
    #[cfg(feature = "tcpclv4-model")]
    connection_manager: ConnectionManager,

    /// NonceRegistry for AES-GCM IV uniqueness (RFC 9173 §4.6 / §4.8.1)
    #[cfg(feature = "bpsec-default")]
    nonce_registry: crate::security::NonceRegistry,

    /// RFC9171-4-054: temporary overriding lifetime (ms) while bundles reside
    /// at this node. Does **not** replace `primary.lifetime`; used only as the
    /// effective lifetime for local expiry. `None` = use asserted lifetime.
    lifetime_override_ms: Option<u64>,

    /// RFC9172-109: last post-security bundle size (bytes) accounted for in
    /// storage/MTU scheduling decisions.
    last_accounted_bundle_bytes: Option<u64>,

    /// RFC9171-5-018: extension hook — when set, CLA send-complete generates a
    /// status report with this reason code.
    extension_cla_finish_report_reason: Option<crate::bpa::admin::ReasonCode>,

    /// Bundle IDs whose CLA send has finished and await poll() processing.
    cla_send_complete_pending: VecDeque<BundleId>,
}

impl BundleAgent {
    /// Create new BPA
    pub fn new(config: BpaConfig, storage: StorageManager) -> Self {
        // RFC 9171 §5.9: Allocate fixed capacity for fragment reassembly (1 MiB)
        let reassembly_capacity = crate::types::Bytes::from_mib(1).unwrap();

        Self {
            config,
            storage,
            metadata: HashMap::new(),
            delivered: HashSet::new(),
            deleted: HashSet::new(),
            cla_tx_queue: VecDeque::new(),
            delivered_adus: Vec::new(),
            generated_reports: Vec::new(),
            connection_requests: Vec::new(),
            current_time: SimInstant::ZERO,
            reassembly: crate::bp::fragment::ReassemblyManager::new(reassembly_capacity),
            neighbor_domains: HashMap::new(),
            not_acceptable_blocked: HashSet::new(),
            reactive_fragment_pending: HashSet::new(),
            // RFC 9174 §4.1: Create connection manager with default backoff config
            #[cfg(feature = "tcpclv4-model")]
            connection_manager: ConnectionManager::new(ReconnectConfig::default()),
            #[cfg(feature = "bpsec-default")]
            nonce_registry: crate::security::NonceRegistry::new(),
            lifetime_override_ms: None,
            last_accounted_bundle_bytes: None,
            extension_cla_finish_report_reason: None,
            cla_send_complete_pending: VecDeque::new(),
        }
    }

    /// RFC9171-4-054: impose a temporary overriding lifetime (ms) at this node.
    /// Asserted primary.lifetime is never replaced.
    pub fn set_lifetime_override_ms(&mut self, override_ms: Option<u64>) {
        self.lifetime_override_ms = override_ms;
    }

    /// RFC9172-109: last post-security size used for storage/MTU accounting.
    pub fn last_accounted_bundle_bytes(&self) -> Option<u64> {
        self.last_accounted_bundle_bytes
    }

    /// RFC9171-5-018: register extension hook requesting a status report when
    /// convergence-layer data-sending concludes.
    pub fn set_extension_cla_finish_report(
        &mut self,
        reason: Option<crate::bpa::admin::ReasonCode>,
    ) {
        self.extension_cla_finish_report_reason = reason;
    }

    /// Queue a CLA send-complete event for `bundle_id` (processed in `poll`).
    pub fn queue_cla_send_complete(&mut self, bundle_id: BundleId) {
        self.cla_send_complete_pending.push_back(bundle_id);
    }

    /// Configure neighbor domain (RFC9758-011, RFC9758-030)
    ///
    /// RFC 9758 §5.4-027: LocalNode ipn EIDs MUST NOT be published in directories
    /// discovery / neighbor tables — rejected here.
    pub fn set_neighbor_domain(&mut self, neighbor: NodeId, domain: u32) -> Result<()> {
        // LocalNode is node 4294967295 in default allocator (RFC 9758 §3.4.2)
        if matches!(
            &neighbor,
            NodeId::Ipn { allocator: 0, node } if *node == u32::MAX as u64
        ) {
            return Err(Error::policy_rejected(
                "RFC 9758 §5.4: LocalNode ipn EID MUST NOT be published in peer discovery",
            ));
        }
        self.neighbor_domains.insert(neighbor, domain);
        Ok(())
    }

    fn crosses_domain_boundary(&self, next_hop: &NodeId) -> bool {
        match self.config.administrative_domain {
            None => true,
            Some(local_domain) => match self.neighbor_domains.get(next_hop) {
                None => true,
                Some(&neighbor_domain) => neighbor_domain != local_domain,
            },
        }
    }

    /// Get configuration
    pub fn config(&self) -> &BpaConfig {
        &self.config
    }

    /// Mutable access to the BPSec security context (RFC9173-080/081 counters/IV registry).
    #[cfg(feature = "bpsec-default")]
    pub fn security_context_mut(
        &mut self,
    ) -> Option<&mut crate::bpa::security_processing::SecurityContext> {
        self.config.security_context.as_mut()
    }

    /// Mutable access to outbound BCB config (IV counter for uniqueness tests).
    #[cfg(feature = "bpsec-default")]
    pub fn outbound_bcb_mut(&mut self) -> Option<&mut OutboundBcbConfig> {
        self.config.outbound_bcb.as_mut()
    }

    /// RFC9172-111: whether to emit security reason codes on security DeleteBundle.
    #[cfg(feature = "bpsec-default")]
    fn should_emit_security_reason_code(&self) -> bool {
        if let Some(ref p) = self.config.security_policy
            && p.should_emit_security_reason_codes()
        {
            return true;
        }
        self.config.status_report_policy.report_on_deletion
    }

    /// Admit bundle to storage
    pub fn admit_bundle(&mut self, bundle: Bundle, time: SimInstant) -> Result<BundleId> {
        // Check if destination is local
        let _is_local = self.is_local_destination(&bundle.primary.destination);

        // Admit to storage
        let bundle_id = self.storage.admit(bundle)?;

        // Record metadata
        self.metadata.insert(
            bundle_id.clone(),
            BundleMetadata {
                state: BundleState::Admitted,
                _admitted_at: time,
                _hops: 0,
                retention_constraints: RetentionConstraintSet::new(),
            },
        );

        Ok(bundle_id)
    }

    /// Check if bundle is expired
    pub fn check_expiration(&self, bundle_id: &BundleId, current_time: SimInstant) -> Result<bool> {
        let bundle = self
            .storage
            .get(bundle_id)
            .ok_or_else(|| Error::not_found("Bundle not in storage"))?;

        // Convert creation time to SimInstant (simplified)
        let creation_ms = bundle.primary.creation_timestamp.time.as_millis();
        // RFC9171-4-054: effective lifetime may be a temporary override; asserted
        // primary.lifetime is never replaced.
        let lifetime_ms = match self.lifetime_override_ms {
            Some(ovr) => ovr.min(bundle.primary.lifetime),
            None => bundle.primary.lifetime,
        };

        // Compute expiration (simplified: ignore DTN epoch for now)
        let expiry_ms = creation_ms + lifetime_ms;
        let current_ms = current_time.as_nanos() / 1_000_000;

        Ok(current_ms >= expiry_ms)
    }

    /// Scan for expired bundles and return list
    pub fn find_expired_bundles(&self, current_time: SimInstant) -> Vec<BundleId> {
        self.metadata
            .keys()
            .filter(|id| self.check_expiration(id, current_time).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// Generate status report for bundle reception (RFC 9171 §5.6)
    pub fn generate_reception_status_report(
        &self,
        bundle_id: &BundleId,
        current_time: SimInstant,
    ) -> Option<crate::bpa::admin::StatusReport> {
        let bundle = self.storage().get(bundle_id)?;

        // RFC 9171 §6.1: Never generate status reports for admin records
        if crate::bpa::admin::is_admin_record(bundle) {
            return None;
        }

        // Check if bundle requests reception report
        if !crate::bpa::admin::requests_reception_report(bundle) {
            return None;
        }

        // Check if policy allows
        if !self.config.status_report_policy.report_on_reception {
            return None;
        }

        let requests_time = crate::bpa::admin::requests_status_time(bundle);
        let mut report = crate::bpa::admin::StatusReport::reception(
            bundle.primary.source.clone(),
            bundle.primary.creation_timestamp,
            if requests_time {
                Some(current_time)
            } else {
                None
            },
        );
        // RFC 9171 §6.1.1 / RFC9171-6-019: fragment reports MUST carry offset+length
        Self::attach_fragment_fields(&mut report, bundle);
        Some(report)
    }

    /// Generate status report for bundle forwarding (RFC 9171 §5.4)
    pub fn generate_forwarding_status_report(
        &self,
        bundle_id: &BundleId,
        current_time: SimInstant,
    ) -> Option<crate::bpa::admin::StatusReport> {
        let bundle = self.storage().get(bundle_id)?;

        // RFC 9171 §6.1: Never generate status reports for admin records
        if crate::bpa::admin::is_admin_record(bundle) {
            return None;
        }

        // Check if bundle requests forwarding report
        if !crate::bpa::admin::requests_forward_report(bundle) {
            return None;
        }

        // Check if policy allows
        if !self.config.status_report_policy.report_on_forwarding {
            return None;
        }

        let requests_time = crate::bpa::admin::requests_status_time(bundle);
        let mut report = crate::bpa::admin::StatusReport::forwarding(
            bundle.primary.source.clone(),
            bundle.primary.creation_timestamp,
            if requests_time {
                Some(current_time)
            } else {
                None
            },
        );
        Self::attach_fragment_fields(&mut report, bundle);
        Some(report)
    }

    /// Generate status report for bundle delivery (RFC 9171 §5.7)
    pub fn generate_delivery_status_report(
        &self,
        bundle_id: &BundleId,
        current_time: SimInstant,
    ) -> Option<crate::bpa::admin::StatusReport> {
        let bundle = self.storage().get(bundle_id)?;

        // RFC 9171 §6.1: Never generate status reports for admin records
        if crate::bpa::admin::is_admin_record(bundle) {
            return None;
        }

        // Check if bundle requests delivery report
        if !crate::bpa::admin::requests_delivery_report(bundle) {
            return None;
        }

        // Check if policy allows
        if !self.config.status_report_policy.report_on_delivery {
            return None;
        }

        let requests_time = crate::bpa::admin::requests_status_time(bundle);
        let mut report = crate::bpa::admin::StatusReport::delivery(
            bundle.primary.source.clone(),
            bundle.primary.creation_timestamp,
            if requests_time {
                Some(current_time)
            } else {
                None
            },
        );
        Self::attach_fragment_fields(&mut report, bundle);
        Some(report)
    }

    /// Generate status report for bundle deletion (RFC 9171 §5.10)
    pub fn generate_deletion_status_report(
        &self,
        bundle_id: &BundleId,
        reason_code: crate::bpa::admin::ReasonCode,
        current_time: SimInstant,
    ) -> Option<crate::bpa::admin::StatusReport> {
        let bundle = self.storage().get(bundle_id)?;

        // RFC 9171 §6.1: Never generate status reports for admin records
        if crate::bpa::admin::is_admin_record(bundle) {
            return None;
        }

        // Check if bundle requests deletion report
        if !crate::bpa::admin::requests_deletion_report(bundle) {
            return None;
        }

        // Check if policy allows
        if !self
            .config
            .status_report_policy
            .should_report_deletion(reason_code)
        {
            return None;
        }

        let requests_time = crate::bpa::admin::requests_status_time(bundle);
        let mut report = crate::bpa::admin::StatusReport::deletion(
            bundle.primary.source.clone(),
            bundle.primary.creation_timestamp,
            reason_code,
            if requests_time {
                Some(current_time)
            } else {
                None
            },
        );
        Self::attach_fragment_fields(&mut report, bundle);
        Some(report)
    }

    /// RFC 9171 §6.1.1: if the referenced bundle is a fragment, the admin record
    /// MUST contain fragment offset and fragment length.
    fn attach_fragment_fields(report: &mut crate::bpa::admin::StatusReport, bundle: &Bundle) {
        if bundle.primary.is_fragment() {
            report.fragment_offset = bundle.primary.fragment_offset;
            let frag_len = bundle
                .blocks
                .iter()
                .find(|b| matches!(b.block_type, crate::bp::BlockType::Payload))
                .map(|b| b.data.len() as u64)
                .unwrap_or(0);
            report.fragment_length = Some(frag_len);
        }
    }

    /// Mark bundle as delivered
    pub fn deliver_bundle(&mut self, bundle_id: &BundleId, _time: SimInstant) -> Result<()> {
        if let Some(meta) = self.metadata.get_mut(bundle_id) {
            meta.state = BundleState::Delivered;
        }
        self.delivered.insert(bundle_id.clone());
        Ok(())
    }

    /// Delete bundle (RFC 9171 §5.13)
    pub fn delete_bundle(
        &mut self,
        bundle_id: &BundleId,
        reason: crate::bpa::admin::ReasonCode,
    ) -> Result<()> {
        // Capture report-to before the bundle is removed from storage
        let report_to = self
            .storage
            .get(bundle_id)
            .map(|b| b.primary.report_to.clone());

        // RFC 9171 §5.13: Generate deletion status report if requested
        if let Some(report) =
            self.generate_deletion_status_report(bundle_id, reason, self.current_time)
        {
            self.generated_reports.push(report.clone());
            // RFC 9171 §6.1.1 Step 2 / RFC9171-6-020: present transmission request to BPA
            if let Some(ref report_to) = report_to {
                let admin = crate::bpa::admin::create_status_report_bundle(
                    report,
                    &self.config.local_eid,
                    report_to,
                    self.current_time,
                    self.current_time.as_nanos(), // unique-enough creation seq
                    false,
                )?;
                // send() admits + DispatchPending — the transmission request to the BPA
                let _ = self.send(admin);
            }
        }

        // RFC 9171 §5.13: Remove all retention constraints
        if let Some(meta) = self.metadata.get_mut(bundle_id) {
            meta.retention_constraints = RetentionConstraintSet::new();
            meta.state = BundleState::Deleted;
        }
        self.deleted.insert(bundle_id.clone());
        self.storage.remove(bundle_id)?;
        Ok(())
    }

    /// Cancel a transmission (RFC 9171 §5.12 / RFC9171-5-066).
    ///
    /// When the bundle created for the transmission has not yet been discarded,
    /// delete it for reason "Transmission canceled".
    pub fn cancel_transmission(&mut self, bundle_id: &BundleId) -> Result<()> {
        if self.deleted.contains(bundle_id) || self.storage.get(bundle_id).is_none() {
            return Ok(()); // already discarded — nothing to cancel
        }
        self.delete_bundle(
            bundle_id,
            crate::bpa::admin::ReasonCode::TransmissionCancelled,
        )
    }

    /// Get bundle state
    pub fn get_state(&self, bundle_id: &BundleId) -> Option<BundleState> {
        self.metadata.get(bundle_id).map(|m| m.state)
    }

    /// Check if destination is local
    pub fn is_local_destination(&self, dest: &EndpointId) -> bool {
        // Simple check: compare node IDs
        match (&self.config.local_eid, dest) {
            (
                EndpointId::Ipn {
                    allocator: a1,
                    node: n1,
                    ..
                },
                EndpointId::Ipn {
                    allocator: a2,
                    node: n2,
                    ..
                },
            ) => a1 == a2 && n1 == n2,
            (EndpointId::Dtn { ssp: s1 }, EndpointId::Dtn { ssp: s2 }) => s1 == s2,
            _ => false,
        }
    }

    /// Update bundle state
    pub fn update_state(&mut self, bundle_id: &BundleId, new_state: BundleState) -> Result<()> {
        if let Some(meta) = self.metadata.get_mut(bundle_id) {
            meta.state = new_state;
            Ok(())
        } else {
            Err(Error::not_found("Bundle metadata not found"))
        }
    }

    /// Get storage reference
    pub fn storage(&self) -> &StorageManager {
        &self.storage
    }

    /// Get mutable storage reference
    pub fn storage_mut(&mut self) -> &mut StorageManager {
        &mut self.storage
    }

    /// Get bundle reference
    pub fn get_bundle(&self, bundle_id: &BundleId) -> Option<&Bundle> {
        self.storage.get(bundle_id)
    }

    /// List bundles in given state
    pub fn list_bundles_in_state(&self, state: BundleState) -> Vec<BundleId> {
        self.metadata
            .iter()
            .filter(|(_, meta)| meta.state == state)
            .map(|(id, _)| id.clone())
            .collect()
    }

    // ========== Node-level harness API for testing ==========

    /// Receive bundle bytes from CLA (RFC 9171 §5.6 Bundle Reception)
    ///
    /// This is the entry point for bundles received from a convergence layer.
    /// Decodes, validates CRCs, and processes the bundle per §5.6.
    pub fn receive_bytes_from_cla(&mut self, bundle_bytes: &[u8]) -> Result<BundleId> {
        use crate::bp::codec::BundleCodec;

        // RFC 9171 §5.6 Step 3: Decode and validate CRCs
        // If CRC validation fails, bundle is rejected (not admitted to storage)
        let bundle = BundleCodec::decode(bundle_bytes)?;

        // Route through receive_from_cla for consistent validation
        self.receive_from_cla(bundle)
    }

    /// Receive pre-decoded bundle from CLA (for testing)
    ///
    /// Note: Use receive_bytes_from_cla() for production code to ensure CRC validation.
    pub fn receive_from_cla(&mut self, mut bundle: Bundle) -> Result<BundleId> {
        use crate::bp::processing::{ReceptionResult, process_on_reception};

        // RFC 9172 §3.3-3.4: Validate security blocks before processing
        #[cfg(feature = "bpsec-default")]
        {
            if let Err(e) = crate::security::validation::validate_security_blocks(&bundle) {
                // RFC 9172 §11.2 code 16: Conflicting security operation
                // Security validation failures that involve duplicate/conflicting operations generate code 16
                let error_msg = e.to_string();
                if (error_msg.contains("duplicate security operation")
                    || error_msg.contains("MUST be unique"))
                    && self.config.status_report_policy.report_on_deletion
                {
                    let report = StatusReport::deletion(
                        bundle.primary.source.clone(),
                        bundle.primary.creation_timestamp,
                        ReasonCode::ConflictingSecurityOperation,
                        None,
                    );
                    self.generated_reports.push(report);
                }
                // Security validation failure - delete bundle
                return Err(Error::new(
                    ErrorKind::ProtocolViolation,
                    format!("Security block validation failed: {}", e),
                ));
            }
        }

        // RFC 9172 §5, §8: Check security policy BEFORE processing (identify present operations)
        #[cfg(feature = "bpsec-default")]
        let present_security_ops = {
            use crate::bpa::security_policy::SecurityOperation;
            use std::collections::HashMap;

            let mut present_ops: HashMap<crate::bp::BlockType, Vec<SecurityOperation>> =
                HashMap::new();
            let mut operation_counts: HashMap<(crate::bp::BlockType, SecurityOperation), usize> =
                HashMap::new();

            for block in &bundle.blocks {
                match block.block_type {
                    crate::bp::BlockType::Bib => {
                        // Parse BIB to get targets and check context
                        if let Ok(bib) = crate::bpa::security_processing::parse_bib_block(block) {
                            // RFC 9172 §11.2 code 13: Unknown security context
                            if bib.context_id != 1 {
                                if self.config.status_report_policy.report_on_deletion {
                                    let report = StatusReport::deletion(
                                        bundle.primary.source.clone(),
                                        bundle.primary.creation_timestamp,
                                        ReasonCode::UnknownSecurityContext,
                                        None,
                                    );
                                    self.generated_reports.push(report);
                                }
                                return Err(Error::new(
                                    ErrorKind::SecurityFailure,
                                    format!("Unknown BIB context ID: {}", bib.context_id),
                                ));
                            }

                            for target in &bib.targets {
                                if let Some(target_block) =
                                    bundle.blocks.iter().find(|b| b.block_number == *target)
                                {
                                    present_ops
                                        .entry(target_block.block_type)
                                        .or_default()
                                        .push(SecurityOperation::Bib);

                                    // RFC 9172 §11.2 code 16: Track for conflict detection
                                    *operation_counts
                                        .entry((target_block.block_type, SecurityOperation::Bib))
                                        .or_insert(0) += 1;
                                }
                            }
                        }
                    }
                    crate::bp::BlockType::Bcb => {
                        // Parse BCB to get targets and check context
                        if let Ok(bcb) = crate::bpa::security_processing::parse_bcb_block(block) {
                            // RFC 9172 §11.2 code 13: Unknown security context
                            if bcb.context_id != 2 {
                                if self.config.status_report_policy.report_on_deletion {
                                    let report = StatusReport::deletion(
                                        bundle.primary.source.clone(),
                                        bundle.primary.creation_timestamp,
                                        ReasonCode::UnknownSecurityContext,
                                        None,
                                    );
                                    self.generated_reports.push(report);
                                }
                                return Err(Error::new(
                                    ErrorKind::SecurityFailure,
                                    format!("Unknown BCB context ID: {}", bcb.context_id),
                                ));
                            }

                            for target in &bcb.targets {
                                if let Some(target_block) =
                                    bundle.blocks.iter().find(|b| b.block_number == *target)
                                {
                                    present_ops
                                        .entry(target_block.block_type)
                                        .or_default()
                                        .push(SecurityOperation::Bcb);

                                    // RFC 9172 §11.2 code 16: Track for conflict detection
                                    *operation_counts
                                        .entry((target_block.block_type, SecurityOperation::Bcb))
                                        .or_insert(0) += 1;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // RFC 9172 §11.2 code 16: Conflict detection moved to validate_security_blocks()
            // to maintain single code path. The validation layer now generates reports for conflicts.

            // RFC 9172 §11.2 code 14: Check for forbidden operations (ION-style explicit forbid)
            #[cfg(feature = "bpsec-default")]
            if let Some(ref sec_policy) = self.config.security_policy {
                for (block_type, ops) in &present_ops {
                    for op in ops {
                        // Check if any rule explicitly forbids this operation
                        if let Some(rule) = sec_policy.find_matching_rule(
                            &bundle.primary.source,
                            &bundle.primary.destination,
                            None,
                            Some(*block_type),
                        ) && let Some(forbidden_op) = rule.forbidden_operation
                            && forbidden_op == *op
                        {
                            if self.config.status_report_policy.report_on_deletion {
                                let report = StatusReport::deletion(
                                    bundle.primary.source.clone(),
                                    bundle.primary.creation_timestamp,
                                    ReasonCode::UnexpectedSecurityOperation,
                                    None,
                                );
                                self.generated_reports.push(report);
                            }
                            return Err(Error::new(
                                ErrorKind::SecurityFailure,
                                format!("Forbidden {:?} operation on {:?}", op, block_type),
                            ));
                        }
                    }
                }
            }

            present_ops
        };

        // RFC 9172 §5.1: Process security operations
        // RFC9172-076: BCBs MUST be evaluated before BIBs when they share a target
        #[cfg(feature = "bpsec-default")]
        {
            let is_destination = self.is_local_destination(&bundle.primary.destination);
            if let Some(ref mut sec_ctx) = self.config.security_context {
                use crate::bpa::security_processing::{SecurityProcessingResult, process_bibs};

                // RFC 9172 §4.4: Process BCBs first (decrypt)
                match crate::bpa::security_processing::process_bcbs_ex(
                    &mut bundle,
                    sec_ctx,
                    is_destination,
                )? {
                    SecurityProcessingResult::Success => {
                        // BCB processing succeeded, continue
                    }
                    SecurityProcessingResult::BcbDecryptionFailed {
                        bcb_block_num,
                        target_block_num,
                    } => {
                        // RFC9172-079: Apply security failure policy
                        match sec_ctx.bcb_failure_policy {
                            crate::bpa::security_processing::SecurityFailurePolicy::DeleteBundle => {
                                // RFC9172-111: emit security reason codes per BPSec policy
                                if self.should_emit_security_reason_code() {
                                    let report = StatusReport::deletion(
                                        bundle.primary.source.clone(),
                                        bundle.primary.creation_timestamp,
                                        ReasonCode::FailedSecurityOperation, // RFC 9172 §11.2 code 15
                                        None,
                                    );
                                    self.generated_reports.push(report);
                                }
                                return Err(Error::new(
                                    ErrorKind::SecurityFailure,
                                    format!(
                                        "BCB {} decryption failed for target {}: DeleteBundle policy",
                                        bcb_block_num, target_block_num
                                    ),
                                ));
                            }
                            crate::bpa::security_processing::SecurityFailurePolicy::StripSecurityBlock => {
                                // Strip BCB and continue (ciphertext remains)
                                bundle.blocks.retain(|b| !matches!(b.block_type, crate::bp::BlockType::Bcb));
                            }
                        }
                    }
                    SecurityProcessingResult::BibVerificationFailed { .. } => {
                        // BCBs don't return BIB failures
                        unreachable!()
                    }
                }

                // RFC 9172 §4.3: Process BIBs second (verify)
                match process_bibs(&mut bundle, sec_ctx, is_destination)? {
                    SecurityProcessingResult::Success => {
                        // BIB processing succeeded, continue
                    }
                    SecurityProcessingResult::BibVerificationFailed {
                        bib_block_num,
                        target_block_num,
                    } => {
                        // RFC9172-079: Apply security failure policy
                        match sec_ctx.bib_failure_policy {
                            crate::bpa::security_processing::SecurityFailurePolicy::DeleteBundle => {
                                // RFC9172-111: emit security reason codes per BPSec policy
                                if self.should_emit_security_reason_code() {
                                    let report = StatusReport::deletion(
                                        bundle.primary.source.clone(),
                                        bundle.primary.creation_timestamp,
                                        ReasonCode::FailedSecurityOperation, // RFC 9172 §11.2 code 15
                                        None,
                                    );
                                    self.generated_reports.push(report);
                                }
                                return Err(Error::new(
                                    ErrorKind::SecurityFailure,
                                    format!(
                                        "BIB {} verification failed for target {}: DeleteBundle policy",
                                        bib_block_num, target_block_num
                                    ),
                                ));
                            }
                            crate::bpa::security_processing::SecurityFailurePolicy::StripSecurityBlock => {
                                // Strip BIB and continue (target data unverified)
                                bundle.blocks.retain(|b| !matches!(b.block_type, crate::bp::BlockType::Bib));
                            }
                        }
                    }
                    SecurityProcessingResult::BcbDecryptionFailed { .. } => {
                        // BIBs don't return BCB failures
                        unreachable!()
                    }
                }
            }
        }

        // RFC 9172 §5.1.1 & §5.1.2: Check security policy and execute configured actions
        #[cfg(feature = "bpsec-default")]
        {
            if let Some(ref sec_policy) = self.config.security_policy {
                use crate::bp::BlockType;
                use crate::bpa::security_policy::SecurityAction;

                // Check all block types that might have policy rules
                let block_types_to_check = vec![
                    BlockType::Payload,
                    BlockType::PreviousNode,
                    BlockType::BundleAge,
                    BlockType::HopCount,
                ];

                let mut should_delete = false;
                let mut should_report = false;
                let mut blocks_to_remove = Vec::new();

                for block_type in block_types_to_check {
                    // Check if required security operation is present
                    if sec_policy
                        .check_required_security(
                            &bundle.primary.source,
                            &bundle.primary.destination,
                            block_type,
                            &present_security_ops,
                        )
                        .is_err()
                    {
                        // RFC9172-084/098: Missing required security operation
                        // Get configured failure actions
                        let actions = sec_policy.get_failure_actions(
                            &bundle.primary.source,
                            &bundle.primary.destination,
                            None, // No security source for missing operation
                            Some(block_type),
                        );

                        for action in actions {
                            match action {
                                SecurityAction::DeleteBundle => {
                                    should_delete = true;
                                }
                                SecurityAction::RemoveTarget => {
                                    // RFC 9172 §5.1.1: "If the removed security target is the
                                    // payload block, the bundle MUST be discarded."
                                    if block_type == BlockType::Payload {
                                        should_delete = true;
                                    } else {
                                        blocks_to_remove.push(block_type);
                                    }
                                }
                                SecurityAction::Report => {
                                    should_report = true;
                                }
                            }
                        }
                    }
                }

                // Execute RemoveTarget actions (before admission to storage)
                if !blocks_to_remove.is_empty() {
                    bundle
                        .blocks
                        .retain(|b| !blocks_to_remove.contains(&b.block_type));
                }

                // Execute DeleteBundle action
                if should_delete {
                    // Generate report if requested (before deletion)
                    if should_report && self.config.status_report_policy.report_on_deletion {
                        let report = StatusReport::deletion(
                            bundle.primary.source.clone(),
                            bundle.primary.creation_timestamp,
                            ReasonCode::MissingSecurityOperation, // RFC 9172 §11.2 code 12
                            None, // Time will be added during poll() processing
                        );
                        self.generated_reports.push(report);
                    }

                    return Err(Error::new(
                        ErrorKind::SecurityFailure,
                        "Security policy violation: DeleteBundle action",
                    ));
                }

                // Execute Report action (bundle continues processing)
                if should_report && self.config.status_report_policy.report_on_deletion {
                    let report = StatusReport::deletion(
                        bundle.primary.source.clone(),
                        bundle.primary.creation_timestamp,
                        ReasonCode::MissingSecurityOperation, // RFC 9172 §11.2 code 12
                        None, // Time will be added during poll() processing
                    );
                    self.generated_reports.push(report);

                    // For Report-only action, we still reject the bundle
                    return Err(Error::new(
                        ErrorKind::SecurityFailure,
                        "Security policy violation: missing required security operation",
                    ));
                }
            }
        }

        // RFC 9172 §11.2 code 14: Unexpected security operation
        // Note: Code 14 is informational and applies only when policy explicitly forbids operations.
        // Per ION convention, absence of policy or absence of matching rule does NOT trigger code 14.
        // Valid secured bundles with no matching policy rule must be processed normally.
        // Code 14 generation requires explicit policy configuration (future enhancement).

        // RFC 9171 §5.6: Process block control flags for unintelligible blocks
        let reception_result = process_on_reception(&mut bundle)
            .map_err(|e| Error::new(ErrorKind::MalformedInput, e.to_string()))?;

        match reception_result {
            ReceptionResult::DeleteBundle(reason) => {
                // RFC 9171 §5.6: Delete bundle for block unintelligible
                let reason_code = match reason {
                    crate::bp::processing::DeletionReason::BlockUnsupported => {
                        ReasonCode::BlockUnsupported
                    }
                    _ => ReasonCode::NoAdditionalInformation,
                };
                return Err(Error::new(
                    ErrorKind::ProtocolViolation,
                    format!("Bundle rejected: {:?}", reason_code),
                ));
            }
            ReceptionResult::ReportFailure(reason) => {
                // RFC 9171 §5.6: Generate status report for block unintelligible
                // The bundle continues processing (not deleted like DeleteBundle case)
                let report_reason = match reason {
                    crate::bp::processing::DeletionReason::BlockUnsupported => {
                        ReasonCode::BlockUnsupported
                    }
                    _ => ReasonCode::NoAdditionalInformation,
                };

                // Admit bundle to storage first
                let bundle_id = self.storage.admit(bundle.clone())?;

                // RFC 9171 §5.6: Add DispatchPending retention constraint
                let mut constraints = RetentionConstraintSet::new();
                constraints.add(RetentionConstraint::DispatchPending);

                // Record metadata
                self.metadata.insert(
                    bundle_id.clone(),
                    BundleMetadata {
                        state: BundleState::Admitted,
                        _admitted_at: self.current_time,
                        _hops: 0,
                        retention_constraints: constraints,
                    },
                );

                // RFC 9171 §5.6: Generate status report with reason code for unintelligible block
                if let Some(mut report) =
                    self.generate_reception_status_report(&bundle_id, self.current_time)
                {
                    // Set the reason code to BlockUnintelligible
                    report.reason_code = report_reason;
                    self.generated_reports.push(report);
                }

                return Ok(bundle_id);
            }
            ReceptionResult::Accepted => {
                // Continue with normal reception
            }
        }

        // RFC 9171 §5.7 Step 1 & §5.9: Check if bundle is a fragment
        let bundle_is_fragment = bundle.primary.is_fragment();

        if bundle_is_fragment {
            // RFC 9171 §5.9: Reassembly key is (source, timestamp, total_length)
            // NOT fragment-specific (without offset)
            let reassembly_key = BundleId::new(
                bundle.primary.source.clone(),
                bundle.primary.creation_timestamp,
            );
            match self
                .reassembly
                .add_fragment(reassembly_key.clone(), &bundle)?
            {
                Some(reassembled_payload) => {
                    // RFC 9171 §5.9: Reassembly complete
                    // Create reassembled bundle with complete payload
                    let mut reassembled = bundle.clone();
                    reassembled.primary.fragment_offset = None;
                    reassembled.primary.total_app_data_length = None;
                    // Remove is-fragment flag (bit 20)
                    reassembled.primary.bundle_flags &= !0x100000;

                    // Replace payload
                    if let Some(payload_idx) = reassembled
                        .blocks
                        .iter()
                        .position(|b| b.block_type == crate::bp::BlockType::Payload)
                    {
                        reassembled.blocks[payload_idx].data = reassembled_payload;
                    }

                    // RFC 9171 §5.9: "The 'Reassembly pending' retention constraint MUST be removed
                    // from every other fragment with the same source node ID and creation timestamp"
                    // Delete all fragments that were stored with ReassemblyPending
                    let fragments_to_delete: Vec<BundleId> = self
                        .metadata
                        .iter()
                        .filter_map(|(id, meta)| {
                            // Check if this bundle has ReassemblyPending constraint
                            if !meta.has_constraint(RetentionConstraint::ReassemblyPending) {
                                return None;
                            }
                            // Get the bundle to check source and timestamp
                            if let Some(frag_bundle) = self.storage.get(id) {
                                // Check if source and timestamp match
                                if frag_bundle.primary.source == bundle.primary.source
                                    && frag_bundle.primary.creation_timestamp
                                        == bundle.primary.creation_timestamp
                                {
                                    return Some(id.clone());
                                }
                            }
                            None
                        })
                        .collect();

                    // Delete fragments from storage and metadata
                    for frag_id in fragments_to_delete {
                        let _ = self.storage.remove(&frag_id);
                        self.metadata.remove(&frag_id);
                        self.deleted.insert(frag_id);
                    }

                    // Admit reassembled bundle to storage
                    let bundle_id = self.storage.admit(reassembled)?;

                    // RFC 9171 §5.6: Add DispatchPending retention constraint
                    let mut constraints = RetentionConstraintSet::new();
                    constraints.add(RetentionConstraint::DispatchPending);

                    // Record metadata
                    self.metadata.insert(
                        bundle_id.clone(),
                        BundleMetadata {
                            state: BundleState::Admitted,
                            _admitted_at: self.current_time,
                            _hops: 0,
                            retention_constraints: constraints,
                        },
                    );

                    return Ok(bundle_id);
                }
                None => {
                    // RFC 9171 §5.7 Step 1 & §5.45: Reassembly not yet complete
                    // Store fragment with ReassemblyPending retention constraint
                    // "the retention constraint 'Reassembly pending' MUST be added to the bundle"

                    let fragment_bundle_id = bundle.id();

                    // RFC 9171 §5.7: Check for duplicate fragment (retransmission)
                    // If already stored with identical data, skip re-admission
                    if self.storage.get(&fragment_bundle_id).is_some() {
                        // Duplicate fragment already in storage
                        return Ok(fragment_bundle_id);
                    }

                    self.storage.admit(bundle)?;

                    let mut constraints = RetentionConstraintSet::new();
                    constraints.add(RetentionConstraint::ReassemblyPending);

                    self.metadata.insert(
                        fragment_bundle_id.clone(),
                        BundleMetadata {
                            state: BundleState::Admitted,
                            _admitted_at: self.current_time,
                            _hops: 0,
                            retention_constraints: constraints,
                        },
                    );

                    // RFC 9171 §5.45: "all remaining steps of this procedure MUST be skipped"
                    // Return early - no dispatch, no status report
                    return Ok(fragment_bundle_id);
                }
            }
        }

        // Admit bundle to storage
        let bundle_id = self.storage.admit(bundle)?;

        // RFC 9171 §5.6: Add DispatchPending retention constraint
        let mut constraints = RetentionConstraintSet::new();
        constraints.add(RetentionConstraint::DispatchPending);

        // Record metadata
        self.metadata.insert(
            bundle_id.clone(),
            BundleMetadata {
                state: BundleState::Admitted,
                _admitted_at: self.current_time,
                _hops: 0,
                retention_constraints: constraints,
            },
        );

        // RFC 9171 §5.6: Generate reception status report if requested
        if let Some(report) = self.generate_reception_status_report(&bundle_id, self.current_time) {
            self.generated_reports.push(report);
        }

        Ok(bundle_id)
    }

    /// Send bundle from application (RFC 9171 §5.2 Bundle Transmission)
    ///
    /// Originate a bundle and mark it DispatchPending so poll() forwards it.
    ///
    /// When `outbound_bcb` is configured, applies a BCB to the payload with a
    /// unique IV registered in NonceRegistry (RFC 9173 §4.6 / §4.8.1).
    pub fn send(&mut self, mut bundle: Bundle) -> Result<BundleId> {
        // RFC 9173 §4.6/§4.8.1: Apply outbound BCB with unique (key, IV) pairing
        #[cfg(feature = "bpsec-default")]
        {
            if self.config.outbound_bcb.is_some() {
                bundle = self.apply_outbound_bcb(bundle)?;
            }
        }

        // RFC9171-4-051: primary CRC type MUST be non-zero unless a BIB targets
        // the primary block. Origination path applies CRC-16 when the builder left
        // CRC as None and no primary BIB is present.
        ensure_primary_crc_policy(&mut bundle)?;

        let bundle_id = self.admit_bundle(bundle, self.current_time)?;
        // RFC 9171 §5.2 → §5.3: originated bundles enter dispatch
        self.add_retention_constraint(&bundle_id, RetentionConstraint::DispatchPending)?;
        Ok(bundle_id)
    }

    /// Apply outbound BCB with unique IV (RFC 9173 §4.6 / §4.8.1)
    ///
    /// Mints a unique IV via OutboundBcbConfig counter, registers it in
    /// NonceRegistry (fails on reuse), encrypts payload, and inserts BCB.
    /// When `pre_bib_targets` is configured, applies a multi-target BIB first and
    /// performs RFC 9172 §3.9 BIB split + new-BIB encryption on partial overlap.
    #[cfg(feature = "bpsec-default")]
    fn apply_outbound_bcb(&mut self, mut bundle: Bundle) -> Result<Bundle> {
        use crate::bp::BlockType;
        use crate::security::bcb::{BcbConfig, BcbTargets, generate_bcb};
        use crate::security::bib::{
            BibConfig, BibTargets, generate_bib, split_bibs_for_partial_bcb_targets,
            strip_crc_from_security_targets,
        };

        let local_eid = self.config.local_eid.clone();

        // Snapshot outbound fields we need (avoid holding &mut across generates)
        let (mut pre_bib_targets, bib_hmac_key, bib_sha_variant, key_id, key, aes_variant) = {
            let outbound = self
                .config
                .outbound_bcb
                .as_mut()
                .ok_or_else(|| Error::protocol_violation("outbound_bcb config missing"))?;
            (
                outbound.pre_bib_targets.clone(),
                outbound.bib_hmac_key.as_ref().map(|k| k.to_vec()),
                outbound.bib_sha_variant,
                outbound.key_id.clone(),
                outbound.key.to_vec(),
                outbound.aes_variant,
            )
        };

        // RFC9172-108: recommended policy covers every block (primary + extensions + payload)
        let every_block = self
            .config
            .security_policy
            .as_ref()
            .is_some_and(|p| p.applies_to_every_block());
        if every_block && bib_hmac_key.is_some() {
            let mut targets: Vec<u64> = vec![0]; // primary
            for b in &bundle.blocks {
                if !matches!(b.block_type, BlockType::Bib | BlockType::Bcb) {
                    targets.push(b.block_number);
                }
            }
            targets.sort_unstable();
            targets.dedup();
            pre_bib_targets = Some(targets);
        }

        let gen_policy = self
            .config
            .security_context
            .as_ref()
            .map(|c| c.generation_failure_policy)
            .unwrap_or_default();

        // Optional multi-target BIB before BCB (sets up §3.9 partial-overlap case)
        if let (Some(targets), Some(hmac_key), Some(sha_variant)) =
            (&pre_bib_targets, &bib_hmac_key, bib_sha_variant)
        {
            // RFC9173-027/029: strip CRC from BIB targets before IPPT generation
            strip_crc_from_security_targets(&mut bundle, targets);
            match generate_bib(
                &bundle,
                &BibConfig {
                    security_source: local_eid.clone(),
                    targets: BibTargets {
                        block_numbers: targets.clone(),
                    },
                    sha_variant,
                    key: hmac_key.clone(),
                    wrapped_key: None,
                    scope_flags: 0x00,
                    #[cfg(feature = "test-fixtures")]
                    skip_source_validation: true,
                    #[cfg(feature = "test-fixtures")]
                    hmac_key_policy: None,
                },
            ) {
                Ok(mut bib) => {
                    let bib_num = bundle
                        .blocks
                        .iter()
                        .map(|b| b.block_number)
                        .max()
                        .unwrap_or(0)
                        + 1;
                    bib.block_number = bib_num;
                    bundle.blocks.insert(0, bib);
                }
                Err(e) => match gen_policy {
                    // RFC9173-040: process generation problems per local policy
                    crate::bpa::security_processing::SecurityGenerationPolicy::FailClosed => {
                        return Err(e);
                    }
                    crate::bpa::security_processing::SecurityGenerationPolicy::OmitSecurityOperation => {
                        // Continue without the BIB
                    }
                },
            }
        }

        let payload_num = bundle
            .blocks
            .iter()
            .find(|b| matches!(b.block_type, BlockType::Payload))
            .map(|b| b.block_number)
            .ok_or_else(|| Error::protocol_violation("No payload block for outbound BCB"))?;

        // RFC 9172 §3.9: split multi-target BIBs that partially overlap the BCB target
        let mut bibs_to_encrypt = Vec::new();
        if let (Some(hmac_key), Some(sha_variant)) = (&bib_hmac_key, bib_sha_variant) {
            bibs_to_encrypt = split_bibs_for_partial_bcb_targets(
                &mut bundle,
                &[payload_num],
                hmac_key,
                sha_variant,
                &local_eid,
            )?;
        }

        // RFC9173-091: strip CRC from BCB target before encryption
        strip_crc_from_security_targets(&mut bundle, &[payload_num]);

        let plaintext_len = bundle
            .blocks
            .iter()
            .find(|b| b.block_number == payload_num)
            .map(|b| b.data.len())
            .unwrap_or(0);

        // Encrypt payload (erratum 7002: one target per BCB)
        let iv = self.config.outbound_bcb.as_mut().unwrap().next_iv();
        let bcb_num = bundle
            .blocks
            .iter()
            .map(|b| b.block_number)
            .max()
            .unwrap_or(0)
            + 1;
        let bcb_config = BcbConfig {
            security_source: local_eid.clone(),
            targets: BcbTargets {
                block_numbers: vec![payload_num],
            },
            aes_variant,
            key: key.clone(),
            iv,
            wrapped_key: None,
            scope_flags: 0x00,
            key_id: Some(key_id.clone()),
            #[cfg(feature = "test-fixtures")]
            skip_source_validation: true,
        };
        let gen_result = generate_bcb(&bundle, &bcb_config, Some(&mut self.nonce_registry));
        let (mut bcb_block, ciphertexts) = match gen_result {
            Ok(v) => v,
            Err(e) => match gen_policy {
                // RFC9173-111: process encryption problems per local policy
                crate::bpa::security_processing::SecurityGenerationPolicy::FailClosed => {
                    return Err(e);
                }
                crate::bpa::security_processing::SecurityGenerationPolicy::OmitSecurityOperation => {
                    return Ok(bundle);
                }
            },
        };
        // RFC9172-109/110: ciphertext+tag is larger than plaintext for AES-GCM;
        // policy decides whether that expansion is permitted.
        const AES_GCM_TAG_LEN: usize = 16;
        let effective_ct_len = ciphertexts[0].len() + AES_GCM_TAG_LEN;
        if effective_ct_len > plaintext_len {
            let permitted = self
                .config
                .security_policy
                .as_ref()
                .map(|p| p.permits_ciphertext_expansion())
                .unwrap_or(true);
            if !permitted {
                return Err(Error::policy_rejected(
                    "RFC9172-110: security policy forbids ciphertext larger than plaintext",
                ));
            }
        }
        bcb_block.block_number = bcb_num;
        // RFC9172-041/050: generated BCB must not set delete/discard-on-failure flags
        debug_assert_eq!(
            bcb_block.block_flags
                & (crate::bp::BlockFlags::DELETE_BUNDLE_ON_FAILURE
                    | crate::bp::BlockFlags::DISCARD_BLOCK_ON_FAILURE),
            0
        );
        if let Some(payload) = bundle
            .blocks
            .iter_mut()
            .find(|b| b.block_number == payload_num)
        {
            payload.data = ciphertexts[0].clone();
        }
        bundle.blocks.insert(0, bcb_block);

        // RFC 9172 §3.9 / RFC9172-067: encrypt BIBs covering encrypted targets
        for bib_num in bibs_to_encrypt {
            strip_crc_from_security_targets(&mut bundle, &[bib_num]);
            let iv = self.config.outbound_bcb.as_mut().unwrap().next_iv();
            let bcb_num = bundle
                .blocks
                .iter()
                .map(|b| b.block_number)
                .max()
                .unwrap_or(0)
                + 1;
            let bib_bcb_config = BcbConfig {
                security_source: local_eid.clone(),
                targets: BcbTargets {
                    block_numbers: vec![bib_num],
                },
                aes_variant,
                key: key.clone(),
                iv,
                wrapped_key: None,
                scope_flags: 0x00,
                key_id: Some(key_id.clone()),
                #[cfg(feature = "test-fixtures")]
                skip_source_validation: true,
            };
            let (mut bib_bcb, bib_cts) =
                generate_bcb(&bundle, &bib_bcb_config, Some(&mut self.nonce_registry))?;
            bib_bcb.block_number = bcb_num;
            if let Some(bib_block) = bundle.blocks.iter_mut().find(|b| b.block_number == bib_num) {
                bib_block.data = bib_cts[0].clone();
            }
            bundle.blocks.insert(0, bib_bcb);
        }

        // RFC9172-109: account for post-BCB size in storage capacity and MTU scheduling
        let account_size = self
            .config
            .security_policy
            .as_ref()
            .is_some_and(|p| p.accounts_for_block_size_changes());
        if account_size {
            let encoded = crate::bp::encode(&bundle)?;
            let post_bytes = encoded.len() as u64;
            self.last_accounted_bundle_bytes = Some(post_bytes);
            let available = self.storage.usage().available().0;
            if post_bytes > available {
                return Err(Error::insufficient_storage(
                    crate::types::Bytes(post_bytes),
                    crate::types::Bytes(available),
                ));
            }
            if let Some(mtu) = self.config.cla_mtu
                && post_bytes > mtu.0
                && bundle.primary.must_not_fragment()
            {
                return Err(Error::new(
                    ErrorKind::TransferFailed,
                    format!(
                        "RFC9172-109: post-BCB size {post_bytes} exceeds MTU {} (must-not-fragment)",
                        mtu.0
                    ),
                ));
            }
        }

        Ok(bundle)
    }

    /// Drive bundle processing (RFC 9171 §5)
    ///
    /// Process expiration, forwarding, and other time-driven events.
    /// This is the main processing loop for node-level testing.
    pub fn poll(&mut self, now: SimInstant) {
        self.current_time = now;

        // RFC 9171 §5.11: Check for expired bundles
        let expired_bundles = self.find_expired_bundles(now);
        for bundle_id in expired_bundles {
            // RFC 9171 §5.11: Delete with reason code LifetimeExpired
            let _ = self.delete_bundle(&bundle_id, crate::bpa::admin::ReasonCode::LifetimeExpired);
        }

        // RFC 9171 §5.3: Process bundles in DispatchPending state
        // This is the production forwarding path that populates cla_tx_queue
        self.process_dispatch_pending();

        // RFC 9174 §4.1: Process connection requests with backoff
        // Must come AFTER dispatch so cla_tx_queue is populated
        self.process_connection_requests(now);

        // RFC9171-5-018: process CLA send-complete events (extension hook)
        self.process_cla_send_complete();
    }

    /// RFC9171-5-018: when an extension has registered a CLA-finish report hook,
    /// emit a status report with the extension-mandated reason code.
    fn process_cla_send_complete(&mut self) {
        while let Some(bundle_id) = self.cla_send_complete_pending.pop_front() {
            let Some(reason) = self.extension_cla_finish_report_reason else {
                // No extension mandate — drain silently
                continue;
            };
            let Some(bundle) = self.storage.get(&bundle_id).cloned() else {
                continue;
            };
            let mut report = crate::bpa::admin::StatusReport::forwarding(
                bundle.primary.source.clone(),
                bundle.primary.creation_timestamp,
                Some(self.current_time),
            );
            report.reason_code = reason;
            Self::attach_fragment_fields(&mut report, &bundle);
            self.generated_reports.push(report);
            // CLA finished: drop from tx queue
            self.cla_tx_queue.retain(|t| t.bundle_id != bundle_id);
        }
    }

    /// RFC 9174 §4.1: Process connection requests with backoff
    ///
    /// For each unique destination in cla_tx_queue, attempt to emit a connection
    /// request if the ConnectionManager allows it (respecting minimum delay and
    /// exponential backoff per RFC 9174 §4.1).
    ///
    /// Without `tcpclv4-model`, emits a request for every pending destination
    /// (no retry/backoff state machine).
    fn process_connection_requests(&mut self, now: SimInstant) {
        // Collect unique destination nodes from pending transmissions
        let mut destinations = std::collections::HashSet::new();
        for transmission in &self.cla_tx_queue {
            destinations.insert(transmission.destination_node.clone());
        }

        #[cfg(feature = "tcpclv4-model")]
        {
            // Convert SimInstant to TimeMs for ConnectionManager
            let now_ms = now.as_nanos() / 1_000_000;

            // For each destination, attempt connection if allowed by backoff
            for dest in destinations {
                let result = self
                    .connection_manager
                    .attempt_connect(&dest.to_string(), now_ms);

                match result {
                    ConnectionResult::Success => {
                        // RFC 9174 §4.1: Connection attempt is allowed, emit request
                        self.connection_requests.push(ConnectionRequest {
                            peer: dest,
                            time: now,
                        });
                    }
                    ConnectionResult::Backoff { .. } => {
                        // RFC 9174 §4.1-003/007: Blocked by backoff, don't overwhelm target
                        // No connection request emitted
                    }
                    _ => {}
                }
            }
        }

        #[cfg(not(feature = "tcpclv4-model"))]
        {
            for dest in destinations {
                self.connection_requests.push(ConnectionRequest {
                    peer: dest,
                    time: now,
                });
            }
        }
    }

    /// RFC 9171 §5.3: Bundle Dispatching
    ///
    /// Process all bundles with DispatchPending retention constraint.
    /// This implements the production forwarding path that determines whether
    /// a bundle should be locally delivered or forwarded to another node.
    ///
    /// ION Convention: This is deterministic and synchronous, driven by poll().
    fn process_dispatch_pending(&mut self) {
        // Collect bundle IDs with DispatchPending constraint
        let pending_bundles: Vec<BundleId> = self
            .metadata
            .iter()
            .filter(|(_, meta)| {
                meta.retention_constraints
                    .has(RetentionConstraint::DispatchPending)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for bundle_id in pending_bundles {
            // RFC 9171 §5.3 Step 1: Check if destination is local
            if let Some(bundle) = self.storage.get(&bundle_id) {
                let dest = &bundle.primary.destination;

                if self.is_local_destination(dest) {
                    // RFC 9171 §5.7: Local delivery
                    if self.config.enable_delivery {
                        let _ = self.deliver_bundle_internal(&bundle_id);
                    } else {
                        // Delivery disabled: forwarding contraindicated
                        let _ = self.delete_bundle(&bundle_id, ReasonCode::NoKnownRoute);
                    }
                } else {
                    // RFC 9171 §5.4: Forward bundle
                    if self.config.enable_forwarding {
                        let _ = self.forward_bundle_internal(&bundle_id);
                    } else {
                        // Forwarding disabled: contraindicated
                        let _ = self.delete_bundle(&bundle_id, ReasonCode::NoKnownRoute);
                    }
                }
            }
        }
    }

    /// RFC 9171 §5.4: Internal forwarding implementation
    ///
    /// This is called by process_dispatch_pending() and implements the production
    /// forwarding path with deterministic next-hop selection.
    fn forward_bundle_internal(&mut self, bundle_id: &BundleId) -> Result<()> {
        // Get bundle to check destination
        let bundle = self
            .storage
            .get(bundle_id)
            .ok_or_else(|| Error::not_found("Bundle not in storage"))?
            .clone();

        // RFC 9758 §5.4: LocalNode ipn EIDs MUST NOT leave the local node
        // Check these BEFORE route lookup since they're absolute constraints
        if bundle.primary.source.is_local_node() || bundle.primary.destination.is_local_node() {
            self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
            return Err(Error::policy_rejected(
                "RFC 9758 §5.4: LocalNode ipn EID MUST NOT leave local node",
            ));
        }

        if bundle.primary.report_to.is_local_node() {
            self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
            return Err(Error::policy_rejected(
                "RFC 9758 §5.4: LocalNode ipn EID in report-to MUST NOT leave local node",
            ));
        }

        // RFC 9171 §5.4: Determine next hop from routing table
        let next_hop = if let Some(ref routes) = self.config.static_routes {
            routes.get(&bundle.primary.destination).cloned()
        } else {
            None
        };

        // RFC9758-011, RFC9758-030: Check Private Use restrictions before route check
        if self.config.enforce_private_use_restrictions {
            let crosses_boundary = match next_hop {
                Some(ref hop) => self.crosses_domain_boundary(hop),
                None => true,
            };

            if crosses_boundary {
                if bundle.primary.source.is_private_use_ipn()
                    || bundle.primary.destination.is_private_use_ipn()
                {
                    self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
                    return Err(Error::policy_rejected(
                        "RFC 9758 §5.5: Private Use ipn EID MUST NOT cross administrative domains",
                    ));
                }

                if bundle.primary.report_to.is_private_use_ipn() {
                    self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
                    return Err(Error::policy_rejected(
                        "RFC 9758 §5.5: Private Use ipn EID in report-to MUST NOT cross domains",
                    ));
                }
            }
        }

        // If no route found, forwarding is contraindicated (§5.4.1)
        if next_hop.is_none() {
            // RFC 9171 §5.4.1: Forwarding contraindicated
            // RFC 9171 §5.4.2: Forwarding Failed procedure
            self.handle_forwarding_failed(bundle_id, ReasonCode::NoKnownRoute)?;
            return Err(Error::new(
                ErrorKind::NoRoute,
                "No known route to destination",
            ));
        }

        // Forward to the determined next hop
        self.forward_bundle_to(bundle_id, next_hop.as_ref())
    }

    /// RFC 9171 §5.4.2: Handle Forwarding Failed
    ///
    /// Called when forwarding is contraindicated (no route, bundle too large, etc.)
    /// Applies the configured forwarding_failed_policy:
    /// - Delete: delete bundle with given reason code
    /// - ReturnToPreviousNode: attempt to return to previous node, else delete
    /// - Retain: keep bundle in storage without deleting
    fn handle_forwarding_failed(&mut self, bundle_id: &BundleId, reason: ReasonCode) -> Result<()> {
        use crate::bp::BlockType;
        use crate::bp::extensions::PreviousNodeBlock;
        use crate::bpa::policy::ForwardingFailedPolicy;

        match self.config.forwarding_failed_policy {
            ForwardingFailedPolicy::Delete => {
                // RFC 9171 §5.4.2: "Otherwise, the bundle MUST be deleted"
                self.delete_bundle(bundle_id, reason)?;
            }

            ForwardingFailedPolicy::ReturnToPreviousNode => {
                // RFC 9171 §5.4.2 Step 1: "The BPA MAY forward the bundle back to the
                // node that sent it, as identified by the Previous Node Block, if present"

                let bundle = self
                    .storage
                    .get(bundle_id)
                    .ok_or_else(|| Error::not_found("Bundle not in storage"))?;

                // Find Previous Node block
                let prev_node_block = bundle.blocks.iter().find_map(|b| {
                    if b.block_type == BlockType::PreviousNode {
                        PreviousNodeBlock::from_canonical(b).ok()
                    } else {
                        None
                    }
                });

                if let Some(prev_node) = prev_node_block {
                    // Check if previous node differs from local node (avoid loops)
                    if prev_node.previous_node != self.config.local_eid {
                        // RFC 9171 §5.4.2 Step 2: "This forwarding, if performed, SHALL be
                        // accomplished by performing Step 4 and Step 5 of Section 5.4"
                        // Step 3: "where the sole node selected for forwarding SHALL be the
                        // node that sent the bundle"

                        // Extract NodeId from previous node EID
                        if let Ok(node_id) = NodeId::from_endpoint(&prev_node.previous_node) {
                            // Forward to previous node (bypasses route lookup)
                            return self.forward_bundle_to(bundle_id, Some(&node_id));
                        }
                    }
                }

                // No previous node or previous node is local: fall back to delete
                // RFC 9171 §5.4.2: "Otherwise, the bundle MUST be deleted"
                self.delete_bundle(bundle_id, reason)?;
            }

            ForwardingFailedPolicy::Retain => {
                // Retain bundle in storage without deleting
                // Bundle keeps ForwardPending constraint (already set by forward_bundle_to)
                // This allows manual intervention or policy changes to retry forwarding
            }
        }

        Ok(())
    }

    /// RFC 9171 §5.7: Internal local delivery implementation
    fn deliver_bundle_internal(&mut self, bundle_id: &BundleId) -> Result<()> {
        // Remove DispatchPending constraint
        let _ = self.remove_retention_constraint(bundle_id, RetentionConstraint::DispatchPending);

        // Get bundle
        let bundle = self
            .storage
            .get(bundle_id)
            .ok_or_else(|| Error::not_found("Bundle not in storage"))?
            .clone();

        // Check if admin record (no delivery for admin records per RFC 9171 §6)
        // Bit 0 of bundle_flags indicates administrative record
        if (bundle.primary.bundle_flags & 0x000001) != 0 {
            // Admin records are not delivered to applications
            // They're processed by the BPA itself
            self.delete_bundle(bundle_id, ReasonCode::NoAdditionalInformation)?;
            return Ok(());
        }

        // Add to delivered ADUs
        self.delivered_adus.push(bundle.clone());
        self.delivered.insert(bundle_id.clone());

        // Generate delivery status report if requested
        if let Some(report) = self.generate_delivery_status_report(bundle_id, self.current_time) {
            self.generated_reports.push(report);
        }

        // RFC 9171 §5.7: Delivery successful, remove bundle
        self.delete_bundle(bundle_id, ReasonCode::NoAdditionalInformation)?;

        Ok(())
    }

    /// Get CLA transmission queue (observable output)
    pub fn cla_tx_queue(&self) -> &VecDeque<ClaTransmission> {
        &self.cla_tx_queue
    }

    /// Get delivered ADUs (observable output)
    pub fn delivered_adus(&self) -> &[Bundle] {
        &self.delivered_adus
    }

    /// Get generated status reports (observable output)
    pub fn generated_reports(&self) -> &[StatusReport] {
        &self.generated_reports
    }

    /// Get connection requests (observable output, RFC 9174 §4.1 compliant)
    pub fn connection_requests(&self) -> &[ConnectionRequest] {
        &self.connection_requests
    }

    /// Record a connection failure (RFC 9174 §4.1)
    #[cfg(feature = "tcpclv4-model")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tcpclv4-model")))]
    pub fn record_connection_failure(&mut self, peer: &NodeId) {
        self.connection_manager.record_failure(&peer.to_string());
    }

    /// Record a successful connection (RFC 9174 §4.1)
    #[cfg(feature = "tcpclv4-model")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tcpclv4-model")))]
    pub fn record_connection_success(&mut self, peer: &NodeId) {
        self.connection_manager.record_success(&peer.to_string());
    }

    /// Clear generated reports (for test harness)
    pub fn clear_generated_reports(&mut self) {
        self.generated_reports.clear();
    }

    /// Get bundle metadata (for test verification)
    pub fn get_metadata(&self, bundle_id: &BundleId) -> Option<&BundleMetadata> {
        self.metadata.get(bundle_id)
    }

    /// Clear CLA transmission queue (for test harness)
    pub fn clear_cla_tx_queue(&mut self) {
        self.cla_tx_queue.clear();
    }

    /// Add retention constraint to bundle
    pub fn add_retention_constraint(
        &mut self,
        bundle_id: &BundleId,
        constraint: RetentionConstraint,
    ) -> Result<()> {
        if let Some(meta) = self.metadata.get_mut(bundle_id) {
            meta.retention_constraints.add(constraint);
            Ok(())
        } else {
            Err(Error::not_found("Bundle not found"))
        }
    }

    /// Remove retention constraint from bundle
    pub fn remove_retention_constraint(
        &mut self,
        bundle_id: &BundleId,
        constraint: RetentionConstraint,
    ) -> Result<()> {
        if let Some(meta) = self.metadata.get_mut(bundle_id) {
            meta.retention_constraints.remove(constraint);
            Ok(())
        } else {
            Err(Error::not_found("Bundle not found"))
        }
    }

    /// Check if bundle has any retention constraints
    pub fn has_retention_constraints(&self, bundle_id: &BundleId) -> bool {
        self.metadata
            .get(bundle_id)
            .map(|m| !m.retention_constraints.is_empty())
            .unwrap_or(false)
    }

    /// Check if bundle has specific retention constraint
    pub fn has_retention_constraint(
        &self,
        bundle_id: &BundleId,
        constraint: RetentionConstraint,
    ) -> bool {
        self.metadata
            .get(bundle_id)
            .map(|m| m.retention_constraints.has(constraint))
            .unwrap_or(false)
    }

    /// Forward bundle to specific next hop (RFC9758-011, RFC9758-030)
    ///
    /// PRIVATE: Tests must use production path (receive_from_cla + poll).
    /// This is called internally by forward_bundle_internal().
    fn forward_bundle_to(&mut self, bundle_id: &BundleId, next_hop: Option<&NodeId>) -> Result<()> {
        use crate::bp::BlockType;
        use crate::bp::extensions::{BundleAgeBlock, HopCountBlock, PreviousNodeBlock};

        // RFC 9171 §5.4 Step 1: Add ForwardPending retention constraint
        self.add_retention_constraint(bundle_id, RetentionConstraint::ForwardPending)?;

        // RFC 9171 §5.4: Remove DispatchPending if present
        let _ = self.remove_retention_constraint(bundle_id, RetentionConstraint::DispatchPending);

        let mut bundle = self
            .storage
            .get(bundle_id)
            .ok_or_else(|| Error::not_found("Bundle not in storage"))?
            .clone();

        // RFC 9758 §5.4: LocalNode ipn EIDs MUST NOT leave the local node
        // RFC9758-022, 023: Reject forwarding bundles with LocalNode source or destination
        if bundle.primary.source.is_local_node() || bundle.primary.destination.is_local_node() {
            self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
            return Err(Error::policy_rejected(
                "RFC 9758 §5.4: LocalNode ipn EID MUST NOT leave local node",
            ));
        }

        // RFC9758-024, 025: Check report-to field for LocalNode
        if bundle.primary.report_to.is_local_node() {
            self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
            return Err(Error::policy_rejected(
                "RFC 9758 §5.4: LocalNode ipn EID in report-to MUST NOT leave local node",
            ));
        }

        // RFC9758-011, RFC9758-030: Domain boundary check
        if self.config.enforce_private_use_restrictions {
            let crosses_boundary = match next_hop {
                Some(hop) => self.crosses_domain_boundary(hop),
                None => true,
            };

            if crosses_boundary {
                if bundle.primary.source.is_private_use_ipn()
                    || bundle.primary.destination.is_private_use_ipn()
                {
                    self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
                    return Err(Error::policy_rejected(
                        "RFC 9758 §5.5: Private Use ipn EID MUST NOT cross administrative domains",
                    ));
                }

                if bundle.primary.report_to.is_private_use_ipn() {
                    self.delete_bundle(bundle_id, ReasonCode::NoKnownRoute)?;
                    return Err(Error::policy_rejected(
                        "RFC 9758 §5.5: Private Use ipn EID in report-to MUST NOT cross domains",
                    ));
                }
            }
        }

        // Note: Route checking is done in forward_bundle_internal() (production path)
        // This method can be called directly by tests with a specific next_hop

        // RFC 9171 §5.8: Check if fragmentation is needed
        if let Some(mtu) = self.config.cla_mtu {
            let encoded = crate::bp::encode(&bundle)?;
            if encoded.len() as u64 > mtu.0 {
                // Bundle exceeds MTU
                if bundle.primary.must_not_fragment() {
                    // RFC 9171 §5.4.2: Forwarding contraindicated - bundle too large to forward
                    // without fragmentation. Apply Forwarding Failed procedure.
                    self.handle_forwarding_failed(bundle_id, ReasonCode::NoKnownRoute)?;
                    return Err(Error::new(
                        ErrorKind::TransferFailed,
                        "Bundle exceeds MTU but has must-not-fragment flag",
                    ));
                }

                // Apply forwarding updates to original bundle before fragmenting
                // This ensures age/hop/previous node are set correctly
                use crate::bp::BlockType;
                use crate::bp::extensions::{BundleAgeBlock, HopCountBlock, PreviousNodeBlock};

                // Update bundle age
                if let Some(age_idx) = bundle
                    .blocks
                    .iter()
                    .position(|b| b.block_type == BlockType::BundleAge)
                {
                    let mut age_block = BundleAgeBlock::from_canonical(&bundle.blocks[age_idx])?;
                    let residence_time = if let Some(meta) = self.metadata.get(bundle_id) {
                        self.current_time
                            .duration_since(meta._admitted_at)
                            .unwrap_or(crate::types::SimDuration::ZERO)
                            .as_millis()
                    } else {
                        0
                    };
                    age_block.age_ms += residence_time;
                    bundle.blocks[age_idx] = age_block.to_canonical()?;
                }

                // Increment hop count
                if let Some(hop_idx) = bundle
                    .blocks
                    .iter()
                    .position(|b| b.block_type == BlockType::HopCount)
                {
                    let mut hop_block = HopCountBlock::from_canonical(&bundle.blocks[hop_idx])?;
                    hop_block.hop_count += 1;
                    bundle.blocks[hop_idx] = hop_block.to_canonical()?;
                }

                // Insert previous node block (never reuse payload block number 1)
                if let Some(prev_idx) = bundle
                    .blocks
                    .iter()
                    .position(|b| b.block_type == BlockType::PreviousNode)
                {
                    let existing_num = bundle.blocks[prev_idx].block_number;
                    let prev_node_block =
                        PreviousNodeBlock::new(existing_num, self.config.local_eid.clone());
                    bundle.blocks[prev_idx] = prev_node_block.to_canonical()?;
                } else {
                    let prev_num = bundle
                        .blocks
                        .iter()
                        .map(|b| b.block_number)
                        .max()
                        .unwrap_or(1)
                        .saturating_add(1)
                        .max(2);
                    let prev_node_block =
                        PreviousNodeBlock::new(prev_num, self.config.local_eid.clone());
                    bundle.blocks.insert(0, prev_node_block.to_canonical()?);
                }

                // Now fragment the updated bundle
                let fragments = crate::bp::fragment::fragment_bundle(&bundle, mtu)?;

                // Queue all fragments for transmission
                let dest_node = NodeId::from_endpoint(&bundle.primary.destination)?;
                for frag in fragments {
                    self.cla_tx_queue.push_back(ClaTransmission {
                        bundle: frag,
                        bundle_id: bundle_id.clone(),
                        destination_node: dest_node.clone(),
                    });
                }

                // Original bundle has been fragmented, remove it
                self.storage.remove(bundle_id)?;
                self.metadata.remove(bundle_id);

                return Ok(());
            }
        }

        // RFC 9171 §4.4.2: Update bundle age
        if let Some(age_idx) = bundle
            .blocks
            .iter()
            .position(|b| b.block_type == BlockType::BundleAge)
        {
            let mut age_block = BundleAgeBlock::from_canonical(&bundle.blocks[age_idx])?;
            // Add residence time (simplified - using current time for now)
            let residence_time = if let Some(meta) = self.metadata.get(bundle_id) {
                self.current_time
                    .duration_since(meta._admitted_at)
                    .unwrap_or(crate::types::SimDuration::ZERO)
                    .as_millis()
            } else {
                0
            };
            age_block.age_ms += residence_time;
            bundle.blocks[age_idx] = age_block.to_canonical()?;
        }

        // RFC 9171 §4.4.3: Increment hop count and check limit
        if let Some(hop_idx) = bundle
            .blocks
            .iter()
            .position(|b| b.block_type == BlockType::HopCount)
        {
            let mut hop_block = HopCountBlock::from_canonical(&bundle.blocks[hop_idx])?;
            hop_block.hop_count += 1;

            // RFC 9171 §4.4.3: Delete if hop limit exceeded
            if hop_block.hop_count > hop_block.hop_limit as u64 {
                self.delete_bundle(bundle_id, crate::bpa::admin::ReasonCode::HopLimitExceeded)?;
                return Err(Error::new(
                    crate::types::ErrorKind::TransferFailed,
                    "Hop limit exceeded",
                ));
            }

            bundle.blocks[hop_idx] = hop_block.to_canonical()?;
        }

        // RFC 9171 §4.4.1: Insert or replace previous node block.
        // Block number 1 is reserved for the payload; allocate a free number ≥2.
        if let Some(prev_idx) = bundle
            .blocks
            .iter()
            .position(|b| b.block_type == BlockType::PreviousNode)
        {
            let existing_num = bundle.blocks[prev_idx].block_number;
            let prev_node_block =
                PreviousNodeBlock::new(existing_num, self.config.local_eid.clone());
            bundle.blocks[prev_idx] = prev_node_block.to_canonical()?;
        } else {
            let prev_num = bundle
                .blocks
                .iter()
                .map(|b| b.block_number)
                .max()
                .unwrap_or(1)
                .saturating_add(1)
                .max(2);
            let prev_node_block = PreviousNodeBlock::new(prev_num, self.config.local_eid.clone());
            bundle.blocks.insert(0, prev_node_block.to_canonical()?);
        }

        // RFC 9174 §5.2.4-122: SHOULD NOT retry same bundle with same extensions
        let fp = Self::bundle_retry_fingerprint(&bundle);
        if self.not_acceptable_blocked.contains(&fp) {
            // Suppress re-transmission of identical bundle+extensions
            return Ok(());
        }

        // Update storage with modified bundle
        self.storage.remove(bundle_id)?;
        let new_id = self.storage.admit(bundle.clone())?;

        // Queue for CLA transmission
        let dest_node = NodeId::from_endpoint(&bundle.primary.destination)?;
        self.cla_tx_queue.push_back(ClaTransmission {
            bundle: bundle.clone(),
            bundle_id: new_id.clone(),
            destination_node: dest_node,
        });

        // Update state
        if let Some(meta) = self.metadata.get_mut(&new_id) {
            meta.state = BundleState::QueuedForTransmission;
        }

        // RFC 9171 §5.4: Generate forwarding status report if requested
        if let Some(report) = self.generate_forwarding_status_report(&new_id, self.current_time) {
            self.generated_reports.push(report);
        }

        Ok(())
    }

    /// Confirm successful transmission (RFC 9171 §5.4)
    ///
    /// Called when CLA confirms bundle was successfully forwarded.
    /// Removes ForwardPending retention constraint.
    pub fn confirm_transmission_success(&mut self, bundle_id: &BundleId) -> Result<()> {
        // RFC 9171 §5.4: Remove ForwardPending after successful transmission
        self.remove_retention_constraint(bundle_id, RetentionConstraint::ForwardPending)?;

        // If bundle has no remaining retention constraints, it may be deleted
        // (but that's a policy decision for the BPA)

        Ok(())
    }

    /// Fingerprint of bundle identity + extension block types for retry suppression
    fn bundle_retry_fingerprint(bundle: &Bundle) -> Vec<u8> {
        let mut fp = Vec::new();
        fp.extend_from_slice(bundle.primary.source.to_string().as_bytes());
        fp.push(0);
        fp.extend_from_slice(bundle.primary.destination.to_string().as_bytes());
        fp.push(0);
        let cts = &bundle.primary.creation_timestamp;
        fp.extend_from_slice(&cts.time.as_millis().to_be_bytes());
        fp.extend_from_slice(&cts.sequence.to_be_bytes());
        for block in &bundle.blocks {
            fp.extend_from_slice(&block.block_type.to_u64().to_be_bytes());
            fp.extend_from_slice(&block.block_number.to_be_bytes());
        }
        fp
    }

    /// CLA reports XFER_REFUSE for a transfer (RFC 9174 §5.2.4-121/122)
    ///
    /// Production path: after a refuse, the BPA decides whether to reactively
    /// fragment and retry (No Resources) or suppress same-bundle retry (Not Acceptable).
    pub fn notify_cla_transfer_refused(
        &mut self,
        bundle_id: &BundleId,
        reason_code: u8,
    ) -> Result<()> {
        // RFC 9174 Table 6 reason codes (avoid tcpcl feature coupling)
        const NO_RESOURCES: u8 = 0x02;
        const NOT_ACCEPTABLE: u8 = 0x04;

        // Remove any in-flight CLA queue entries for this transfer
        self.cla_tx_queue.retain(|t| &t.bundle_id != bundle_id);

        match reason_code {
            // RFC 9174 §5.2.4-121: No Resources → SHOULD apply reactive fragmentation before retrying
            NO_RESOURCES => {
                self.reactive_fragment_pending.insert(bundle_id.clone());
                let bundle = self
                    .storage
                    .get(bundle_id)
                    .ok_or_else(|| Error::not_found("Bundle not in storage for reactive fragment"))?
                    .clone();

                if bundle.primary.must_not_fragment() {
                    return Ok(());
                }

                let encoded = crate::bp::encode(&bundle)?;
                // Reactive fragment size: half the encoded length (at least 64 bytes)
                let frag_size = crate::types::Bytes((encoded.len() as u64 / 2).max(64));
                let fragments = crate::bp::fragment::fragment_bundle(&bundle, frag_size)?;
                let dest_node = NodeId::from_endpoint(&bundle.primary.destination)?;
                for frag in fragments {
                    self.cla_tx_queue.push_back(ClaTransmission {
                        bundle: frag,
                        bundle_id: bundle_id.clone(),
                        destination_node: dest_node.clone(),
                    });
                }
                self.reactive_fragment_pending.remove(bundle_id);
                Ok(())
            }
            // RFC 9174 §5.2.4-122: Not Acceptable → SHOULD NOT retry same bundle with same extensions
            NOT_ACCEPTABLE => {
                if let Some(bundle) = self.storage.get(bundle_id) {
                    let fp = Self::bundle_retry_fingerprint(bundle);
                    self.not_acceptable_blocked.insert(fp);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Deliver bundle to local application (RFC 9171 §5.7)
    ///
    /// Marks bundle as delivered and makes it available to applications.
    pub fn deliver_local(&mut self, bundle_id: &BundleId) -> Result<()> {
        let bundle = self
            .storage
            .get(bundle_id)
            .ok_or_else(|| Error::not_found("Bundle not in storage"))?
            .clone();

        // Add to delivered ADUs
        self.delivered_adus.push(bundle.clone());

        // Update state
        self.deliver_bundle(bundle_id, self.current_time)?;

        // RFC 9171 §5.7: Generate delivery status report if requested
        if let Some(report) = self.generate_delivery_status_report(bundle_id, self.current_time) {
            self.generated_reports.push(report);
        }

        Ok(())
    }
}

/// RFC9171-4-051: primary CRC type MUST be non-zero unless a BIB targets primary.
/// On origination, upgrade `CrcType::None` → `Crc16` when no primary-targeting BIB.
fn ensure_primary_crc_policy(bundle: &mut Bundle) -> Result<()> {
    use crate::bp::processing::bib_targets_primary;
    use crate::bp::{BlockType, CrcType};

    if bundle.primary.crc_type != CrcType::None {
        return Ok(());
    }
    let has_primary_bib = bundle
        .blocks
        .iter()
        .any(|b| matches!(b.block_type, BlockType::Bib) && bib_targets_primary(&b.data));
    if has_primary_bib {
        // MAY be zero when BIB targets primary
        return Ok(());
    }
    bundle.primary.crc_type = CrcType::Crc16;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::BundleBuilder;
    use crate::types::{Bytes, CreationTimestamp, DtnTimeMs};

    #[test]
    fn test_bpa_admit_bundle() {
        let config = BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: crate::bpa::StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: crate::bpa::policy::ForwardingFailedPolicy::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        };
        let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
        let mut bpa = BundleAgent::new(config, storage);

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 2, 0).unwrap())
            .destination(EndpointId::ipn(0, 1, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let bundle_id = bpa.admit_bundle(bundle, SimInstant::ZERO).unwrap();
        assert_eq!(bpa.get_state(&bundle_id), Some(BundleState::Admitted));
    }

    #[test]
    fn test_bpa_local_destination() {
        let config = BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: crate::bpa::StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: crate::bpa::policy::ForwardingFailedPolicy::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        };
        let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
        let bpa = BundleAgent::new(config, storage);

        assert!(bpa.is_local_destination(&EndpointId::ipn(0, 1, 0).unwrap()));
        assert!(bpa.is_local_destination(&EndpointId::ipn(0, 1, 5).unwrap()));
        assert!(!bpa.is_local_destination(&EndpointId::ipn(0, 2, 0).unwrap()));
    }

    #[test]
    fn test_bpa_deliver_and_delete() {
        let config = BpaConfig {
            local_node: NodeId::ipn(0, 1),
            local_eid: EndpointId::ipn(0, 1, 0).unwrap(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: crate::bpa::StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec-default")]
            security_context: None,
            #[cfg(feature = "bpsec-default")]
            security_policy: None,
            enforce_private_use_restrictions: false,
            administrative_domain: None,
            static_routes: None,
            forwarding_failed_policy: crate::bpa::policy::ForwardingFailedPolicy::default(),
            #[cfg(feature = "bpsec-default")]
            outbound_bcb: None,
        };
        let storage = StorageManager::new(Bytes::from_mib(1).unwrap());
        let mut bpa = BundleAgent::new(config, storage);

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 2, 0).unwrap())
            .destination(EndpointId::ipn(0, 1, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let bundle_id = bpa.admit_bundle(bundle, SimInstant::ZERO).unwrap();

        bpa.deliver_bundle(&bundle_id, SimInstant::ZERO).unwrap();
        assert_eq!(bpa.get_state(&bundle_id), Some(BundleState::Delivered));

        bpa.delete_bundle(
            &bundle_id,
            crate::bpa::admin::ReasonCode::NoAdditionalInformation,
        )
        .unwrap();
        assert_eq!(bpa.get_state(&bundle_id), Some(BundleState::Deleted));
    }
}
