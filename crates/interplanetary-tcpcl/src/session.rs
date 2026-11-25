//! Complete TCPCLv4 session implementation per RFC 9174 §§3-6
//!
//! Full state machine with all message types and error conditions.

use super::clock::TimeMs;
use super::messages::*;
use super::session_fsm::{Event, Role, SessionFsm};
use super::stream::{CloseKind, VirtualStream};
use interplanetary_types::{Error, Result};
use std::collections::{HashMap, HashSet, VecDeque};

/// Session errors with distinguishable outcomes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Transfer refused by peer
    TransferRefused {
        /// Transfer identifier
        transfer_id: u64,
        /// Refusal reason code
        reason: u8,
    },
    /// Message rejected by peer
    MessageRejected {
        /// Rejected message type
        message_type: u8,
        /// Rejection reason code
        reason: u8,
    },
    /// Session terminated by peer
    SessionTerminated {
        /// Termination reason code
        reason: u8,
        /// Optional diagnostic message
        message: Option<String>,
    },
    /// Unsupported critical extension
    UnsupportedCriticalExtension {
        /// Extension type code
        type_code: u16,
    },
    /// Receive window exhausted
    ReceiveWindowExhausted {
        /// Transfer identifier
        transfer_id: u64,
        /// Requested bytes
        requested: u64,
        /// Available bytes in window
        available: u64,
    },
    /// Lost acknowledgment (simulated)
    AcknowledgmentLost {
        /// Transfer identifier
        transfer_id: u64,
    },
    /// Protocol violation
    ProtocolViolation(String),
}

/// Session state per RFC 9174 Figure 1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, waiting for contact header
    ContactNegotiation,
    /// Contact exchanged, waiting for SESS_INIT
    SessionInit,
    /// Session established, transfers allowed
    Established,
    /// Termination in progress
    Ending,
    /// Session terminated
    Terminated,
}

/// Session configuration per RFC 9174 §5.1
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Role in the session (Active or Passive) per RFC 9174 §4.1
    pub role: Role,
    /// Keepalive interval in seconds (0 = disabled)
    pub keepalive_interval: u16,
    /// Maximum receive unit for segments
    pub segment_mru: u64,
    /// Maximum receive unit for complete transfers
    pub transfer_mru: u64,
    /// Local node identifier
    pub node_id: String,
    /// Supported extensions
    pub extensions: Vec<ExtensionItem>,
    /// Contact Header reception timeout in seconds (RFC 9174 §4.1-012/013)
    /// RFC 9174 §4.1-012: SHALL close connection if no Contact Header received within timeout.
    /// RFC 9174 §4.1-013: SHOULD be ≤60 seconds. SDK clamps values >60 to 60.
    pub contact_header_timeout: u16,
    /// Maximum acceptable peer keepalive interval (RFC 9174 §4.7-076)
    /// If peer's keepalive > this value, terminate with Contact Failure.
    /// If None, any value is acceptable.
    pub max_peer_keepalive: Option<u16>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            role: Role::Active,
            keepalive_interval: 30,
            segment_mru: 65535,
            transfer_mru: 10_000_000,
            node_id: "dtn:none".to_string(),
            extensions: Vec::new(),
            contact_header_timeout: 60, // RFC 9174 §4.1-013: SHOULD be ≤60s
            max_peer_keepalive: None,   // Accept any keepalive by default
        }
    }
}

/// Active transfer state
#[derive(Debug, Clone)]
struct TransferState {
    /// Transfer data
    data: Vec<u8>,
    /// Bytes acknowledged by peer
    acked: u64,
    /// Bytes already emitted via create_segments (rate-limit cursor)
    segmented: u64,
    /// Whether START flag received
    started: bool,
    /// Whether END flag received
    ended: bool,
}

/// Complete TCPCLv4 session
#[derive(Debug)]
pub struct TcpclSession {
    state: SessionState,
    /// Pure deterministic FSM for state management
    fsm: SessionFsm,
    local_config: SessionConfig,
    peer_config: Option<SessionConfig>,
    /// Negotiated keepalive interval (minimum of local and peer values per RFC 9174 §5.1)
    negotiated_keepalive: Option<u16>,
    next_transfer_id: u64,
    outgoing_transfers: HashMap<u64, TransferState>,
    incoming_transfers: HashMap<u64, TransferState>,
    /// Track incoming transfers that we've refused (RFC 9174 §5.2.4)
    refused_incoming_transfers: HashSet<u64>,
    /// Simulated receive window usage
    receive_window_used: u64,
    /// Whether we sent SESS_TERM (for REPLY flag handling per RFC 9174 §6.1)
    sent_session_term: bool,
    /// Last time we sent any message (for keepalive per RFC 9174 §5.1.1)
    last_send_time_ms: Option<TimeMs>,
    /// Last time we received any message (for idle timeout per RFC 9174 §5.1.1)
    last_receive_time_ms: Option<TimeMs>,
    /// Whether we've received the peer's contact header (for role enforcement)
    received_peer_contact: bool,
    /// Whether we've sent our contact header (for RFC 9174 §6.1 enforcement)
    sent_contact_header: bool,
    /// Session creation time (for contact header timeout per RFC 9174 §4.1-012)
    creation_time_ms: TimeMs,
    /// Outbound messages queued by the session (SESS_TERM, etc.)
    outbound_queue: VecDeque<Message>,
    /// How the SDK last closed the simulated transport (RFC 9174 §4.1-014)
    transport_close: Option<CloseKind>,
    /// RFC9171-7-001: max outbound payload bytes per window (`None` = unlimited)
    rate_limit_bytes_per_window: Option<u64>,
    /// Window length in ms for rate limiting
    rate_limit_window_ms: u64,
    /// Bytes emitted in the current rate-limit window
    rate_window_bytes: u64,
    /// Start of the current rate-limit window (sim ms)
    rate_window_start_ms: TimeMs,
}

impl TcpclSession {
    /// Validate and normalize session configuration
    fn validate_config(config: &mut SessionConfig) -> Result<()> {
        // RFC 9758 §5.4 (RFC9758-028): LocalNode ipn EID MUST NOT be advertised in TCPCL
        if let Ok(eid) = interplanetary_types::EndpointId::parse(&config.node_id)
            && eid.is_local_node()
        {
            return Err(Error::new(
                interplanetary_types::ErrorKind::InvalidConfig,
                "RFC 9758 §5.4: LocalNode ipn EID MUST NOT be used as TCPCLv4 node_id",
            ));
        }

        // RFC 9174 §4.1-012: SHALL close if no Contact Header received
        // Timeout of 0 would disable this SHALL requirement, so we reject it
        if config.contact_header_timeout == 0 {
            return Err(Error::new(
                interplanetary_types::ErrorKind::InvalidConfig,
                "RFC 9174 §4.1-012: Contact header timeout cannot be 0 (would violate SHALL)",
            ));
        }

        // RFC 9174 §4.1-013: SHOULD be ≤60 seconds
        // Clamp values above 60 to 60
        if config.contact_header_timeout > 60 {
            config.contact_header_timeout = 60;
        }

        // RFC 9174 §5.1.1-084/085/086: Keepalive interval recommendations
        // 0 = keepalive disabled (allowed). Otherwise clamp to [30, 600].
        if config.keepalive_interval != 0 {
            config.keepalive_interval = config.keepalive_interval.clamp(30, 600);
        }

        Ok(())
    }

    /// Create new TCPCL session
    ///
    /// RFC 9174 §4.1-012: Connection establishment time is recorded at construction,
    /// not at first poll, so timeout is measured from TCP connection establishment.
    pub fn new(mut config: SessionConfig) -> Result<Self> {
        Self::validate_config(&mut config)?;
        let role = config.role;
        Ok(Self {
            state: SessionState::ContactNegotiation,
            fsm: SessionFsm::new(role),
            local_config: config,
            peer_config: None,
            negotiated_keepalive: None,
            next_transfer_id: 1,
            outgoing_transfers: HashMap::new(),
            incoming_transfers: HashMap::new(),
            refused_incoming_transfers: HashSet::new(),
            receive_window_used: 0,
            sent_session_term: false,
            last_send_time_ms: None,
            last_receive_time_ms: None,
            received_peer_contact: false,
            sent_contact_header: false,
            creation_time_ms: 0, // RFC 9174 §4.1-012: Set at construction (connection establishment)
            outbound_queue: VecDeque::new(),
            transport_close: None,
            // RFC9171-7-001: rate limiting available via set_rate_limit
            rate_limit_bytes_per_window: None,
            rate_limit_window_ms: 1000,
            rate_window_bytes: 0,
            rate_window_start_ms: 0,
        })
    }

    /// Create new TCPCL session with explicit connection establishment time
    ///
    /// RFC 9174 §4.1-012: Timeout is measured from TCP connection establishment.
    pub fn new_at_time(mut config: SessionConfig, connection_time_ms: TimeMs) -> Result<Self> {
        Self::validate_config(&mut config)?;
        let role = config.role;
        Ok(Self {
            state: SessionState::ContactNegotiation,
            fsm: SessionFsm::new(role),
            local_config: config,
            peer_config: None,
            negotiated_keepalive: None,
            next_transfer_id: 1,
            outgoing_transfers: HashMap::new(),
            incoming_transfers: HashMap::new(),
            refused_incoming_transfers: HashSet::new(),
            receive_window_used: 0,
            sent_session_term: false,
            last_send_time_ms: None,
            last_receive_time_ms: None,
            received_peer_contact: false,
            sent_contact_header: false,
            creation_time_ms: connection_time_ms,
            outbound_queue: VecDeque::new(),
            transport_close: None,
            rate_limit_bytes_per_window: None, // enable via set_rate_limit (RFC9171-7-001)
            rate_limit_window_ms: 1000,
            rate_window_bytes: 0,
            rate_window_start_ms: connection_time_ms,
        })
    }

    /// Take next outbound message produced by the session (e.g. SESS_TERM)
    pub fn take_outbound(&mut self) -> Option<Message> {
        self.outbound_queue.pop_front()
    }

    /// How the SDK closed the simulated transport, if it has closed
    pub fn transport_close_kind(&self) -> Option<CloseKind> {
        self.transport_close
    }

    /// Configure CLA rate limiting (RFC 9171 §7.2 / RFC9171-7-001).
    /// Pass `None` for unlimited (test harnesses that ignore congestion control).
    pub fn set_rate_limit(&mut self, bytes_per_window: Option<u64>, window_ms: u64) {
        self.rate_limit_bytes_per_window = bytes_per_window;
        self.rate_limit_window_ms = window_ms.max(1);
        self.rate_window_bytes = 0;
    }

    /// Effective (possibly clamped) local keepalive interval
    pub fn local_keepalive_interval(&self) -> u16 {
        self.local_config.keepalive_interval
    }

    /// Close the simulated transport with FIN per RFC 9174 §4.1-014
    pub fn close_transport(&mut self, stream: &mut VirtualStream) {
        stream.close(); // CloseKind::Fin
        self.transport_close = Some(CloseKind::Fin);
        if self.state != SessionState::Terminated {
            self.state = SessionState::Terminated;
        }
    }

    /// Abort mid-message: MUST NOT send SESS_TERM, SHALL close with FIN
    /// (RFC 9174 §6.1-160 + §4.1-014)
    pub fn abort_mid_message(&mut self, stream: &mut VirtualStream) {
        // Do not enqueue or emit SESS_TERM
        self.outbound_queue.clear();
        self.sent_session_term = false;
        self.close_transport(stream);
    }

    /// Get session role
    pub fn role(&self) -> Role {
        self.local_config.role
    }

    /// Get negotiated keepalive interval (RFC 9174 §5.1: minimum of local and peer)
    pub fn negotiated_keepalive_interval(&self) -> Option<u16> {
        self.negotiated_keepalive
    }

    /// Set negotiated keepalive for testing
    #[cfg(test)]
    pub fn set_negotiated_keepalive_for_test(&mut self, interval: u16) {
        self.negotiated_keepalive = Some(interval);
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Set negotiated keepalive (for testing only)
    #[doc(hidden)]
    pub fn set_keepalive_for_test(&mut self, interval: u16) {
        self.negotiated_keepalive = Some(interval);
    }

    /// Send contact header
    ///
    /// RFC 9174 §4.1: Active entity SHALL immediately transmit its Contact Header.
    /// Passive entity SHALL wait for the active entity's Contact Header.
    ///
    /// Returns Err if called on a Passive session that hasn't received the peer's contact header yet.
    pub fn send_contact_header(&mut self) -> Result<ContactHeader> {
        match self.local_config.role {
            Role::Active => {
                // Active can send contact header at any time (should be first thing)
                self.sent_contact_header = true;
                Ok(ContactHeader::new())
            }
            Role::Passive => {
                // Passive must wait to receive peer's contact header first
                if self.received_peer_contact {
                    self.sent_contact_header = true;
                    Ok(ContactHeader::new())
                } else {
                    Err(Error::protocol_violation(
                        "Passive session cannot send contact header before receiving peer's",
                    ))
                }
            }
        }
    }

    /// Process received contact header
    pub fn process_contact_header(&mut self, header: &ContactHeader) -> Result<()> {
        if self.state != SessionState::ContactNegotiation {
            return Err(Error::protocol_violation("Contact header in wrong state"));
        }

        if header.version != ContactHeader::VERSION {
            return Err(Error::unsupported(format!(
                "TCPCL version {}",
                header.version
            )));
        }

        // Mark that we've received the peer's contact header
        self.received_peer_contact = true;

        // Route through FSM
        let _actions = self.fsm.process_event(Event::ContactHeaderReceived)?;

        self.state = SessionState::SessionInit;
        Ok(())
    }

    /// Send SESS_INIT
    pub fn send_session_init(&mut self) -> Result<Message> {
        if self.state != SessionState::SessionInit {
            return Err(Error::protocol_violation("SESS_INIT in wrong state"));
        }

        Ok(Message::SessionInit {
            keepalive_interval: self.local_config.keepalive_interval,
            segment_mru: self.local_config.segment_mru,
            transfer_mru: self.local_config.transfer_mru,
            node_id: self.local_config.node_id.clone(),
            extensions: self.local_config.extensions.clone(),
        })
    }

    /// Process received SESS_INIT
    pub fn process_session_init(&mut self, msg: &Message) -> Result<()> {
        if self.state != SessionState::SessionInit {
            return Err(Error::protocol_violation("SESS_INIT in wrong state"));
        }

        match msg {
            Message::SessionInit {
                keepalive_interval,
                segment_mru,
                transfer_mru,
                node_id,
                extensions,
            } => {
                // Check for unsupported critical extensions
                for ext in extensions {
                    if ext.is_critical() {
                        // In real impl, check if we support this type_code
                        // For now, reject all critical extensions
                        return Err(Error::unsupported(format!(
                            "Unsupported critical extension type {}",
                            ext.type_code
                        )));
                    }
                }

                // RFC 9174 §4.7-076: "If the Session Keepalive Interval is unacceptable,
                // the entity SHALL terminate the session with a reason code of 'Contact Failure'."
                if let Some(max_keepalive) = self.local_config.max_peer_keepalive
                    && *keepalive_interval > max_keepalive
                {
                    // SHALL terminate: emit SESS_TERM with Contact Failure and close
                    self.state = SessionState::Ending;
                    self.sent_session_term = true;
                    let term = Message::SessionTerm {
                        flags: 0,
                        reason_code: term_reason::CONTACT_FAILURE,
                        message: Some("Contact Failure: keepalive unacceptable".to_string()),
                    };
                    self.outbound_queue.push_back(term);
                    self.transport_close = Some(CloseKind::Fin);
                    return Err(Error::protocol_violation(format!(
                        "RFC 9174 §4.7-076: Peer keepalive interval {} exceeds maximum acceptable {} (session terminating)",
                        keepalive_interval, max_keepalive
                    )));
                }

                // Route through FSM
                let _actions = self.fsm.process_event(Event::SessionInitReceived)?;

                // RFC 9174 §5.1: Keepalive interval is negotiated to the MINIMUM
                // of the two peer values
                let negotiated =
                    std::cmp::min(self.local_config.keepalive_interval, *keepalive_interval);
                self.negotiated_keepalive = Some(negotiated);

                self.peer_config = Some(SessionConfig {
                    role: Role::Active, // Peer's role is opposite of ours, but doesn't matter here
                    keepalive_interval: *keepalive_interval,
                    segment_mru: *segment_mru,
                    transfer_mru: *transfer_mru,
                    node_id: node_id.clone(),
                    extensions: extensions.clone(),
                    contact_header_timeout: 60, // Stored peer view; not used for local timeout
                    max_peer_keepalive: None,   // Peer config doesn't need this
                });

                self.state = SessionState::Established;
                Ok(())
            }
            _ => Err(Error::protocol_violation("Expected SESS_INIT")),
        }
    }

    /// Start new outgoing transfer
    pub fn start_transfer(&mut self, data: Vec<u8>) -> Result<u64> {
        if self.state != SessionState::Established {
            return Err(Error::protocol_violation(
                "Transfer in non-established session",
            ));
        }

        // Check transfer size against peer's MRU
        if let Some(peer) = &self.peer_config
            && data.len() as u64 > peer.transfer_mru
        {
            return Err(Error::invalid_config(format!(
                "Transfer size {} exceeds peer MRU {}",
                data.len(),
                peer.transfer_mru
            )));
        }

        let transfer_id = self.next_transfer_id;
        self.next_transfer_id += 1;

        self.outgoing_transfers.insert(
            transfer_id,
            TransferState {
                data,
                acked: 0,
                segmented: 0,
                started: false,
                ended: false,
            },
        );

        Ok(transfer_id)
    }

    /// Create transfer segments for transmission.
    ///
    /// RFC9171-7-001: respects `set_rate_limit`. Use [`Self::create_segments_at`]
    /// when advancing the deterministic clock across windows.
    pub fn create_segments(
        &mut self,
        transfer_id: u64,
        max_segment_size: usize,
    ) -> Result<Vec<Message>> {
        self.create_segments_at(transfer_id, max_segment_size, self.rate_window_start_ms)
    }

    /// Create transfer segments at a deterministic clock instant (rate-limit aware).
    pub fn create_segments_at(
        &mut self,
        transfer_id: u64,
        max_segment_size: usize,
        now_ms: TimeMs,
    ) -> Result<Vec<Message>> {
        let window_ms = self.rate_limit_window_ms.max(1);
        if now_ms.saturating_sub(self.rate_window_start_ms) >= window_ms {
            self.rate_window_start_ms = now_ms;
            self.rate_window_bytes = 0;
        }

        let transfer = self
            .outgoing_transfers
            .get_mut(&transfer_id)
            .ok_or_else(|| Error::not_found("Transfer not found"))?;

        let segment_size = if let Some(peer) = &self.peer_config {
            max_segment_size.min(peer.segment_mru as usize)
        } else {
            max_segment_size
        };

        let mut segments = Vec::new();
        let data_len = transfer.data.len();
        let mut offset = transfer.segmented as usize;
        if offset > data_len {
            offset = data_len;
        }

        while offset < data_len {
            let mut end = (offset + segment_size).min(data_len);
            let mut chunk_len = end - offset;

            if let Some(limit) = self.rate_limit_bytes_per_window {
                let remaining = limit.saturating_sub(self.rate_window_bytes);
                if remaining == 0 {
                    if segments.is_empty() {
                        return Err(Error::new(
                            interplanetary_types::ErrorKind::TransferFailed,
                            "RFC 9171 §7.2: TCPCL rate limit exceeded for this window",
                        ));
                    }
                    break;
                }
                if chunk_len as u64 > remaining {
                    end = offset + remaining as usize;
                    chunk_len = remaining as usize;
                }
            }

            let chunk = transfer.data[offset..end].to_vec();

            let mut flags = 0u8;
            if offset == 0 && !transfer.started {
                flags |= transfer_flags::START;
                transfer.started = true;
            }
            if end == data_len {
                flags |= transfer_flags::END;
                transfer.ended = true;
            }

            self.rate_window_bytes = self.rate_window_bytes.saturating_add(chunk_len as u64);
            segments.push(Message::TransferSegment {
                flags,
                transfer_id,
                extensions: Vec::new(),
                data: chunk,
            });

            offset = end;
            transfer.segmented = offset as u64;
        }

        Ok(segments)
    }

    /// Process received XFER_ACK
    pub fn process_ack(&mut self, transfer_id: u64, acked_length: u64) -> Result<bool> {
        let transfer = self
            .outgoing_transfers
            .get_mut(&transfer_id)
            .ok_or_else(|| Error::not_found("Transfer not found"))?;

        transfer.acked = acked_length;

        // Transfer complete if all data acknowledged
        if acked_length >= transfer.data.len() as u64 {
            self.outgoing_transfers.remove(&transfer_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Process received XFER_REFUSE (sender side - we sent the transfer, peer refused it)
    pub fn process_refuse(&mut self, transfer_id: u64, reason_code: u8) -> Result<()> {
        // RFC 9174 §5.2.4-120: Normalize unknown reason codes to UNKNOWN
        let normalized_reason = refuse_reason::normalize(reason_code);

        self.outgoing_transfers.remove(&transfer_id);
        Err(Error::protocol_violation(format!(
            "Transfer {} refused with reason {}",
            transfer_id, normalized_reason
        )))
    }

    /// Refuse an incoming transfer (receiver side - we're refusing a transfer sent to us)
    ///
    /// Auto-refuse all incomplete transfers preceding the given transfer_id
    ///
    /// RFC9174-5-2-4-124: "The receiver MUST, for each transfer preceding the one to be refused,
    /// have either acknowledged all XFER_SEGMENT messages or refused the bundle transfer."
    ///
    /// This helper ensures compliance by auto-refusing any earlier incomplete transfers.
    fn auto_refuse_earlier_incomplete_transfers(&mut self, transfer_id: u64) {
        // Find all earlier transfers that are incomplete and not yet refused
        let to_refuse: Vec<u64> = (1..transfer_id)
            .filter(|&earlier_id| {
                // Not already refused
                !self.refused_incoming_transfers.contains(&earlier_id)
                    // And incomplete
                    && self.incoming_transfers.get(&earlier_id)
                        .map(|t| !t.ended)
                        .unwrap_or(false)
            })
            .collect();

        // Auto-refuse them
        for earlier_id in to_refuse {
            self.refused_incoming_transfers.insert(earlier_id);
            self.incoming_transfers.remove(&earlier_id);
        }
    }

    /// Check if a transfer can be refused per RFC 9174 §5.2.4
    ///
    /// RFC9174-5-2-4-124: "The receiver MUST, for each transfer preceding the one to be refused,
    /// have either acknowledged all XFER_SEGMENT messages or refused the bundle transfer."
    fn can_refuse_transfer(&self, transfer_id: u64) -> Result<()> {
        // Check all transfers with ID < transfer_id
        for earlier_id in 1..transfer_id {
            // Skip if already refused
            if self.refused_incoming_transfers.contains(&earlier_id) {
                continue;
            }

            // Check if fully acknowledged
            if let Some(transfer) = self.incoming_transfers.get(&earlier_id) {
                // Transfer exists but not fully completed
                if !transfer.ended {
                    return Err(Error::new(
                        interplanetary_types::ErrorKind::ProtocolViolation,
                        format!(
                            "RFC 9174 §5.2.4: Cannot refuse transfer {} while transfer {} is incomplete",
                            transfer_id, earlier_id
                        ),
                    ));
                }
            }
            // If transfer doesn't exist in map and not in refused set, it was never started
            // which is allowed
        }
        Ok(())
    }

    /// RFC 9174 §5.2.4: After sending XFER_REFUSE, subsequent segments SHALL also be
    /// responded to by XFER_REFUSE messages.
    ///
    /// RFC9174-5-2-4-124: Returns error if refusing would violate ordering constraints.
    pub fn refuse_incoming_transfer(
        &mut self,
        transfer_id: u64,
        reason_code: u8,
    ) -> Result<Message> {
        // RFC9174-5-2-4-124: Validate ordering constraints
        self.can_refuse_transfer(transfer_id)?;

        // Record this transfer as refused
        self.refused_incoming_transfers.insert(transfer_id);

        // Clean up any state for this transfer
        self.incoming_transfers.remove(&transfer_id);

        // Return the XFER_REFUSE message to send
        Ok(Message::TransferRefuse {
            reason_code,
            transfer_id,
        })
    }

    /// Process received XFER_SEGMENT
    pub fn process_segment(&mut self, segment: &Message) -> Result<Option<Message>> {
        if self.state != SessionState::Established {
            return Err(Error::protocol_violation(
                "Segment in non-established session",
            ));
        }

        match segment {
            Message::TransferSegment {
                flags,
                transfer_id,
                extensions,
                data,
            } => {
                // RFC 9174 §5.2.4: "if this happens, subsequent segments of the bundle
                // SHALL also be responded to by XFER_REFUSE messages"
                // Check if we've already refused this transfer
                if self.refused_incoming_transfers.contains(transfer_id) {
                    return Ok(Some(Message::TransferRefuse {
                        reason_code: refuse_reason::NO_RESOURCES, // Use same reason as original refuse
                        transfer_id: *transfer_id,
                    }));
                }

                // Check for unsupported critical extensions
                for ext in extensions {
                    if ext.is_critical() {
                        // RFC9174-5-2-4-124: Auto-refuse earlier incomplete transfers
                        self.auto_refuse_earlier_incomplete_transfers(*transfer_id);

                        // Refuse transfer due to extension
                        // Record this refusal
                        self.refused_incoming_transfers.insert(*transfer_id);
                        return Ok(Some(Message::TransferRefuse {
                            reason_code: refuse_reason::EXTENSION_FAILURE,
                            transfer_id: *transfer_id,
                        }));
                    }
                }

                // Check if this is a new transfer (START flag)
                let is_new_transfer = *flags & transfer_flags::START != 0;
                if is_new_transfer {
                    // Route through FSM to track transfer lifecycle
                    let _actions = self.fsm.process_event(Event::TransferStart {
                        transfer_id: *transfer_id,
                    })?;
                }

                // Check receive window
                let new_size = self.receive_window_used + data.len() as u64;
                if new_size > self.local_config.transfer_mru {
                    // RFC9174-5-2-4-124: Auto-refuse earlier incomplete transfers
                    self.auto_refuse_earlier_incomplete_transfers(*transfer_id);

                    // Refuse transfer - no resources
                    // Record this refusal
                    self.refused_incoming_transfers.insert(*transfer_id);
                    return Ok(Some(Message::TransferRefuse {
                        reason_code: refuse_reason::NO_RESOURCES,
                        transfer_id: *transfer_id,
                    }));
                }

                // Get or create transfer state
                let transfer = self
                    .incoming_transfers
                    .entry(*transfer_id)
                    .or_insert_with(|| TransferState {
                        data: Vec::new(),
                        acked: 0,
                        segmented: 0,
                        started: false,
                        ended: false,
                    });

                // Check START/END flags
                if *flags & transfer_flags::START != 0 {
                    if transfer.started {
                        return Err(Error::protocol_violation("Duplicate START flag"));
                    }
                    transfer.started = true;
                }

                // Append data
                transfer.data.extend_from_slice(data);
                self.receive_window_used += data.len() as u64;

                if *flags & transfer_flags::END != 0 {
                    if transfer.ended {
                        return Err(Error::protocol_violation("Duplicate END flag"));
                    }
                    transfer.ended = true;
                }

                // Send acknowledgment
                let acked_length = transfer.data.len() as u64;
                transfer.acked = acked_length;

                Ok(Some(Message::TransferAck {
                    flags: 0,
                    transfer_id: *transfer_id,
                    acked_length,
                }))
            }
            _ => Err(Error::protocol_violation("Expected XFER_SEGMENT")),
        }
    }

    /// Send SESS_TERM
    ///
    /// RFC 9174 §6.1: "However, an entity MUST always send the Contact Header to its
    /// peer before sending a SESS_TERM message."
    ///
    /// RFC 9174 §6.1: "If reception of the Contact Header itself somehow fails (e.g., an
    /// invalid magic string is received), an entity SHALL close the TCP connection without
    /// sending a SESS_TERM message."
    pub fn send_session_term(
        &mut self,
        reason_code: u8,
        message: Option<String>,
    ) -> Result<Message> {
        // RFC 9174 §6.1: Enforce Contact Header before SESS_TERM - NO exceptions
        // If contact negotiation fails, close TCP connection without SESS_TERM per §6.1
        if !self.sent_contact_header {
            return Err(Error::protocol_violation(
                "RFC 9174 §6.1: MUST send Contact Header before SESS_TERM (always, no exceptions)",
            ));
        }

        self.state = SessionState::Ending;
        self.sent_session_term = true;
        // RFC 9174 §4.1-014: eventual close uses FIN
        self.transport_close = Some(CloseKind::Fin);

        // RFC 9174 §6.1: When initiating termination, REPLY flag SHALL be 0
        let term = Message::SessionTerm {
            flags: 0,
            reason_code,
            message,
        };
        self.outbound_queue.push_back(term.clone());
        Ok(term)
    }

    /// Process received SESS_TERM per RFC 9174 §6.1
    /// Returns Ok(Some(reply)) if we need to send acknowledging SESS_TERM with REPLY flag
    pub fn process_session_term(&mut self, msg: &Message) -> Result<Option<Message>> {
        match msg {
            Message::SessionTerm {
                flags,
                reason_code,
                message,
            } => {
                // RFC 9174 §6.1-155: Normalize unknown reason codes to UNKNOWN
                let normalized_reason = term_reason::normalize(*reason_code);

                // Route through FSM
                let _actions = self.fsm.process_event(Event::SessionTermReceived {
                    flags: *flags,
                    reason_code: normalized_reason,
                })?;

                self.state = SessionState::Terminated;

                // RFC 9174 §6.1: "Upon receiving a SESS_TERM message after not sending
                // a SESS_TERM message in the same session, an entity SHALL send an
                // acknowledging SESS_TERM message"
                let reply = if !self.sent_session_term {
                    // We didn't send SESS_TERM yet, so send acknowledging SESS_TERM
                    // with REPLY flag (0x01) set
                    Some(Message::SessionTerm {
                        flags: 0x01, // REPLY flag
                        reason_code: normalized_reason,
                        message: message.clone(),
                    })
                } else {
                    // We already sent SESS_TERM
                    // If received message has REPLY flag, it's an acknowledgment - no further reply
                    // If no REPLY flag, it's simultaneous termination - no further reply
                    None
                };

                Ok(reply)
            }
            _ => Err(Error::protocol_violation("Expected SESS_TERM")),
        }
    }

    /// Process received MSG_REJECT
    pub fn process_message_reject(&mut self, rejected_type: u8, reason: u8) -> Result<()> {
        Err(Error::protocol_violation(format!(
            "Message type {} rejected with reason {}",
            rejected_type, reason
        )))
    }

    /// Process raw message byte and detect unknown types per RFC 9174 §5.1.2
    /// Returns MSG_REJECT message if type is unknown
    pub fn process_raw_message_type(&self, message_type: u8) -> Option<Message> {
        // RFC 9174 Table 1: Known message types
        // 0x01 = XFER_SEGMENT
        // 0x02 = XFER_ACK
        // 0x03 = XFER_REFUSE
        // 0x04 = KEEPALIVE
        // 0x05 = SESS_TERM
        // 0x06 = MSG_REJECT
        // 0x07 = SESS_INIT

        match message_type {
            Message::TYPE_XFER_SEGMENT
            | Message::TYPE_XFER_ACK
            | Message::TYPE_XFER_REFUSE
            | Message::TYPE_KEEPALIVE
            | Message::TYPE_SESS_TERM
            | Message::TYPE_MSG_REJECT
            | Message::TYPE_SESS_INIT => None, // Known type, no rejection
            _ => {
                // RFC 9174 §5.1.2: "the entity SHALL send a MSG_REJECT message
                // with a reason code of 0x01 (Message Type Unknown)"
                Some(Message::MessageReject {
                    reason_code: 0x01, // Message Type Unknown
                    rejected_message_header: message_type,
                })
            }
        }
    }

    /// Check if transfer is complete
    pub fn is_transfer_complete(&self, transfer_id: u64) -> bool {
        !self.outgoing_transfers.contains_key(&transfer_id)
    }

    /// Get received transfer data
    pub fn get_received_transfer(&self, transfer_id: u64) -> Option<&[u8]> {
        self.incoming_transfers
            .get(&transfer_id)
            .filter(|t| t.ended)
            .map(|t| t.data.as_slice())
    }

    /// Record that we sent a message at the given time
    pub fn record_send(&mut self, now_ms: TimeMs) {
        self.last_send_time_ms = Some(now_ms);
    }

    /// Record that we received a message at the given time
    pub fn record_receive(&mut self, now_ms: TimeMs) {
        self.last_receive_time_ms = Some(now_ms);
    }

    /// Poll session at given time and return actions due per RFC 9174 §5.1.1
    ///
    /// Returns:
    /// - Some(Message::Keepalive) if keepalive interval elapsed with no send
    /// - Some(Message::SessionTerm) if idle timeout (twice keepalive interval) elapsed with no receive
    /// - None if no action needed
    pub fn poll(&mut self, now_ms: TimeMs) -> Option<Message> {
        // RFC 9174 §4.1-012: Contact Header reception timeout
        // "If either entity does not receive a Contact Header after some
        // implementation-defined time duration after the TCP connection is
        // established, the waiting entity SHALL close the TCP connection."
        //
        // RFC 9174 §4.1-013: "Entities SHOULD choose a Contact Header reception
        // timeout interval no longer than one minute (60 seconds)."
        //
        // Timeout is measured from creation_time_ms (connection establishment),
        // not from first poll.
        if self.state == SessionState::ContactNegotiation && !self.received_peer_contact {
            let timeout_ms = (self.local_config.contact_header_timeout as u64) * 1000;
            let elapsed_ms = now_ms.saturating_sub(self.creation_time_ms);
            if elapsed_ms >= timeout_ms {
                // RFC 9174 §4.1-012: Contact header timeout - close connection with FIN
                // No SESS_TERM - timeout before protocol establishment (§6.1)
                self.state = SessionState::Terminated;
                self.transport_close = Some(CloseKind::Fin);
                return None;
            }
        }

        // Only process keepalive/idle in Established state
        if self.state != SessionState::Established {
            return None;
        }

        let keepalive_interval_ms = match self.negotiated_keepalive {
            Some(interval_sec) if interval_sec > 0 => (interval_sec as u64) * 1000,
            _ => return None, // Keepalive disabled (interval = 0)
        };

        // RFC 9174 §5.1.1: "If no message (KEEPALIVE or other) has been received
        // in a session after some implementation-defined time duration, then the
        // entity SHALL terminate the session by transmitting a SESS_TERM message
        // with a reason code of 'Idle timeout'"
        //
        // "If not configurable, the idle timeout duration SHOULD be exactly
        // twice the Keepalive Interval"
        if let Some(last_receive) = self.last_receive_time_ms {
            let idle_timeout_ms = keepalive_interval_ms * 2;
            if now_ms.saturating_sub(last_receive) >= idle_timeout_ms {
                // Idle timeout - terminate session
                self.state = SessionState::Ending;
                self.sent_session_term = true;
                return Some(Message::SessionTerm {
                    flags: 0,
                    reason_code: term_reason::IDLE_TIMEOUT,
                    message: Some("Idle timeout".to_string()),
                });
            }
        }

        // RFC 9174 §5.1.1: "Both sides SHALL send a KEEPALIVE message whenever
        // the negotiated interval has elapsed with no transmission of any message
        // (KEEPALIVE or other)"
        if let Some(last_send) = self.last_send_time_ms {
            if now_ms.saturating_sub(last_send) >= keepalive_interval_ms {
                self.last_send_time_ms = Some(now_ms);
                return Some(Message::Keepalive);
            }
        } else {
            // No send yet, initialize
            self.last_send_time_ms = Some(now_ms);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_negotiation() {
        let mut session = TcpclSession::new(SessionConfig::default()).unwrap();
        assert_eq!(session.state(), SessionState::ContactNegotiation);

        let header = session.send_contact_header().unwrap();
        assert_eq!(header.version, 4);

        session.process_contact_header(&header).unwrap();
        assert_eq!(session.state(), SessionState::SessionInit);
    }

    #[test]
    fn test_session_establishment() {
        let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
        let mut remote = TcpclSession::new(SessionConfig::default()).unwrap();

        // Contact exchange
        let local_contact = local.send_contact_header().unwrap();
        let remote_contact = remote.send_contact_header().unwrap();

        local.process_contact_header(&remote_contact).unwrap();
        remote.process_contact_header(&local_contact).unwrap();

        // SESS_INIT exchange
        let local_init = local.send_session_init().unwrap();
        let remote_init = remote.send_session_init().unwrap();

        local.process_session_init(&remote_init).unwrap();
        remote.process_session_init(&local_init).unwrap();

        assert_eq!(local.state(), SessionState::Established);
        assert_eq!(remote.state(), SessionState::Established);
    }

    #[test]
    fn test_transfer_refused() {
        let mut session = TcpclSession::new(SessionConfig::default()).unwrap();
        session.state = SessionState::Established;

        let transfer_id = 1;
        session.outgoing_transfers.insert(
            transfer_id,
            TransferState {
                data: vec![0; 100],
                acked: 0,
                segmented: 0,
                started: true,
                ended: false,
            },
        );

        // Process XFER_REFUSE
        let result = session.process_refuse(transfer_id, refuse_reason::NO_RESOURCES);
        assert!(result.is_err());
        assert!(!session.outgoing_transfers.contains_key(&transfer_id));
    }

    #[test]
    fn test_unsupported_critical_extension() {
        let mut session = TcpclSession::new(SessionConfig::default()).unwrap();
        session.state = SessionState::SessionInit;

        let init_with_critical_ext = Message::SessionInit {
            keepalive_interval: 30,
            segment_mru: 65535,
            transfer_mru: 1_000_000,
            node_id: "dtn:test".to_string(),
            extensions: vec![
                ExtensionItem::new(0x9999, vec![1, 2, 3], true), // Critical unsupported
            ],
        };

        let result = session.process_session_init(&init_with_critical_ext);
        assert!(result.is_err());
    }

    #[test]
    fn test_receive_window_exhaustion() {
        let config = SessionConfig {
            transfer_mru: 100, // Small window
            ..SessionConfig::default()
        };

        let mut session = TcpclSession::new(config).unwrap();
        // Establish session through FSM
        session
            .fsm
            .process_event(Event::ContactHeaderReceived)
            .unwrap();
        session
            .fsm
            .process_event(Event::SessionInitReceived)
            .unwrap();
        session.state = SessionState::Established;

        // Try to receive segment exceeding window
        let large_segment = Message::TransferSegment {
            flags: transfer_flags::START | transfer_flags::END,
            transfer_id: 1,
            extensions: Vec::new(),
            data: vec![0; 200], // Exceeds 100-byte limit
        };

        let response = session.process_segment(&large_segment).unwrap();

        // Should receive XFER_REFUSE
        match response {
            Some(Message::TransferRefuse { reason_code, .. }) => {
                assert_eq!(reason_code, refuse_reason::NO_RESOURCES);
            }
            _ => panic!("Expected XFER_REFUSE"),
        }
    }

    #[test]
    fn test_simultaneous_session_term() {
        let mut local = TcpclSession::new(SessionConfig::default()).unwrap();
        let mut remote = TcpclSession::new(SessionConfig::default()).unwrap();

        // RFC 9174 §6.1: MUST send Contact Header before SESS_TERM
        // Simulate full session establishment with contact headers sent
        local
            .fsm
            .process_event(Event::ContactHeaderReceived)
            .unwrap();
        local.fsm.process_event(Event::SessionInitReceived).unwrap();
        local.state = SessionState::Established;
        local.sent_contact_header = true; // RFC 9174 §6.1: Contact Header sent

        remote
            .fsm
            .process_event(Event::ContactHeaderReceived)
            .unwrap();
        remote
            .fsm
            .process_event(Event::SessionInitReceived)
            .unwrap();
        remote.state = SessionState::Established;
        remote.sent_contact_header = true; // RFC 9174 §6.1: Contact Header sent

        // Both sides send SESS_TERM
        let local_term = local
            .send_session_term(term_reason::IDLE_TIMEOUT, None)
            .unwrap();
        let remote_term = remote
            .send_session_term(term_reason::IDLE_TIMEOUT, None)
            .unwrap();

        assert_eq!(local.state(), SessionState::Ending);
        assert_eq!(remote.state(), SessionState::Ending);

        // Process each other's SESS_TERM
        let _ = local.process_session_term(&remote_term);
        let _ = remote.process_session_term(&local_term);

        assert_eq!(local.state(), SessionState::Terminated);
        assert_eq!(remote.state(), SessionState::Terminated);
    }

    #[test]
    fn test_keepalive_negotiation() {
        // RFC 9174 §5.1: Keepalive interval is negotiated to the MINIMUM
        let local_config = SessionConfig {
            keepalive_interval: 60,
            ..SessionConfig::default()
        };

        let remote_config = SessionConfig {
            keepalive_interval: 30,
            ..SessionConfig::default()
        };

        let mut local = TcpclSession::new(local_config).unwrap();
        let mut remote = TcpclSession::new(remote_config).unwrap();

        // Exchange contact headers
        let local_contact = local.send_contact_header().unwrap();
        let remote_contact = remote.send_contact_header().unwrap();
        local.process_contact_header(&remote_contact).unwrap();
        remote.process_contact_header(&local_contact).unwrap();

        // Exchange SESS_INIT
        let local_init = local.send_session_init().unwrap();
        let remote_init = remote.send_session_init().unwrap();

        local.process_session_init(&remote_init).unwrap();
        remote.process_session_init(&local_init).unwrap();

        // Both should negotiate to minimum (30)
        assert_eq!(local.negotiated_keepalive_interval(), Some(30));
        assert_eq!(remote.negotiated_keepalive_interval(), Some(30));
    }

    /// RFC9171-7-001: convergence-layer MUST provide rate limiting.
    #[test]
    fn test_rfc9171_7_001_tcpcl_rate_limiting() {
        let mut session = TcpclSession::new(SessionConfig::default()).unwrap();
        session.state = SessionState::Established;
        session.set_rate_limit(Some(100), 1000);

        let tid = session.start_transfer(vec![0xABu8; 250]).unwrap();
        let segs1 = session.create_segments_at(tid, 64, 0).unwrap();
        let bytes1: usize = segs1
            .iter()
            .map(|m| match m {
                Message::TransferSegment { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert!(bytes1 <= 100, "first window exceeded rate limit: {bytes1}");
        assert!(bytes1 > 0);

        let again = session.create_segments_at(tid, 64, 0);
        assert!(
            again.is_err() || again.as_ref().map(|v| v.is_empty()).unwrap_or(false),
            "exhausted window must block further segments"
        );

        let segs2 = session.create_segments_at(tid, 64, 1000).unwrap();
        let bytes2: usize = segs2
            .iter()
            .map(|m| match m {
                Message::TransferSegment { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert!(bytes2 > 0, "new window must allow more segments");
        assert!(bytes1 + bytes2 <= 250);
    }
}
