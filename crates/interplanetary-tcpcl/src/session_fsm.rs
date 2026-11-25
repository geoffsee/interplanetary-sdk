//! Pure deterministic TCPCLv4 session state machine
//!
//! RFC 9174 §4: Session lifecycle from contact negotiation through termination.
//! No I/O, no timers - all state changes driven by explicit events.

use super::TimeMs;
use interplanetary_types::{Error, Result};

/// Session states per RFC 9174
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Contact header negotiation in progress
    ContactNegotiation,
    /// SESS_INIT exchange
    SessionInit,
    /// Normal operation
    Established,
    /// Termination in progress
    Ending,
    /// Session closed
    Terminated,
}

/// Role in the session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Active entity: initiates connection, sends SESS_INIT first
    Active,
    /// Passive entity: accepts connection, responds to SESS_INIT
    Passive,
}

/// Events that drive state transitions
#[derive(Debug, Clone)]
pub enum Event {
    /// Contact header received from peer
    ContactHeaderReceived,
    /// SESS_INIT message received
    SessionInitReceived,
    /// Transfer segment received with START flag
    TransferStart {
        /// Transfer identifier
        transfer_id: u64,
    },
    /// SESS_TERM received
    SessionTermReceived {
        /// Message flags
        flags: u8,
        /// Termination reason code
        reason_code: u8,
    },
    /// Keepalive received
    KeepaliveReceived,
}

/// Actions to perform in response to events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send contact header
    SendContactHeader,
    /// Send SESS_INIT
    SendSessionInit,
    /// Send SESS_TERM
    SendSessionTerm {
        /// Message flags (REPLY bit)
        flags: u8,
        /// Termination reason code
        reason_code: u8,
    },
    /// Send keepalive
    SendKeepalive,
    /// Refuse transfer
    RefuseTransfer {
        /// Transfer identifier to refuse
        transfer_id: u64,
        /// Refusal reason code
        reason: u8,
    },
    /// Close the session
    CloseSession,
}

/// Pure session state machine
#[derive(Debug)]
pub struct SessionFsm {
    /// Current session state
    state: SessionState,
    /// Role in the session (Active or Passive)
    role: Role,
    /// True if we sent SESS_TERM
    sent_term: bool,
    /// True if we received SESS_TERM
    received_term: bool,
    /// Negotiated keepalive interval (seconds)
    keepalive_interval: Option<u16>,
    /// Last send time for keepalive timer
    last_send_ms: Option<TimeMs>,
    /// Active transfers (simple tracking for "in-progress" vs "new")
    active_transfers: std::collections::HashSet<u64>,
}

impl SessionFsm {
    /// Create new FSM in initial state
    pub fn new(role: Role) -> Self {
        Self {
            state: SessionState::ContactNegotiation,
            role,
            sent_term: false,
            received_term: false,
            keepalive_interval: None,
            last_send_ms: None,
            active_transfers: std::collections::HashSet::new(),
        }
    }

    /// Current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Set negotiated keepalive interval
    pub fn set_keepalive_interval(&mut self, interval_seconds: u16) {
        self.keepalive_interval = Some(interval_seconds);
    }

    /// Record that we sent a message (for keepalive timer)
    pub fn record_send(&mut self, now_ms: TimeMs) {
        self.last_send_ms = Some(now_ms);
    }

    /// Process an event and return actions to perform
    pub fn process_event(&mut self, event: Event) -> Result<Vec<Action>> {
        match (&self.state, &event) {
            // Contact negotiation
            (SessionState::ContactNegotiation, Event::ContactHeaderReceived) => {
                self.state = SessionState::SessionInit;

                match self.role {
                    Role::Active => Ok(vec![Action::SendSessionInit]),
                    Role::Passive => Ok(vec![]), // Wait for peer's SESS_INIT
                }
            }

            // Session init exchange
            (SessionState::SessionInit, Event::SessionInitReceived) => {
                match self.role {
                    Role::Active => {
                        // Active receives passive's SESS_INIT reply
                        self.state = SessionState::Established;
                        Ok(vec![])
                    }
                    Role::Passive => {
                        // Passive receives active's SESS_INIT, replies and transitions
                        self.state = SessionState::Established;
                        Ok(vec![Action::SendSessionInit])
                    }
                }
            }

            // Established: normal operation
            (SessionState::Established, Event::TransferStart { transfer_id }) => {
                self.active_transfers.insert(*transfer_id);
                Ok(vec![])
            }

            (SessionState::Established, Event::SessionTermReceived { flags, reason_code }) => {
                self.received_term = true;
                self.state = SessionState::Ending;

                // Send reply with REPLY flag set
                Ok(vec![Action::SendSessionTerm {
                    flags: flags | 0x01, // Set REPLY bit
                    reason_code: *reason_code,
                }])
            }

            (SessionState::Established, Event::KeepaliveReceived) => {
                // Just record receipt, no action needed
                Ok(vec![])
            }

            // Ending: termination in progress
            (SessionState::Ending, Event::SessionTermReceived { .. }) if !self.sent_term => {
                // We received SESS_TERM, now peer sent reply - transition to Terminated
                self.state = SessionState::Terminated;
                Ok(vec![Action::CloseSession])
            }

            (
                SessionState::Ending,
                Event::SessionTermReceived {
                    flags,
                    reason_code: _,
                },
            ) if !self.received_term && self.sent_term => {
                // We sent SESS_TERM, peer replies
                self.received_term = true;

                // Verify it's a reply (REPLY flag set)
                if flags & 0x01 == 0 {
                    return Err(Error::protocol_violation(
                        "Expected SESS_TERM reply with REPLY flag set",
                    ));
                }

                self.state = SessionState::Terminated;
                Ok(vec![Action::CloseSession])
            }

            (SessionState::Ending, Event::TransferStart { transfer_id }) => {
                // Refuse new transfers in Ending state
                Ok(vec![Action::RefuseTransfer {
                    transfer_id: *transfer_id,
                    reason: 0x02, // Session Terminating
                }])
            }

            // Invalid transitions
            _ => Err(Error::protocol_violation(format!(
                "Invalid event {:?} in state {:?}",
                self.state, event
            ))),
        }
    }

    /// Initiate session termination
    pub fn initiate_termination(&mut self, reason_code: u8) -> Result<Vec<Action>> {
        if self.state == SessionState::Terminated {
            return Err(Error::protocol_violation("Session already terminated"));
        }

        self.sent_term = true;
        self.state = SessionState::Ending;

        Ok(vec![Action::SendSessionTerm {
            flags: 0x00, // REPLY=0 for initiating
            reason_code,
        }])
    }

    /// Check if new outgoing transfers are allowed
    pub fn can_initiate_transfer(&self) -> bool {
        self.state == SessionState::Established && !self.sent_term && !self.received_term
    }

    /// Poll for periodic actions (keepalives)
    pub fn poll(&mut self, now_ms: TimeMs) -> Vec<Action> {
        if self.state != SessionState::Established {
            return vec![];
        }

        let Some(interval_seconds) = self.keepalive_interval else {
            return vec![];
        };

        let Some(last_send) = self.last_send_ms else {
            return vec![];
        };

        let interval_ms = (interval_seconds as u64) * 1000;
        let elapsed = now_ms.saturating_sub(last_send);

        if elapsed >= interval_ms {
            vec![Action::SendKeepalive]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_session_establishment() {
        let mut fsm = SessionFsm::new(Role::Active);

        assert_eq!(fsm.state(), SessionState::ContactNegotiation);

        // Receive contact header
        let actions = fsm.process_event(Event::ContactHeaderReceived).unwrap();
        assert_eq!(fsm.state(), SessionState::SessionInit);
        assert_eq!(actions, vec![Action::SendSessionInit]);

        // Receive SESS_INIT reply
        let actions = fsm.process_event(Event::SessionInitReceived).unwrap();
        assert_eq!(fsm.state(), SessionState::Established);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_passive_session_establishment() {
        let mut fsm = SessionFsm::new(Role::Passive);

        // Receive contact header
        let actions = fsm.process_event(Event::ContactHeaderReceived).unwrap();
        assert_eq!(fsm.state(), SessionState::SessionInit);
        assert!(actions.is_empty()); // Passive waits for SESS_INIT

        // Receive SESS_INIT
        let actions = fsm.process_event(Event::SessionInitReceived).unwrap();
        assert_eq!(fsm.state(), SessionState::Established);
        assert_eq!(actions, vec![Action::SendSessionInit]);
    }

    #[test]
    fn test_sess_term_initiating() {
        let mut fsm = SessionFsm::new(Role::Active);

        // Establish session
        fsm.process_event(Event::ContactHeaderReceived).unwrap();
        fsm.process_event(Event::SessionInitReceived).unwrap();
        assert_eq!(fsm.state(), SessionState::Established);

        // Initiate termination
        let actions = fsm.initiate_termination(0x00).unwrap();
        assert_eq!(fsm.state(), SessionState::Ending);
        assert_eq!(
            actions,
            vec![Action::SendSessionTerm {
                flags: 0x00,
                reason_code: 0x00,
            }]
        );

        assert!(!fsm.can_initiate_transfer());
    }

    #[test]
    fn test_sess_term_reply() {
        let mut fsm = SessionFsm::new(Role::Passive);

        // Establish session
        fsm.process_event(Event::ContactHeaderReceived).unwrap();
        fsm.process_event(Event::SessionInitReceived).unwrap();

        // Receive SESS_TERM
        let actions = fsm
            .process_event(Event::SessionTermReceived {
                flags: 0x00,
                reason_code: 0x01,
            })
            .unwrap();

        assert_eq!(fsm.state(), SessionState::Ending);
        assert_eq!(
            actions,
            vec![Action::SendSessionTerm {
                flags: 0x01, // REPLY flag set
                reason_code: 0x01,
            }]
        );
    }

    #[test]
    fn test_refuse_new_transfer_in_ending() {
        let mut fsm = SessionFsm::new(Role::Active);

        // Establish and terminate
        fsm.process_event(Event::ContactHeaderReceived).unwrap();
        fsm.process_event(Event::SessionInitReceived).unwrap();
        fsm.initiate_termination(0x00).unwrap();

        // Attempt new transfer
        let actions = fsm
            .process_event(Event::TransferStart { transfer_id: 42 })
            .unwrap();

        assert_eq!(
            actions,
            vec![Action::RefuseTransfer {
                transfer_id: 42,
                reason: 0x02,
            }]
        );
    }

    #[test]
    fn test_keepalive_poll() {
        let mut fsm = SessionFsm::new(Role::Active);

        fsm.process_event(Event::ContactHeaderReceived).unwrap();
        fsm.process_event(Event::SessionInitReceived).unwrap();
        fsm.set_keepalive_interval(10); // 10 seconds
        fsm.record_send(1000);

        // Not yet time for keepalive
        let actions = fsm.poll(5000);
        assert!(actions.is_empty());

        // Past keepalive interval
        let actions = fsm.poll(11001);
        assert_eq!(actions, vec![Action::SendKeepalive]);
    }

    #[test]
    fn test_invalid_transition_rejected() {
        let mut fsm = SessionFsm::new(Role::Active);

        // Try to receive SESS_INIT before contact header
        let result = fsm.process_event(Event::SessionInitReceived);
        assert!(result.is_err());
    }
}
