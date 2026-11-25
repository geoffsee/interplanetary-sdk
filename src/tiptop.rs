//! TIPTOP Experimental Module (Charter §11)
//!
//! **EXPERIMENTAL**: This module implements IP-based DTN protocols per:
//! - draft-ietf-tiptop-usecase-04
//! - draft-ietf-tiptop-ip-architecture-03  
//! - draft-ietf-tiptop-quic-profile-01
//!
//! **All outputs are SYNTHETIC and EXPERIMENTAL.**
//! This is a model for research, not a production IP stack or QUIC implementation.

use crate::types::SimInstant;
use std::net::{Ipv4Addr, Ipv6Addr};

/// IP packet model (distinct from Bundle Protocol types)
#[derive(Clone, Debug)]
pub enum IpPacket {
    /// IPv4 packet
    V4(IPv4Packet),
    /// IPv6 packet
    V6(IPv6Packet),
}

/// IPv4 packet with modeled fields (not complete IP stack)
#[derive(Clone, Debug)]
pub struct IPv4Packet {
    /// Source address
    pub source: Ipv4Addr,
    /// Destination address
    pub destination: Ipv4Addr,
    /// Time-to-live
    pub ttl: u8,
    /// Payload bytes
    pub payload: Vec<u8>,
    /// Total packet length
    pub total_length: u16,
}

/// IPv6 packet with modeled fields
#[derive(Clone, Debug)]
pub struct IPv6Packet {
    /// Source address
    pub source: Ipv6Addr,
    /// Destination address
    pub destination: Ipv6Addr,
    /// Hop limit
    pub hop_limit: u8,
    /// Payload bytes
    pub payload: Vec<u8>,
    /// Payload length
    pub payload_length: u16,
}

/// IP forwarding queue with finite buffering through outages
#[derive(Clone, Debug)]
pub struct IpForwardingQueue {
    packets: Vec<(IpPacket, SimInstant)>, // packet + enqueue time
    capacity: usize,
    dropped: u64,
}

impl IpForwardingQueue {
    /// Create new forwarding queue with given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            packets: Vec::new(),
            capacity,
            dropped: 0,
        }
    }

    /// Enqueue packet if capacity available
    pub fn enqueue(&mut self, packet: IpPacket, time: SimInstant) -> Result<(), &'static str> {
        if self.packets.len() >= self.capacity {
            self.dropped += 1;
            return Err("Queue full");
        }
        self.packets.push((packet, time));
        Ok(())
    }

    /// Dequeue oldest packet
    pub fn dequeue(&mut self) -> Option<(IpPacket, SimInstant)> {
        if self.packets.is_empty() {
            None
        } else {
            Some(self.packets.remove(0))
        }
    }

    /// Get current queue occupancy
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Return count of dropped packets due to capacity
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }
}

/// QUIC Deep Space Profile per draft-ietf-tiptop-quic-profile-01
///
/// **EXPERIMENTAL**: Separates negotiated transport params from local settings
#[derive(Clone, Debug)]
pub struct QuicDeepSpaceProfile {
    /// Negotiated parameters (exchange during handshake)
    pub negotiated: NegotiatedParams,

    /// Local implementation settings (not wire-negotiated)
    pub local: LocalSettings,
}

/// Negotiated QUIC transport parameters
#[derive(Clone, Debug)]
pub struct NegotiatedParams {
    /// Maximum idle timeout (milliseconds)
    pub max_idle_timeout_ms: u64,

    /// Initial max data (flow control)
    pub initial_max_data: u64,

    /// Initial max stream data bidirectional
    pub initial_max_stream_data_bidi: u64,

    /// Max UDP payload size
    pub max_udp_payload_size: u16,
}

/// Local QUIC implementation settings
#[derive(Clone, Debug)]
pub struct LocalSettings {
    /// Initial RTT estimate (milliseconds) - NOT a wire parameter
    pub initial_rtt_ms: u64,

    /// Pacing rate limit (bytes per second, 0 = unlimited)
    pub pacing_rate_bps: u64,

    /// Congestion control enabled
    pub congestion_control_enabled: bool,

    /// 0-RTT enabled (must consider replay safety)
    pub zero_rtt_enabled: bool,
}

impl Default for QuicDeepSpaceProfile {
    fn default() -> Self {
        Self {
            negotiated: NegotiatedParams {
                max_idle_timeout_ms: 300_000,            // 5 minutes
                initial_max_data: 10_000_000,            // 10 MB
                initial_max_stream_data_bidi: 1_000_000, // 1 MB
                max_udp_payload_size: 1200,
            },
            local: LocalSettings {
                initial_rtt_ms: 1000,       // 1 second default
                pacing_rate_bps: 1_000_000, // 1 Mbps
                congestion_control_enabled: true,
                zero_rtt_enabled: false, // Off by default (replay concerns)
            },
        }
    }
}

impl QuicDeepSpaceProfile {
    /// Lunar profile: continuous high-latency link
    pub fn lunar() -> Self {
        Self {
            negotiated: NegotiatedParams {
                max_idle_timeout_ms: 600_000, // 10 minutes (long delays expected)
                initial_max_data: 50_000_000, // 50 MB (ample buffer)
                initial_max_stream_data_bidi: 10_000_000, // 10 MB
                max_udp_payload_size: 1400,
            },
            local: LocalSettings {
                initial_rtt_ms: 2500,        // ~2.5s one-way delay
                pacing_rate_bps: 10_000_000, // 10 Mbps
                congestion_control_enabled: true,
                zero_rtt_enabled: false,
            },
        }
    }

    /// Intermittent relay profile: periodic connectivity
    pub fn intermittent_relay() -> Self {
        Self {
            negotiated: NegotiatedParams {
                max_idle_timeout_ms: 1_800_000,          // 30 minutes (long gaps)
                initial_max_data: 20_000_000,            // 20 MB
                initial_max_stream_data_bidi: 5_000_000, // 5 MB
                max_udp_payload_size: 1200,
            },
            local: LocalSettings {
                initial_rtt_ms: 5000,       // 5s (relay adds delay)
                pacing_rate_bps: 2_000_000, // 2 Mbps
                congestion_control_enabled: true,
                zero_rtt_enabled: false,
            },
        }
    }

    /// Asymmetric return path profile: different up/down rates
    pub fn asymmetric_return() -> Self {
        Self {
            negotiated: NegotiatedParams {
                max_idle_timeout_ms: 180_000,            // 3 minutes
                initial_max_data: 5_000_000,             // 5 MB (constrained uplink)
                initial_max_stream_data_bidi: 1_000_000, // 1 MB
                max_udp_payload_size: 1000,              // Smaller for uplink
            },
            local: LocalSettings {
                initial_rtt_ms: 2000,     // 2s
                pacing_rate_bps: 500_000, // 500 Kbps (uplink limited)
                congestion_control_enabled: true,
                zero_rtt_enabled: false,
            },
        }
    }

    /// Long blackout profile: extended periods without connectivity
    pub fn long_blackout() -> Self {
        Self {
            negotiated: NegotiatedParams {
                max_idle_timeout_ms: 7_200_000, // 2 hours (survive blackouts)
                initial_max_data: 100_000_000,  // 100 MB (large buffer)
                initial_max_stream_data_bidi: 50_000_000, // 50 MB
                max_udp_payload_size: 1400,
            },
            local: LocalSettings {
                initial_rtt_ms: 10_000,            // 10s initial estimate
                pacing_rate_bps: 5_000_000,        // 5 Mbps when available
                congestion_control_enabled: false, // Open-loop during blackouts
                zero_rtt_enabled: false,
            },
        }
    }
}

/// Abstract timeout/flow-control experiment result
#[derive(Clone, Debug)]
pub enum ExperimentResult {
    /// Feature supported and modeled
    Supported {
        /// Feature description
        description: String,
    },

    /// Feature not implemented in this model
    UnsupportedFeature {
        /// Feature name
        feature: String,
        /// Reason not supported
        reason: String,
    },
}

/// Run abstract QUIC timeout experiment
pub fn experiment_timeout_behavior(
    profile: &QuicDeepSpaceProfile,
    delay_ms: u64,
) -> ExperimentResult {
    if delay_ms < profile.negotiated.max_idle_timeout_ms {
        ExperimentResult::Supported {
            description: format!(
                "Connection survives {}ms delay (timeout: {}ms)",
                delay_ms, profile.negotiated.max_idle_timeout_ms
            ),
        }
    } else {
        ExperimentResult::Supported {
            description: format!(
                "Connection times out after {}ms (exceeds {}ms timeout)",
                delay_ms, profile.negotiated.max_idle_timeout_ms
            ),
        }
    }
}

/// Run abstract flow control experiment
pub fn experiment_flow_control(profile: &QuicDeepSpaceProfile, data_size: u64) -> ExperimentResult {
    if data_size <= profile.negotiated.initial_max_data {
        ExperimentResult::Supported {
            description: format!(
                "Flow control allows {} bytes (limit: {} bytes)",
                data_size, profile.negotiated.initial_max_data
            ),
        }
    } else {
        ExperimentResult::Supported {
            description: format!(
                "Flow control blocks {} bytes (exceeds {} byte limit)",
                data_size, profile.negotiated.initial_max_data
            ),
        }
    }
}

/// Unsupported feature example: ACK frequency extension
pub fn experiment_ack_frequency() -> ExperimentResult {
    ExperimentResult::UnsupportedFeature {
        feature: "ACK Frequency Extension".to_string(),
        reason: "Requires separate draft pinning and implementation".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_forwarding_queue_capacity() {
        let mut queue = IpForwardingQueue::new(2);

        let packet1 = IpPacket::V4(IPv4Packet {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ttl: 64,
            payload: vec![0xAA; 100],
            total_length: 120,
        });

        let packet2 = packet1.clone();
        let packet3 = packet1.clone();

        let time = SimInstant::from_nanos(0);

        // Fill queue
        assert!(queue.enqueue(packet1.clone(), time).is_ok());
        assert!(queue.enqueue(packet2.clone(), time).is_ok());

        // Exceed capacity
        assert!(queue.enqueue(packet3, time).is_err());
        assert_eq!(queue.dropped_count(), 1);

        // Dequeue
        assert!(queue.dequeue().is_some());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_quic_profiles() {
        let lunar = QuicDeepSpaceProfile::lunar();
        assert!(lunar.local.initial_rtt_ms > 2000); // High latency

        let relay = QuicDeepSpaceProfile::intermittent_relay();
        assert!(relay.negotiated.max_idle_timeout_ms > 1_000_000); // Long timeout

        let asymmetric = QuicDeepSpaceProfile::asymmetric_return();
        assert!(asymmetric.local.pacing_rate_bps < 1_000_000); // Limited uplink

        let blackout = QuicDeepSpaceProfile::long_blackout();
        assert!(!blackout.local.congestion_control_enabled); // Open-loop
    }

    #[test]
    fn test_timeout_experiment() {
        let profile = QuicDeepSpaceProfile::default();

        // Within timeout
        let result1 = experiment_timeout_behavior(&profile, 60_000);
        match result1 {
            ExperimentResult::Supported { .. } => {}
            _ => panic!("Expected supported"),
        }

        // Exceeds timeout
        let result2 = experiment_timeout_behavior(&profile, 400_000);
        match result2 {
            ExperimentResult::Supported { description } => {
                assert!(description.contains("times out"));
            }
            _ => panic!("Expected supported"),
        }
    }

    #[test]
    fn test_unsupported_feature() {
        let result = experiment_ack_frequency();
        match result {
            ExperimentResult::UnsupportedFeature { feature, .. } => {
                assert_eq!(feature, "ACK Frequency Extension");
            }
            _ => panic!("Expected unsupported feature"),
        }
    }
}
