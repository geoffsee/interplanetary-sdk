//! TCPCLv4 message types per RFC 9174 §5

/// Contact header (magic + version + flags)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactHeader {
    /// Protocol version
    pub version: u8,
    /// Contact header flags
    pub flags: u8,
}

impl ContactHeader {
    /// Magic bytes per RFC 9174 §4.1
    pub const MAGIC: &'static [u8] = b"dtn!";
    /// Protocol version (4 for TCPCLv4)
    pub const VERSION: u8 = 4;
    /// Flag indicating TLS capability
    pub const FLAG_CAN_TLS: u8 = 0x01;

    /// Create new contact header with default version and no flags
    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            flags: 0,
        }
    }

    /// Create new contact header with specific flags
    pub fn with_flags(flags: u8) -> Self {
        Self {
            version: Self::VERSION,
            flags,
        }
    }

    /// Encode contact header to bytes per RFC 9174 §4.1
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::MAGIC);
        bytes.push(self.version);
        bytes.push(self.flags);
        bytes
    }

    /// Decode contact header from bytes per RFC 9174 §4.1
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 {
            return Err("Contact header too short".to_string());
        }
        if &bytes[0..4] != Self::MAGIC {
            return Err("Invalid magic".to_string());
        }
        Ok(Self {
            version: bytes[4],
            flags: bytes[5],
        })
    }
}

/// Extension item per RFC 9174 §5.1.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionItem {
    /// Extension flags (bit 0: critical)
    pub flags: u8,
    /// Extension type code
    pub type_code: u16,
    /// Extension value bytes
    pub value: Vec<u8>,
}

impl ExtensionItem {
    /// Critical flag bit per RFC 9174 §5.1.1
    pub const FLAG_CRITICAL: u8 = 0x01;

    /// Create new extension item
    pub fn new(type_code: u16, value: Vec<u8>, critical: bool) -> Self {
        Self {
            flags: if critical { Self::FLAG_CRITICAL } else { 0 },
            type_code,
            value,
        }
    }

    /// Check if this extension is marked critical
    pub fn is_critical(&self) -> bool {
        self.flags & Self::FLAG_CRITICAL != 0
    }

    /// Encode extension item per RFC 9174 §5.1.1
    /// Format: flags(1) | type(2) | length(2) | value(variable)
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + self.value.len());
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.type_code.to_be_bytes());
        bytes.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.value);
        bytes
    }

    /// Decode extension item from bytes
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), String> {
        if bytes.len() < 5 {
            return Err("Extension item too short".to_string());
        }

        let flags = bytes[0];
        let type_code = u16::from_be_bytes([bytes[1], bytes[2]]);
        let value_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        if bytes.len() < 5 + value_len {
            return Err("Extension item value truncated".to_string());
        }

        let value = bytes[5..5 + value_len].to_vec();

        Ok((
            Self {
                flags,
                type_code,
                value,
            },
            5 + value_len,
        ))
    }
}

/// TCPCL message types per RFC 9174 §5
#[derive(Debug, Clone)]
pub enum Message {
    /// SESS_INIT (message type 0x07)
    SessionInit {
        /// Keepalive interval in seconds
        keepalive_interval: u16,
        /// Maximum receive unit for segments
        segment_mru: u64,
        /// Maximum receive unit for transfers
        transfer_mru: u64,
        /// Node identifier
        node_id: String,
        /// Session extensions
        extensions: Vec<ExtensionItem>,
    },
    /// SESS_TERM (message type 0x05)
    SessionTerm {
        /// Termination flags (bit 0: reply)
        flags: u8,
        /// Reason code per RFC 9174 Table 3
        reason_code: u8,
        /// Optional diagnostic message
        message: Option<String>,
    },
    /// XFER_SEGMENT (message type 0x01)
    TransferSegment {
        /// Transfer flags (bit 0: END, bit 1: START)
        flags: u8,
        /// Transfer identifier
        transfer_id: u64,
        /// Transfer extensions
        extensions: Vec<ExtensionItem>,
        /// Segment data
        data: Vec<u8>,
    },
    /// XFER_ACK (message type 0x02)
    TransferAck {
        /// Acknowledgment flags (currently unused)
        flags: u8,
        /// Transfer identifier
        transfer_id: u64,
        /// Total acknowledged byte count
        acked_length: u64,
    },
    /// XFER_REFUSE (message type 0x03)
    TransferRefuse {
        /// Refusal reason code per RFC 9174 Table 4
        reason_code: u8,
        /// Transfer identifier
        transfer_id: u64,
    },
    /// KEEPALIVE (message type 0x04)
    Keepalive,
    /// MSG_REJECT (message type 0x06)
    MessageReject {
        /// Rejection reason code per RFC 9174 Table 5
        reason_code: u8,
        /// First byte of rejected message header
        rejected_message_header: u8,
    },
}

impl Message {
    /// Message type code for XFER_SEGMENT per RFC 9174 Table 1
    pub const TYPE_XFER_SEGMENT: u8 = 0x01;
    /// Message type code for XFER_ACK per RFC 9174 Table 1
    pub const TYPE_XFER_ACK: u8 = 0x02;
    /// Message type code for XFER_REFUSE per RFC 9174 Table 1
    pub const TYPE_XFER_REFUSE: u8 = 0x03;
    /// Message type code for KEEPALIVE per RFC 9174 Table 1
    pub const TYPE_KEEPALIVE: u8 = 0x04;
    /// Message type code for SESS_TERM per RFC 9174 Table 1
    pub const TYPE_SESS_TERM: u8 = 0x05;
    /// Message type code for MSG_REJECT per RFC 9174 Table 1
    pub const TYPE_MSG_REJECT: u8 = 0x06;
    /// Message type code for SESS_INIT per RFC 9174 Table 1
    pub const TYPE_SESS_INIT: u8 = 0x07;

    /// Encode message to wire format per RFC 9174 §5
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::SessionInit {
                keepalive_interval,
                segment_mru,
                transfer_mru,
                node_id,
                extensions,
            } => {
                let mut bytes = Vec::new();
                bytes.push(Self::TYPE_SESS_INIT);
                bytes.extend_from_slice(&keepalive_interval.to_be_bytes());
                bytes.extend_from_slice(&segment_mru.to_be_bytes());
                bytes.extend_from_slice(&transfer_mru.to_be_bytes());

                // Node ID as length-prefixed string
                let node_id_bytes = node_id.as_bytes();
                bytes.extend_from_slice(&(node_id_bytes.len() as u16).to_be_bytes());
                bytes.extend_from_slice(node_id_bytes);

                // Extensions as length-prefixed sequence
                let ext_bytes: Vec<u8> = extensions.iter().flat_map(|e| e.encode()).collect();
                bytes.extend_from_slice(&(ext_bytes.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&ext_bytes);

                bytes
            }

            Message::SessionTerm {
                flags,
                reason_code,
                message,
            } => {
                let mut bytes = Vec::new();
                bytes.push(Self::TYPE_SESS_TERM);
                bytes.push(*flags);
                bytes.push(*reason_code);

                // Optional message string
                if let Some(msg) = message {
                    bytes.extend_from_slice(msg.as_bytes());
                }

                bytes
            }

            Message::TransferSegment {
                flags,
                transfer_id,
                extensions,
                data,
            } => {
                let mut bytes = Vec::new();
                bytes.push(Self::TYPE_XFER_SEGMENT);
                bytes.push(*flags);
                bytes.extend_from_slice(&transfer_id.to_be_bytes());

                // Extensions as length-prefixed sequence
                let ext_bytes: Vec<u8> = extensions.iter().flat_map(|e| e.encode()).collect();
                bytes.extend_from_slice(&(ext_bytes.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&ext_bytes);

                // Data length and data
                bytes.extend_from_slice(&(data.len() as u64).to_be_bytes());
                bytes.extend_from_slice(data);

                bytes
            }

            Message::TransferAck {
                flags,
                transfer_id,
                acked_length,
            } => {
                let mut bytes = Vec::new();
                bytes.push(Self::TYPE_XFER_ACK);
                bytes.push(*flags);
                bytes.extend_from_slice(&transfer_id.to_be_bytes());
                bytes.extend_from_slice(&acked_length.to_be_bytes());
                bytes
            }

            Message::TransferRefuse {
                reason_code,
                transfer_id,
            } => {
                let mut bytes = Vec::new();
                bytes.push(Self::TYPE_XFER_REFUSE);
                bytes.push(*reason_code);
                bytes.extend_from_slice(&transfer_id.to_be_bytes());
                bytes
            }

            Message::Keepalive => {
                vec![Self::TYPE_KEEPALIVE]
            }

            Message::MessageReject {
                reason_code,
                rejected_message_header,
            } => {
                let mut bytes = vec![Self::TYPE_MSG_REJECT];
                bytes.push(*reason_code);
                bytes.push(*rejected_message_header);
                bytes
            }
        }
    }

    /// Decode SESS_INIT message from wire format per RFC 9174 §4.6
    ///
    /// Validates that Node ID Data contains valid UTF-8 per RFC 9174 §4.6:
    /// "A non-zero-length Node ID Data SHALL contain the UTF-8 encoded node ID"
    pub fn decode_sess_init(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty SESS_INIT message".to_string());
        }

        if bytes[0] != Self::TYPE_SESS_INIT {
            return Err(format!(
                "Wrong message type: expected 0x{:02x}, got 0x{:02x}",
                Self::TYPE_SESS_INIT,
                bytes[0]
            ));
        }

        // Minimum size: type(1) + keepalive(2) + segment_mru(8) + transfer_mru(8) +
        // node_id_len(2) + extensions_len(4) = 25 bytes
        if bytes.len() < 25 {
            return Err(format!(
                "SESS_INIT too short: {} bytes, need at least 25",
                bytes.len()
            ));
        }

        let mut offset = 1; // Skip message type

        // Parse keepalive_interval (2 bytes)
        let keepalive_interval = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        // Parse segment_mru (8 bytes)
        let segment_mru = u64::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // Parse transfer_mru (8 bytes)
        let transfer_mru = u64::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // Parse node_id length (2 bytes)
        if offset + 2 > bytes.len() {
            return Err("SESS_INIT truncated at node_id length".to_string());
        }
        let node_id_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Parse node_id bytes and validate UTF-8
        if offset + node_id_len > bytes.len() {
            return Err(format!(
                "SESS_INIT truncated: node_id claims {} bytes but only {} remain",
                node_id_len,
                bytes.len() - offset
            ));
        }

        let node_id_bytes = &bytes[offset..offset + node_id_len];
        // RFC 9174 §4.6: "A non-zero-length Node ID Data SHALL contain the UTF-8 encoded node ID"
        let node_id = if node_id_len > 0 {
            String::from_utf8(node_id_bytes.to_vec())
                .map_err(|e| format!("Node ID is not valid UTF-8: {}", e))?
        } else {
            String::new()
        };
        offset += node_id_len;

        // Parse extensions length (4 bytes)
        if offset + 4 > bytes.len() {
            return Err("SESS_INIT truncated at extensions length".to_string());
        }
        let extensions_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        // Parse extensions
        if offset + extensions_len > bytes.len() {
            return Err(format!(
                "SESS_INIT truncated: extensions claim {} bytes but only {} remain",
                extensions_len,
                bytes.len() - offset
            ));
        }

        let ext_bytes = &bytes[offset..offset + extensions_len];
        let mut extensions = Vec::new();
        let mut ext_offset = 0;
        while ext_offset < ext_bytes.len() {
            let (ext, consumed) = ExtensionItem::decode(&ext_bytes[ext_offset..]).map_err(|e| {
                format!("Failed to decode extension at offset {}: {}", ext_offset, e)
            })?;
            extensions.push(ext);
            ext_offset += consumed;
        }

        Ok(Message::SessionInit {
            keepalive_interval,
            segment_mru,
            transfer_mru,
            node_id,
            extensions,
        })
    }

    /// Get message type byte
    pub fn message_type(&self) -> u8 {
        match self {
            Message::SessionInit { .. } => Self::TYPE_SESS_INIT,
            Message::SessionTerm { .. } => Self::TYPE_SESS_TERM,
            Message::TransferSegment { .. } => Self::TYPE_XFER_SEGMENT,
            Message::TransferAck { .. } => Self::TYPE_XFER_ACK,
            Message::TransferRefuse { .. } => Self::TYPE_XFER_REFUSE,
            Message::Keepalive => Self::TYPE_KEEPALIVE,
            Message::MessageReject { .. } => Self::TYPE_MSG_REJECT,
        }
    }
}

/// Transfer flags per RFC 9174 §6.2
pub mod transfer_flags {
    /// End of transfer flag
    pub const END: u8 = 0x01;
    /// Start of transfer flag
    pub const START: u8 = 0x02;
}

/// SESS_TERM reason codes per RFC 9174 Table 2
pub mod term_reason {
    /// Unknown reason
    pub const UNKNOWN: u8 = 0x00;
    /// Idle timeout
    pub const IDLE_TIMEOUT: u8 = 0x01;
    /// Version mismatch
    pub const VERSION_MISMATCH: u8 = 0x02;
    /// Busy
    pub const BUSY: u8 = 0x03;
    /// Contact failure
    pub const CONTACT_FAILURE: u8 = 0x04;
    /// Resource exhaustion
    pub const RESOURCE_EXHAUSTION: u8 = 0x05;

    /// RFC 9174 §6.1-155: Normalize unknown reason codes to UNKNOWN
    ///
    /// "If a termination has a reason code that is not decodable to the BPA,
    /// the agent SHOULD treat the termination as having a reason code of 'Unknown'."
    pub fn normalize(code: u8) -> u8 {
        if code <= RESOURCE_EXHAUSTION {
            code
        } else {
            UNKNOWN
        }
    }
}

/// XFER_REFUSE reason codes per RFC 9174 Table 3
pub mod refuse_reason {
    /// Unknown reason
    pub const UNKNOWN: u8 = 0x00;
    /// Transfer completed
    pub const COMPLETED: u8 = 0x01;
    /// No resources
    pub const NO_RESOURCES: u8 = 0x02;
    /// Retransmit
    pub const RETRANSMIT: u8 = 0x03;
    /// Not acceptable
    pub const NOT_ACCEPTABLE: u8 = 0x04;
    /// Extension failure
    pub const EXTENSION_FAILURE: u8 = 0x05;

    /// RFC 9174 §5.2.4-120: Normalize unknown reason codes to UNKNOWN
    ///
    /// "If a transfer refusal has a reason code that is not decodable to the BPA,
    /// the agent SHOULD treat the refusal as having a reason code of 'Unknown'."
    pub fn normalize(code: u8) -> u8 {
        if code <= EXTENSION_FAILURE {
            code
        } else {
            UNKNOWN
        }
    }
}

/// MSG_REJECT reason codes per RFC 9174 Table 4
pub mod reject_reason {
    /// Unknown reason
    pub const UNKNOWN: u8 = 0x01;
    /// Message type unsupported
    pub const UNSUPPORTED: u8 = 0x02;
    /// Message unexpected in current state
    pub const UNEXPECTED: u8 = 0x03;
}

impl Default for ContactHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_header_encode_decode() {
        // RFC 9174 §3: 6-byte format
        let header = ContactHeader::with_flags(ContactHeader::FLAG_CAN_TLS);
        let encoded = header.encode();

        assert_eq!(encoded.len(), 6);
        assert_eq!(&encoded[0..4], b"dtn!");
        assert_eq!(encoded[4], 4); // Version
        assert_eq!(encoded[5], 0x01); // CAN_TLS flag

        let decoded = ContactHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_extension_item_encode_decode() {
        // RFC 9174 §5.1.1: flags(1) | type(2) | length(2) | value(var)
        let ext = ExtensionItem::new(0x1234, vec![0xAA, 0xBB, 0xCC], true);
        let encoded = ext.encode();

        assert_eq!(encoded[0], ExtensionItem::FLAG_CRITICAL);
        assert_eq!(u16::from_be_bytes([encoded[1], encoded[2]]), 0x1234);
        assert_eq!(u16::from_be_bytes([encoded[3], encoded[4]]), 3); // value length
        assert_eq!(&encoded[5..], &[0xAA, 0xBB, 0xCC]);

        let (decoded, consumed) = ExtensionItem::decode(&encoded).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(decoded.type_code, 0x1234);
        assert_eq!(decoded.value, vec![0xAA, 0xBB, 0xCC]);
        assert!(decoded.is_critical());
    }

    #[test]
    fn test_sess_init_encoding() {
        let msg = Message::SessionInit {
            keepalive_interval: 60,
            segment_mru: 65535,
            transfer_mru: 1_000_000,
            node_id: "dtn:test".to_string(),
            extensions: vec![],
        };

        let encoded = msg.encode();

        assert_eq!(encoded[0], Message::TYPE_SESS_INIT);
        assert_eq!(u16::from_be_bytes([encoded[1], encoded[2]]), 60);
        assert_eq!(
            u64::from_be_bytes(encoded[3..11].try_into().unwrap()),
            65535
        );
        assert_eq!(
            u64::from_be_bytes(encoded[11..19].try_into().unwrap()),
            1_000_000
        );
    }

    #[test]
    fn test_xfer_ack_encoding() {
        let msg = Message::TransferAck {
            flags: 0,
            transfer_id: 42,
            acked_length: 1234,
        };

        let encoded = msg.encode();

        assert_eq!(encoded[0], Message::TYPE_XFER_ACK);
        assert_eq!(encoded[1], 0); // flags
        assert_eq!(u64::from_be_bytes(encoded[2..10].try_into().unwrap()), 42);
        assert_eq!(
            u64::from_be_bytes(encoded[10..18].try_into().unwrap()),
            1234
        );
    }

    #[test]
    fn test_xfer_refuse_encoding() {
        let msg = Message::TransferRefuse {
            reason_code: refuse_reason::NO_RESOURCES,
            transfer_id: 99,
        };

        let encoded = msg.encode();

        assert_eq!(encoded[0], Message::TYPE_XFER_REFUSE);
        assert_eq!(encoded[1], refuse_reason::NO_RESOURCES);
        assert_eq!(u64::from_be_bytes(encoded[2..10].try_into().unwrap()), 99);
    }

    #[test]
    fn test_sess_term_encoding() {
        let msg = Message::SessionTerm {
            flags: 0,
            reason_code: term_reason::IDLE_TIMEOUT,
            message: Some("Timed out".to_string()),
        };

        let encoded = msg.encode();

        assert_eq!(encoded[0], Message::TYPE_SESS_TERM);
        assert_eq!(encoded[1], 0); // flags
        assert_eq!(encoded[2], term_reason::IDLE_TIMEOUT);
        assert_eq!(&encoded[3..], b"Timed out");
    }

    #[test]
    fn test_keepalive_encoding() {
        let msg = Message::Keepalive;
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], Message::TYPE_KEEPALIVE);
    }

    #[test]
    fn test_msg_reject_encoding() {
        let msg = Message::MessageReject {
            reason_code: reject_reason::UNSUPPORTED,
            rejected_message_header: Message::TYPE_XFER_SEGMENT,
        };

        let encoded = msg.encode();

        assert_eq!(encoded[0], Message::TYPE_MSG_REJECT);
        assert_eq!(encoded[1], reject_reason::UNSUPPORTED);
        assert_eq!(encoded[2], Message::TYPE_XFER_SEGMENT);
    }
}
