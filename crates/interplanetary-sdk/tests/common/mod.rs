//! Common test helpers for RFC 9171 behavioral tests

#![allow(dead_code)]

use ciborium::Value;
use interplanetary_sdk::bp::{Bundle, BundleBuilder};
use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};

/// RFC 9172 §3.6 Abstract Security Block (ASB) helpers for test mutation.
///
/// This crate encodes ASB block-type-specific data as a **sequence** of CBOR
/// values (not one wrapping array), matching `parse_bib_block` /
/// `parse_bcb_block`. Logical field order when parameters are present:
/// `targets, context_id, context_flags, security_source, parameters, results`
/// where `results` is `[ [* [result_id, value] ], ... ]` (one entry per target).
pub mod asb {
    use super::Value;
    use std::io::Cursor;

    pub const TARGETS: usize = 0;
    pub const CONTEXT_ID: usize = 1;
    pub const CONTEXT_FLAGS: usize = 2;
    pub const SECURITY_SOURCE: usize = 3;
    pub const PARAMETERS: usize = 4;
    pub const RESULTS: usize = 5;

    /// Index of the value inside an `[id, value]` parameter/result pair.
    pub const PAIR_VALUE: usize = 1;

    /// Decode concatenated ASB CBOR items into a logical `Value::Array`.
    pub fn decode(data: &[u8]) -> Value {
        let mut cursor = Cursor::new(data);
        let mut fields = Vec::new();
        while (cursor.position() as usize) < data.len() {
            let item: Value = ciborium::from_reader(&mut cursor).unwrap_or_else(|e| {
                panic!("ASB decode failed at offset {}: {}", cursor.position(), e)
            });
            fields.push(item);
        }
        assert!(
            fields.len() >= 5,
            "ASB expected at least 5 CBOR items, got {}",
            fields.len()
        );
        Value::Array(fields)
    }

    /// Encode a logical ASB array back to concatenated CBOR items.
    pub fn encode(asb: &Value) -> Vec<u8> {
        let fields = asb
            .as_array()
            .unwrap_or_else(|| panic!("expected ASB array for encode"));
        let mut out = Vec::new();
        for field in fields {
            ciborium::into_writer(field, &mut out)
                .unwrap_or_else(|e| panic!("ASB encode failed: {e}"));
        }
        out
    }

    fn expect_array_mut<'a>(value: &'a mut Value, label: &str) -> &'a mut Vec<Value> {
        value
            .as_array_mut()
            .unwrap_or_else(|| panic!("expected CBOR array for {label}"))
    }

    fn expect_array<'a>(value: &'a Value, label: &str) -> &'a Vec<Value> {
        value
            .as_array()
            .unwrap_or_else(|| panic!("expected CBOR array for {label}"))
    }

    fn field_array_mut<'a>(asb: &'a mut Value, field: usize, label: &str) -> &'a mut Vec<Value> {
        expect_array_mut(asb, "ASB")
            .get_mut(field)
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("ASB missing array field {field} ({label})"))
    }

    fn field_array<'a>(asb: &'a Value, field: usize, label: &str) -> &'a Vec<Value> {
        expect_array(asb, "ASB")
            .get(field)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("ASB missing array field {field} ({label})"))
    }

    /// Mutable security-context parameters list (`[[id, value], ...]`).
    pub fn parameters_mut(asb: &mut Value) -> &mut Vec<Value> {
        field_array_mut(asb, PARAMETERS, "security context parameters")
    }

    /// Mutable result-items for the first security target (`[[id, value], ...]`).
    pub fn first_target_result_items_mut(asb: &mut Value) -> &mut Vec<Value> {
        let results = field_array_mut(asb, RESULTS, "security results");
        results
            .first_mut()
            .and_then(Value::as_array_mut)
            .expect("ASB missing first target result items")
    }

    /// Immutable result-items for the first security target.
    pub fn first_target_result_items(asb: &Value) -> &Vec<Value> {
        let results = field_array(asb, RESULTS, "security results");
        results
            .first()
            .and_then(Value::as_array)
            .expect("ASB missing first target result items")
    }

    /// Find `[id, value]` by integer id and return a borrow of `value`.
    pub fn find_pair_value(pairs: &[Value], id: i128) -> Option<&Value> {
        for pair in pairs {
            let Some(arr) = pair.as_array() else {
                continue;
            };
            let Some(Value::Integer(pid)) = arr.first() else {
                continue;
            };
            if i128::from(*pid) == id {
                return arr.get(PAIR_VALUE);
            }
        }
        None
    }

    /// Find `[id, value]` by integer id and return a mutable borrow of `value`.
    pub fn find_pair_value_mut(pairs: &mut [Value], id: i128) -> Option<&mut Value> {
        for pair in pairs {
            let Some(arr) = pair.as_array_mut() else {
                continue;
            };
            let Some(Value::Integer(pid)) = arr.first() else {
                continue;
            };
            if i128::from(*pid) == id {
                return arr.get_mut(PAIR_VALUE);
            }
        }
        None
    }

    /// True when `item` is an `[id, value]` pair whose id equals `id`.
    pub fn pair_id_eq(item: &Value, id: i128) -> bool {
        item.as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| match v {
                Value::Integer(pid) => Some(i128::from(*pid) == id),
                _ => None,
            })
            .unwrap_or(false)
    }
}

/// Create a simple test bundle with sensible defaults
pub fn simple_bundle(source: EndpointId, dest: EndpointId) -> Bundle {
    BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000000), 0))
        .lifetime(3600000) // 1 hour
        .payload(vec![0x01, 0x02, 0x03, 0x04])
        .build()
        .unwrap()
}

/// Create a test bundle with custom creation time and lifetime
pub fn bundle_with_lifetime(
    source: EndpointId,
    dest: EndpointId,
    creation_time_ms: u64,
    lifetime_ms: u64,
) -> Bundle {
    BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(
            DtnTimeMs::from_millis(creation_time_ms),
            0,
        ))
        .lifetime(lifetime_ms)
        .payload(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .build()
        .unwrap()
}

/// Create a test bundle with creation time = 0 (requires Bundle Age)
pub fn bundle_with_zero_time(source: EndpointId, dest: EndpointId) -> Bundle {
    BundleBuilder::new()
        .source(source)
        .destination(dest)
        .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(0), 0))
        .lifetime(3600000)
        .payload(vec![0xCA, 0xFE])
        .build()
        .unwrap()
}

#[cfg(feature = "tcpclv4-model")]
use interplanetary_sdk::tcpcl::{Role, SessionConfig, TcpclSession};
#[cfg(feature = "tcpclv4-model")]
use interplanetary_sdk::types::Result;

/// Pair of Active and Passive sessions that have completed contact header
/// and SESS_INIT exchange, reaching Established state.
#[cfg(feature = "tcpclv4-model")]
pub struct SessionPair {
    pub active: TcpclSession,
    pub passive: TcpclSession,
}

#[cfg(feature = "tcpclv4-model")]
impl SessionPair {
    /// Create and establish a pair of Active/Passive sessions.
    ///
    /// This helper performs the complete handshake:
    /// 1. Active sends contact header
    /// 2. Passive sends contact header
    /// 3. Active sends SESS_INIT
    /// 4. Passive processes SESS_INIT and sends its own SESS_INIT
    /// 5. Active processes Passive's SESS_INIT
    ///
    /// Both sessions are now in Established state.
    pub fn establish() -> Result<Self> {
        Self::establish_with_config(
            SessionConfig {
                role: Role::Active,
                node_id: "dtn://active.node".to_string(),
                ..Default::default()
            },
            SessionConfig {
                role: Role::Passive,
                node_id: "dtn://passive.node".to_string(),
                ..Default::default()
            },
        )
    }

    /// Create and establish a pair of sessions with custom configurations
    pub fn establish_with_config(
        active_config: SessionConfig,
        passive_config: SessionConfig,
    ) -> Result<Self> {
        let mut active = TcpclSession::new(active_config).unwrap();
        let mut passive = TcpclSession::new(passive_config).unwrap();

        // RFC 9174 §4.1: Active sends contact header first
        let active_contact = active.send_contact_header()?;

        // Active sends contact header to Passive
        passive.process_contact_header(&active_contact)?;

        // RFC 9174 §4.1: Passive now sends its contact header (after receiving Active's)
        let passive_contact = passive.send_contact_header()?;

        // Active processes Passive's contact header
        active.process_contact_header(&passive_contact)?;

        // RFC 9174 §4.1: Active sends SESS_INIT first
        let active_init = active.send_session_init()?;

        // RFC 9174 §4.1: Passive sends its SESS_INIT (can send before processing active's)
        let passive_init = passive.send_session_init()?;

        // Now both process the received SESS_INITs
        // Active processes Passive's SESS_INIT
        active.process_session_init(&passive_init)?;

        // Passive processes Active's SESS_INIT
        passive.process_session_init(&active_init)?;

        // Both sessions should now be in Established state
        assert_eq!(
            active.state(),
            interplanetary_sdk::tcpcl::SessionState::Established
        );
        assert_eq!(
            passive.state(),
            interplanetary_sdk::tcpcl::SessionState::Established
        );

        Ok(Self { active, passive })
    }
}
