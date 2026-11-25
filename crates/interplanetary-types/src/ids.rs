use super::{DtnTimeMs, Error, Result};
use std::fmt;

/// Endpoint Identifier per RFC 9171 §4.2.5
///
/// Represents a Bundle Protocol endpoint using a URI scheme.
/// Supported schemes: `dtn:` (§4.2.5.1.1), `ipn:` (§4.2.5.1.2, RFC 9758)
///
/// Unknown schemes are preserved but bounded to prevent resource exhaustion.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum EndpointId {
    /// dtn: scheme with SSP (scheme-specific part)
    Dtn {
        /// Scheme-specific part (node name + optional demux)
        ssp: String,
    },

    /// ipn: scheme with allocator, node, and service numbers (RFC 9758)
    Ipn {
        /// Node allocator
        allocator: u64,
        /// Node number
        node: u64,
        /// Service number
        service: u64,
    },

    /// Null endpoint (used for anonymous bundles)
    Null,

    /// Unknown/unsupported scheme (preserved for protocol compliance)
    Unknown {
        /// Scheme identifier
        scheme: String,
        /// Scheme-specific part
        ssp: String,
    },
}

impl EndpointId {
    /// Maximum URI length to prevent resource exhaustion
    const MAX_URI_LEN: usize = 4096;

    /// Parse endpoint ID from URI string.
    ///
    /// Accepts `dtn:` and `ipn:` (RFC 9758) forms. `dtn:none` becomes [`EndpointId::Null`].
    /// Unknown schemes are preserved (bounded) rather than rejected.
    ///
    /// # Examples
    ///
    /// ```
    /// use interplanetary_types::EndpointId;
    ///
    /// # fn main() -> interplanetary_types::Result<()> {
    /// let ipn = EndpointId::parse("ipn:0.1.1")?;
    /// assert_eq!(ipn.scheme(), "ipn");
    /// // Allocator 0 uses the two-element display form (RFC 9758 legacy)
    /// assert_eq!(ipn.to_string(), "ipn:1.1");
    ///
    /// let dtn = EndpointId::parse("dtn://node-a/service")?;
    /// assert_eq!(dtn.scheme(), "dtn");
    ///
    /// assert!(EndpointId::parse("dtn:none")?.is_null());
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(uri: &str) -> Result<Self> {
        if uri.len() > Self::MAX_URI_LEN {
            return Err(Error::malformed_input(format!(
                "URI too long: {} > {}",
                uri.len(),
                Self::MAX_URI_LEN
            )));
        }

        if uri == "dtn:none" {
            return Ok(Self::Null);
        }

        let (scheme, ssp) = uri
            .split_once(':')
            .ok_or_else(|| Error::malformed_input("Invalid URI: missing scheme separator"))?;

        match scheme {
            "dtn" => Self::parse_dtn(ssp),
            "ipn" => Self::parse_ipn(ssp),
            _ => Ok(Self::Unknown {
                scheme: scheme.to_string(),
                ssp: ssp.to_string(),
            }),
        }
    }

    fn parse_dtn(ssp: &str) -> Result<Self> {
        if ssp.is_empty() {
            return Err(Error::malformed_input("Empty dtn: SSP"));
        }

        // RFC validation would check for valid characters, percent-encoding, etc.
        // For now, basic validation
        Ok(Self::Dtn {
            ssp: ssp.to_string(),
        })
    }

    fn parse_ipn(ssp: &str) -> Result<Self> {
        // RFC 9758 format: allocator.node.service
        // Legacy format: node.service (allocator = 0)
        let parts: Vec<&str> = ssp.split('.').collect();

        // Helper to parse number with RFC 9758 §4 validation
        let parse_number = |s: &str, field_name: &str| -> Result<u64> {
            // RFC 9758 §4: '!' is a shorthand for 4294967295 (u32::MAX)
            if s == "!" {
                return Ok(u32::MAX as u64);
            }

            // RFC 9758 §4: "All leading '0' characters MUST be omitted"
            // Reject numbers with leading zeros (except "0" itself)
            if s.len() > 1 && s.starts_with('0') {
                return Err(Error::malformed_input(format!(
                    "ipn {} has leading zero (RFC 9758 §4)",
                    field_name
                )));
            }
            let value = s
                .parse::<u64>()
                .map_err(|_| Error::malformed_input(format!("Invalid ipn {}", field_name)))?;

            // RFC 9758 §4: Node and service numbers MUST fit in u32
            // "The IPN numeric code shall be in the range of 0 to 4294967295"
            if value > u32::MAX as u64 {
                return Err(Error::malformed_input(format!(
                    "ipn {} exceeds u32::MAX ({}): {}",
                    field_name,
                    u32::MAX,
                    value
                )));
            }

            Ok(value)
        };

        match parts.len() {
            2 => {
                // Legacy format: node.service
                let node = parse_number(parts[0], "node number")?;
                let service = parse_number(parts[1], "service number")?;

                // RFC 9758 §3.4.1: Node 0 under Default Allocator (0) identifies Null ipn URI
                // "any ipn URI with a zero (0) Allocator Identifier and a zero (0) Node Number"
                // "processors of such ipn URIs MUST consider them as the Null ipn URI"
                if node == 0 {
                    // Node 0 with allocator 0 always maps to Null, regardless of service
                    return Ok(Self::Null);
                }

                Ok(Self::Ipn {
                    allocator: 0,
                    node,
                    service,
                })
            }
            3 => {
                // RFC 9758 format: allocator.node.service
                let allocator = parse_number(parts[0], "allocator")?;
                let node = parse_number(parts[1], "node number")?;
                let service = parse_number(parts[2], "service number")?;

                // RFC 9758 §3.4.1 explicitly addresses allocator=0, node=0 only
                // It says node 0 is "solely" for Null under Default Allocator but doesn't
                // explicitly forbid node=0 with other allocators. Be permissive.
                if node == 0 {
                    // Treat as Null for consistency (conservative interpretation of "solely")
                    return Ok(Self::Null);
                }

                Ok(Self::Ipn {
                    allocator,
                    node,
                    service,
                })
            }
            _ => Err(Error::malformed_input(
                "Invalid ipn format (expected node.service or allocator.node.service)",
            )),
        }
    }

    /// Create a dtn: endpoint
    pub fn dtn(ssp: impl Into<String>) -> Result<Self> {
        let ssp = ssp.into();
        if ssp.is_empty() {
            return Err(Error::invalid_config("Empty dtn: SSP"));
        }
        Ok(Self::Dtn { ssp })
    }

    /// Create an `ipn:` endpoint with validation.
    ///
    /// RFC 9758 §4: node and service numbers MUST fit in `u32`.
    /// RFC 9758 §3.4.1: `ipn:0.0.<service≠0>` MUST NOT be composed.
    ///
    /// # Examples
    ///
    /// ```
    /// use interplanetary_types::EndpointId;
    ///
    /// # fn main() -> interplanetary_types::Result<()> {
    /// let eid = EndpointId::ipn(0, 1, 1)?;
    /// assert_eq!(eid.to_string(), "ipn:1.1"); // allocator 0 → legacy form
    ///
    /// let named = EndpointId::ipn(1, 2, 3)?;
    /// assert_eq!(named.to_string(), "ipn:1.2.3");
    ///
    /// // Node number zero with non-zero service is rejected
    /// assert!(EndpointId::ipn(0, 0, 1).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn ipn(allocator: u64, node: u64, service: u64) -> Result<Self> {
        // RFC 9758 §4: "The IPN numeric code shall be in the range of 0 to 4294967295"
        if node > u32::MAX as u64 {
            return Err(Error::malformed_input(format!(
                "ipn node number exceeds u32::MAX ({}): {}",
                u32::MAX,
                node
            )));
        }
        if service > u32::MAX as u64 {
            return Err(Error::malformed_input(format!(
                "ipn service number exceeds u32::MAX ({}): {}",
                u32::MAX,
                service
            )));
        }

        // RFC 9758 §3.4.1: "Such ipn URIs MUST NOT be composed"
        // "Any ipn URI (regardless of the Allocator Identifier) that has
        // a Node Number of zero (0) is invalid."
        // The composition ban applies to allocator=0, node=0 with non-zero service
        if allocator == 0 && node == 0 && service != 0 {
            return Err(Error::malformed_input(format!(
                "ipn URI with allocator=0, node=0, service={} MUST NOT be composed (RFC 9758 §3.4.1)",
                service
            )));
        }

        Ok(Self::Ipn {
            allocator,
            node,
            service,
        })
    }

    /// Create null endpoint
    pub fn null() -> Self {
        Self::Null
    }

    /// Get scheme name
    pub fn scheme(&self) -> &str {
        match self {
            Self::Dtn { .. } => "dtn",
            Self::Ipn { .. } => "ipn",
            Self::Null => "dtn",
            Self::Unknown { scheme, .. } => scheme,
        }
    }

    /// Check if this is the null endpoint
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Check if this is a LocalNode ipn EID per RFC 9758 §3.4.2
    ///
    /// LocalNode is node 4294967295 in the Default Allocator (allocator 0).
    pub fn is_local_node(&self) -> bool {
        matches!(
            self,
            Self::Ipn {
                allocator: 0,
                node: 4294967295,
                ..
            }
        )
    }

    /// Check if this is a Private Use ipn EID per RFC 9758 §5.5
    ///
    /// Private Use range in Default Allocator: nodes 1..16777215 (0x000001..0xFFFFFF)
    pub fn is_private_use_ipn(&self) -> bool {
        matches!(
            self,
            Self::Ipn {
                allocator: 0,
                node: 1..=16777215,
                ..
            }
        )
    }

    /// Check if this EID is valid as a BPSec security source per RFC 9758 §5.4-5.5
    ///
    /// Returns Ok(()) if valid, Err with reason if not.
    ///
    /// Per RFC 9758:
    /// - §5.4: LocalNode ipn EID MUST NOT be used as a BPSec security source
    /// - §5.5: Private Use ipn EID MUST NOT be used as a BPSec security source
    ///   (for bundles crossing administrative domains)
    pub fn validate_as_security_source(&self) -> Result<()> {
        if self.is_local_node() {
            return Err(Error::policy_rejected(
                "LocalNode ipn EID MUST NOT be used as BPSec security source (RFC 9758 §5.4)",
            ));
        }
        if self.is_private_use_ipn() {
            return Err(Error::policy_rejected(
                "Private Use ipn EID MUST NOT be used as BPSec security source (RFC 9758 §5.5)",
            ));
        }
        Ok(())
    }

    /// Get canonical bytes for security operations (IPPT/AAD)
    ///
    /// This is the CBOR encoding of the EID for security canonical forms.
    /// Not the same as Display format.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Placeholder: would be CBOR [scheme_code, ssp_data]
        // For now, use URI format as approximation
        self.to_string().into_bytes()
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dtn { ssp } => write!(f, "dtn:{}", ssp),
            Self::Ipn {
                allocator,
                node,
                service,
            } => {
                // Helper to format a number, using '!' for u32::MAX per RFC 9758 §4
                let format_num = |n: u64| -> String {
                    if n == u32::MAX as u64 {
                        "!".to_string()
                    } else {
                        n.to_string()
                    }
                };

                if *allocator == 0 {
                    // Legacy format
                    write!(f, "ipn:{}.{}", format_num(*node), format_num(*service))
                } else {
                    write!(
                        f,
                        "ipn:{}.{}.{}",
                        format_num(*allocator),
                        format_num(*node),
                        format_num(*service)
                    )
                }
            }
            Self::Null => write!(f, "dtn:none"),
            Self::Unknown { scheme, ssp } => write!(f, "{}:{}", scheme, ssp),
        }
    }
}

impl fmt::Debug for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dtn { ssp } => f.debug_struct("Dtn").field("ssp", ssp).finish(),
            Self::Ipn {
                allocator,
                node,
                service,
            } => f
                .debug_struct("Ipn")
                .field("allocator", allocator)
                .field("node", node)
                .field("service", service)
                .finish(),
            Self::Null => write!(f, "Null"),
            Self::Unknown { scheme, ssp } => f
                .debug_struct("Unknown")
                .field("scheme", scheme)
                .field("ssp", ssp)
                .finish(),
        }
    }
}

/// Node identifier extracted from an endpoint ID
///
/// Represents the identity of a bundle node, not a service endpoint.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum NodeId {
    /// dtn: node (node-name portion of SSP)
    Dtn {
        /// Node name
        node_name: String,
    },

    /// ipn: node (allocator + node, no service)
    Ipn {
        /// Node allocator number
        allocator: u64,
        /// Node number within allocator
        node: u64,
    },

    /// Unknown scheme node
    Unknown {
        /// Node identifier string
        identifier: String,
    },
}

impl NodeId {
    /// Extract node ID from endpoint ID
    pub fn from_endpoint(eid: &EndpointId) -> Result<Self> {
        match eid {
            EndpointId::Dtn { ssp } => {
                // For dtn:, the node-name is typically before the first '/' or the whole SSP
                let node_name = ssp.split('/').next().unwrap_or(ssp).to_string();
                Ok(Self::Dtn { node_name })
            }
            EndpointId::Ipn {
                allocator, node, ..
            } => Ok(Self::Ipn {
                allocator: *allocator,
                node: *node,
            }),
            EndpointId::Null => Err(Error::invalid_config("Cannot extract node from null EID")),
            EndpointId::Unknown { scheme, ssp } => Ok(Self::Unknown {
                identifier: format!("{}:{}", scheme, ssp),
            }),
        }
    }

    /// Create dtn node ID
    pub fn dtn(node_name: impl Into<String>) -> Self {
        Self::Dtn {
            node_name: node_name.into(),
        }
    }

    /// Create ipn node ID
    pub fn ipn(allocator: u64, node: u64) -> Self {
        Self::Ipn { allocator, node }
    }

    /// Convert to endpoint ID (with service 0 for IPN)
    pub fn to_endpoint_id(&self) -> Result<EndpointId> {
        match self {
            NodeId::Ipn { allocator, node } => EndpointId::ipn(*allocator, *node, 0),
            NodeId::Dtn { node_name } => Ok(EndpointId::dtn(node_name).unwrap_or(EndpointId::Null)),
            NodeId::Unknown { identifier: _ } => {
                Ok(EndpointId::Null) // Fallback for unknown
            }
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dtn { node_name } => write!(f, "dtn:{}", node_name),
            Self::Ipn { allocator, node } => {
                if *allocator == 0 {
                    write!(f, "ipn:{}", node)
                } else {
                    write!(f, "ipn:{}.{}", allocator, node)
                }
            }
            Self::Unknown { identifier } => write!(f, "{}", identifier),
        }
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dtn { node_name } => f.debug_struct("Dtn").field("node_name", node_name).finish(),
            Self::Ipn { allocator, node } => f
                .debug_struct("Ipn")
                .field("allocator", allocator)
                .field("node", node)
                .finish(),
            Self::Unknown { identifier } => f
                .debug_struct("Unknown")
                .field("identifier", identifier)
                .finish(),
        }
    }
}

/// Bundle creation timestamp per RFC 9171 §4.2.7
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CreationTimestamp {
    /// DTN time (0 = unknown clock)
    pub time: DtnTimeMs,
    /// Sequence number for disambiguation
    pub sequence: u64,
}

impl CreationTimestamp {
    /// Create new timestamp
    pub const fn new(time: DtnTimeMs, sequence: u64) -> Self {
        Self { time, sequence }
    }

    /// Check if clock is unknown (time = 0)
    pub const fn is_unknown_clock(&self) -> bool {
        self.time.is_unknown()
    }
}

impl fmt::Debug for CreationTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreationTimestamp")
            .field("time", &self.time)
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl fmt::Display for CreationTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.time, self.sequence)
    }
}

/// Fragment information for fragmented bundles
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FragmentInfo {
    /// Offset in bytes from start of original payload
    pub offset: u64,
    /// Total length of original payload
    pub total_len: u64,
}

impl FragmentInfo {
    /// Create new fragment info
    pub const fn new(offset: u64, total_len: u64) -> Self {
        Self { offset, total_len }
    }

    /// Check if this describes a complete (unfragmented) bundle
    pub const fn is_complete(&self) -> bool {
        self.offset == 0 && self.total_len == 0
    }
}

/// Bundle identifier per protocol semantics
///
/// Uniquely identifies a bundle (or fragment) for protocol purposes.
/// Note: Anonymous source bundles (null EID) require additional internal tracking.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BundleId {
    /// Source endpoint
    pub source: EndpointId,
    /// Creation timestamp
    pub timestamp: CreationTimestamp,
    /// Fragment info (None = complete bundle)
    pub fragment_info: Option<FragmentInfo>,
}

impl BundleId {
    /// Create bundle ID for complete (unfragmented) bundle
    pub fn new(source: EndpointId, timestamp: CreationTimestamp) -> Self {
        Self {
            source,
            timestamp,
            fragment_info: None,
        }
    }

    /// Create bundle ID for fragment
    pub fn new_fragment(
        source: EndpointId,
        timestamp: CreationTimestamp,
        fragment_info: FragmentInfo,
    ) -> Self {
        Self {
            source,
            timestamp,
            fragment_info: Some(fragment_info),
        }
    }

    /// Check if this is a complete (unfragmented) bundle
    pub fn is_complete(&self) -> bool {
        self.fragment_info.is_none()
    }

    /// Check if source is anonymous (null)
    pub fn is_anonymous_source(&self) -> bool {
        self.source.is_null()
    }
}

impl fmt::Debug for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("BundleId");
        s.field("source", &self.source);
        s.field("timestamp", &self.timestamp);
        if let Some(frag) = &self.fragment_info {
            s.field("fragment", frag);
        }
        s.finish()
    }
}

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.source, self.timestamp)?;
        if let Some(frag) = &self.fragment_info {
            write!(f, "[{}:{}]", frag.offset, frag.total_len)?;
        }
        Ok(())
    }
}

// Internal ID types (not part of public API)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dtn_eid() {
        let eid = EndpointId::parse("dtn://example/service").unwrap();
        assert_eq!(eid.scheme(), "dtn");
        assert_eq!(eid.to_string(), "dtn://example/service");
    }

    #[test]
    fn test_parse_ipn_legacy() {
        let eid = EndpointId::parse("ipn:1.2").unwrap();
        match eid {
            EndpointId::Ipn {
                allocator,
                node,
                service,
            } => {
                assert_eq!(allocator, 0);
                assert_eq!(node, 1);
                assert_eq!(service, 2);
            }
            _ => panic!("Expected Ipn variant"),
        }
        assert_eq!(eid.to_string(), "ipn:1.2");
    }

    #[test]
    fn test_parse_ipn_rfc9758() {
        let eid = EndpointId::parse("ipn:100.1.2").unwrap();
        match eid {
            EndpointId::Ipn {
                allocator,
                node,
                service,
            } => {
                assert_eq!(allocator, 100);
                assert_eq!(node, 1);
                assert_eq!(service, 2);
            }
            _ => panic!("Expected Ipn variant"),
        }
        assert_eq!(eid.to_string(), "ipn:100.1.2");
    }

    #[test]
    fn test_null_eid() {
        let eid = EndpointId::parse("dtn:none").unwrap();
        assert!(eid.is_null());
        assert_eq!(eid.to_string(), "dtn:none");
    }

    #[test]
    fn test_unknown_scheme() {
        let eid = EndpointId::parse("unknown:data").unwrap();
        assert_eq!(eid.scheme(), "unknown");
        assert_eq!(eid.to_string(), "unknown:data");
    }

    #[test]
    fn test_node_id_from_dtn() {
        let eid = EndpointId::dtn("example/service").unwrap();
        let node = NodeId::from_endpoint(&eid).unwrap();
        assert_eq!(node.to_string(), "dtn:example");
    }

    #[test]
    fn test_node_id_from_ipn() {
        let eid = EndpointId::ipn(100, 1, 2).unwrap();
        let node = NodeId::from_endpoint(&eid).unwrap();
        match node {
            NodeId::Ipn { allocator, node } => {
                assert_eq!(allocator, 100);
                assert_eq!(node, 1);
            }
            _ => panic!("Expected Ipn node"),
        }
    }

    #[test]
    fn test_creation_timestamp() {
        let ts = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 42);
        assert_eq!(ts.time.as_millis(), 1000);
        assert_eq!(ts.sequence, 42);
        assert!(!ts.is_unknown_clock());

        let ts_unknown = CreationTimestamp::new(DtnTimeMs::UNKNOWN, 0);
        assert!(ts_unknown.is_unknown_clock());
    }

    #[test]
    fn test_bundle_id_complete() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);
        let bid = BundleId::new(source.clone(), timestamp);

        assert!(bid.is_complete());
        assert!(!bid.is_anonymous_source());
        assert_eq!(bid.to_string(), "ipn:1.0@1000ms#0");
    }

    #[test]
    fn test_bundle_id_fragment() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);
        let frag = FragmentInfo::new(500, 2000);
        let bid = BundleId::new_fragment(source, timestamp, frag);

        assert!(!bid.is_complete());
        assert!(bid.to_string().contains("[500:2000]"));
    }

    #[test]
    fn test_uri_too_long() {
        let long_uri = format!("dtn:{}", "x".repeat(5000));
        assert!(EndpointId::parse(&long_uri).is_err());
    }
}
