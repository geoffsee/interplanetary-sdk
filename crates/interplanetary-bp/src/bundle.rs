//! Bundle data structures per RFC 9171

use super::blocks::{CanonicalBlock, PrimaryBlock};
use interplanetary_types::{BundleId, CreationTimestamp, DtnTimeMs, EndpointId, Result};

/// A complete Bundle Protocol bundle.
///
/// Per RFC 9171 §4.1, a bundle consists of:
/// - One primary block (mandatory, first)
/// - Zero or more canonical blocks (extensions, payload, security)
///
/// Prefer [`BundleBuilder`] for construction; use [`crate::encode`] /
/// [`crate::decode`] for the wire format.
///
/// # Examples
///
/// ```
/// use interplanetary_bp::{BundleBuilder, CrcType};
/// use interplanetary_types::{CreationTimestamp, DtnTimeMs, EndpointId};
///
/// # fn main() -> interplanetary_types::Result<()> {
/// let bundle = BundleBuilder::new()
///     .source(EndpointId::ipn(0, 1, 0)?)
///     .destination(EndpointId::ipn(0, 3, 0)?)
///     .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 1))
///     .lifetime(60_000)
///     .payload(vec![0u8; 64])
///     .crc_type(CrcType::Crc16)
///     .build()?;
///
/// assert!(bundle.payload_block().is_some());
/// assert_eq!(bundle.primary.destination, EndpointId::ipn(0, 3, 0)?);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Bundle {
    /// Primary block (RFC 9171 §4.3.1)
    pub primary: PrimaryBlock,

    /// Canonical blocks in transmission order
    pub blocks: Vec<CanonicalBlock>,
}

impl Bundle {
    /// Create a new bundle
    pub fn new(primary: PrimaryBlock, blocks: Vec<CanonicalBlock>) -> Self {
        Self { primary, blocks }
    }

    /// Get the bundle's protocol identity
    pub fn id(&self) -> BundleId {
        // RFC 9171 §5.9: Fragments are keyed by source, timestamp, offset, and total length
        if let (Some(offset), Some(total_len)) = (
            self.primary.fragment_offset,
            self.primary.total_app_data_length,
        ) {
            BundleId::new_fragment(
                self.primary.source.clone(),
                self.primary.creation_timestamp,
                interplanetary_types::FragmentInfo { offset, total_len },
            )
        } else {
            BundleId::new(self.primary.source.clone(), self.primary.creation_timestamp)
        }
    }

    /// Find payload block (if present)
    pub fn payload_block(&self) -> Option<&CanonicalBlock> {
        self.blocks.iter().find(|b| b.block_type.is_payload())
    }

    /// Check if bundle has expired
    /// RFC 9171 §5.4: When creation time is 0, bundle age MUST be obtained from Bundle Age block
    pub fn is_expired(&self, now: DtnTimeMs) -> bool {
        if let Some(expiry) = self.primary.expiry_time() {
            now >= expiry
        } else {
            // Unknown clock bundles (creation time = 0) use Bundle Age block
            // RFC 9171 §5.4: "bundle age MUST be obtained from the Bundle Age extension block"
            if let Some(age_block) = self.blocks.iter().find(|b| b.block_type.is_bundle_age()) {
                // Decode Bundle Age block
                if let Ok(age) = ciborium::from_reader::<ciborium::Value, _>(&age_block.data[..])
                    && let Some(age_ms) = age.as_integer().and_then(|i| u64::try_from(i).ok())
                {
                    // Bundle is expired if age >= lifetime
                    return age_ms >= self.primary.lifetime;
                }
            }
            // If no Bundle Age block or decode fails, cannot determine expiry
            false
        }
    }

    /// Get total size estimate in bytes
    pub fn estimated_size(&self) -> usize {
        // Rough estimate: will be refined with actual encoding
        let primary_size = 200; // Primary block ~150-200 bytes
        let blocks_size: usize = self
            .blocks
            .iter()
            .map(|b| b.data.len() + 50) // Block overhead ~50 bytes
            .sum();
        primary_size + blocks_size
    }
}

/// Builder for constructing [`Bundle`] values with validated fields.
///
/// Required: [`source`](Self::source), [`destination`](Self::destination),
/// [`creation_timestamp`](Self::creation_timestamp), [`lifetime`](Self::lifetime).
/// Payload defaults to empty if omitted; CRC defaults to [`super::CrcType::None`].
///
/// # Examples
///
/// ```
/// use interplanetary_bp::{BundleBuilder, CrcType};
/// use interplanetary_types::{CreationTimestamp, DtnTimeMs, EndpointId};
///
/// # fn main() -> interplanetary_types::Result<()> {
/// let bundle = BundleBuilder::new()
///     .source(EndpointId::parse("ipn:0.1.1")?)
///     .destination(EndpointId::parse("ipn:0.2.1")?)
///     .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(100), 42))
///     .lifetime(3_600_000)
///     .payload(b"ping".to_vec())
///     .crc_type(CrcType::Crc32)
///     .build()?;
/// assert_eq!(bundle.id().timestamp.sequence, 42);
/// # Ok(())
/// # }
/// ```
#[derive(Default, Debug)]
pub struct BundleBuilder {
    source: Option<EndpointId>,
    destination: Option<EndpointId>,
    report_to: Option<EndpointId>,
    creation_timestamp: Option<CreationTimestamp>,
    lifetime: Option<u64>,
    payload: Option<Vec<u8>>,
    crc_type: Option<super::CrcType>,
    bundle_flags: Option<u64>,
}

impl BundleBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set source endpoint
    pub fn source(mut self, source: EndpointId) -> Self {
        self.source = Some(source);
        self
    }

    /// Set destination endpoint
    pub fn destination(mut self, dest: EndpointId) -> Self {
        self.destination = Some(dest);
        self
    }

    /// Set report-to endpoint (defaults to source if not set)
    pub fn report_to(mut self, report_to: EndpointId) -> Self {
        self.report_to = Some(report_to);
        self
    }

    /// Set creation timestamp
    pub fn creation_timestamp(mut self, timestamp: CreationTimestamp) -> Self {
        self.creation_timestamp = Some(timestamp);
        self
    }

    /// Set lifetime in milliseconds
    pub fn lifetime(mut self, lifetime_ms: u64) -> Self {
        self.lifetime = Some(lifetime_ms);
        self
    }

    /// Set payload data
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = Some(data);
        self
    }

    /// Set CRC type for primary block and payload block
    pub fn crc_type(mut self, crc_type: super::CrcType) -> Self {
        self.crc_type = Some(crc_type);
        self
    }

    /// Set bundle processing control flags (RFC 9171 §4.2.3)
    pub fn bundle_flags(mut self, flags: u64) -> Self {
        self.bundle_flags = Some(flags);
        self
    }

    /// Build the bundle
    pub fn build(self) -> Result<Bundle> {
        use super::BlockType;
        use interplanetary_types::Error;

        let source = self
            .source
            .ok_or_else(|| Error::invalid_config("Missing source"))?;
        let destination = self
            .destination
            .ok_or_else(|| Error::invalid_config("Missing destination"))?;
        let report_to = self.report_to.unwrap_or_else(|| source.clone());
        let creation_timestamp = self
            .creation_timestamp
            .ok_or_else(|| Error::invalid_config("Missing creation timestamp"))?;
        let lifetime = self
            .lifetime
            .ok_or_else(|| Error::invalid_config("Missing lifetime"))?;

        let crc_type = self.crc_type.unwrap_or(super::CrcType::None);
        let mut bundle_flags = self.bundle_flags.unwrap_or(0);

        // RFC 9171 §4.2.3: If source is null endpoint, must set constraints
        if source.is_null() {
            // Bit 2: Bundle must not be fragmented
            bundle_flags |= 0x000004;
            // Bits 14-19: All status report flags must be zero
            bundle_flags &= !0x000FC000;
        }

        // RFC 9171 §4.2.3 (RFC9171-4-018): If bundle's ADU is an administrative record,
        // then all status report request flag values MUST be zero
        const IS_ADMIN_RECORD: u64 = 0x000002;
        const STATUS_REPORT_FLAGS: u64 = 0x07C000; // Bits 14-18
        if (bundle_flags & IS_ADMIN_RECORD) != 0 && (bundle_flags & STATUS_REPORT_FLAGS) != 0 {
            return Err(Error::malformed_input(
                "Admin records must have zero status report flags (RFC 9171 §4.2.3)",
            ));
        }

        let primary = PrimaryBlock {
            version: 7,
            bundle_flags,
            crc_type,
            destination,
            source,
            report_to,
            creation_timestamp,
            lifetime,
            fragment_offset: None,
            total_app_data_length: None,
        };

        let mut blocks = Vec::new();

        // Add payload block if provided
        if let Some(data) = self.payload {
            blocks.push(CanonicalBlock {
                block_type: BlockType::Payload,
                block_number: 1,
                block_flags: 0,
                crc_type,
                data,
            });
        }

        Ok(Bundle::new(primary, blocks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_types::DtnTimeMs;

    #[test]
    fn test_bundle_builder() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let dest = EndpointId::ipn(0, 2, 0).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

        let bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(dest.clone())
            .creation_timestamp(timestamp)
            .lifetime(60_000)
            .payload(b"Hello DTN".to_vec())
            .build()
            .unwrap();

        assert_eq!(bundle.primary.source, source);
        assert_eq!(bundle.primary.destination, dest);
        assert_eq!(bundle.blocks.len(), 1);
        assert!(bundle.payload_block().is_some());
    }

    #[test]
    fn test_bundle_id() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let dest = EndpointId::ipn(0, 2, 0).unwrap();
        let timestamp = CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0);

        let bundle = BundleBuilder::new()
            .source(source.clone())
            .destination(dest)
            .creation_timestamp(timestamp)
            .lifetime(60_000)
            .build()
            .unwrap();

        let id = bundle.id();
        assert_eq!(id.source, source);
        assert_eq!(id.timestamp, timestamp);
    }
}
