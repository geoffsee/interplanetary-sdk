//! Bundle Protocol v7 wire codec and block processing (RFC 9171 §4).
//!
//! **Owns:** CBOR encode/decode, primary/canonical blocks, CRC, extension blocks,
//! fragmentation helpers, and generation/forward validation.
//!
//! **Does not own:** the Bundle Protocol Agent lifecycle — that lives in [`crate::bpa`]
//! (RFC 9171 §5: transmission, forwarding, delivery, deletion).
//!
//! Enable with the `bpv7` feature (on by default).
//!
//! # Examples
//!
//! Build, encode, and decode a minimal bundle:
//!
//! ```
//! use interplanetary_sdk::bp::{decode, encode, BundleBuilder, CrcType};
//! use interplanetary_sdk::types::{CreationTimestamp, DtnTimeMs, EndpointId};
//!
//! # fn main() -> interplanetary_sdk::Result<()> {
//! let bundle = BundleBuilder::new()
//!     .source(EndpointId::ipn(0, 1, 1)?)
//!     .destination(EndpointId::ipn(0, 2, 1)?)
//!     .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1_000), 1))
//!     .lifetime(60_000)
//!     .payload(b"hello".to_vec())
//!     .crc_type(CrcType::Crc16)
//!     .build()?;
//!
//! let bytes = encode(&bundle)?;
//! let decoded = decode(&bytes)?;
//! assert_eq!(decoded.id(), bundle.id());
//! # Ok(())
//! # }
//! ```

pub mod blocks;
pub mod bundle;
pub mod cbor_encoding;
pub mod codec;
pub mod crc;
pub mod extensions;
pub mod fragment;
pub mod processing;

pub use blocks::{Block, BlockFlags, BlockType, CanonicalBlock, PrimaryBlock};
pub use bundle::{Bundle, BundleBuilder};
pub use codec::{BundleCodec, DecodeError, EncodeError, decode, encode};
pub use crc::{Crc, CrcType};
pub use extensions::{BundleAgeBlock, HopCountBlock, PreviousNodeBlock};
pub use fragment::{ReassemblyManager, fragment_bundle};
pub use processing::{DeletionReason, process_on_forward, validate_at_generation};

// Re-export for convenience
pub use crate::types::{BundleId, CreationTimestamp, EndpointId};
