//! Bundle storage with bounded capacity per charter §8

use crate::bp::Bundle;
use crate::types::{BundleId, Bytes, Error, Result};
use std::collections::HashMap;

/// Storage usage statistics
#[derive(Debug, Clone, Copy)]
pub struct StorageUsage {
    /// Bytes currently used
    pub used: Bytes,
    /// Total capacity in bytes
    pub capacity: Bytes,
    /// Number of bundles stored
    pub bundle_count: usize,
}

impl StorageUsage {
    /// Calculate available bytes
    pub fn available(&self) -> Bytes {
        self.capacity.saturating_sub(self.used)
    }

    /// Check if storage is full
    pub fn is_full(&self) -> bool {
        self.used >= self.capacity
    }
}

/// Bounded bundle storage.
///
/// `admit` is atomic: on failure the store is unchanged. [`get`](Self::get)
/// returns an owned [`Bundle`] reference while the entry remains admitted.
pub trait BundleStore {
    /// Admit bundle (atomic: success = stored, failure = no change)
    fn admit(&mut self, bundle: Bundle) -> Result<BundleId>;

    /// Get bundle by ID (immutable reference)
    fn get(&self, id: &BundleId) -> Option<&Bundle>;

    /// Remove bundle and free storage
    fn remove(&mut self, id: &BundleId) -> Result<()>;

    /// Enumerate all bundle IDs
    fn enumerate(&self) -> Vec<BundleId>;

    /// Get storage usage
    fn usage(&self) -> StorageUsage;
}

/// In-memory [`BundleStore`] with a hard byte capacity.
///
/// # Examples
///
/// ```
/// use interplanetary_sdk::bp::{BundleBuilder, CrcType};
/// use interplanetary_sdk::sim::{BundleStore, StorageManager};
/// use interplanetary_sdk::types::*;
///
/// # fn main() -> Result<()> {
/// let mut store = StorageManager::new(Bytes::from_kib(64).unwrap());
/// let bundle = BundleBuilder::new()
///     .source(EndpointId::ipn(0, 1, 0)?)
///     .destination(EndpointId::ipn(0, 2, 0)?)
///     .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1), 1))
///     .lifetime(60_000)
///     .payload(b"stored".to_vec())
///     .crc_type(CrcType::Crc16)
///     .build()?;
///
/// let id = store.admit(bundle)?;
/// assert!(store.get(&id).is_some());
/// assert_eq!(store.usage().bundle_count, 1);
/// store.remove(&id)?;
/// assert!(store.get(&id).is_none());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct StorageManager {
    bundles: HashMap<BundleId, Bundle>,
    capacity: Bytes,
    used: Bytes,
}

impl StorageManager {
    /// Create new storage manager with given capacity
    pub fn new(capacity: Bytes) -> Self {
        Self {
            bundles: HashMap::new(),
            capacity,
            used: Bytes::ZERO,
        }
    }
}

impl BundleStore for StorageManager {
    fn admit(&mut self, bundle: Bundle) -> Result<BundleId> {
        let bundle_id = bundle.id();
        let size = Bytes(bundle.estimated_size() as u64);

        // Check capacity
        let available = self.capacity.saturating_sub(self.used);
        if size > available {
            return Err(Error::insufficient_storage(size, available));
        }

        // Check for duplicate
        if self.bundles.contains_key(&bundle_id) {
            return Err(Error::protocol_violation("Bundle already stored"));
        }

        // Atomic: insert and update usage
        self.bundles.insert(bundle_id.clone(), bundle);
        self.used = self.used.saturating_add(size);

        Ok(bundle_id)
    }

    fn get(&self, id: &BundleId) -> Option<&Bundle> {
        self.bundles.get(id)
    }

    fn remove(&mut self, id: &BundleId) -> Result<()> {
        if let Some(bundle) = self.bundles.remove(id) {
            let size = Bytes(bundle.estimated_size() as u64);
            self.used = self.used.saturating_sub(size);
        }
        Ok(())
    }

    fn enumerate(&self) -> Vec<BundleId> {
        self.bundles.keys().cloned().collect()
    }

    fn usage(&self) -> StorageUsage {
        StorageUsage {
            used: self.used,
            capacity: self.capacity,
            bundle_count: self.bundles.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp::BundleBuilder;
    use crate::types::{CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_storage_admit_and_retrieve() {
        let mut storage = StorageManager::new(Bytes::from_mib(1).unwrap());

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let bundle_id = storage.admit(bundle).unwrap();

        assert!(storage.get(&bundle_id).is_some());
        assert_eq!(storage.usage().bundle_count, 1);
    }

    #[test]
    fn test_storage_capacity_enforcement() {
        let mut storage = StorageManager::new(Bytes(500)); // Very small capacity

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
            .lifetime(60_000)
            .payload(vec![0u8; 10000]) // Large payload
            .build()
            .unwrap();

        let result = storage.admit(bundle);
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_remove_frees_space() {
        let mut storage = StorageManager::new(Bytes::from_kib(10).unwrap());

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let bundle_id = storage.admit(bundle).unwrap();
        let used_before = storage.usage().used;

        storage.remove(&bundle_id).unwrap();
        let used_after = storage.usage().used;

        assert!(used_after < used_before);
        assert_eq!(storage.usage().bundle_count, 0);
    }

    #[test]
    fn test_storage_rejects_duplicate() {
        let mut storage = StorageManager::new(Bytes::from_mib(1).unwrap());

        let bundle = BundleBuilder::new()
            .source(EndpointId::ipn(0, 1, 0).unwrap())
            .destination(EndpointId::ipn(0, 2, 0).unwrap())
            .creation_timestamp(CreationTimestamp::new(DtnTimeMs::from_millis(1000), 0))
            .lifetime(60_000)
            .payload(b"Test".to_vec())
            .build()
            .unwrap();

        let bundle_clone = bundle.clone();

        storage.admit(bundle).unwrap();
        let result = storage.admit(bundle_clone);

        assert!(result.is_err());
    }
}
