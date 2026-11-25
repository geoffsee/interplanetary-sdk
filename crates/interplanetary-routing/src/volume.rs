//! Volume-aware routing and first-hop reservations per charter §9

use interplanetary_contacts::ContactId;
use interplanetary_types::*;
use std::collections::HashMap;

/// Volume reservation for a contact
#[derive(Debug, Clone)]
pub struct VolumeReservation {
    /// Bundle making this reservation
    pub bundle_id: BundleId,
    /// Number of bytes reserved
    pub reserved_bytes: Bytes,
    /// Timestamp of reservation
    pub reserved_at: u64, // Timestamp
}

/// Volume-aware contact capacity tracker
#[derive(Debug)]
pub struct VolumeTracker {
    /// Reserved capacity per contact
    reservations: HashMap<ContactId, Vec<VolumeReservation>>,
    /// Total capacity per contact
    capacities: HashMap<ContactId, Bytes>,
}

impl VolumeTracker {
    /// Create new volume tracker
    pub fn new() -> Self {
        Self {
            reservations: HashMap::new(),
            capacities: HashMap::new(),
        }
    }

    /// Register contact capacity
    pub fn register_contact(&mut self, contact_id: ContactId, capacity: Bytes) {
        self.capacities.insert(contact_id, capacity);
        self.reservations.insert(contact_id, Vec::new());
    }

    /// Check available capacity
    pub fn available_capacity(&self, contact_id: ContactId) -> Option<Bytes> {
        let total = self.capacities.get(&contact_id)?;
        let reserved: u64 = self
            .reservations
            .get(&contact_id)?
            .iter()
            .map(|r| r.reserved_bytes.0)
            .sum();

        Some(Bytes(total.0.saturating_sub(reserved)))
    }

    /// Try to reserve capacity
    pub fn try_reserve(
        &mut self,
        contact_id: ContactId,
        bundle_id: BundleId,
        bytes: Bytes,
        timestamp: u64,
    ) -> Result<()> {
        let available = self
            .available_capacity(contact_id)
            .ok_or_else(|| Error::not_found("Contact not registered"))?;

        if bytes > available {
            return Err(Error::insufficient_storage(bytes, available));
        }

        let reservation = VolumeReservation {
            bundle_id: bundle_id.clone(),
            reserved_bytes: bytes,
            reserved_at: timestamp,
        };

        self.reservations
            .get_mut(&contact_id)
            .ok_or_else(|| Error::not_found("Contact not registered"))?
            .push(reservation);

        Ok(())
    }

    /// Release reservation
    pub fn release(&mut self, contact_id: ContactId, bundle_id: &BundleId) -> Result<()> {
        let reservations = self
            .reservations
            .get_mut(&contact_id)
            .ok_or_else(|| Error::not_found("Contact not registered"))?;

        reservations.retain(|r| &r.bundle_id != bundle_id);
        Ok(())
    }

    /// Clear expired reservations
    pub fn clear_expired(&mut self, current_time: u64, max_age: u64) {
        for reservations in self.reservations.values_mut() {
            reservations.retain(|r| current_time.saturating_sub(r.reserved_at) < max_age);
        }
    }
}

impl Default for VolumeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use interplanetary_types::{CreationTimestamp, DtnTimeMs, EndpointId};

    #[test]
    fn test_volume_reservation() {
        let mut tracker = VolumeTracker::new();
        let contact_id = ContactId(1);

        tracker.register_contact(contact_id, Bytes::from_kib(10).unwrap());

        let bundle_id = BundleId {
            source: EndpointId::ipn(0, 1, 0).unwrap(),
            timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            fragment_info: None,
        };

        // Should have 10 KiB available
        assert_eq!(
            tracker.available_capacity(contact_id),
            Some(Bytes::from_kib(10).unwrap())
        );

        // Reserve 5 KiB
        tracker
            .try_reserve(
                contact_id,
                bundle_id.clone(),
                Bytes::from_kib(5).unwrap(),
                0,
            )
            .unwrap();

        // Should have 5 KiB available
        assert_eq!(
            tracker.available_capacity(contact_id),
            Some(Bytes::from_kib(5).unwrap())
        );

        // Try to reserve 6 KiB (should fail)
        let bundle_id2 = BundleId {
            source: EndpointId::ipn(0, 2, 0).unwrap(),
            timestamp: CreationTimestamp::new(DtnTimeMs::ZERO, 1),
            fragment_info: None,
        };

        assert!(
            tracker
                .try_reserve(contact_id, bundle_id2, Bytes::from_kib(6).unwrap(), 0)
                .is_err()
        );

        // Release first reservation
        tracker.release(contact_id, &bundle_id).unwrap();

        // Should have 10 KiB available again
        assert_eq!(
            tracker.available_capacity(contact_id),
            Some(Bytes::from_kib(10).unwrap())
        );
    }
}
