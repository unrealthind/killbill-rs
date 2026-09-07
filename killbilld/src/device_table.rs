//! The daemon's view of what is currently plugged in.
//!
//! A count per USB id (a hub or a headset can legitimately present the same id
//! more than once). The daemon owns every mutation; the [`policy`](crate::policy)
//! engine only reads it, and only to answer "how many of this id are already
//! here?" for the `max_count` check.

use std::collections::HashMap;

use killbill_proto::UsbId;

/// Connected-device counts, keyed by USB id.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeviceTable {
    counts: HashMap<UsbId, u32>,
}

impl DeviceTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many devices with this id are currently connected.
    pub fn count(&self, id: UsbId) -> u32 {
        self.counts.get(&id).copied().unwrap_or(0)
    }

    /// Total number of connected devices across all ids.
    pub fn total(&self) -> usize {
        self.counts.values().map(|&c| c as usize).sum()
    }

    /// Number of distinct ids present.
    pub fn distinct(&self) -> usize {
        self.counts.len()
    }

    /// Record one device with this id as connected. Returns the new count.
    pub fn insert(&mut self, id: UsbId) -> u32 {
        let slot = self.counts.entry(id).or_insert(0);
        *slot = slot.saturating_add(1);
        *slot
    }

    /// Record one device with this id as disconnected. Returns the new count.
    /// Removing an id that isn't tracked is a no-op and returns 0.
    pub fn remove(&mut self, id: UsbId) -> u32 {
        match self.counts.get_mut(&id) {
            Some(slot) if *slot > 1 => {
                *slot -= 1;
                *slot
            }
            Some(_) => {
                self.counts.remove(&id);
                0
            }
            None => 0,
        }
    }
}

impl FromIterator<UsbId> for DeviceTable {
    fn from_iter<I: IntoIterator<Item = UsbId>>(iter: I) -> Self {
        let mut table = DeviceTable::new();
        for id in iter {
            table.insert(id);
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: UsbId = UsbId::new(0x1050, 0x0407);
    const B: UsbId = UsbId::new(0x1d6b, 0x0002);

    #[test]
    fn insert_and_remove_track_counts() {
        let mut t = DeviceTable::new();
        assert_eq!(t.count(A), 0);
        assert_eq!(t.insert(A), 1);
        assert_eq!(t.insert(A), 2);
        assert_eq!(t.insert(B), 1);
        assert_eq!(t.total(), 3);
        assert_eq!(t.distinct(), 2);

        assert_eq!(t.remove(A), 1);
        assert_eq!(t.remove(A), 0);
        assert_eq!(t.count(A), 0);
        assert_eq!(t.distinct(), 1);
    }

    #[test]
    fn removing_absent_id_is_a_noop() {
        let mut t = DeviceTable::new();
        assert_eq!(t.remove(A), 0);
        assert_eq!(t.total(), 0);
    }

    #[test]
    fn collects_from_an_iterator_of_ids() {
        let t: DeviceTable = [A, A, B].into_iter().collect();
        assert_eq!(t.count(A), 2);
        assert_eq!(t.count(B), 1);
    }
}
