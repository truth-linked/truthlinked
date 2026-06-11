//! Truthlinked Consensus Src Sync
//!
//! Owns sync state helpers shared by consensus components.
//! Consensus changes are protocol-critical; preserve deterministic replay, recovery safety, and wire compatibility.

use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    Syncing { current: u64, target: u64 },
    Synced,
    Offline,
}

pub struct SyncManager {
    pub state: SyncState,
    pub last_sync_check: Instant,
    pub peer_heights: HashMap<Vec<u8>, PeerHeight>,
}

#[derive(Debug, Clone)]
pub struct PeerHeight {
    pub height: u64,
    pub last_seen: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn sync_manager_prunes_stale_peers() {
        let mut mgr = SyncManager::new();
        mgr.update_peer_height(vec![1u8], 10);
        mgr.update_peer_height(vec![2u8], 20);

        if let Some(info) = mgr.peer_heights.get_mut(&vec![1u8]) {
            info.last_seen = Instant::now() - Duration::from_secs(100);
        }

        mgr.prune_stale(30);
        assert!(mgr.peer_heights.get(&vec![1u8]).is_none());
        assert!(mgr.peer_heights.get(&vec![2u8]).is_some());
    }

    #[test]
    fn sync_state_transitions() {
        let mut mgr = SyncManager::new();
        assert_eq!(mgr.state, SyncState::Offline);

        mgr.set_syncing(5, 10);
        assert_eq!(
            mgr.state,
            SyncState::Syncing {
                current: 5,
                target: 10
            }
        );

        mgr.update_syncing_progress(7);
        assert_eq!(
            mgr.state,
            SyncState::Syncing {
                current: 7,
                target: 10
            }
        );

        mgr.set_synced();
        assert!(mgr.is_synced());
    }
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            state: SyncState::Offline,
            last_sync_check: Instant::now(),
            peer_heights: HashMap::new(),
        }
    }

    pub fn set_syncing(&mut self, current: u64, target: u64) {
        tracing::warn!(
            "🔴 SYNC STATE CHANGE: Synced -> Syncing (current={}, target={})",
            current,
            target
        );
        self.state = SyncState::Syncing { current, target };
    }

    pub fn update_syncing_progress(&mut self, current: u64) {
        if let SyncState::Syncing {
            current: ref mut c,
            target: _,
        } = self.state
        {
            *c = current;
        }
    }

    pub fn set_synced(&mut self) {
        tracing::info!("SYNC STATE CHANGE: -> Synced");
        self.state = SyncState::Synced;
    }

    pub fn is_synced(&self) -> bool {
        matches!(self.state, SyncState::Synced)
    }

    pub fn update_peer_height(&mut self, peer_id: Vec<u8>, height: u64) {
        if !self.peer_heights.contains_key(&peer_id)
            && self.peer_heights.len() >= truthlinked_state::constants::MAX_SYNC_PEER_HEIGHTS
        {
            // Evict the peer whose height is furthest from the median.
            // This preserves catching-up nodes (near median) and removes outliers
            // (both suspiciously high reporters and genuinely stale low ones).
            let mut heights: Vec<u64> = self.peer_heights.values().map(|p| p.height).collect();
            heights.sort_unstable();
            let median = heights[heights.len() / 2];
            if let Some(evict) = self
                .peer_heights
                .iter()
                .max_by_key(|(_, p)| p.height.abs_diff(median))
                .map(|(k, _)| k.clone())
            {
                self.peer_heights.remove(&evict);
            }
        }
        let entry = self.peer_heights.entry(peer_id).or_insert(PeerHeight {
            height,
            last_seen: Instant::now(),
        });
        entry.height = height;
        entry.last_seen = Instant::now();
    }

    pub fn get_highest_peer_height(&self) -> Option<u64> {
        self.peer_heights.values().map(|p| p.height).max()
    }

    /// Number of peers reporting height >= min_height.
    /// Used to require 2+ peers confirming before marking synced.
    pub fn peer_count_at_or_above(&self, min_height: u64) -> usize {
        self.peer_heights
            .values()
            .filter(|p| p.height >= min_height)
            .count()
    }

    pub fn prune_stale(&mut self, ttl_secs: u64) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(ttl_secs);
        self.peer_heights
            .retain(|_, info| now.duration_since(info.last_seen) <= ttl);
    }
}
