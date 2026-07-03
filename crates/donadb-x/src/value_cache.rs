//! Bounded in-process value cache — populated by the fold thread, queried
//! by `get()` before touching the mmap.
//!
//! Uses CLOCK eviction algorithm for efficient, lock-free eviction without
//! iterating through the entire map.

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct ValueCache {
    inner:       Arc<Inner>,
    max_entries: usize,
}

struct Inner {
    /// Main key-value store with slot index for CLOCK eviction
    map:   DashMap<[u8; 32], (Bytes, usize)>,
    count: AtomicUsize,
    /// Circular buffer of keys for CLOCK algorithm
    slots: Box<[parking_lot::RwLock<Option<[u8; 32]>>]>,
    /// Reference bits for CLOCK - one byte per slot (bit 0 = referenced)
    ref_bits: Box<[AtomicU8]>,
    /// CLOCK hand position
    clock_hand: AtomicU64,
}

impl ValueCache {
    pub fn new(max_entries: usize) -> Self {
        let capacity = max_entries.min(1 << 20);
        
        let slots: Vec<_> = (0..capacity)
            .map(|_| parking_lot::RwLock::new(None))
            .collect();
        
        let ref_bits: Vec<_> = (0..capacity)
            .map(|_| AtomicU8::new(0))
            .collect();
        
        Self {
            inner: Arc::new(Inner {
                map:   DashMap::with_capacity(capacity),
                count: AtomicUsize::new(0),
                slots: slots.into_boxed_slice(),
                ref_bits: ref_bits.into_boxed_slice(),
                clock_hand: AtomicU64::new(0),
            }),
            max_entries: capacity,
        }
    }

    /// Insert or update a key-value pair. Uses CLOCK eviction when full.
    pub fn insert(&self, key: [u8; 32], value: Bytes) {
        if self.max_entries == 0 { return; }

        // Check if key already exists
        if let Some(mut entry) = self.inner.map.get_mut(&key) {
            entry.0 = value;
            let slot_idx = entry.1;
            // Mark as referenced (set bit 0)
            self.inner.ref_bits[slot_idx].fetch_or(1, Ordering::Relaxed);
            return;
        }

        // If cache is full, run CLOCK eviction
        if self.inner.count.load(Ordering::Relaxed) >= self.max_entries {
            self.evict_one_clock();
        }

        // Get next slot position
        let hand = self.inner.clock_hand.fetch_add(1, Ordering::Relaxed) as usize;
        let slot_idx = hand % self.max_entries;
        
        // Insert into map with slot index
        self.inner.map.insert(key, (value, slot_idx));
        
        // Update slot and set reference bit
        *self.inner.slots[slot_idx].write() = Some(key);
        self.inner.ref_bits[slot_idx].store(1, Ordering::Relaxed);
        
        self.inner.count.fetch_add(1, Ordering::Relaxed);
    }

    /// CLOCK eviction: sweep through slots, giving referenced entries a second chance.
    fn evict_one_clock(&self) {
        let max_sweeps = self.max_entries.min(1024);
        
        for _ in 0..max_sweeps {
            let hand = self.inner.clock_hand.fetch_add(1, Ordering::Relaxed) as usize;
            let slot_idx = hand % self.max_entries;
            
            // Check and clear reference bit atomically
            let ref_bit = self.inner.ref_bits[slot_idx].fetch_and(!1, Ordering::Relaxed);
            if ref_bit & 1 != 0 {
                // Was referenced, give it another chance
                continue;
            }
            
            // Try to evict this slot
            if let Some(victim_key) = *self.inner.slots[slot_idx].read() {
                if self.inner.map.remove(&victim_key).is_some() {
                    *self.inner.slots[slot_idx].write() = None;
                    self.inner.count.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    /// Look up a key — O(1), returns a cheap Bytes clone (Arc refcount bump).
    #[inline(always)]
    pub fn get(&self, key: &[u8; 32]) -> Option<Bytes> {
        self.inner.map.get(key).map(|entry| {
            let (value, slot_idx) = entry.value();
            // Mark as referenced for CLOCK (set bit 0)
            self.inner.ref_bits[*slot_idx].fetch_or(1, Ordering::Relaxed);
            value.clone()
        })
    }

    /// Remove a key (called on delete/tombstone and before segment rotation).
    #[inline(always)]
    pub fn remove(&self, key: &[u8; 32]) {
        if let Some((_, (_, slot_idx))) = self.inner.map.remove(key) {
            *self.inner.slots[slot_idx].write() = None;
            self.inner.ref_bits[slot_idx].store(0, Ordering::Relaxed);
            self.inner.count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Evict all entries — called on segment rotation.
    pub fn clear(&self) {
        self.inner.map.clear();
        for slot in self.inner.slots.iter() {
            *slot.write() = None;
        }
        for ref_bit in self.inner.ref_bits.iter() {
            ref_bit.store(0, Ordering::Relaxed);
        }
        self.inner.count.store(0, Ordering::Relaxed);
        self.inner.clock_hand.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.count.load(Ordering::Relaxed)
    }
}
