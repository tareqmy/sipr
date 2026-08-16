//! The call table: a sharded concurrent map from Call-ID to per-call state.
//!
//! Sharding keeps lock contention negligible at high call counts without a
//! dependency on `dashmap` (std-only build). The value type is generic — the
//! engine stores call mailboxes/handles here at M3.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Mutex, MutexGuard};

const SHARDS: usize = 64;

/// Sharded `Call-ID → V` map. Cheap to share behind an `Arc`.
pub struct CallTable<V> {
    shards: Vec<Mutex<HashMap<String, V>>>,
}

impl<V> Default for CallTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> CallTable<V> {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    fn shard(&self, call_id: &str) -> MutexGuard<'_, HashMap<String, V>> {
        let mut h = DefaultHasher::new();
        call_id.hash(&mut h);
        #[allow(clippy::cast_possible_truncation)]
        let idx = (h.finish() as usize) % SHARDS;
        match self.shards[idx].lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Insert a call. Returns the previous value if the Call-ID was taken.
    pub fn insert(&self, call_id: &str, value: V) -> Option<V> {
        self.shard(call_id).insert(call_id.to_owned(), value)
    }

    /// Remove a call, returning its state.
    pub fn remove(&self, call_id: &str) -> Option<V> {
        self.shard(call_id).remove(call_id)
    }

    /// Run `f` on the call's state, if present. Returns `None` when absent.
    pub fn with<R>(&self, call_id: &str, f: impl FnOnce(&mut V) -> R) -> Option<R> {
        self.shard(call_id).get_mut(call_id).map(f)
    }

    /// True if the Call-ID is present.
    #[must_use]
    pub fn contains(&self, call_id: &str) -> bool {
        self.shard(call_id).contains_key(call_id)
    }

    /// Total number of live calls (sums all shards; not a snapshot).
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| match s.lock() {
                Ok(g) => g.len(),
                Err(poisoned) => poisoned.into_inner().len(),
            })
            .sum()
    }

    /// True when no calls are live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn insert_get_remove_roundtrip() {
        let t: CallTable<u32> = CallTable::new();
        assert!(t.insert("a@1", 1).is_none());
        assert!(t.insert("b@2", 2).is_none());
        assert_eq!(t.insert("a@1", 10), Some(1), "reinsert returns old");
        assert_eq!(t.with("a@1", |v| *v), Some(10));
        assert_eq!(t.with("missing", |v| *v), None);
        assert_eq!(t.len(), 2);
        assert_eq!(t.remove("a@1"), Some(10));
        assert!(!t.contains("a@1"));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn concurrent_inserts_land_once() {
        let t: Arc<CallTable<usize>> = Arc::new(CallTable::new());
        let threads: Vec<_> = (0..8)
            .map(|k| {
                let t = Arc::clone(&t);
                std::thread::spawn(move || {
                    for i in 0..500 {
                        let id = format!("call-{}-{i}", k % 4); // overlapping ids
                        t.insert(&id, i);
                        t.with(&id, |v| *v += 1);
                    }
                })
            })
            .collect();
        for th in threads {
            th.join().expect("no panics");
        }
        assert_eq!(t.len(), 4 * 500);
    }
}
