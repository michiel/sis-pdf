use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Clone)]
pub struct PreviewCache<K, V> {
    max_entries: usize,
    max_total_bytes: usize,
    total_bytes: usize,
    values: HashMap<K, CacheValue<V>>,
    lru: VecDeque<K>,
}

#[derive(Clone)]
struct CacheValue<V> {
    value: V,
    size_bytes: usize,
}

impl<K, V> PreviewCache<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new(max_entries: usize, max_total_bytes: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_total_bytes: max_total_bytes.max(1),
            total_bytes: 0,
            values: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    pub fn get_cloned(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let value = self.values.get(key)?.value.clone();
        self.touch(key);
        Some(value)
    }

    pub fn insert(&mut self, key: K, value: V, size_bytes: usize) {
        if let Some(existing) = self.values.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(existing.size_bytes);
            self.remove_from_lru(&key);
        }
        self.total_bytes = self.total_bytes.saturating_add(size_bytes);
        self.values.insert(key.clone(), CacheValue { value, size_bytes });
        self.lru.push_back(key);
        self.evict_to_budget();
    }

    fn touch(&mut self, key: &K) {
        self.remove_from_lru(key);
        self.lru.push_back(key.clone());
    }

    fn remove_from_lru(&mut self, key: &K) {
        if let Some(pos) = self.lru.iter().position(|item| item == key) {
            self.lru.remove(pos);
        }
    }

    fn evict_to_budget(&mut self) {
        while self.values.len() > self.max_entries || self.total_bytes > self.max_total_bytes {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            if let Some(removed) = self.values.remove(&oldest) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.size_bytes);
            }
        }
    }
}

impl<K, V> Default for PreviewCache<K, V>
where
    K: Eq + Hash + Clone,
{
    fn default() -> Self {
        Self::new(32, 128 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::PreviewCache;

    #[test]
    fn preview_cache_hit_avoids_redecode() {
        let mut cache = PreviewCache::new(8, 1024);
        cache.insert(1u32, "decoded".to_string(), 32);
        let first = cache.get_cloned(&1);
        let second = cache.get_cloned(&1);
        assert_eq!(first.as_deref(), Some("decoded"));
        assert_eq!(second.as_deref(), Some("decoded"));
    }

    #[test]
    fn preview_cache_enforces_entry_budget() {
        let mut cache = PreviewCache::new(2, 4096);
        cache.insert(1u32, "a".to_string(), 8);
        cache.insert(2u32, "b".to_string(), 8);
        cache.insert(3u32, "c".to_string(), 8);
        assert_eq!(cache.len(), 2);
        assert!(cache.get_cloned(&1).is_none());
        assert_eq!(cache.get_cloned(&2).as_deref(), Some("b"));
        assert_eq!(cache.get_cloned(&3).as_deref(), Some("c"));
    }

    #[test]
    fn preview_cache_enforces_byte_budget() {
        let mut cache = PreviewCache::new(8, 16);
        cache.insert(1u32, "small".to_string(), 8);
        cache.insert(2u32, "small".to_string(), 8);
        cache.insert(3u32, "large".to_string(), 12);
        assert!(cache.get_cloned(&1).is_none());
        assert!(cache.get_cloned(&2).is_none());
        assert_eq!(cache.get_cloned(&3).as_deref(), Some("large"));
    }

    #[test]
    fn preview_cache_tracks_total_bytes_after_eviction() {
        let mut cache = PreviewCache::new(2, 20);
        cache.insert(1u32, "a".to_string(), 8);
        cache.insert(2u32, "b".to_string(), 8);
        assert_eq!(cache.total_bytes(), 16);
        cache.insert(3u32, "c".to_string(), 8);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.total_bytes(), 16);
    }
}
