use std::collections::{BTreeMap, BTreeSet};

pub struct ShortIdTable {
    map: BTreeMap<String, String>,
    used: BTreeSet<String>,
}

impl ShortIdTable {
    pub fn new() -> Self {
        Self { map: BTreeMap::new(), used: BTreeSet::new() }
    }

    pub fn insert(&mut self, long: &str) {
        let short = shorten_id(long, &mut self.used);
        self.map.insert(long.to_string(), short);
    }

    pub fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        for item in items {
            self.insert(item.as_ref());
        }
    }

    pub fn map(&self) -> &BTreeMap<String, String> {
        &self.map
    }

    pub fn into_map(self) -> BTreeMap<String, String> {
        self.map
    }
}

fn shorten_id(long: &str, used: &mut BTreeSet<String>) -> String {
    if long.len() <= 14 {
        used.insert(long.to_string());
        return long.to_string();
    }
    if let Some(rest) = long.strip_prefix("sis-") {
        for len in [8usize, 12, 16, rest.len()] {
            let slice_len = len.min(rest.len());
            let candidate = format!("sis-{}", &rest[..slice_len]);
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
    } else {
        for len in [8usize, 12, 16, long.len()] {
            let slice_len = len.min(long.len());
            let candidate = long[..slice_len].to_string();
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
    }
    long.to_string()
}
