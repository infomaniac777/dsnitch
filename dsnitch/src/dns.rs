use std::{
    collections::HashMap,
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use dsnitch_common::DnsPacketEvent;
use hickory_proto::{op::Message, rr::RData};
use lru::LruCache;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct DnsEntry {
    pub domain: String,
    pub resolved_at: Instant,
    pub ttl: Duration,
}

#[derive(Clone)]
pub struct DnsCache {
    cgroups: Arc<RwLock<HashMap<u64, LruCache<IpAddr, DnsEntry>>>>,
    max_entries_per_cgroup: NonZeroUsize,
}

impl DnsCache {
    pub fn new(capacity_per_cgroup: usize) -> Self {
        let cap = NonZeroUsize::new(capacity_per_cgroup).unwrap_or(NonZeroUsize::new(256).unwrap());
        Self {
            cgroups: Arc::new(RwLock::new(HashMap::new())),
            max_entries_per_cgroup: cap,
        }
    }

    /// Parses an incoming DNS packet with full EDNS0/extension support and caches A/AAAA answer records
    pub async fn process_packet(&self, event: &DnsPacketEvent) {
        if event.len == 0 {
            return;
        }
        let len = (event.len as usize).min(event.payload.len());
        let slice = &event.payload[..len];

        if let Ok(msg) = Message::from_vec(slice) {
            let mut updates: Vec<(IpAddr, String, u32)> = Vec::new();

            // Extract the user's original query domain from the Question section
            let query_domain = msg.queries().first().map(|q| {
                let s = q.name().to_string();
                s.trim_end_matches('.').to_string()
            });

            for record in msg.answers() {
                let domain = query_domain
                    .clone()
                    .unwrap_or_else(|| record.name().to_string().trim_end_matches('.').to_string());
                let ttl = record.ttl();

                match record.data() {
                    RData::A(record_a) => {
                        let ip = IpAddr::V4(record_a.0);
                        updates.push((ip, domain.clone(), ttl));
                    }
                    RData::AAAA(record_aaaa) => {
                        let ip = IpAddr::V6(record_aaaa.0);
                        updates.push((ip, domain.clone(), ttl));
                    }
                    _ => {}
                }
            }

            if !updates.is_empty() {
                let mut map = self.cgroups.write().await;
                let lru = map.entry(event.cgroup_id).or_insert_with(|| {
                    LruCache::new(self.max_entries_per_cgroup)
                });

                let now = Instant::now();
                for (ip, domain, ttl) in updates {
                    log::debug!(
                        "[DNS] Cached (cgroup: {}, IP: {}) -> {} (ttl: {}s)",
                        event.cgroup_id,
                        ip,
                        domain,
                        ttl
                    );
                    lru.put(
                        ip,
                        DnsEntry {
                            domain,
                            resolved_at: now,
                            ttl: Duration::from_secs(ttl.max(60) as u64),
                        },
                    );
                }
            }
        }
    }

    /// Resolves an IP strictly within the querying container's cgroup isolation table (with cross-cgroup fallback)
    pub async fn resolve(&self, cgroup_id: u64, ip: &IpAddr) -> Option<String> {
        let mut map = self.cgroups.write().await;

        // 1. Primary: Exact match in container's own cgroup cache
        if let Some(lru) = map.get_mut(&cgroup_id) {
            if let Some(entry) = lru.get(ip) {
                if entry.resolved_at.elapsed() <= entry.ttl + Duration::from_secs(60) {
                    return Some(entry.domain.clone());
                }
            }
        }

        // 2. Secondary fallback: Look across any other recent DNS resolutions
        for (cg_id, lru) in map.iter_mut() {
            if *cg_id != cgroup_id {
                if let Some(entry) = lru.get(ip) {
                    if entry.resolved_at.elapsed() <= entry.ttl + Duration::from_secs(60) {
                        return Some(entry.domain.clone());
                    }
                }
            }
        }

        None
    }

    /// Evicts the entire DNS table for a stopped container
    pub async fn evict_cgroup(&self, cgroup_id: u64) {
        let mut map = self.cgroups.write().await;
        if map.remove(&cgroup_id).is_some() {
            log::debug!("[DNS] Evicted DNS cache for stopped cgroup: {}", cgroup_id);
        }
    }
}
