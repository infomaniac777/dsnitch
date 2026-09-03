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

#[cfg(test)]
mod tests {
    use super::*;
    use dsnitch_common::MAX_DNS_PAYLOAD;

    fn build_mock_dns_response(domain: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut packet = Vec::new();
        // Transaction ID
        packet.extend_from_slice(&[0x12, 0x34]);
        // Flags: Standard query response, No error (0x8180)
        packet.extend_from_slice(&[0x81, 0x80]);
        // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // ANCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // NSCOUNT = 0, ARCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // QNAME
        for part in domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0x00); // Root label

        // QTYPE = A (1), QCLASS = IN (1)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer section: Name compression pointer to offset 12
        packet.extend_from_slice(&[0xc0, 0x0c]);
        // TYPE = A (1), CLASS = IN (1)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // TTL
        packet.extend_from_slice(&ttl.to_be_bytes());
        // RDLENGTH = 4
        packet.extend_from_slice(&[0x00, 0x04]);
        // RDATA
        packet.extend_from_slice(&ip);

        packet
    }

    #[tokio::test]
    async fn test_dns_cache_process_and_resolve() {
        let cache = DnsCache::new(10);
        let cgroup_id = 42;
        let domain = "api.github.com";
        let ip_bytes = [20, 207, 73, 85];
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(20, 207, 73, 85));

        let wire_data = build_mock_dns_response(domain, ip_bytes, 120);

        let mut event = DnsPacketEvent {
            timestamp_ns: 1000,
            cgroup_id,
            len: wire_data.len() as u32,
            payload: [0u8; MAX_DNS_PAYLOAD],
        };
        event.payload[..wire_data.len()].copy_from_slice(&wire_data);

        // Before caching
        assert_eq!(cache.resolve(cgroup_id, &ip).await, None);

        // Process packet
        cache.process_packet(&event).await;

        // Resolve after caching
        let resolved = cache.resolve(cgroup_id, &ip).await;
        assert_eq!(resolved, Some("api.github.com".to_string()));

        // Fallback resolution from another cgroup
        let fallback_cgroup = 999;
        let resolved_fallback = cache.resolve(fallback_cgroup, &ip).await;
        assert_eq!(resolved_fallback, Some("api.github.com".to_string()));

        // Evict cgroup
        cache.evict_cgroup(cgroup_id).await;
        assert_eq!(cache.resolve(cgroup_id, &ip).await, None);
    }

    #[tokio::test]
    async fn test_dns_cache_empty_packet_ignored() {
        let cache = DnsCache::new(10);
        let event = DnsPacketEvent {
            timestamp_ns: 1000,
            cgroup_id: 1,
            len: 0,
            payload: [0u8; MAX_DNS_PAYLOAD],
        };
        cache.process_packet(&event).await;
        assert_eq!(cache.resolve(1, &IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))).await, None);
    }
}
