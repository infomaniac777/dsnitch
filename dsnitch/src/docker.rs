use std::{
    collections::HashMap,
    fs,
    num::NonZeroUsize,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
};

use anyhow::Context;
use bollard::{
    query_parameters::{EventsOptions, ListContainersOptions},
    Docker,
};
use futures_util::StreamExt;
use lru::LruCache;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub compose_service: Option<String>,
    pub compose_project: Option<String>,
    pub cgroup_id: u64,
    pub pid: i64,
}

#[derive(Clone)]
pub struct DockerManager {
    docker: Docker,
    containers: Arc<RwLock<HashMap<u64, ContainerInfo>>>,
    recently_stopped: Arc<RwLock<LruCache<u64, ContainerInfo>>>,
    id_to_cgroup: Arc<RwLock<HashMap<String, u64>>>,
}

impl DockerManager {
    pub fn new() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_unix_defaults()
            .context("Failed to connect to Docker daemon via /var/run/docker.sock")?;

        let recent_cap = NonZeroUsize::new(256).unwrap();

        Ok(Self {
            docker,
            containers: Arc::new(RwLock::new(HashMap::new())),
            recently_stopped: Arc::new(RwLock::new(LruCache::new(recent_cap))),
            id_to_cgroup: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Sync currently active containers on startup
    pub async fn sync_running_containers(&self) -> anyhow::Result<usize> {
        let options = Some(ListContainersOptions {
            all: false,
            ..Default::default()
        });

        let list = self
            .docker
            .list_containers(options)
            .await
            .context("Failed to list active Docker containers")?;

        let mut count = 0;
        for summary in list {
            if let Some(id) = summary.id {
                if let Ok(info) = self.inspect_and_cache(&id).await {
                    log::info!(
                        "Discovered active container: {} (cgroup_id: {})",
                        info.name,
                        info.cgroup_id
                    );
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Inspects a container, resolves its cgroup inode, and saves to cache
    pub async fn inspect_and_cache(&self, container_id: &str) -> anyhow::Result<ContainerInfo> {
        let inspect = self
            .docker
            .inspect_container(container_id, None)
            .await
            .with_context(|| format!("Failed to inspect container {}", container_id))?;

        let name = inspect
            .name
            .unwrap_or_else(|| container_id.to_string())
            .trim_start_matches('/')
            .to_string();

        let image = inspect
            .config
            .as_ref()
            .and_then(|c| c.image.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let labels = inspect
            .config
            .as_ref()
            .and_then(|c| c.labels.clone())
            .unwrap_or_default();

        let compose_service = labels.get("com.docker.compose.service").cloned();
        let compose_project = labels.get("com.docker.compose.project").cloned();

        let pid = inspect
            .state
            .as_ref()
            .and_then(|s| s.pid)
            .unwrap_or(0);

        let mut cgroup_id = resolve_cgroup_id(pid, container_id);
        if cgroup_id.is_none() {
            // Short retry loop for fast-starting containers
            for _ in 0..5 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                cgroup_id = resolve_cgroup_id(pid, container_id);
                if cgroup_id.is_some() {
                    break;
                }
            }
        }

        let cgroup_id = cgroup_id
            .with_context(|| format!("Could not resolve cgroup_id for container {} (PID: {})", name, pid))?;

        let info = ContainerInfo {
            id: container_id.to_string(),
            name,
            image,
            compose_service,
            compose_project,
            cgroup_id,
            pid,
        };

        {
            let mut c_map = self.containers.write().await;
            let mut id_map = self.id_to_cgroup.write().await;
            c_map.insert(cgroup_id, info.clone());
            id_map.insert(container_id.to_string(), cgroup_id);
        }

        Ok(info)
    }

    /// Background task listening to Docker daemon container lifecycle events
    pub async fn start_event_listener(self: Arc<Self>, dns_cache: Option<Arc<crate::dns::DnsCache>>) {
        let mut filters = HashMap::new();
        filters.insert(
            "type".to_string(),
            vec!["container".to_string()],
        );
        filters.insert(
            "event".to_string(),
            vec![
                "start".to_string(),
                "die".to_string(),
                "destroy".to_string(),
                "stop".to_string(),
                "kill".to_string(),
                "unpause".to_string(),
            ],
        );

        let options = Some(EventsOptions {
            filters: Some(filters),
            ..Default::default()
        });

        let mut event_stream = self.docker.events(options);

        while let Some(event_result) = event_stream.next().await {
            match event_result {
                Ok(event) => {
                    let action = event.action.as_deref().unwrap_or("");
                    let actor_id = event
                        .actor
                        .as_ref()
                        .and_then(|a| a.id.as_deref())
                        .unwrap_or("");

                    if actor_id.is_empty() {
                        continue;
                    }

                    match action {
                        "start" | "unpause" => {
                            match self.inspect_and_cache(actor_id).await {
                                Ok(info) => {
                                    log::info!(
                                        "Container started: {} (image: {}, cgroup: {})",
                                        info.name, info.image, info.cgroup_id
                                    );
                                }
                                Err(err) => {
                                    log::debug!("Could not inspect starting container: {:#}", err);
                                }
                            }
                        }
                        "die" | "destroy" | "stop" | "kill" => {
                            let mut id_map = self.id_to_cgroup.write().await;
                            let mut c_map = self.containers.write().await;
                            let mut recent = self.recently_stopped.write().await;

                            let cgroup_opt = id_map.remove(actor_id).or_else(|| {
                                c_map.iter().find(|(_, info)| info.id == actor_id).map(|(k, _)| *k)
                            });

                            if let Some(cgroup_id) = cgroup_opt {
                                if let Some(info) = c_map.remove(&cgroup_id) {
                                    log::info!(
                                        "Container stopped: {} (cgroup: {})",
                                        info.name, cgroup_id
                                    );
                                    recent.put(cgroup_id, info);

                                    if let Some(ref dns) = dns_cache {
                                        let dns_clone = Arc::clone(dns);
                                        tokio::spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                                            dns_clone.evict_cgroup(cgroup_id).await;
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    log::warn!("Docker events stream error: {:#}", err);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Fast lookup checking active and recently stopped containers
    pub async fn lookup(&self, cgroup_id: u64) -> Option<ContainerInfo> {
        if let Some(info) = self.containers.read().await.get(&cgroup_id) {
            return Some(info.clone());
        }
        if let Some(info) = self.recently_stopped.write().await.get(&cgroup_id) {
            return Some(info.clone());
        }

        // On-demand resolution fallback for ultrafast ephemeral containers
        if let Some(id) = find_container_id_by_inode(cgroup_id) {
            if let Ok(info) = self.inspect_and_cache(&id).await {
                return Some(info);
            }
        }

        None
    }
}

/// Resolves a container's 64-bit cgroup v2 inode ID (cgroup_id)
pub fn resolve_cgroup_id(pid: i64, container_id: &str) -> Option<u64> {
    if pid > 0 {
        let proc_cgroup = format!("/proc/{}/cgroup", pid);
        if let Ok(content) = fs::read_to_string(&proc_cgroup) {
            for line in content.lines() {
                if let Some(rel_path) = line.strip_prefix("0::") {
                    let full_path = format!("/sys/fs/cgroup{}", rel_path);
                    if let Ok(meta) = fs::metadata(&full_path) {
                        return Some(meta.ino());
                    }
                }
            }
        }
    }

    let candidate_paths = [
        format!("/sys/fs/cgroup/system.slice/docker-{}.scope", container_id),
        format!("/sys/fs/cgroup/docker/{}", container_id),
        format!("/sys/fs/cgroup/docker-{}.scope", container_id),
        format!("/sys/fs/cgroup/docker.slice/docker-{}.scope", container_id),
    ];

    for path_str in &candidate_paths {
        let path = Path::new(path_str);
        if path.exists() {
            if let Ok(meta) = fs::metadata(path) {
                return Some(meta.ino());
            }
        }
    }

    None
}

/// Scans cgroup tree to find container ID corresponding to an inode
fn find_container_id_by_inode(target_ino: u64) -> Option<String> {
    let search_roots = [
        "/sys/fs/cgroup/system.slice",
        "/sys/fs/cgroup/docker",
        "/sys/fs/cgroup",
    ];

    for root in &search_roots {
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.ino() == target_ino {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if let Some(id) = name.strip_prefix("docker-").and_then(|s| s.strip_suffix(".scope")) {
                            return Some(id.to_string());
                        }
                        if root.ends_with("docker") {
                            return Some(name);
                        }
                    }
                }
            }
        }
    }

    None
}
