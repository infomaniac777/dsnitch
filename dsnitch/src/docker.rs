use std::{
    collections::HashMap,
    fs,
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
    id_to_cgroup: Arc<RwLock<HashMap<String, u64>>>,
}

impl DockerManager {
    pub fn new() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_unix_defaults()
            .context("Failed to connect to Docker daemon via /var/run/docker.sock")?;

        Ok(Self {
            docker,
            containers: Arc::new(RwLock::new(HashMap::new())),
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
    async fn inspect_and_cache(&self, container_id: &str) -> anyhow::Result<ContainerInfo> {
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

        let cgroup_id = resolve_cgroup_id(pid, container_id)
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
    pub async fn start_event_listener(self: Arc<Self>) {
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
                            // Small sleep to ensure containerd/cgroups v2 hierarchy is populated
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            match self.inspect_and_cache(actor_id).await {
                                Ok(info) => {
                                    println!(
                                        "[DOCKER] Container started: {} (image: {}, cgroup: {})",
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

                            if let Some(cgroup_id) = id_map.remove(actor_id) {
                                if let Some(info) = c_map.remove(&cgroup_id) {
                                    println!(
                                        "[DOCKER] Container stopped: {} (cgroup: {})",
                                        info.name, cgroup_id
                                    );
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

    /// Fast synchronous lookup for eBPF event loop
    pub async fn lookup(&self, cgroup_id: u64) -> Option<ContainerInfo> {
        self.containers.read().await.get(&cgroup_id).cloned()
    }
}

/// Resolves a container's 64-bit cgroup v2 inode ID (cgroup_id)
pub fn resolve_cgroup_id(pid: i64, container_id: &str) -> Option<u64> {
    // 1. Try resolving via /proc/<pid>/cgroup
    if pid > 0 {
        let proc_cgroup = format!("/proc/{}/cgroup", pid);
        if let Ok(content) = fs::read_to_string(&proc_cgroup) {
            for line in content.lines() {
                // cgroup v2 single hierarchy entry format: "0::<path>"
                if let Some(rel_path) = line.strip_prefix("0::") {
                    let full_path = format!("/sys/fs/cgroup{}", rel_path);
                    if let Ok(meta) = fs::metadata(&full_path) {
                        return Some(meta.ino());
                    }
                }
            }
        }
    }

    // 2. Direct fallback checks on common cgroups v2 paths
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
