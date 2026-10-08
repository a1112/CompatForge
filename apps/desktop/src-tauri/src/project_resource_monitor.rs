//! Read-only application process-tree monitoring. No additional listener is opened.
use monitor_sysinfo::{get_current_pid, ProcessRefreshKind, ProcessesToUpdate, System};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    cpu_percent: Option<f64>,
    memory_bytes: u64,
    read_bytes_per_second: Option<f64>,
    write_bytes_per_second: Option<f64>,
    process_count: usize,
    gpu_percent: Option<f64>,
}

#[derive(Default)]
struct Sampler {
    system: System,
    previous: HashMap<(u32, u64), (u64, u64)>,
    sampled_at: Option<Instant>,
    snapshot: Option<Snapshot>,
}

fn descendants(root: u32, parents: &[(u32, Option<u32>)]) -> HashSet<u32> {
    let mut included = HashSet::from([root]);
    loop {
        let before = included.len();
        for &(pid, parent) in parents {
            if parent.is_some_and(|parent| included.contains(&parent)) {
                included.insert(pid);
            }
        }
        if included.len() == before {
            return included;
        }
    }
}

impl Sampler {
    fn sample(&mut self) -> Result<Snapshot, String> {
        if !cfg!(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos"
        )) {
            return Err("Resource sampling is unavailable on this platform".into());
        }
        let now = Instant::now();
        let elapsed = self
            .sampled_at
            .map(|at| now.duration_since(at).as_secs_f64());
        if elapsed.is_some_and(|seconds| seconds < 1.0) {
            if let Some(snapshot) = &self.snapshot {
                return Ok(snapshot.clone());
            }
        }
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage(),
        );
        let root = get_current_pid().map_err(|e| e.to_string())?;
        if self.system.process(root).is_none() {
            return Err("Unable to sample the application process".into());
        }
        let parents: Vec<_> = self
            .system
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process.parent().map(|pid| pid.as_u32())))
            .collect();
        let included = descendants(root.as_u32(), &parents);
        let mut current = HashMap::new();
        let (mut cpu, mut memory, mut reads, mut writes, mut count) =
            (0.0_f64, 0_u64, 0_u64, 0_u64, 0_usize);
        for (pid, process) in self.system.processes() {
            if !included.contains(&pid.as_u32()) {
                continue;
            }
            count += 1;
            cpu += f64::from(process.cpu_usage());
            memory = memory.saturating_add(process.memory());
            let disk = process.disk_usage();
            let identity = (pid.as_u32(), process.start_time());
            if let Some(&(read, written)) = self.previous.get(&identity) {
                reads = reads.saturating_add(disk.total_read_bytes.saturating_sub(read));
                writes = writes.saturating_add(disk.total_written_bytes.saturating_sub(written));
            }
            current.insert(identity, (disk.total_read_bytes, disk.total_written_bytes));
        }
        let processors = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1) as f64;
        let snapshot = Snapshot {
            cpu_percent: elapsed.map(|_| (cpu / processors).clamp(0.0, 100.0)),
            memory_bytes: memory,
            read_bytes_per_second: elapsed.map(|seconds| reads as f64 / seconds),
            write_bytes_per_second: elapsed.map(|seconds| writes as f64 / seconds),
            process_count: count,
            gpu_percent: None,
        };
        self.previous = current;
        self.sampled_at = Some(now);
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }
}

#[tauri::command]
pub async fn project_resource_snapshot() -> Result<Snapshot, String> {
    static SAMPLER: OnceLock<Mutex<Sampler>> = OnceLock::new();
    tauri::async_runtime::spawn_blocking(|| {
        SAMPLER
            .get_or_init(|| Mutex::new(Sampler::default()))
            .lock()
            .map_err(|_| "Resource sampler unavailable".to_string())?
            .sample()
    })
    .await
    .map_err(|error| error.to_string())?
}

pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("project-resource-monitor")
        .js_init_script(include_str!("project-resource-monitor.js").to_string())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn includes_descendants_without_unrelated_processes_or_cycles() {
        assert_eq!(
            descendants(1, &[(3, Some(2)), (2, Some(1)), (4, Some(5)), (5, Some(4))]),
            HashSet::from([1, 2, 3])
        );
    }
    #[test]
    fn first_sample_has_no_invented_cpu_or_io_rate_and_is_cached() {
        let mut sampler = Sampler::default();
        let first = sampler.sample().unwrap();
        assert!(first.process_count >= 1);
        assert!(first.cpu_percent.is_none());
        assert!(first.read_bytes_per_second.is_none());
        assert!(first.gpu_percent.is_none());
        assert_eq!(first.memory_bytes, sampler.sample().unwrap().memory_bytes);
    }
}
