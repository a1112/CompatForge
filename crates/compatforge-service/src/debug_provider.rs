//! Linux-only private WineDbg/GDB worker owned by the user service.

use crate::jobs::SelectedDebugTarget;
use crate::model::{DebuggerRuntimeConfig, PinnedDebuggerFile};
use compatforge_debug::dap::{DapBinding, SafeDapRequest};
use compatforge_debug::{Backend, DebugError, DebugTarget};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_CONTROL: usize = 64 * 1024;
const STUB_PORT: u16 = 25000;

pub(crate) struct WorkerBackend {
    runtime: Option<DebuggerRuntimeConfig>,
    service_root: PathBuf,
}

pub(crate) struct WorkerOwned {
    child: Child,
    writer: SyncSender<(u64, Vec<u8>)>,
    write_acks: Receiver<(u64, bool)>,
    replies: Receiver<Result<Value, ()>>,
    next_request_id: u64,
    broken: bool,
    session_root: PathBuf,
    prefix: PathBuf,
    binding: DapBinding,
    stopped: bool,
}

impl WorkerBackend {
    pub(crate) fn new(runtime: Option<DebuggerRuntimeConfig>, service_root: PathBuf) -> Self {
        Self { runtime, service_root }
    }

    /// A crashed owner loses in-memory leases. Never admit a replacement
    /// service while a copied debug prefix still has live Wine processes.
    pub(crate) fn recover_stale_sessions(&self) -> Result<(), DebugError> {
        let parent = self.service_root.join("debug-sessions");
        if !parent.exists() {
            return Ok(());
        }
        if parent.is_symlink() || !parent.is_dir() {
            return Err(DebugError::BackendFailed);
        }
        for entry in fs::read_dir(&parent).map_err(|_| DebugError::BackendFailed)? {
            let entry = entry.map_err(|_| DebugError::BackendFailed)?;
            let path = entry.path();
            if !entry.file_name().to_string_lossy().starts_with("session-") || path.is_symlink() || !path.is_dir() {
                return Err(DebugError::BackendFailed);
            }
            if owned_prefix_process_exists(&path.join("prefix"))? {
                return Err(DebugError::BackendFailed);
            }
            fs::remove_dir_all(path).map_err(|_| DebugError::BackendFailed)?;
        }
        Ok(())
    }

    pub(crate) fn launch_selected(
        &self,
        target: &DebugTarget,
        selected: &SelectedDebugTarget,
    ) -> Result<WorkerOwned, DebugError> {
        let runtime = self.runtime.as_ref().ok_or(DebugError::Unavailable)?;
        if selected.runtime_pack_digest != runtime.runtime_pack_digest {
            return Err(DebugError::DigestMismatch);
        }
        for file in [&runtime.worker, &runtime.wine, &runtime.winedbg_module, &runtime.gdb] {
            verify_root_owned_pin(file)?;
        }
        verify_root_owned_directory(Path::new(&runtime.gdb_root))?;
        for helper in ["/usr/bin/cp", "/usr/bin/unshare", "/usr/bin/python3"] {
            verify_root_owned_executable(Path::new(helper))?;
        }
        verify_managed_file(&selected.executable, &selected.executable_digest)?;
        if selected.prefix.is_symlink() || !selected.prefix.is_dir() {
            return Err(DebugError::InvalidTarget);
        }
        let session_root = create_session_root(&self.service_root)?;
        let mut session_guard = SessionDirectoryGuard {
            path: session_root.clone(),
            keep: false,
        };
        let prefix = session_root.join("prefix");
        fs::create_dir(&prefix).map_err(|_| DebugError::BackendFailed)?;
        let mut copy = Command::new("/usr/bin/cp")
            .args(["-a", "--reflink=auto", "--"])
            .arg(selected.prefix.join("."))
            .arg(&prefix)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| DebugError::BackendFailed)?;
        let copy_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = copy.try_wait().map_err(|_| DebugError::BackendFailed)? {
                if !status.success() {
                    return Err(DebugError::BackendFailed);
                }
                break;
            }
            if Instant::now() >= copy_deadline {
                let _ = copy.kill();
                let _ = copy.wait();
                return Err(DebugError::BackendFailed);
            }
            thread::sleep(Duration::from_millis(20));
        }
        let relative_program = selected
            .executable
            .strip_prefix(&selected.prefix)
            .map_err(|_| DebugError::InvalidTarget)?;
        let program = prefix.join(relative_program);
        verify_managed_file(&program, &selected.executable_digest)?;
        let binding = DapBinding::new(
            target.clone(),
            program.to_str().ok_or(DebugError::InvalidTarget)?,
            STUB_PORT,
            runtime
                .source_map
                .iter()
                .map(|(source, backend)| (source.clone(), backend.clone())),
        )?;
        let display = std::env::var("DISPLAY").map_err(|_| DebugError::Unavailable)?;
        let xauthority = std::env::var("XAUTHORITY").map_err(|_| DebugError::Unavailable)?;
        if !display.starts_with(':') || display.len() > 64 || !Path::new(&xauthority).is_absolute() {
            return Err(DebugError::Unavailable);
        }
        let home = std::env::var("HOME").map_err(|_| DebugError::Unavailable)?;
        let user = std::env::var("USER").map_err(|_| DebugError::Unavailable)?;
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").map_err(|_| DebugError::Unavailable)?;
        let payload = json!({
            "schemaVersion":1,"port":STUB_PORT,"program":program,
            "prefix":prefix,"wine":runtime.wine.path,"winedbgModule":runtime.winedbg_module.path,
            "gdb":runtime.gdb.path,"gdbRoot":runtime.gdb_root,
            "display":display,"xauthority":xauthority,
            "backendSources":runtime.source_map.values().collect::<Vec<_>>(),
            "sourceSubstitution":runtime.source_substitution,
            "sha256":{
                "program":digest_hex(&selected.executable_digest)?,
                "wine":digest_hex(&runtime.wine.sha256)?,
                "winedbgModule":digest_hex(&runtime.winedbg_module.sha256)?,
                "gdb":digest_hex(&runtime.gdb.sha256)?
            }
        });
        let mut child = Command::new("/usr/bin/unshare")
            .args(["-Urnpf", "--mount-proc", "--kill-child", "/usr/bin/python3"])
            .arg(&runtime.worker.path)
            .env_clear()
            .env("HOME", home)
            .env("USER", &user)
            .env("LOGNAME", user)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| DebugError::BackendFailed)?;
        let stdin = child.stdin.take().ok_or(DebugError::BackendFailed)?;
        let stdout = child.stdout.take().ok_or(DebugError::BackendFailed)?;
        let (writer, write_queue) = mpsc::sync_channel(1);
        let (write_ack_sender, write_acks) = mpsc::sync_channel(1);
        thread::spawn(move || write_control_lines(stdin, write_queue, write_ack_sender));
        let (sender, replies) = mpsc::sync_channel(4);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let result = read_bounded_line(&mut reader)
                    .and_then(|raw| serde_json::from_slice(&raw).map_err(io::Error::other))
                    .map_err(|_| ());
                let is_error = result.is_err();
                if sender.send(result).is_err() || is_error {
                    break;
                }
            }
        });
        let mut owned = WorkerOwned {
            child,
            writer,
            write_acks,
            replies,
            next_request_id: 1,
            broken: false,
            session_root,
            prefix,
            binding,
            stopped: false,
        };
        if owned.call(&payload, Duration::from_secs(30))?.get("ready") != Some(&json!(true)) {
            return Err(DebugError::BackendFailed);
        }
        session_guard.keep = true;
        Ok(owned)
    }

    pub(crate) fn exchange(
        &self,
        owned: &mut WorkerOwned,
        request: Option<&SafeDapRequest>,
    ) -> Result<Vec<Value>, DebugError> {
        let payload = if let Some(request) = request {
            json!({"op":"send","message":owned.binding.forward(request)?})
        } else {
            json!({"op":"poll"})
        };
        let response = owned.call(&payload, Duration::from_secs(2))?;
        if let Some(metadata) = response.get("oversized") {
            return Ok(vec![oversized_gateway_reply(&owned.binding, metadata)]);
        }
        let messages = response
            .get("messages")
            .and_then(Value::as_array)
            .ok_or(DebugError::BackendFailed)?;
        if messages.len() > 128 {
            return Err(DebugError::BackendFailed);
        }
        messages
            .iter()
            .cloned()
            .map(|message| owned.binding.rewrite_backend_message(message))
            .collect()
    }
}

fn oversized_gateway_reply(binding: &DapBinding, metadata: &Value) -> Value {
    if metadata.get("type").and_then(Value::as_str) == Some("response") {
        if let (Some(command), Some(request_seq)) = (
            metadata.get("command").and_then(Value::as_str),
            metadata.get("request_seq").and_then(Value::as_u64),
        ) {
            let candidate = json!({"seq":1,"type":"response","request_seq":request_seq,
                "command":command,"success":false,"message":"debugger response exceeded 64 KiB"});
            if let Ok(message) = binding.rewrite_backend_message(candidate) {
                return message;
            }
        }
    }
    json!({"seq":1,"type":"event","event":"output",
        "body":{"category":"stderr","output":"CompatForge omitted an oversized debugger event\n"}})
}

struct SessionDirectoryGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for SessionDirectoryGuard {
    fn drop(&mut self) {
        if !self.keep && owned_prefix_process_exists(&self.path.join("prefix")) == Ok(false) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl Backend for WorkerBackend {
    type Owned = WorkerOwned;
    fn launch(&self, _: &DebugTarget) -> Result<Self::Owned, DebugError> {
        Err(DebugError::Unavailable)
    }
    fn terminate(&self, owned: &mut Self::Owned) -> Result<(), DebugError> {
        owned.stop()
    }
    fn disconnect(&self, owned: &mut Self::Owned) -> Result<(), DebugError> {
        owned.stop()
    }
}

impl WorkerOwned {
    fn call(&mut self, payload: &Value, timeout: Duration) -> Result<Value, DebugError> {
        if self.broken {
            return Err(DebugError::BackendFailed);
        }
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).ok_or(DebugError::BackendFailed)?;
        let mut payload = payload.clone();
        payload
            .as_object_mut()
            .ok_or(DebugError::InvalidRequest)?
            .insert("requestId".into(), Value::from(request_id));
        let raw = serde_json::to_vec(&payload).map_err(|_| DebugError::InvalidRequest)?;
        if raw.len() + 1 > MAX_CONTROL {
            return Err(DebugError::InvalidRequest);
        }
        let deadline = Instant::now() + timeout;
        if self.writer.try_send((request_id, raw)).is_err() {
            self.broken = true;
            return Err(DebugError::BackendFailed);
        }
        match self.write_acks.recv_timeout(timeout) {
            Ok((ack_id, true)) if ack_id == request_id => {}
            _ => {
                self.broken = true;
                return Err(DebugError::BackendFailed);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let reply = self.replies.recv_timeout(remaining);
        match reply {
            Ok(Ok(value)) if value.get("requestId").and_then(Value::as_u64) == Some(request_id) => Ok(value),
            _ => {
                self.broken = true;
                Err(DebugError::BackendFailed)
            }
        }
    }

    fn stop(&mut self) -> Result<(), DebugError> {
        if self.stopped {
            return Ok(());
        }
        let acknowledged = self
            .call(&json!({"op":"shutdown"}), Duration::from_secs(5))
            .is_ok_and(|value| value.get("stopped") == Some(&json!(true)));
        if !acknowledged && self.child.try_wait().map_err(|_| DebugError::BackendFailed)?.is_none() {
            let _ = self.child.kill();
        }
        let deadline = Instant::now() + Duration::from_secs(if acknowledged { 15 } else { 5 });
        loop {
            if self.child.try_wait().map_err(|_| DebugError::BackendFailed)?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let forced_deadline = Instant::now() + Duration::from_secs(5);
                while self.child.try_wait().map_err(|_| DebugError::BackendFailed)?.is_none() {
                    if Instant::now() >= forced_deadline {
                        return Err(DebugError::BackendFailed);
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        if owned_prefix_process_exists(&self.prefix)? {
            return Err(DebugError::BackendFailed);
        }
        fs::remove_dir_all(&self.session_root).map_err(|_| DebugError::BackendFailed)?;
        self.stopped = true;
        Ok(())
    }
}

impl Drop for WorkerOwned {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.child.kill();
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn write_control_lines(
    mut stdin: ChildStdin,
    queue: Receiver<(u64, Vec<u8>)>,
    acknowledgements: SyncSender<(u64, bool)>,
) {
    while let Ok((request_id, raw)) = queue.recv() {
        let success = stdin
            .write_all(&raw)
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .is_ok();
        if acknowledgements.send((request_id, success)).is_err() || !success {
            break;
        }
    }
}

fn read_bounded_line(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if raw.len() >= MAX_CONTROL || reader.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded worker response required",
            ));
        }
        if byte[0] == b'\n' {
            return Ok(raw);
        }
        raw.push(byte[0]);
    }
}

fn digest_hex(value: &str) -> Result<&str, DebugError> {
    value
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64)
        .ok_or(DebugError::InvalidRequest)
}

fn verify_root_owned_pin(file: &PinnedDebuggerFile) -> Result<(), DebugError> {
    let path = Path::new(&file.path);
    let resolved = path.canonicalize().map_err(|_| DebugError::Unavailable)?;
    verify_root_owned_directory(resolved.parent().ok_or(DebugError::Unavailable)?)?;
    verify_root_owned_directory(path.parent().ok_or(DebugError::Unavailable)?)?;
    let metadata = fs::metadata(&resolved).map_err(|_| DebugError::Unavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(DebugError::Unauthorized);
    }
    verify_managed_file(&resolved, &file.sha256)
}

fn verify_root_owned_executable(path: &Path) -> Result<(), DebugError> {
    let resolved = path.canonicalize().map_err(|_| DebugError::Unavailable)?;
    verify_root_owned_directory(path.parent().ok_or(DebugError::Unavailable)?)?;
    verify_root_owned_directory(resolved.parent().ok_or(DebugError::Unavailable)?)?;
    let metadata = fs::metadata(resolved).map_err(|_| DebugError::Unavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
        return Err(DebugError::Unauthorized);
    }
    Ok(())
}

fn verify_root_owned_directory(path: &Path) -> Result<(), DebugError> {
    for ancestor in path.ancestors() {
        let metadata = fs::metadata(ancestor).map_err(|_| DebugError::Unavailable)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(DebugError::Unauthorized);
        }
    }
    Ok(())
}

fn verify_managed_file(path: &Path, expected: &str) -> Result<(), DebugError> {
    let mut stream = File::open(path).map_err(|_| DebugError::Unavailable)?;
    let mut digest = Sha256::new();
    io::copy(&mut stream, &mut digest).map_err(|_| DebugError::BackendFailed)?;
    if format!("sha256:{:x}", digest.finalize()) != expected {
        return Err(DebugError::DigestMismatch);
    }
    Ok(())
}

fn create_session_root(service_root: &Path) -> Result<PathBuf, DebugError> {
    let parent = service_root.join("debug-sessions");
    fs::create_dir_all(&parent).map_err(|_| DebugError::BackendFailed)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).map_err(|_| DebugError::BackendFailed)?;
    for attempt in 0..8_u64 {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DebugError::BackendFailed)?
            .as_nanos();
        let path = parent.join(format!("session-{}-{stamp:x}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| DebugError::BackendFailed)?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(DebugError::BackendFailed),
        }
    }
    Err(DebugError::BackendFailed)
}

fn owned_prefix_process_exists(prefix: &Path) -> Result<bool, DebugError> {
    let needle = format!("WINEPREFIX={}", prefix.display());
    for entry in fs::read_dir("/proc").map_err(|_| DebugError::BackendFailed)? {
        let entry = entry.map_err(|_| DebugError::BackendFailed)?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        if let Ok(environ) = fs::read(entry.path().join("environ")) {
            if environ.split(|byte| *byte == 0).any(|part| part == needle.as_bytes()) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_owned(
        writer: SyncSender<(u64, Vec<u8>)>,
        write_acks: Receiver<(u64, bool)>,
        replies: Receiver<Result<Value, ()>>,
    ) -> WorkerOwned {
        let target = DebugTarget {
            application_id: "probe".into(),
            generation_id: "gen-job-1".into(),
            launcher_id: "main".into(),
        };
        WorkerOwned {
            child: Command::new("/usr/bin/sleep").arg("30").spawn().unwrap(),
            writer,
            write_acks,
            replies,
            next_request_id: 1,
            broken: false,
            session_root: PathBuf::from("/tmp/unused-debug-test"),
            prefix: PathBuf::from("/tmp/unused-debug-test/prefix"),
            binding: DapBinding::new(
                target,
                "/tmp/probe.exe",
                STUB_PORT,
                std::iter::empty::<(String, String)>(),
            )
            .unwrap(),
            stopped: false,
        }
    }

    #[test]
    fn wedged_control_writer_cannot_block_service_thread() {
        let (writer, _queued_write) = mpsc::sync_channel(1);
        let (_ack_sender, write_acks) = mpsc::sync_channel(1);
        let (_reply_sender, replies) = mpsc::sync_channel(1);
        let mut owned = synthetic_owned(writer, write_acks, replies);
        let started = Instant::now();
        assert_eq!(
            owned.call(&json!({"op":"poll"}), Duration::from_millis(50)),
            Err(DebugError::BackendFailed)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(owned.broken);
    }

    #[test]
    fn stale_worker_reply_cannot_satisfy_next_control_call() {
        let (writer, _queued_write) = mpsc::sync_channel(1);
        let (ack_sender, write_acks) = mpsc::sync_channel(1);
        let (reply_sender, replies) = mpsc::sync_channel(1);
        ack_sender.send((1, true)).unwrap();
        reply_sender.send(Ok(json!({"requestId":9,"messages":[]}))).unwrap();
        let mut owned = synthetic_owned(writer, write_acks, replies);
        assert_eq!(
            owned.call(&json!({"op":"poll"}), Duration::from_millis(50)),
            Err(DebugError::BackendFailed)
        );
        assert!(owned.broken);
    }

    #[test]
    fn oversized_debugger_message_becomes_bounded_dap_failure_without_stopping_session() {
        let binding = DapBinding::new(
            DebugTarget {
                application_id: "probe".into(),
                generation_id: "gen-job-1".into(),
                launcher_id: "main".into(),
            },
            "/tmp/probe.exe",
            STUB_PORT,
            std::iter::empty::<(String, String)>(),
        )
        .unwrap();
        let response = oversized_gateway_reply(
            &binding,
            &json!({"type":"response","request_seq":8,"command":"variables"}),
        );
        assert_eq!(response["type"], "response");
        assert_eq!(response["request_seq"], 8);
        assert_eq!(response["success"], false);
        let event = oversized_gateway_reply(&binding, &json!({"type":"request","command":"runInTerminal"}));
        assert_eq!(event["event"], "output");
    }

    #[test]
    fn replacement_owner_refuses_live_debug_prefix_then_reclaims_stale_copy() {
        let root = std::env::temp_dir().join(format!("compatforge-debug-recovery-{}", std::process::id()));
        let sessions = root.join("debug-sessions");
        let stale = sessions.join("session-test");
        let prefix = stale.join("prefix");
        fs::create_dir_all(&prefix).unwrap();
        let mut child = Command::new("/usr/bin/sleep")
            .arg("10")
            .env("WINEPREFIX", &prefix)
            .spawn()
            .unwrap();
        let backend = WorkerBackend::new(None, root.clone());
        assert_eq!(backend.recover_stale_sessions(), Err(DebugError::BackendFailed));
        child.kill().unwrap();
        child.wait().unwrap();
        backend.recover_stale_sessions().unwrap();
        assert!(!stale.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
