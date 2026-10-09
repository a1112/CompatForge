use super::*;
use crate::{CoreConfig, ServiceConfig};
use forge_provider_contract::binding::{validate_identity, validate_response_identity, ServerHello};
use forge_provider_contract::{ProviderInfo, ProviderRequirements, MAX_CONTRACT_BYTES};
use fs4::FileExt;
use rustix::net::sockopt::get_socket_peercred;
use rustix::process::{geteuid, getuid};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const CALL_TIMEOUT: Duration = Duration::from_secs(65);

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn caller_uid() -> io::Result<u32> {
    let uid = geteuid();
    if uid.as_raw() == 0 || uid != getuid() {
        return Err(denied("shared service requires an ordinary, non-setuid user"));
    }
    Ok(uid.as_raw())
}

fn private_directory(path: &Path) -> io::Result<()> {
    let uid = caller_uid()?;
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(denied("runtime directory must be canonical"));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(denied("runtime directory has a linked ancestor"));
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != uid || metadata.mode() & 0o777 != 0o700 {
        return Err(denied("runtime directory must be caller-owned mode 0700"));
    }
    Ok(())
}

pub fn runtime_directory() -> io::Result<PathBuf> {
    let root = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| denied("XDG_RUNTIME_DIR is required"))?);
    private_directory(&root)?;
    let path = root.join("compatforge");
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    private_directory(&path)?;
    Ok(path)
}

fn check_socket(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.uid() != caller_uid()? || metadata.mode() & 0o777 != 0o600 {
        return Err(denied("service endpoint must be a caller-owned mode 0600 socket"));
    }
    Ok(metadata)
}

fn authenticate(stream: &UnixStream) -> io::Result<()> {
    if get_socket_peercred(stream)?.uid.as_raw() != caller_uid()? {
        return Err(denied("service peer UID differs from caller"));
    }
    Ok(())
}

fn connect(path: &Path) -> io::Result<UnixStream> {
    use rustix::net::{connect_unix, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let address = SocketAddrUnix::new(path)?;
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        match connect_unix(&socket, &address) {
            Ok(()) => {
                let stream = UnixStream::from(socket);
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(error.into()),
        }
    }
}

struct DeadlineStream<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}
impl DeadlineStream<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "service frame deadline elapsed"))
    }
}
impl Read for DeadlineStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

struct Endpoint {
    listener: UnixListener,
    path: PathBuf,
    inode: u64,
    device: u64,
    _lock: File,
}

impl Endpoint {
    fn bind(directory: &Path) -> io::Result<Self> {
        private_directory(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(directory.join("owner.lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != caller_uid()?
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(denied("invalid endpoint ownership lock"));
        }
        lock.try_lock_exclusive()
            .map_err(|_| io::Error::new(io::ErrorKind::AddrInUse, "service endpoint already owned"))?;
        let path = directory.join(SOCKET_NAME);
        match check_socket(&path) {
            Ok(_) => match connect(&path) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(&path)?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "service endpoint may still be active",
                    ))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = check_socket(&path)?;
        let endpoint = Self {
            listener,
            path,
            inode: metadata.ino(),
            device: metadata.dev(),
            _lock: lock,
        };
        endpoint.listener.set_nonblocking(true)?;
        Ok(endpoint)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if check_socket(&self.path).is_ok_and(|m| m.ino() == self.inode && m.dev() == self.device) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// One request per connection. Disconnect affects only its response delivery.
pub fn request(directory: &Path, request: &ServiceRequest, required: &ProviderRequirements) -> io::Result<DaemonReply> {
    private_directory(directory)?;
    request.validate().map_err(io::Error::other)?;
    let path = directory.join(SOCKET_NAME);
    check_socket(&path)?;
    let mut stream = connect(&path)?;
    authenticate(&stream)?;
    let hello = ClientHello {
        schema_version: WIRE_VERSION.into(),
        request_id: request.request_id.clone(),
        required_provider: required.clone(),
    };
    hello.validate().map_err(io::Error::other)?;
    write_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        &serde_json::to_vec(&hello)?,
        MAX_CONTRACT_BYTES,
    )?;
    let server_bytes = read_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        MAX_CONTRACT_BYTES,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("forge.provider.provider-unavailable: daemon handshake v2 unavailable: {error}"),
        )
    })?;
    let server: ServerHello = serde_json::from_slice(&server_bytes)
        .map_err(|_| io::Error::other("forge.provider.schema-mismatch: daemon must implement identity handshake v2"))?;
    server.validate(&hello).map_err(io::Error::other)?;
    // No business operation is sent until the actual peer's immutable identity matches.
    let bound = BoundDaemonRequest {
        schema_version: WIRE_VERSION.into(),
        daemon_instance_id: server.daemon.instance_id.clone(),
        request,
    };
    write_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        &serde_json::to_vec(&bound)?,
        crate::transport::MAX_REQUEST_BYTES + MAX_CONTRACT_BYTES,
    )?;
    let reply: DaemonReply = serde_json::from_slice(&read_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now()
                + if request.operation == "daemon.stop" {
                    Duration::from_secs(110)
                } else {
                    CALL_TIMEOUT
                },
        },
        MAX_RESPONSE_BYTES,
    )?)
    .map_err(|_| io::Error::other("forge.provider.schema-mismatch: daemon reply must carry wire v2 identity"))?;
    validate_response_identity(&reply.daemon, &server.daemon, required).map_err(io::Error::other)?;
    if reply.schema_version != WIRE_VERSION
        || reply.request_id != request.request_id
        || reply.response.is_some() == reply.error.is_some()
        || reply.response.as_ref().is_some_and(|r| {
            r.schema_version != "1" || r.request_id != request.request_id || r.operation != request.operation
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid daemon reply envelope",
        ));
    }
    Ok(reply)
}

type StopReplies = Mutex<Vec<(UnixStream, DaemonReply)>>;

fn connection(
    mut stream: UnixStream,
    service: &AutomationService,
    stop: &AtomicBool,
    stops: &StopReplies,
    daemon: &DaemonIdentity,
) -> io::Result<()> {
    authenticate(&stream)?;
    let hello: ClientHello = serde_json::from_slice(&read_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        MAX_CONTRACT_BYTES,
    )?)?;
    hello.validate().map_err(io::Error::other)?;
    let server = ServerHello {
        schema_version: WIRE_VERSION.into(),
        request_id: hello.request_id.clone(),
        daemon: daemon.clone(),
    };
    write_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        &serde_json::to_vec(&server)?,
        MAX_CONTRACT_BYTES,
    )?;
    // The daemon validates its own frozen identity, never echoes caller metadata as identity.
    validate_identity(daemon, &hello.required_provider).map_err(io::Error::other)?;
    let bound: BoundDaemonRequest<ServiceRequest> = serde_json::from_slice(&read_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        crate::transport::MAX_REQUEST_BYTES + MAX_CONTRACT_BYTES,
    )?)?;
    let reply = dispatch_bound(service, bound, &hello, stop, daemon)?;
    if reply
        .response
        .as_ref()
        .is_some_and(|response| response.operation == "daemon.stop")
    {
        // ExecStop must not return before cleanup: retain this response stream
        // while its worker exits, then acknowledge only after all jobs join.
        stops
            .lock()
            .map_err(|_| io::Error::other("stop reply lock poisoned"))?
            .push((stream, reply));
        return Ok(());
    }
    send_reply(stream, reply)
}

fn send_reply(mut stream: UnixStream, reply: DaemonReply) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&reply)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        bytes = serde_json::to_vec(&DaemonReply {
            schema_version: WIRE_VERSION.into(),
            request_id: reply.request_id,
            daemon: reply.daemon,
            response: None,
            error: Some(DaemonError {
                code: "response-too-large".into(),
                message: "response exceeds 16 MiB; use an individual record query".into(),
            }),
        })?;
    }
    write_frame(
        &mut DeadlineStream {
            stream: &mut stream,
            deadline: Instant::now() + IO_TIMEOUT,
        },
        &bytes,
        MAX_RESPONSE_BYTES,
    )
}

/// The owning process stops admission, joins clients, then drains every job.
/// systemd ExecStop uses daemon.stop. SIGKILL remains crash/quarantine recovery.
pub fn run(
    directory: &Path,
    config: CoreConfig,
    service_config: ServiceConfig,
    provider: ProviderInfo,
) -> io::Result<()> {
    let daemon = Arc::new(DaemonIdentity {
        schema_version: WIRE_VERSION.into(),
        provider,
        instance_id: format!(
            "daemon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos()
        ),
    });
    validate_identity(&daemon, &daemon.provider.identity()).map_err(io::Error::other)?;
    let endpoint = Endpoint::bind(directory)?;
    let service = Arc::new(AutomationService::new(config, service_config).map_err(io::Error::other)?);
    let stop = Arc::new(AtomicBool::new(false));
    let stops = Arc::new(StopReplies::new(Vec::new()));
    let mut clients: Vec<JoinHandle<()>> = Vec::new();
    let mut last_tick = Instant::now();
    let result = (|| {
        while !stop.load(Ordering::Acquire) {
            let mut index = 0;
            while index < clients.len() {
                if clients[index].is_finished() {
                    clients
                        .swap_remove(index)
                        .join()
                        .map_err(|_| io::Error::other("daemon client panicked"))?;
                } else {
                    index += 1;
                }
            }
            if last_tick.elapsed() >= Duration::from_millis(100) {
                service.poll_active_jobs().map_err(io::Error::other)?;
                last_tick = Instant::now();
            }
            match endpoint.listener.accept() {
                Ok((stream, _)) if clients.len() < MAX_CONNECTIONS => {
                    let service = Arc::clone(&service);
                    let stop = Arc::clone(&stop);
                    let stops = Arc::clone(&stops);
                    let daemon = Arc::clone(&daemon);
                    clients.push(
                        thread::Builder::new()
                            .name("compatforge-client".into())
                            .spawn(move || {
                                // A malformed frame, failed write, or disconnected UI is
                                // local to this connection and never owns service jobs.
                                let _ = connection(stream, &service, &stop, &stops, &daemon);
                            })?,
                    );
                }
                Ok(_) => {} // Bound worker count even for stalled peers.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    let mut drain = Ok(());
    for client in clients {
        if client.join().is_err() {
            drain = Err(io::Error::other("daemon client panicked during drain"));
        }
    }
    let cleanup = service.shutdown_and_wait().map_err(io::Error::other);
    let outcome = cleanup.and(drain).and(result);
    let failure = outcome.as_ref().err().map(ToString::to_string);
    for (stream, reply) in stops
        .lock()
        .map_err(|_| io::Error::other("stop reply lock poisoned"))?
        .drain(..)
    {
        let _ = send_reply(stream, shutdown_reply(reply, failure.as_deref()));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cf-socket-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }
    #[test]
    fn endpoint_is_private_exclusive_and_preserves_foreign_files() {
        let root = directory();
        let owner = Endpoint::bind(&root).unwrap();
        assert_eq!(fs::metadata(&owner.path).unwrap().mode() & 0o777, 0o600);
        assert!(Endpoint::bind(&root).is_err());
        let mut client = UnixStream::connect(&owner.path).unwrap();
        let (server, _) = owner.listener.accept().unwrap();
        authenticate(&client).unwrap();
        authenticate(&server).unwrap();
        write_frame(&mut client, b"hello", 10).unwrap();
        assert_eq!(read_frame(&mut &server, 10).unwrap(), b"hello");
        drop(owner);
        let path = root.join(SOCKET_NAME);
        fs::write(&path, "foreign").unwrap();
        assert!(Endpoint::bind(&root).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "foreign");
    }
    #[test]
    fn refuses_open_directories_symlinks_and_recovers_only_dead_socket() {
        let root = directory();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Endpoint::bind(&root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = root.with_extension("link");
        symlink(&root, &linked).unwrap();
        assert!(Endpoint::bind(&linked).is_err());
        let path = root.join(SOCKET_NAME);
        let stale = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(stale);
        let owner = Endpoint::bind(&root).unwrap();
        assert!(request(
            &root,
            &ServiceRequest {
                schema_version: "bad".into(),
                request_id: "id".into(),
                operation: "applications.list".into(),
                payload: serde_json::json!({})
            },
            &super::super::tests::identity().provider.identity(),
        )
        .is_err());
        drop(owner);
        assert!(!path.exists());
    }
}
