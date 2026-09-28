use compatforge_debug::{
    decode_request, Backend, DebugError, DebugEvent, DebugRequest, DebugSupervisor, DebugTarget, DebuggerBinary,
    DebuggerPackageBinding, PinnedDebugger, SessionState, MAX_ACTIVE_SESSIONS, MAX_TERMINAL_HISTORY,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn target() -> DebugTarget {
    DebugTarget {
        application_id: "sample".into(),
        generation_id: "gen-job-123".into(),
        launcher_id: "main".into(),
    }
}

fn pin() -> PinnedDebugger {
    PinnedDebugger {
        provider_id: "winedbg-gdb".into(),
        runtime_pack_digest: format!("sha256:{}", "a".repeat(64)),
        winedbg_sha256: format!(
            "sha256:{}",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ),
        gdb_sha256: format!(
            "sha256:{}",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ),
    }
}

#[test]
fn wire_rejects_wrong_version_oversized_payload_and_unknown_commands() {
    assert!(decode_request(br#"{"schemaVersion":"2","command":"launch","target":{"applicationId":"sample","generationId":"gen-job-123","launcherId":"main"}}"#).is_err());
    assert!(decode_request(&vec![b' '; 65_537]).is_err());
    assert!(decode_request(br#"{"schemaVersion":"1","command":"attachPid","pid":1}"#).is_err());
    assert!(decode_request(br#"{"schemaVersion":"1","command":"evaluate","expression":"!shell"}"#).is_err());
    assert!(decode_request(br#"{"schemaVersion":"1","command":"launch","target":{"applicationId":"sample","generationId":"gen-job-123","launcherId":"main"},"debuggerPath":"/tmp/gdb"}"#).is_err());
}

#[test]
fn target_requires_managed_identity_not_host_pid_or_paths() {
    assert!(target().validate().is_ok());
    for invalid in ["", "../other", "host:123", "../", "A B"] {
        let mut target = target();
        target.application_id = invalid.into();
        assert!(target.validate().is_err(), "{invalid}");
    }
    let mut target = target();
    target.generation_id = "1234".into();
    assert!(target.validate().is_err());
    target.generation_id = "gen-other".into();
    assert!(
        target.validate().is_err(),
        "only managed install job generations are valid"
    );
}

#[test]
fn pin_rejects_digest_mismatch_and_untrusted_provider() {
    pin().verify_executable(DebuggerBinary::WineDbg, b"hello").unwrap();
    pin().verify_executable(DebuggerBinary::Gdb, b"hello").unwrap();
    assert_eq!(
        pin().verify_executable(DebuggerBinary::Gdb, b"changed"),
        Err(DebugError::DigestMismatch)
    );
    let mut pin = pin();
    pin.provider_id = "custom".into();
    assert!(pin.verify_executable(DebuggerBinary::WineDbg, b"hello").is_err());
}

#[test]
fn package_binding_fails_closed_until_both_executables_and_runtime_are_pinned() {
    let bytes = include_bytes!("../../../packaging/linux/debugger-runtime.json");
    let manifest: DebuggerPackageBinding = serde_json::from_slice(bytes).unwrap();
    assert_eq!(
        manifest.trusted(&manifest.runtime_pack_digest),
        Err(DebugError::Unavailable)
    );
    let mut available = manifest;
    available.available = true;
    assert_eq!(
        available.trusted(&available.runtime_pack_digest),
        Err(DebugError::Unavailable)
    );
    available.winedbg_sha256 = Some(pin().winedbg_sha256);
    available.gdb_sha256 = Some(pin().gdb_sha256);
    assert_eq!(
        available.trusted("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        Err(DebugError::DigestMismatch)
    );
    assert!(available.trusted(&available.runtime_pack_digest).is_ok());
}

#[derive(Default)]
struct BackendCounter {
    launches: AtomicUsize,
    terminations: AtomicUsize,
    disconnects: AtomicUsize,
}

impl Backend for BackendCounter {
    type Owned = ();
    fn launch(&self, _: &DebugTarget) -> Result<Self::Owned, DebugError> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn terminate(&self, _: &mut Self::Owned) -> Result<(), DebugError> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn disconnect(&self, _: &mut Self::Owned) -> Result<(), DebugError> {
        self.disconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn managed_backend_lease_exposes_owned_process_only_to_authorized_handle() {
    let mut sessions = DebugSupervisor::new(BackendCounter::default());
    let handle = sessions
        .launch_with(target(), 1000, |backend, target| backend.launch(target))
        .unwrap();
    assert_eq!(
        sessions.with_owned(&handle, 1001, |_backend, _owned| Ok(true)),
        Err(DebugError::Unauthorized)
    );
    assert_eq!(
        sessions.with_owned(&handle, 1000, |_backend, _owned| Ok(true)),
        Ok(true)
    );
    sessions.disconnect(&handle, 1000).unwrap();
    assert_eq!(
        sessions.with_owned(&handle, 1000, |_backend, _owned| Ok(true)),
        Err(DebugError::InvalidTransition)
    );
}

#[test]
fn supervisor_denies_foreign_handle_and_owns_terminal_transitions() {
    let backend = BackendCounter::default();
    let mut sessions = DebugSupervisor::new(backend);
    let handle = sessions.launch(target(), 1000).unwrap();
    assert_eq!(sessions.state(&handle, 1001), Err(DebugError::Unauthorized));
    let mut forged = handle.clone();
    forged.capability = "0".repeat(64);
    assert_eq!(sessions.state(&forged, 1000), Err(DebugError::Unauthorized));
    assert_eq!(sessions.state(&handle, 1000).unwrap(), SessionState::Active);
    assert_eq!(sessions.target(&handle, 1000).unwrap(), target());
    assert!(sessions.record(&handle, 1000, DebugEvent::Stopped).is_ok());
    assert_eq!(sessions.state(&handle, 1000).unwrap(), SessionState::Stopped);
    assert!(sessions.record(&handle, 1000, DebugEvent::Continued).is_ok());
    assert_eq!(sessions.state(&handle, 1000).unwrap(), SessionState::Active);
    assert!(sessions.terminate(&handle, 1000).is_ok());
    assert!(sessions.terminate(&handle, 1000).is_ok());
    assert_eq!(sessions.backend().terminations.load(Ordering::SeqCst), 1);
    assert_eq!(sessions.state(&handle, 1000).unwrap(), SessionState::Terminated);
    assert_eq!(
        sessions.record(&handle, 1000, DebugEvent::Continued),
        Err(DebugError::InvalidTransition)
    );
}

#[test]
fn disconnect_is_idempotent() {
    let backend = BackendCounter::default();
    let mut sessions = DebugSupervisor::new(backend);
    let handle = sessions.launch(target(), 1000).unwrap();
    sessions.disconnect(&handle, 1000).unwrap();
    sessions.disconnect(&handle, 1000).unwrap();
    assert_eq!(sessions.backend().disconnects.load(Ordering::SeqCst), 1);
    assert_eq!(sessions.state(&handle, 1000).unwrap(), SessionState::Disconnected);
}

#[test]
fn completed_sessions_release_admission_and_keep_only_recent_idempotent_handles() {
    let mut sessions = DebugSupervisor::new(BackendCounter::default());
    let mut handles = Vec::new();
    for _ in 0..(MAX_TERMINAL_HISTORY + MAX_ACTIVE_SESSIONS + 1) {
        let handle = sessions.launch(target(), 1000).unwrap();
        sessions.terminate(&handle, 1000).unwrap();
        handles.push(handle);
    }
    assert!(sessions.count() <= MAX_TERMINAL_HISTORY);
    assert_eq!(sessions.terminate(&handles[0], 1000), Err(DebugError::Unauthorized));
    let recent = handles.last().unwrap();
    assert_eq!(sessions.state(recent, 1000), Ok(SessionState::Terminated));
    assert_eq!(sessions.terminate(recent, 1000), Ok(()));
    assert_eq!(sessions.backend().terminations.load(Ordering::SeqCst), handles.len());
}

#[test]
fn active_capacity_remains_eight_and_tombstone_reclamation_never_evicts_active_sessions() {
    let mut sessions = DebugSupervisor::new(BackendCounter::default());
    let active = (0..MAX_ACTIVE_SESSIONS)
        .map(|_| sessions.launch(target(), 1000).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(sessions.launch(target(), 1000), Err(DebugError::Capacity));
    sessions.disconnect(&active[0], 1000).unwrap();
    for _ in 0..(MAX_TERMINAL_HISTORY + 9) {
        let temporary = sessions.launch(target(), 1000).unwrap();
        sessions.disconnect(&temporary, 1000).unwrap();
    }
    assert!(sessions.count() <= MAX_ACTIVE_SESSIONS - 1 + MAX_TERMINAL_HISTORY);
    for handle in &active[1..] {
        assert_eq!(sessions.state(handle, 1000), Ok(SessionState::Active));
    }
    assert_eq!(sessions.state(&active[0], 1000), Err(DebugError::Unauthorized));
    assert!(sessions.launch(target(), 1000).is_ok());
    assert_eq!(sessions.launch(target(), 1000), Err(DebugError::Capacity));
}

#[test]
fn unavailable_provider_cannot_create_a_fake_debug_session() {
    let mut sessions = DebugSupervisor::new(compatforge_debug::UnavailableBackend);
    assert_eq!(sessions.launch(target(), 1000), Err(DebugError::Unavailable));
    assert_eq!(sessions.count(), 0);
}

struct RefusingCleanup;
impl Backend for RefusingCleanup {
    type Owned = ();
    fn launch(&self, _: &DebugTarget) -> Result<Self::Owned, DebugError> {
        Ok(())
    }
    fn terminate(&self, _: &mut Self::Owned) -> Result<(), DebugError> {
        Err(DebugError::BackendFailed)
    }
    fn disconnect(&self, _: &mut Self::Owned) -> Result<(), DebugError> {
        Err(DebugError::BackendFailed)
    }
}

#[test]
fn shutdown_reports_cleanup_failure_and_keeps_owned_session_for_retry() {
    let mut sessions = DebugSupervisor::new(RefusingCleanup);
    let handle = sessions.launch(target(), 1000).unwrap();
    assert_eq!(sessions.shutdown(), Err(DebugError::BackendFailed));
    assert_eq!(sessions.state(&handle, 1000).unwrap(), SessionState::Active);
    assert_eq!(sessions.count(), 1);
}

#[test]
fn typed_launch_decodes_without_arbitrary_host_process_fields() {
    let request = decode_request(br#"{"schemaVersion":"1","command":"launch","target":{"applicationId":"sample","generationId":"gen-job-123","launcherId":"main"}}"#).unwrap();
    assert_eq!(request, DebugRequest::Launch { target: target() });
}
