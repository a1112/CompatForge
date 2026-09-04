//! Verified, content-addressed Runtime Pack installation and rollback.

#![forbid(unsafe_code)]

use compatforge_domain::{
    validate_digest, validate_id, validate_portable_relative_path, ContractError, ManifestSignature, RuntimeChannel,
    RuntimePackManifest, SignatureAlgorithm, SCHEMA_VERSION_V1,
};
use compatforge_storage::{JsonStore, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const MAX_ACTIVATION_HISTORY: usize = 32;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static STORE_WRITE_LOCK: Mutex<()> = Mutex::new(());

pub trait ManifestSignatureVerifier {
    fn verify(&self, signature: &ManifestSignature, canonical_manifest: &[u8]) -> bool;
}

/// Secure default used until a trusted key provider is configured.
pub struct RejectAllSignatures;

impl ManifestSignatureVerifier for RejectAllSignatures {
    fn verify(&self, _signature: &ManifestSignature, _canonical_manifest: &[u8]) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReceipt {
    pub schema_version: String,
    pub pack_id: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub activated: bool,
    pub reused_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceipt {
    pub schema_version: String,
    pub pack_id: String,
    pub digest: String,
    pub verified_objects: usize,
}

#[derive(Debug, Clone)]
pub struct RuntimePackStore {
    root: PathBuf,
}

impl RuntimePackStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn install_bundle(
        &self,
        bundle_root: impl AsRef<Path>,
        manifest_relative_path: &str,
        verifier: &dyn ManifestSignatureVerifier,
    ) -> Result<InstallReceipt, RuntimePackError> {
        validate_portable_relative_path("runtimePack.manifestPath", manifest_relative_path)?;
        let bundle_root = canonical_directory(bundle_root.as_ref())?;
        let manifest_path = resolve_bundle_file(&bundle_root, manifest_relative_path)?;
        let manifest_bytes = fs::read(manifest_path).map_err(RuntimePackError::Io)?;
        let manifest: RuntimePackManifest = serde_json::from_slice(&manifest_bytes).map_err(RuntimePackError::Json)?;
        self.install(&bundle_root, &manifest, verifier)
    }

    pub fn install(
        &self,
        bundle_root: impl AsRef<Path>,
        manifest: &RuntimePackManifest,
        verifier: &dyn ManifestSignatureVerifier,
    ) -> Result<InstallReceipt, RuntimePackError> {
        let canonical = verify_manifest(manifest, verifier)?;
        let bundle_root = canonical_directory(bundle_root.as_ref())?;
        let _guard = STORE_WRITE_LOCK
            .lock()
            .map_err(|_| RuntimePackError::Internal("runtime store writer lock is poisoned"))?;
        fs::create_dir_all(&self.root).map_err(RuntimePackError::Io)?;

        let mut reused_objects = 0;
        for component in &manifest.components {
            let source = resolve_bundle_file(&bundle_root, &component.artifact_path())?;
            if self.publish_object(&source, &component.digest, &component.name)? {
                reused_objects += 1;
            }
        }
        self.publish_manifest(manifest, &canonical)?;

        let store = JsonStore::new(&self.root);
        let relative = active_ref_path(&manifest.id);
        let current = read_optional_ref(&store, &relative)?;
        if current
            .as_ref()
            .is_some_and(|state| state.active_digest.eq_ignore_ascii_case(&manifest.digest))
        {
            return Ok(InstallReceipt {
                schema_version: SCHEMA_VERSION_V1.into(),
                pack_id: manifest.id.clone(),
                digest: normalized_digest(&manifest.digest),
                previous_digest: current.and_then(|state| state.history.last().cloned()),
                activated: false,
                reused_objects,
            });
        }

        let previous_digest = current.as_ref().map(|state| state.active_digest.clone());
        let mut history = current.map_or_else(Vec::new, |state| {
            let mut history = state.history;
            history.push(state.active_digest);
            history
        });
        if history.len() > MAX_ACTIVATION_HISTORY {
            history.drain(..history.len() - MAX_ACTIVATION_HISTORY);
        }
        let state = ActiveRuntimePack {
            schema_version: SCHEMA_VERSION_V1.into(),
            pack_id: manifest.id.clone(),
            active_digest: normalized_digest(&manifest.digest),
            history,
        };
        state.validate()?;
        store.write(relative, &state).map_err(RuntimePackError::Store)?;
        Ok(InstallReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            pack_id: manifest.id.clone(),
            digest: normalized_digest(&manifest.digest),
            previous_digest,
            activated: true,
            reused_objects,
        })
    }

    pub fn verify_installed(&self, digest: &str) -> Result<VerificationReceipt, RuntimePackError> {
        validate_digest("runtimePack.digest", digest)?;
        let manifest = self.load_manifest(digest)?;
        self.verify_installed_manifest(digest, &manifest)
    }

    /// Load a manifest only after re-verifying its requested digest and every
    /// content-addressed component object.
    pub fn verified_manifest(&self, digest: &str) -> Result<RuntimePackManifest, RuntimePackError> {
        validate_digest("runtimePack.digest", digest)?;
        let manifest = self.load_manifest(digest)?;
        self.verify_installed_manifest(digest, &manifest)?;
        Ok(manifest)
    }

    pub fn active_digest(&self, pack_id: &str) -> Result<Option<String>, RuntimePackError> {
        validate_id("runtimePack.id", pack_id)?;
        let state = read_optional_ref(&JsonStore::new(&self.root), &active_ref_path(pack_id))?;
        state
            .map(|state| {
                state.validate()?;
                Ok(state.active_digest)
            })
            .transpose()
    }

    pub fn rollback(&self, pack_id: &str) -> Result<InstallReceipt, RuntimePackError> {
        validate_id("runtimePack.id", pack_id)?;
        let _guard = STORE_WRITE_LOCK
            .lock()
            .map_err(|_| RuntimePackError::Internal("runtime store writer lock is poisoned"))?;
        let store = JsonStore::new(&self.root);
        let relative = active_ref_path(pack_id);
        let mut state =
            read_optional_ref(&store, &relative)?.ok_or_else(|| RuntimePackError::PackNotInstalled(pack_id.into()))?;
        state.validate()?;
        let previous_digest = state.active_digest.clone();
        let target_digest = state
            .history
            .pop()
            .ok_or_else(|| RuntimePackError::NoRollbackAvailable(pack_id.into()))?;
        let manifest = self.load_manifest(&target_digest)?;
        if manifest.id != pack_id {
            return Err(RuntimePackError::CorruptState(
                "rollback manifest pack id does not match ref",
            ));
        }
        self.verify_installed_manifest(&target_digest, &manifest)?;
        state.active_digest = target_digest.clone();
        store.write(relative, &state).map_err(RuntimePackError::Store)?;
        Ok(InstallReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            pack_id: pack_id.into(),
            digest: target_digest,
            previous_digest: Some(previous_digest),
            activated: true,
            reused_objects: manifest.components.len(),
        })
    }

    fn publish_object(&self, source: &Path, digest: &str, component: &str) -> Result<bool, RuntimePackError> {
        let target = self.root.join(object_relative_path(digest)?);
        if target.is_file() {
            let actual = sha256_digest_file(&target)?;
            if actual.eq_ignore_ascii_case(digest) {
                return Ok(true);
            }
            return Err(RuntimePackError::ObjectCollision(normalized_digest(digest)));
        }
        let parent = target
            .parent()
            .ok_or(RuntimePackError::Internal("object path has no parent"))?;
        fs::create_dir_all(parent).map_err(RuntimePackError::Io)?;
        let temporary = temporary_path(&target)?;
        let result = (|| {
            let mut input = File::open(source).map_err(RuntimePackError::Io)?;
            let mut output = create_private_temporary(&temporary)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; COPY_BUFFER_SIZE];
            loop {
                let read = input.read(&mut buffer).map_err(RuntimePackError::Io)?;
                if read == 0 {
                    break;
                }
                output.write_all(&buffer[..read]).map_err(RuntimePackError::Io)?;
                hasher.update(&buffer[..read]);
            }
            output.sync_all().map_err(RuntimePackError::Io)?;
            let actual = format_digest(hasher.finalize());
            if !actual.eq_ignore_ascii_case(digest) {
                return Err(RuntimePackError::ComponentDigestMismatch {
                    component: component.into(),
                    expected: normalized_digest(digest),
                    actual,
                });
            }
            fs::rename(&temporary, &target).map_err(RuntimePackError::Io)?;
            sync_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map(|()| false)
    }

    fn publish_manifest(&self, manifest: &RuntimePackManifest, canonical: &[u8]) -> Result<(), RuntimePackError> {
        let target = self.root.join(manifest_relative_path(&manifest.digest)?);
        if target.is_file() {
            let existing: RuntimePackManifest =
                serde_json::from_slice(&fs::read(target).map_err(RuntimePackError::Io)?)
                    .map_err(RuntimePackError::Json)?;
            existing.validate()?;
            if existing.canonical_unsigned_bytes().map_err(RuntimePackError::Json)? == canonical {
                return Ok(());
            }
            return Err(RuntimePackError::ManifestCollision(normalized_digest(&manifest.digest)));
        }

        let mut normalized = manifest.clone();
        normalized.components.sort_by(|left, right| left.name.cmp(&right.name));
        normalized.capabilities.sort();
        let mut bytes = serde_json::to_vec_pretty(&normalized).map_err(RuntimePackError::Json)?;
        bytes.push(b'\n');
        publish_bytes(&target, &bytes)
    }

    fn load_manifest(&self, digest: &str) -> Result<RuntimePackManifest, RuntimePackError> {
        let path = self.root.join(manifest_relative_path(digest)?);
        let bytes = fs::read(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RuntimePackError::PackNotInstalled(normalized_digest(digest))
            } else {
                RuntimePackError::Io(error)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(RuntimePackError::Json)
    }

    fn verify_installed_manifest(
        &self,
        expected_digest: &str,
        manifest: &RuntimePackManifest,
    ) -> Result<VerificationReceipt, RuntimePackError> {
        manifest.validate()?;
        if !manifest.digest.eq_ignore_ascii_case(expected_digest) {
            return Err(RuntimePackError::ManifestDigestMismatch {
                expected: normalized_digest(expected_digest),
                actual: normalized_digest(&manifest.digest),
            });
        }
        let canonical = manifest.canonical_unsigned_bytes().map_err(RuntimePackError::Json)?;
        let actual = sha256_digest_bytes(&canonical);
        if !actual.eq_ignore_ascii_case(&manifest.digest) {
            return Err(RuntimePackError::ManifestDigestMismatch {
                expected: normalized_digest(&manifest.digest),
                actual,
            });
        }
        for component in &manifest.components {
            let object = self.root.join(object_relative_path(&component.digest)?);
            let actual = sha256_digest_file(&object)?;
            if !actual.eq_ignore_ascii_case(&component.digest) {
                return Err(RuntimePackError::ComponentDigestMismatch {
                    component: component.name.clone(),
                    expected: normalized_digest(&component.digest),
                    actual,
                });
            }
        }
        Ok(VerificationReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            pack_id: manifest.id.clone(),
            digest: normalized_digest(&manifest.digest),
            verified_objects: manifest.components.len(),
        })
    }
}

pub fn verify_manifest(
    manifest: &RuntimePackManifest,
    verifier: &dyn ManifestSignatureVerifier,
) -> Result<Vec<u8>, RuntimePackError> {
    manifest.validate()?;
    let canonical = manifest.canonical_unsigned_bytes().map_err(RuntimePackError::Json)?;
    let actual = sha256_digest_bytes(&canonical);
    if !actual.eq_ignore_ascii_case(&manifest.digest) {
        return Err(RuntimePackError::ManifestDigestMismatch {
            expected: normalized_digest(&manifest.digest),
            actual,
        });
    }
    match (&manifest.channel, &manifest.signature) {
        (Some(RuntimeChannel::Stable | RuntimeChannel::Candidate), None) => {
            return Err(RuntimePackError::SignatureRequired)
        }
        (_, Some(signature)) if !verifier.verify(signature, &canonical) => {
            return Err(RuntimePackError::SignatureRejected {
                key_id: signature.key_id.clone(),
                algorithm: signature.algorithm,
            })
        }
        _ => {}
    }
    Ok(canonical)
}

#[must_use]
pub fn sha256_digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format_digest(hasher.finalize())
}

fn sha256_digest_file(path: &Path) -> Result<String, RuntimePackError> {
    let mut file = File::open(path).map_err(RuntimePackError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer).map_err(RuntimePackError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format_digest(hasher.finalize()))
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveRuntimePack {
    schema_version: String,
    pack_id: String,
    active_digest: String,
    #[serde(default)]
    history: Vec<String>,
}

impl ActiveRuntimePack {
    fn validate(&self) -> Result<(), RuntimePackError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(RuntimePackError::CorruptState("unsupported active ref schema"));
        }
        validate_id("runtimePack.id", &self.pack_id)?;
        validate_digest("runtimePack.digest", &self.active_digest)?;
        if self.history.len() > MAX_ACTIVATION_HISTORY {
            return Err(RuntimePackError::CorruptState("activation history exceeds its bound"));
        }
        for digest in &self.history {
            validate_digest("runtimePack.history.digest", digest)?;
        }
        Ok(())
    }
}

fn read_optional_ref(store: &JsonStore, relative: &Path) -> Result<Option<ActiveRuntimePack>, RuntimePackError> {
    if !store.exists(relative) {
        return Ok(None);
    }
    let state: ActiveRuntimePack = store.read(relative).map_err(RuntimePackError::Store)?;
    state.validate()?;
    Ok(Some(state))
}

fn active_ref_path(pack_id: &str) -> PathBuf {
    PathBuf::from("refs").join(pack_id).join("current.json")
}

fn object_relative_path(digest: &str) -> Result<PathBuf, RuntimePackError> {
    validate_digest("runtimePack.components.digest", digest)?;
    Ok(PathBuf::from("objects").join("sha256").join(digest_hex(digest)))
}

fn manifest_relative_path(digest: &str) -> Result<PathBuf, RuntimePackError> {
    validate_digest("runtimePack.digest", digest)?;
    Ok(PathBuf::from("manifests")
        .join("sha256")
        .join(format!("{}.json", digest_hex(digest))))
}

fn digest_hex(digest: &str) -> String {
    digest.trim_start_matches("sha256:").to_ascii_lowercase()
}

fn normalized_digest(digest: &str) -> String {
    format!("sha256:{}", digest_hex(digest))
}

fn canonical_directory(path: &Path) -> Result<PathBuf, RuntimePackError> {
    let canonical = path.canonicalize().map_err(RuntimePackError::Io)?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(RuntimePackError::BundlePath("bundle root is not a directory"))
    }
}

fn resolve_bundle_file(bundle_root: &Path, relative: &str) -> Result<PathBuf, RuntimePackError> {
    validate_portable_relative_path("runtimePack.bundlePath", relative)?;
    let candidate = relative
        .split('/')
        .fold(bundle_root.to_path_buf(), |path, component| path.join(component));
    let canonical = candidate.canonicalize().map_err(RuntimePackError::Io)?;
    if !canonical.starts_with(bundle_root) || !canonical.is_file() {
        return Err(RuntimePackError::BundlePath(
            "bundle artifact escapes its root or is not a file",
        ));
    }
    Ok(canonical)
}

fn temporary_path(target: &Path) -> Result<PathBuf, RuntimePackError> {
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RuntimePackError::Internal("store target has no UTF-8 filename"))?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(target.with_file_name(format!(".{name}.tmp-{}-{counter}", std::process::id())))
}

fn publish_bytes(target: &Path, bytes: &[u8]) -> Result<(), RuntimePackError> {
    let parent = target
        .parent()
        .ok_or(RuntimePackError::Internal("store target has no parent"))?;
    fs::create_dir_all(parent).map_err(RuntimePackError::Io)?;
    let temporary = temporary_path(target)?;
    let result = (|| {
        let mut file = create_private_temporary(&temporary)?;
        file.write_all(bytes).map_err(RuntimePackError::Io)?;
        file.sync_all().map_err(RuntimePackError::Io)?;
        fs::rename(&temporary, target).map_err(RuntimePackError::Io)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_private_temporary(path: &Path) -> Result<File, RuntimePackError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let file = options.open(path).map_err(RuntimePackError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(RuntimePackError::Io(error));
        }
    }
    Ok(file)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), RuntimePackError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(RuntimePackError::Io)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), RuntimePackError> {
    Ok(())
}

fn format_digest(bytes: impl AsRef<[u8]>) -> String {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
    }
    value
}

#[derive(Debug)]
pub enum RuntimePackError {
    Contract(ContractError),
    Json(serde_json::Error),
    Store(StoreError),
    Io(io::Error),
    BundlePath(&'static str),
    ManifestDigestMismatch {
        expected: String,
        actual: String,
    },
    ComponentDigestMismatch {
        component: String,
        expected: String,
        actual: String,
    },
    SignatureRequired,
    SignatureRejected {
        key_id: String,
        algorithm: SignatureAlgorithm,
    },
    ObjectCollision(String),
    ManifestCollision(String),
    PackNotInstalled(String),
    NoRollbackAvailable(String),
    CorruptState(&'static str),
    Internal(&'static str),
}

impl fmt::Display for RuntimePackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid Runtime Pack contract: {error}"),
            Self::Json(error) => write!(formatter, "Runtime Pack JSON failed: {error}"),
            Self::Store(error) => write!(formatter, "Runtime Pack state failed: {error}"),
            Self::Io(error) => write!(formatter, "Runtime Pack I/O failed: {error}"),
            Self::BundlePath(message) => write!(formatter, "invalid Runtime Pack bundle path: {message}"),
            Self::ManifestDigestMismatch { expected, actual } => {
                write!(formatter, "manifest digest mismatch: expected {expected}, got {actual}")
            }
            Self::ComponentDigestMismatch {
                component,
                expected,
                actual,
            } => write!(
                formatter,
                "component {component} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::SignatureRequired => formatter.write_str("stable/candidate Runtime Pack requires a signature"),
            Self::SignatureRejected { key_id, algorithm } => {
                write!(
                    formatter,
                    "Runtime Pack signature rejected for key {key_id} ({algorithm:?})"
                )
            }
            Self::ObjectCollision(digest) => write!(formatter, "content-addressed object collision at {digest}"),
            Self::ManifestCollision(digest) => write!(formatter, "content-addressed manifest collision at {digest}"),
            Self::PackNotInstalled(value) => write!(formatter, "Runtime Pack is not installed: {value}"),
            Self::NoRollbackAvailable(pack_id) => write!(formatter, "Runtime Pack {pack_id} has no rollback target"),
            Self::CorruptState(message) => write!(formatter, "Runtime Pack state is corrupt: {message}"),
            Self::Internal(message) => write!(formatter, "Runtime Pack internal error: {message}"),
        }
    }
}

impl std::error::Error for RuntimePackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for RuntimePackError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{CpuArchitecture, HostOs, RuntimeComponent, RuntimeHost};
    #[cfg(unix)]
    use compatforge_storage::JsonStore;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct AcceptAllSignatures;

    impl ManifestSignatureVerifier for AcceptAllSignatures {
        fn verify(&self, _signature: &ManifestSignature, _canonical_manifest: &[u8]) -> bool {
            true
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("compatforge-runtime-{name}-{}-{nonce}", std::process::id()))
    }

    fn write_bundle(root: &Path, artifact: &[u8], version: &str, channel: RuntimeChannel) -> RuntimePackManifest {
        fs::create_dir_all(root.join("components")).unwrap();
        fs::write(root.join("components/runtime.blob"), artifact).unwrap();
        let mut manifest = RuntimePackManifest {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: "test-runtime".into(),
            version: version.into(),
            channel: Some(channel),
            host: RuntimeHost {
                os: HostOs::Linux,
                architecture: CpuArchitecture::X86_64,
                minimum_version: None,
            },
            components: vec![RuntimeComponent {
                name: "runtime".into(),
                version: version.into(),
                license: "MIT".into(),
                source: None,
                artifact: Some("components/runtime.blob".into()),
                digest: sha256_digest_bytes(artifact),
                entrypoints: BTreeMap::from([("runtime".into(), "bin/runtime".into())]),
            }],
            capabilities: vec!["guest-x86_64".into()],
            digest: format!("sha256:{}", "0".repeat(64)),
            signature: None,
            sbom: None,
        };
        manifest.digest = sha256_digest_bytes(&manifest.canonical_unsigned_bytes().unwrap());
        manifest
    }

    #[test]
    fn sha256_matches_nist_vectors_and_streaming_boundaries() {
        assert_eq!(
            sha256_digest_bytes(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_digest_bytes(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let bytes = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_digest_bytes(&bytes),
            "sha256:cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn installs_idempotently_and_verifies_content_addressed_objects() {
        let root = temporary_directory("install");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let mut manifest = write_bundle(&bundle, b"runtime-v1", "1.0.0", RuntimeChannel::Preview);
        manifest.components[0].artifact = None;
        manifest.digest = sha256_digest_bytes(&manifest.canonical_unsigned_bytes().unwrap());

        let first = store.install(&bundle, &manifest, &RejectAllSignatures).unwrap();
        assert!(first.activated);
        assert_eq!(first.reused_objects, 0);
        let second = store.install(&bundle, &manifest, &RejectAllSignatures).unwrap();
        assert!(!second.activated);
        assert_eq!(second.reused_objects, 1);
        assert_eq!(
            store.active_digest("test-runtime").unwrap(),
            Some(manifest.digest.clone())
        );
        assert_eq!(store.verify_installed(&manifest.digest).unwrap().verified_objects, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn runtime_store_private_modes_are_independent_of_umask() {
        use std::process::Command;

        for mask in ["0000", "0002"] {
            let root = temporary_directory(&format!("umask-{mask}"));
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; export COMPATFORGE_RUNTIME_UMASK_ROOT=\"$2\"; exec \"$3\" --ignored --exact tests::runtime_store_private_mode_child --nocapture")
                .arg("compatforge-runtime-umask")
                .arg(mask)
                .arg(&root)
                .arg(std::env::current_exe().unwrap())
                .status()
                .expect("run isolated umask child");
            assert!(status.success(), "umask {mask}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore]
    fn runtime_store_private_mode_child() {
        use std::os::unix::fs::PermissionsExt;

        let root = PathBuf::from(std::env::var_os("COMPATFORGE_RUNTIME_UMASK_ROOT").expect("child root"));
        let bundle = root.join("bundle");
        let store_root = root.join("store");
        let store = RuntimePackStore::new(&store_root);
        let manifest = write_bundle(&bundle, b"private-runtime", "1.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &manifest, &RejectAllSignatures).unwrap();
        store.verified_manifest(&manifest.digest).unwrap();
        let digest_hex = manifest.components[0].digest.trim_start_matches("sha256:");
        let manifest_hex = manifest.digest.trim_start_matches("sha256:");
        for path in [
            store_root.join("objects/sha256").join(digest_hex),
            store_root.join("manifests/sha256").join(format!("{manifest_hex}.json")),
            store_root.join("refs/test-runtime/current.json"),
        ] {
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let json = JsonStore::new(root.join("json"));
        json.write("state.json", &manifest).unwrap();
        assert_eq!(
            fs::metadata(root.join("json/state.json")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fn no_temps(path: &Path) -> bool {
            fs::read_dir(path).unwrap().all(|entry| {
                let entry = entry.unwrap();
                !entry.file_name().to_string_lossy().contains(".tmp-")
                    && (!entry.path().is_dir() || no_temps(&entry.path()))
            })
        }
        assert!(no_temps(&root));
    }

    #[test]
    fn rejects_digest_mismatch_without_activating_the_pack() {
        let root = temporary_directory("mismatch");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let manifest = write_bundle(&bundle, b"expected", "1.0.0", RuntimeChannel::Preview);
        fs::write(bundle.join("components/runtime.blob"), b"tampered").unwrap();

        let error = store.install(&bundle, &manifest, &RejectAllSignatures).unwrap_err();
        assert!(matches!(error, RuntimePackError::ComponentDigestMismatch { .. }));
        assert_eq!(store.active_digest("test-runtime").unwrap(), None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_manifest_digest_mismatch_and_bundle_traversal() {
        let root = temporary_directory("manifest-mismatch");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let mut manifest = write_bundle(&bundle, b"runtime", "1.0.0", RuntimeChannel::Preview);
        manifest.version = "tampered".into();
        assert!(matches!(
            store.install(&bundle, &manifest, &RejectAllSignatures),
            Err(RuntimePackError::ManifestDigestMismatch { .. })
        ));

        manifest.version = "1.0.0".into();
        manifest.components[0].artifact = Some("../outside.blob".into());
        assert!(matches!(
            store.install(&bundle, &manifest, &RejectAllSignatures),
            Err(RuntimePackError::Contract(ContractError::UnsupportedValue(
                "runtimePack.components.artifact"
            )))
        ));
        assert_eq!(store.active_digest("test-runtime").unwrap(), None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rolls_back_only_after_reverifying_the_previous_pack() {
        let root = temporary_directory("rollback");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let first = write_bundle(&bundle, b"runtime-v1", "1.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &first, &RejectAllSignatures).unwrap();
        let second = write_bundle(&bundle, b"runtime-v2", "2.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &second, &RejectAllSignatures).unwrap();

        let receipt = store.rollback("test-runtime").unwrap();
        assert_eq!(receipt.digest, first.digest);
        assert_eq!(receipt.previous_digest, Some(second.digest));
        assert_eq!(store.active_digest("test-runtime").unwrap(), Some(receipt.digest));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_rollback_when_the_previous_object_was_tampered() {
        let root = temporary_directory("rollback-tamper");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let first = write_bundle(&bundle, b"runtime-v1", "1.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &first, &RejectAllSignatures).unwrap();
        let second = write_bundle(&bundle, b"runtime-v2", "2.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &second, &RejectAllSignatures).unwrap();

        let object = store
            .root
            .join(object_relative_path(&first.components[0].digest).unwrap());
        fs::write(object, b"tampered").unwrap();
        assert!(matches!(
            store.rollback("test-runtime"),
            Err(RuntimePackError::ComponentDigestMismatch { .. })
        ));
        assert_eq!(store.active_digest("test-runtime").unwrap(), Some(second.digest));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binds_installed_manifest_to_the_requested_digest() {
        let root = temporary_directory("manifest-swap");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let first = write_bundle(&bundle, b"runtime-v1", "1.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &first, &RejectAllSignatures).unwrap();
        let second = write_bundle(&bundle, b"runtime-v2", "2.0.0", RuntimeChannel::Preview);
        store.install(&bundle, &second, &RejectAllSignatures).unwrap();

        let first_path = store.root.join(manifest_relative_path(&first.digest).unwrap());
        let second_path = store.root.join(manifest_relative_path(&second.digest).unwrap());
        fs::copy(second_path, first_path).unwrap();

        let expected = normalized_digest(&first.digest);
        let actual = normalized_digest(&second.digest);
        assert!(matches!(
            store.verify_installed(&first.digest),
            Err(RuntimePackError::ManifestDigestMismatch {
                expected: error_expected,
                actual: error_actual,
            }) if error_expected == expected && error_actual == actual
        ));
        assert!(matches!(
            store.rollback("test-runtime"),
            Err(RuntimePackError::ManifestDigestMismatch {
                expected: error_expected,
                actual: error_actual,
            }) if error_expected == expected && error_actual == actual
        ));
        assert_eq!(store.active_digest("test-runtime").unwrap(), Some(second.digest));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsigned_release_channels_and_unverified_signatures() {
        let root = temporary_directory("signature");
        let bundle = root.join("bundle");
        let store = RuntimePackStore::new(root.join("store"));
        let mut manifest = write_bundle(&bundle, b"runtime", "1.0.0", RuntimeChannel::Stable);
        assert!(matches!(
            store.install(&bundle, &manifest, &RejectAllSignatures),
            Err(RuntimePackError::SignatureRequired)
        ));

        manifest.signature = Some(ManifestSignature {
            key_id: "release-key".into(),
            algorithm: SignatureAlgorithm::Ed25519,
            value: "test-signature".into(),
        });
        assert!(matches!(
            store.install(&bundle, &manifest, &RejectAllSignatures),
            Err(RuntimePackError::SignatureRejected { .. })
        ));
        store.install(&bundle, &manifest, &AcceptAllSignatures).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_digest_is_independent_of_semantic_array_order() {
        let root = temporary_directory("canonical");
        let bundle = root.join("bundle");
        let mut manifest = write_bundle(&bundle, b"runtime", "1.0.0", RuntimeChannel::Preview);
        let component = manifest.components[0].clone();
        let mut second = component.clone();
        second.name = "helper".into();
        second.artifact = Some("components/runtime.blob".into());
        manifest.components = vec![component, second];
        manifest.capabilities = vec!["zeta".into(), "alpha".into()];
        let left = sha256_digest_bytes(&manifest.canonical_unsigned_bytes().unwrap());
        manifest.components.reverse();
        manifest.capabilities.reverse();
        let right = sha256_digest_bytes(&manifest.canonical_unsigned_bytes().unwrap());
        assert_eq!(left, right);

        let explicit_default = manifest.canonical_unsigned_bytes().unwrap();
        manifest
            .components
            .iter_mut()
            .find(|component| component.name == "runtime")
            .unwrap()
            .artifact = None;
        let implicit_default = manifest.canonical_unsigned_bytes().unwrap();
        assert_eq!(explicit_default, implicit_default);
        fs::remove_dir_all(root).unwrap();
    }
}
