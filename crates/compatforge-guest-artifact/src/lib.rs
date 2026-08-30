//! Immutable, content-addressed storage for inspected Windows guest programs.

#![deny(unsafe_op_in_unsafe_fn)]

mod pinned_platform;

use compatforge_domain::{
    BottleExecutableBinding, ContractError, CpuArchitecture, GuestArtifactBinding, SCHEMA_VERSION_V1,
};
#[cfg(target_os = "macos")]
use compatforge_inspect::inspect_file;
use compatforge_inspect::{
    inspect_bytes, inspect_path, InspectionError, PeArchitecture, PeImageKind, PeInspectionReport, PeSubsystem,
    MAX_PE_FILE_BYTES,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub const MAX_PINNED_EVIDENCE_BYTES: u64 = 1_048_576;

#[cfg(any(target_os = "macos", test))]
const PINNED_BOTTLE_ID: &str = "gui-sumatrapdf";
#[cfg(target_os = "macos")]
const PINNED_RELATIVE_DIRECTORIES: [&str; 6] = [
    "bottles",
    PINNED_BOTTLE_ID,
    "prefix",
    "drive_c",
    "CompatForge",
    "SumatraPDF",
];
#[cfg(any(target_os = "macos", test))]
const PINNED_SOURCE_NAME: &str = "SumatraPDF.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedEvidenceKind {
    Inspection,
    Plan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedEvidenceBinding {
    pub byte_length: u64,
    pub sha256: String,
}

pub struct HeldExternalWorkRoot {
    handle: Option<pinned_platform::DirectoryHandle>,
    #[cfg(target_os = "macos")]
    reviewed_path: PathBuf,
}

impl fmt::Debug for HeldExternalWorkRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldExternalWorkRoot { .. }")
    }
}

impl HeldExternalWorkRoot {
    /// Duplicate a caller-owned inherited directory descriptor without taking
    /// ownership of the raw descriptor. A descriptor reused before validation
    /// that satisfies the complete contract is not distinguishable.
    pub fn duplicate_inherited(
        raw_fd: i32,
        reviewed_path: &Path,
        forbidden_roots: &[&Path],
    ) -> Result<Self, GuestArtifactError> {
        #[cfg(target_os = "macos")]
        if !reviewed_path.is_absolute()
            || reviewed_path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            || forbidden_roots.iter().any(|root| {
                !root.is_absolute()
                    || root
                        .components()
                        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
                    || paths_lexically_overlap(reviewed_path, root)
            })
        {
            return Err(GuestArtifactError::InvalidPinnedWorkRoot);
        }
        let handle = pinned_platform::duplicate_work_root(raw_fd, reviewed_path, forbidden_roots)
            .map_err(map_work_root_error)?;
        Ok(Self {
            handle: Some(handle),
            #[cfg(target_os = "macos")]
            reviewed_path: reviewed_path.to_owned(),
        })
    }

    pub fn create_unlinked_execution_file(&self) -> Result<File, GuestArtifactError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or(GuestArtifactError::PinnedUnsupportedPlatform)?;
        let anonymous = pinned_platform::create_unlinked(handle).map_err(map_capture_error)?;
        Ok(anonymous.into_file())
    }

    pub fn revalidate(&self) -> Result<(), GuestArtifactError> {
        self.handle
            .as_ref()
            .ok_or(GuestArtifactError::PinnedUnsupportedPlatform)?
            .revalidate()
            .map_err(map_integrity_error)
    }

    #[cfg(all(test, not(target_os = "macos")))]
    fn unsupported_test_value() -> Self {
        Self { handle: None }
    }

    #[cfg(all(test, target_os = "macos"))]
    fn create_unlinked_with_test_fault(
        &self,
        bytes: [u8; 16],
        fault: pinned_platform::CreateTestFault,
    ) -> Result<File, GuestArtifactError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or(GuestArtifactError::PinnedUnsupportedPlatform)?;
        let anonymous =
            pinned_platform::create_unlinked_with_test_fault(handle, bytes, fault).map_err(map_capture_error)?;
        Ok(anonymous.into_file())
    }

    #[cfg(all(test, target_os = "macos"))]
    fn create_unlinked_with_test_fault_counted(
        &self,
        bytes: [u8; 16],
        fault: pinned_platform::CreateTestFault,
    ) -> (Result<File, GuestArtifactError>, usize) {
        let Some(handle) = self.handle.as_ref() else {
            return (Err(GuestArtifactError::PinnedUnsupportedPlatform), 0);
        };
        let (result, attempts) = pinned_platform::create_unlinked_with_test_fault_counted(handle, bytes, fault);
        (
            result.map(|anonymous| anonymous.into_file()).map_err(map_capture_error),
            attempts,
        )
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_raw_cloexec_for_test(&self) {
        self.handle
            .as_ref()
            .expect("test work root is held")
            .clear_raw_cloexec_for_test();
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_inherited_cloexec_for_test(&self) {
        self.handle
            .as_ref()
            .expect("test work root is held")
            .clear_inherited_cloexec_for_test();
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_path_cloexec_for_test(&self) {
        self.handle
            .as_ref()
            .expect("test work root is held")
            .clear_path_cloexec_for_test();
    }

    #[cfg(target_os = "macos")]
    fn reject_overlap(&self, forbidden_roots: &[&Path]) -> Result<(), GuestArtifactError> {
        if forbidden_roots
            .iter()
            .any(|root| paths_lexically_overlap(&self.reviewed_path, root))
        {
            return Err(GuestArtifactError::InvalidPinnedWorkRoot);
        }
        self.handle
            .as_ref()
            .ok_or(GuestArtifactError::PinnedUnsupportedPlatform)?
            .reject_physical_overlap(forbidden_roots)
            .map_err(map_work_root_error)
    }
}

pub struct InheritedEvidenceFile {
    kind: PinnedEvidenceKind,
    handle: pinned_platform::EvidenceHandle,
}

impl fmt::Debug for InheritedEvidenceFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InheritedEvidenceFile")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl InheritedEvidenceFile {
    /// Duplicate a caller-owned inherited anonymous output without taking
    /// ownership of the raw descriptor. A descriptor reused before validation
    /// that satisfies the complete contract is not distinguishable.
    pub fn duplicate_inherited(raw_fd: i32, kind: PinnedEvidenceKind) -> Result<Self, GuestArtifactError> {
        let handle = pinned_platform::duplicate_evidence(raw_fd).map_err(map_evidence_error)?;
        Ok(Self { kind, handle })
    }

    pub fn ensure_distinct(&self, other: &Self) -> Result<(), GuestArtifactError> {
        if self.kind == other.kind || self.handle.same_identity(&other.handle) {
            return Err(GuestArtifactError::InvalidPinnedEvidence);
        }
        Ok(())
    }

    pub fn write_canonical(&mut self, bytes: &[u8]) -> Result<PublishedEvidenceBinding, GuestArtifactError> {
        validate_pinned_evidence_length(bytes.len() as u64)?;
        self.handle.revalidate(0).map_err(map_evidence_error)?;
        write_and_read_back_canonical(self.handle.file_mut(), bytes)?;
        self.handle
            .revalidate_after_successful_write(bytes.len() as u64)
            .map_err(map_evidence_error)?;
        Ok(PublishedEvidenceBinding {
            byte_length: bytes.len() as u64,
            sha256: digest_bytes(bytes),
        })
    }

    /// Revalidate both the caller-owned descriptor and this wrapper's owned
    /// duplicate against the exact bytes published earlier.
    pub fn revalidate_binding(&mut self, binding: &PublishedEvidenceBinding) -> Result<(), GuestArtifactError> {
        validate_pinned_evidence_length(binding.byte_length)?;
        self.handle
            .revalidate(binding.byte_length)
            .map_err(map_evidence_error)?;
        let actual = read_published_evidence_digest(self.handle.file_mut(), binding.byte_length)?;
        self.handle
            .revalidate(binding.byte_length)
            .map_err(map_evidence_error)?;
        if actual != binding.sha256 {
            return Err(GuestArtifactError::InvalidPinnedEvidence);
        }
        Ok(())
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_raw_cloexec_for_test(&self) {
        self.handle.clear_raw_cloexec_for_test();
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_owned_cloexec_for_test(&self) {
        self.handle.clear_owned_cloexec_for_test();
    }
}

pub struct PinnedBottleExecutable {
    binding: BottleExecutableBinding,
    inspection: PeInspectionReport,
    execution: pinned_platform::AnonymousFile,
    source: pinned_platform::SourceHandle,
}

impl fmt::Debug for PinnedBottleExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedBottleExecutable { .. }")
    }
}

impl PinnedBottleExecutable {
    #[must_use]
    pub fn binding(&self) -> &BottleExecutableBinding {
        &self.binding
    }

    #[must_use]
    pub fn inspection(&self) -> &PeInspectionReport {
        &self.inspection
    }

    pub fn duplicate_execution_file(&self) -> Result<File, GuestArtifactError> {
        self.execution.duplicate().map_err(map_integrity_error)
    }

    pub fn revalidate(&self) -> Result<(), GuestArtifactError> {
        self.source.revalidate().map_err(map_integrity_error)?;
        self.execution
            .revalidate(self.binding.size_bytes)
            .map_err(map_integrity_error)?;
        let source_digest = digest_open_file(
            self.source.duplicate_source().map_err(map_integrity_error)?,
            self.binding.size_bytes,
        )?;
        let execution_digest = digest_open_file(
            self.execution.duplicate().map_err(map_integrity_error)?,
            self.binding.size_bytes,
        )?;
        self.source.revalidate().map_err(map_integrity_error)?;
        self.execution
            .revalidate(self.binding.size_bytes)
            .map_err(map_integrity_error)?;
        if source_digest != self.binding.digest || execution_digest != self.binding.digest {
            return Err(GuestArtifactError::PinnedIntegrityFailure);
        }
        Ok(())
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_source_parent_cloexec_for_test(&self) {
        self.source.clear_parent_cloexec_for_test();
    }

    #[cfg(all(test, target_os = "macos"))]
    fn clear_source_cloexec_for_test(&self) {
        self.source.clear_source_cloexec_for_test();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedGuestArtifact {
    pub binding: GuestArtifactBinding,
    pub inspection: PeInspectionReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBottleExecutable {
    pub binding: BottleExecutableBinding,
    pub inspection: PeInspectionReport,
}

#[derive(Debug, Clone)]
pub struct GuestArtifactStore {
    root: PathBuf,
}

impl GuestArtifactStore {
    #[must_use]
    pub fn new(storage_root: impl AsRef<Path>) -> Self {
        Self {
            root: storage_root.as_ref().join("guest-artifacts"),
        }
    }

    /// Read an absolute regular file once, inspect those exact bytes, and
    /// publish the bytes under their SHA-256 digest.
    pub fn prepare(&self, source: &Path) -> Result<PreparedGuestArtifact, GuestArtifactError> {
        if !self.root.is_absolute() {
            return Err(GuestArtifactError::RelativeStorageRoot(self.root.clone()));
        }
        let (bytes, original_name) = read_source(source)?;
        let inspection = inspect_bytes(&bytes).map_err(GuestArtifactError::Inspection)?;
        validate_supported_inspection(&inspection)?;
        let architecture = map_architecture(inspection.architecture)?;
        let target = self.object_path(&inspection.file_digest)?;
        publish_object(&target, &bytes, &inspection.file_digest)?;

        let binding = GuestArtifactBinding {
            digest: inspection.file_digest.clone(),
            size_bytes: inspection.file_size_bytes,
            stored_path: target.to_string_lossy().into_owned(),
            original_name,
            architecture,
            image_kind: "executable".into(),
            subsystem: subsystem_name(inspection.subsystem).into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        };
        self.verify(&binding)?;
        Ok(PreparedGuestArtifact { binding, inspection })
    }

    pub fn verify(&self, binding: &GuestArtifactBinding) -> Result<(), GuestArtifactError> {
        binding.validate().map_err(GuestArtifactError::InvalidBinding)?;
        let expected = self.object_path(&binding.digest)?;
        if Path::new(&binding.stored_path) != expected {
            return Err(GuestArtifactError::UnexpectedObjectPath {
                expected,
                actual: PathBuf::from(&binding.stored_path),
            });
        }
        verify_binding_contents(binding)
    }

    /// Inspect and bind an executable in the Bottle's Wine `drive_c` tree
    /// without copying it. The complete path is checked for symlinks and the
    /// resulting digest/size is revalidated immediately before spawn.
    pub fn prepare_bottle_in_place(
        &self,
        bottle_id: &str,
        source: &Path,
    ) -> Result<PreparedBottleExecutable, GuestArtifactError> {
        let storage_root = self
            .root
            .parent()
            .ok_or_else(|| GuestArtifactError::RelativeStorageRoot(self.root.clone()))?;
        let bottle_root = storage_root
            .join("bottles")
            .join(bottle_id)
            .join("prefix")
            .join("drive_c");
        validate_bottle_path(storage_root, &bottle_root, source)?;
        let inspection = inspect_path(source).map_err(GuestArtifactError::Inspection)?;
        validate_supported_inspection(&inspection)?;
        let architecture = map_architecture(inspection.architecture)?;
        let original_name = source
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && !matches!(*name, "." | ".."))
            .ok_or_else(|| GuestArtifactError::InvalidFileName(source.to_owned()))?
            .to_owned();
        let binding = BottleExecutableBinding {
            bottle_id: bottle_id.to_owned(),
            digest: inspection.file_digest.clone(),
            size_bytes: inspection.file_size_bytes,
            path: source.to_string_lossy().into_owned(),
            original_name,
            architecture,
            image_kind: "executable".into(),
            subsystem: subsystem_name(inspection.subsystem).into(),
            inspection_schema_version: SCHEMA_VERSION_V1.into(),
        };
        verify_bottle_binding_contents(storage_root, &binding)?;
        Ok(PreparedBottleExecutable { binding, inspection })
    }

    pub fn verify_bottle(&self, binding: &BottleExecutableBinding) -> Result<(), GuestArtifactError> {
        let storage_root = self
            .root
            .parent()
            .ok_or_else(|| GuestArtifactError::RelativeStorageRoot(self.root.clone()))?;
        verify_bottle_binding_contents(storage_root, binding)
    }

    pub fn pin_sumatra_bottle_executable(
        &self,
        bottle_id: &str,
        source: &Path,
        work_root: &HeldExternalWorkRoot,
    ) -> Result<PinnedBottleExecutable, GuestArtifactError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (bottle_id, source, work_root);
            Err(GuestArtifactError::PinnedUnsupportedPlatform)
        }
        #[cfg(target_os = "macos")]
        {
            let storage_root = self.root.parent().ok_or(GuestArtifactError::InvalidPinnedContract)?;
            validate_pinned_sumatra_request(storage_root, bottle_id, source)?;
            let bottle_root = storage_root.join("bottles").join(PINNED_BOTTLE_ID);
            work_root.reject_overlap(&[storage_root, &bottle_root, source])?;
            work_root.revalidate()?;
            let work_handle = work_root
                .handle
                .as_ref()
                .ok_or(GuestArtifactError::PinnedUnsupportedPlatform)?;
            let relative_directories = PINNED_RELATIVE_DIRECTORIES
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&std::ffi::OsStr>>();
            let mut held_source = pinned_platform::open_fixed_source(
                storage_root,
                &relative_directories,
                std::ffi::OsStr::new(PINNED_SOURCE_NAME),
            )
            .map_err(map_capture_error)?;
            let source_size = held_source.source_size().map_err(map_capture_error)?;
            if source_size > MAX_PE_FILE_BYTES {
                return Err(GuestArtifactError::PinnedCaptureFailed);
            }

            // The ordinary file has already been unlinked and revalidated with
            // link count zero before this first source byte is read.
            let mut execution = pinned_platform::create_unlinked(work_handle).map_err(map_capture_error)?;
            copy_pinned_source(held_source.source_mut(), execution.file_mut(), source_size)?;
            execution.revalidate(source_size).map_err(map_capture_error)?;
            let inspection = inspect_file(execution.file_mut()).map_err(|_| GuestArtifactError::PinnedCaptureFailed)?;
            validate_supported_inspection(&inspection).map_err(|_| GuestArtifactError::PinnedCaptureFailed)?;
            if inspection.architecture != PeArchitecture::X86_64
                || inspection.subsystem != PeSubsystem::WindowsGui
                || inspection.file_size_bytes != source_size
            {
                return Err(GuestArtifactError::PinnedCaptureFailed);
            }
            execution
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(|_| GuestArtifactError::PinnedCaptureFailed)?;
            let binding = BottleExecutableBinding {
                bottle_id: PINNED_BOTTLE_ID.to_owned(),
                digest: inspection.file_digest.clone(),
                size_bytes: inspection.file_size_bytes,
                path: source
                    .to_str()
                    .ok_or(GuestArtifactError::InvalidPinnedContract)?
                    .to_owned(),
                original_name: PINNED_SOURCE_NAME.to_owned(),
                architecture: CpuArchitecture::X86_64,
                image_kind: "executable".into(),
                subsystem: "windowsGui".into(),
                inspection_schema_version: SCHEMA_VERSION_V1.into(),
            };
            binding
                .validate()
                .map_err(|_| GuestArtifactError::PinnedCaptureFailed)?;
            let pinned = PinnedBottleExecutable {
                binding,
                inspection,
                execution,
                source: held_source,
            };
            pinned.revalidate()?;
            work_root.revalidate()?;
            Ok(pinned)
        }
    }

    fn object_path(&self, digest: &str) -> Result<PathBuf, GuestArtifactError> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| GuestArtifactError::InvalidDigest(digest.into()))?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GuestArtifactError::InvalidDigest(digest.into()));
        }
        Ok(self.root.join("objects").join("sha256").join(hex.to_ascii_lowercase()))
    }
}

/// Re-hash a serialized binding immediately before a process is created.
pub fn verify_binding_contents(binding: &GuestArtifactBinding) -> Result<(), GuestArtifactError> {
    binding.validate().map_err(GuestArtifactError::InvalidBinding)?;
    let path = Path::new(&binding.stored_path);
    if !path.is_absolute() {
        return Err(GuestArtifactError::RelativeObjectPath(path.to_owned()));
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| GuestArtifactError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GuestArtifactError::NotRegularFile(path.to_owned()));
    }
    if metadata.len() != binding.size_bytes {
        return Err(GuestArtifactError::SizeMismatch {
            expected: binding.size_bytes,
            actual: metadata.len(),
        });
    }
    let actual = digest_file(path)?;
    if !actual.eq_ignore_ascii_case(&binding.digest) {
        return Err(GuestArtifactError::DigestMismatch {
            expected: binding.digest.clone(),
            actual,
        });
    }
    Ok(())
}

/// Re-hash an in-place Bottle executable immediately before a process is
/// created. This intentionally does not claim to sandbox sibling resources.
pub fn verify_bottle_binding_contents(
    storage_root: &Path,
    binding: &BottleExecutableBinding,
) -> Result<(), GuestArtifactError> {
    binding.validate().map_err(GuestArtifactError::InvalidBottleBinding)?;
    let bottle_root = storage_root
        .join("bottles")
        .join(&binding.bottle_id)
        .join("prefix")
        .join("drive_c");
    let path = Path::new(&binding.path);
    validate_bottle_path(storage_root, &bottle_root, path)?;
    verify_in_place_binding_contents(binding)
}

/// Re-hash an in-place binding without making assumptions about the storage
/// root. Policy authorization is responsible for the Bottle boundary; this
/// final check closes the symlink/race window immediately before spawn.
pub fn verify_in_place_binding_contents(binding: &BottleExecutableBinding) -> Result<(), GuestArtifactError> {
    binding.validate().map_err(GuestArtifactError::InvalidBottleBinding)?;
    let path = Path::new(&binding.path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GuestArtifactError::AmbiguousSource(path.to_owned()));
    }
    let components = path.components().collect::<Vec<_>>();
    let drive_c_index = components
        .windows(4)
        .position(|window| {
            window[0].as_os_str() == std::ffi::OsStr::new("bottles")
                && window[2].as_os_str() == std::ffi::OsStr::new("prefix")
                && window[3].as_os_str() == std::ffi::OsStr::new("drive_c")
        })
        .map(|index| index + 3)
        .ok_or_else(|| GuestArtifactError::BottlePathOutsideRoot {
            root: PathBuf::from("<bottle>/prefix/drive_c"),
            actual: path.to_owned(),
        })?;
    let mut cursor = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        cursor.push(component.as_os_str());
        if index < drive_c_index {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor).map_err(|source| GuestArtifactError::Filesystem {
            path: cursor.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(GuestArtifactError::SymbolicLink(cursor));
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| GuestArtifactError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GuestArtifactError::NotRegularFile(path.to_owned()));
    }
    if metadata.len() != binding.size_bytes {
        return Err(GuestArtifactError::SizeMismatch {
            expected: binding.size_bytes,
            actual: metadata.len(),
        });
    }
    let actual = digest_file(path)?;
    if !actual.eq_ignore_ascii_case(&binding.digest) {
        return Err(GuestArtifactError::DigestMismatch {
            expected: binding.digest.clone(),
            actual,
        });
    }
    Ok(())
}

fn validate_pinned_evidence_length(length: u64) -> Result<(), GuestArtifactError> {
    if !(1..=MAX_PINNED_EVIDENCE_BYTES).contains(&length) {
        return Err(GuestArtifactError::InvalidPinnedEvidence);
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn validate_pinned_sumatra_request(
    storage_root: &Path,
    bottle_id: &str,
    source: &Path,
) -> Result<(), GuestArtifactError> {
    if bottle_id != PINNED_BOTTLE_ID
        || !storage_root.is_absolute()
        || !source.is_absolute()
        || source.to_str().is_none()
        || storage_root.components().any(|component| {
            !matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
        || source.components().any(|component| {
            !matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
    {
        return Err(GuestArtifactError::InvalidPinnedContract);
    }
    let expected = storage_root
        .join("bottles")
        .join(PINNED_BOTTLE_ID)
        .join("prefix")
        .join("drive_c")
        .join("CompatForge")
        .join("SumatraPDF")
        .join(PINNED_SOURCE_NAME);
    if source != expected {
        return Err(GuestArtifactError::InvalidPinnedContract);
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn paths_lexically_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[cfg(any(target_os = "macos", test))]
fn pinned_staging_name(bytes: [u8; 16]) -> String {
    let mut value = String::with_capacity(54);
    value.push_str(".compatforge-pinned-");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

trait DurableIo: Read + Write + Seek {
    fn truncate_zero(&mut self) -> io::Result<()>;
    fn sync_durable(&mut self) -> io::Result<()>;
}

impl DurableIo for File {
    fn truncate_zero(&mut self) -> io::Result<()> {
        self.set_len(0)
    }

    fn sync_durable(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

#[cfg(any(target_os = "macos", test))]
fn copy_pinned_source<R: Read + Seek, W: DurableIo>(
    source: &mut R,
    execution: &mut W,
    expected_size: u64,
) -> Result<(), GuestArtifactError> {
    source
        .seek(SeekFrom::Start(0))
        .and_then(|_| execution.seek(SeekFrom::Start(0)))
        .and_then(|_| execution.truncate_zero())
        .map_err(|_| GuestArtifactError::PinnedCaptureFailed)?;
    let copied = io::copy(&mut Read::by_ref(source).take(MAX_PE_FILE_BYTES + 1), execution)
        .map_err(|_| GuestArtifactError::PinnedCaptureFailed)?;
    if copied != expected_size || copied > MAX_PE_FILE_BYTES {
        return Err(GuestArtifactError::PinnedCaptureFailed);
    }
    execution
        .sync_durable()
        .and_then(|_| execution.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|_| GuestArtifactError::PinnedCaptureFailed)
}

fn write_and_read_back_canonical<T: DurableIo>(io: &mut T, bytes: &[u8]) -> Result<(), GuestArtifactError> {
    io.seek(SeekFrom::Start(0))
        .and_then(|_| io.truncate_zero())
        .and_then(|_| io.write_all(bytes))
        .and_then(|_| io.sync_durable())
        .and_then(|_| io.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|_| GuestArtifactError::PinnedEvidenceWriteFailed)?;
    let mut readback = Vec::with_capacity(bytes.len());
    Read::by_ref(io)
        .take(MAX_PINNED_EVIDENCE_BYTES + 1)
        .read_to_end(&mut readback)
        .map_err(|_| GuestArtifactError::PinnedEvidenceWriteFailed)?;
    if readback != bytes {
        return Err(GuestArtifactError::PinnedEvidenceWriteFailed);
    }
    io.seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|_| GuestArtifactError::PinnedEvidenceWriteFailed)
}

fn read_published_evidence_digest<T: Read + Seek>(
    io: &mut T,
    expected_size: u64,
) -> Result<String, GuestArtifactError> {
    validate_pinned_evidence_length(expected_size)?;
    io.seek(SeekFrom::Start(0))
        .map_err(|_| GuestArtifactError::InvalidPinnedEvidence)?;
    let mut readback =
        Vec::with_capacity(usize::try_from(expected_size).map_err(|_| GuestArtifactError::InvalidPinnedEvidence)?);
    Read::by_ref(io)
        .take(MAX_PINNED_EVIDENCE_BYTES + 1)
        .read_to_end(&mut readback)
        .map_err(|_| GuestArtifactError::InvalidPinnedEvidence)?;
    io.seek(SeekFrom::Start(0))
        .map_err(|_| GuestArtifactError::InvalidPinnedEvidence)?;
    if readback.len() as u64 != expected_size {
        return Err(GuestArtifactError::InvalidPinnedEvidence);
    }
    Ok(digest_bytes(&readback))
}

fn digest_open_file(file: File, expected_size: u64) -> Result<String, GuestArtifactError> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::FileExt;

        digest_positioned_reader(expected_size, |buffer, offset| file.read_at(buffer, offset))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (file, expected_size);
        Err(GuestArtifactError::PinnedUnsupportedPlatform)
    }
}

#[cfg(any(test, target_os = "macos"))]
fn digest_positioned_reader(
    expected_size: u64,
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> Result<String, GuestArtifactError> {
    if expected_size > MAX_PE_FILE_BYTES {
        return Err(GuestArtifactError::PinnedIntegrityFailure);
    }
    let read_limit = expected_size + 1;
    let mut bytes = Vec::with_capacity(usize::try_from(expected_size).unwrap_or(0));
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < read_limit {
        let remaining = usize::try_from((read_limit - offset).min(buffer.len() as u64))
            .map_err(|_| GuestArtifactError::PinnedIntegrityFailure)?;
        let count =
            read_at(&mut buffer[..remaining], offset).map_err(|_| GuestArtifactError::PinnedIntegrityFailure)?;
        if count == 0 {
            break;
        }
        if count > remaining {
            return Err(GuestArtifactError::PinnedIntegrityFailure);
        }
        bytes.extend_from_slice(&buffer[..count]);
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| GuestArtifactError::PinnedIntegrityFailure)?)
            .ok_or(GuestArtifactError::PinnedIntegrityFailure)?;
    }
    if offset != expected_size {
        return Err(GuestArtifactError::PinnedIntegrityFailure);
    }
    Ok(digest_bytes(&bytes))
}

fn map_work_root_error(error: pinned_platform::PlatformError) -> GuestArtifactError {
    match error {
        pinned_platform::PlatformError::Unsupported => GuestArtifactError::PinnedUnsupportedPlatform,
        pinned_platform::PlatformError::InvalidDescriptor => GuestArtifactError::InvalidPinnedDescriptor,
        _ => GuestArtifactError::InvalidPinnedWorkRoot,
    }
}

fn map_evidence_error(error: pinned_platform::PlatformError) -> GuestArtifactError {
    match error {
        pinned_platform::PlatformError::Unsupported => GuestArtifactError::PinnedUnsupportedPlatform,
        pinned_platform::PlatformError::InvalidDescriptor => GuestArtifactError::InvalidPinnedDescriptor,
        _ => GuestArtifactError::InvalidPinnedEvidence,
    }
}

fn map_capture_error(error: pinned_platform::PlatformError) -> GuestArtifactError {
    match error {
        pinned_platform::PlatformError::Unsupported => GuestArtifactError::PinnedUnsupportedPlatform,
        pinned_platform::PlatformError::InvalidDescriptor => GuestArtifactError::InvalidPinnedDescriptor,
        _ => GuestArtifactError::PinnedCaptureFailed,
    }
}

fn map_integrity_error(error: pinned_platform::PlatformError) -> GuestArtifactError {
    match error {
        pinned_platform::PlatformError::Unsupported => GuestArtifactError::PinnedUnsupportedPlatform,
        pinned_platform::PlatformError::InvalidDescriptor => GuestArtifactError::InvalidPinnedDescriptor,
        _ => GuestArtifactError::PinnedIntegrityFailure,
    }
}

fn validate_bottle_path(storage_root: &Path, bottle_root: &Path, source: &Path) -> Result<(), GuestArtifactError> {
    if !storage_root.is_absolute() || !source.is_absolute() {
        return Err(GuestArtifactError::RelativeSource(source.to_owned()));
    }
    if source
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GuestArtifactError::AmbiguousSource(source.to_owned()));
    }
    if !source.starts_with(bottle_root) || source == bottle_root {
        return Err(GuestArtifactError::BottlePathOutsideRoot {
            root: bottle_root.to_owned(),
            actual: source.to_owned(),
        });
    }
    let storage_metadata =
        fs::symlink_metadata(storage_root).map_err(|source_error| GuestArtifactError::Filesystem {
            path: storage_root.to_owned(),
            source: source_error,
        })?;
    if storage_metadata.file_type().is_symlink() || !storage_metadata.is_dir() {
        return Err(GuestArtifactError::SymbolicLink(storage_root.to_owned()));
    }
    let relative = source
        .strip_prefix(storage_root)
        .map_err(|_| GuestArtifactError::BottlePathOutsideRoot {
            root: bottle_root.to_owned(),
            actual: source.to_owned(),
        })?;
    let mut cursor = storage_root.to_owned();
    for component in relative.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(|source_error| GuestArtifactError::Filesystem {
            path: cursor.clone(),
            source: source_error,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(GuestArtifactError::SymbolicLink(cursor));
        }
    }
    let metadata = fs::symlink_metadata(source).map_err(|source_error| GuestArtifactError::Filesystem {
        path: source.to_owned(),
        source: source_error,
    })?;
    if !metadata.is_file() {
        return Err(GuestArtifactError::NotRegularFile(source.to_owned()));
    }
    if metadata.len() > MAX_PE_FILE_BYTES {
        return Err(GuestArtifactError::FileTooLarge(metadata.len()));
    }
    Ok(())
}

fn read_source(source: &Path) -> Result<(Vec<u8>, String), GuestArtifactError> {
    if !source.is_absolute() {
        return Err(GuestArtifactError::RelativeSource(source.to_owned()));
    }
    if source
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GuestArtifactError::AmbiguousSource(source.to_owned()));
    }
    let metadata = fs::symlink_metadata(source).map_err(|error| GuestArtifactError::Filesystem {
        path: source.to_owned(),
        source: error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GuestArtifactError::NotRegularFile(source.to_owned()));
    }
    if metadata.len() > MAX_PE_FILE_BYTES {
        return Err(GuestArtifactError::FileTooLarge(metadata.len()));
    }
    let original_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !matches!(*name, "." | ".."))
        .ok_or_else(|| GuestArtifactError::InvalidFileName(source.to_owned()))?
        .to_owned();
    let mut file = File::open(source).map_err(|error| GuestArtifactError::Filesystem {
        path: source.to_owned(),
        source: error,
    })?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_PE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| GuestArtifactError::Filesystem {
            path: source.to_owned(),
            source: error,
        })?;
    if bytes.len() as u64 > MAX_PE_FILE_BYTES {
        return Err(GuestArtifactError::FileTooLarge(bytes.len() as u64));
    }
    Ok((bytes, original_name))
}

fn validate_supported_inspection(report: &PeInspectionReport) -> Result<(), GuestArtifactError> {
    if report.image_kind != PeImageKind::Executable {
        return Err(GuestArtifactError::UnsupportedImageKind(report.image_kind));
    }
    if !matches!(report.subsystem, PeSubsystem::WindowsConsole | PeSubsystem::WindowsGui) {
        return Err(GuestArtifactError::UnsupportedSubsystem(report.subsystem));
    }
    map_architecture(report.architecture).map(|_| ())
}

fn subsystem_name(subsystem: PeSubsystem) -> &'static str {
    match subsystem {
        PeSubsystem::WindowsConsole => "windowsConsole",
        PeSubsystem::WindowsGui => "windowsGui",
        _ => "unknown",
    }
}

fn map_architecture(architecture: PeArchitecture) -> Result<CpuArchitecture, GuestArtifactError> {
    match architecture {
        PeArchitecture::X86 => Ok(CpuArchitecture::I386),
        PeArchitecture::X86_64 => Ok(CpuArchitecture::X86_64),
        PeArchitecture::Arm | PeArchitecture::Arm64 => Err(GuestArtifactError::UnsupportedArchitecture(architecture)),
    }
}

fn publish_object(target: &Path, bytes: &[u8], digest: &str) -> Result<(), GuestArtifactError> {
    if target.exists() {
        return verify_existing(target, bytes.len() as u64, digest);
    }
    let parent = target.parent().expect("content object always has a parent");
    fs::create_dir_all(parent).map_err(|source| GuestArtifactError::Filesystem {
        path: parent.to_owned(),
        source,
    })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".guest-artifact-{}-{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|source| GuestArtifactError::Filesystem {
            path: temp.clone(),
            source,
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(GuestArtifactError::Filesystem { path: temp, source });
    }
    drop(file);
    match fs::rename(&temp, target) {
        Ok(()) => {
            let mut permissions = fs::metadata(target)
                .map_err(|source| GuestArtifactError::Filesystem {
                    path: target.to_owned(),
                    source,
                })?
                .permissions();
            permissions.set_readonly(true);
            fs::set_permissions(target, permissions).map_err(|source| GuestArtifactError::Filesystem {
                path: target.to_owned(),
                source,
            })?;
            verify_existing(target, bytes.len() as u64, digest)
        }
        Err(_source) if target.exists() => {
            let _ = fs::remove_file(&temp);
            verify_existing(target, bytes.len() as u64, digest)
        }
        Err(source) => {
            let _ = fs::remove_file(&temp);
            Err(GuestArtifactError::Filesystem {
                path: target.to_owned(),
                source,
            })
        }
    }
}

fn verify_existing(path: &Path, size: u64, digest: &str) -> Result<(), GuestArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| GuestArtifactError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GuestArtifactError::NotRegularFile(path.to_owned()));
    }
    if metadata.len() != size {
        return Err(GuestArtifactError::ObjectCollision(digest.into()));
    }
    if !digest_file(path)?.eq_ignore_ascii_case(digest) {
        return Err(GuestArtifactError::ObjectCollision(digest.into()));
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, GuestArtifactError> {
    let mut file = File::open(path).map_err(|source| GuestArtifactError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| GuestArtifactError::Filesystem {
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(value)
}

#[derive(Debug)]
pub enum GuestArtifactError {
    PinnedUnsupportedPlatform,
    InvalidPinnedContract,
    InvalidPinnedDescriptor,
    InvalidPinnedWorkRoot,
    InvalidPinnedEvidence,
    PinnedCaptureFailed,
    PinnedIntegrityFailure,
    PinnedEvidenceWriteFailed,
    RelativeStorageRoot(PathBuf),
    RelativeSource(PathBuf),
    AmbiguousSource(PathBuf),
    RelativeObjectPath(PathBuf),
    InvalidFileName(PathBuf),
    NotRegularFile(PathBuf),
    FileTooLarge(u64),
    InvalidDigest(String),
    InvalidBinding(ContractError),
    InvalidBottleBinding(ContractError),
    Inspection(InspectionError),
    UnsupportedArchitecture(PeArchitecture),
    UnsupportedImageKind(PeImageKind),
    UnsupportedSubsystem(PeSubsystem),
    UnexpectedObjectPath { expected: PathBuf, actual: PathBuf },
    SizeMismatch { expected: u64, actual: u64 },
    DigestMismatch { expected: String, actual: String },
    ObjectCollision(String),
    BottlePathOutsideRoot { root: PathBuf, actual: PathBuf },
    SymbolicLink(PathBuf),
    Filesystem { path: PathBuf, source: io::Error },
}

impl fmt::Display for GuestArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PinnedUnsupportedPlatform => {
                formatter.write_str("pinned Bottle execution is unsupported on this platform")
            }
            Self::InvalidPinnedContract => formatter.write_str("invalid pinned Bottle execution contract"),
            Self::InvalidPinnedDescriptor => formatter.write_str("invalid pinned inherited descriptor"),
            Self::InvalidPinnedWorkRoot => formatter.write_str("invalid pinned external work root"),
            Self::InvalidPinnedEvidence => formatter.write_str("invalid pinned evidence file"),
            Self::PinnedCaptureFailed => formatter.write_str("pinned Bottle executable capture failed"),
            Self::PinnedIntegrityFailure => formatter.write_str("pinned Bottle executable integrity failure"),
            Self::PinnedEvidenceWriteFailed => formatter.write_str("pinned evidence publication failed"),
            Self::RelativeStorageRoot(path) => write!(
                formatter,
                "guest artifact storage root must be absolute: {}",
                path.display()
            ),
            Self::RelativeSource(path) => write!(formatter, "guest source path must be absolute: {}", path.display()),
            Self::AmbiguousSource(path) => write!(
                formatter,
                "guest source path contains parent traversal: {}",
                path.display()
            ),
            Self::RelativeObjectPath(path) => {
                write!(formatter, "guest object path must be absolute: {}", path.display())
            }
            Self::InvalidFileName(path) => write!(
                formatter,
                "guest source has no valid UTF-8 file name: {}",
                path.display()
            ),
            Self::NotRegularFile(path) => write!(
                formatter,
                "guest artifact is not a regular non-symlink file: {}",
                path.display()
            ),
            Self::FileTooLarge(size) => write!(formatter, "guest artifact exceeds the inspection limit: {size} bytes"),
            Self::InvalidDigest(digest) => write!(formatter, "invalid guest artifact digest: {digest}"),
            Self::InvalidBinding(error) => write!(formatter, "invalid guest artifact binding: {error}"),
            Self::InvalidBottleBinding(error) => write!(formatter, "invalid Bottle executable binding: {error}"),
            Self::Inspection(error) => write!(formatter, "guest artifact inspection failed: {error}"),
            Self::UnsupportedArchitecture(value) => write!(formatter, "unsupported guest architecture: {value:?}"),
            Self::UnsupportedImageKind(value) => write!(formatter, "unsupported guest image kind: {value:?}"),
            Self::UnsupportedSubsystem(value) => write!(formatter, "unsupported guest subsystem: {value:?}"),
            Self::UnexpectedObjectPath { expected, actual } => write!(
                formatter,
                "guest object path mismatch: expected {}, got {}",
                expected.display(),
                actual.display()
            ),
            Self::SizeMismatch { expected, actual } => write!(
                formatter,
                "guest artifact size mismatch: expected {expected}, got {actual}"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "guest artifact digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ObjectCollision(digest) => write!(formatter, "guest artifact object collision at {digest}"),
            Self::BottlePathOutsideRoot { root, actual } => write!(
                formatter,
                "Bottle executable path {} is outside authorized drive_c root {}",
                actual.display(),
                root.display()
            ),
            Self::SymbolicLink(path) => write!(
                formatter,
                "Bottle executable path contains a symbolic link: {}",
                path.display()
            ),
            Self::Filesystem { path, source } => write!(
                formatter,
                "guest artifact filesystem error at {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for GuestArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBinding(error) | Self::InvalidBottleBinding(error) => Some(error),
            Self::Inspection(error) => Some(error),
            Self::Filesystem { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("compatforge-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hello-x86_64.exe")
            .canonicalize()
            .unwrap()
    }

    fn gui_fixture_bytes() -> Vec<u8> {
        let path = fixture();
        let mut bytes = fs::read(path).unwrap();
        // PE32+ optional header subsystem field: 0x98 + 68.
        bytes[0xdc..0xde].copy_from_slice(&2_u16.to_le_bytes());
        bytes
    }

    fn make_writable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions).unwrap();
        }
        #[cfg(windows)]
        {
            let status = std::process::Command::new("attrib")
                .arg("-R")
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[test]
    fn prepares_and_verifies_a_console_executable() {
        let root = temp_root("guest-store");
        let store = GuestArtifactStore::new(&root);
        let prepared = store.prepare(&fixture()).unwrap();
        assert_eq!(prepared.binding.architecture, CpuArchitecture::X86_64);
        assert_eq!(prepared.binding.original_name, "hello-x86_64.exe");
        assert!(Path::new(&prepared.binding.stored_path).starts_with(root.join("guest-artifacts")));
        store.verify(&prepared.binding).unwrap();
        make_writable(Path::new(&prepared.binding.stored_path));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_changes_do_not_change_the_materialized_object() {
        let root = temp_root("guest-source-change");
        let source = root.join("hello.exe");
        fs::copy(fixture(), &source).unwrap();
        let store = GuestArtifactStore::new(root.join("store"));
        let prepared = store.prepare(&source).unwrap();
        fs::write(&source, b"replaced after inspection").unwrap();
        store.verify(&prepared.binding).unwrap();
        make_writable(Path::new(&prepared.binding.stored_path));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binds_gui_executable_in_place_and_rejects_tampering_or_escape() {
        let root = temp_root("bottle-in-place");
        let storage = root.join("storage");
        let executable = storage.join("bottles/gui-test/prefix/drive_c/Program Files/Example/Example.exe");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, gui_fixture_bytes()).unwrap();
        let store = GuestArtifactStore::new(&storage);
        let prepared = store.prepare_bottle_in_place("gui-test", &executable).unwrap();
        assert_eq!(prepared.binding.subsystem, "windowsGui");
        assert_eq!(prepared.binding.path, executable.to_string_lossy());
        store.verify_bottle(&prepared.binding).unwrap();

        fs::write(&executable, b"tampered").unwrap();
        assert!(matches!(
            store.verify_bottle(&prepared.binding),
            Err(GuestArtifactError::SizeMismatch { .. }) | Err(GuestArtifactError::DigestMismatch { .. })
        ));
        let outside = root.join("outside.exe");
        fs::write(&outside, gui_fixture_bytes()).unwrap();
        let escaped = BottleExecutableBinding {
            path: outside.to_string_lossy().into_owned(),
            ..prepared.binding
        };
        assert!(matches!(
            store.verify_bottle(&escaped),
            Err(GuestArtifactError::BottlePathOutsideRoot { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_tampered_objects() {
        let root = temp_root("guest-tamper");
        let store = GuestArtifactStore::new(&root);
        let prepared = store.prepare(&fixture()).unwrap();
        let path = Path::new(&prepared.binding.stored_path);
        make_writable(path);
        fs::write(path, b"tampered").unwrap();
        assert!(matches!(
            store.verify(&prepared.binding),
            Err(GuestArtifactError::SizeMismatch { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_sources() {
        use std::os::unix::fs::symlink;
        let root = temp_root("guest-symlink");
        let source = root.join("hello.exe");
        symlink(fixture(), &source).unwrap();
        let store = GuestArtifactStore::new(root.join("store"));
        assert!(matches!(
            store.prepare(&source),
            Err(GuestArtifactError::NotRegularFile(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_evidence_contract_has_an_exact_closed_bound() {
        assert_eq!(MAX_PINNED_EVIDENCE_BYTES, 1_048_576);
        assert!(validate_pinned_evidence_length(1).is_ok());
        assert!(validate_pinned_evidence_length(MAX_PINNED_EVIDENCE_BYTES).is_ok());
        assert!(validate_pinned_evidence_length(0).is_err());
        assert!(validate_pinned_evidence_length(MAX_PINNED_EVIDENCE_BYTES + 1).is_err());
    }

    #[test]
    fn pinned_sumatra_contract_accepts_only_the_fixed_bottle_path() {
        #[cfg(windows)]
        let storage = Path::new("C:\\reviewed\\storage");
        #[cfg(not(windows))]
        let storage = Path::new("/reviewed/storage");
        let fixed = storage.join("bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe");
        assert!(validate_pinned_sumatra_request(storage, "gui-sumatrapdf", &fixed).is_ok());
        assert!(validate_pinned_sumatra_request(storage, "gui-other", &fixed).is_err());
        assert!(
            validate_pinned_sumatra_request(storage, "gui-sumatrapdf", &fixed.with_file_name("Other.exe"),).is_err()
        );
        assert!(validate_pinned_sumatra_request(
            storage,
            "gui-sumatrapdf",
            Path::new("CompatForge/SumatraPDF/SumatraPDF.exe"),
        )
        .is_err());
    }

    #[test]
    fn pinned_names_are_fixed_lowercase_hex_without_disclosing_a_path() {
        let bytes = [
            0x00, 0x01, 0x0a, 0x0f, 0x10, 0x2f, 0x30, 0x4f, 0x50, 0x6f, 0x70, 0x8f, 0x90, 0xaf, 0xf0, 0xff,
        ];
        assert_eq!(
            pinned_staging_name(bytes),
            ".compatforge-pinned-00010a0f102f304f506f708f90aff0ff"
        );
    }

    #[test]
    fn lexical_overlap_rejects_same_ancestor_and_descendant_roots() {
        let root = Path::new("/external/work");
        assert!(paths_lexically_overlap(root, root));
        assert!(paths_lexically_overlap(root, Path::new("/external/work/child")));
        assert!(paths_lexically_overlap(Path::new("/external"), root));
        assert!(!paths_lexically_overlap(root, Path::new("/external/worker")));
        assert!(!paths_lexically_overlap(root, Path::new("/other/work")));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn pinned_platform_is_rejected_before_any_path_access() {
        let inaccessible = Path::new("Z:/this/path/must/not/be/accessed");
        assert!(matches!(
            HeldExternalWorkRoot::duplicate_inherited(3, inaccessible, &[inaccessible]),
            Err(GuestArtifactError::PinnedUnsupportedPlatform)
        ));
        let store = GuestArtifactStore::new("relative-storage-that-must-not-be-accessed");
        assert!(matches!(
            store.pin_sumatra_bottle_executable(
                "gui-sumatrapdf",
                inaccessible,
                &HeldExternalWorkRoot::unsupported_test_value(),
            ),
            Err(GuestArtifactError::PinnedUnsupportedPlatform)
        ));
    }

    struct InjectedDurableIo {
        cursor: io::Cursor<Vec<u8>>,
        fail_truncate: bool,
        fail_sync: bool,
        fail_seek_call: Option<usize>,
        seek_calls: usize,
        stop_writing_after: Option<usize>,
        written: usize,
        corrupt_on_sync: bool,
    }

    impl InjectedDurableIo {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                cursor: io::Cursor::new(bytes),
                fail_truncate: false,
                fail_sync: false,
                fail_seek_call: None,
                seek_calls: 0,
                stop_writing_after: None,
                written: 0,
                corrupt_on_sync: false,
            }
        }
    }

    impl Read for InjectedDurableIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.cursor.read(buffer)
        }
    }

    impl Write for InjectedDurableIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Some(limit) = self.stop_writing_after {
                if self.written >= limit {
                    return Ok(0);
                }
                let count = buffer.len().min(limit - self.written);
                let written = self.cursor.write(&buffer[..count])?;
                self.written += written;
                Ok(written)
            } else {
                let written = self.cursor.write(buffer)?;
                self.written += written;
                Ok(written)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Seek for InjectedDurableIo {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.seek_calls += 1;
            if self.fail_seek_call == Some(self.seek_calls) {
                return Err(io::Error::other("injected seek failure"));
            }
            self.cursor.seek(position)
        }
    }

    impl DurableIo for InjectedDurableIo {
        fn truncate_zero(&mut self) -> io::Result<()> {
            if self.fail_truncate {
                return Err(io::Error::other("injected truncate failure"));
            }
            self.cursor.get_mut().clear();
            Ok(())
        }

        fn sync_durable(&mut self) -> io::Result<()> {
            if self.fail_sync {
                return Err(io::Error::other("injected sync failure"));
            }
            if self.corrupt_on_sync {
                if let Some(first) = self.cursor.get_mut().first_mut() {
                    *first ^= 1;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn pinned_capture_injections_reject_short_copy_write_sync_and_rewind() {
        let mut exact_source = io::Cursor::new(b"abcd".to_vec());
        let mut exact_execution = InjectedDurableIo::new(b"stale".to_vec());
        copy_pinned_source(&mut exact_source, &mut exact_execution, 4).unwrap();
        assert_eq!(exact_execution.cursor.get_ref(), b"abcd");
        assert_eq!(exact_execution.cursor.position(), 0);

        let mut short_source = io::Cursor::new(b"abc".to_vec());
        assert!(matches!(
            copy_pinned_source(&mut short_source, &mut InjectedDurableIo::new(Vec::new()), 4),
            Err(GuestArtifactError::PinnedCaptureFailed)
        ));

        let mut source = io::Cursor::new(b"abcd".to_vec());
        let mut short_write = InjectedDurableIo::new(Vec::new());
        short_write.stop_writing_after = Some(2);
        assert!(matches!(
            copy_pinned_source(&mut source, &mut short_write, 4),
            Err(GuestArtifactError::PinnedCaptureFailed)
        ));

        let mut source = io::Cursor::new(b"abcd".to_vec());
        let mut sync_failure = InjectedDurableIo::new(Vec::new());
        sync_failure.fail_sync = true;
        assert!(matches!(
            copy_pinned_source(&mut source, &mut sync_failure, 4),
            Err(GuestArtifactError::PinnedCaptureFailed)
        ));

        let mut source = io::Cursor::new(b"abcd".to_vec());
        let mut rewind_failure = InjectedDurableIo::new(Vec::new());
        rewind_failure.fail_seek_call = Some(2);
        assert!(matches!(
            copy_pinned_source(&mut source, &mut rewind_failure, 4),
            Err(GuestArtifactError::PinnedCaptureFailed)
        ));
    }

    #[test]
    fn pinned_evidence_injections_reject_truncate_write_sync_rewind_and_readback() {
        let bytes = br#"{"recordType":"test"}"#;
        let mut exact = InjectedDurableIo::new(b"stale bytes".to_vec());
        exact.cursor.set_position(5);
        write_and_read_back_canonical(&mut exact, bytes).unwrap();
        assert_eq!(exact.cursor.get_ref(), bytes);
        assert_eq!(exact.cursor.position(), 0);

        let mut truncate_failure = InjectedDurableIo::new(Vec::new());
        truncate_failure.fail_truncate = true;
        assert!(write_and_read_back_canonical(&mut truncate_failure, bytes).is_err());

        let mut short_write = InjectedDurableIo::new(Vec::new());
        short_write.stop_writing_after = Some(2);
        assert!(write_and_read_back_canonical(&mut short_write, bytes).is_err());

        let mut sync_failure = InjectedDurableIo::new(Vec::new());
        sync_failure.fail_sync = true;
        assert!(write_and_read_back_canonical(&mut sync_failure, bytes).is_err());

        let mut rewind_failure = InjectedDurableIo::new(Vec::new());
        rewind_failure.fail_seek_call = Some(2);
        assert!(write_and_read_back_canonical(&mut rewind_failure, bytes).is_err());

        let mut corrupt_readback = InjectedDurableIo::new(Vec::new());
        corrupt_readback.corrupt_on_sync = true;
        assert!(write_and_read_back_canonical(&mut corrupt_readback, bytes).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_digest_revalidation_preserves_a_shared_file_offset() {
        let root = temp_root("pinned-positioned-digest");
        let path = root.join("execution.bin");
        let bytes = (0_u8..64).collect::<Vec<_>>();
        fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        let mut shared = file.try_clone().unwrap();
        shared.seek(SeekFrom::Start(17)).unwrap();

        assert_eq!(
            digest_open_file(file, bytes.len() as u64).unwrap(),
            digest_bytes(&bytes)
        );
        assert_eq!(shared.stream_position().unwrap(), 17);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn positioned_digest_loops_over_short_reads_and_requires_exact_eof() {
        fn read_chunk(data: &[u8], buffer: &mut [u8], offset: u64) -> io::Result<usize> {
            let offset = usize::try_from(offset).unwrap();
            if offset >= data.len() {
                return Ok(0);
            }
            let count = (data.len() - offset).min(buffer.len()).min(2);
            buffer[..count].copy_from_slice(&data[offset..offset + count]);
            Ok(count)
        }

        let exact = b"abcdef";
        let mut offsets = Vec::new();
        let digest = digest_positioned_reader(exact.len() as u64, |buffer, offset| {
            offsets.push(offset);
            read_chunk(exact, buffer, offset)
        })
        .unwrap();
        assert_eq!(digest, digest_bytes(exact));
        assert_eq!(offsets, [0, 2, 4, 6]);

        assert!(matches!(
            digest_positioned_reader(7, |buffer, offset| read_chunk(exact, buffer, offset)),
            Err(GuestArtifactError::PinnedIntegrityFailure)
        ));
        assert!(matches!(
            digest_positioned_reader(5, |buffer, offset| read_chunk(exact, buffer, offset)),
            Err(GuestArtifactError::PinnedIntegrityFailure)
        ));
        assert!(matches!(
            digest_positioned_reader(MAX_PE_FILE_BYTES + 1, |_buffer, _offset| {
                panic!("oversize input must be rejected before reading")
            }),
            Err(GuestArtifactError::PinnedIntegrityFailure)
        ));
        assert!(matches!(
            digest_positioned_reader(1, |_buffer, _offset| Err(io::Error::other("injected read failure"))),
            Err(GuestArtifactError::PinnedIntegrityFailure)
        ));
    }

    #[test]
    fn positioned_digest_exposes_changed_bytes_to_the_digest_binding() {
        let stable = b"abcdef";
        let changed = b"abXdef";
        let observed = digest_positioned_reader(stable.len() as u64, |buffer, offset| {
            let offset = usize::try_from(offset).unwrap();
            if offset >= stable.len() {
                return Ok(0);
            }
            let data = if offset == 0 {
                stable.as_slice()
            } else {
                changed.as_slice()
            };
            let count = (data.len() - offset).min(buffer.len()).min(2);
            buffer[..count].copy_from_slice(&data[offset..offset + count]);
            Ok(count)
        })
        .unwrap();

        assert_ne!(observed, digest_bytes(stable));
        assert_eq!(observed, digest_bytes(b"abXdef"));
    }

    #[cfg(target_os = "macos")]
    mod pinned_macos {
        use super::*;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        use std::sync::{Mutex, MutexGuard};

        static PINNED_MACOS_TEST_LOCK: Mutex<()> = Mutex::new(());

        struct Context {
            _serial: MutexGuard<'static, ()>,
            root: PathBuf,
            storage: PathBuf,
            source: PathBuf,
            work: PathBuf,
        }

        fn context(label: &str) -> Context {
            let serial = PINNED_MACOS_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let root = temp_root(label);
            let storage = root.join("storage");
            let source = storage.join("bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe");
            let work = root.join("external-work");
            fs::create_dir_all(source.parent().unwrap()).unwrap();
            fs::create_dir(&work).unwrap();
            fs::write(&source, gui_fixture_bytes()).unwrap();
            Context {
                _serial: serial,
                root,
                storage,
                source,
                work,
            }
        }

        fn held_work(context: &Context) -> (File, HeldExternalWorkRoot) {
            let raw = File::open(&context.work).unwrap();
            let held = HeldExternalWorkRoot::duplicate_inherited(
                raw.as_raw_fd(),
                &context.work,
                &[&context.storage, &context.source],
            )
            .unwrap();
            assert!(pinned_platform::descriptor_is_cloexec(raw.as_raw_fd()));
            (raw, held)
        }

        fn create_output(root: &Path, label: &str) -> (PathBuf, File) {
            let path = root.join(format!("{label}.json"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC)
                .open(&path)
                .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            (path, file)
        }

        #[test]
        fn captures_the_fixed_source_into_an_unlinked_lease_and_revalidates_it() {
            let context = context("pinned-capture");
            let (_raw_work, work) = held_work(&context);
            let store = GuestArtifactStore::new(&context.storage);
            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            assert_eq!(pinned.binding().bottle_id, PINNED_BOTTLE_ID);
            assert_eq!(pinned.binding().path, context.source.to_string_lossy());
            assert_eq!(pinned.binding().digest, pinned.inspection().file_digest);
            let execution = pinned.duplicate_execution_file().unwrap();
            let metadata = execution.metadata().unwrap();
            assert_eq!(metadata.nlink(), 0);
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert!(pinned_platform::descriptor_is_cloexec(execution.as_raw_fd()));
            pinned.revalidate().unwrap();
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn full_pinned_revalidation_does_not_move_the_shared_execution_offset() {
            let context = context("pinned-revalidate-offset");
            let (_raw_work, work) = held_work(&context);
            let pinned = GuestArtifactStore::new(&context.storage)
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            let mut execution = pinned.duplicate_execution_file().unwrap();
            execution.seek(SeekFrom::Start(17)).unwrap();

            pinned.revalidate().unwrap();

            assert_eq!(execution.stream_position().unwrap(), 17);
            drop(execution);
            drop(pinned);
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn rejects_symlink_and_hardlink_source_entries() {
            use std::os::unix::fs::symlink;

            let context = context("pinned-source-links");
            let (_raw_work, work) = held_work(&context);
            let store = GuestArtifactStore::new(&context.storage);
            let hardlink = context.root.join("source-hardlink.exe");
            fs::hard_link(&context.source, &hardlink).unwrap();
            assert!(matches!(
                store.pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work),
                Err(GuestArtifactError::PinnedCaptureFailed)
            ));
            fs::remove_file(&hardlink).unwrap();
            let bytes = fs::read(&context.source).unwrap();
            fs::remove_file(&context.source).unwrap();
            let target = context.root.join("symlink-target.exe");
            fs::write(&target, bytes).unwrap();
            symlink(&target, &context.source).unwrap();
            assert!(matches!(
                store.pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work),
                Err(GuestArtifactError::InvalidPinnedWorkRoot)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn rejects_inspection_failure_after_unlinked_capture() {
            let context = context("pinned-inspection-failure");
            fs::write(&context.source, b"not a PE image").unwrap();
            let (_raw_work, work) = held_work(&context);
            let store = GuestArtifactStore::new(&context.storage);
            assert!(matches!(
                store.pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work),
                Err(GuestArtifactError::PinnedCaptureFailed)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn detects_source_content_entry_and_ancestor_substitution() {
            let context = context("pinned-source-drift");
            let (_raw_work, work) = held_work(&context);
            let store = GuestArtifactStore::new(&context.storage);
            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            let mut bytes = fs::read(&context.source).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            fs::write(&context.source, &bytes).unwrap();
            assert!(matches!(
                pinned.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            drop(pinned);

            fs::write(&context.source, gui_fixture_bytes()).unwrap();
            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            let compatforge = context
                .storage
                .join("bottles/gui-sumatrapdf/prefix/drive_c/CompatForge");
            let moved = compatforge.with_file_name("CompatForge-moved");
            fs::rename(&compatforge, &moved).unwrap();
            fs::create_dir_all(context.source.parent().unwrap()).unwrap();
            fs::write(&context.source, gui_fixture_bytes()).unwrap();
            assert!(matches!(
                pinned.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn detects_work_root_substitution_and_rejects_overlap() {
            let context = context("pinned-work-drift");
            let raw = File::open(&context.work).unwrap();
            assert!(matches!(
                HeldExternalWorkRoot::duplicate_inherited(raw.as_raw_fd(), &context.work, &[&context.work]),
                Err(GuestArtifactError::InvalidPinnedWorkRoot)
            ));
            let held = HeldExternalWorkRoot::duplicate_inherited(
                raw.as_raw_fd(),
                &context.work,
                &[&context.storage, &context.source],
            )
            .unwrap();
            let moved = context.work.with_file_name("external-work-moved");
            fs::rename(&context.work, &moved).unwrap();
            fs::create_dir(&context.work).unwrap();
            assert!(matches!(
                held.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn full_directory_metadata_and_cloexec_drift_are_rejected() {
            let context = context("pinned-directory-metadata-drift");
            let (_raw_work, work) = held_work(&context);
            let original_mode = fs::metadata(&context.work).unwrap().permissions().mode();
            fs::set_permissions(&context.work, fs::Permissions::from_mode(original_mode ^ 0o100)).unwrap();
            assert!(matches!(
                work.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            fs::set_permissions(&context.work, fs::Permissions::from_mode(original_mode)).unwrap();

            let (_raw_work, work) = held_work(&context);
            work.clear_raw_cloexec_for_test();
            assert!(matches!(
                work.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));

            let (_raw_work, work) = held_work(&context);
            work.clear_inherited_cloexec_for_test();
            assert!(matches!(
                work.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));

            let (_raw_work, work) = held_work(&context);
            work.clear_path_cloexec_for_test();
            assert!(matches!(
                work.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn source_parent_metadata_and_held_fd_cloexec_drift_are_rejected() {
            let context = context("pinned-source-parent-drift");
            let (_raw_work, work) = held_work(&context);
            let store = GuestArtifactStore::new(&context.storage);
            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            let source_parent = context.source.parent().unwrap();
            let original_mode = fs::metadata(source_parent).unwrap().permissions().mode();
            fs::set_permissions(source_parent, fs::Permissions::from_mode(original_mode ^ 0o100)).unwrap();
            assert!(matches!(
                pinned.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            fs::set_permissions(source_parent, fs::Permissions::from_mode(original_mode)).unwrap();
            drop(pinned);

            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            let sibling = source_parent.join("sibling.tmp");
            fs::write(&sibling, b"metadata drift").unwrap();
            assert!(matches!(
                pinned.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            drop(pinned);
            fs::remove_file(&sibling).unwrap();

            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            pinned.clear_source_parent_cloexec_for_test();
            assert!(matches!(
                pinned.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            drop(pinned);

            let pinned = store
                .pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &context.source, &work)
                .unwrap();
            pinned.clear_source_cloexec_for_test();
            assert!(matches!(
                pinned.revalidate(),
                Err(GuestArtifactError::PinnedIntegrityFailure)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn evidence_is_unlinked_distinct_bounded_and_offset_independent() {
            let context = context("pinned-evidence");
            let (inspection_path, mut inspection_raw) = create_output(&context.work, "inspection");
            let (plan_path, plan_raw) = create_output(&context.work, "plan");
            fs::remove_file(&inspection_path).unwrap();
            fs::remove_file(&plan_path).unwrap();
            inspection_raw.seek(SeekFrom::Start(7)).unwrap();
            let mut inspection =
                InheritedEvidenceFile::duplicate_inherited(inspection_raw.as_raw_fd(), PinnedEvidenceKind::Inspection)
                    .unwrap();
            let plan =
                InheritedEvidenceFile::duplicate_inherited(plan_raw.as_raw_fd(), PinnedEvidenceKind::Plan).unwrap();
            assert!(pinned_platform::descriptor_is_cloexec(inspection_raw.as_raw_fd()));
            assert!(pinned_platform::descriptor_is_cloexec(plan_raw.as_raw_fd()));
            inspection.ensure_distinct(&plan).unwrap();
            let bytes = vec![b'x'; MAX_PINNED_EVIDENCE_BYTES as usize];
            let binding = inspection.write_canonical(&bytes).unwrap();
            assert_eq!(binding.byte_length, MAX_PINNED_EVIDENCE_BYTES);
            assert_eq!(binding.sha256, digest_bytes(&bytes));
            assert!(matches!(
                inspection.write_canonical(&vec![b'x'; MAX_PINNED_EVIDENCE_BYTES as usize + 1]),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));
            assert_eq!(inspection_raw.metadata().unwrap().nlink(), 0);
            inspection_raw.seek(SeekFrom::Start(0)).unwrap();
            let mut readback = Vec::new();
            inspection_raw.read_to_end(&mut readback).unwrap();
            assert_eq!(readback, bytes);
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn evidence_rejects_alias_link_size_mode_and_status_flag_mutants() {
            let context = context("pinned-evidence-mutants");
            let (alias_path, alias_raw) = create_output(&context.work, "alias");
            fs::remove_file(&alias_path).unwrap();
            let inspection =
                InheritedEvidenceFile::duplicate_inherited(alias_raw.as_raw_fd(), PinnedEvidenceKind::Inspection)
                    .unwrap();
            let alias =
                InheritedEvidenceFile::duplicate_inherited(alias_raw.as_raw_fd(), PinnedEvidenceKind::Plan).unwrap();
            assert!(matches!(
                inspection.ensure_distinct(&alias),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));

            let (linked_path, linked) = create_output(&context.work, "linked");
            assert!(matches!(
                InheritedEvidenceFile::duplicate_inherited(linked.as_raw_fd(), PinnedEvidenceKind::Plan),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));
            fs::remove_file(linked_path).unwrap();

            let (nonempty_path, mut nonempty) = create_output(&context.work, "nonempty");
            nonempty.write_all(b"x").unwrap();
            fs::remove_file(nonempty_path).unwrap();
            assert!(matches!(
                InheritedEvidenceFile::duplicate_inherited(nonempty.as_raw_fd(), PinnedEvidenceKind::Plan),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));

            let (mode_path, mode) = create_output(&context.work, "mode");
            fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o640)).unwrap();
            fs::remove_file(mode_path).unwrap();
            assert!(matches!(
                InheritedEvidenceFile::duplicate_inherited(mode.as_raw_fd(), PinnedEvidenceKind::Plan),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));

            for (label, read, write, append) in [
                ("read-only", true, false, false),
                ("write-only", false, true, false),
                ("append", true, false, true),
            ] {
                let path = context.work.join(label);
                fs::write(&path, b"").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                let file = OpenOptions::new()
                    .read(read)
                    .write(write)
                    .append(append)
                    .custom_flags(libc::O_CLOEXEC)
                    .open(&path)
                    .unwrap();
                fs::remove_file(&path).unwrap();
                assert!(matches!(
                    InheritedEvidenceFile::duplicate_inherited(file.as_raw_fd(), PinnedEvidenceKind::Plan),
                    Err(GuestArtifactError::InvalidPinnedEvidence)
                ));
            }
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn inherited_wrappers_reject_stdio_closed_and_wrong_descriptor_kinds() {
            let context = context("pinned-descriptor-mutants");
            assert!(InheritedEvidenceFile::duplicate_inherited(0, PinnedEvidenceKind::Inspection).is_err());
            assert!(HeldExternalWorkRoot::duplicate_inherited(1, &context.work, &[&context.storage]).is_err());

            let closed = File::open(&context.source).unwrap();
            let closed_fd = closed.as_raw_fd();
            drop(closed);
            assert!(InheritedEvidenceFile::duplicate_inherited(closed_fd, PinnedEvidenceKind::Plan).is_err());

            let directory = File::open(&context.work).unwrap();
            assert!(
                InheritedEvidenceFile::duplicate_inherited(directory.as_raw_fd(), PinnedEvidenceKind::Inspection,)
                    .is_err()
            );
            let regular = File::open(&context.source).unwrap();
            assert!(
                HeldExternalWorkRoot::duplicate_inherited(regular.as_raw_fd(), &context.work, &[&context.storage],)
                    .is_err()
            );
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn evidence_raw_and_duplicate_cloexec_drift_are_rejected() {
            let context = context("pinned-evidence-cloexec-drift");
            let (raw_path, raw) = create_output(&context.work, "raw-cloexec");
            fs::remove_file(raw_path).unwrap();
            let mut evidence =
                InheritedEvidenceFile::duplicate_inherited(raw.as_raw_fd(), PinnedEvidenceKind::Inspection).unwrap();
            evidence.clear_raw_cloexec_for_test();
            assert!(matches!(
                evidence.write_canonical(b"{}"),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));

            let (owned_path, owned) = create_output(&context.work, "owned-cloexec");
            fs::remove_file(owned_path).unwrap();
            let mut evidence =
                InheritedEvidenceFile::duplicate_inherited(owned.as_raw_fd(), PinnedEvidenceKind::Plan).unwrap();
            evidence.clear_owned_cloexec_for_test();
            assert!(matches!(
                evidence.write_canonical(b"{}"),
                Err(GuestArtifactError::InvalidPinnedEvidence)
            ));
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn published_evidence_revalidation_rejects_each_raw_and_owned_cloexec_drift() {
            let context = context("pinned-published-evidence-cloexec-drift");
            for (label, kind, clear_owned) in [
                ("inspection-raw", PinnedEvidenceKind::Inspection, false),
                ("inspection-owned", PinnedEvidenceKind::Inspection, true),
                ("plan-raw", PinnedEvidenceKind::Plan, false),
                ("plan-owned", PinnedEvidenceKind::Plan, true),
            ] {
                let (path, raw) = create_output(&context.work, label);
                fs::remove_file(path).unwrap();
                let mut evidence = InheritedEvidenceFile::duplicate_inherited(raw.as_raw_fd(), kind).unwrap();
                let binding = evidence.write_canonical(b"{\"schemaVersion\":1}").unwrap();
                if clear_owned {
                    evidence.clear_owned_cloexec_for_test();
                } else {
                    evidence.clear_raw_cloexec_for_test();
                }
                assert!(matches!(
                    evidence.revalidate_binding(&binding),
                    Err(GuestArtifactError::InvalidPinnedEvidence)
                ));
            }
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn fifo_leaf_and_forbidden_root_reject_within_a_bound() {
            use std::sync::mpsc;
            use std::time::Duration;

            assert!(pinned_platform::leaf_open_flags_are_nonblocking_for_test());
            let context = context("pinned-fifo-bound");
            let fifo = context.root.join("forbidden.fifo");
            assert!(std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success());
            let raw_work = File::open(&context.work).unwrap();
            let raw_fd = raw_work.as_raw_fd();
            let reviewed = context.work.clone();
            let forbidden = fifo.clone();
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result = HeldExternalWorkRoot::duplicate_inherited(raw_fd, &reviewed, &[&forbidden]);
                sender.send((result.is_err(), raw_work)).unwrap();
            });
            assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap().0);

            let raw_work = File::open(&context.work).unwrap();
            let held =
                HeldExternalWorkRoot::duplicate_inherited(raw_work.as_raw_fd(), &context.work, &[&context.storage])
                    .unwrap();
            fs::remove_file(&context.source).unwrap();
            assert!(std::process::Command::new("/usr/bin/mkfifo")
                .arg(&context.source)
                .status()
                .unwrap()
                .success());
            let store = GuestArtifactStore::new(&context.storage);
            let source = context.source.clone();
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result = store.pin_sumatra_bottle_executable(PINNED_BOTTLE_ID, &source, &held);
                sender.send((result.is_err(), raw_work)).unwrap();
            });
            assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap().0);
            fs::remove_dir_all(context.root).unwrap();
        }

        #[test]
        fn ordinary_file_trust_boundary_does_not_claim_acl_capable_window_protection() {
            // This assertion is deliberately narrow: the inode is mode 0600,
            // single-link before unlink, and zero-link afterwards. It does not
            // claim protection from a directory-search-capable principal that
            // opens the random name between successful openat and unlinkat.
            let context = context("pinned-trust-boundary");
            let random = [0x7a; 16];
            let staging_path = context.work.join(pinned_staging_name(random));
            fs::write(&staging_path, b"").unwrap();
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o600)).unwrap();
            let collision_before = fs::metadata(&staging_path).unwrap();
            let (_raw_work, work) = held_work(&context);
            let (collision_result, attempts) =
                work.create_unlinked_with_test_fault_counted(random, pinned_platform::CreateTestFault::None);
            assert!(matches!(collision_result, Err(GuestArtifactError::PinnedCaptureFailed)));
            assert_eq!(attempts, 16);
            let collision_after = fs::metadata(&staging_path).unwrap();
            assert_eq!(collision_after.ino(), collision_before.ino());
            assert_eq!(collision_after.len(), 0);
            assert_eq!(collision_after.mode() & 0o777, 0o600);
            fs::remove_file(&staging_path).unwrap();
            for fault in [
                pinned_platform::CreateTestFault::NonzeroBeforeInitialCheck,
                pinned_platform::CreateTestFault::RemoveBeforeUnlink,
                pinned_platform::CreateTestFault::NonzeroAfterUnlink,
            ] {
                let (_raw_fault_work, fault_work) = held_work(&context);
                assert!(matches!(
                    fault_work.create_unlinked_with_test_fault(random, fault),
                    Err(GuestArtifactError::PinnedCaptureFailed)
                ));
                if staging_path.exists() {
                    fs::remove_file(&staging_path).unwrap();
                }
            }
            let (_raw_final_work, final_work) = held_work(&context);
            let file = final_work
                .create_unlinked_with_test_fault(random, pinned_platform::CreateTestFault::None)
                .unwrap();
            let metadata = file.metadata().unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 0);
            assert_eq!(metadata.len(), 0);
            assert!(matches!(File::open(&staging_path), Err(error) if error.kind() == io::ErrorKind::NotFound));
            fs::remove_dir_all(context.root).unwrap();
        }
    }
}
