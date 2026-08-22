//! Audited descriptor and `openat` boundary for pinned macOS execution.
//!
//! The ordinary staging name exists only between `openat(O_EXCL)` and the
//! immediately following `unlinkat`. This does not claim protection against a
//! directory-search-capable principal that opens that name during that window.

use std::fs::File;
use std::path::Path;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformError {
    #[allow(dead_code)]
    Unsupported,
    InvalidDescriptor,
    InvalidWorkRoot,
    InvalidEvidence,
    Capture,
    Integrity,
}

#[cfg(any(target_os = "macos", test))]
const MAX_CREATE_ATTEMPTS: usize = 16;
#[cfg(any(target_os = "macos", test))]
const REGULAR_FILE_KIND: u32 = 0o100000;

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    kind: u32,
    mode: u32,
    links: u64,
    owner: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(any(target_os = "macos", test))]
fn full_identity_and_cloexec_match(expected: MetadataSnapshot, actual: MetadataSnapshot, cloexec: bool) -> bool {
    cloexec && expected == actual
}

#[cfg(any(target_os = "macos", test))]
fn valid_initial_staging_snapshot(snapshot: MetadataSnapshot, effective_user: u64) -> bool {
    snapshot.kind == REGULAR_FILE_KIND
        && snapshot.owner == effective_user
        && snapshot.mode & 0o777 == 0o600
        && snapshot.links == 1
        && snapshot.size == 0
}

#[cfg(any(target_os = "macos", test))]
enum CreateAttemptError {
    Collision,
    Fatal(PlatformError),
}

#[cfg(any(target_os = "macos", test))]
fn retry_exclusive_create<T, F>(mut attempt: F) -> Result<T, PlatformError>
where
    F: FnMut() -> Result<T, CreateAttemptError>,
{
    for _ in 0..MAX_CREATE_ATTEMPTS {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(CreateAttemptError::Collision) => {}
            Err(CreateAttemptError::Fatal(error)) => return Err(error),
        }
    }
    Err(PlatformError::Capture)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{
        full_identity_and_cloexec_match, retry_exclusive_create, valid_initial_staging_snapshot, CreateAttemptError,
        File, MetadataSnapshot, Path, PlatformError,
    };
    use std::cell::Cell;
    use std::ffi::{CStr, CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Identity {
        device: libc::dev_t,
        inode: libc::ino_t,
        mode: libc::mode_t,
        links: libc::nlink_t,
        owner: libc::uid_t,
        size: libc::off_t,
        modified_seconds: libc::time_t,
        modified_nanoseconds: libc::c_long,
        changed_seconds: libc::time_t,
        changed_nanoseconds: libc::c_long,
    }

    impl Identity {
        fn snapshot(self) -> MetadataSnapshot {
            MetadataSnapshot {
                device: self.device as u64,
                inode: self.inode,
                kind: u32::from(self.mode & libc::S_IFMT),
                mode: u32::from(self.mode),
                links: u64::from(self.links),
                owner: u64::from(self.owner),
                size: self.size,
                modified_seconds: self.modified_seconds,
                modified_nanoseconds: self.modified_nanoseconds,
                changed_seconds: self.changed_seconds,
                changed_nanoseconds: self.changed_nanoseconds,
            }
        }

        fn same_object(self, other: Self) -> bool {
            self.device == other.device
                && self.inode == other.inode
                && (self.mode & libc::S_IFMT) == (other.mode & libc::S_IFMT)
        }

        fn is_directory(self) -> bool {
            self.mode & libc::S_IFMT == libc::S_IFDIR
        }

        fn is_regular(self) -> bool {
            self.mode & libc::S_IFMT == libc::S_IFREG
        }

        fn permissions(self) -> libc::mode_t {
            self.mode & 0o777
        }
    }

    struct ChainEntry {
        file: File,
        identity: Cell<Identity>,
        name_from_parent: Option<CString>,
        full_identity: bool,
    }

    pub(crate) struct DirectoryHandle {
        raw_fd: RawFd,
        inherited: File,
        identity: Cell<Identity>,
        path_chain: Vec<ChainEntry>,
    }

    pub(crate) struct EvidenceHandle {
        raw_fd: RawFd,
        file: File,
        identity: Cell<Identity>,
    }

    pub(crate) struct SourceHandle {
        directories: Vec<ChainEntry>,
        source: File,
        source_identity: Identity,
        source_name: CString,
    }

    pub(crate) struct AnonymousFile {
        file: File,
        identity: Identity,
    }

    pub(crate) fn effective_user() -> libc::uid_t {
        // SAFETY: `geteuid` takes no arguments and has no failure mode.
        unsafe { libc::geteuid() }
    }

    fn last_os_error() -> io::Error {
        io::Error::last_os_error()
    }

    fn c_string(value: &OsStr) -> Result<CString, PlatformError> {
        CString::new(value.as_bytes()).map_err(|_| PlatformError::Integrity)
    }

    fn fstat_fd(fd: RawFd) -> Result<Identity, PlatformError> {
        let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `value` points to writable storage for one `stat`, and `fd`
        // is only inspected; success initializes the complete structure.
        if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
            return Err(PlatformError::InvalidDescriptor);
        }
        // SAFETY: the successful `fstat` above initialized `value`.
        let value = unsafe { value.assume_init() };
        Ok(Identity {
            device: value.st_dev,
            inode: value.st_ino,
            mode: value.st_mode,
            links: value.st_nlink,
            owner: value.st_uid,
            size: value.st_size,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: value.st_mtime_nsec,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: value.st_ctime_nsec,
        })
    }

    fn fstat_entry(parent: RawFd, name: &CStr) -> Result<Identity, PlatformError> {
        let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `parent` is a held directory descriptor, `name` is a valid
        // NUL-terminated component, and `value` is writable `stat` storage.
        if unsafe { libc::fstatat(parent, name.as_ptr(), value.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(PlatformError::Integrity);
        }
        // SAFETY: the successful `fstatat` above initialized `value`.
        let value = unsafe { value.assume_init() };
        Ok(Identity {
            device: value.st_dev,
            inode: value.st_ino,
            mode: value.st_mode,
            links: value.st_nlink,
            owner: value.st_uid,
            size: value.st_size,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: value.st_mtime_nsec,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: value.st_ctime_nsec,
        })
    }

    fn fd_flags(fd: RawFd) -> Result<libc::c_int, PlatformError> {
        // SAFETY: `F_GETFD` only inspects the supplied descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            Err(PlatformError::InvalidDescriptor)
        } else {
            Ok(flags)
        }
    }

    #[cfg(test)]
    pub(crate) fn descriptor_is_cloexec(fd: RawFd) -> bool {
        fd_flags(fd).map(|flags| flags & libc::FD_CLOEXEC != 0).unwrap_or(false)
    }

    #[cfg(test)]
    fn clear_cloexec_for_test(fd: RawFd) {
        let flags = fd_flags(fd).expect("test descriptor must be live");
        // SAFETY: the test owns or explicitly retains the live descriptor and
        // changes only its descriptor-local close-on-exec flag.
        assert!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } >= 0);
    }

    fn status_flags(fd: RawFd) -> Result<libc::c_int, PlatformError> {
        // SAFETY: `F_GETFL` only inspects the supplied descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            Err(PlatformError::InvalidDescriptor)
        } else {
            Ok(flags)
        }
    }

    fn set_cloexec(fd: RawFd) -> Result<(), PlatformError> {
        let flags = fd_flags(fd)?;
        // SAFETY: `F_SETFD` updates only descriptor flags on the live `fd`.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(PlatformError::InvalidDescriptor);
        }
        if fd_flags(fd)? & libc::FD_CLOEXEC == 0 {
            return Err(PlatformError::InvalidDescriptor);
        }
        Ok(())
    }

    fn duplicate_cloexec(fd: RawFd) -> Result<File, PlatformError> {
        // SAFETY: `F_DUPFD_CLOEXEC` duplicates the live descriptor and returns
        // a new owned descriptor on success.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(PlatformError::InvalidDescriptor);
        }
        // SAFETY: `duplicate` was freshly returned by `fcntl` and ownership is
        // transferred exactly once into `File`.
        let file = unsafe { File::from_raw_fd(duplicate) };
        if fd_flags(file.as_raw_fd())? & libc::FD_CLOEXEC == 0 {
            return Err(PlatformError::InvalidDescriptor);
        }
        Ok(file)
    }

    fn openat_file(parent: RawFd, name: &CStr, flags: libc::c_int) -> Result<File, PlatformError> {
        // SAFETY: `parent` is held open, `name` is NUL-terminated, and the
        // flags request a descriptor without passing a mode argument.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(PlatformError::Integrity);
        }
        // SAFETY: `fd` was freshly returned by `openat` and is transferred
        // exactly once into `File`.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn open_root() -> Result<ChainEntry, PlatformError> {
        let root = c"/";
        let file = openat_file(
            libc::AT_FDCWD,
            root,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        let identity = fstat_fd(file.as_raw_fd())?;
        if !identity.is_directory() || fd_flags(file.as_raw_fd())? & libc::FD_CLOEXEC == 0 {
            return Err(PlatformError::Integrity);
        }
        Ok(ChainEntry {
            file,
            identity: Cell::new(identity),
            name_from_parent: None,
            full_identity: false,
        })
    }

    fn path_components(path: &Path) -> Result<Vec<CString>, PlatformError> {
        if !path.is_absolute() {
            return Err(PlatformError::Integrity);
        }
        let mut values = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(value) => values.push(c_string(value)?),
                _ => return Err(PlatformError::Integrity),
            }
        }
        if values.is_empty() {
            return Err(PlatformError::Integrity);
        }
        Ok(values)
    }

    fn open_directory_chain(path: &Path, bind_final_full_identity: bool) -> Result<Vec<ChainEntry>, PlatformError> {
        let components = path_components(path)?;
        let mut chain = vec![open_root()?];
        let component_count = components.len();
        for (index, component) in components.into_iter().enumerate() {
            let parent = chain.last().expect("root entry is present").file.as_raw_fd();
            let file = openat_file(
                parent,
                &component,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let identity = fstat_fd(file.as_raw_fd())?;
            let entry_identity = fstat_entry(parent, &component)?;
            if !identity.is_directory()
                || !full_identity_and_cloexec_match(
                    identity.snapshot(),
                    entry_identity.snapshot(),
                    fd_flags(file.as_raw_fd())? & libc::FD_CLOEXEC != 0,
                )
            {
                return Err(PlatformError::Integrity);
            }
            chain.push(ChainEntry {
                file,
                identity: Cell::new(identity),
                name_from_parent: Some(component),
                full_identity: bind_final_full_identity && index + 1 == component_count,
            });
        }
        Ok(chain)
    }

    fn open_existing_chain(path: &Path) -> Result<Vec<ChainEntry>, PlatformError> {
        let components = path_components(path)?;
        let mut chain = vec![open_root()?];
        for (index, component) in components.iter().enumerate() {
            let parent = chain.last().expect("root entry is present").file.as_raw_fd();
            let final_component = index + 1 == components.len();
            let directory_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let flags = if final_component {
                leaf_open_flags()
            } else {
                directory_flags
            };
            let file = openat_file(parent, component, flags)?;
            let identity = fstat_fd(file.as_raw_fd())?;
            let entry_identity = fstat_entry(parent, component)?;
            let valid_kind = if final_component {
                identity.is_regular() || identity.is_directory()
            } else {
                identity.is_directory()
            };
            if !valid_kind
                || !full_identity_and_cloexec_match(
                    identity.snapshot(),
                    entry_identity.snapshot(),
                    fd_flags(file.as_raw_fd())? & libc::FD_CLOEXEC != 0,
                )
            {
                return Err(PlatformError::Integrity);
            }
            chain.push(ChainEntry {
                file,
                identity: Cell::new(identity),
                name_from_parent: Some(component.clone()),
                full_identity: false,
            });
        }
        Ok(chain)
    }

    fn revalidate_chain(chain: &[ChainEntry]) -> Result<(), PlatformError> {
        if chain.is_empty() {
            return Err(PlatformError::Integrity);
        }
        for (index, entry) in chain.iter().enumerate() {
            let current = fstat_fd(entry.file.as_raw_fd())?;
            let expected = entry.identity.get();
            let cloexec = fd_flags(entry.file.as_raw_fd())? & libc::FD_CLOEXEC != 0;
            let valid_handle = if entry.full_identity {
                full_identity_and_cloexec_match(expected.snapshot(), current.snapshot(), cloexec)
            } else {
                cloexec && expected.same_object(current)
            };
            if !valid_handle {
                return Err(PlatformError::Integrity);
            }
            if let Some(name) = &entry.name_from_parent {
                let parent = chain.get(index.wrapping_sub(1)).ok_or(PlatformError::Integrity)?;
                let current_entry = fstat_entry(parent.file.as_raw_fd(), name)?;
                let valid_entry = if entry.full_identity {
                    expected == current_entry
                } else {
                    expected.same_object(current_entry)
                };
                if !valid_entry {
                    return Err(PlatformError::Integrity);
                }
            }
        }
        Ok(())
    }

    fn leaf_open_flags() -> libc::c_int {
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }

    #[cfg(test)]
    pub(crate) fn leaf_open_flags_are_nonblocking_for_test() -> bool {
        leaf_open_flags() & libc::O_NONBLOCK != 0
    }

    fn validate_raw(raw_fd: i32) -> Result<(Identity, libc::c_int), PlatformError> {
        if raw_fd <= 2 {
            return Err(PlatformError::InvalidDescriptor);
        }
        fd_flags(raw_fd)?;
        let status = status_flags(raw_fd)?;
        let identity = fstat_fd(raw_fd)?;
        Ok((identity, status))
    }

    pub(crate) fn duplicate_work_root(
        raw_fd: i32,
        reviewed_path: &Path,
        forbidden_roots: &[&Path],
    ) -> Result<DirectoryHandle, PlatformError> {
        let (before, _) = validate_raw(raw_fd)?;
        if !before.is_directory() || before.owner != effective_user() {
            return Err(PlatformError::InvalidWorkRoot);
        }
        set_cloexec(raw_fd)?;
        let inherited = duplicate_cloexec(raw_fd)?;
        let duplicate_identity = fstat_fd(inherited.as_raw_fd())?;
        if !full_identity_and_cloexec_match(
            before.snapshot(),
            duplicate_identity.snapshot(),
            fd_flags(raw_fd)? & libc::FD_CLOEXEC != 0 && fd_flags(inherited.as_raw_fd())? & libc::FD_CLOEXEC != 0,
        ) {
            return Err(PlatformError::InvalidWorkRoot);
        }
        let path_chain = open_directory_chain(reviewed_path, true).map_err(|_| PlatformError::InvalidWorkRoot)?;
        let path_identity = path_chain.last().ok_or(PlatformError::InvalidWorkRoot)?.identity.get();
        if !full_identity_and_cloexec_match(before.snapshot(), path_identity.snapshot(), true) {
            return Err(PlatformError::InvalidWorkRoot);
        }
        for forbidden in forbidden_roots {
            let forbidden_chain = open_existing_chain(forbidden).map_err(|_| PlatformError::InvalidWorkRoot)?;
            let forbidden_identity = forbidden_chain
                .last()
                .ok_or(PlatformError::InvalidWorkRoot)?
                .identity
                .get();
            if forbidden_chain
                .iter()
                .any(|entry| before.same_object(entry.identity.get()))
                || path_chain
                    .iter()
                    .any(|entry| forbidden_identity.same_object(entry.identity.get()))
            {
                return Err(PlatformError::InvalidWorkRoot);
            }
        }
        Ok(DirectoryHandle {
            raw_fd,
            inherited,
            identity: Cell::new(before),
            path_chain,
        })
    }

    impl DirectoryHandle {
        pub(crate) fn revalidate(&self) -> Result<(), PlatformError> {
            revalidate_chain(&self.path_chain)?;
            let raw = fstat_fd(self.raw_fd)?;
            let current = fstat_fd(self.inherited.as_raw_fd())?;
            let expected = self.identity.get();
            if !full_identity_and_cloexec_match(
                expected.snapshot(),
                raw.snapshot(),
                fd_flags(self.raw_fd)? & libc::FD_CLOEXEC != 0,
            ) || !full_identity_and_cloexec_match(
                expected.snapshot(),
                current.snapshot(),
                fd_flags(self.inherited.as_raw_fd())? & libc::FD_CLOEXEC != 0,
            ) || current.owner != effective_user()
            {
                return Err(PlatformError::Integrity);
            }
            Ok(())
        }

        fn revalidate_after_successful_unlink(&self) -> Result<(), PlatformError> {
            let final_index = self.path_chain.len().checked_sub(1).ok_or(PlatformError::Integrity)?;
            revalidate_chain(&self.path_chain[..final_index])?;
            let final_entry = self.path_chain.get(final_index).ok_or(PlatformError::Integrity)?;
            let parent = self
                .path_chain
                .get(final_index.checked_sub(1).ok_or(PlatformError::Integrity)?)
                .ok_or(PlatformError::Integrity)?;
            let name = final_entry.name_from_parent.as_ref().ok_or(PlatformError::Integrity)?;
            let raw = fstat_fd(self.raw_fd)?;
            let inherited = fstat_fd(self.inherited.as_raw_fd())?;
            let path_handle = fstat_fd(final_entry.file.as_raw_fd())?;
            let path_entry = fstat_entry(parent.file.as_raw_fd(), name)?;
            let previous = self.identity.get();
            let all_same = previous.same_object(raw)
                && full_identity_and_cloexec_match(
                    raw.snapshot(),
                    inherited.snapshot(),
                    fd_flags(self.raw_fd)? & libc::FD_CLOEXEC != 0
                        && fd_flags(self.inherited.as_raw_fd())? & libc::FD_CLOEXEC != 0,
                )
                && full_identity_and_cloexec_match(
                    raw.snapshot(),
                    path_handle.snapshot(),
                    fd_flags(final_entry.file.as_raw_fd())? & libc::FD_CLOEXEC != 0,
                )
                && raw == path_entry
                && raw.is_directory()
                && raw.owner == effective_user();
            if !all_same {
                return Err(PlatformError::Integrity);
            }
            self.identity.set(raw);
            final_entry.identity.set(raw);
            Ok(())
        }

        pub(crate) fn reject_physical_overlap(&self, forbidden_roots: &[&Path]) -> Result<(), PlatformError> {
            for forbidden in forbidden_roots {
                let forbidden_chain = open_existing_chain(forbidden).map_err(|_| PlatformError::InvalidWorkRoot)?;
                let forbidden_identity = forbidden_chain
                    .last()
                    .ok_or(PlatformError::InvalidWorkRoot)?
                    .identity
                    .get();
                if forbidden_chain
                    .iter()
                    .any(|entry| self.identity.get().same_object(entry.identity.get()))
                    || self
                        .path_chain
                        .iter()
                        .any(|entry| forbidden_identity.same_object(entry.identity.get()))
                {
                    return Err(PlatformError::InvalidWorkRoot);
                }
            }
            Ok(())
        }

        fn raw_fd(&self) -> RawFd {
            self.inherited.as_raw_fd()
        }

        #[cfg(test)]
        pub(crate) fn clear_raw_cloexec_for_test(&self) {
            clear_cloexec_for_test(self.raw_fd);
        }

        #[cfg(test)]
        pub(crate) fn clear_inherited_cloexec_for_test(&self) {
            clear_cloexec_for_test(self.inherited.as_raw_fd());
        }

        #[cfg(test)]
        pub(crate) fn clear_path_cloexec_for_test(&self) {
            let ancestor = self.path_chain.first().expect("held path chain includes root");
            clear_cloexec_for_test(ancestor.file.as_raw_fd());
        }
    }

    pub(crate) fn duplicate_evidence(raw_fd: i32) -> Result<EvidenceHandle, PlatformError> {
        let (before, status) = validate_raw(raw_fd)?;
        if !before.is_regular()
            || before.owner != effective_user()
            || before.permissions() != 0o600
            || before.links != 0
            || before.size != 0
            || status & libc::O_ACCMODE != libc::O_RDWR
            || status & libc::O_APPEND != 0
        {
            return Err(PlatformError::InvalidEvidence);
        }
        set_cloexec(raw_fd)?;
        let file = duplicate_cloexec(raw_fd)?;
        let after = fstat_fd(file.as_raw_fd())?;
        if !full_identity_and_cloexec_match(
            before.snapshot(),
            after.snapshot(),
            fd_flags(raw_fd)? & libc::FD_CLOEXEC != 0 && fd_flags(file.as_raw_fd())? & libc::FD_CLOEXEC != 0,
        ) {
            return Err(PlatformError::InvalidEvidence);
        }
        Ok(EvidenceHandle {
            raw_fd,
            file,
            identity: Cell::new(before),
        })
    }

    impl EvidenceHandle {
        pub(crate) fn file_mut(&mut self) -> &mut File {
            &mut self.file
        }

        pub(crate) fn same_identity(&self, other: &Self) -> bool {
            self.identity.get().same_object(other.identity.get())
        }

        pub(crate) fn revalidate(&self, expected_size: u64) -> Result<(), PlatformError> {
            let raw = fstat_fd(self.raw_fd)?;
            let current = fstat_fd(self.file.as_raw_fd())?;
            let raw_status = status_flags(self.raw_fd)?;
            let expected = self.identity.get();
            if !full_identity_and_cloexec_match(
                expected.snapshot(),
                raw.snapshot(),
                fd_flags(self.raw_fd)? & libc::FD_CLOEXEC != 0,
            ) || !full_identity_and_cloexec_match(
                expected.snapshot(),
                current.snapshot(),
                fd_flags(self.file.as_raw_fd())? & libc::FD_CLOEXEC != 0,
            ) || raw.owner != expected.owner
                || raw.permissions() != 0o600
                || raw.links != 0
                || u64::try_from(raw.size).map_err(|_| PlatformError::InvalidEvidence)? != expected_size
                || raw_status & libc::O_ACCMODE != libc::O_RDWR
                || raw_status & libc::O_APPEND != 0
                || current.owner != expected.owner
                || current.permissions() != 0o600
                || current.links != 0
                || u64::try_from(current.size).map_err(|_| PlatformError::InvalidEvidence)? != expected_size
            {
                return Err(PlatformError::InvalidEvidence);
            }
            Ok(())
        }

        pub(crate) fn revalidate_after_successful_write(&self, expected_size: u64) -> Result<(), PlatformError> {
            let raw = fstat_fd(self.raw_fd)?;
            let current = fstat_fd(self.file.as_raw_fd())?;
            let previous = self.identity.get();
            let raw_status = status_flags(self.raw_fd)?;
            if !previous.same_object(raw)
                || !full_identity_and_cloexec_match(
                    raw.snapshot(),
                    current.snapshot(),
                    fd_flags(self.raw_fd)? & libc::FD_CLOEXEC != 0
                        && fd_flags(self.file.as_raw_fd())? & libc::FD_CLOEXEC != 0,
                )
                || raw.owner != previous.owner
                || raw.permissions() != 0o600
                || raw.links != 0
                || u64::try_from(raw.size).map_err(|_| PlatformError::InvalidEvidence)? != expected_size
                || raw_status & libc::O_ACCMODE != libc::O_RDWR
                || raw_status & libc::O_APPEND != 0
            {
                return Err(PlatformError::InvalidEvidence);
            }
            self.identity.set(raw);
            Ok(())
        }

        #[cfg(test)]
        pub(crate) fn clear_raw_cloexec_for_test(&self) {
            clear_cloexec_for_test(self.raw_fd);
        }

        #[cfg(test)]
        pub(crate) fn clear_owned_cloexec_for_test(&self) {
            clear_cloexec_for_test(self.file.as_raw_fd());
        }
    }

    pub(crate) fn open_fixed_source(
        storage_root: &Path,
        relative_directories: &[&OsStr],
        source_name: &OsStr,
    ) -> Result<SourceHandle, PlatformError> {
        let mut directories = open_directory_chain(storage_root, true).map_err(|_| PlatformError::Capture)?;
        if directories.last().ok_or(PlatformError::Capture)?.identity.get().owner != effective_user() {
            return Err(PlatformError::Capture);
        }
        for component in relative_directories {
            let name = c_string(component).map_err(|_| PlatformError::Capture)?;
            let parent = directories.last().ok_or(PlatformError::Capture)?.file.as_raw_fd();
            let file = openat_file(
                parent,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .map_err(|_| PlatformError::Capture)?;
            let identity = fstat_fd(file.as_raw_fd()).map_err(|_| PlatformError::Capture)?;
            let entry_identity = fstat_entry(parent, &name).map_err(|_| PlatformError::Capture)?;
            if !identity.is_directory()
                || !full_identity_and_cloexec_match(
                    identity.snapshot(),
                    entry_identity.snapshot(),
                    fd_flags(file.as_raw_fd()).map_err(|_| PlatformError::Capture)? & libc::FD_CLOEXEC != 0,
                )
                || identity.owner != effective_user()
            {
                return Err(PlatformError::Capture);
            }
            directories.push(ChainEntry {
                file,
                identity: Cell::new(identity),
                name_from_parent: Some(name),
                full_identity: true,
            });
        }
        let source_name = c_string(source_name).map_err(|_| PlatformError::Capture)?;
        let parent = directories.last().ok_or(PlatformError::Capture)?.file.as_raw_fd();
        let source = openat_file(parent, &source_name, leaf_open_flags()).map_err(|_| PlatformError::Capture)?;
        let source_identity = fstat_fd(source.as_raw_fd()).map_err(|_| PlatformError::Capture)?;
        let entry_identity = fstat_entry(parent, &source_name).map_err(|_| PlatformError::Capture)?;
        if !source_identity.is_regular()
            || !full_identity_and_cloexec_match(
                source_identity.snapshot(),
                entry_identity.snapshot(),
                fd_flags(source.as_raw_fd()).map_err(|_| PlatformError::Capture)? & libc::FD_CLOEXEC != 0,
            )
            || source_identity.owner != effective_user()
            || source_identity.links != 1
        {
            return Err(PlatformError::Capture);
        }
        Ok(SourceHandle {
            directories,
            source,
            source_identity,
            source_name,
        })
    }

    impl SourceHandle {
        pub(crate) fn source_mut(&mut self) -> &mut File {
            &mut self.source
        }

        pub(crate) fn duplicate_source(&self) -> Result<File, PlatformError> {
            duplicate_cloexec(self.source.as_raw_fd()).map_err(|_| PlatformError::Integrity)
        }

        pub(crate) fn source_size(&self) -> Result<u64, PlatformError> {
            u64::try_from(self.source_identity.size).map_err(|_| PlatformError::Capture)
        }

        pub(crate) fn revalidate(&self) -> Result<(), PlatformError> {
            revalidate_chain(&self.directories)?;
            let current = fstat_fd(self.source.as_raw_fd())?;
            let parent = self
                .directories
                .last()
                .ok_or(PlatformError::Integrity)?
                .file
                .as_raw_fd();
            let current_entry = fstat_entry(parent, &self.source_name)?;
            if !full_identity_and_cloexec_match(
                self.source_identity.snapshot(),
                current.snapshot(),
                fd_flags(self.source.as_raw_fd())? & libc::FD_CLOEXEC != 0,
            ) || self.source_identity != current_entry
                || current.links != 1
                || current.owner != effective_user()
            {
                return Err(PlatformError::Integrity);
            }
            Ok(())
        }

        #[cfg(test)]
        pub(crate) fn clear_parent_cloexec_for_test(&self) {
            let parent = self.directories.last().expect("source parent is held");
            clear_cloexec_for_test(parent.file.as_raw_fd());
        }

        #[cfg(test)]
        pub(crate) fn clear_source_cloexec_for_test(&self) {
            clear_cloexec_for_test(self.source.as_raw_fd());
        }
    }

    fn random_staging_name() -> CString {
        let mut bytes = [0_u8; 16];
        // SAFETY: `bytes` is valid writable storage for exactly 16 bytes.
        unsafe { libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
        CString::new(crate::pinned_staging_name(bytes)).expect("fixed staging alphabet contains no NUL")
    }

    fn unlink_created_name(directory: RawFd, name: &CStr) -> Result<(), PlatformError> {
        // SAFETY: `directory` is a held directory descriptor and `name` is the
        // NUL-terminated component created relative to that descriptor.
        if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } != 0 {
            return Err(PlatformError::Capture);
        }
        Ok(())
    }

    fn create_unlinked_with_names<F>(
        directory: &DirectoryHandle,
        mut next_name: F,
        #[cfg(test)] faults: CreateFaults,
    ) -> Result<AnonymousFile, PlatformError>
    where
        F: FnMut() -> CString,
    {
        directory.revalidate()?;
        retry_exclusive_create(|| {
            let name = next_name();
            // SAFETY: the held directory and NUL-terminated random name are
            // valid, and `O_CREAT` is paired with the explicit `0600` mode.
            let fd = unsafe {
                libc::openat(
                    directory.raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                if last_os_error().kind() == io::ErrorKind::AlreadyExists {
                    return Err(CreateAttemptError::Collision);
                }
                return Err(CreateAttemptError::Fatal(PlatformError::Capture));
            }
            // SAFETY: `fd` was freshly returned by `openat` and is transferred
            // exactly once into `File`.
            let file = unsafe { File::from_raw_fd(fd) };
            #[cfg(test)]
            if faults.nonzero_before_initial_check {
                file.set_len(1)
                    .map_err(|_| CreateAttemptError::Fatal(PlatformError::Capture))?;
            }
            let initial = match fstat_fd(file.as_raw_fd()) {
                Ok(initial) => initial,
                Err(_) => {
                    let _ = unlink_created_name(directory.raw_fd(), &name);
                    return Err(CreateAttemptError::Fatal(PlatformError::Capture));
                }
            };
            if !valid_initial_staging_snapshot(initial.snapshot(), u64::from(effective_user())) {
                let _ = unlink_created_name(directory.raw_fd(), &name);
                return Err(CreateAttemptError::Fatal(PlatformError::Capture));
            }
            #[cfg(test)]
            if faults.remove_before_unlink {
                unlink_created_name(directory.raw_fd(), &name).map_err(CreateAttemptError::Fatal)?;
            }
            unlink_created_name(directory.raw_fd(), &name).map_err(CreateAttemptError::Fatal)?;
            #[cfg(test)]
            if faults.nonzero_after_unlink {
                file.set_len(1)
                    .map_err(|_| CreateAttemptError::Fatal(PlatformError::Capture))?;
            }
            let unlinked = fstat_fd(file.as_raw_fd()).map_err(|_| CreateAttemptError::Fatal(PlatformError::Capture))?;
            if !initial.same_object(unlinked) || unlinked.size != 0 || unlinked.links != 0 {
                return Err(CreateAttemptError::Fatal(PlatformError::Capture));
            }
            directory
                .revalidate_after_successful_unlink()
                .map_err(CreateAttemptError::Fatal)?;
            Ok(AnonymousFile {
                file,
                identity: unlinked,
            })
        })
    }

    pub(crate) fn create_unlinked(directory: &DirectoryHandle) -> Result<AnonymousFile, PlatformError> {
        create_unlinked_with_names(
            directory,
            random_staging_name,
            #[cfg(test)]
            CreateFaults::default(),
        )
    }

    #[cfg(test)]
    #[derive(Default)]
    struct CreateFaults {
        nonzero_before_initial_check: bool,
        remove_before_unlink: bool,
        nonzero_after_unlink: bool,
    }

    #[cfg(test)]
    #[derive(Clone, Copy)]
    pub(crate) enum CreateTestFault {
        None,
        NonzeroBeforeInitialCheck,
        RemoveBeforeUnlink,
        NonzeroAfterUnlink,
    }

    #[cfg(test)]
    pub(crate) fn create_unlinked_with_test_fault(
        directory: &DirectoryHandle,
        bytes: [u8; 16],
        fault: CreateTestFault,
    ) -> Result<AnonymousFile, PlatformError> {
        let faults = match fault {
            CreateTestFault::None => CreateFaults::default(),
            CreateTestFault::NonzeroBeforeInitialCheck => CreateFaults {
                nonzero_before_initial_check: true,
                ..CreateFaults::default()
            },
            CreateTestFault::RemoveBeforeUnlink => CreateFaults {
                remove_before_unlink: true,
                ..CreateFaults::default()
            },
            CreateTestFault::NonzeroAfterUnlink => CreateFaults {
                nonzero_after_unlink: true,
                ..CreateFaults::default()
            },
        };
        create_unlinked_with_names(
            directory,
            || CString::new(crate::pinned_staging_name(bytes)).expect("fixed staging alphabet contains no NUL"),
            faults,
        )
    }

    #[cfg(test)]
    pub(crate) fn create_unlinked_with_test_fault_counted(
        directory: &DirectoryHandle,
        bytes: [u8; 16],
        fault: CreateTestFault,
    ) -> (Result<AnonymousFile, PlatformError>, usize) {
        let faults = match fault {
            CreateTestFault::None => CreateFaults::default(),
            CreateTestFault::NonzeroBeforeInitialCheck => CreateFaults {
                nonzero_before_initial_check: true,
                ..CreateFaults::default()
            },
            CreateTestFault::RemoveBeforeUnlink => CreateFaults {
                remove_before_unlink: true,
                ..CreateFaults::default()
            },
            CreateTestFault::NonzeroAfterUnlink => CreateFaults {
                nonzero_after_unlink: true,
                ..CreateFaults::default()
            },
        };
        let attempts = Cell::new(0);
        let result = create_unlinked_with_names(
            directory,
            || {
                attempts.set(attempts.get() + 1);
                CString::new(crate::pinned_staging_name(bytes)).expect("fixed staging alphabet contains no NUL")
            },
            faults,
        );
        (result, attempts.get())
    }

    impl AnonymousFile {
        pub(crate) fn into_file(self) -> File {
            self.file
        }

        pub(crate) fn file_mut(&mut self) -> &mut File {
            &mut self.file
        }

        pub(crate) fn duplicate(&self) -> Result<File, PlatformError> {
            duplicate_cloexec(self.file.as_raw_fd()).map_err(|_| PlatformError::Integrity)
        }

        pub(crate) fn revalidate(&self, expected_size: u64) -> Result<(), PlatformError> {
            let current = fstat_fd(self.file.as_raw_fd())?;
            if !self.identity.same_object(current)
                || current.owner != self.identity.owner
                || current.permissions() != 0o600
                || current.links != 0
                || u64::try_from(current.size).map_err(|_| PlatformError::Integrity)? != expected_size
                || fd_flags(self.file.as_raw_fd())? & libc::FD_CLOEXEC == 0
            {
                return Err(PlatformError::Integrity);
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use macos::{
    create_unlinked, duplicate_evidence, duplicate_work_root, open_fixed_source, AnonymousFile, DirectoryHandle,
    EvidenceHandle, SourceHandle,
};
#[cfg(all(test, target_os = "macos"))]
pub(crate) use macos::{
    create_unlinked_with_test_fault, create_unlinked_with_test_fault_counted, descriptor_is_cloexec,
    leaf_open_flags_are_nonblocking_for_test, CreateTestFault,
};

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
mod unsupported {
    use super::{File, Path, PlatformError};
    use std::ffi::OsStr;

    pub(crate) struct DirectoryHandle;
    pub(crate) struct EvidenceHandle;
    pub(crate) struct SourceHandle;
    pub(crate) struct AnonymousFile;

    pub(crate) fn duplicate_work_root(
        _raw_fd: i32,
        _reviewed_path: &Path,
        _forbidden_roots: &[&Path],
    ) -> Result<DirectoryHandle, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub(crate) fn duplicate_evidence(_raw_fd: i32) -> Result<EvidenceHandle, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub(crate) fn open_fixed_source(
        _storage_root: &Path,
        _relative_directories: &[&OsStr],
        _source_name: &OsStr,
    ) -> Result<SourceHandle, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub(crate) fn create_unlinked(_directory: &DirectoryHandle) -> Result<AnonymousFile, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    impl DirectoryHandle {
        pub(crate) fn revalidate(&self) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }

        pub(crate) fn reject_physical_overlap(&self, _forbidden_roots: &[&Path]) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }
    }

    impl EvidenceHandle {
        pub(crate) fn file_mut(&mut self) -> &mut File {
            unreachable!("unsupported platform never constructs evidence handles")
        }

        pub(crate) fn same_identity(&self, _other: &Self) -> bool {
            false
        }

        pub(crate) fn revalidate(&self, _expected_size: u64) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }

        pub(crate) fn revalidate_after_successful_write(&self, _expected_size: u64) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }
    }

    impl SourceHandle {
        pub(crate) fn source_mut(&mut self) -> &mut File {
            unreachable!("unsupported platform never constructs source handles")
        }

        pub(crate) fn duplicate_source(&self) -> Result<File, PlatformError> {
            Err(PlatformError::Unsupported)
        }

        pub(crate) fn source_size(&self) -> Result<u64, PlatformError> {
            Err(PlatformError::Unsupported)
        }

        pub(crate) fn revalidate(&self) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }
    }

    impl AnonymousFile {
        pub(crate) fn into_file(self) -> File {
            unreachable!("unsupported platform never constructs anonymous files")
        }

        pub(crate) fn file_mut(&mut self) -> &mut File {
            unreachable!("unsupported platform never constructs anonymous files")
        }

        pub(crate) fn duplicate(&self) -> Result<File, PlatformError> {
            Err(PlatformError::Unsupported)
        }

        pub(crate) fn revalidate(&self, _expected_size: u64) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) use unsupported::{
    create_unlinked, duplicate_evidence, duplicate_work_root, AnonymousFile, DirectoryHandle, EvidenceHandle,
    SourceHandle,
};

#[cfg(test)]
mod contract_tests {
    use super::*;
    use std::cell::Cell;

    fn snapshot() -> MetadataSnapshot {
        MetadataSnapshot {
            device: 7,
            inode: 11,
            kind: 0o100000,
            mode: 0o100600,
            links: 1,
            owner: 501,
            size: 0,
            modified_seconds: 13,
            modified_nanoseconds: 17,
            changed_seconds: 19,
            changed_nanoseconds: 23,
        }
    }

    #[test]
    fn full_identity_and_cloexec_oracle_kills_every_metadata_mutant() {
        let expected = snapshot();
        assert!(full_identity_and_cloexec_match(expected, expected, true));
        assert!(!full_identity_and_cloexec_match(expected, expected, false));
        for actual in [
            MetadataSnapshot { device: 8, ..expected },
            MetadataSnapshot { inode: 12, ..expected },
            MetadataSnapshot {
                kind: 0o040000,
                ..expected
            },
            MetadataSnapshot {
                mode: 0o100400,
                ..expected
            },
            MetadataSnapshot { links: 2, ..expected },
            MetadataSnapshot { owner: 502, ..expected },
            MetadataSnapshot { size: 1, ..expected },
            MetadataSnapshot {
                modified_seconds: 14,
                ..expected
            },
            MetadataSnapshot {
                modified_nanoseconds: 18,
                ..expected
            },
            MetadataSnapshot {
                changed_seconds: 20,
                ..expected
            },
            MetadataSnapshot {
                changed_nanoseconds: 24,
                ..expected
            },
        ] {
            assert!(!full_identity_and_cloexec_match(expected, actual, true));
        }
    }

    #[test]
    fn staging_policy_oracle_rejects_owner_mode_link_size_and_kind_mutants() {
        let expected = snapshot();
        assert!(valid_initial_staging_snapshot(expected, 501));
        assert!(!valid_initial_staging_snapshot(
            MetadataSnapshot { owner: 502, ..expected },
            501,
        ));
        assert!(!valid_initial_staging_snapshot(
            MetadataSnapshot {
                mode: 0o100640,
                ..expected
            },
            501,
        ));
        assert!(!valid_initial_staging_snapshot(
            MetadataSnapshot { links: 2, ..expected },
            501,
        ));
        assert!(!valid_initial_staging_snapshot(
            MetadataSnapshot { size: 1, ..expected },
            501,
        ));
        assert!(!valid_initial_staging_snapshot(
            MetadataSnapshot {
                kind: 0o040000,
                mode: 0o040600,
                ..expected
            },
            501,
        ));
    }

    #[test]
    fn raw_to_duplicate_and_evidence_pre_post_identity_drift_are_rejected() {
        let raw_before = snapshot();
        let duplicate_after = MetadataSnapshot {
            changed_nanoseconds: raw_before.changed_nanoseconds + 1,
            ..raw_before
        };
        assert!(!full_identity_and_cloexec_match(raw_before, duplicate_after, true,));
        let evidence_after = MetadataSnapshot {
            mode: 0o100400,
            ..raw_before
        };
        assert!(!full_identity_and_cloexec_match(raw_before, evidence_after, true,));
    }

    #[test]
    fn collision_retry_policy_attempts_exactly_sixteen_times() {
        let attempts = Cell::new(0);
        let result: Result<(), PlatformError> = retry_exclusive_create(|| {
            attempts.set(attempts.get() + 1);
            Err(CreateAttemptError::Collision)
        });
        assert_eq!(attempts.get(), 16);
        assert_eq!(result, Err(PlatformError::Capture));

        let attempts = Cell::new(0);
        let result: Result<(), PlatformError> = retry_exclusive_create(|| {
            attempts.set(attempts.get() + 1);
            Err(CreateAttemptError::Fatal(PlatformError::Integrity))
        });
        assert_eq!(attempts.get(), 1);
        assert_eq!(result, Err(PlatformError::Integrity));
    }
}
