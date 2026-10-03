//! Bounded immutable MSI staging. MSI metadata is never inspected as PE.
use compatforge_domain::{
    CpuArchitecture, InstallPackage, MsiInstallBinding, MsiPackageBinding, RuntimeInstallerTool, MAX_MSI_BYTES,
};
use compatforge_inspect::{inspect_file, PeArchitecture, PeImageKind, PeInspectionReport};
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "linux"))]
use std::fs::{self, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
const SUMMARY_BOUND: u64 = 64 * 1024;
const INSPECTION_READ_BOUND: u64 = 64 * 1024 * 1024;
fn check_cancelled(flag: Option<&AtomicBool>) -> io::Result<()> {
    if flag.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        Err(io::Error::new(io::ErrorKind::Interrupted, "MSI preparation cancelled"))
    } else {
        Ok(())
    }
}

pub fn inspect_msi_installer_tool(tool: &RuntimeInstallerTool) -> io::Result<PeInspectionReport> {
    let (_, report) = pin_installer_tool(tool)?;
    Ok(report)
}

fn pin_installer_tool(tool: &RuntimeInstallerTool) -> io::Result<(File, PeInspectionReport)> {
    tool.validate()
        .map_err(|_| invalid("invalid MSI runtime tool binding"))?;
    let mut file = open_regular(Path::new(&tool.path))?;
    if file.metadata()?.len() > 16 * 1024 * 1024 {
        return Err(invalid("MSI runtime tool exceeds fixed tool bound"));
    }
    let report = inspect_file(&mut file).map_err(|_| invalid("MSI runtime tool is not a bounded PE"))?;
    let architecture = match report.architecture {
        PeArchitecture::X86 => CpuArchitecture::I386,
        PeArchitecture::X86_64 => CpuArchitecture::X86_64,
        _ => CpuArchitecture::Unknown,
    };
    if report.file_digest != tool.digest
        || architecture != tool.architecture
        || report.image_kind != PeImageKind::Executable
    {
        return Err(invalid("MSI runtime tool identity differs"));
    }
    Ok((file, report))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub struct MsiPackageStore {
    root: PathBuf,
}
impl MsiPackageStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn path(&self, p: &InstallPackage) -> PathBuf {
        self.root
            .join("installer-packages/objects/sha256")
            .join(&p.sha256)
            .join("package.msi")
    }
    pub fn prepare(&self, package: &InstallPackage, architecture: CpuArchitecture) -> io::Result<MsiPackageBinding> {
        self.prepare_cancellable(package, architecture, None)
    }
    pub fn prepare_cancellable(
        &self,
        package: &InstallPackage,
        architecture: CpuArchitecture,
        cancellation: Option<&AtomicBool>,
    ) -> io::Result<MsiPackageBinding> {
        check_cancelled(cancellation)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (package, architecture);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "managed MSI staging is supported only by the Linux Wine preview",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags};
            use std::os::unix::fs::MetadataExt;
            package
                .validate()
                .map_err(|_| invalid("invalid MSI package contract"))?;
            verify_source_cancellable(package, architecture, cancellation)?;
            let target = self.path(package);
            let parent = open_directory(target.parent().ok_or_else(|| invalid("missing MSI parent"))?, true)?;
            let metadata = parent.metadata()?;
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
                return Err(invalid("MSI object directory is not privately owned"));
            }
            match rustix::fs::openat(
                &parent,
                "package.msi",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(_) => {}
                Err(rustix::io::Errno::NOENT) => {
                    // Anonymous temporary inode: no attacker-controlled temporary name,
                    // no replacement publication and no path-based cleanup operation.
                    let mut destination: File = rustix::fs::openat(
                        &parent,
                        ".",
                        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )?
                    .into();
                    let mut source = open_regular(Path::new(&package.path))?;
                    stream_digest(&mut source, Some(&mut destination), package, cancellation)?;
                    destination.sync_all()?;
                    if inspect_architecture(destination.try_clone()?)? != architecture {
                        return Err(invalid("staged MSI architecture drift"));
                    }
                    let mut permissions = destination.metadata()?.permissions();
                    permissions.set_readonly(true);
                    destination.set_permissions(permissions)?;
                    // Publish without replacement. A concurrent object must independently
                    // match the complete content binding rather than overwrite evidence.
                    check_cancelled(cancellation)?;
                    publish_anonymous(&parent, &destination)?;
                    parent.sync_all()?;
                }
                Err(e) => return Err(e.into()),
            }
            let binding = MsiPackageBinding {
                package: package.clone(),
                stored_path: target.to_string_lossy().into(),
                architecture,
            };
            verify_msi_package_contents_cancellable(&binding, cancellation)?;
            Ok(binding)
        }
    }
    pub fn verify(&self, binding: &MsiPackageBinding) -> io::Result<()> {
        self.verify_cancellable(binding, None)
    }
    pub fn verify_cancellable(&self, binding: &MsiPackageBinding, cancellation: Option<&AtomicBool>) -> io::Result<()> {
        if Path::new(&binding.stored_path) != self.path(&binding.package) {
            return Err(invalid("MSI object is outside its content store"));
        }
        verify_msi_package_contents_cancellable(binding, cancellation)
    }
}

pub fn verify_msi_package_contents(binding: &MsiPackageBinding) -> io::Result<()> {
    verify_msi_package_contents_cancellable(binding, None)
}
fn verify_msi_package_contents_cancellable(
    binding: &MsiPackageBinding,
    cancellation: Option<&AtomicBool>,
) -> io::Result<()> {
    binding.package.validate().map_err(|_| invalid("invalid MSI binding"))?;
    verify_source_cancellable(&binding.package, binding.architecture, cancellation)?;
    let mut file = open_regular(Path::new(&binding.stored_path))?;
    verify_stored_file(&mut file, binding, cancellation)
}
fn verify_stored_file(
    file: &mut File,
    binding: &MsiPackageBinding,
    cancellation: Option<&AtomicBool>,
) -> io::Result<()> {
    if !file.metadata()?.permissions().readonly() {
        return Err(invalid("MSI object is writable"));
    }
    stream_digest(file, None, &binding.package, cancellation)?;
    if inspect_architecture(file.try_clone()?)? != binding.architecture {
        return Err(invalid("MSI object architecture differs"));
    }
    Ok(())
}

/// Verified handles remain owned until the process tree and cleanup finish.
/// Execution can reference these handles without reopening mutable paths.
pub struct PinnedMsiInputs {
    binding: MsiInstallBinding,
    package: Arc<File>,
    tool: Arc<File>,
}
impl PinnedMsiInputs {
    pub fn pin(binding: &MsiInstallBinding, cancellation: Option<&AtomicBool>) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (binding, cancellation);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned MSI execution requires Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            binding.validate().map_err(|_| invalid("invalid MSI install binding"))?;
            verify_source_cancellable(&binding.package.package, binding.package.architecture, cancellation)?;
            let mut package = open_regular(Path::new(&binding.package.stored_path))?;
            verify_stored_file(&mut package, &binding.package, cancellation)?;
            let (tool, _) = pin_installer_tool(&binding.tool)?;
            Ok(Self {
                binding: binding.clone(),
                package: Arc::new(package),
                tool: Arc::new(tool),
            })
        }
    }
    pub fn files(&self) -> Vec<Arc<File>> {
        vec![Arc::clone(&self.tool), Arc::clone(&self.package)]
    }
    pub fn revalidate(&self, cancellation: Option<&AtomicBool>) -> io::Result<()> {
        let mut package = self.package.try_clone()?;
        verify_stored_file(&mut package, &self.binding.package, cancellation)?;
        let mut tool = self.tool.try_clone()?;
        let report = inspect_file(&mut tool).map_err(|_| invalid("held MSI runtime tool differs"))?;
        if report.file_digest != self.binding.tool.digest {
            return Err(invalid("held MSI runtime tool digest differs"));
        }
        Ok(())
    }
    pub fn execution_arguments(&self) -> io::Result<Vec<String>> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned MSI execution requires Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut arguments = self
                .binding
                .arguments()
                .map_err(|_| invalid("invalid held MSI command"))?;
            // Wine's Unix device path bypasses mutable DOS drive mappings.
            // The owner keeps both descriptors alive until tree cleanup.
            arguments[0] = format!(r"\\?\unix\proc\{}\fd\{}", std::process::id(), self.tool.as_raw_fd());
            arguments[2] = format!(r"\\?\unix\proc\{}\fd\{}", std::process::id(), self.package.as_raw_fd());
            Ok(arguments)
        }
    }
}
pub fn inspect_msi_package(package: &InstallPackage, architecture: CpuArchitecture) -> io::Result<()> {
    package
        .validate()
        .map_err(|_| invalid("invalid MSI package contract"))?;
    verify_source(package, architecture)
}
fn verify_source(package: &InstallPackage, architecture: CpuArchitecture) -> io::Result<()> {
    verify_source_cancellable(package, architecture, None)
}
fn verify_source_cancellable(
    package: &InstallPackage,
    architecture: CpuArchitecture,
    cancellation: Option<&AtomicBool>,
) -> io::Result<()> {
    check_cancelled(cancellation)?;
    if !matches!(architecture, CpuArchitecture::I386 | CpuArchitecture::X86_64) {
        return Err(invalid("unsupported MSI architecture"));
    }
    let mut source = open_regular(Path::new(&package.path))?;
    stream_digest(&mut source, None, package, cancellation)?;
    if inspect_architecture(source)? != architecture {
        return Err(invalid("MSI Template Summary architecture differs"));
    }
    Ok(())
}
fn stream_digest(
    source: &mut File,
    target: Option<&mut File>,
    package: &InstallPackage,
    cancellation: Option<&AtomicBool>,
) -> io::Result<()> {
    if source.metadata()?.len() != package.size_bytes {
        return Err(invalid("MSI size differs"));
    }
    source.seek(SeekFrom::Start(0))?;
    stream_copy(source, target.map(|file| file as &mut dyn Write), package, cancellation)
}
fn stream_copy(
    source: &mut impl Read,
    mut target: Option<&mut dyn Write>,
    package: &InstallPackage,
    cancellation: Option<&AtomicBool>,
) -> io::Result<()> {
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        check_cancelled(cancellation)?;
        let count = source.read(&mut buffer)?;
        check_cancelled(cancellation)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| invalid("MSI size overflow"))?;
        if size > package.size_bytes || size > MAX_MSI_BYTES {
            return Err(invalid("MSI grew beyond its reviewed size"));
        }
        hash.update(&buffer[..count]);
        if let Some(output) = target.as_deref_mut() {
            output.write_all(&buffer[..count])?;
        }
    }
    if size != package.size_bytes || format!("{:x}", hash.finalize()) != package.sha256 {
        return Err(invalid("MSI SHA-256 differs"));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn check_path(path: &Path, allow_missing: bool) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("MSI path must be absolute and non-traversing"));
    }
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(m) => {
                #[cfg(windows)]
                let linked = {
                    use std::os::windows::fs::MetadataExt;
                    m.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let linked = m.file_type().is_symlink();
                if linked || cursor != path && !m.is_dir() {
                    return Err(invalid("MSI path contains a link or non-directory ancestor"));
                }
            }
            Err(e) if allow_missing && e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_anonymous(parent: &File, file: &File) -> io::Result<()> {
    use rustix::fs::AtFlags;
    use std::os::fd::AsRawFd;
    let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    match rustix::fs::linkat(
        rustix::fs::CWD,
        proc_path,
        parent,
        "package.msi",
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn open_regular(path: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags};
        let parent = open_directory(path.parent().ok_or_else(|| invalid("missing MSI parent"))?, false)?;
        let file: File = rustix::fs::openat(
            &parent,
            path.file_name().ok_or_else(|| invalid("missing MSI filename"))?,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?
        .into();
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MSI_BYTES {
            return Err(invalid("MSI input is not a bounded regular file"));
        }
        Ok(file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        check_path(path, false)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MSI_BYTES {
            return Err(invalid("MSI input is not a bounded regular file"));
        }
        Ok(file)
    }
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path, create: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    if !path.is_absolute() {
        return Err(invalid("MSI directory must be absolute"));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory: File = rustix::fs::open("/", flags, Mode::empty())?.into();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let opened = rustix::fs::openat(&directory, name, flags, Mode::empty());
                let next = match opened {
                    Err(rustix::io::Errno::NOENT) if create => {
                        match rustix::fs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                            Err(e) => return Err(e.into()),
                        }
                        rustix::fs::openat(&directory, name, flags, Mode::empty())?
                    }
                    Ok(fd) => fd,
                    Err(e) => return Err(e.into()),
                };
                directory = next.into();
            }
            _ => return Err(invalid("MSI directory contains traversal")),
        }
    }
    Ok(directory)
}

struct InspectionReader {
    file: File,
    remaining: u64,
}
impl Read for InspectionReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(invalid("MSI metadata read budget exhausted"));
        }
        let max = buffer.len().min(self.remaining as usize);
        let count = self.file.read(&mut buffer[..max])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}
impl Seek for InspectionReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}
fn inspect_architecture(mut file: File) -> io::Result<CpuArchitecture> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 512];
    file.read_exact(&mut header)?;
    let shift = u16::from_le_bytes([header[30], header[31]]);
    if header[..8] != [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
        || !matches!(shift, 9 | 12)
        || word(&header, 64)? as u64 * (1u64 << shift) > 16 * 1024 * 1024
    {
        return Err(invalid("CFB header or MiniFAT allocation exceeds fixed bound"));
    }
    file.seek(SeekFrom::Start(0))?;
    // Strict mode checks actual MiniFAT chain length against the bounded
    // header BEFORE Vec::with_capacity; an I/O budget alone is insufficient.
    let mut compound = cfb::CompoundFile::open_strict(InspectionReader {
        file,
        remaining: INSPECTION_READ_BOUND,
    })?;
    if compound.root_entry().clsid().to_string() != "000c1084-0000-0000-c000-000000000046" {
        return Err(invalid("compound file is not an MSI installer"));
    }
    let summary = compound.open_stream("\u{5}SummaryInformation")?;
    if summary.len() > SUMMARY_BOUND {
        return Err(invalid("MSI summary exceeds 64 KiB"));
    }
    let mut bytes = Vec::new();
    summary.take(SUMMARY_BOUND + 1).read_to_end(&mut bytes)?;
    summary_architecture(&bytes)
}
fn word(bytes: &[u8], offset: usize) -> io::Result<usize> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid("MSI summary offset overflow"))?;
    let value = bytes.get(offset..end).ok_or_else(|| invalid("truncated MSI summary"))?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()) as usize)
}
fn summary_architecture(bytes: &[u8]) -> io::Result<CpuArchitecture> {
    // MS-OLEPS PropertySetStream and PID_TEMPLATE (7), read only within the
    // bounded summary. Never parse MSI database strings/tables into unbounded
    // allocations. String architecture tokens are ASCII in every codepage.
    if bytes.get(0..2) != Some(&[0xfe, 0xff])
        || word(bytes, 24)? != 1
        || bytes.get(28..44)
            != Some(&[
                0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9,
            ])
    {
        return Err(invalid("unsupported MSI SummaryInformation header"));
    }
    let base = word(bytes, 44)?;
    if base < 48 {
        return Err(invalid("MSI property set overlaps header"));
    }
    let size = word(bytes, base)?;
    let end = base
        .checked_add(size)
        .ok_or_else(|| invalid("MSI property set overflow"))?;
    if end > bytes.len() || size < 8 {
        return Err(invalid("MSI property set is outside summary"));
    }
    let count = word(bytes, base + 4)?;
    if count > 128 || 8 + count * 8 > size {
        return Err(invalid("MSI property count exceeds bound"));
    }
    let mut template = None;
    for i in 0..count {
        if word(bytes, base + 8 + i * 8)? != 7 {
            continue;
        }
        if template.is_some() {
            return Err(invalid("duplicate MSI template property"));
        }
        let offset = word(bytes, base + 12 + i * 8)?;
        if offset < 8 + count * 8 || offset > size.saturating_sub(8) {
            return Err(invalid("MSI template offset outside property set"));
        }
        let position = base + offset;
        let variant = word(bytes, position)?;
        let length = word(bytes, position + 4)?;
        let byte_length = match variant {
            30 => length,
            31 => length
                .checked_mul(2)
                .ok_or_else(|| invalid("MSI template length overflow"))?,
            _ => return Err(invalid("MSI template is not a string")),
        };
        if byte_length == 0 || byte_length > 512 || position + 8 + byte_length > end {
            return Err(invalid("MSI template length outside bound"));
        }
        let raw = &bytes[position + 8..position + 8 + byte_length];
        let value = if variant == 30 {
            if raw.last() != Some(&0) {
                return Err(invalid("MSI template is not terminated"));
            }
            String::from_utf8(raw[..raw.len() - 1].to_vec()).map_err(|_| invalid("MSI template is not ASCII UTF-8"))?
        } else {
            let words: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            if words.last() != Some(&0) {
                return Err(invalid("MSI template is not terminated"));
            }
            String::from_utf16(&words[..words.len() - 1]).map_err(|_| invalid("MSI template UTF-16 is invalid"))?
        };
        template = Some(value);
    }
    let value = template.ok_or_else(|| invalid("MSI template architecture absent"))?;
    match value.split(';').next() {
        Some("x64") => Ok(CpuArchitecture::X86_64),
        Some("Intel") => Ok(CpuArchitecture::I386),
        _ => Err(invalid("MSI template architecture unsupported")),
    }
}
#[cfg(all(test, target_os = "linux"))]
mod capability_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn copy_cancellation_after_first_chunk_stops_before_the_next_read() {
        struct CancellingWriter<'a> {
            flag: &'a AtomicBool,
            bytes: Vec<u8>,
        }
        impl Write for CancellingWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                self.flag.store(true, Ordering::Release);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let flag = AtomicBool::new(false);
        let bytes = vec![1; 128 * 1024];
        let mut source = io::Cursor::new(&bytes);
        let mut target = CancellingWriter {
            flag: &flag,
            bytes: Vec::new(),
        };
        let package = InstallPackage {
            path: "/fixture/canary.msi".into(),
            file_name: "canary.msi".into(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            size_bytes: bytes.len() as u64,
            media_type: "application/x-msi".into(),
        };
        let error = stream_copy(&mut source, Some(&mut target), &package, Some(&flag)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(source.position(), 64 * 1024);
        assert_eq!(target.bytes.len(), 64 * 1024);
    }
    #[test]
    fn directory_rebinding_cannot_redirect_anonymous_publication_or_cleanup() {
        use rustix::fs::{Mode, OFlags};
        let root = std::env::temp_dir().join(format!("cf-msi-dir-race-{}", std::process::id()));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        let original = root.join("objects");
        let retained = root.join("retained");
        let outside = root.join("outside");
        let parent = open_directory(&original, true).unwrap();
        fs::create_dir(&outside).unwrap();
        let retained_file = original.join(".msi-predictable.tmp");
        fs::write(&retained_file, b"existing retained evidence").unwrap();
        let mut anonymous: File = rustix::fs::openat(
            &parent,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .unwrap()
        .into();
        anonymous.write_all(b"verified held inode").unwrap();
        anonymous.sync_all().unwrap();
        anonymous.set_permissions(fs::Permissions::from_mode(0o400)).unwrap();
        fs::rename(&original, &retained).unwrap();
        symlink(&outside, &original).unwrap();
        publish_anonymous(&parent, &anonymous).unwrap();
        assert_eq!(fs::read(retained.join("package.msi")).unwrap(), b"verified held inode");
        assert_eq!(
            fs::read(retained.join(".msi-predictable.tmp")).unwrap(),
            b"existing retained evidence"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert!(open_directory(&original, false).is_err());
        drop(anonymous);
        drop(parent);
        fs::remove_dir_all(root).unwrap();
    }
}
