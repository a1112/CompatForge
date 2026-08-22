//! Bounded, read-only inspection of Windows Portable Executable files.
//!
//! This crate parses only metadata needed for compatibility planning. It does
//! not map an image, execute code, resolve providers or create a launch plan.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const MAX_PE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PE_SECTIONS: u16 = 96;
pub const MAX_IMPORT_LIBRARIES: usize = 256;

const DOS_HEADER_BYTES: usize = 64;
const COFF_HEADER_BYTES: usize = 20;
const SECTION_HEADER_BYTES: usize = 40;
const MAX_OPTIONAL_HEADER_BYTES: usize = 4 * 1024;
const MAX_IMPORT_NAME_BYTES: usize = 260;
const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PeFormat {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeArchitecture {
    X86,
    X86_64,
    Arm,
    Arm64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PeImageKind {
    Executable,
    DynamicLibrary,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PeSubsystem {
    Unknown,
    Native,
    WindowsGui,
    WindowsConsole,
    PosixConsole,
    NativeWindows,
    EfiApplication,
    EfiBootServiceDriver,
    EfiRuntimeDriver,
    Xbox,
    WindowsBootApplication,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeSectionSummary {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_size: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeInspectionReport {
    pub schema_version: String,
    pub file_digest: String,
    pub file_size_bytes: u64,
    pub format: PeFormat,
    pub architecture: PeArchitecture,
    pub machine_code: u16,
    pub image_kind: PeImageKind,
    pub subsystem: PeSubsystem,
    pub subsystem_code: u16,
    pub entry_point_rva: u32,
    pub sections: Vec<PeSectionSummary>,
    pub import_libraries: Vec<String>,
}

/// Inspect one absolute regular-file path with a 64 MiB pre-allocation limit.
pub fn inspect_path(path: &Path) -> Result<PeInspectionReport, InspectionError> {
    inspect_path_with_before_open(path, || {})
}

/// Inspect one caller-owned open regular file without reopening a pathname.
pub fn inspect_file(file: &mut fs::File) -> Result<PeInspectionReport, InspectionError> {
    inspect_file_with_before_read(file, || {})
}

fn inspect_file_with_before_read(
    file: &mut fs::File,
    before_read: impl FnOnce(),
) -> Result<PeInspectionReport, InspectionError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| InspectionError::FileHandle {
            operation: "seek",
            source,
        })?;
    let metadata = file.metadata().map_err(|source| InspectionError::FileHandle {
        operation: "read metadata for",
        source,
    })?;
    if !metadata.is_file() {
        return Err(InspectionError::NotRegularFileHandle);
    }
    if metadata.len() > MAX_PE_FILE_BYTES {
        return Err(InspectionError::FileTooLarge(metadata.len()));
    }

    before_read();
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_PE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| InspectionError::FileHandle {
            operation: "read",
            source,
        })?;
    if bytes.len() as u64 > MAX_PE_FILE_BYTES {
        return Err(InspectionError::FileTooLarge(bytes.len() as u64));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(InspectionError::ChangedDuringRead);
    }
    inspect_bytes(&bytes)
}

fn inspect_path_with_before_open(
    path: &Path,
    before_open: impl FnOnce(),
) -> Result<PeInspectionReport, InspectionError> {
    if !path.is_absolute() {
        return Err(InspectionError::RelativePath(path.to_owned()));
    }

    let path_metadata = fs::symlink_metadata(path).map_err(|source| InspectionError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata_is_link(&path_metadata) {
        return Err(InspectionError::SymbolicLink(path.to_owned()));
    }
    if !path_metadata.is_file() {
        return Err(InspectionError::NotRegularFile(path.to_owned()));
    }

    before_open();
    let mut file = match open_without_following_links(path) {
        Ok(file) => file,
        Err(source) => {
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata_is_link(&metadata)) {
                return Err(InspectionError::SymbolicLink(path.to_owned()));
            }
            return Err(InspectionError::Filesystem {
                path: path.to_owned(),
                source,
            });
        }
    };
    let metadata = file.metadata().map_err(|source| InspectionError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata_is_link(&metadata) {
        return Err(InspectionError::SymbolicLink(path.to_owned()));
    }
    if !metadata.is_file() {
        return Err(InspectionError::NotRegularFile(path.to_owned()));
    }
    if metadata.len() > MAX_PE_FILE_BYTES {
        return Err(InspectionError::FileTooLarge(metadata.len()));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_PE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| InspectionError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > MAX_PE_FILE_BYTES {
        return Err(InspectionError::FileTooLarge(bytes.len() as u64));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(InspectionError::ChangedDuringRead);
    }
    inspect_bytes(&bytes)
}

#[cfg(unix)]
fn open_without_following_links(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_without_following_links(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
compile_error!("compatforge-inspect requires atomic no-follow file opening support");

#[cfg(not(windows))]
fn metadata_is_link(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Inspect an in-memory PE image without executing or mapping it.
pub fn inspect_bytes(bytes: &[u8]) -> Result<PeInspectionReport, InspectionError> {
    if bytes.len() as u64 > MAX_PE_FILE_BYTES {
        return Err(InspectionError::FileTooLarge(bytes.len() as u64));
    }
    if bytes.len() < DOS_HEADER_BYTES || !bytes.starts_with(b"MZ") {
        return Err(InspectionError::InvalidDosHeader);
    }

    let pe_offset = usize::try_from(read_u32(bytes, 0x3c)?).map_err(|_| InspectionError::IntegerOverflow)?;
    let coff_offset = pe_offset.checked_add(4).ok_or(InspectionError::IntegerOverflow)?;
    if pe_offset < DOS_HEADER_BYTES || checked_slice(bytes, pe_offset, 4)? != &b"PE\0\0"[..] {
        return Err(InspectionError::InvalidPeSignature);
    }
    checked_slice(bytes, coff_offset, COFF_HEADER_BYTES)?;

    let machine_code = read_u16(bytes, coff_offset)?;
    let section_count = read_u16(bytes, coff_offset + 2)?;
    if section_count == 0 || section_count > MAX_PE_SECTIONS {
        return Err(InspectionError::InvalidSectionCount(section_count));
    }
    let optional_size = usize::from(read_u16(bytes, coff_offset + 16)?);
    if optional_size > MAX_OPTIONAL_HEADER_BYTES {
        return Err(InspectionError::OptionalHeaderTooLarge(optional_size));
    }
    let characteristics = read_u16(bytes, coff_offset + 18)?;
    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return Err(InspectionError::NotExecutableImage);
    }

    let optional_offset = coff_offset
        .checked_add(COFF_HEADER_BYTES)
        .ok_or(InspectionError::IntegerOverflow)?;
    checked_slice(bytes, optional_offset, optional_size)?;
    let magic = read_u16(bytes, optional_offset)?;
    let (format, minimum_optional_size, data_directory_offset, directory_count_offset) = match magic {
        PE32_MAGIC => (PeFormat::Pe32, 96usize, 96usize, 92usize),
        PE32_PLUS_MAGIC => (PeFormat::Pe32Plus, 112usize, 112usize, 108usize),
        value => return Err(InspectionError::UnsupportedOptionalHeader(value)),
    };
    if optional_size < minimum_optional_size {
        return Err(InspectionError::TruncatedOptionalHeader);
    }

    let architecture = architecture(machine_code, format)?;
    let entry_point_rva = read_u32(bytes, optional_offset + 16)?;
    let size_of_headers =
        usize::try_from(read_u32(bytes, optional_offset + 60)?).map_err(|_| InspectionError::IntegerOverflow)?;
    let subsystem_code = read_u16(bytes, optional_offset + 68)?;
    let image_kind = if characteristics & IMAGE_FILE_DLL == 0 {
        PeImageKind::Executable
    } else {
        PeImageKind::DynamicLibrary
    };

    let section_table_offset = optional_offset
        .checked_add(optional_size)
        .ok_or(InspectionError::IntegerOverflow)?;
    let section_table_bytes = usize::from(section_count)
        .checked_mul(SECTION_HEADER_BYTES)
        .ok_or(InspectionError::IntegerOverflow)?;
    let section_table_end = section_table_offset
        .checked_add(section_table_bytes)
        .ok_or(InspectionError::IntegerOverflow)?;
    checked_slice(bytes, section_table_offset, section_table_bytes)?;
    if size_of_headers < section_table_end || size_of_headers > bytes.len() {
        return Err(InspectionError::InvalidHeadersSize);
    }

    let sections = parse_sections(bytes, section_table_offset, section_count, size_of_headers)?;
    let directory_count = read_u32(bytes, optional_offset + directory_count_offset)?;
    let import_libraries = if directory_count < 2 {
        Vec::new()
    } else {
        if optional_size < data_directory_offset + 16 {
            return Err(InspectionError::TruncatedOptionalHeader);
        }
        let import_directory = optional_offset + data_directory_offset + 8;
        let import_rva = read_u32(bytes, import_directory)?;
        let import_size = read_u32(bytes, import_directory + 4)?;
        parse_imports(bytes, &sections, import_rva, import_size)?
    };

    Ok(PeInspectionReport {
        schema_version: "1".to_owned(),
        file_digest: sha256_digest(bytes),
        file_size_bytes: bytes.len() as u64,
        format,
        architecture,
        machine_code,
        image_kind,
        subsystem: subsystem(subsystem_code),
        subsystem_code,
        entry_point_rva,
        sections: sections.into_iter().map(Section::summary).collect(),
        import_libraries,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    summary: PeSectionSummary,
    raw_data_offset: u32,
}

impl Section {
    fn summary(self) -> PeSectionSummary {
        self.summary
    }
}

fn parse_sections(
    bytes: &[u8],
    table_offset: usize,
    section_count: u16,
    size_of_headers: usize,
) -> Result<Vec<Section>, InspectionError> {
    let mut sections = Vec::with_capacity(usize::from(section_count));
    let mut names = BTreeSet::new();
    for index in 0..usize::from(section_count) {
        let offset = table_offset
            .checked_add(index * SECTION_HEADER_BYTES)
            .ok_or(InspectionError::IntegerOverflow)?;
        let name = parse_section_name(checked_slice(bytes, offset, 8)?)?;
        if !names.insert(name.clone()) {
            return Err(InspectionError::DuplicateSectionName(name));
        }
        let virtual_size = read_u32(bytes, offset + 8)?;
        let virtual_address = read_u32(bytes, offset + 12)?;
        let raw_data_size = read_u32(bytes, offset + 16)?;
        let raw_data_offset = read_u32(bytes, offset + 20)?;
        let characteristics = read_u32(bytes, offset + 36)?;
        if raw_data_size > 0 {
            let raw_offset = usize::try_from(raw_data_offset).map_err(|_| InspectionError::IntegerOverflow)?;
            let raw_size = usize::try_from(raw_data_size).map_err(|_| InspectionError::IntegerOverflow)?;
            if raw_offset < size_of_headers {
                return Err(InspectionError::SectionOverlapsHeaders);
            }
            checked_slice(bytes, raw_offset, raw_size)?;
        }
        sections.push(Section {
            summary: PeSectionSummary {
                name,
                virtual_address,
                virtual_size,
                raw_data_size,
                readable: characteristics & 0x4000_0000 != 0,
                writable: characteristics & 0x8000_0000 != 0,
                executable: characteristics & 0x2000_0000 != 0,
            },
            raw_data_offset,
        });
    }
    for (index, section) in sections.iter().enumerate() {
        for previous in &sections[..index] {
            if ranges_overlap(
                section.summary.virtual_address,
                section.summary.virtual_size.max(section.summary.raw_data_size),
                previous.summary.virtual_address,
                previous.summary.virtual_size.max(previous.summary.raw_data_size),
            )? || ranges_overlap(
                section.raw_data_offset,
                section.summary.raw_data_size,
                previous.raw_data_offset,
                previous.summary.raw_data_size,
            )? {
                return Err(InspectionError::OverlappingSections);
            }
        }
    }
    Ok(sections)
}

fn ranges_overlap(
    first_start: u32,
    first_length: u32,
    second_start: u32,
    second_length: u32,
) -> Result<bool, InspectionError> {
    if first_length == 0 || second_length == 0 {
        return Ok(false);
    }
    let first_end = first_start
        .checked_add(first_length)
        .ok_or(InspectionError::IntegerOverflow)?;
    let second_end = second_start
        .checked_add(second_length)
        .ok_or(InspectionError::IntegerOverflow)?;
    Ok(first_start < second_end && second_start < first_end)
}

fn parse_imports(
    bytes: &[u8],
    sections: &[Section],
    import_rva: u32,
    import_size: u32,
) -> Result<Vec<String>, InspectionError> {
    if import_rva == 0 && import_size == 0 {
        return Ok(Vec::new());
    }
    if import_rva == 0 || import_size < 20 {
        return Err(InspectionError::InvalidImportDirectory);
    }
    let descriptor_limit = usize::try_from(import_size / 20)
        .map_err(|_| InspectionError::IntegerOverflow)?
        .min(MAX_IMPORT_LIBRARIES + 1);
    let mut imports = BTreeSet::new();
    for index in 0..descriptor_limit {
        let descriptor_rva = import_rva
            .checked_add(u32::try_from(index * 20).map_err(|_| InspectionError::IntegerOverflow)?)
            .ok_or(InspectionError::IntegerOverflow)?;
        let (offset, _) = rva_window(bytes, sections, descriptor_rva, 20)?;
        let descriptor = checked_slice(bytes, offset, 20)?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Ok(imports.into_iter().collect());
        }
        if imports.len() >= MAX_IMPORT_LIBRARIES {
            return Err(InspectionError::TooManyImports);
        }
        let name_rva = read_u32(descriptor, 12)?;
        if name_rva == 0 {
            return Err(InspectionError::InvalidImportDirectory);
        }
        let (name_offset, available) = rva_window(bytes, sections, name_rva, 1)?;
        let maximum = available.min(MAX_IMPORT_NAME_BYTES + 1);
        let name_bytes = checked_slice(bytes, name_offset, maximum)?;
        let terminator = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(InspectionError::ImportNameTooLong)?;
        if terminator == 0 || terminator > MAX_IMPORT_NAME_BYTES {
            return Err(InspectionError::InvalidImportName);
        }
        let name = std::str::from_utf8(&name_bytes[..terminator]).map_err(|_| InspectionError::InvalidImportName)?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(InspectionError::InvalidImportName);
        }
        imports.insert(name.to_ascii_lowercase());
    }
    Err(InspectionError::UnterminatedImportDirectory)
}

fn rva_window(
    bytes: &[u8],
    sections: &[Section],
    rva: u32,
    required: usize,
) -> Result<(usize, usize), InspectionError> {
    for section in sections {
        let start = section.summary.virtual_address;
        let span = section.summary.virtual_size.max(section.summary.raw_data_size);
        let end = start.checked_add(span).ok_or(InspectionError::IntegerOverflow)?;
        if rva < start || rva >= end {
            continue;
        }
        let delta = rva - start;
        if delta >= section.summary.raw_data_size {
            return Err(InspectionError::UnmappedRva(rva));
        }
        let available =
            usize::try_from(section.summary.raw_data_size - delta).map_err(|_| InspectionError::IntegerOverflow)?;
        if available < required {
            return Err(InspectionError::UnmappedRva(rva));
        }
        let offset = section
            .raw_data_offset
            .checked_add(delta)
            .ok_or(InspectionError::IntegerOverflow)?;
        let offset = usize::try_from(offset).map_err(|_| InspectionError::IntegerOverflow)?;
        checked_slice(bytes, offset, required)?;
        return Ok((offset, available.min(bytes.len() - offset)));
    }
    Err(InspectionError::UnmappedRva(rva))
}

fn architecture(machine: u16, format: PeFormat) -> Result<PeArchitecture, InspectionError> {
    match (machine, format) {
        (0x014c, PeFormat::Pe32) => Ok(PeArchitecture::X86),
        (0x01c0, PeFormat::Pe32) | (0x01c4, PeFormat::Pe32) => Ok(PeArchitecture::Arm),
        (0x8664, PeFormat::Pe32Plus) => Ok(PeArchitecture::X86_64),
        (0xaa64, PeFormat::Pe32Plus) => Ok(PeArchitecture::Arm64),
        _ => Err(InspectionError::UnsupportedMachine { machine, format }),
    }
}

const fn subsystem(code: u16) -> PeSubsystem {
    match code {
        1 => PeSubsystem::Native,
        2 => PeSubsystem::WindowsGui,
        3 => PeSubsystem::WindowsConsole,
        7 => PeSubsystem::PosixConsole,
        8 => PeSubsystem::NativeWindows,
        10 => PeSubsystem::EfiApplication,
        11 => PeSubsystem::EfiBootServiceDriver,
        12 => PeSubsystem::EfiRuntimeDriver,
        14 => PeSubsystem::Xbox,
        16 => PeSubsystem::WindowsBootApplication,
        _ => PeSubsystem::Unknown,
    }
}

fn parse_section_name(bytes: &[u8]) -> Result<String, InspectionError> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) || end == 0 {
        return Err(InspectionError::InvalidSectionName);
    }
    let value = std::str::from_utf8(&bytes[..end]).map_err(|_| InspectionError::InvalidSectionName)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'$' | b'_' | b'-'))
    {
        return Err(InspectionError::InvalidSectionName);
    }
    Ok(value.to_owned())
}

fn checked_slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], InspectionError> {
    let end = offset.checked_add(length).ok_or(InspectionError::IntegerOverflow)?;
    bytes.get(offset..end).ok_or(InspectionError::TruncatedImage)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, InspectionError> {
    let value: [u8; 2] = checked_slice(bytes, offset, 2)?
        .try_into()
        .map_err(|_| InspectionError::TruncatedImage)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, InspectionError> {
    let value: [u8; 4] = checked_slice(bytes, offset, 4)?
        .try_into()
        .map_err(|_| InspectionError::TruncatedImage)?;
    Ok(u32::from_le_bytes(value))
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in digest {
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

#[derive(Debug)]
pub enum InspectionError {
    RelativePath(PathBuf),
    SymbolicLink(PathBuf),
    NotRegularFile(PathBuf),
    NotRegularFileHandle,
    Filesystem { path: PathBuf, source: io::Error },
    FileHandle { operation: &'static str, source: io::Error },
    FileTooLarge(u64),
    ChangedDuringRead,
    InvalidDosHeader,
    InvalidPeSignature,
    TruncatedImage,
    IntegerOverflow,
    InvalidSectionCount(u16),
    OptionalHeaderTooLarge(usize),
    UnsupportedOptionalHeader(u16),
    TruncatedOptionalHeader,
    UnsupportedMachine { machine: u16, format: PeFormat },
    NotExecutableImage,
    InvalidHeadersSize,
    SectionOverlapsHeaders,
    OverlappingSections,
    InvalidSectionName,
    DuplicateSectionName(String),
    InvalidImportDirectory,
    TooManyImports,
    UnterminatedImportDirectory,
    ImportNameTooLong,
    InvalidImportName,
    UnmappedRva(u32),
}

impl fmt::Display for InspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativePath(path) => write!(formatter, "inspection path must be absolute: {}", path.display()),
            Self::SymbolicLink(path) => write!(
                formatter,
                "inspection path must not be a symbolic link: {}",
                path.display()
            ),
            Self::NotRegularFile(path) => {
                write!(formatter, "inspection path is not a regular file: {}", path.display())
            }
            Self::NotRegularFileHandle => formatter.write_str("inspection file handle is not a regular file"),
            Self::Filesystem { path, source } => write!(formatter, "could not read {}: {source}", path.display()),
            Self::FileHandle { operation, source } => {
                write!(formatter, "could not {operation} inspection file handle: {source}")
            }
            Self::FileTooLarge(size) => write!(formatter, "PE image exceeds {MAX_PE_FILE_BYTES} bytes: {size}"),
            Self::ChangedDuringRead => formatter.write_str("PE image changed while it was being read"),
            Self::InvalidDosHeader => formatter.write_str("invalid DOS header"),
            Self::InvalidPeSignature => formatter.write_str("invalid PE signature"),
            Self::TruncatedImage => formatter.write_str("truncated PE image"),
            Self::IntegerOverflow => formatter.write_str("PE offset arithmetic overflow"),
            Self::InvalidSectionCount(count) => write!(formatter, "invalid PE section count: {count}"),
            Self::OptionalHeaderTooLarge(size) => write!(formatter, "PE optional header is too large: {size}"),
            Self::UnsupportedOptionalHeader(magic) => {
                write!(formatter, "unsupported PE optional header: 0x{magic:04x}")
            }
            Self::TruncatedOptionalHeader => formatter.write_str("truncated PE optional header"),
            Self::UnsupportedMachine { machine, format } => {
                write!(formatter, "unsupported PE machine 0x{machine:04x} for {format:?}")
            }
            Self::NotExecutableImage => formatter.write_str("COFF image is not marked executable"),
            Self::InvalidHeadersSize => formatter.write_str("invalid PE SizeOfHeaders"),
            Self::SectionOverlapsHeaders => formatter.write_str("PE section raw data overlaps image headers"),
            Self::OverlappingSections => formatter.write_str("PE sections have overlapping address ranges"),
            Self::InvalidSectionName => formatter.write_str("invalid PE section name"),
            Self::DuplicateSectionName(name) => write!(formatter, "duplicate PE section name: {name}"),
            Self::InvalidImportDirectory => formatter.write_str("invalid PE import directory"),
            Self::TooManyImports => formatter.write_str("PE import library limit exceeded"),
            Self::UnterminatedImportDirectory => formatter.write_str("unterminated PE import directory"),
            Self::ImportNameTooLong => formatter.write_str("PE import name is too long or unterminated"),
            Self::InvalidImportName => formatter.write_str("invalid PE import library name"),
            Self::UnmappedRva(rva) => write!(formatter, "PE RVA 0x{rva:08x} is not backed by file data"),
        }
    }
}

impl std::error::Error for InspectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Filesystem { source, .. } | Self::FileHandle { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0x00f0u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        bytes[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x0001_4000_0000_u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        bytes[optional + 120..optional + 124].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 124..optional + 128].copy_from_slice(&40u32.to_le_bytes());
        let section = optional + 0xf0;
        bytes[section..section + 8].copy_from_slice(b".rdata\0\0");
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        bytes[0x20c..0x210].copy_from_slice(&0x1040u32.to_le_bytes());
        bytes[0x240..0x24d].copy_from_slice(b"KERNEL32.dll\0");
        bytes
    }

    fn unique_test_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("compatforge-inspect-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn inspect_file_seeks_to_zero_and_leaves_ownership_with_the_caller() {
        let path = unique_test_path("offset.exe");
        fs::write(&path, fixture()).unwrap();
        let mut file = fs::File::open(&path).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();

        let report = inspect_file(&mut file).unwrap();

        assert_eq!(report, inspect_bytes(&fixture()).unwrap());
        assert_eq!(file.stream_position().unwrap(), fixture().len() as u64);
        file.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(file.metadata().unwrap().len(), fixture().len() as u64);
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inspect_file_keeps_inspecting_the_held_inode_after_source_rename() {
        let path = unique_test_path("rename.exe");
        let renamed = path.with_extension("held");
        let original = fixture();
        fs::write(&path, &original).unwrap();
        let mut file = fs::File::open(&path).unwrap();
        fs::rename(&path, &renamed).unwrap();
        fs::write(&path, b"replacement").unwrap();

        let report = inspect_file(&mut file).unwrap();

        assert_eq!(report, inspect_bytes(&original).unwrap());
        drop(file);
        fs::remove_file(path).unwrap();
        fs::remove_file(renamed).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inspect_file_rejects_non_regular_handles() {
        let directory = unique_test_path("directory");
        fs::create_dir(&directory).unwrap();
        let mut file = fs::File::open(&directory).unwrap();

        assert!(matches!(
            inspect_file(&mut file),
            Err(InspectionError::NotRegularFileHandle)
        ));

        drop(file);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn inspect_file_accepts_the_exact_size_limit_and_rejects_larger_files() {
        let exact_path = unique_test_path("exact-limit.exe");
        let exact = fs::File::create(&exact_path).unwrap();
        exact.set_len(MAX_PE_FILE_BYTES).unwrap();
        drop(exact);
        let mut exact = fs::File::open(&exact_path).unwrap();
        assert!(matches!(
            inspect_file(&mut exact),
            Err(InspectionError::InvalidDosHeader)
        ));
        drop(exact);
        fs::remove_file(exact_path).unwrap();

        let over_path = unique_test_path("over-limit.exe");
        let over = fs::File::create(&over_path).unwrap();
        over.set_len(MAX_PE_FILE_BYTES + 1).unwrap();
        drop(over);
        let mut over = fs::File::open(&over_path).unwrap();
        assert!(matches!(
            inspect_file(&mut over),
            Err(InspectionError::FileTooLarge(size)) if size == MAX_PE_FILE_BYTES + 1
        ));
        drop(over);
        fs::remove_file(over_path).unwrap();
    }

    #[test]
    fn inspect_file_rejects_a_short_read_after_metadata() {
        let path = unique_test_path("short.exe");
        fs::write(&path, fixture()).unwrap();
        let mut file = fs::File::open(&path).unwrap();

        let result = inspect_file_with_before_read(&mut file, || {
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(32)
                .unwrap();
        });

        assert!(matches!(result, Err(InspectionError::ChangedDuringRead)));
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inspect_file_rejects_growth_after_metadata() {
        use std::io::Write;

        let path = unique_test_path("growth.exe");
        fs::write(&path, fixture()).unwrap();
        let mut file = fs::File::open(&path).unwrap();

        let result = inspect_file_with_before_read(&mut file, || {
            let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
            writer.write_all(b"changed").unwrap();
        });

        assert!(matches!(result, Err(InspectionError::ChangedDuringRead)));
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inspect_file_caps_growth_reads_at_one_byte_beyond_the_limit() {
        let path = unique_test_path("bounded-growth.exe");
        fs::write(&path, fixture()).unwrap();
        let mut file = fs::File::open(&path).unwrap();

        let result = inspect_file_with_before_read(&mut file, || {
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(MAX_PE_FILE_BYTES + 2)
                .unwrap();
        });

        match result {
            Err(InspectionError::FileTooLarge(size)) => assert_eq!(size, MAX_PE_FILE_BYTES + 1),
            other => panic!("expected a bounded oversized-file error, got {other:?}"),
        }
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inspect_file_matches_the_existing_inspect_path_report() {
        let path = unique_test_path("compatibility.exe");
        fs::write(&path, fixture()).unwrap();
        let mut file = fs::File::open(&path).unwrap();

        assert_eq!(inspect_file(&mut file).unwrap(), inspect_path(&path).unwrap());

        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inspects_bounded_pe32_plus_metadata() {
        let report = inspect_bytes(&fixture()).unwrap();
        assert_eq!(report.schema_version, "1");
        assert_eq!(report.format, PeFormat::Pe32Plus);
        assert_eq!(report.architecture, PeArchitecture::X86_64);
        assert_eq!(report.image_kind, PeImageKind::Executable);
        assert_eq!(report.subsystem, PeSubsystem::WindowsConsole);
        assert_eq!(report.import_libraries, ["kernel32.dll"]);
        assert_eq!(report.sections[0].name, ".rdata");
        assert!(report.sections[0].readable);
        assert!(!report.sections[0].writable);
        assert!(report.file_digest.starts_with("sha256:"));
        assert_eq!(
            report.file_digest,
            "sha256:49c866f38f749fc92ded8749930b07eea51b1b8931492eff00c80c037ce46d02"
        );
    }

    #[test]
    fn rejects_malformed_headers_and_machine_mismatch() {
        let mut bytes = fixture();
        bytes[0] = 0;
        assert!(matches!(inspect_bytes(&bytes), Err(InspectionError::InvalidDosHeader)));

        let mut bytes = fixture();
        bytes[0x80] = 0;
        assert!(matches!(
            inspect_bytes(&bytes),
            Err(InspectionError::InvalidPeSignature)
        ));

        let mut bytes = fixture();
        bytes[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        assert!(matches!(
            inspect_bytes(&bytes),
            Err(InspectionError::UnsupportedMachine { .. })
        ));
    }

    #[test]
    fn rejects_unmapped_or_unterminated_imports() {
        let mut bytes = fixture();
        bytes[0x20c..0x210].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(matches!(
            inspect_bytes(&bytes),
            Err(InspectionError::UnmappedRva(0x9000))
        ));

        let mut bytes = fixture();
        bytes.copy_within(0x200..0x214, 0x214);
        assert!(matches!(
            inspect_bytes(&bytes),
            Err(InspectionError::UnterminatedImportDirectory)
        ));
    }

    #[test]
    fn rejects_relative_paths_without_reading_them() {
        assert!(matches!(
            inspect_path(Path::new("hello.exe")),
            Err(InspectionError::RelativePath(_))
        ));
    }

    #[test]
    fn rejects_file_size_before_reading_content() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("compatforge-inspect-{}-{nonce}.exe", std::process::id()));
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_PE_FILE_BYTES + 1).unwrap();
        drop(file);
        assert!(matches!(
            inspect_path(&path),
            Err(InspectionError::FileTooLarge(size)) if size == MAX_PE_FILE_BYTES + 1
        ));
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_replacement_between_check_and_open() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("compatforge-inspect-race-{}-{nonce}", std::process::id()));
        let inspected = directory.join("inspected.exe");
        let target = directory.join("target.exe");
        fs::create_dir(&directory).unwrap();
        fs::write(&inspected, fixture()).unwrap();
        fs::write(&target, fixture()).unwrap();

        let result = inspect_path_with_before_open(&inspected, || {
            fs::remove_file(&inspected).unwrap();
            symlink(&target, &inspected).unwrap();
        });

        assert!(matches!(
            result,
            Err(InspectionError::SymbolicLink(_)) | Err(InspectionError::Filesystem { .. })
        ));
        fs::remove_file(inspected).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn rejects_overlapping_sections() {
        let mut bytes = fixture();
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        let first_section = 0x188;
        let second_section = first_section + SECTION_HEADER_BYTES;
        let duplicate = bytes[first_section..first_section + SECTION_HEADER_BYTES].to_vec();
        bytes[second_section..second_section + SECTION_HEADER_BYTES].copy_from_slice(&duplicate);
        bytes[second_section..second_section + 8].copy_from_slice(b".data\0\0\0");
        assert!(matches!(
            inspect_bytes(&bytes),
            Err(InspectionError::OverlappingSections)
        ));
    }
}
