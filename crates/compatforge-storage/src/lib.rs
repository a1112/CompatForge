//! Cross-platform application paths and recoverable JSON persistence.

#![forbid(unsafe_code)]

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::fs::File;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoragePlatform {
    MacOs,
    Linux,
    Android,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    #[must_use]
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_environment(
        platform: StoragePlatform,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, PathError> {
        if let Some(root) = non_empty(environment, "COMPATFORGE_HOME") {
            return Ok(Self::from_root(root));
        }

        let root = match platform {
            StoragePlatform::MacOs => PathBuf::from(required(environment, "HOME")?)
                .join("Library")
                .join("Application Support")
                .join("CompatForge"),
            StoragePlatform::Linux => {
                let data_home = match non_empty(environment, "XDG_DATA_HOME") {
                    Some(value) => PathBuf::from(value),
                    None => PathBuf::from(required(environment, "HOME")?)
                        .join(".local")
                        .join("share"),
                };
                data_home.join("compatforge")
            }
            StoragePlatform::Windows => PathBuf::from(required(environment, "LOCALAPPDATA")?).join("CompatForge"),
            StoragePlatform::Android => {
                return Err(PathError::ExplicitRootRequired(StoragePlatform::Android));
            }
        };

        if root.as_os_str().is_empty() {
            return Err(PathError::MissingEnvironment("HOME"));
        }
        Ok(Self::from_root(root))
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn bottles(&self) -> PathBuf {
        self.root.join("bottles")
    }

    #[must_use]
    pub fn bottle(&self, id: &str) -> PathBuf {
        self.bottles().join(id)
    }

    #[must_use]
    pub fn runtime_packs(&self) -> PathBuf {
        self.root.join("runtime-packs")
    }

    #[must_use]
    pub fn recipes(&self) -> PathBuf {
        self.root.join("recipes")
    }

    #[must_use]
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }
}

fn non_empty<'a>(environment: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    environment
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn required<'a>(environment: &'a BTreeMap<String, String>, key: &'static str) -> Result<&'a str, PathError> {
    non_empty(environment, key).ok_or(PathError::MissingEnvironment(key))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    MissingEnvironment(&'static str),
    ExplicitRootRequired(StoragePlatform),
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(key) => write!(formatter, "missing environment variable {key}"),
            Self::ExplicitRootRequired(platform) => {
                write!(formatter, "{platform:?} requires an explicit COMPATFORGE_HOME")
            }
        }
    }
}

impl std::error::Error for PathError {}

#[derive(Debug, Clone)]
pub struct JsonStore {
    root: PathBuf,
}

impl JsonStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn read<T: DeserializeOwned>(&self, relative_path: impl AsRef<Path>) -> Result<T, StoreError> {
        let path = self.resolve(relative_path.as_ref())?;
        let bytes = fs::read(path).map_err(StoreError::Io)?;
        serde_json::from_slice(&bytes).map_err(StoreError::Json)
    }

    pub fn write<T: Serialize>(&self, relative_path: impl AsRef<Path>, value: &T) -> Result<(), StoreError> {
        self.write_with_directory_sync(relative_path, value, sync_directory)
    }

    fn write_with_directory_sync<T: Serialize>(
        &self,
        relative_path: impl AsRef<Path>,
        value: &T,
        directory_sync: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        self.write_with_publish(relative_path, value, replace_file, directory_sync)
    }

    fn write_with_publish<T: Serialize>(
        &self,
        relative_path: impl AsRef<Path>,
        value: &T,
        publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
        directory_sync: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let path = self.resolve(relative_path.as_ref())?;
        let parent = path.parent().ok_or(StoreError::InvalidRelativePath)?;
        fs::create_dir_all(parent).map_err(StoreError::Io)?;

        let mut bytes = serde_json::to_vec_pretty(value).map_err(StoreError::Json)?;
        bytes.push(b'\n');

        let temporary = temporary_path(&path)?;
        let result = (|| {
            let mut file = create_private_temporary(&temporary)?;
            file.write_all(&bytes).map_err(StoreError::Io)?;
            file.sync_all().map_err(StoreError::Io)?;
            publish(&temporary, &path).map_err(StoreError::Io)?;
            directory_sync(parent).map_err(StoreError::DurabilityUncertain)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    #[must_use]
    pub fn exists(&self, relative_path: impl AsRef<Path>) -> bool {
        self.resolve(relative_path.as_ref()).is_ok_and(|path| path.is_file())
    }

    fn resolve(&self, relative_path: &Path) -> Result<PathBuf, StoreError> {
        if relative_path.as_os_str().is_empty()
            || relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StoreError::InvalidRelativePath);
        }
        Ok(self.root.join(relative_path))
    }
}

fn create_private_temporary(path: &Path) -> Result<fs::File, StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let file = options.open(path).map_err(StoreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(StoreError::Io(error));
        }
    }
    Ok(file)
}

fn temporary_path(target: &Path) -> Result<PathBuf, StoreError> {
    let file_name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(StoreError::InvalidRelativePath)?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(target.with_file_name(format!(".{file_name}.tmp-{}-{counter}", std::process::id())))
}

fn replace_file(temporary: &Path, target: &Path) -> io::Result<()> {
    // Rust 1.78 implements this with rename(2) on Unix and
    // MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows. Both replace the
    // destination without first removing the visible target path.
    fs::rename(temporary, target)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path).and_then(|directory| directory.sync_all())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug)]
pub enum StoreError {
    InvalidRelativePath,
    Io(io::Error),
    /// The replacement is visible, but syncing its parent directory failed.
    /// Callers must not retry as though the old value were still active.
    DurabilityUncertain(io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelativePath => formatter.write_str("store path must be a non-empty relative path"),
            Self::Io(error) => write!(formatter, "store I/O failed: {error}"),
            Self::DurabilityUncertain(error) => {
                write!(formatter, "store commit durability is uncertain: {error}")
            }
            Self::Json(error) => write!(formatter, "store JSON failed: {error}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRelativePath => None,
            Self::Io(error) | Self::DurabilityUncertain(error) => Some(error),
            Self::Json(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
    struct Fixture {
        schema_version: String,
        value: u32,
    }

    fn temporary_directory(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("compatforge-{test_name}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn resolves_platform_roots_without_developer_paths() {
        let mut environment = BTreeMap::new();
        environment.insert("HOME".into(), "/home/tester".into());
        let linux = AppPaths::from_environment(StoragePlatform::Linux, &environment).unwrap();
        assert_eq!(linux.root(), Path::new("/home/tester/.local/share/compatforge"));

        environment.insert("COMPATFORGE_HOME".into(), "/srv/compatforge".into());
        let android = AppPaths::from_environment(StoragePlatform::Android, &environment).unwrap();
        assert_eq!(android.root(), Path::new("/srv/compatforge"));
    }

    #[test]
    fn writes_reads_and_replaces_json() {
        let directory = temporary_directory("json-store");
        let store = JsonStore::new(&directory);
        let relative = Path::new("bottles/example.json");

        store
            .write(
                relative,
                &Fixture {
                    schema_version: "1".into(),
                    value: 1,
                },
            )
            .unwrap();
        store
            .write(
                relative,
                &Fixture {
                    schema_version: "1".into(),
                    value: 2,
                },
            )
            .unwrap();

        let restored: Fixture = store.read(relative).unwrap();
        assert_eq!(restored.value, 2);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_paths_that_escape_the_store() {
        let store = JsonStore::new(temporary_directory("traversal"));
        let error = store
            .write(
                "../outside.json",
                &Fixture {
                    schema_version: "1".into(),
                    value: 1,
                },
            )
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidRelativePath));
    }

    #[test]
    fn post_rename_directory_sync_failure_is_typed_and_keeps_published_value() {
        for existing in [false, true] {
            let directory = temporary_directory("post-rename-sync");
            let store = JsonStore::new(&directory);
            let relative = Path::new("state.json");
            if existing {
                store
                    .write(
                        relative,
                        &Fixture {
                            schema_version: "1".into(),
                            value: 1,
                        },
                    )
                    .unwrap();
            }
            let error = store
                .write_with_directory_sync(
                    relative,
                    &Fixture {
                        schema_version: "1".into(),
                        value: 9,
                    },
                    |_| Err(io::Error::other("injected directory sync failure")),
                )
                .unwrap_err();

            assert!(matches!(error, StoreError::DurabilityUncertain(_)));
            assert_eq!(store.read::<Fixture>(relative).unwrap().value, 9);
            assert!(fs::read_dir(&directory).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")));
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn pre_rename_failure_is_not_uncertain_and_preserves_existing_value() {
        let directory = temporary_directory("pre-rename-failure");
        let store = JsonStore::new(&directory);
        let relative = Path::new("state.json");
        store
            .write(
                relative,
                &Fixture {
                    schema_version: "1".into(),
                    value: 3,
                },
            )
            .unwrap();
        let error = store
            .write_with_publish(
                relative,
                &Fixture {
                    schema_version: "1".into(),
                    value: 4,
                },
                |_, _| Err(io::Error::other("injected rename failure")),
                |_| Ok(()),
            )
            .unwrap_err();
        assert!(matches!(error, StoreError::Io(_)));
        assert_eq!(store.read::<Fixture>(relative).unwrap().value, 3);
        assert!(fs::read_dir(&directory).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn json_store_private_mode_is_independent_of_umask() {
        use std::process::Command;

        use std::os::unix::fs::PermissionsExt;

        for mask in ["0000", "0002", "0777"] {
            let root = temporary_directory(&format!("umask-{mask}"));
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg("umask \"$1\"; export COMPATFORGE_STORAGE_UMASK_ROOT=\"$2\"; exec \"$3\" --ignored --exact tests::json_store_private_mode_child --nocapture")
                .arg("compatforge-storage-umask")
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
    fn json_store_private_mode_child() {
        use std::os::unix::fs::PermissionsExt;

        let root = PathBuf::from(std::env::var_os("COMPATFORGE_STORAGE_UMASK_ROOT").expect("child root"));
        let store = JsonStore::new(&root);
        store
            .write(
                "state.json",
                &Fixture {
                    schema_version: "1".into(),
                    value: 7,
                },
            )
            .unwrap();
        let target = root.join("state.json");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(store.read::<Fixture>("state.json").unwrap().value, 7);
        assert!(fs::read_dir(&root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
    }
}
