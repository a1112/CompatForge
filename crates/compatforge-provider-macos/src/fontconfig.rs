use crate::MacOsBootstrapError;
use compatforge_runtime::sha256_digest_bytes;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILE_ID: &str = "macos-cjk-fontconfig-v2";
const CONFIG_RELATIVE_ROOT: &[&str] = &["compatibility", "fontconfig", "objects", "sha256"];
const BOTTLE_FONT_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/STHeiti Medium.ttc",
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
];
const BOTTLE_FONT_ALIASES: &[&str] = &["Heiti SC", "Microsoft YaHei", "SimHei", "SimSun"];
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(1);

const CONFIG: &str = r#"<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <dir>/System/Library/Fonts</dir>
  <dir>/System/Library/Fonts/Supplemental</dir>
  <dir>/Library/Fonts</dir>
  <dir>~/Library/Fonts</dir>
  <alias>
    <family>Tahoma</family>
    <prefer>
      <family>Tahoma</family>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>Arial</family>
    <prefer>
      <family>Arial</family>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>Segoe UI</family>
    <prefer>
      <family>Tahoma</family>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>Microsoft YaHei UI</family>
    <prefer>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>Microsoft YaHei</family>
    <prefer>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>SimSun</family>
    <prefer>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>SimHei</family>
    <prefer>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <alias>
    <family>sans-serif</family>
    <prefer>
      <family>Arial</family>
      <family>Heiti SC</family>
      <family>Hiragino Sans GB</family>
    </prefer>
  </alias>
  <match target="pattern">
    <test name="family" compare="eq"><string>Tahoma</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
  <match target="pattern">
    <test name="family" compare="eq"><string>Arial</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
  <match target="pattern">
    <test name="family" compare="eq"><string>Segoe UI</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
  <match target="pattern">
    <test name="family" compare="eq"><string>Microsoft Sans Serif</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Tahoma</string>
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
  <match target="pattern">
    <test name="family" compare="eq"><string>MS Shell Dlg</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Tahoma</string>
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
  <match target="pattern">
    <test name="family" compare="eq"><string>MS Shell Dlg 2</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Tahoma</string>
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
  <match target="pattern">
    <test name="family" compare="eq"><string>System</string></test>
    <edit name="family" mode="append" binding="strong">
      <string>Tahoma</string>
      <string>Heiti SC</string>
      <string>Hiragino Sans GB</string>
    </edit>
  </match>
</fontconfig>
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsFontFallbackReceipt {
    pub profile_id: String,
    pub config_digest: String,
    pub fallback_families: Vec<String>,
    pub bottle_font_digest: String,
    pub bottle_font_aliases: Vec<String>,
}

pub(crate) struct InstalledMacOsFontFallback {
    pub receipt: MacOsFontFallbackReceipt,
    pub config_path: String,
    pub bottle_font_path: String,
}

pub(crate) fn install(storage_root: &Path) -> Result<InstalledMacOsFontFallback, MacOsBootstrapError> {
    let directory = create_directory_chain(storage_root, CONFIG_RELATIVE_ROOT)?;
    let digest = sha256_digest_bytes(CONFIG.as_bytes());
    let digest_hex = digest
        .strip_prefix("sha256:")
        .ok_or(MacOsBootstrapError::RegistrationFailed("font config digest"))?;
    let destination = directory.join(format!("{digest_hex}.conf"));
    publish_exact(&destination, CONFIG.as_bytes())?;
    let bottle_font_path = BOTTLE_FONT_CANDIDATES
        .iter()
        .map(Path::new)
        .find(|path| is_regular_file(path))
        .ok_or(MacOsBootstrapError::RegistrationFailed("Bottle CJK font"))?;
    let bottle_font_digest = crate::sha256_file(bottle_font_path)
        .map_err(|_| MacOsBootstrapError::RegistrationFailed("Bottle CJK font digest"))?;
    Ok(InstalledMacOsFontFallback {
        config_path: destination.to_string_lossy().into_owned(),
        bottle_font_path: bottle_font_path.to_string_lossy().into_owned(),
        receipt: MacOsFontFallbackReceipt {
            profile_id: PROFILE_ID.into(),
            config_digest: digest,
            fallback_families: vec!["Heiti SC".into(), "Hiragino Sans GB".into()],
            bottle_font_digest,
            bottle_font_aliases: BOTTLE_FONT_ALIASES.iter().map(|value| (*value).into()).collect(),
        },
    })
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

fn create_directory_chain(root: &Path, components: &[&str]) -> Result<PathBuf, MacOsBootstrapError> {
    let root_metadata =
        fs::symlink_metadata(root).map_err(|_| MacOsBootstrapError::RegistrationFailed("font config root"))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(MacOsBootstrapError::RegistrationFailed("font config root"));
    }
    let mut cursor = root.to_path_buf();
    for component in components {
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(MacOsBootstrapError::RegistrationFailed("font config directory"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&cursor)
                    .map_err(|_| MacOsBootstrapError::RegistrationFailed("font config directory"))?;
            }
            Err(_) => return Err(MacOsBootstrapError::RegistrationFailed("font config directory")),
        }
    }
    Ok(cursor)
}

fn publish_exact(destination: &Path, bytes: &[u8]) -> Result<(), MacOsBootstrapError> {
    match verify_exact(destination, bytes) {
        Ok(()) => return Ok(()),
        Err(VerifyError::Missing) => {}
        Err(VerifyError::Invalid) => {
            return Err(MacOsBootstrapError::RegistrationFailed("font config object"));
        }
    }

    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(MacOsBootstrapError::RegistrationFailed("font config object"))?;
    let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = destination.with_file_name(format!(".{file_name}.{}.{}", std::process::id(), counter));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("font config temporary"))?;
        output
            .write_all(bytes)
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("font config temporary"))?;
        output
            .sync_all()
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("font config temporary"))?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(_) => Err(MacOsBootstrapError::RegistrationFailed("font config publication")),
        }
    })();
    let _ = fs::remove_file(&temporary);
    result?;
    verify_exact(destination, bytes).map_err(|_| MacOsBootstrapError::RegistrationFailed("font config object"))
}

enum VerifyError {
    Missing,
    Invalid,
}

fn verify_exact(path: &Path, expected: &[u8]) -> Result<(), VerifyError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(VerifyError::Missing),
        Err(_) => return Err(VerifyError::Invalid),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != u64::try_from(expected.len()).map_err(|_| VerifyError::Invalid)?
    {
        return Err(VerifyError::Invalid);
    }
    let actual = fs::read(path).map_err(|_| VerifyError::Invalid)?;
    if actual == expected {
        Ok(())
    } else {
        Err(VerifyError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "compatforge-fontconfig-{label}-{}-{}",
            std::process::id(),
            TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn publishes_an_idempotent_content_addressed_font_configuration() {
        let root = temporary_root("publish");
        let first = install(&root).unwrap();
        let second = install(&root).unwrap();
        assert_eq!(first.receipt, second.receipt);
        assert_eq!(first.config_path, second.config_path);
        assert_eq!(first.bottle_font_path, second.bottle_font_path);
        assert_eq!(fs::read(&first.config_path).unwrap(), CONFIG.as_bytes());
        assert!(first.receipt.bottle_font_digest.starts_with("sha256:"));
        assert!(!serde_json::to_string(&first.receipt)
            .unwrap()
            .contains("/System/Library"));
        assert!(first
            .config_path
            .ends_with(&format!("{}.conf", &first.receipt.config_digest[7..])));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_a_tampered_or_redirected_font_configuration() {
        let root = temporary_root("tamper");
        let installed = install(&root).unwrap();
        fs::write(&installed.config_path, b"tampered").unwrap();
        assert!(install(&root).is_err());
        fs::remove_file(&installed.config_path).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/dev/null", &installed.config_path).unwrap();
        #[cfg(unix)]
        assert!(install(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
