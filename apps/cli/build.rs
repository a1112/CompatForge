use std::path::Path;
use std::process::Command;

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("-C").arg(root).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in [
        "apps",
        "crates",
        "contracts",
        "schemas",
        "packaging",
        "tools",
        "Cargo.toml",
        "Cargo.lock",
        ".git/HEAD",
        ".git/index",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    if let Some(reference) = git(&root, &["symbolic-ref", "--quiet", "HEAD"]) {
        println!("cargo:rerun-if-changed={}", root.join(".git").join(reference).display());
    }
    // No override permits an archive/dirty build to impersonate a pinned commit.
    let source = git(&root, &["rev-parse", "HEAD"])
        .filter(|value| value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".into());
    let dirty = git(&root, &["status", "--porcelain", "--untracked-files=normal"])
        .map(|value| !value.is_empty())
        .unwrap_or(true);
    println!("cargo:rustc-env=FORGE_PROVIDER_SOURCE={source}");
    println!("cargo:rustc-env=FORGE_PROVIDER_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=FORGE_PROVIDER_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
}
