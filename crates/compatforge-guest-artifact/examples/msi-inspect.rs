//! Verify a fixed MSI pin without installation or mutable staging.
use compatforge_domain::{CpuArchitecture, InstallPackage};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: msi-inspect ABSOLUTE_MSI SHA256 SIZE_BYTES x86_64|i386".into());
    }
    let path = std::path::Path::new(&args[0]);
    let package = InstallPackage {
        path: args[0].clone(),
        file_name: path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid filename")?
            .into(),
        sha256: args[1].clone(),
        size_bytes: args[2].parse()?,
        media_type: "application/x-msi".into(),
    };
    let architecture = match args[3].as_str() {
        "x86_64" => CpuArchitecture::X86_64,
        "i386" => CpuArchitecture::I386,
        _ => return Err("unsupported architecture".into()),
    };
    compatforge_guest_artifact::inspect_msi_package(&package, architecture)?;
    println!(
        "Verified MSI installer type, architecture {}, size {} and SHA-256 {}. No installation performed.",
        architecture.as_str(),
        package.size_bytes,
        package.sha256
    );
    Ok(())
}
