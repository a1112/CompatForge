//! Read-only recipe diagnostics for an already pinned official MSI; never installs.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: msi-tables ABSOLUTE_MSI SHA256 SIZE_BYTES x86_64|i386".into());
    }
    let path = std::path::Path::new(&args[0]);
    let package = compatforge_domain::InstallPackage {
        path: args[0].clone(),
        file_name: path.file_name().and_then(|s| s.to_str()).ok_or("filename")?.into(),
        sha256: args[1].clone(),
        size_bytes: args[2].parse()?,
        media_type: "application/x-msi".into(),
    };
    let architecture = match args[3].as_str() {
        "x86_64" => compatforge_domain::CpuArchitecture::X86_64,
        "i386" => compatforge_domain::CpuArchitecture::I386,
        _ => return Err("architecture".into()),
    };
    compatforge_guest_artifact::inspect_msi_package(&package, architecture)?;
    let mut database = msi::open(path)?;
    for name in ["Property", "Directory", "Component", "File", "Media", "CustomAction"] {
        if !database.has_table(name) {
            continue;
        }
        let rows = database.select_rows(msi::Select::table(name))?;
        let columns: Vec<_> = rows.columns().iter().map(|c| c.name().to_owned()).collect();
        let mut values = Vec::new();
        for row in rows.take(5000) {
            values.push((0..columns.len()).map(|i| row[i].to_string()).collect::<Vec<_>>());
        }
        println!(
            "{}",
            serde_json::json!({"table":name,"columns":columns,"rows":values,"limit":5000})
        );
    }
    Ok(())
}
