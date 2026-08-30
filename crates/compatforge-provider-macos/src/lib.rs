//! Verified macOS Wine, Rosetta, and graphics Provider integration.

#![forbid(unsafe_code)]

use compatforge_domain::{
    validate_digest, validate_id, validate_portable_relative_path, validate_schema_version, CapabilityObservation,
    CapabilityReport, CapabilityValue, ContractError, CoreConfig, CpuArchitecture, HostOs, ProbeSource, ProbeStatus,
    ProviderDescriptor, RuntimeBinding, RuntimeChannel, RuntimeComponent, RuntimeHost, RuntimePackManifest,
    SandboxProfile, SupervisorPolicy, SCHEMA_VERSION_V1,
};
use compatforge_runtime::{sha256_digest_bytes, RejectAllSignatures, RuntimePackStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROBE_OUTPUT_BYTES: u64 = 64 * 1024;
const AUTO_PACK_ID: &str = "wine-macos-auto-preview";
const AUTO_CAPABILITIES: &[&str] = &["guest-i386", "guest-x86_64", "new-wow64"];
const AUTO_WINED3D_CAPABILITIES: &[&str] = &["d3d9", "d3d11", "opengl"];

/// Configuration emitted by a trusted Runtime Pack materializer.
///
/// Every executable path is relative to `materializedRoot`, every relevant
/// file is bound to a SHA-256 digest, and the source Runtime Pack is verified
/// again before any Provider binary is executed.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacOsProviderConfig {
    pub schema_version: String,
    pub runtime_store_root: String,
    pub wine_runtime: WineRuntimeConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WineRuntimeConfig {
    pub provider_id: String,
    pub pack_id: String,
    pub pack_digest: String,
    pub version: String,
    pub architecture: CpuArchitecture,
    pub materialized_root: String,
    pub wine: VerifiedEntrypoint,
    pub wineserver: VerifiedEntrypoint,
    pub capabilities: Vec<String>,
    pub wined3d_capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d3dmetal: Option<GraphicsPluginConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedEntrypoint {
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphicsPluginConfig {
    pub provider_id: String,
    pub version: String,
    pub probe_file: VerifiedEntrypoint,
    pub capabilities: Vec<String>,
}

/// Minimal, path-bearing input accepted by the Rust bootstrap boundary. The
/// optional override is all-or-nothing so callers cannot mix a discovered
/// executable with an unverified root or version.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacOsLocalContextRequest {
    pub schema_version: String,
    pub runtime_store_root: String,
    pub storage_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialized_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wineserver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl MacOsLocalContextRequest {
    fn validate(&self) -> Result<(), MacOsBootstrapError> {
        validate_schema_version(&self.schema_version).map_err(MacOsBootstrapError::Contract)?;
        if !serialized_path_is_absolute(&self.runtime_store_root) {
            return Err(MacOsBootstrapError::InvalidRequest("runtimeStoreRoot"));
        }
        if !serialized_path_is_absolute(&self.storage_root) {
            return Err(MacOsBootstrapError::InvalidRequest("storageRoot"));
        }
        let supplied = [
            self.materialized_root.is_some(),
            self.wine.is_some(),
            self.wineserver.is_some(),
            self.version.is_some(),
        ];
        if supplied.iter().any(|value| *value) && !supplied.iter().all(|value| *value) {
            return Err(MacOsBootstrapError::InvalidRequest("runtime override quartet"));
        }
        if let Some(root) = &self.materialized_root {
            if !serialized_path_is_absolute(root) {
                return Err(MacOsBootstrapError::InvalidRequest("materializedRoot"));
            }
            validate_portable_relative_path("wine", self.wine.as_deref().unwrap())
                .map_err(MacOsBootstrapError::Contract)?;
            validate_portable_relative_path("wineserver", self.wineserver.as_deref().unwrap())
                .map_err(MacOsBootstrapError::Contract)?;
            if self.version.as_deref().unwrap().is_empty() {
                return Err(MacOsBootstrapError::InvalidRequest("version"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsLocalContextReceipt {
    pub schema_version: String,
    pub source: String,
    pub version: String,
    pub architecture: CpuArchitecture,
    pub pack_id: String,
    pub pack_digest: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MacOsLocalContext {
    pub config: CoreConfig,
    pub receipt: MacOsLocalContextReceipt,
}

#[derive(Debug, Clone)]
struct DiscoveredWine {
    source: String,
    materialized_root: PathBuf,
    wine: String,
    wineserver: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalWineCandidate {
    source: &'static str,
    root: PathBuf,
    wine: &'static str,
    wineserver: &'static str,
}

impl MacOsProviderConfig {
    pub fn validate(&self) -> Result<(), MacOsProviderError> {
        validate_schema_version(&self.schema_version)?;
        if !serialized_path_is_absolute(&self.runtime_store_root) {
            return Err(MacOsProviderError::InvalidConfig("runtimeStoreRoot"));
        }
        self.wine_runtime.validate()
    }
}

impl WineRuntimeConfig {
    fn validate(&self) -> Result<(), MacOsProviderError> {
        validate_id("macosProvider.wineRuntime.providerId", &self.provider_id)?;
        validate_id("macosProvider.wineRuntime.packId", &self.pack_id)?;
        validate_digest("macosProvider.wineRuntime.packDigest", &self.pack_digest)?;
        if self.version.is_empty() {
            return Err(MacOsProviderError::InvalidConfig("wineRuntime.version"));
        }
        if !matches!(self.architecture, CpuArchitecture::X86_64 | CpuArchitecture::Arm64) {
            return Err(MacOsProviderError::InvalidConfig("wineRuntime.architecture"));
        }
        if !serialized_path_is_absolute(&self.materialized_root) {
            return Err(MacOsProviderError::InvalidConfig("wineRuntime.materializedRoot"));
        }
        self.wine.validate("wineRuntime.wine")?;
        self.wineserver.validate("wineRuntime.wineserver")?;
        validate_capabilities(&self.capabilities, ProviderCapabilityClass::Runtime)?;
        validate_capabilities(&self.wined3d_capabilities, ProviderCapabilityClass::Graphics)?;
        if let Some(plugin) = &self.d3dmetal {
            plugin.validate()?;
        }
        Ok(())
    }
}

impl VerifiedEntrypoint {
    fn validate(&self, field: &'static str) -> Result<(), MacOsProviderError> {
        validate_portable_relative_path(field, &self.path)?;
        validate_digest(field, &self.digest)?;
        Ok(())
    }
}

impl GraphicsPluginConfig {
    fn validate(&self) -> Result<(), MacOsProviderError> {
        validate_id("macosProvider.d3dmetal.providerId", &self.provider_id)?;
        if self.version.is_empty() {
            return Err(MacOsProviderError::InvalidConfig("d3dmetal.version"));
        }
        self.probe_file.validate("macosProvider.d3dmetal.probeFile")?;
        validate_capabilities(&self.capabilities, ProviderCapabilityClass::Graphics)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsProviderSnapshot {
    pub capabilities: CapabilityReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_binding: Option<RuntimeBinding>,
}

impl MacOsProviderSnapshot {
    pub fn core_config(&self, storage_root: String) -> Result<CoreConfig, MacOsProviderError> {
        if !serialized_path_is_absolute(&storage_root) {
            return Err(MacOsProviderError::InvalidConfig("storageRoot"));
        }
        let storage_root_path = Path::new(&storage_root);
        fs::create_dir_all(storage_root_path).map_err(|_| MacOsProviderError::InvalidConfig("storageRoot"))?;
        let storage_root = fs::canonicalize(storage_root_path)
            .map_err(|_| MacOsProviderError::InvalidConfig("storageRoot"))?
            .to_string_lossy()
            .into_owned();
        let runtime_binding = self
            .runtime_binding
            .clone()
            .ok_or(MacOsProviderError::ProviderUnavailable)?;
        let config = CoreConfig {
            schema_version: compatforge_domain::SCHEMA_VERSION_V1.into(),
            capabilities: self.capabilities.clone(),
            runtime_bindings: vec![runtime_binding],
            storage_root,
            sandbox_profile: SandboxProfile::Desktop,
            supervisor: SupervisorPolicy::default(),
        };
        config.validate()?;
        Ok(config)
    }
}

pub struct MacOsProviderSet;

impl MacOsProviderSet {
    /// Probe only explicitly configured, digest-bound Provider entrypoints.
    ///
    /// This method never scans `PATH`, downloads content, invokes a shell, or
    /// relies on `/usr/bin/arch`. An x86_64 Wine version probe that succeeds in
    /// an ARM64 process is the Runtime-specific evidence for Rosetta.
    pub fn probe(
        host_report: &CapabilityReport,
        config: &MacOsProviderConfig,
    ) -> Result<MacOsProviderSnapshot, MacOsProviderError> {
        Self::probe_with(host_report, config, &SystemProbeCommand)
    }

    pub fn probe_with(
        host_report: &CapabilityReport,
        config: &MacOsProviderConfig,
        command: &dyn ProbeCommand,
    ) -> Result<MacOsProviderSnapshot, MacOsProviderError> {
        host_report.validate()?;
        config.validate()?;
        if host_report.host.os != HostOs::MacOs {
            return Err(MacOsProviderError::UnsupportedHost);
        }

        let wine_result = probe_wine(host_report.host.architecture, config, command);
        let (wine_available, wine_reason, wine_evidence) = match wine_result {
            Ok(evidence) => (true, None, Some(evidence)),
            Err(reason) => (false, Some(reason.as_str().into()), None),
        };

        let runtime = &config.wine_runtime;
        let mut report = host_report.clone();
        report.runtime_providers = vec![ProviderDescriptor {
            id: runtime.provider_id.clone(),
            kind: "wine".into(),
            version: runtime.version.clone(),
            available: wine_available,
            reason: wine_reason.clone(),
            capabilities: runtime.capabilities.clone(),
        }];

        report.translators.retain(|provider| provider.kind == "native");
        let rosetta_available = wine_evidence.as_ref().is_some_and(|evidence| evidence.used_rosetta);
        report.translators.push(ProviderDescriptor {
            id: "macos-rosetta-runtime".into(),
            kind: "rosetta".into(),
            version: "system".into(),
            available: rosetta_available,
            reason: (!rosetta_available)
                .then(|| rosetta_unavailable_reason(host_report, runtime, wine_reason.as_deref())),
            capabilities: vec!["i386-on-arm64".into(), "x86_64-on-arm64".into()],
        });

        let wined3d_available = wine_available;
        report.graphics_backends = vec![ProviderDescriptor {
            id: "macos-wined3d".into(),
            kind: "wined3d".into(),
            version: runtime.version.clone(),
            available: wined3d_available,
            reason: (!wined3d_available).then(|| "Wine Runtime Provider is unavailable".into()),
            capabilities: runtime.wined3d_capabilities.clone(),
        }];

        let d3dmetal_result = runtime
            .d3dmetal
            .as_ref()
            .map(|plugin| probe_graphics_plugin(runtime, plugin));
        match (&runtime.d3dmetal, d3dmetal_result) {
            (Some(plugin), Some(Ok(()))) if wine_available => report.graphics_backends.push(ProviderDescriptor {
                id: plugin.provider_id.clone(),
                kind: "d3dmetal".into(),
                version: plugin.version.clone(),
                available: true,
                reason: None,
                capabilities: plugin.capabilities.clone(),
            }),
            (Some(plugin), Some(result)) => report.graphics_backends.push(ProviderDescriptor {
                id: plugin.provider_id.clone(),
                kind: "d3dmetal".into(),
                version: plugin.version.clone(),
                available: false,
                reason: Some(match result {
                    Ok(()) => "Wine Runtime Provider is unavailable".into(),
                    Err(reason) => reason.as_str().into(),
                }),
                capabilities: plugin.capabilities.clone(),
            }),
            (None, None) => report.graphics_backends.push(ProviderDescriptor {
                id: "macos-d3dmetal-external".into(),
                kind: "d3dmetal".into(),
                version: "external".into(),
                available: false,
                reason: Some("external D3DMetal plugin is not configured".into()),
                capabilities: vec!["d3d11".into(), "d3d12".into(), "metal".into()],
            }),
            _ => return Err(MacOsProviderError::InvalidConfig("d3dmetal")),
        }

        upsert_observation(
            &mut report,
            provider_observation(
                "provider.macos-wine",
                "runtime",
                ProbeSource::RuntimePack,
                wine_available,
                wine_reason.as_deref(),
            ),
        );
        upsert_observation(
            &mut report,
            provider_observation(
                "provider.macos-rosetta",
                "translator",
                ProbeSource::RuntimePack,
                rosetta_available,
                (!rosetta_available)
                    .then(|| rosetta_unavailable_reason(host_report, runtime, wine_reason.as_deref()))
                    .as_deref(),
            ),
        );
        upsert_observation(
            &mut report,
            provider_observation(
                "provider.macos-wined3d",
                "graphics",
                ProbeSource::RuntimePack,
                wined3d_available,
                (!wined3d_available).then_some("Wine Runtime Provider is unavailable"),
            ),
        );
        let (d3dmetal_available, d3dmetal_reason) = report
            .graphics_backends
            .iter()
            .find(|provider| provider.kind == "d3dmetal")
            .map(|provider| (provider.available, provider.reason.clone()))
            .ok_or(MacOsProviderError::InvalidConfig("d3dmetal"))?;
        upsert_observation(
            &mut report,
            provider_observation(
                "provider.macos-d3dmetal",
                "graphics",
                ProbeSource::RuntimePack,
                d3dmetal_available,
                d3dmetal_reason.as_deref(),
            ),
        );

        canonicalize_report(&mut report);
        report.validate()?;

        let runtime_binding = wine_evidence.map(|evidence| {
            let wineserver = evidence.wineserver_path.to_string_lossy().into_owned();
            let mut environment: BTreeMap<String, String> = [
                ("COMPATFORGE_RUNTIME_PACK".into(), runtime.pack_id.clone()),
                ("COMPATFORGE_RUNTIME_PACK_DIGEST".into(), runtime.pack_digest.clone()),
                (
                    "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256".into(),
                    runtime.wine.digest.clone(),
                ),
                (
                    "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256".into(),
                    runtime.wineserver.digest.clone(),
                ),
                ("WINEDEBUG".into(), "-all".into()),
                ("WINESERVER".into(), wineserver.clone()),
            ]
            .into_iter()
            .collect();
            if let Some(path) = interactive_wine_dll_path(&evidence.wine_path) {
                environment.insert("WINEDLLPATH".into(), path.to_string_lossy().into_owned());
            }
            RuntimeBinding {
                provider_id: runtime.provider_id.clone(),
                pack_id: runtime.pack_id.clone(),
                pack_digest: runtime.pack_digest.clone(),
                executable: evidence.wine_path.to_string_lossy().into_owned(),
                wineserver_executable: Some(wineserver),
                environment,
                working_directory: None,
            }
        });

        Ok(MacOsProviderSnapshot {
            capabilities: report,
            runtime_binding,
        })
    }
}

/// Discover a verified local x86_64 Wine from the closed candidate list and
/// register it as a local preview Runtime Pack. No PATH lookup, shell, network,
/// or recursive directory traversal is involved.
pub fn create_local_context(
    host_report: &CapabilityReport,
    request: &MacOsLocalContextRequest,
) -> Result<MacOsLocalContext, MacOsBootstrapError> {
    create_local_context_with(host_report, request, &SystemProbeCommand)
}

pub fn create_local_context_with(
    host_report: &CapabilityReport,
    request: &MacOsLocalContextRequest,
    command: &dyn ProbeCommand,
) -> Result<MacOsLocalContext, MacOsBootstrapError> {
    request.validate()?;
    host_report.validate().map_err(MacOsBootstrapError::Contract)?;
    if host_report.host.os != HostOs::MacOs || host_report.host.architecture != CpuArchitecture::Arm64 {
        return Err(MacOsBootstrapError::UnsupportedHost);
    }
    let runtime_store_root = canonical_bootstrap_directory(&request.runtime_store_root, "runtimeStoreRoot")?;
    let storage_root = canonical_bootstrap_directory(&request.storage_root, "storageRoot")?;
    if runtime_store_root == storage_root
        || runtime_store_root.starts_with(&storage_root)
        || storage_root.starts_with(&runtime_store_root)
    {
        return Err(MacOsBootstrapError::InvalidRequest("runtime/storage root overlap"));
    }
    let discovered = if let (Some(materialized_root), Some(wine), Some(wineserver), Some(version)) = (
        request.materialized_root.as_deref(),
        request.wine.as_deref(),
        request.wineserver.as_deref(),
        request.version.as_deref(),
    ) {
        verify_discovered_candidate(
            "explicit-override",
            Path::new(materialized_root),
            wine,
            wineserver,
            version,
            command,
        )?
    } else {
        discover_local_wine(host_report, command)?
    };

    let pack_digest = register_preview_pack(&runtime_store_root.to_string_lossy(), &discovered)?;
    let provider_config = MacOsProviderConfig {
        schema_version: SCHEMA_VERSION_V1.into(),
        runtime_store_root: runtime_store_root.to_string_lossy().into_owned(),
        wine_runtime: WineRuntimeConfig {
            provider_id: AUTO_PACK_ID.into(),
            pack_id: AUTO_PACK_ID.into(),
            pack_digest: pack_digest.clone(),
            version: discovered.version.clone(),
            architecture: CpuArchitecture::X86_64,
            materialized_root: discovered.materialized_root.to_string_lossy().into_owned(),
            wine: VerifiedEntrypoint {
                path: discovered.wine.clone(),
                digest: sha256_file(&discovered.materialized_root.join(&discovered.wine))
                    .map_err(|_| MacOsBootstrapError::RegistrationFailed("wine digest"))?,
            },
            wineserver: VerifiedEntrypoint {
                path: discovered.wineserver.clone(),
                digest: sha256_file(&discovered.materialized_root.join(&discovered.wineserver))
                    .map_err(|_| MacOsBootstrapError::RegistrationFailed("wineserver digest"))?,
            },
            capabilities: AUTO_CAPABILITIES.iter().map(|value| (*value).into()).collect(),
            wined3d_capabilities: AUTO_WINED3D_CAPABILITIES.iter().map(|value| (*value).into()).collect(),
            d3dmetal: None,
        },
    };
    let snapshot =
        MacOsProviderSet::probe_with(host_report, &provider_config, command).map_err(MacOsBootstrapError::Provider)?;
    let config = snapshot
        .core_config(storage_root.to_string_lossy().into_owned())
        .map_err(MacOsBootstrapError::Provider)?;
    let mut capabilities = provider_config.wine_runtime.capabilities.clone();
    capabilities.push("windows-gui".into());
    capabilities.sort();
    capabilities.dedup();
    Ok(MacOsLocalContext {
        config,
        receipt: MacOsLocalContextReceipt {
            schema_version: SCHEMA_VERSION_V1.into(),
            source: discovered.source,
            version: discovered.version,
            architecture: CpuArchitecture::X86_64,
            pack_id: AUTO_PACK_ID.into(),
            pack_digest,
            capabilities,
        },
    })
}

fn discover_local_wine(
    host_report: &CapabilityReport,
    command: &dyn ProbeCommand,
) -> Result<DiscoveredWine, MacOsBootstrapError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let candidates = local_wine_candidates(home.as_deref());
    for candidate in candidates {
        if let Ok(discovered) = verify_discovered_candidate(
            candidate.source,
            &candidate.root,
            candidate.wine,
            candidate.wineserver,
            "",
            command,
        ) {
            return Ok(discovered);
        }
    }
    let _ = host_report;
    Err(MacOsBootstrapError::DiscoveryFailed)
}

fn local_wine_candidates(home: Option<&Path>) -> Vec<LocalWineCandidate> {
    let mut candidates = Vec::new();
    let mut add = |source: &'static str, root: PathBuf, wine: &'static str, wineserver: &'static str| {
        candidates.push(LocalWineCandidate {
            source,
            root,
            wine,
            wineserver,
        });
    };

    for app_root in [
        Some(PathBuf::from(
            "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver",
        )),
        home.map(|home| home.join("Applications/CrossOver.app/Contents/SharedSupport/CrossOver")),
    ]
    .into_iter()
    .flatten()
    {
        // CrossOver's wineloader is the supported launcher entrypoint. Keep
        // the legacy wine wrapper immediately after it for older installs.
        add("crossover-app", app_root.clone(), "bin/wineloader", "bin/wineserver");
        add("crossover-app", app_root, "bin/wine", "bin/wineserver");
    }

    add(
        "whisky-app",
        PathBuf::from("/Applications/Whisky.app/Contents/Resources/Libraries/Wine"),
        "bin/wine64",
        "bin/wineserver",
    );
    add(
        "whisky-app",
        PathBuf::from("/Applications/Whisky.app/Contents/Resources/Wine"),
        "bin/wine64",
        "bin/wineserver",
    );
    if let Some(home) = home {
        add(
            "whisky-app",
            home.join("Applications/Whisky.app/Contents/Resources/Libraries/Wine"),
            "bin/wine64",
            "bin/wineserver",
        );
        add(
            "whisky-app",
            home.join("Applications/Whisky.app/Contents/Resources/Wine"),
            "bin/wine64",
            "bin/wineserver",
        );
        add(
            "whisky-library",
            home.join("Library/Application Support/com.isaacmarovitz.Whisky/Libraries/Wine"),
            "bin/wine64",
            "bin/wineserver",
        );
        add(
            "whisky-library",
            home.join("Library/Application Support/com.isaacmarovitz.Whisky/Libraries/Wine"),
            "bin/wine",
            "bin/wineserver",
        );
    }

    let development_refs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../Mac-Win/refs");
    for build in [
        "Whisky-wow64-game-build",
        "Whisky-x86_64-build",
        "Whisky-x86_64-game-build",
    ] {
        add(
            "mac-win-development-build",
            development_refs.join(build),
            "loader/wine",
            "server/wineserver",
        );
    }
    candidates
}

fn verify_discovered_candidate(
    source: &str,
    root: &Path,
    wine_relative: &str,
    wineserver_relative: &str,
    requested_version: &str,
    command: &dyn ProbeCommand,
) -> Result<DiscoveredWine, MacOsBootstrapError> {
    let root = fs::canonicalize(root).map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    if !root.is_dir() {
        return Err(MacOsBootstrapError::CandidateRejected);
    }
    validate_portable_relative_path("wine", wine_relative).map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    validate_portable_relative_path("wineserver", wineserver_relative)
        .map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    let wine_path = root.join(wine_relative);
    let wineserver_path = root.join(wineserver_relative);
    let wine_path = verify_entrypoint(
        &root,
        &VerifiedEntrypoint {
            path: wine_relative.into(),
            digest: sha256_file(&wine_path).map_err(|_| MacOsBootstrapError::CandidateRejected)?,
        },
        CpuArchitecture::X86_64,
        true,
    )
    .map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    let wineserver_path = verify_entrypoint(
        &root,
        &VerifiedEntrypoint {
            path: wineserver_relative.into(),
            digest: sha256_file(&wineserver_path).map_err(|_| MacOsBootstrapError::CandidateRejected)?,
        },
        CpuArchitecture::X86_64,
        true,
    )
    .map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    let version_output = command
        .run(&wine_path, &["--version"], &root, PROBE_TIMEOUT)
        .map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    let line = version_output.stdout.trim().lines().next().unwrap_or_default();
    if !version_output.success || !line.starts_with("wine-") {
        return Err(MacOsBootstrapError::CandidateRejected);
    }
    let version = line.trim_start_matches("wine-").trim();
    if version.is_empty() || (!requested_version.is_empty() && version != requested_version) {
        return Err(MacOsBootstrapError::CandidateRejected);
    }
    let wineserver_output = command
        .run(&wineserver_path, &["--version"], &root, PROBE_TIMEOUT)
        .map_err(|_| MacOsBootstrapError::CandidateRejected)?;
    if !wineserver_output.success {
        return Err(MacOsBootstrapError::CandidateRejected);
    }
    Ok(DiscoveredWine {
        source: source.into(),
        materialized_root: root,
        wine: wine_relative.into(),
        wineserver: wineserver_relative.into(),
        version: version.into(),
    })
}

fn register_preview_pack(runtime_store_root: &str, discovered: &DiscoveredWine) -> Result<String, MacOsBootstrapError> {
    let wine_path = discovered.materialized_root.join(&discovered.wine);
    let wineserver_path = discovered.materialized_root.join(&discovered.wineserver);
    let wine_digest = sha256_file(&wine_path).map_err(|_| MacOsBootstrapError::RegistrationFailed("wine digest"))?;
    let wineserver_digest =
        sha256_file(&wineserver_path).map_err(|_| MacOsBootstrapError::RegistrationFailed("wineserver digest"))?;
    let mut manifest = RuntimePackManifest {
        schema_version: SCHEMA_VERSION_V1.into(),
        id: AUTO_PACK_ID.into(),
        version: discovered.version.clone(),
        channel: Some(RuntimeChannel::Preview),
        host: RuntimeHost {
            os: HostOs::MacOs,
            architecture: CpuArchitecture::X86_64,
            minimum_version: None,
        },
        components: vec![
            RuntimeComponent {
                name: "wine-entrypoint".into(),
                version: discovered.version.clone(),
                license: "LGPL-2.1-or-later".into(),
                source: None,
                artifact: Some("components/wine-entrypoint.bin".into()),
                digest: wine_digest,
                entrypoints: [("wine".into(), discovered.wine.clone())].into_iter().collect(),
            },
            RuntimeComponent {
                name: "wineserver-entrypoint".into(),
                version: discovered.version.clone(),
                license: "LGPL-2.1-or-later".into(),
                source: None,
                artifact: Some("components/wineserver-entrypoint.bin".into()),
                digest: wineserver_digest,
                entrypoints: [("wineserver".into(), discovered.wineserver.clone())]
                    .into_iter()
                    .collect(),
            },
        ],
        capabilities: AUTO_CAPABILITIES.iter().map(|value| (*value).into()).collect(),
        digest: String::new(),
        signature: None,
        sbom: None,
    };
    manifest.digest = sha256_digest_bytes(
        &manifest
            .canonical_unsigned_bytes()
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("manifest"))?,
    );
    let pack_digest = manifest.digest.clone();
    let temporary = std::env::temp_dir().join(format!("compatforge-bootstrap-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|_| MacOsBootstrapError::RegistrationFailed("temporary bundle"))?;
    }
    fs::create_dir_all(temporary.join("components"))
        .map_err(|_| MacOsBootstrapError::RegistrationFailed("temporary bundle"))?;
    let result = (|| {
        fs::copy(&wine_path, temporary.join("components/wine-entrypoint.bin"))
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("wine copy"))?;
        fs::copy(&wineserver_path, temporary.join("components/wineserver-entrypoint.bin"))
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("wineserver copy"))?;
        let manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|_| MacOsBootstrapError::RegistrationFailed("manifest"))?;
        let mut file = File::create(temporary.join("manifest.json"))
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("manifest"))?;
        file.write_all(&manifest_bytes)
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("manifest"))?;
        RuntimePackStore::new(runtime_store_root)
            .install(&temporary, &manifest, &RejectAllSignatures)
            .map_err(|_| MacOsBootstrapError::RegistrationFailed("Runtime Pack install"))?;
        Ok::<(), MacOsBootstrapError>(())
    })();
    let _ = fs::remove_dir_all(&temporary);
    result.map(|()| pack_digest)
}

fn rosetta_unavailable_reason(
    host_report: &CapabilityReport,
    runtime: &WineRuntimeConfig,
    wine_reason: Option<&str>,
) -> String {
    match (host_report.host.architecture, runtime.architecture) {
        (CpuArchitecture::X86_64, _) => "Rosetta is not required on an x86_64 host".into(),
        (CpuArchitecture::Arm64, CpuArchitecture::Arm64) => {
            "configured Runtime is native ARM64 and provides no Rosetta evidence".into()
        }
        (CpuArchitecture::Arm64, CpuArchitecture::X86_64) => wine_reason
            .unwrap_or("x86_64 Runtime probe did not provide Rosetta evidence")
            .into(),
        _ => "configured host/runtime architecture cannot use Rosetta".into(),
    }
}

#[derive(Debug)]
struct WineEvidence {
    wine_path: PathBuf,
    wineserver_path: PathBuf,
    used_rosetta: bool,
}

fn interactive_wine_dll_path(wine_path: &Path) -> Option<PathBuf> {
    for ancestor in wine_path.ancestors() {
        let candidate = ancestor.join("runtime/lib/wine/x86_64-unix");
        if candidate.is_dir() {
            return fs::canonicalize(candidate).ok();
        }
    }
    None
}

fn probe_wine(
    host_architecture: CpuArchitecture,
    config: &MacOsProviderConfig,
    command: &dyn ProbeCommand,
) -> Result<WineEvidence, EvidenceFailure> {
    let runtime = &config.wine_runtime;
    let manifest = RuntimePackStore::new(&config.runtime_store_root)
        .verified_manifest(&runtime.pack_digest)
        .map_err(|_| EvidenceFailure::RuntimePack)?;
    if manifest.id != runtime.pack_id
        || manifest.version != runtime.version
        || manifest.host.os != HostOs::MacOs
        || manifest.host.architecture != runtime.architecture
        || !runtime
            .capabilities
            .iter()
            .all(|capability| manifest.capabilities.contains(capability))
    {
        return Err(EvidenceFailure::RuntimePack);
    }

    let root = fs::canonicalize(&runtime.materialized_root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    if !root.is_dir() {
        return Err(EvidenceFailure::MaterializedRoot);
    }
    let cross_architecture = host_architecture != runtime.architecture;
    let wine_path = verify_entrypoint(&root, &runtime.wine, runtime.architecture, cross_architecture)?;
    let wineserver_path = verify_entrypoint(&root, &runtime.wineserver, runtime.architecture, cross_architecture)?;

    let used_rosetta = match (host_architecture, runtime.architecture) {
        (CpuArchitecture::X86_64, CpuArchitecture::X86_64) | (CpuArchitecture::Arm64, CpuArchitecture::Arm64) => false,
        (CpuArchitecture::Arm64, CpuArchitecture::X86_64) => true,
        _ => return Err(EvidenceFailure::Architecture),
    };

    let wine_version = command
        .run(&wine_path, &["--version"], &root, PROBE_TIMEOUT)
        .map_err(|_| EvidenceFailure::Command)?;
    if !wine_version.success || !wine_version.stdout.trim().starts_with("wine-") {
        return Err(EvidenceFailure::Command);
    }
    let wineserver_version = command
        .run(&wineserver_path, &["--version"], &root, PROBE_TIMEOUT)
        .map_err(|_| EvidenceFailure::Command)?;
    if !wineserver_version.success {
        return Err(EvidenceFailure::Command);
    }

    Ok(WineEvidence {
        wine_path,
        wineserver_path,
        used_rosetta,
    })
}

fn probe_graphics_plugin(runtime: &WineRuntimeConfig, plugin: &GraphicsPluginConfig) -> Result<(), EvidenceFailure> {
    let root = fs::canonicalize(&runtime.materialized_root).map_err(|_| EvidenceFailure::MaterializedRoot)?;
    verify_entrypoint(&root, &plugin.probe_file, runtime.architecture, false).map(|_| ())
}

fn verify_entrypoint(
    root: &Path,
    entrypoint: &VerifiedEntrypoint,
    expected_architecture: CpuArchitecture,
    require_single_architecture: bool,
) -> Result<PathBuf, EvidenceFailure> {
    let path = fs::canonicalize(root.join(&entrypoint.path)).map_err(|_| EvidenceFailure::Entrypoint)?;
    if !path.starts_with(root) || !path.is_file() {
        return Err(EvidenceFailure::Entrypoint);
    }
    if !is_executable(&path) {
        return Err(EvidenceFailure::Entrypoint);
    }
    let actual_digest = sha256_file(&path).map_err(|_| EvidenceFailure::Entrypoint)?;
    if !entrypoint.digest.eq_ignore_ascii_case(&actual_digest) {
        return Err(EvidenceFailure::Digest);
    }
    let architectures = mach_o_architectures(&path).map_err(|_| EvidenceFailure::MachO)?;
    if !architectures.contains(&expected_architecture) || (require_single_architecture && architectures.len() != 1) {
        return Err(EvidenceFailure::Architecture);
    }
    Ok(path)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let mut value = String::from("sha256:");
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing a digest to a string cannot fail");
    }
    Ok(value)
}

fn mach_o_architectures(path: &Path) -> io::Result<BTreeSet<CpuArchitecture>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024).read_to_end(&mut bytes)?;
    parse_mach_o_architectures(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "entrypoint is not a supported Mach-O binary",
        )
    })
}

fn parse_mach_o_architectures(bytes: &[u8]) -> Option<BTreeSet<CpuArchitecture>> {
    if bytes.len() < 8 {
        return None;
    }
    let mut architectures = BTreeSet::new();
    match &bytes[..4] {
        [0xcf, 0xfa, 0xed, 0xfe] => {
            architectures.insert(cpu_type_to_architecture(u32::from_le_bytes(
                bytes[4..8].try_into().ok()?,
            ))?);
        }
        [0xfe, 0xed, 0xfa, 0xcf] => {
            architectures.insert(cpu_type_to_architecture(u32::from_be_bytes(
                bytes[4..8].try_into().ok()?,
            ))?);
        }
        [0xca, 0xfe, 0xba, 0xbe] | [0xca, 0xfe, 0xba, 0xbf] => {
            let is_64 = bytes[3] == 0xbf;
            let count = usize::try_from(u32::from_be_bytes(bytes[4..8].try_into().ok()?)).ok()?;
            if count == 0 || count > 32 {
                return None;
            }
            let stride = if is_64 { 32 } else { 20 };
            for index in 0..count {
                let offset = 8 + index * stride;
                let cpu = u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
                if let Some(architecture) = cpu_type_to_architecture(cpu) {
                    architectures.insert(architecture);
                }
            }
        }
        _ => return None,
    }
    (!architectures.is_empty()).then_some(architectures)
}

fn cpu_type_to_architecture(cpu_type: u32) -> Option<CpuArchitecture> {
    match cpu_type {
        0x0100_0007 => Some(CpuArchitecture::X86_64),
        0x0100_000c => Some(CpuArchitecture::Arm64),
        _ => None,
    }
}

pub trait ProbeCommand {
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        working_directory: &Path,
        timeout: Duration,
    ) -> io::Result<ProbeCommandOutput>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub struct SystemProbeCommand;

impl ProbeCommand for SystemProbeCommand {
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        working_directory: &Path,
        timeout: Duration,
    ) -> io::Result<ProbeCommandOutput> {
        let mut child = Command::new(executable)
            .args(arguments)
            .current_dir(working_directory)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("WINEDEBUG", "-all")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "probe stdout was not captured"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "probe stderr was not captured"))?;
        let stdout_reader = thread::spawn(move || read_limited(stdout));
        let stderr_reader = thread::spawn(move || read_limited(stderr));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Provider probe timed out"));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| io::Error::other("probe stdout reader panicked"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| io::Error::other("probe stderr reader panicked"))??;
        Ok(ProbeCommandOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

fn read_limited(reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_PROBE_OUTPUT_BYTES).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Clone, Copy)]
enum EvidenceFailure {
    RuntimePack,
    MaterializedRoot,
    Entrypoint,
    Digest,
    MachO,
    Architecture,
    Command,
}

impl EvidenceFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimePack => "Runtime Pack verification failed",
            Self::MaterializedRoot => "materialized Runtime root is unavailable",
            Self::Entrypoint => "verified Provider entrypoint is unavailable",
            Self::Digest => "Provider entrypoint digest mismatch",
            Self::MachO => "Provider entrypoint is not a supported Mach-O binary",
            Self::Architecture => "Provider entrypoint architecture is incompatible",
            Self::Command => "bounded Provider version probe failed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ProviderCapabilityClass {
    Runtime,
    Graphics,
}

fn validate_capabilities(capabilities: &[String], class: ProviderCapabilityClass) -> Result<(), MacOsProviderError> {
    if capabilities.is_empty() {
        return Err(MacOsProviderError::InvalidConfig("provider.capabilities"));
    }
    let mut unique = BTreeSet::new();
    for capability in capabilities {
        let supported = match class {
            ProviderCapabilityClass::Runtime => {
                matches!(
                    capability.as_str(),
                    "win32" | "win64" | "new-wow64" | "guest-i386" | "guest-x86_64"
                )
            }
            ProviderCapabilityClass::Graphics => matches!(
                capability.as_str(),
                "d3d8" | "d3d9" | "d3d10" | "d3d11" | "d3d12" | "opengl" | "metal"
            ),
        };
        if !supported {
            return Err(MacOsProviderError::InvalidConfig("provider.capabilities"));
        }
        if !unique.insert(capability) {
            return Err(MacOsProviderError::InvalidConfig("provider.capabilities"));
        }
    }
    Ok(())
}

fn provider_observation(
    id: &str,
    category: &str,
    source: ProbeSource,
    available: bool,
    reason: Option<&str>,
) -> CapabilityObservation {
    CapabilityObservation {
        id: id.into(),
        category: category.into(),
        status: if available {
            ProbeStatus::Detected
        } else {
            ProbeStatus::Unavailable
        },
        source,
        value: available.then_some(CapabilityValue::Boolean(true)),
        reason: (!available).then(|| reason.unwrap_or("Provider is unavailable").into()),
    }
}

fn upsert_observation(report: &mut CapabilityReport, observation: CapabilityObservation) {
    report.observations.retain(|existing| existing.id != observation.id);
    report.observations.push(observation);
}

fn canonicalize_report(report: &mut CapabilityReport) {
    for providers in [
        &mut report.runtime_providers,
        &mut report.translators,
        &mut report.graphics_backends,
    ] {
        for provider in providers.iter_mut() {
            provider.capabilities.sort();
        }
        providers.sort_by(|left, right| left.id.cmp(&right.id));
    }
    report.observations.sort_by(|left, right| left.id.cmp(&right.id));
}

fn serialized_path_is_absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
        || path
            .as_bytes()
            .get(1..3)
            .is_some_and(|separator| separator == b":\\" || separator == b":/")
        || path.starts_with("\\\\")
}

fn canonical_bootstrap_directory(value: &str, field: &'static str) -> Result<PathBuf, MacOsBootstrapError> {
    let path = Path::new(value);
    fs::create_dir_all(path).map_err(|_| MacOsBootstrapError::InvalidRequest(field))?;
    let canonical = fs::canonicalize(path).map_err(|_| MacOsBootstrapError::InvalidRequest(field))?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(MacOsBootstrapError::InvalidRequest(field))
    }
}

#[derive(Debug)]
pub enum MacOsProviderError {
    Contract(ContractError),
    InvalidConfig(&'static str),
    UnsupportedHost,
    ProviderUnavailable,
}

#[derive(Debug)]
pub enum MacOsBootstrapError {
    Contract(ContractError),
    InvalidRequest(&'static str),
    UnsupportedHost,
    DiscoveryFailed,
    CandidateRejected,
    RegistrationFailed(&'static str),
    Provider(MacOsProviderError),
}

impl fmt::Display for MacOsBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid macOS bootstrap contract: {error}"),
            Self::InvalidRequest(field) => write!(formatter, "invalid macOS bootstrap request: {field}"),
            Self::UnsupportedHost => formatter.write_str("automatic macOS bootstrap requires Darwin/arm64"),
            Self::DiscoveryFailed => formatter.write_str("no executable-verified x86_64 Wine candidate was found"),
            Self::CandidateRejected => formatter.write_str("Wine candidate failed bounded verification"),
            Self::RegistrationFailed(field) => write!(formatter, "local Runtime Pack registration failed: {field}"),
            Self::Provider(error) => write!(formatter, "macOS Provider bootstrap failed: {error}"),
        }
    }
}

impl std::error::Error for MacOsBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Provider(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for MacOsProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid macOS Provider contract: {error}"),
            Self::InvalidConfig(field) => write!(formatter, "invalid macOS Provider configuration: {field}"),
            Self::UnsupportedHost => formatter.write_str("macOS Provider requires a macOS host capability report"),
            Self::ProviderUnavailable => formatter.write_str("macOS Wine Runtime Provider is unavailable"),
        }
    }
}

impl std::error::Error for MacOsProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::InvalidConfig(_) | Self::UnsupportedHost | Self::ProviderUnavailable => None,
        }
    }
}

impl From<ContractError> for MacOsProviderError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{
        CapabilityReport, ExecutableRequest, HostDescriptor, LaunchConstraints, LaunchRequest, ManifestSignature,
        NetworkPolicy, RuntimeChannel, RuntimeComponent, RuntimeHost, RuntimePackManifest, TranslatorKind,
        SCHEMA_VERSION_V1,
    };
    use compatforge_orchestrator::PolicyEngine;
    use compatforge_runtime::{sha256_digest_bytes, RejectAllSignatures};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_DIRECTORY_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct SuccessfulCommand {
        calls: AtomicUsize,
    }

    impl ProbeCommand for SuccessfulCommand {
        fn run(
            &self,
            executable: &Path,
            arguments: &[&str],
            _working_directory: &Path,
            _timeout: Duration,
        ) -> io::Result<ProbeCommandOutput> {
            assert!(executable.is_absolute());
            assert_eq!(arguments, ["--version"]);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProbeCommandOutput {
                success: true,
                stdout: "wine-11.0\n".into(),
                stderr: String::new(),
            })
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let sequence = TEMP_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "compatforge-macos-provider-{name}-{}-{nonce}-{sequence}",
            std::process::id()
        ))
    }

    fn mach_o(architecture: CpuArchitecture) -> Vec<u8> {
        let cpu = match architecture {
            CpuArchitecture::X86_64 => 0x0100_0007_u32,
            CpuArchitecture::Arm64 => 0x0100_000c_u32,
            _ => unreachable!(),
        };
        let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe];
        bytes.extend_from_slice(&cpu.to_le_bytes());
        bytes.resize(64, 0);
        bytes
    }

    fn universal_mach_o() -> Vec<u8> {
        let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
        for cpu in [0x0100_0007_u32, 0x0100_000c_u32] {
            bytes.extend_from_slice(&cpu.to_be_bytes());
            bytes.extend_from_slice(&[0; 16]);
        }
        bytes
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    fn installed_fixture(
        host_architecture: CpuArchitecture,
        runtime_architecture: CpuArchitecture,
        d3dmetal: bool,
    ) -> (PathBuf, MacOsProviderConfig, CapabilityReport) {
        let root = temporary_directory("fixture");
        let bundle = root.join("bundle");
        let store_root = root.join("store");
        let materialized = root.join("materialized");
        fs::create_dir_all(bundle.join("components")).unwrap();
        fs::create_dir_all(materialized.join("bin")).unwrap();
        fs::create_dir_all(materialized.join("lib")).unwrap();
        fs::write(bundle.join("components/runtime.blob"), b"macos-runtime-pack").unwrap();

        let mut manifest = RuntimePackManifest {
            schema_version: SCHEMA_VERSION_V1.into(),
            id: "wine-macos-test".into(),
            version: "11.0".into(),
            channel: Some(RuntimeChannel::Preview),
            host: RuntimeHost {
                os: HostOs::MacOs,
                architecture: runtime_architecture,
                minimum_version: None,
            },
            components: vec![RuntimeComponent {
                name: "runtime".into(),
                version: "11.0".into(),
                license: "LGPL-2.1-or-later".into(),
                source: None,
                artifact: Some("components/runtime.blob".into()),
                digest: sha256_digest_bytes(b"macos-runtime-pack"),
                entrypoints: BTreeMap::from([
                    ("wine".into(), "bin/wine".into()),
                    ("wineserver".into(), "bin/wineserver".into()),
                ]),
            }],
            capabilities: vec!["guest-i386".into(), "guest-x86_64".into(), "new-wow64".into()],
            digest: format!("sha256:{}", "0".repeat(64)),
            signature: None::<ManifestSignature>,
            sbom: None,
        };
        manifest.digest = sha256_digest_bytes(&manifest.canonical_unsigned_bytes().unwrap());
        RuntimePackStore::new(&store_root)
            .install(&bundle, &manifest, &RejectAllSignatures)
            .unwrap();

        let wine_bytes = mach_o(runtime_architecture);
        let wine = materialized.join("bin/wine");
        let wineserver = materialized.join("bin/wineserver");
        fs::write(&wine, &wine_bytes).unwrap();
        fs::write(&wineserver, &wine_bytes).unwrap();
        make_executable(&wine);
        make_executable(&wineserver);
        let d3dmetal_path = materialized.join("lib/d3dmetal.dylib");
        fs::write(&d3dmetal_path, &wine_bytes).unwrap();
        make_executable(&d3dmetal_path);

        let config = MacOsProviderConfig {
            schema_version: SCHEMA_VERSION_V1.into(),
            runtime_store_root: store_root.to_string_lossy().into_owned(),
            wine_runtime: WineRuntimeConfig {
                provider_id: "wine-macos-test".into(),
                pack_id: manifest.id,
                pack_digest: manifest.digest,
                version: "11.0".into(),
                architecture: runtime_architecture,
                materialized_root: materialized.to_string_lossy().into_owned(),
                wine: VerifiedEntrypoint {
                    path: "bin/wine".into(),
                    digest: sha256_digest_bytes(&wine_bytes),
                },
                wineserver: VerifiedEntrypoint {
                    path: "bin/wineserver".into(),
                    digest: sha256_digest_bytes(&wine_bytes),
                },
                capabilities: vec!["guest-i386".into(), "guest-x86_64".into(), "new-wow64".into()],
                wined3d_capabilities: vec!["d3d9".into(), "d3d11".into(), "opengl".into()],
                d3dmetal: d3dmetal.then(|| GraphicsPluginConfig {
                    provider_id: "d3dmetal-user-pack".into(),
                    version: "1.1".into(),
                    probe_file: VerifiedEntrypoint {
                        path: "lib/d3dmetal.dylib".into(),
                        digest: sha256_digest_bytes(&wine_bytes),
                    },
                    capabilities: vec!["d3d11".into(), "d3d12".into(), "metal".into()],
                }),
            },
        };
        let host = CapabilityReport {
            schema_version: SCHEMA_VERSION_V1.into(),
            host: HostDescriptor {
                os: HostOs::MacOs,
                os_version: "test".into(),
                architecture: host_architecture,
                kernel: None,
                device_model: None,
            },
            runtime_providers: Vec::new(),
            translators: vec![ProviderDescriptor {
                id: "native-host".into(),
                kind: "native".into(),
                version: "host".into(),
                available: true,
                reason: None,
                capabilities: vec![match host_architecture {
                    CpuArchitecture::Arm64 => "arm64-on-arm64".into(),
                    CpuArchitecture::X86_64 => "x86_64-on-x86_64".into(),
                    _ => unreachable!(),
                }],
            }],
            graphics_backends: Vec::new(),
            observations: Vec::new(),
            features: BTreeMap::new(),
        };
        (root, config, host)
    }

    #[test]
    fn x86_wine_on_arm64_proves_rosetta_and_builds_a_pinned_context() {
        let (root, config, host) = installed_fixture(CpuArchitecture::Arm64, CpuArchitecture::X86_64, false);
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        let snapshot = MacOsProviderSet::probe_with(&host, &config, &command).unwrap();
        assert_eq!(command.calls.load(Ordering::SeqCst), 2);
        assert!(snapshot.capabilities.runtime_providers[0].available);
        assert!(snapshot
            .capabilities
            .translators
            .iter()
            .any(|provider| provider.kind == "rosetta" && provider.available));
        assert!(snapshot
            .capabilities
            .graphics_backends
            .iter()
            .any(|provider| provider.kind == "wined3d" && provider.available));
        assert!(snapshot
            .capabilities
            .graphics_backends
            .iter()
            .any(|provider| provider.kind == "d3dmetal" && !provider.available));

        let core = snapshot
            .core_config(root.join("bottles").to_string_lossy().into_owned())
            .unwrap();
        assert_eq!(core.runtime_bindings[0].pack_digest, config.wine_runtime.pack_digest);
        assert_eq!(
            core.runtime_bindings[0].environment["COMPATFORGE_RUNTIME_PACK_DIGEST"],
            config.wine_runtime.pack_digest
        );
        assert_eq!(
            core.runtime_bindings[0].environment["COMPATFORGE_RUNTIME_EXECUTABLE_SHA256"],
            config.wine_runtime.wine.digest
        );
        assert_eq!(
            core.runtime_bindings[0].environment["COMPATFORGE_WINESERVER_EXECUTABLE_SHA256"],
            config.wine_runtime.wineserver.digest
        );
        let request = LaunchRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            request_id: "macos-provider-plan".into(),
            bottle_id: "macos-smoke".into(),
            recipe_id: None,
            executable: ExecutableRequest {
                path: "C:\\compatforge-smoke.exe".into(),
                architecture: CpuArchitecture::X86_64,
                mode: compatforge_domain::ExecutableMode::ImmutableArtifact,
                sha256: None,
            },
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            constraints: LaunchConstraints {
                allow_virtual_machine: false,
                allow_remote: false,
                requires_kernel_driver: false,
                requires_direct_x12: false,
                network_policy: NetworkPolicy::Deny,
                required_capabilities: Vec::new(),
            },
        };
        let plan = PolicyEngine::compile(&core, &request).unwrap();
        assert_eq!(plan.translator.provider, TranslatorKind::Rosetta);
        assert_eq!(plan.process.executable, core.runtime_bindings[0].executable);
        PolicyEngine::authorize(&core, &plan).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_bootstrap_registers_idempotent_preview_pack_without_paths_in_receipt() {
        let (root, _config, host) = installed_fixture(CpuArchitecture::Arm64, CpuArchitecture::X86_64, false);
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        let request = MacOsLocalContextRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            runtime_store_root: root.join("auto-store").to_string_lossy().into_owned(),
            storage_root: root.join("auto-storage").to_string_lossy().into_owned(),
            materialized_root: Some(root.join("materialized").to_string_lossy().into_owned()),
            wine: Some("bin/wine".into()),
            wineserver: Some("bin/wineserver".into()),
            version: Some("11.0".into()),
        };
        let first = create_local_context_with(&host, &request, &command).unwrap();
        let second = create_local_context_with(&host, &request, &command).unwrap();
        assert_eq!(first.receipt.pack_digest, second.receipt.pack_digest);
        assert_eq!(first.receipt.source, "explicit-override");
        let receipt_json = serde_json::to_string(&first.receipt).unwrap();
        assert!(!receipt_json.contains(root.to_string_lossy().as_ref()));
        assert_eq!(first.config.runtime_bindings.len(), 1);
        let materialized = root.join("materialized").canonicalize().unwrap();
        assert!(first.config.runtime_bindings[0]
            .executable
            .starts_with(materialized.to_string_lossy().as_ref()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_bootstrap_requires_a_complete_override_quartet() {
        let runtime_store_root = if cfg!(windows) {
            r"C:\\tmp\\runtime-store"
        } else {
            "/tmp/runtime-store"
        };
        let storage_root = if cfg!(windows) {
            r"C:\\tmp\\storage"
        } else {
            "/tmp/storage"
        };
        let materialized_root = if cfg!(windows) { r"C:\\tmp\\root" } else { "/tmp/root" };
        let request = MacOsLocalContextRequest {
            schema_version: SCHEMA_VERSION_V1.into(),
            runtime_store_root: runtime_store_root.into(),
            storage_root: storage_root.into(),
            materialized_root: Some(materialized_root.into()),
            wine: None,
            wineserver: None,
            version: None,
        };
        assert!(matches!(
            request.validate(),
            Err(MacOsBootstrapError::InvalidRequest("runtime override quartet"))
        ));
    }

    #[test]
    fn native_runtime_does_not_claim_rosetta() {
        let (root, config, host) = installed_fixture(CpuArchitecture::Arm64, CpuArchitecture::Arm64, false);
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        let snapshot = MacOsProviderSet::probe_with(&host, &config, &command).unwrap();
        assert!(snapshot
            .capabilities
            .translators
            .iter()
            .any(|provider| provider.kind == "rosetta" && !provider.available));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn digest_mismatch_is_unavailable_and_never_executes() {
        let (root, mut config, host) = installed_fixture(CpuArchitecture::Arm64, CpuArchitecture::X86_64, false);
        config.wine_runtime.wine.digest = format!("sha256:{}", "f".repeat(64));
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        let snapshot = MacOsProviderSet::probe_with(&host, &config, &command).unwrap();
        assert!(!snapshot.capabilities.runtime_providers[0].available);
        assert!(snapshot.runtime_binding.is_none());
        assert_eq!(command.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            snapshot.core_config(root.join("bottles").to_string_lossy().into_owned()),
            Err(MacOsProviderError::ProviderUnavailable)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configured_d3dmetal_is_bound_to_the_same_pack_and_verified() {
        let (root, config, host) = installed_fixture(CpuArchitecture::X86_64, CpuArchitecture::X86_64, true);
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        let snapshot = MacOsProviderSet::probe_with(&host, &config, &command).unwrap();
        assert!(snapshot
            .capabilities
            .graphics_backends
            .iter()
            .any(|provider| provider.kind == "d3dmetal" && provider.available));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn universal_runtime_cannot_be_used_as_rosetta_execution_evidence() {
        let (root, mut config, host) = installed_fixture(CpuArchitecture::Arm64, CpuArchitecture::X86_64, false);
        let universal = universal_mach_o();
        let materialized = Path::new(&config.wine_runtime.materialized_root);
        fs::write(materialized.join("bin/wine"), &universal).unwrap();
        fs::write(materialized.join("bin/wineserver"), &universal).unwrap();
        make_executable(&materialized.join("bin/wine"));
        make_executable(&materialized.join("bin/wineserver"));
        config.wine_runtime.wine.digest = sha256_digest_bytes(&universal);
        config.wine_runtime.wineserver.digest = sha256_digest_bytes(&universal);
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        let snapshot = MacOsProviderSet::probe_with(&host, &config, &command).unwrap();
        assert!(!snapshot.capabilities.runtime_providers[0].available);
        assert!(
            !snapshot
                .capabilities
                .translators
                .iter()
                .find(|provider| provider.kind == "rosetta")
                .unwrap()
                .available
        );
        assert_eq!(command.calls.load(Ordering::SeqCst), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unknown_capabilities_and_non_macos_hosts() {
        let (root, mut config, mut host) = installed_fixture(CpuArchitecture::X86_64, CpuArchitecture::X86_64, false);
        config.wine_runtime.capabilities.push("arbitrary-host-secret".into());
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };
        assert!(matches!(
            MacOsProviderSet::probe_with(&host, &config, &command),
            Err(MacOsProviderError::InvalidConfig("provider.capabilities"))
        ));
        config.wine_runtime.capabilities.pop();
        host.host.os = HostOs::Linux;
        assert!(matches!(
            MacOsProviderSet::probe_with(&host, &config, &command),
            Err(MacOsProviderError::UnsupportedHost)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_thin_and_universal_macho_architectures() {
        assert_eq!(
            parse_mach_o_architectures(&mach_o(CpuArchitecture::Arm64)),
            Some(BTreeSet::from([CpuArchitecture::Arm64]))
        );
        assert_eq!(
            parse_mach_o_architectures(&universal_mach_o()),
            Some(BTreeSet::from([CpuArchitecture::X86_64, CpuArchitecture::Arm64]))
        );
        assert_eq!(parse_mach_o_architectures(b"not-macho"), None);
    }

    #[test]
    fn local_candidates_prefer_crossover_wineloader_with_legacy_fallback() {
        let home = Path::new("/Users/compatforge-test");
        let candidates = local_wine_candidates(Some(home));
        let crossover: Vec<&LocalWineCandidate> = candidates
            .iter()
            .filter(|candidate| candidate.source == "crossover-app")
            .collect();

        assert_eq!(crossover.len(), 4);
        for pair in crossover.chunks_exact(2) {
            assert_eq!(pair[0].root, pair[1].root);
            assert_eq!(pair[0].wine, "bin/wineloader");
            assert_eq!(pair[1].wine, "bin/wine");
            assert_eq!(pair[0].wineserver, "bin/wineserver");
            assert_eq!(pair[1].wineserver, "bin/wineserver");
        }
    }

    #[test]
    fn crossover_wineloader_is_a_verified_wine_entrypoint() {
        let root = temporary_directory("crossover-wineloader");
        fs::create_dir_all(root.join("bin")).unwrap();
        let bytes = mach_o(CpuArchitecture::X86_64);
        let wineloader = root.join("bin/wineloader");
        let wineserver = root.join("bin/wineserver");
        fs::write(&wineloader, &bytes).unwrap();
        fs::write(&wineserver, &bytes).unwrap();
        make_executable(&wineloader);
        make_executable(&wineserver);
        let command = SuccessfulCommand {
            calls: AtomicUsize::new(0),
        };

        let discovered =
            verify_discovered_candidate("crossover-app", &root, "bin/wineloader", "bin/wineserver", "", &command)
                .unwrap();

        assert_eq!(discovered.wine, "bin/wineloader");
        assert_eq!(discovered.wineserver, "bin/wineserver");
        assert_eq!(command.calls.load(Ordering::SeqCst), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
