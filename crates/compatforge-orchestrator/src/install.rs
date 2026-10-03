//! Closed MSI intent followed by byte-verified preparation under an owned job.
use super::*;
use compatforge_domain::{
    ExecutableRequest, InstallRequest, LaunchConstraints, MsiInstallBinding, MsiPackageBinding, NetworkPolicy,
    WineAppearance,
};
use compatforge_guest_artifact::{inspect_msi_installer_tool, MsiPackageStore};
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone, Default)]
pub struct InstallLaunchOptions {
    pub environment: BTreeMap<String, String>,
    pub wine_appearance: Option<WineAppearance>,
}

/// This type declares reviewed identities; it deliberately does not claim that
/// the package bytes have been inspected. The dormant process owner performs
/// preparation before Wine startup and before any guest can execute.
#[derive(Debug, Clone)]
pub struct InstallIntent {
    request: InstallRequest,
    options: InstallLaunchOptions,
    plan: LaunchPlan,
    context_fingerprint: String,
}

impl InstallIntent {
    pub fn compile(
        config: &CoreConfig,
        request: &InstallRequest,
        architecture: CpuArchitecture,
        options: InstallLaunchOptions,
    ) -> Result<Self, PreparationError> {
        config
            .validate()
            .map_err(PlanError::InvalidConfig)
            .map_err(PreparationError::Planning)?;
        request.validate().map_err(PreparationError::InvalidRequest)?;
        if !matches!(architecture, CpuArchitecture::I386 | CpuArchitecture::X86_64) {
            return Err(PreparationError::ArchitectureMismatch {
                requested: architecture,
                inspected: CpuArchitecture::Unknown,
            });
        }
        let stored_path = Path::new(&config.storage_root)
            .join("installer-packages/objects/sha256")
            .join(&request.package.sha256)
            .join("package.msi");
        let package = MsiPackageBinding {
            package: request.package.clone(),
            stored_path: stored_path.to_string_lossy().into(),
            architecture,
        };
        let mut launch = LaunchRequest {
            schema_version: request.schema_version.clone(),
            request_id: request.request_id.clone(),
            bottle_id: request.bottle_id.clone(),
            recipe_id: request.recipe_id.clone(),
            executable: ExecutableRequest {
                path: request.package.path.clone(),
                architecture,
                mode: ExecutableMode::ImmutableArtifact,
                sha256: None,
            },
            arguments: request
                .handler
                .arguments(&package.stored_path)
                .map_err(PreparationError::InvalidRequest)?,
            environment: options.environment.clone(),
            constraints: LaunchConstraints {
                allow_virtual_machine: false,
                allow_remote: false,
                requires_kernel_driver: false,
                requires_direct_x12: false,
                network_policy: if request.constraints.network_policy == "deny" {
                    NetworkPolicy::Deny
                } else {
                    NetworkPolicy::InstallerOnly
                },
                required_capabilities: Vec::new(),
            },
            wine_appearance: options.wine_appearance,
        };
        let selection = PolicyEngine::compile(config, &launch).map_err(PreparationError::Planning)?;
        let tool = config
            .wine_installer_tools
            .iter()
            .find(|tool| {
                tool.pack_id == selection.runtime.pack_id
                    && tool.pack_digest == selection.runtime.pack_digest
                    && tool.architecture == architecture
            })
            .ok_or(PreparationError::Planning(PlanError::PlanMismatch(
                "missing pinned MSI runtime tool",
            )))?
            .clone();
        launch.executable.path = tool.path.clone();
        launch.executable.sha256 = tool.digest.strip_prefix("sha256:").map(str::to_owned);
        let mut plan = PolicyEngine::compile(config, &launch).map_err(PreparationError::Planning)?;
        let maximum = config
            .supervisor
            .maximum_runtime_milliseconds
            .map_or(request.constraints.maximum_runtime_milliseconds, |bound| {
                bound.min(request.constraints.maximum_runtime_milliseconds)
            });
        plan.msi_install = Some(MsiInstallBinding {
            package,
            handler: request.handler.clone(),
            tool,
            maximum_runtime_milliseconds: maximum,
        });
        plan.lifecycle.maximum_runtime_milliseconds = Some(maximum);
        plan.decision_trace
            .push("MSI identity declared; bytes require owned preparation before execution".into());
        PolicyEngine::authorize(config, &plan).map_err(PreparationError::Planning)?;
        Ok(Self {
            request: request.clone(),
            options,
            plan,
            context_fingerprint: fingerprint_context(config)?,
        })
    }
    pub fn plan(&self) -> &LaunchPlan {
        &self.plan
    }

    pub fn prepare(
        &self,
        config: &CoreConfig,
        cancellation: Option<&AtomicBool>,
    ) -> Result<PreparedInstall, PreparationError> {
        if fingerprint_context(config)? != self.context_fingerprint {
            return Err(PreparationError::ContextMismatch);
        }
        let binding = self
            .plan
            .msi_install
            .as_ref()
            .ok_or(PreparationError::PreparedPlanMismatch)?;
        let package = MsiPackageStore::new(&config.storage_root)
            .prepare_cancellable(&self.request.package, binding.package.architecture, cancellation)
            .map_err(PreparationError::Installer)?;
        if package != binding.package {
            return Err(PreparationError::PreparedPlanMismatch);
        }
        let tool_inspection = inspect_msi_installer_tool(&binding.tool).map_err(PreparationError::Installer)?;
        let current = Self::compile(config, &self.request, package.architecture, self.options.clone())?;
        if current.plan != self.plan {
            return Err(PreparationError::PreparedPlanMismatch);
        }
        Ok(PreparedInstall {
            intent: self.clone(),
            tool_inspection,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreparedInstall {
    intent: InstallIntent,
    tool_inspection: PeInspectionReport,
}
impl PreparedInstall {
    pub fn plan(&self) -> &LaunchPlan {
        self.intent.plan()
    }
    pub fn tool_inspection(&self) -> &PeInspectionReport {
        &self.tool_inspection
    }
    pub fn authorize<'a>(&'a self, config: &CoreConfig) -> Result<&'a LaunchPlan, PreparationError> {
        self.authorize_cancellable(config, None)
    }
    pub fn authorize_cancellable<'a>(
        &'a self,
        config: &CoreConfig,
        cancellation: Option<&AtomicBool>,
    ) -> Result<&'a LaunchPlan, PreparationError> {
        if fingerprint_context(config)? != self.intent.context_fingerprint {
            return Err(PreparationError::ContextMismatch);
        }
        let binding = self
            .plan()
            .msi_install
            .as_ref()
            .ok_or(PreparationError::PreparedPlanMismatch)?;
        MsiPackageStore::new(&config.storage_root)
            .verify_cancellable(&binding.package, cancellation)
            .map_err(PreparationError::Installer)?;
        if inspect_msi_installer_tool(&binding.tool).map_err(PreparationError::Installer)? != self.tool_inspection {
            return Err(PreparationError::PreparedPlanMismatch);
        }
        let current = InstallIntent::compile(
            config,
            &self.intent.request,
            binding.package.architecture,
            self.intent.options.clone(),
        )?;
        if current.plan != *self.plan() {
            return Err(PreparationError::PreparedPlanMismatch);
        }
        PolicyEngine::authorize(config, self.plan()).map_err(PreparationError::Planning)?;
        Ok(self.plan())
    }
}
