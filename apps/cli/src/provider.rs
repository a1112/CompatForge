//! Read-only implementation capability report. Never opens a daemon or context.
use forge_provider_contract::{ProviderInfo, CONTRACT_VERSION};
use std::collections::BTreeMap;

pub(crate) fn info() -> ProviderInfo {
    let linux = cfg!(target_os = "linux");
    let map = |names: &[&str]| -> BTreeMap<String, String> {
        if linux {
            names.iter().map(|name| ((*name).into(), "1".into())).collect()
        } else {
            BTreeMap::new()
        }
    };
    let list = |names: &[&str]| -> Vec<String> {
        let mut result: Vec<String> = if linux {
            names.iter().map(|name| (*name).into()).collect()
        } else {
            vec![]
        };
        result.sort();
        result
    };
    ProviderInfo {
        schema_version: "1".into(),
        contract_version: CONTRACT_VERSION.into(),
        provider_id: "compatforge".into(),
        provider_version: env!("CARGO_PKG_VERSION").into(),
        source_commit: env!("FORGE_PROVIDER_SOURCE").into(),
        source_dirty: env!("FORGE_PROVIDER_DIRTY") != "false",
        target: env!("FORGE_PROVIDER_TARGET").into(),
        service_name: if linux {
            "compatforge.service".into()
        } else {
            String::new()
        },
        commands: if linux {
            ["service-call", "service-daemon", "desktop-export", "desktop-launch"]
                .iter()
                .map(|name| ((*name).into(), "2".into()))
                .collect()
        } else {
            BTreeMap::new()
        },
        schemas: {
            let mut schemas = map(&[
                "service-request",
                "service-response",
                "job",
                "desktop-export",
                "desktop-launcher",
            ]);
            if linux {
                for name in ["daemon-handshake", "daemon-reply", "bound-request", "bound-response"] {
                    schemas.insert(name.into(), "2".into());
                }
            }
            schemas
        },
        capabilities: list(&[
            "shared-service-v1",
            "managed-applications-v1",
            "generation-lifecycle-v1",
            "desktop-launchers-v1",
            "provider-binding-v2",
        ]),
        operations: list(&[
            "applications.list",
            "applications.get",
            "applications.upsert",
            "applications.generations",
            "applications.rollback",
            "applications.uninstall",
            "jobs.submit",
            "jobs.get",
            "jobs.poll",
            "jobs.cancel",
            "desktop.launchers",
        ]),
    }
}

pub fn run(arguments: &[String]) -> Option<Result<(), Box<dyn std::error::Error>>> {
    if arguments.first().map(String::as_str) != Some("provider-info") {
        return None;
    }
    Some((|| {
        if arguments.len() != 1 {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "provider-info accepts no arguments").into(),
            );
        }
        println!("{}", serde_json::to_string(&info())?);
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_is_bounded_platform_specific_and_has_no_runtime_claim() {
        let report = info();
        let raw = serde_json::to_vec(&report).unwrap();
        assert!(raw.len() < forge_provider_contract::MAX_CONTRACT_BYTES);
        forge_provider_contract::decode_info(&raw).unwrap();
        assert_eq!(report.commands.contains_key("service-call"), cfg!(target_os = "linux"));
        assert!(!report.capabilities.iter().any(|capability| capability.contains("wine")));
        assert!(run(&["provider-info".into(), "--context".into()]).unwrap().is_err());
        assert!(run(&["other".into()]).is_none());
    }
}
