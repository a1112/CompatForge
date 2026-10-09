# Forge provider protocol v1

The CLI-only v1 candidate is superseded by [binding v2](provider-binding-v2.md)
after independent review. Current consumers require 2.0.0 and reject unbound v1
results; this file records the original metadata shape, not runtime acceptance.

`compatforge-cli provider-info` emits a bounded JSON report without opening a
context, runtime directory, daemon, Wine process or network connection. It
accepts no arguments. The report describes the protocols implemented in this
build; it does not declare a working Wine installation or a running service.
Linux builds declare shared-service, managed-generation and desktop-launcher
protocols. Other targets report empty protocol sets and are rejected by Linux
consumers. C ABI negotiation remains independent and unchanged.

`contracts/provider-info-v1.schema.json` defines the report. Command versions,
schema versions and contract/provider versions are distinct. The compiled
source commit and dirty flag come from Git at build time, with no environment
override. Archives without Git are dirty/unconfigured. Rebuild after committing
the provider slice; dirty builds cannot satisfy a composition lock.

`crates/forge-provider-contract` is the reusable Rust decoder/negotiator;
`tools/forge_provider_contract.py` is its standard-library Python adapter.
Consumers carry identical copies and share `contracts/provider-vectors-v1.json`.
No third-party dependency is added beyond the existing serde/serde_json closure;
each repository's Cargo.lock fixes its resolved versions. Their provenance is
the existing crates.io checksums. Report parsing rejects unknown/duplicate
fields, wrong types, unsorted/duplicate identifiers and data above 64 KiB.

The v1 error vocabulary is `provider-unavailable`, `schema-mismatch`,
`unsupported-version`, `capability-missing`, and `source-mismatch`, rendered as
`forge.provider.<code>`. These are domain adapter errors. Public contract
`ErrorCode::public_code` and Python `ContractError.public_code` explicitly adapt
to R-SDK interop `1.0.0`: unavailable/missing → `CAPABILITY_UNAVAILABLE`, schema
→ `SCHEMA_INVALID`, version → `UNSUPPORTED_VERSION`, source → `BINDING_MISMATCH`.
The adapter preserves the domain code/message and does not claim to validate
R-SDK envelopes, authorization or its ABI. This module does not modify R-SDK.

Store must negotiate before creating a request file or invoking `service-call`.
Desktop must negotiate before `desktop-export` and any launcher reconciliation.
Versioned consumer locks pin the exact clean provider commit, package version,
target, service, commands, schemas and operations. A separately saved composition
lock binds the final Store/Desktop/provider/ForgeOS commits. CLI metadata is
compatibility evidence; artifact authenticity remains the existing audited
source/digest and image-provenance boundary.

This slice is independently derived from `fix/managed-msi-install` at
`cfc9b6cb9498844f4098cbe786694515568a3bc7`. It must receive a separate review/PR;
the candidate's 34-ahead/9-behind divergence is not resolved by this change.
Rollback restores the prior consumer and matching provider pins as one reviewed
combination. No default branch, engine, system service or runtime state changes.
