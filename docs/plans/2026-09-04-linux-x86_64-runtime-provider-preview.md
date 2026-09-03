# Linux x86_64 Runtime Provider Preview Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a fail-closed Linux x86_64 Wine Provider and run the repository's fixed Windows Console fixture through the existing PreparedLaunch and ProcessSupervisor chain with digest-bound, path-redacted evidence.

**Architecture:** Add a Linux-only Provider crate that accepts one explicit x86_64 Wine Runtime, verifies its Runtime Store evidence, ELF entrypoints, digests, permissions, and real version commands, and then emits the existing CoreConfig/RuntimeBinding types. Add four additive CLI routes plus an explicit Python canary runner; keep Wine download, PATH discovery, GUI, Wayland, ARM64 translation, Desktop packaging, and arbitrary untrusted applications out of this slice.

**Tech Stack:** Rust 1.78+ workspace, serde/serde_json, sha2, existing compatforge-domain/runtime/orchestrator/process crates, JSON Schema Draft 2020-12, Python 3.12 standard library, Linux ELF64, MinGW-w64, and a developer-supplied pinned Wine Runtime.

---

## Mandatory skills, context, and stop rules

Use @superpowers:test-driven-development for every behavior change, @superpowers:verification-before-completion before any success claim, and @superpowers:requesting-code-review after the complete offline implementation.

Run all commands from the dedicated agent/linux-x86_64-runtime-provider-preview worktree. Confirm git branch --show-current before each task; never substitute the main checkout or the frozen macOS worktree.

Read before implementation:

- docs/plans/2026-09-04-linux-x86_64-runtime-provider-preview-design.md
- docs/implementation/phase-1-macos-provider.md
- docs/implementation/phase-1-trusted-launch-preparation.md
- docs/decisions/0009-macos-provider-evidence.md
- docs/security.md
- docs/compliance.md

Keep Cargo output outside the worktree. On the current Windows host:

~~~powershell
$CF_WORKTREE = (Get-Location).Path
$env:CARGO_TARGET_DIR = Join-Path (Split-Path -Parent $CF_WORKTREE) '.build\compatforge-linux-x86_64-provider-preview'
$CF_PYTHON = '<absolute Python 3.12 executable returned by the workspace dependency resolver>'
& $CF_PYTHON --version
~~~

Replace the quoted Python placeholder in the shell only; never write that machine-specific value into a tracked file. Expected version: Python 3.12.x.

On Linux:

~~~bash
export CARGO_TARGET_DIR=/tmp/compatforge-linux-x86_64-provider-preview-target
CF_PYTHON=python3
~~~

Do not modify:

- tools/run_gui_soak.py
- tests/test_gui_baseline_contracts.py
- tests/test_phase_2_3_contracts.py
- docs/testing.md
- docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md
- apps/desktop/
- crates/compatforge-ffi/

Do not download or install Wine, search PATH/Home for a Runtime, accept a shell wrapper as Wine, add Linux ARM64/FEX, or claim GUI/Beta/Tier 1 support. Do not commit a Wine binary, generated ELF, generated PE, private CoreConfig, absolute local paths, or canary logs.

If real Linux prerequisites are unavailable, stop after the offline status implemented-awaiting-linux-canary. Never replace the real canary with a stub result.

Every RED/GREEN step has two lanes. Pure parsers, state machines, injected process/filesystem seams, and serialization tests must genuinely run on Windows; a skipped test is not RED or GREEN. Unix permissions, ELF execution, process groups, selectors, and /proc tests must run in the Ubuntu lane as soon as Task 14 provides it and all must pass before the offline implementation is called complete.

## Task 1: Reconfirm the isolated baseline

**Files:**

- Read: docs/plans/2026-09-04-linux-x86_64-runtime-provider-preview-design.md
- No source modifications

**Step 1: Confirm the branch and exact base**

Run:

~~~powershell
git status --short --branch
git rev-parse HEAD
git merge-base HEAD main
git log --oneline main..HEAD
~~~

Expected:

- branch is agent/linux-x86_64-runtime-provider-preview;
- status is clean;
- merge-base is 7c9561257fe21e0c9e077f3046c3b3785c1c30f2;
- branch history contains only the approved design and implementation-plan documentation commits; there are no source changes yet.

**Step 2: Run the repository contract with Python 3.12**

Run:

~~~powershell
& $CF_PYTHON -B scripts\validate_repository.py
~~~

Expected: repository contracts are internally consistent.

Do not use the current PATH python on the Windows host: it is Python 3.9.11 and cannot evaluate the validator's ast.MatchAs checks.

**Step 3: Run the Rust baseline outside the worktree**

Run:

~~~powershell
cargo test --workspace --locked
~~~

Expected: all workspace unit, integration, and doc tests pass.

**Step 4: Confirm the validator sees no generated build artifacts**

Run:

~~~powershell
& $CF_PYTHON -B scripts\validate_repository.py
git status --short
~~~

Expected: validation passes and Git status prints nothing. If a generated target directory appears inside the worktree, first verify its resolved path is exactly this worktree's target, then run cargo clean --target-dir (Join-Path (Get-Location) 'target'); keep the external CARGO_TARGET_DIR set before continuing.

## Task 2: Freeze the two Linux JSON contracts

**Files:**

- Create: schemas/linux-provider.schema.json
- Create: schemas/linux-bootstrap-request.schema.json
- Create: tests/test_linux_provider_contracts.py
- Modify: scripts/validate_repository.py:123-160
- Test: tests/test_linux_provider_contracts.py

**Step 1: Write the failing schema tests**

Create tests/test_linux_provider_contracts.py with this initial boundary:

~~~python
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_SCHEMA = ROOT / "schemas" / "linux-provider.schema.json"
BOOTSTRAP_SCHEMA = ROOT / "schemas" / "linux-bootstrap-request.schema.json"


def document(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class LinuxProviderSchemaTests(unittest.TestCase):
    def test_provider_schema_is_closed_and_x86_64_only(self) -> None:
        self.assertTrue(PROVIDER_SCHEMA.is_file(), "Linux Provider schema is missing")
        schema = document(PROVIDER_SCHEMA)
        runtime = schema["properties"]["wineRuntime"]
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(runtime["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {"schemaVersion", "runtimeStoreRoot", "wineRuntime"},
        )
        self.assertEqual(runtime["properties"]["architecture"], {"const": "x86_64"})
        self.assertEqual(
            runtime["properties"]["capabilities"],
            {"const": ["guest-x86_64"]},
        )
        self.assertEqual(
            runtime["properties"]["wined3dCapabilities"],
            {"const": ["opengl"]},
        )

    def test_bootstrap_schema_requires_the_explicit_runtime_quartet(self) -> None:
        self.assertTrue(BOOTSTRAP_SCHEMA.is_file(), "Linux bootstrap schema is missing")
        schema = document(BOOTSTRAP_SCHEMA)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {
                "schemaVersion",
                "runtimeStoreRoot",
                "storageRoot",
                "materializedRoot",
                "wine",
                "wineserver",
                "version",
            },
        )

    def test_linux_path_patterns_accept_and_reject_examples(self) -> None:
        for schema in (document(PROVIDER_SCHEMA), document(BOOTSTRAP_SCHEMA)):
            absolute = re.compile(schema["$defs"]["absoluteLinuxPath"]["pattern"])
            relative = re.compile(schema["$defs"]["relativePath"]["pattern"])
            self.assertIsNotNone(absolute.fullmatch("/opt/wine"))
            self.assertIsNotNone(relative.fullmatch("bin/wine64"))
            for value in ("/", "/opt//wine", "/./wine", "/opt/../wine", "/opt/", "C:\\wine", "/bad\npath", "/bad\0path"):
                self.assertIsNone(absolute.fullmatch(value), value)
            for value in ("/bin/wine", "../wine", "bin//wine", "bin\\wine", "C:wine", "bad\npath", "bad\0path"):
                self.assertIsNone(relative.fullmatch(value), value)


if __name__ == "__main__":
    unittest.main()
~~~

**Step 2: Run the tests to prove RED**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts -v
~~~

Expected: FAIL with the explicit missing-schema assertions; no production schema exists yet.

**Step 3: Add the closed bootstrap schema**

Create schemas/linux-bootstrap-request.schema.json. Use the same canonical pretty-JSON style as schemas/macos-bootstrap-request.schema.json, but require all seven fields. The effective contract must be:

~~~json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://compatforge.dev/schemas/linux-bootstrap-request.schema.json",
  "title": "CompatForge Linux Local Context Bootstrap Request",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schemaVersion",
    "runtimeStoreRoot",
    "storageRoot",
    "materializedRoot",
    "wine",
    "wineserver",
    "version"
  ],
  "properties": {
    "schemaVersion": {"const": "1"},
    "runtimeStoreRoot": {"$ref": "#/$defs/absoluteLinuxPath"},
    "storageRoot": {"$ref": "#/$defs/absoluteLinuxPath"},
    "materializedRoot": {"$ref": "#/$defs/absoluteLinuxPath"},
    "wine": {"$ref": "#/$defs/relativePath"},
    "wineserver": {"$ref": "#/$defs/relativePath"},
    "version": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[0-9][0-9A-Za-z._+-]{0,127}$"
    }
  },
  "$defs": {
    "absoluteLinuxPath": {
      "type": "string",
      "minLength": 2,
      "maxLength": 4096,
      "pattern": "^/(?!\\.\\.?(?:/|$))(?!.*(?:/\\.\\.?)(?:/|$))(?!.*//)(?!.*\\\\)(?!.*[\\u0000\\r\\n])[^/]+(?:/[^/]+)*$"
    },
    "relativePath": {
      "type": "string",
      "minLength": 1,
      "maxLength": 1024,
      "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.?(?:/|$))(?!.*[\\\\:])(?!.*[\\u0000\\r\\n])[^/]+(?:/[^/]+)*$"
    }
  }
}
~~~

Format the actual file with the repository's established two-space indentation and one final newline.

**Step 4: Add the closed Provider schema**

Create schemas/linux-provider.schema.json by mirroring the safe definitions in schemas/macos-provider.schema.json and applying these exact differences:

- title and ID identify Linux;
- architecture is const x86_64;
- capabilities is const [guest-x86_64];
- wined3dCapabilities is const [opengl];
- no d3dmetal object;
- all absolute paths use absoluteLinuxPath;
- digest uses lowercase canonical sha256 only.
- IDs are 2..128 characters, versions 1..128, absolute paths at most 4096, and relative entrypoints at most 1024.
- versions use ^[0-9][0-9A-Za-z._+-]{0,127}$; every path rejects NUL, CR, and LF; Provider $defs use the same absoluteLinuxPath/relativePath patterns as bootstrap.

The Wine Runtime required fields are exactly:

~~~json
[
  "providerId",
  "packId",
  "packDigest",
  "version",
  "architecture",
  "materializedRoot",
  "wine",
  "wineserver",
  "capabilities",
  "wined3dCapabilities"
]
~~~

Verified entrypoints remain closed objects with exactly path and digest. The schema tests must exercise positive/negative path, ID, version, digest, and exact-array examples against these definitions; checking only that keys exist is insufficient.

**Step 5: Authenticate the schema additions in the repository validator**

Add these two names to BOTTLE_MIGRATION_SCHEMA_NAMES in scripts/validate_repository.py:

~~~python
"linux-bootstrap-request.schema.json",
"linux-provider.schema.json",
~~~

Do not change any pinned Bottle schema digest. The global schema-name set is the only trust-root update required for these additive documents.

**Step 6: Run GREEN tests and the repository validator**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts -v
& $CF_PYTHON -B scripts\validate_repository.py
git diff --check
~~~

Expected: two schema tests pass, repository contracts are internally consistent, and diff check is empty.

**Step 7: Commit**

~~~powershell
git add schemas/linux-provider.schema.json schemas/linux-bootstrap-request.schema.json tests/test_linux_provider_contracts.py scripts/validate_repository.py
git commit -m "test: define Linux provider contracts"
~~~

## Task 3: Scaffold the Linux Provider and validate serialized configuration

**Files:**

- Create: crates/compatforge-provider-linux/Cargo.toml
- Create: crates/compatforge-provider-linux/src/lib.rs
- Modify: Cargo.toml:3-17
- Test: crates/compatforge-provider-linux/src/lib.rs

**Step 1: Add the crate shell and a failing configuration test**

Create the crate manifest with only existing workspace dependencies:

~~~toml
[package]
name = "compatforge-provider-linux"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
compatforge-domain = { path = "../compatforge-domain" }
compatforge-runtime = { path = "../compatforge-runtime" }
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true

[dev-dependencies]
compatforge-orchestrator = { path = "../compatforge-orchestrator" }

[lints]
workspace = true
~~~

Add crates/compatforge-provider-linux to the root workspace members.

Start src/lib.rs with deny(unsafe_op_in_unsafe_fn), no unsafe code, the serde imports, the contract structs named below, and this test before implementing validate. Task 5 will later isolate the only audited Unix unsafe calls in one module:

~~~rust
#[test]
fn configuration_is_closed_and_x86_64_only() {
    let mut value = valid_config_json();
    value["wineRuntime"]["architecture"] = serde_json::json!("arm64");
    let config: LinuxProviderConfig = serde_json::from_value(value).unwrap();
    assert!(matches!(
        config.validate(),
        Err(LinuxProviderError::InvalidConfig("wineRuntime.architecture"))
    ));

    let mut value = valid_config_json();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<LinuxProviderConfig>(value).is_err());
}
~~~

valid_config_json must return a complete Linux config using /runtime-store, /runtime, relative bin/wine and bin/wineserver, canonical lowercase digests, guest-x86_64, and opengl.

**Step 2: Run the focused test to prove RED**

Run:

~~~powershell
cargo test -p compatforge-provider-linux configuration_is_closed_and_x86_64_only --locked
~~~

Expected: compilation fails because LinuxProviderConfig/validate and LinuxProviderError are not implemented.

**Step 3: Implement the closed DTOs**

Implement these public serde types with rename_all = camelCase and deny_unknown_fields:

~~~rust
pub struct LinuxProviderConfig {
    pub schema_version: String,
    pub runtime_store_root: String,
    pub wine_runtime: WineRuntimeConfig,
}

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
}

pub struct VerifiedEntrypoint {
    pub path: String,
    pub digest: String,
}

pub struct LinuxLocalContextRequest {
    pub schema_version: String,
    pub runtime_store_root: String,
    pub storage_root: String,
    pub materialized_root: String,
    pub wine: String,
    pub wineserver: String,
    pub version: String,
}

pub struct LinuxLocalContextReceipt {
    pub schema_version: String,
    pub source: String,
    pub version: String,
    pub architecture: CpuArchitecture,
    pub pack_id: String,
    pub pack_digest: String,
    pub capabilities: Vec<String>,
}

pub struct LinuxLocalContext {
    pub config: CoreConfig,
    pub receipt: LinuxLocalContextReceipt,
}
~~~

Derive Debug, Clone, PartialEq/Eq where possible, Deserialize for inputs, and Serialize for all externally emitted contracts.

At this point implement only enough validate behavior for configuration_is_closed_and_x86_64_only to pass: schema version and architecture checks. Run that one test GREEN before adding any broader lexical validation.

**Step 4: Write the lexical negative tables before implementing them**

Cover:

- unknown fields at every object level;
- /, Windows drive paths, UNC paths, repeated slash, trailing slash, dot/dot-dot, newline, and NUL roots;
- absolute/traversing/backslash/drive-prefixed entrypoints;
- uppercase or non-sha256 digest;
- empty/oversized version;
- arm64/unknown architecture;
- missing, duplicate, reordered, or extra capabilities.

Each invalid value must return a closed field/category error without reflecting the supplied path.

Name the tables linux_absolute_path_rejects_noncanonical_serialized_forms and configuration_rejects_every_closed_contract_mutation.

**Step 5: Prove the lexical tests are RED**

Run:

~~~powershell
cargo test -p compatforge-provider-linux linux_absolute_path_rejects_noncanonical_serialized_forms --locked
cargo test -p compatforge-provider-linux configuration_rejects_every_closed_contract_mutation --locked
~~~

Expected: both tests compile, and cases not covered by the minimal schema/architecture validator fail their assertions.

**Step 6: Implement purely lexical validation**

Use existing domain helpers for schema version, IDs, digests, and portable relative paths. Add a private serialized_linux_absolute_path helper that:

- requires a leading slash and at least one non-root component;
- rejects backslashes, NUL, CR, LF, empty interior components, dot, and dot-dot;
- rejects an absolute path longer than 4096 bytes or relative path longer than 1024 bytes;
- behaves identically when the crate is tested on Windows.

LinuxProviderConfig::validate must require:

- schema version 1;
- Linux-form runtimeStoreRoot and materializedRoot;
- canonical provider/pack IDs no longer than 128 bytes and lowercase canonical digests;
- version matches ^[0-9][0-9A-Za-z._+-]{0,127}$ byte-for-byte;
- architecture exactly CpuArchitecture::X86_64;
- capabilities exactly [guest-x86_64];
- wined3dCapabilities exactly [opengl];
- both entrypoint paths and digests valid.

LinuxLocalContextRequest::validate must apply the same root/path/version rules. Filesystem existence and root overlap are deferred to bootstrap.

**Step 7: Run GREEN tests**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-provider-linux --locked
cargo clippy -p compatforge-provider-linux --all-targets --locked -- -D warnings
~~~

Expected: all new crate tests pass and Clippy has no warnings.

**Step 8: Commit**

~~~powershell
git add Cargo.toml Cargo.lock crates/compatforge-provider-linux
git commit -m "feat: add Linux provider configuration"
~~~

## Task 4: Parse ELF64 and verify pinned entrypoints before execution

**Files:**

- Create: crates/compatforge-provider-linux/src/elf.rs
- Modify: crates/compatforge-provider-linux/src/lib.rs
- Test: crates/compatforge-provider-linux/src/elf.rs
- Test: crates/compatforge-provider-linux/src/lib.rs

**Step 1: Write the failing ELF parser table**

Use a 64-byte in-memory helper; do not invoke readelf, file, a shell, or a host compiler:

~~~rust
fn elf64_x86_64(object_type: u16) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&object_type.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // EM_X86_64
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // ELF64 e_ehsize
    bytes
}

#[test]
fn accepts_only_little_endian_x86_64_exec_or_dyn_elf() {
    assert!(parse_x86_64(&elf64_x86_64(2)).is_ok());
    assert!(parse_x86_64(&elf64_x86_64(3)).is_ok());
    for mutation in [
        Mutant::Magic,
        Mutant::Class32,
        Mutant::BigEndian,
        Mutant::MachineArm64,
        Mutant::Relocatable,
        Mutant::HeaderVersion,
        Mutant::HeaderSize,
        Mutant::Truncated,
    ] {
        assert!(parse_x86_64(&mutated_elf(mutation)).is_err(), "{mutation:?}");
    }
}
~~~

**Step 2: Run the parser test to prove RED**

Run:

~~~powershell
cargo test -p compatforge-provider-linux accepts_only_little_endian_x86_64_exec_or_dyn_elf --locked
~~~

Expected: FAIL because elf::parse_x86_64 does not exist.

**Step 3: Implement a bounded parser**

parse_x86_64 reads offsets only after checking for the complete 64-byte ELF64 header. It must verify:

- bytes 0..4 are 7f 45 4c 46;
- EI_CLASS is 2;
- EI_DATA is 1;
- EI_VERSION is 1;
- e_type is 2 or 3;
- e_machine is 62;
- e_version is 1.
- e_ehsize is 64.

Return a small closed ElfError enum. Never inspect section headers, allocate based on ELF counts, or run an external tool.

**Step 4: Write failing filesystem evidence tests**

Add tests around verify_entrypoint:

~~~rust
#[test]
fn entrypoint_requires_containment_digest_regular_file_and_elf() {
    let fixture = EntryFixture::new();
    assert!(verify_entrypoint(
        &fixture.root,
        &fixture.verified("bin/wine"),
    )
    .is_ok());

    assert_rejected(fixture.digest_mismatch());
    assert_rejected(fixture.directory_entry());
    assert_rejected(fixture.non_elf_entry());
    assert_rejected(fixture.truncated_entry());
}
~~~

On Unix only, also test no executable bits, an escaping symlink, and an internal symlink whose canonical target remains inside the root. The escaping link must fail; the internal link may succeed but the returned path must be the canonical regular target.

**Step 5: Implement entrypoint evidence**

Implement:

- streaming sha256_file with a fixed 64 KiB buffer;
- read_elf_header that reads at most 64 bytes;
- cfg(unix) executable-bit enforcement with PermissionsExt;
- cfg(not(unix)) regular-file behavior so pure tests compile on Windows;
- canonicalize root and entrypoint;
- require the canonical entrypoint to start with the canonical root;
- require a regular file, configured digest equality, and valid x86_64 ELF;
- return the canonical absolute path.

Do not expose supplied paths in Display implementations. EvidenceFailure variants should describe only MaterializedRoot, Entrypoint, Digest, Elf, Architecture, RuntimePack, Version, and Command classes.

**Step 6: Run GREEN and mutation-focused tests**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-provider-linux elf --locked
cargo test -p compatforge-provider-linux entrypoint --locked
cargo clippy -p compatforge-provider-linux --all-targets --locked -- -D warnings
~~~

Expected: all parser and entrypoint tables pass on Windows; Unix-only permission/symlink cases run in Ubuntu CI.

**Step 7: Commit**

~~~powershell
git add crates/compatforge-provider-linux/src/elf.rs crates/compatforge-provider-linux/src/lib.rs
git commit -m "feat: verify Linux ELF runtime entrypoints"
~~~

## Task 5: Execute bounded, exact Wine version probes

**Files:**

- Create: crates/compatforge-provider-linux/src/probe.rs
- Create: crates/compatforge-provider-linux/src/unix_process_group.rs
- Modify: crates/compatforge-provider-linux/Cargo.toml
- Modify: crates/compatforge-provider-linux/src/lib.rs
- Test: crates/compatforge-provider-linux/src/probe.rs

**Step 1: Write failing stream-normalization tests**

Add table tests for these exact release formats:

~~~rust
#[test]
fn release_version_streams_are_exact_and_distinct() {
    assert_eq!(parse_wine_version(b"wine-11.0\n", b"", "11.0").unwrap(), "11.0");
    assert_eq!(parse_wineserver_version(b"", b"Wine 11.0\n", "11.0").unwrap(), "11.0");
    for output in invalid_version_outputs() {
        assert!(output.parse().is_err(), "{}", output.name);
    }
}
~~~

invalid_version_outputs must cover swapped streams, extra blank or nonblank lines, leading/trailing spaces, ambiguous prefixes, mismatched declared versions, invalid UTF-8, embedded NUL, and more than one terminal newline. Permit exactly no terminator, one LF, or one CRLF.

**Step 2: Prove parser RED**

Run:

~~~powershell
cargo test -p compatforge-provider-linux release_version_streams_are_exact_and_distinct --locked
~~~

Expected: FAIL because the version parsers do not exist.

**Step 3: Implement only the strict byte parsers and prove GREEN**

Implement parse_wine_version and parse_wineserver_version against the exact accepted terminators and invalid table. Also declare the ProbeCommand trait and a compiling probe_runtime_with entry point whose temporary closed behavior returns LinuxProviderError::UnsupportedHost without invoking the injected command. This makes the next RED a behavior assertion rather than a missing-symbol error. Do not start a process in this step.

Run:

~~~powershell
cargo test -p compatforge-provider-linux release_version_streams_are_exact_and_distinct --locked
~~~

Expected: PASS.

**Step 4: Write command-boundary and rehash tests before implementation**

Define a RecordingProbeCommand test double and first write probe_command_is_exact_bounded_and_rehashed. It must assert the executable, argv, cwd, environment, five-second absolute deadline, combined 65,536-byte budget, command order, and four digest observations. Script a mutation after the first probe and assert Provider verification returns integrity failure before a Context is emitted.

Under cfg(target_os = "linux"), also write system_probe_ tests that compile or launch a temporary test helper and cover:

- exact argv, cwd, and environment allowlist;
- stdout+stderr exactly at the cap and at cap+1;
- a no-newline flood;
- a forked child that holds stdout open after the parent exits;
- timeout and overflow both leave the process group absent and the root child reaped.

Use explicit current_exe/temp helper paths in tests. Do not call sh, env, timeout, pkill, or kill executables.

**Step 5: Prove command-boundary RED**

Run on every host:

~~~powershell
cargo test -p compatforge-provider-linux probe_command_is_exact_bounded_and_rehashed --locked
~~~

Expected: the test compiles against the declared ProbeCommand seam and fails because Provider verification does not yet execute the two commands or perform the post-probe hashes.

On Ubuntu also run:

~~~bash
cargo test -p compatforge-provider-linux system_probe_ --locked
~~~

Expected: FAIL because the production Linux bounded process-group adapter is absent.

**Step 6: Implement the exact bounded command contract and rehash**

Define ProbeCommand so tests can inspect the executable, argv, cwd, environment, timeout, and combined output cap. SystemProbeCommand must execute exactly:

~~~text
<canonical-wine> --version
<canonical-wineserver> --version
~~~

For each command:

- use no shell and no PATH lookup;
- set cwd to canonical materializedRoot;
- env_clear, then set only LANG=C, LC_ALL=C, and WINEDEBUG=-all;
- use a five-second monotonic timeout;
- capture stdout and stderr as bytes with one shared 65,536-byte budget;
- read cap+1 and reject overflow rather than truncating;
- reject a nonzero or signalled status;
- kill and reap the complete probe process group on timeout, overflow, or reader failure.

Do not use Command::output because its capture is unbounded.

In Provider evidence verification, hash Wine and Wineserver before the first probe and again after the second probe. All four values must equal the configured digests. This catches persistent mutation during probing but does not claim to eliminate pathname TOCTOU.

Keep the crate-level deny(unsafe_op_in_unsafe_fn), add libc.workspace = true, and confine every unsafe call to unix_process_group.rs. Use std::os::unix::process::CommandExt::process_group(0) to create the group and a documented libc::kill(-pgid, SIGKILL) call to terminate it. No other Provider module may contain unsafe.

On non-Linux targets, the production SystemProbeCommand must return UnsupportedHost without starting a process. Injected ProbeCommand implementations remain available for portable unit tests.

Implement in this order, rerunning probe_command_is_exact_bounded_and_rehashed after each portable increment: command specification; pre-probe hashes; injected command calls; strict stream parsing; post-probe hashes. Then implement the Linux adapter in this order, rerunning system_probe_: group creation; fixed-buffer readers; timeout/overflow termination; bounded root reap; group-absence confirmation.

**Step 7: Run GREEN**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-provider-linux version --locked
cargo clippy -p compatforge-provider-linux --all-targets --locked -- -D warnings
~~~

On Ubuntu also run:

~~~bash
cargo test -p compatforge-provider-linux system_probe --locked
~~~

Expected: portable parsing tests pass everywhere and process-group tests pass on Linux.

**Step 8: Commit**

~~~powershell
git add crates/compatforge-provider-linux
git commit -m "feat: add bounded Linux Wine version probes"
~~~

## Task 6: Bind Runtime Store evidence into the Provider snapshot

**Files:**

- Modify: crates/compatforge-provider-linux/src/lib.rs
- Test: crates/compatforge-provider-linux/src/lib.rs

**Step 1: Write the complete fail-closed Pack, Provider, descriptor, and binding tests**

Write this test before the happy path:

~~~rust
#[test]
fn unrelated_verified_pack_cannot_authorize_external_entrypoints() {
    let (config, manifest) = self_consistent_but_unrelated_manifest();
    assert!(associate_verified_manifest(&config.wine_runtime, &manifest).is_err());
}
~~~

Keep associate_verified_manifest pure so this RED runs on Windows. The unrelated manifest must be self-consistent under Runtime Pack rules while naming another component digest or entrypoint. A Linux integration test must also install that manifest and prove the public Provider returns unavailable with no RuntimeBinding. This proves Provider-to-Pack association is a separate obligation.

Before any Task 6 implementation, add these named tables:

- pack_association_rejects_every_manifest_mutation: ID, version, host OS/architecture, capability order/content, component count/name/version/object digest, entrypoint key/path, and every extra mapping;
- configured_digest_ignores_a_different_active_ref: install two valid manifests for one Pack ID, point the active ref at the other digest, and require association with only the explicitly configured digest;
- provider_failure_semantics_are_closed_and_path_redacted: malformed configuration and unsupported host return Err, while each missing/mutated Store object, entrypoint, ELF, permission, command, and version observation yields unavailable with no RuntimeBinding and no reflected path;
- planning_descriptors_are_exact_and_preview_limited: require exactly Wine guest-x86_64, native x86_64, and same-Pack wined3d/opengl descriptors without any GUI/D3D validation claim;
- runtime_binding_contains_only_fixed_linux_runtime_values: require canonical Wine/Wineserver paths, the exact eight fixed environment values below, the protected-root association, and no private root in the public receipt.

All pure tables use injected manifests/host/evidence observations and execute on Windows. Add separate cfg(target_os = "linux") public Provider cases for Store objects, permissions, entrypoints, and real SystemProbeCommand; Windows skips are not substitutes.

**Step 2: Prove RED**

Run:

~~~powershell
cargo test -p compatforge-provider-linux unrelated_verified_pack_cannot_authorize_external_entrypoints --locked
cargo test -p compatforge-provider-linux pack_association_ --locked
cargo test -p compatforge-provider-linux provider_failure_semantics_ --locked
cargo test -p compatforge-provider-linux planning_descriptors_ --locked
cargo test -p compatforge-provider-linux runtime_binding_ --locked
~~~

Expected: the tables are present and FAIL because association, Provider mapping, descriptors, and RuntimeBinding are not implemented.

**Step 3: Implement exact Pack association**

Load only config.wineRuntime.packDigest through RuntimePackStore::verified_manifest. Never resolve authorization through an active ref. Require:

- manifest ID/version exactly equal the configured Pack ID/version;
- host os=linux and architecture=x86_64;
- capabilities exactly [guest-x86_64];
- exactly two required components named wine-entrypoint and wineserver-entrypoint;
- each component version equals the configured Runtime version;
- each component object digest equals its configured entrypoint digest;
- the Wine component maps entrypoint wine to the configured relative Wine path;
- the Wineserver component maps entrypoint wineserver to the configured relative Wineserver path;
- no extra component, entrypoint, capability, or host mapping is accepted.

Make unrelated_verified_pack_cannot_authorize_external_entrypoints, pack_association_rejects_every_manifest_mutation, and configured_digest_ignores_a_different_active_ref pass before continuing. The explicit configured digest must remain the only manifest used.

**Step 4: Implement host and evidence failure semantics**

LinuxProviderSet::probe and probe_with must:

- return Err for malformed configuration or an unsupported non-Linux/non-x86_64 host report;
- return an unavailable, canonical CapabilityReport with no RuntimeBinding for missing/mutated Store objects, entrypoint, ELF, permissions, command, or version evidence;
- never fall back to another Pack, PATH, HOME, a network action, or a less capable binding.

Keep errors path-redacted. Evidence details may identify only a closed category.

Make provider_failure_semantics_are_closed_and_path_redacted pass before adding descriptors.

**Step 5: Emit the exact planning descriptors**

The available report must advertise:

- the Wine Runtime for guest-x86_64;
- the native x86_64 translator route;
- the same Pack's wined3d/opengl planning descriptor.

The graphics descriptor only satisfies the existing Planner selection contract. No test or public field may call it GUI, D3D, or graphics validation.

Make planning_descriptors_are_exact_and_preview_limited pass before adding RuntimeBinding.

**Step 6: Emit the RuntimeBinding**

Bind canonical Wine/Wineserver paths and exactly these fixed environment values, in addition to any existing planner-added Bottle variables:

~~~text
COMPATFORGE_RUNTIME_PACK=<packId>
COMPATFORGE_RUNTIME_PACK_DIGEST=<packDigest>
COMPATFORGE_RUNTIME_EXECUTABLE_SHA256=<wine digest>
COMPATFORGE_WINESERVER_EXECUTABLE_SHA256=<wineserver digest>
WINEDEBUG=-all
WINESERVER=<canonical wineserver>
WINEARCH=win64
WINEDLLOVERRIDES=mscoree,mshtml=
~~~

Set working_directory only when required by the existing Planner contract. Carry private protected-root information needed to reject Runtime Store/Storage overlap; never serialize those roots in the public receipt.

Make runtime_binding_contains_only_fixed_linux_runtime_values pass before running the combined suite.

**Step 7: Run GREEN and planner integration tests**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-provider-linux pack --locked
cargo test -p compatforge-provider-linux provider --locked
cargo test -p compatforge-provider-linux planner --locked
cargo clippy -p compatforge-provider-linux --all-targets --locked -- -D warnings
~~~

Expected: all Pack mutation tables fail closed and the happy path compiles one Wine/native/wined3d plan.

The pure association/planner tables must pass on Windows. The public filesystem/probe happy path and Unix mutation cases must additionally pass in the Ubuntu lane; a Windows skip is not that evidence.

**Step 8: Commit**

~~~powershell
git add crates/compatforge-provider-linux/src/lib.rs
git commit -m "feat: bind Linux runtime evidence to CoreConfig"
~~~

## Task 7: Bootstrap only an explicit, disjoint local Runtime

**Files:**

- Modify: crates/compatforge-provider-linux/src/lib.rs
- Test: crates/compatforge-provider-linux/src/lib.rs

**Step 1: Write failing mutation-order tests**

Start with:

~~~rust
#[test]
fn bootstrap_validation_precedes_every_mutation() {
    let operations = RecordingBootstrapOperations::default();
    let result = validate_then_bootstrap(&invalid_request(), &operations);
    assert!(result.is_err());
    assert!(operations.recorded().is_empty());
}
~~~

Keep the operation-order test portable through an injected recording seam. In Linux integration tests, call the public bootstrap and cover every permutation of equal/ancestor/descendant Runtime Store, Storage, and materialized roots, including lexical dot segments and symlink aliases; each failure must leave Store, Storage, and output unmodified.

Before implementing, also write failing tests named bootstrap_receipt_is_exact_and_path_free, bootstrap_is_idempotent_for_the_same_digest, bootstrap_refuses_conflicting_active_ref_before_install, bootstrap_allows_only_documented_immutable_leftovers_after_install_failure, and bootstrap_rejects_unsafe_store_control_paths. Their tables cover missing materializedRoot, Store objects/manifests/refs symlinks or non-directories, wide permissions, install/ref-write failure, and staging cleanup failure.

**Step 2: Prove RED**

Run:

~~~powershell
cargo test -p compatforge-provider-linux bootstrap_validation_precedes_every_mutation --locked
cargo test -p compatforge-provider-linux bootstrap_ --locked
~~~

Expected: FAIL because local bootstrap is absent.

**Step 3: Resolve destinations without creating them**

Implement a helper that canonicalizes the nearest existing ancestor and safely appends checked missing components. Before any mkdir/install/ref/output action:

- materializedRoot must already exist and canonicalize to a directory;
- Runtime Store and Storage may be absent or pre-existing private directories that pass the ownership, permission, and Store-control-path checks;
- all three physical roots must be pairwise unequal and neither ancestor nor descendant;
- reject a symlink or non-directory at any Store path component;
- on Unix require newly created private directories to be 0700 and reject pre-existing group/other-writable Store control directories.

Do not canonicalize by first creating attacker-selected paths.

**Step 4: Register the Preview Pack under the Preview single-writer rule**

Use fixed identities:

~~~text
providerId = wine-linux-x86-64-preview
packId = wine-linux-x86-64-local-preview
~~~

Build a two-component bundle containing only copies of the already-verified Wine and Wineserver entrypoint files plus the manifest. Create an unpredictable exclusive staging directory beneath a verified 0700 parent; create files with create_new. Never remove_dir_all a predictable path.

Require the caller to hold single-writer ownership of this Runtime Store for the bootstrap call. Before install, read any active ref: an identical digest is idempotent, while a different digest fails before Provider mutation. Validate the complete request, roots, files, ELF, permissions, digests, and versions before installing the Pack or writing an active ref. On every error, remove only the staging directory created by this invocation. Do not remove caller roots.

Do not claim cross-process compare-and-install atomicity: RuntimePackStore currently has only an in-process lock. An install/ref failure may leave valid content-addressed object/manifest files, but it must not overwrite a pre-existing conflicting ref, emit a Context, or print a success receipt. Test this exact allowed-leftover boundary. The real Runner avoids it by using a new exclusive Store root.

**Step 5: Re-enter the normal Provider path**

After RuntimePackStore installs the bundle, synthesize LinuxProviderConfig with the installed digest and call LinuxProviderSet::probe_with. Do not construct CoreConfig independently. The returned context must use the same Pack association and entrypoint verification as explicit Provider configuration.

**Step 6: Implement receipt and idempotency behavior against the existing RED tests**

Serialize the receipt with exactly:

~~~text
schemaVersion, source, version, architecture, packId, packDigest, capabilities
~~~

source is explicit-override, architecture is x86_64, and no absolute input path appears recursively in the receipt. A repeated identical bootstrap may reuse the same immutable object/manifest digest. If an existing active ref points elsewhere, bootstrap must fail before mutation rather than overwrite it; explicit Provider authorization still uses only its configured digest.

Make every previously written receipt, idempotency, ref, failure, and cleanup test pass without weakening its mutation assertions.

**Step 7: Run GREEN**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-provider-linux bootstrap --locked
cargo test -p compatforge-provider-linux receipt --locked
cargo clippy -p compatforge-provider-linux --all-targets --locked -- -D warnings
~~~

Expected: portable validation/order tests pass on Windows. On Ubuntu, public bootstrap, Unix ownership/permission/symlink tests, idempotency, and physical no-mutation checks must also pass before this task is considered GREEN.

**Step 8: Commit**

~~~powershell
git add crates/compatforge-provider-linux/src/lib.rs
git commit -m "feat: bootstrap explicit Linux Wine preview"
~~~

## Task 8: Enforce Runtime identity invariants at the spawn boundary

**Files:**

- Modify: crates/compatforge-process/src/lib.rs:558-584
- Test: crates/compatforge-process/src/lib.rs

**Step 1: Write the pre-spawn negative tests**

Add tests that start from an otherwise valid Wine LaunchPlan and mutate one field at a time:

Create RuntimeEvidenceFixture with two distinct executable files, their real digests, one bound prefix, complete Pack variables, and three command-log paths. Its valid_plan method must return a fully valid managed Wine plan. Its alternate_wineserver and alternate_prefix methods return existing test-owned paths; alternate_pack_digest returns a syntactically valid digest unequal to the plan's Pack digest. Use this common assertion so every mutation is checked through ProcessSupervisor::start, not only through the private validator:

~~~rust
fn assert_runtime_evidence_rejected(
    fixture: &RuntimeEvidenceFixture,
    mutate: impl FnOnce(&mut LaunchPlan),
) {
    let mut plan = fixture.valid_plan();
    mutate(&mut plan);

    assert!(matches!(
        ProcessSupervisor::start(&plan),
        Err(ProcessError::InvalidRuntimeEvidence(_))
    ));
    fixture.assert_no_command_logs();
}
~~~

Then add the six tests with these exact one-field mutations:

~~~rust
#[test]
fn runtime_evidence_mismatched_wineserver_environment_is_rejected_before_spawn() {
    let fixture = RuntimeEvidenceFixture::new();
    assert_runtime_evidence_rejected(&fixture, |plan| {
        plan.process.environment.insert(
            "WINESERVER".into(),
            fixture.alternate_wineserver().to_string_lossy().into_owned(),
        );
    });
}

#[test]
fn runtime_evidence_mismatched_pack_environment_is_rejected_before_spawn() {
    let fixture = RuntimeEvidenceFixture::new();
    assert_runtime_evidence_rejected(&fixture, |plan| {
        plan.process
            .environment
            .insert("COMPATFORGE_RUNTIME_PACK".into(), "different-pack".into());
    });

    let fixture = RuntimeEvidenceFixture::new();
    assert_runtime_evidence_rejected(&fixture, |plan| {
        plan.process.environment.insert(
            "COMPATFORGE_RUNTIME_PACK_DIGEST".into(),
            fixture.alternate_pack_digest(),
        );
    });
}

#[test]
fn runtime_evidence_missing_or_unpaired_digests_are_rejected_before_spawn() {
    for missing in [
        RUNTIME_EXECUTABLE_DIGEST_ENV,
        WINESERVER_EXECUTABLE_DIGEST_ENV,
        "COMPATFORGE_RUNTIME_PACK_DIGEST",
    ] {
        let fixture = RuntimeEvidenceFixture::new();
        assert_runtime_evidence_rejected(&fixture, |plan| {
            plan.process.environment.remove(missing);
        });
    }
}

#[test]
fn runtime_evidence_swapped_digests_are_rejected_before_spawn() {
    let fixture = RuntimeEvidenceFixture::new();
    assert_runtime_evidence_rejected(&fixture, |plan| {
        let runtime = plan
            .process
            .environment
            .remove(RUNTIME_EXECUTABLE_DIGEST_ENV)
            .unwrap();
        let wineserver = plan
            .process
            .environment
            .remove(WINESERVER_EXECUTABLE_DIGEST_ENV)
            .unwrap();
        plan.process
            .environment
            .insert(RUNTIME_EXECUTABLE_DIGEST_ENV.into(), wineserver);
        plan.process
            .environment
            .insert(WINESERVER_EXECUTABLE_DIGEST_ENV.into(), runtime);
    });
}

#[test]
fn runtime_evidence_wine_lifecycle_without_complete_evidence_is_rejected_before_spawn() {
    let fixture = RuntimeEvidenceFixture::new();
    assert_runtime_evidence_rejected(&fixture, |plan| {
        plan.process.environment.remove(RUNTIME_EXECUTABLE_DIGEST_ENV);
        plan.process
            .environment
            .remove(WINESERVER_EXECUTABLE_DIGEST_ENV);
    });
}

#[test]
fn runtime_evidence_wineprefix_must_equal_lifecycle_prefix() {
    let fixture = RuntimeEvidenceFixture::new();
    assert_runtime_evidence_rejected(&fixture, |plan| {
        plan.process.environment.insert(
            "WINEPREFIX".into(),
            fixture.alternate_prefix().to_string_lossy().into_owned(),
        );
    });
}
~~~

Each test must prove the Wine, Guest, and Wineserver test logs were never created; wineboot is the first external command and must not run on invalid evidence.

**Step 2: Prove RED**

Run:

~~~powershell
cargo test -p compatforge-process runtime_evidence_ --locked
~~~

Expected: at least the WINESERVER, Pack ID/digest, and WINEPREFIX mismatch assertions fail because the current validator accepts them and continues beyond the required pre-spawn rejection point.

**Step 3: Extend verify_pinned_runtime**

Define managed evidence as a plan with a Wineserver lifecycle or any of COMPATFORGE_RUNTIME_PACK_DIGEST, COMPATFORGE_RUNTIME_EXECUTABLE_SHA256, COMPATFORGE_WINESERVER_EXECUTABLE_SHA256, or WINESERVER. COMPATFORGE_RUNTIME_PACK and WINEPREFIX alone do not activate managed evidence because the existing FFI smoke fixture intentionally carries those legacy markers without lifecycle/digests; lock this compatibility exception with a named test.

For managed evidence, require the complete set below before any Wine command:

- plan.runtime.provider is RuntimeKind::Wine;
- both executable digest variables are present and valid under the existing cross-platform digest contract;
- lifecycle.wineserver exists;
- process.environment.WINESERVER equals lifecycle.wineserver.executable byte-for-byte;
- process.environment.WINEPREFIX equals lifecycle.wineserver.prefix byte-for-byte;
- process.environment.COMPATFORGE_RUNTIME_PACK equals plan.runtime.pack_id;
- process.environment.COMPATFORGE_RUNTIME_PACK_DIGEST equals plan.runtime.pack_digest;
- each path hashes to its corresponding, unswapped digest.

Retain the unmanaged path only for plans with no lifecycle/activating field, including the named legacy Pack+WINEPREFIX fixture. Every other partial field must fail closed. This check proves LaunchPlan internal consistency and file digests; it does not re-associate the Store manifest, which remains the Provider/PreparedLaunch precondition.

Do not globally reject uppercase hex here: the existing macOS schema and domain contract accept it. Linux Provider input remains lowercase-only at its own new schema/validation boundary.

**Step 4: Run regression tests**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-process pinned_runtime --locked
cargo test -p compatforge-process runtime_evidence_ --locked
cargo test -p compatforge-process --locked
cargo test -p compatforge-provider-macos --locked
cargo test -p compatforge-orchestrator --locked
cargo clippy -p compatforge-process --all-targets --locked -- -D warnings
~~~

Expected: new invariants pass and existing macOS RuntimeBindings remain valid.

**Step 5: Commit**

~~~powershell
git add crates/compatforge-process/src/lib.rs
git commit -m "fix: enforce pinned Wine runtime identity"
~~~

## Task 9: Make Wine startup a cleanup transaction

**Files:**

- Modify: crates/compatforge-process/src/lib.rs:95-386
- Modify: crates/compatforge-process/src/lib.rs:454-515
- Modify: crates/compatforge-process/src/lib.rs:1270-1545
- Test: crates/compatforge-process/src/lib.rs

**Step 1: Write startup-failure tests first**

Add portable unit tests through injected spawn, attach, clock, signal, and cleanup seams, plus Linux integration tests for:

- wineboot exits nonzero;
- wineboot exceeds its timeout while a descendant holds a pipe;
- Guest alias preparation fails after WineSession acquire;
- Guest is mutated during wineboot;
- Wine or Wineserver is mutated during wineboot;
- main Guest spawn or process-tree attach fails;
- cleanup -k or -w fails after any of the above.

Use this result matrix:

- when the fixed Wineserver digest still matches and authoritative -w succeeds, run exact -k then -w, release the canonical prefix lease, and allow reacquire; a nonzero -k followed by successful -w remains idempotent success;
- when the Wineserver digest changed, execute neither the substituted -k nor -w, return cleanup failure, and poison/quarantine the canonical prefix lease;
- when -w, bounded reap, or other cleanup fails, return cleanup failure and poison/quarantine the lease rather than making it reusable.

Every case must prove no Guest starts after a digest mismatch. Do not assert that a substituted Wineserver both remains unexecuted and receives cleanup commands.

**Step 2: Prove RED**

Run:

~~~powershell
cargo test -p compatforge-process startup_transaction_ --locked
~~~

Expected: injected tests fail on Windows before implementation; Linux integration tests additionally exercise real process groups without waiting for the production 90-second timeout.

**Step 3: Add a startup cleanup guard**

After WineSession acquisition, wrap the caller-owned Arc in StartupWineSessionGuard and route every fallible pre-LaunchHandle step through it. The guard remains armed across wineboot, font preparation, Guest alias, command spawn, and process-tree attach. Transfer/commit ownership only after the controller and exit watcher have both accepted the same Arc. On error before commit:

1. stop the exact WineSession synchronously;
2. wait for its fixed Wineserver lifecycle to finish;
3. release the canonical prefix lease only on memoized cleanup success, otherwise mark it poisoned;
4. return a closed ProcessError.

Split WineSession stop into a cleanup core with optional event publication so startup can call it before an EventEmitter exists. Memoize the complete StopOutcome, including failure, so concurrent/repeated callers cannot turn a first cleanup failure into Ok. Add closed StartupStage and CleanupStage values to preserve both classes in ProcessError::StartupCleanup without reflecting local paths. Do not rely on Drop to run external commands; dropping an armed or unsuccessfully stopped session poisons rather than releases its lease.

After materialize_launch_directories, canonicalize the prefix used as the lease key and cleanup target. Lexical aliases such as /a/b and /a/./b must contend for one lease.

Introduce the ownership and terminal-state types before rerouting any startup stage:

~~~rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseState {
    Live,
    Released,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopOutcome {
    Complete,
    Failed(CleanupStage),
}

struct StartupWineSessionGuard {
    session: Arc<WineSession>,
    armed: bool,
}

impl StartupWineSessionGuard {
    fn new(session: Arc<WineSession>) -> Self {
        Self { session, armed: true }
    }

    fn commit(mut self) {
        self.armed = false;
    }

    fn abort(mut self, startup: StartupStage) -> Result<(), ProcessError> {
        let outcome = self.session.stop_core(None);
        self.armed = false;
        match outcome {
            StopOutcome::Complete => Err(ProcessError::Startup(startup)),
            StopOutcome::Failed(cleanup) => Err(ProcessError::StartupCleanup { startup, cleanup }),
        }
    }
}

impl Drop for StartupWineSessionGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.poison_lease();
        }
    }
}
~~~

Add stop_outcome: OnceLock<StopOutcome> and lease_state: Mutex<LeaseState> to WineSession. Implement stop_core with get_or_init so only one caller executes cleanup and every later caller receives the same cloned result. Work in this order, running the focused startup_transaction test after each item: canonical lease acquisition; memoized cleanup core; startup guard around wineboot; extend it across font and alias preparation; extend it across spawn and attach; clone the Arc into both long-lived owners; commit the guard.

**Step 4: Put wineboot in a managed process group**

Use the existing platform ProcessTree machinery for wineboot. Its timeout must terminate the complete tree and perform bounded root reap. A forked child holding stdout/stderr must not make start block indefinitely. Preserve the current wineboot command contract and do not invoke a shell. Route font helpers and attach rollback through the same bounded child/tree primitives; no auxiliary subprocess may retain an unbounded wait.

**Step 5: Reverify immediately before Guest spawn and cleanup commands**

After wineboot and alias preparation, call Guest verification and verify_pinned_runtime again immediately before the main spawn. Store the expected Wineserver digest in WineSession and verify it immediately before every natural-idle -w, cleanup -k, cleanup -w, and every ETXTBSY retry. If the path changed, fail cleanup without executing it.

These checks narrow persistent mutation windows but remain pathname-based and must not be described as FD-pinned execution.

**Step 6: Run GREEN and existing lifecycle tests**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-process wineboot --locked
cargo test -p compatforge-process wine_session --locked
cargo test -p compatforge-process mutation --locked
cargo test -p compatforge-process prefix_lease --locked
cargo clippy -p compatforge-process --all-targets --locked -- -D warnings
~~~

Expected: all startup paths either transfer one live session into a LaunchHandle or synchronously produce a memoized cleanup result; only successful cleanup releases the canonical lease.

**Step 7: Commit**

~~~powershell
git add crates/compatforge-process/src/lib.rs
git commit -m "fix: close Wine startup cleanup transaction"
~~~

## Task 10: Bound process output, reap, and supervisor completion

**Files:**

- Modify: crates/compatforge-process/src/lib.rs:790-1240
- Modify: crates/compatforge-process/src/lib.rs:1560-1730
- Test: crates/compatforge-process/src/lib.rs

**Step 1: Write output-budget tests**

Add tests for a fixed 1,048,576-byte combined stdout/stderr budget:

- exactly at cap completes;
- cap+1 emits one Failed event and terminates the tree;
- one no-newline write cannot allocate past cap+1;
- interleaved stdout/stderr share the same budget;
- one-byte/newline-heavy writes cannot create an unbounded event count;
- a descendant holding a pipe cannot hold terminate_and_wait forever.

Also assert RuntimeEvent sequences remain contiguous from zero through the final Exited event and that only one overflow failure is emitted.

**Step 2: Prove RED**

Run:

~~~powershell
cargo test -p compatforge-process output_budget --locked
cargo test -p compatforge-process descendant_holding_pipe --locked
~~~

Expected: current read_until capture exceeds the cap or blocks a reader join.

**Step 3: Replace line-unbounded readers**

Extract a synchronous pump_output(Read, shared_budget, terminate_callback) seam and test it without relying on a test harness pipe. Accumulate output into at most 16 KiB event chunks and use one shared budget for both streams, so the 1 MiB cap also bounds output-event count. Preserve the existing bounded lossy UTF-8 ProcessOutput behavior after enforcing the byte cap; this checkpoint must not redefine arbitrary Windows application encoding. When the shared cap would be exceeded:

1. set a one-shot overflow flag;
2. emit one path-free Failed event;
3. request process-tree termination;
4. stop accepting output bytes.

Wire each production reader to a Weak<TerminationController>; overflow must upgrade it and request the exact launch tree's termination. With fixed chunks and a fixed number of lifecycle events, the existing channel is now bounded by construction even if its type remains mpsc::channel.

Add these exact shared primitives first, then replace stdout and stderr one at a time while keeping the focused tests green:

~~~rust
const MAX_COMBINED_OUTPUT_BYTES: usize = 1_048_576;
const MAX_OUTPUT_EVENT_BYTES: usize = 16 * 1024;

struct OutputBudget {
    remaining: AtomicUsize,
    overflow_emitted: AtomicBool,
}

fn pump_output<R: Read>(
    reader: R,
    stream: OutputStream,
    budget: Arc<OutputBudget>,
    emitter: Arc<EventEmitter>,
    controller: Weak<TerminationController>,
) -> io::Result<()>;
~~~

The implementation must read into a fixed MAX_OUTPUT_EVENT_BYTES buffer, reserve bytes from remaining with one atomic compare/update operation, emit only the reserved prefix, and treat any unreserved byte as overflow. Stdout, stderr, the exit watcher, and cleanup must all clone the same Arc<EventEmitter> so one sequence/terminal state governs every RuntimeEvent. The one caller that changes overflow_emitted from false to true emits Failed and requests termination. Other readers stop without a second failure event.

**Step 4: Write cleanup-quiescence tests before changing completion**

Cover:

- cleanup waits until the supervised process group disappears;
- wineserver -w success plus a still-live group is failure;
- a different process group is never signalled;
- a disarmed/dropped ProcessTree cannot signal a reused group ID;
- failed reap/join sets cleanup_failed and makes terminate_and_wait return Err;
- normal native and Wine launches still end with one Exited event.

Do not implement a product-wide Linux /proc killer in this task. Exact-prefix /proc observation remains Runner evidence for the Preview.

**Step 5: Prove cleanup-quiescence RED**

Run:

~~~powershell
cargo test -p compatforge-process cleanup_waits_until_group_disappears --locked
cargo test -p compatforge-process process_tree_drop_never_signals_reused_group --locked
cargo test -p compatforge-process failed_reap_or_join_refuses_acknowledgement --locked
~~~

Expected: the tests compile against injected signal/clock/join seams and fail because completion can acknowledge before group disappearance, ProcessTree::Drop still signals, or force-kill/reap errors are discarded. If a seam is missing, introduce only the compiling recording trait and keep its production adapter behavior unchanged before rerunning RED.

**Step 6: Make completion waits bounded**

Give every output reader and supervisor worker a completion signal. Normal cleanup acknowledgement requires every worker to signal completion and be joined. Wait only until an explicit monotonic deadline; if cancellation/kill cannot make a worker finish, return bounded Err with no cleanup acknowledgement and never report success. A deadline failure may leave a detached Rust worker as a last-resort failure state, so it must remain ineligible for canary success. Replace the unconditional child.wait after force-kill with a bounded try_wait/reap loop and propagate, rather than discard, every force-kill/reap error.

Represent each worker with a JoinState containing its completion receiver and JoinHandle. Add join_until(deadline) and make TerminationController::join_workers accept the same absolute deadline. Convert one worker at a time in this order: stdout, stderr, exit watcher, timeout watcher. After each conversion, make the prewritten completion-before-deadline and deadline-expiry fake-clock cases pass; never create a fresh per-worker deadline.

On Unix, after force_kill, poll the exact process group with signal 0 until ESRCH or the cleanup deadline. EPERM means the group still exists, not success. Never target a PID or prefix not owned by the LaunchHandle.

Remove the Unix ProcessTree::Drop blind SIGKILL on a stored integer PGID. All signals must flow through an explicit live-tree transaction. Disarm/consume the tree only after root reap and group ESRCH; Drop itself must never signal a possibly reused PGID. Make the injected signal-backend test prove a terminal/disarmed drop emits zero signals.

**Step 7: Run GREEN and cross-platform regression**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-process output --locked
cargo test -p compatforge-process cleanup --locked
cargo test -p compatforge-process emits_started_output_and_exit_in_sequence --locked
cargo test -p compatforge-process --locked
cargo clippy -p compatforge-process --all-targets --locked -- -D warnings
~~~

Expected: all waits and buffers are bounded and existing event semantics remain stable.

**Step 8: Commit**

~~~powershell
git add crates/compatforge-process/src/lib.rs
git commit -m "fix: bound process output and completion"
~~~

## Task 11: Expose exact Linux CLI forms and acknowledge cleanup

**Files:**

- Modify: apps/cli/Cargo.toml
- Modify: apps/cli/src/main.rs:1-180
- Modify: apps/cli/src/main.rs:1022-1054
- Modify: apps/cli/src/main.rs:1308-1375
- Modify: Cargo.lock
- Test: apps/cli/src/main.rs

**Step 1: Write the exact-argv parser tests**

Extract Linux command parsing as Result<Option<LinuxCommand>, InvalidInput>: None means the argv is not a Linux command; Err means it has a provider linux or local linux prefix but is malformed. Cover exactly these forms:

~~~text
provider linux probe <provider-config.json>
provider linux context <provider-config.json> <storage-root>
local linux context <bootstrap-request.json>
local linux context <bootstrap-request.json> <private-context-output.json>
~~~

Any argv beginning with provider linux or local linux that has a misspelled command, missing operand, or extra operand must return InvalidInput and a nonzero CLI exit; it must not fall through to help with success.

Before implementation, also write private_output_ tests through an injected filesystem/write/sync seam. They require an absolute path and existing safe parent, create_new/no overwrite, symlink/directory refusal, Unix mode 0600 at open time, partial-file cleanup on serialization/write/sync failure, and no output when bootstrap validation fails.

**Step 2: Prove parser RED**

Run:

~~~powershell
cargo test -p compatforge-cli linux_provider_argv_accepts_only_exact_forms --locked
cargo test -p compatforge-cli private_output_ --locked
~~~

Expected: FAIL because Linux parsing and the private writer do not exist.

**Step 3: Wire the Linux Provider without changing macOS behavior**

Add compatforge-provider-linux to apps/cli/Cargo.toml. Alias the two platform create_local_context imports so dispatch is unambiguous. Implement the four forms:

- provider linux probe prints only the CapabilityReport;
- provider linux context prints only the private CoreConfig to stdout;
- local linux context without output prints only the public receipt;
- local linux context with output writes the private CoreConfig and prints only the public receipt.

Keep diagnostics on stderr and never echo private input JSON or local paths in a public receipt.

At this step the output form may delegate to a compiling write_new_private_json stub that returns a closed error; do not write an unsafe temporary implementation merely to make dispatch compile.

**Step 4: Implement private-output safety against the existing RED tests**

Implement the output form so the prewritten tests prove it:

- requires an absolute path;
- requires an existing safe parent;
- uses create_new and refuses overwrite;
- refuses an output symlink or directory;
- creates mode 0600 at open time on Unix, never by chmod after writing;
- removes a partial file if serialization/write/sync fails;
- leaves the output absent when bootstrap validation fails.

Define a safe parent as an existing canonical directory that is not a symlink and is owned by the caller on Unix. Implement one write_new_private_json helper and use it only for the new Linux route unless a separate regression test proves another route can adopt it safely.

**Step 5: Run the Linux route tests and commit the additive CLI surface**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-cli linux_ --locked
cargo clippy -p compatforge-cli --all-targets --locked -- -D warnings
git add apps/cli/Cargo.toml apps/cli/src/main.rs Cargo.lock
git commit -m "feat: expose Linux provider CLI"
~~~

Expected: exact Linux forms work, malformed Linux prefixes fail nonzero, and macOS CLI tests remain unchanged.

**Step 6: Write the completion-handshake tests with a fake handle**

Extract the event loop behind supervise_plan into an internal SupervisedLaunch trait with next_event, terminate, terminate_and_wait, and is_finished, plus an injected event-output sink. A fake handle must prove:

- successful Exited still calls terminate_and_wait before returning success;
- Failed requests termination, drains through the terminal event, and waits for cleanup;
- an event stream that closes early still waits for cleanup and returns failure;
- Failed followed forever by Timeout with is_finished=true still enters bounded cleanup and returns failure;
- Failed with no Exited never hangs and cannot succeed;
- a zero Guest exit plus cleanup failure returns failure;
- queued events after the first Failed are drained and printed in sequence;
- event serialization/write/flush failure still triggers cleanup;
- a cleanup deadline/error has final precedence.

Use these interfaces so the state machine is testable without starting a child:

~~~rust
trait SupervisedLaunch {
    fn next_event(&self, timeout: Duration) -> EventPoll;
    fn terminate(&self) -> Result<(), ProcessError>;
    fn terminate_and_wait(&self, graceful_wait: Duration) -> Result<(), ProcessError>;
    fn is_finished(&self) -> bool;
}

trait EventSink {
    fn write_event(&mut self, event: &compatforge_domain::RuntimeEvent) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionMode {
    Normal,
    TerminateAfter(Duration),
}
~~~

Implement SupervisedLaunch for LaunchHandle and EventSink for a stdout JSONL writer. Make supervise_plan create those production adapters and delegate to supervise_launch(&dyn SupervisedLaunch, &mut dyn EventSink, CompletionMode). The fake owns a VecDeque<EventPoll>, call counters, a configurable cleanup result, and a configurable is_finished result; each assertion above must check both the returned status and the exact method-call order.

**Step 7: Implement the generic handshake**

For prepared-launch and existing generic launch commands:

1. stream and validate every received event;
2. remember Failed, TimedOut, GracePeriodExpired, Exited, and output-sink error state;
3. on Failed or sink failure, request termination and immediately enter the bounded completion handshake rather than waiting for an Exited that may never arrive;
4. on Exited, Closed, or a poll Timeout with is_finished=true, call terminate_and_wait with the configured grace budget;
5. after completion, drain queued events with zero-duration polls until empty and validate their sequence;
6. in normal mode (terminate_after=None), return success only for an observed successful Exited, no adverse event, successful output publication, and successful cleanup acknowledgement;
7. in explicit terminate mode, preserve current semantics: if termination was actually requested, an observed Exited may be nonzero and GracePeriodExpired may occur, but Failed, TimedOut, sink error, missing Exited, or cleanup failure still fails; an exit before the requested time uses normal success rules.

Do not alter the pinned macOS transcript protocol or silently turn launch-terminate/prepared-launch-terminate into strict normal-launch mode.

**Step 8: Run completion GREEN and commit separately**

Run:

~~~powershell
cargo fmt --all
cargo test -p compatforge-cli supervise_plan --locked
cargo test -p compatforge-cli pinned_ --locked
cargo test -p compatforge-cli --locked
cargo clippy -p compatforge-cli --all-targets --locked -- -D warnings
git add apps/cli/src/main.rs
git commit -m "fix: wait for supervised cleanup before CLI exit"
~~~

Expected: no generic success is emitted before cleanup completes, and the pinned macOS transcript protocol remains unchanged.

## Task 12: Validate Runner inputs before creating evidence

**Files:**

- Create: tools/run_linux_console_preview.py
- Modify: tests/test_linux_provider_contracts.py
- Test: tests/test_linux_provider_contracts.py

**Step 1: Write preflight tests before the runner**

First add LinuxConsoleRunnerPreflightTests.test_runner_module_exists, which asserts that ROOT / "tools" / "run_linux_console_preview.py" is a file. After that first RED, load the tool with importlib and add tests around injected PlatformView, FileSystemView, and CommandRecorder seams so parser and side-effect ordering genuinely execute on Windows. Cover:

- non-Linux and non-x86_64 hosts;
- missing, relative, non-file, or symlink CLI/MinGW executables;
- absolute or traversing Wine/Wineserver entrypoints;
- absent/non-directory materialized root;
- Runtime Store, Storage, or Evidence roots that already contain data;
- every equal/ancestor/descendant pair among repository, Runtime Store, Storage, materialized, and Evidence roots;
- physical aliases through symlinks or nearest existing ancestors;
- an anticipated Bottle prefix that already exists;
- duplicate command-line flags.

Each case must fail before a subprocess runs or any caller root is created. Add Linux-only integration cases for physical symlink aliases, owner/mode checks, and nearest-existing-ancestor resolution.

**Step 2: Prove RED**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxConsoleRunnerPreflightTests.test_runner_module_exists -v
~~~

Expected: FAIL with the explicit missing-runner assertion, not an import error.

**Step 3: Implement a closed parser and physical root model**

Require each flag exactly once and reject positional extras. Inputs must include explicit absolute CLI, compiler, Runtime Store, Storage, materialized root, Evidence root, relative Wine/Wineserver, and declared version. Do not read PATH, HOME, XDG directories, Wine registries, package managers, or the network.

Resolve physical destinations using the same nearest-existing-ancestor rule as bootstrap. Require Runtime Store, Storage, and Evidence roots to be absent at start; create each exclusively with mode 0700 only after all preflight checks pass. materializedRoot and both entrypoints must pre-exist.

Introduce these seams before filesystem mutation:

~~~text
RunnerInputs:
  cli: Path
  compiler: Path
  runtime_store_root: Path
  storage_root: Path
  materialized_root: Path
  evidence_root: Path
  wine_relative: PurePosixPath
  wineserver_relative: PurePosixPath
  declared_version: str

PlatformView.os_name() -> str
PlatformView.machine() -> str
PlatformView.current_uid() -> int
FileSystemView.inspect(path: Path) -> PathFacts
FileSystemView.nearest_existing_ancestor(path: Path) -> PhysicalAncestor
CommandRecorder.record(argv: Sequence[str], environment: Mapping[str, str]) -> None

parse_closed_args(argv: Sequence[str]) -> RunnerInputs
preflight(inputs: RunnerInputs, platform: PlatformView, filesystem: FileSystemView) -> PreflightResult
create_exclusive_roots(preflight: PreflightResult, filesystem: FileSystemView) -> CreatedRoots
~~~

Build in four short passes: make duplicate/unknown flag tests green with parse_closed_args; make platform and executable tests green; add lexical overlap checks; add physical-alias checks. Only then add create_exclusive_roots and prove through CommandRecorder that every invalid preflight has recorded zero commands and created zero roots.

**Step 4: Write evidence and bounded-command tests before implementation**

Add EvidencePrimitiveTests for exclusive 0600 creation, symlink/overwrite refusal, bounded JSON reads, write/sync failure cleanup, fsynced run-start ordering, pre-marker empty-root rollback, post-marker one-private-failure preservation, and prohibition of public-summary.json on failure.

Add BoundedCommandStateMachineTests for normal EOF/exit, exact cap, cap+1, no-newline overflow, shared stdout/stderr budget, timeout, observer/read failure, outer kill failure, outer reap failure, and partial-byte preservation. Every failure assertion distinguishes outer_cleanup_status from any inner product cleanup.

**Step 5: Prove the new tests are RED**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.EvidencePrimitiveTests -v
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.BoundedCommandStateMachineTests -v
~~~

Expected: both classes import successfully and fail behavioral assertions because the exclusive evidence writer and bounded command state machine are absent. If an interface is missing, add only its closed recording shell before rerunning RED.

**Step 6: Implement evidence file primitives**

Every private artifact must be opened with O_CREAT|O_EXCL|O_NOFOLLOW where available and mode 0600. Flush and fsync before treating a file as complete. Bound every JSON document read from disk.

Define the failure boundary explicitly: during preflight/setup, before an exclusive run-start marker is fsynced, remove only empty roots/files created by this invocation and leave caller state untouched. The marker may be created only after the fixed context, canonical prefix, and Wineserver digest are available and immediately before the product execution phase. Once it exists, every return path must invoke the Task 13 failure/success finalizer, remove incomplete temporary files, and preserve the private Evidence root plus one bounded, path-private failure record for diagnosis; never write public-summary.json on failure.

Use fixed evidence names, not user-influenced names. Keep public-summary.json separate from private context, request, plans, inspection, events, and command diagnostics. Make each prewritten EvidencePrimitiveTests case pass before continuing.

**Step 7: Implement a bounded subprocess primitive**

Use subprocess.Popen with an explicit executable list, start_new_session=True, an empty/explicit environment, a monotonic deadline, and streaming selectors on Linux. Enforce one combined 1 MiB stdout/stderr limit by reading cap+1. On timeout, overflow, observer failure, or read failure, kill the exact outer process group and reap the root child.

Keep the readiness/deadline/budget/signal state machine portable with injected reads, clock, observer, and kill/reap callbacks. On Linux, integration-test the production selectors/process-group primitive with absolute sys.executable. Never discover Python through PATH inside the runner.

Keep the portable state machine separate from the Linux adapter with this contract:

~~~text
CommandSpec(argv, environment, cwd, output_limit_bytes, deadline)
CommandResult(return_code, stdout, stderr, outer_pid, outer_process_group_id)
CommandFailure(reason, partial_stdout, partial_stderr, outer_pid, outer_process_group_id, outer_cleanup_status)
CommandStreamObserver.on_chunk(stream: str, chunk: bytes) -> None
CommandStateMachine.step(readiness, now) -> Sequence[CommandAction]
CommandStateMachine.finish(return_code) -> CommandResult
LinuxCommandAdapter.start(spec: CommandSpec) -> RunningCommand
LinuxCommandAdapter.apply(action: CommandAction, running: RunningCommand) -> None
run_bounded(spec: CommandSpec, adapter: CommandAdapter, observer: CommandStreamObserver, clock: Clock) -> CommandResult
~~~

First make the prewritten normal EOF/exit and exact-cap cases pass against the fake adapter. Then make overflow, timeout, observer failure, read failure, kill failure, and reap failure pass one at a time. Every path returns within its absolute deadline with bounded partial bytes and outer_cleanup_status. Mark that status Complete only when the Runner-owned root is reaped and its group returns ESRCH; otherwise return Failed or TimedOut with the specific closed stage. Task 13 still runs its finalizer after an incomplete outer cleanup, but the run remains permanently ineligible for success. This primitive must never label outer cleanup as cleanup of a child process group created later by ProcessSupervisor. Finally bind selectors, start_new_session, killpg, and waitpid in LinuxCommandAdapter and run the Linux-only integration class.

**Step 8: Run GREEN**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxConsoleRunnerPreflightTests -v
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.EvidencePrimitiveTests -v
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.BoundedCommandStateMachineTests -v
& $CF_PYTHON -B scripts\validate_repository.py
~~~

Expected on Windows: all pure invalid-input and command-state cases execute and pass. In the Ubuntu lane also run LinuxBoundedCommandIntegrationTests plus the physical preflight cases; all must pass before offline completion.

**Step 9: Commit**

~~~powershell
git add tools/run_linux_console_preview.py tests/test_linux_provider_contracts.py
git commit -m "feat: validate Linux console preview inputs"
~~~

## Task 13: Run and correlate the real Console trust chain

**Files:**

- Modify: tools/run_linux_console_preview.py
- Modify: tests/test_linux_provider_contracts.py
- Test: tests/test_linux_provider_contracts.py

**Step 1: Write a mocked exact-chain test**

The injected command, ProcView, clock, and filesystem boundaries must accept only this ordered chain:

~~~text
explicit Python /proc observer self-test helper
explicit MinGW compiler
compatforge-cli inspect
compatforge-cli local linux context
compatforge-cli prepared-plan
compatforge-cli prepared-launch
compatforge-cli prepared-plan
exact wineserver --version recheck
exact wineserver -w
~~~

It must also prove the compiler output and all evidence paths are outside the repository, no command uses a shell, and the Runner never invokes curl, wget, a package manager, Wine discovery, or a Runtime download. The helper uses the already-running interpreter's absolute sys.executable; it is not discovered through PATH.

Model orchestration with closed command kinds and injected boundaries:

~~~text
CommandKind = PROC_OBSERVER_SELF_TEST | COMPILE_GUEST | INSPECT_GUEST |
              BOOTSTRAP_CONTEXT | PREPARED_PLAN_PRE | PREPARED_LAUNCH |
              PREPARED_PLAN_POST | WINESERVER_VERSION | WINESERVER_KILL |
              WINESERVER_WAIT

EvidencePaths.bootstrap_context: Path
EvidencePaths.execution_context: Path
EvidencePaths.launch_request: Path
EvidencePaths.pre_plan: Path
EvidencePaths.events: Path
EvidencePaths.post_plan: Path
EvidencePaths.private_failure: Path
EvidencePaths.public_summary: Path

StartedProcessObservation = Verified(pid, uid, start_time_ticks, canonical_prefix) |
                            ExitedBeforeSnapshot(pid)
PreviewLaunchObserver.on_chunk(stream: str, chunk: bytes) -> None
PreviewLaunchObserver.started_observation() -> StartedProcessObservation | None
FinalizerOutcome(outer_cleanup, inner_group_cleanup, wineserver_cleanup, prefix_observation)

execute_preview(
    inputs: RunnerInputs,
    paths: EvidencePaths,
    commands: CommandAdapter,
    processes: ProcView,
    filesystem: FileSystemView,
    clock: Clock,
) -> PreviewResult
~~~

In the first RED, the fake CommandAdapter rejects any kind not equal to the next expected item and records argv, cwd, environment, and deadline. ProcView returns a scripted exact-prefix process set plus PID UID/start-time/environment identity. FileSystemView records every create/open/hash operation. The success test must assert the nine command kinds above, then assert public_summary is the final successful write. Failure tests use WINESERVER_VERSION, WINESERVER_KILL, and WINESERVER_WAIT after any aborted PREPARED_LAUNCH; they must never confuse the Runner-owned CLI process group with the inner Started PID/process group.

Before implementation, add the complete failure table to the same test class. Use named tests for compiler_or_inspection_failure_is_closed, immutable_input_or_plan_drift_is_closed, malformed_or_adverse_events_are_closed, cleanup_failure_is_closed, and deadline_or_output_failure_runs_failure_finalizer. Across those tests cover compiler failure, inspection drift, bootstrap drift, pre/post input mutation, plan mismatch, malformed/gapped events, missing/duplicate marker, nonzero exit, failure event, cleanup acknowledgement failure, Wineserver rehash mismatch, -w failure/timeout, hidden /proc, live exact-prefix process, live group, output overflow, and overall deadline.

Split assertions at the fsynced run-start boundary. Compiler, inspection, bootstrap, observer self-test, initial hash/pre-plan, and insufficient-cleanup-reserve failures are pre-marker: remove only empty or incomplete artifacts created by this invocation, leave no run-start marker, invoke no product finalizer, and write no public summary; a private failure record is optional and cannot be mistaken for post-start evidence. Prepared-launch, event, post-input/post-plan, and cleanup/residual failures are post-marker: invoke the finalizer, write exactly one bounded private failure record, and write no public summary.

The post-marker finalizer table must separately cover abort before Started, abort after a recorded matching identity, ENOENT/zombie exited-before-snapshot, disappeared leader, changed PID start-time, prefix mismatch, outer cleanup failure, post-marker overall deadline, and output overflow; it asserts exact -k/-w behavior, no signal to an unverified/reused inner PGID, and that outer PGID cleanup alone never passes. The normal quick-exit case must pass only when CLI acknowledgement, fixed Wineserver -w, empty exact-prefix scan, and numeric group ESRCH all hold.

**Step 2: Prove RED**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxConsoleRunnerExecutionTests -v
~~~

Expected: the happy path and each closed failure assertion FAIL because execution orchestration and the failure finalizer are absent.

**Step 3: Compile and inspect the fixed Guest**

Compile tests/fixtures/windows_console_smoke.c to an x86_64 Console PE with this exact argument list and no source-tree output:

~~~text
<compiler> -std=c11 -Wall -Wextra -Werror -O2 -Wl,--subsystem,console,--no-insert-timestamp <source> -o <external-guest.exe>
~~~

Reject warnings and a missing/non-regular output. Hash the source, CLI, and compiler before compilation; re-hash all three after compilation and again before the final summary. Hash the PE after compilation. Call compatforge-cli inspect and require Windows, x86_64, console subsystem, and the same PE digest used later.

**Step 4: Bootstrap the private context and request**

Call local linux context with the explicit quartet and a bootstrap-context private output path. Parse the public receipt from stdout; require its exact key set. Parse that context, update only supervisor.maximumRuntimeMilliseconds to 60000, and write a second execution-context file through the exclusive private-file primitive. Never overwrite the CLI-created bootstrap context.

Create a closed LaunchRequest for the fixed Guest with:

- one fixed request/Bottle ID scoped to this evidence root;
- executable.path equal to the external PE, architecture=x86_64, and the default immutableArtifact mode;
- executable.sha256 equal to inspection.fileDigest with the sha256: prefix removed;
- no arguments;
- an empty environment;
- allowVirtualMachine=false, allowRemote=false, and requiresKernelDriver=false;
- requiresDirectX12=false;
- networkPolicy=deny;
- required capability guest-x86_64.

Require the anticipated Bottle prefix not to exist before launch.

**Step 5: Correlate plans and immutable inputs**

Before launch:

1. hash private CoreConfig, LaunchRequest, and Guest;
2. run prepared-plan;
3. parse the plan, serialize canonical JSON with sorted keys and compact separators, and record sha256 of those canonical bytes;
4. require Pack/Guest digest and Wine/native/wined3d selections to match receipt and inspection.

After prepared-launch returns and cleanup is acknowledged:

1. re-hash all three inputs and require equality;
2. run prepared-plan again;
3. require byte-identical canonical pre/post plans and equal digest.

Record planCorrelation as pre-post-canonical-match. Never claim the saved plan object was directly passed to prepared-launch.

**Step 6: Validate the complete event transcript**

Parse bounded JSONL and require:

- every event has schemaVersion 1 and the expected requestId;
- sequence starts at 0 and is contiguous with no duplicate;
- first kind is started;
- concatenated stdout chunks contain exactly one line equal to COMPATFORGE_WINDOWS_CONSOLE_OK;
- stderr contains no marker;
- no failed, timed-out, grace-period-expired, or terminate-requested event occurs on success;
- wine-server-stop-requested occurs before the terminal event;
- the final event is exited with code 0 and success true;
- no event arrives after exited.

The CLI process must itself exit zero only after its terminate_and_wait acknowledgement.

**Step 7: Implement one bounded success/failure finalizer**

Before starting the product chain, launch one bounded helper through absolute sys.executable with the test WINEPREFIX in an otherwise explicit environment. The /proc observer must find that same-UID helper by its NUL-delimited exact environment entry, then stop/reap it and prove it disappears. Failure is test-infrastructure.

Use one fixed 300-second monotonic deadline across observer self-test, compilation, bootstrap, Guest execution, CLI cleanup, plan correlation, and residual observation. Reserve the final 45 seconds exclusively for finalization. Before fsyncing run-start.json, require more than 45 seconds to remain; after that marker, every non-finalizer command deadline must be no later than overall_deadline minus 45 seconds. Do not start prepared-launch without the reserve.

Feed prepared-launch stdout chunks into PreviewLaunchObserver while the CLI is still running. On the first valid Started event, record its PID and try to read /proc/<pid>/stat and environ immediately. If the process is live, require current UID, start-time ticks, and byte-exact WINEPREFIX and store Verified. If stat returns ENOENT, or stat proves the process is already a zombie before environ can be read, store ExitedBeforeSnapshot instead; the zero-delay Console fixture is allowed to exit before the outer CLI flush reaches the Runner. Other read errors, a live process with unreadable/empty environ, a second Started event, or a prefix/UID mismatch are execution/test-infrastructure failures but still enter finalization. Do not derive an inner PGID from the outer CLI PID.

After run-start.json exists, execute finalization in a finally block for success, CLI nonzero, malformed output, observer/read failure, overflow, and any deadline exception:

1. require run_bounded to have reaped the outer CLI root and confirmed its own process group absent; failure here remains cleanup failure but does not skip later steps;
2. on an abnormal path with a Verified observation, signal the inner group only if /proc still reports the exact PID, UID, start-time ticks, and WINEPREFIX; use bounded TERM, then KILL if needed, and poll for group disappearance;
3. for ExitedBeforeSnapshot or a later-absent leader, send no signal to its numeric PGID and rely on fixed-prefix Wineserver cleanup plus /proc observation; if a live identity drifted or cannot be read, send no signal and record cleanup failure;
4. re-hash the configured Wineserver immediately before each invocation; run exact --version, then on an abnormal path exact -k, then on every path exact -w, always with WINEPREFIX set to the canonical test prefix and the fixed environment allowlist;
5. scan only numeric /proc directories whose stat owner equals the current UID and compare NUL-delimited environ entries for byte-exact WINEPREFIX=<canonical-prefix>; require no match;
6. whenever a Started PID was recorded, require its numeric inner process group to return ESRCH; if a Verified leader identity no longer permits safe signalling, or an ExitedBeforeSnapshot numeric group still exists, report cleanup failure rather than touching a possibly reused group.

If prepared-launch aborts before Started, steps 1 and 4-5 are still mandatory; killing only the outer CLI group is never cleanup success. If the fixed Wineserver digest changes, execute no substituted entrypoint, record integrity plus cleanup failure, and continue only with non-signalling observation. Hidden/unreadable environ for an otherwise eligible process is test-infrastructure, not a skip. The Runner finalizer is Preview evidence and must not be advertised as product-level Linux orphan recovery.

**Step 8: Write the closed public summary**

The exact public fields must include:

~~~text
schemaVersion
checkpoint
hostOs
hostArchitecture
hostDisplayDetected
displayForwarded
runtimePackId
runtimeVersion
runtimePackDigest
guestDigest
planDigest
planCorrelation
runtimeEventKinds
exitCode
cleanupStatus
consoleValidated
graphicsValidated
runtimeEvidenceScope
runtimeTreeValidated
networkIsolationValidated
~~~

Fix values displayForwarded=false, planCorrelation=pre-post-canonical-match, consoleValidated=true, graphicsValidated=false, runtimeEvidenceScope=entrypoints-only, runtimeTreeValidated=false, and networkIsolationValidated=false. Recursively reject absolute paths, file names, command lines, private IDs, environment values, or free-form diagnostics from the public summary.

Only write the summary after every gate succeeds and FinalizerOutcome reports outer cleanup, applicable identity-guarded inner-group cleanup, fixed Wineserver rendezvous, and exact-prefix observation complete. On failure, write no success summary and return a nonzero category: contract, integrity, unsupported-host, test-infrastructure, execution, or cleanup.

**Step 9: Run the prewritten happy-path and failure-table tests GREEN**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxConsoleRunnerExecutionTests -v
& $CF_PYTHON -B scripts\validate_repository.py
~~~

Expected on Windows: the complete orchestration/state-machine mock produces one path-free summary and every injected mutation fails closed. Ubuntu must additionally pass real selectors, /proc observer self-test, process-group, permissions, and ELF integration cases; only Task 16 may claim real Wine execution.

**Step 10: Commit**

~~~powershell
git add tools/run_linux_console_preview.py tests/test_linux_provider_contracts.py
git commit -m "feat: run trusted Linux console canary"
~~~

## Task 14: Gate the Provider with synthetic Ubuntu evidence

**Files:**

- Create: tests/fixtures/linux_provider_stub.c
- Create: scripts/create_linux_provider_fixture.py
- Create: .github/workflows/linux-provider-preview.yml
- Modify: tests/test_linux_provider_contracts.py
- Test: tests/test_linux_provider_contracts.py

**Step 1: Write CI/source contract tests**

Add LinuxProviderCiContractTests that require:

- the dedicated workflow and both fixture sources exist;
- actions/checkout and actions/setup-python use the repository's existing full commit SHAs, while dtolnay/rust-toolchain uses the same stable selector as ci.yml;
- Python 3.12 and rustfmt/clippy are configured;
- CARGO_TARGET_DIR and every generated fixture/evidence root use RUNNER_TEMP, never the checkout;
- the workflow contains no apt, apt-get, brew, curl, wget, Wine package install, Runtime download, or prepared-launch command;
- it runs schema tests, repository validator, fmt, check, workspace tests, Clippy, release CLI build, explicit Provider probe/context, and local bootstrap.

**Step 2: Prove RED**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxProviderCiContractTests -v
~~~

Expected: FAIL because the workflow and fixtures are absent.

**Step 3: Create two real ELF fixture entrypoints**

linux_provider_stub.c must:

- accept exactly argv[1] == --version and no other arguments;
- require a fixed marker in cwd;
- require PATH and HOME to be absent;
- require exactly LANG=C, LC_ALL=C, and WINEDEBUG=-all from the probe allowlist;
- emit wine-11.0 plus LF on stdout for its Wine build;
- emit Wine 11.0 plus LF on stderr for its Wineserver build;
- return nonzero on every mismatch.

Compile Wine as a real non-PIE ET_EXEC and Wineserver as a real PIE ET_DYN, using macros to select the role. This validates both accepted ELF types without pretending either helper can launch a Windows Guest.

**Step 4: Generate a deterministic external fixture**

create_linux_provider_fixture.py takes one explicit output root plus the two explicit ELF paths. It creates:

- a materialized Runtime tree and cwd marker;
- the exact two-component Runtime Pack bundle;
- provider.json and bootstrap.json;
- expected digests for static assertions.

Use only the Python standard library, closed JSON, create-new writes, and lowercase sha256. Refuse an existing nonempty output root. Generated artifacts must never live beneath the repository.

**Step 5: Add the dedicated Ubuntu workflow**

Create linux-provider-preview.yml rather than editing the high-traffic ci.yml. Reuse the repository's pinned checkout/setup-python action revisions. In an ubuntu-latest job:

1. set CARGO_TARGET_DIR under RUNNER_TEMP;
2. compile both ELF helpers with cc -std=c11 -Wall -Wextra -Werror and explicit PIE/non-PIE flags;
3. generate the external fixture;
4. install the synthetic Pack with compatforge-cli runtime install;
5. run provider linux probe and provider linux context;
6. run local linux context with a separate new Store/Storage root and private output;
7. assert the receipts/configs with Python;
8. run all offline gates listed in Step 1.

Never execute prepared-launch with these helpers. The workflow proves contracts, ELF/process probing, Pack association, and CLI wiring—not Wine semantics.

**Step 6: Run GREEN locally where possible**

Run on Windows:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxProviderCiContractTests -v
& $CF_PYTHON -B scripts\validate_repository.py
~~~

Run the complete workflow commands on Ubuntu before accepting CI:

~~~bash
python3 -S -B -m unittest tests.test_linux_provider_contracts -v
python3 -B scripts/validate_repository.py
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p compatforge-cli --release --locked
~~~

Expected: synthetic Provider gates pass; no test claims Console execution.

**Step 7: Commit**

~~~powershell
git add tests/fixtures/linux_provider_stub.c scripts/create_linux_provider_fixture.py .github/workflows/linux-provider-preview.yml tests/test_linux_provider_contracts.py
git commit -m "ci: gate Linux runtime provider preview"
~~~

## Task 15: Document the offline implementation gate and real prerequisites

**Files:**

- Create: docs/guides/linux-console-preview.md
- Create: docs/implementation/phase-2-3-linux-x86_64-runtime-provider-preview.md
- Test: tests/test_linux_provider_contracts.py

**Step 1: Write documentation contract tests**

Require both documents to state:

- Linux x86_64 Console Preview, not Beta/Tier 1;
- status implemented-awaiting-linux-canary until a real receipt exists;
- true ELF Wine loader and Wineserver, not shell wrappers;
- a fixed release Runtime whose Wine and Wineserver report the same declared release;
- Runtime can run from env_clear without caller LD_LIBRARY_PATH/HOME/PATH;
- explicit MinGW-w64 compiler and explicit Runtime quartet;
- readable /proc with same-UID environ access;
- X11 is not used or forwarded by this Console slice;
- network policy is recorded but Linux network isolation is not validated;
- Pack evidence covers entrypoints only, not the complete Runtime tree;
- pathname TOCTOU and product-level detached-client cleanup remain follow-up work;
- the current supervised stdout/stderr budget is 1 MiB combined and overflow fails the launch;
- evidence must stay outside Git.

Also require the exact CLI and runner forms, all public summary limitations, and a rollback/removal procedure limited to the caller-owned Preview roots.

The contract test must accept exactly two coherent status shapes: awaiting with consoleValidated=false and no canary receipt, or passed with consoleValidated=true plus every required path-free public field. This lets Task 16 update only the status document after a real pass without weakening the test.

**Step 2: Prove RED**

Run:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts.LinuxProviderDocumentationTests -v
~~~

Expected: FAIL because the documents are absent.

**Step 3: Write the operator guide**

Document a copy/paste path using only CF_-prefixed variables. Never instruct operators to overwrite HOME, XDG variables, or TMPDIR. Explain that the runner creates new Store/Storage/Evidence roots and refuses reuse or overlap.

Include troubleshooting by closed failure category without suggesting PATH discovery, permissive chmod, disabling digest checks, using a shell wrapper, or downloading Wine automatically.

**Step 4: Write the implementation status page**

Record the exact implemented surfaces and offline gates. Set:

~~~text
Status: implemented-awaiting-linux-canary
consoleValidated: false
graphicsValidated: false
runtimeEvidenceScope: entrypoints-only
runtimeTreeValidated: false
networkIsolationValidated: false
~~~

Do not copy private paths, plan JSON, Runtime logs, or synthetic fixture output into the page.

**Step 5: Run the full offline gate**

On the current Windows worktree:

~~~powershell
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts -v
& $CF_PYTHON -B scripts\validate_repository.py
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p compatforge-cli --release --locked
git diff --check
~~~

Expected: every offline gate passes with Cargo artifacts outside the worktree.

**Step 6: Commit**

~~~powershell
git add docs/guides/linux-console-preview.md docs/implementation/phase-2-3-linux-x86_64-runtime-provider-preview.md tests/test_linux_provider_contracts.py
git commit -m "docs: document Linux console preview gate"
~~~

## Task 16: Run the first real Linux x86_64 Wine canary

**Files:**

- Modify only after a pass: docs/implementation/phase-2-3-linux-x86_64-runtime-provider-preview.md
- Never add: evidence directory, private JSON, PE output, Runtime files, or logs

**Step 1: Stop if prerequisites are not real**

Follow the approved merge boundary first: after PR #29 is merged, fast-forward local main and integrate that new main into this Linux branch/worktree only. Resolve and reverify this branch without rewriting or modifying the frozen PR #29 branch/worktree. If PR #29 is still open, keep implemented-awaiting-linux-canary; the offline Linux implementation and CI do not wait for it.

The real run also requires a user-controlled Linux x86_64 host, a fixed self-contained/installed Wine release Runtime with true ELF Wine and Wineserver entrypoints, a readable /proc, and an explicit x86_64-w64-mingw32 compiler. If any item is absent, record no pass and keep implemented-awaiting-linux-canary.

Do not use the CI stub, distro wrapper, Rosetta, QEMU, FEX, a container that hides /proc evidence, or an opportunistically discovered Wine.

**Step 2: Re-run Linux offline gates**

From a clean checkout/worktree of this branch:

~~~bash
export CARGO_TARGET_DIR=/tmp/compatforge-linux-x86_64-provider-preview-target
python3 -S -B -m unittest tests.test_linux_provider_contracts -v
python3 -B scripts/validate_repository.py
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p compatforge-cli --release --locked
git status --short
~~~

Expected: all gates pass and Git status is empty.

**Step 3: Define only explicit CF_ inputs**

The operator supplies absolute values appropriate to the controlled host:

~~~bash
export CF_CLI=/tmp/compatforge-linux-x86_64-provider-preview-target/release/compatforge-cli
export CF_MINGW=/absolute/path/to/x86_64-w64-mingw32-gcc
export CF_RUNTIME_ROOT=/absolute/path/to/pinned-wine-runtime
export CF_RUNTIME_STORE=/absolute/new/path/runtime-store
export CF_STORAGE_ROOT=/absolute/new/path/storage
export CF_EVIDENCE_ROOT=/absolute/new/path/evidence
export CF_WINE_ENTRY=bin/wine64
export CF_WINESERVER_ENTRY=bin/wineserver
export CF_WINE_VERSION='REPLACE_WITH_EXACT_RELEASE_VERSION'
~~~

Runtime Store, Storage, and Evidence roots must not exist yet. Do not assign HOME, TMPDIR, PATH, WINEPREFIX, or LD_LIBRARY_PATH.

**Step 4: Run the explicit canary once**

~~~bash
python3 -B tools/run_linux_console_preview.py \
  --cli "$CF_CLI" \
  --compiler "$CF_MINGW" \
  --runtime-store-root "$CF_RUNTIME_STORE" \
  --storage-root "$CF_STORAGE_ROOT" \
  --materialized-root "$CF_RUNTIME_ROOT" \
  --evidence-root "$CF_EVIDENCE_ROOT" \
  --wine "$CF_WINE_ENTRY" \
  --wineserver "$CF_WINESERVER_ENTRY" \
  --version "$CF_WINE_VERSION"
~~~

Expected: exit 0 and one public-summary.json containing the exact closed success fields. Any retry must use three new absent roots; do not overwrite the failed evidence run.

**Step 5: Independently inspect the public result**

Require consoleValidated=true, cleanupStatus=passed, exitCode=0, displayForwarded=false, graphicsValidated=false, runtimeEvidenceScope=entrypoints-only, runtimeTreeValidated=false, networkIsolationValidated=false, and planCorrelation=pre-post-canonical-match. Confirm no absolute path occurs anywhere in the public JSON and Git remains clean.

Private evidence remains on the controlled host for diagnosis and is not a release artifact.

**Step 6: Record only a path-free pass**

Only after all checks pass, update the implementation page from implemented-awaiting-linux-canary to linux-console-preview-passed and copy only the public, path-free field values plus the Git commit tested. Do not claim X11/GUI, graphics, network isolation, full Runtime integrity, Beta, or Tier 1.

Run the documentation contract tests and commit:

~~~bash
python3 -S -B -m unittest tests.test_linux_provider_contracts.LinuxProviderDocumentationTests -v
git diff --check
git add docs/implementation/phase-2-3-linux-x86_64-runtime-provider-preview.md
git commit -m "docs: record Linux console preview canary"
~~~

If the canary does not pass, make no success commit; report the closed failure category and preserve the external evidence root for the user.

## Task 17: Perform final verification and independent review

**Files:**

- Review all Linux feature files changed from the branch's current merge-base with main
- No new behavior unless review finds a defect, in which case return to RED/GREEN first

**Step 1: Run the authoritative offline verification**

Use @superpowers:verification-before-completion. On Windows, keep the external CARGO_TARGET_DIR and bundled Python 3.12 defined at the top of this plan, then run:

~~~powershell
& $CF_PYTHON -B scripts\validate_repository.py
& $CF_PYTHON -S -B -m unittest tests.test_linux_provider_contracts -v
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p compatforge-cli --release --locked
git diff --check
git status --short
~~~

On Ubuntu, repeat the workflow commands and the Linux-only process/probe tests. If Task 16 ran, repeat the canary summary checks without rerunning or overwriting its evidence.

**Step 2: Audit the conflict boundary**

Run:

~~~powershell
$CF_LINUX_BASE = (git merge-base HEAD main).Trim()
git diff --name-only "${CF_LINUX_BASE}...HEAD"
git log --oneline --decorate "${CF_LINUX_BASE}..HEAD"
~~~

Fail if the Linux feature diff changes any forbidden macOS soak/GUI/Desktop/FFI file from the stop rules. Ancestor changes already present in an updated main after PR #29 are not attributed to this branch. Confirm no generated target, PE, ELF, private context, Runtime object, or evidence log is tracked.

Do not merge, rebase, or modify PR #29 or its frozen macOS worktree.

**Step 3: Request independent code review**

Use @superpowers:requesting-code-review. Give the reviewer the approved design, this plan, the base commit, the exact verification output, and these explicit questions:

- Can an unrelated Pack, active ref, alternate WINESERVER, or swapped digest authorize execution?
- Can startup, output overflow, timeout, stream close, or cleanup failure return success or leak a lease/process?
- Can any root alias, symlink, pre-existing output, PATH/Home lookup, or public summary expose/bypass the trust boundary?
- Does any synthetic evidence overclaim real Wine, Console, X11, graphics, network isolation, or full Runtime validation?

Resolve every actionable finding with a failing test first and repeat Step 1.

**Step 4: Report the exact achieved state**

If Task 16 has not passed, report implemented-awaiting-linux-canary even when all offline gates are green. If it passed, report linux-console-preview-passed with only the path-free public summary. In both cases list remaining non-goals and provide the branch/worktree/commit without claiming merge completion.
