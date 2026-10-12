# CompatForge version management

## Current authority

The existing source/package values below are preserved. They are not a claim that a product is stable or that these source commits were released. Independent applications, libraries, build tools and protocol/schema numbers are not reset to one repository-wide version.

- `rust-workspace`: `0.12.0` from `Cargo.toml` (workspace.package.version); explicit local bump supported. Rust workspace package version; inherited crate declarations remain source bindings.
- `crate-compatforge-desktop`: `0.12.0` from `apps/desktop/src-tauri/Cargo.toml` (package.version); explicit local bump supported. Independent Rust package; no repository-wide release version is inferred Tauri application packaging version is synchronized with its own Cargo package.
- `crate-compatforge-native-window-corners`: `0.1.0` from `apps/desktop/src-tauri/native-window-corners/Cargo.toml` (package.version); explicit local bump supported. Independent Rust package; no repository-wide release version is inferred.

The machine-readable inventory is `versioning.json`. Cargo workspace inheritance and local lock entries are bound explicitly. Node lock root fields are distinct from registry dependency versions. Tauri versions are bound to their own package; different frontend numbers remain independent.

## Check and change

Python 3.11 or newer; standard library only. Run from the repository root.

```sh
python3 scripts/version_manager.py show
python3 scripts/version_manager.py check
python3 scripts/test_versioning.py -v
```

Choose a single unit. Preview is non-mutating; apply is explicit and should always include the observed current value:

```sh
python3 scripts/version_manager.py bump patch --unit rust-workspace
python3 scripts/version_manager.py bump patch --unit rust-workspace --expect 0.12.0 --apply
python3 scripts/version_manager.py check
```

`set NEW --unit NAME` also previews; add `--expect CURRENT --apply` only after review. For prereleases use `bump prerelease`; stable promotion requires explicit `--allow-stable`. The helper does not run Git, tags, package managers, release hooks, signing, installers or network requests. All source edits are validated before any write.

Check-only units intentionally refuse bump/set because native dependency resolution, existing tooling or historical/test-only ownership must be respected. Incoming local Cargo version requirements and Python workspace locks are not approximated by search-and-replace. Use the project’s native packaging process, update constraints/locks together, then rerun these checks.

## Release history and channels

- Existing prerelease: [linux-runtime-v0.12.0-rc.2](https://github.com/a1112/CompatForge/releases/tag/linux-runtime-v0.12.0-rc.2)
- Existing tags are retained: `linux-runtime-v0.12.0-rc.1`, `linux-runtime-v0.12.0-rc.2`.
- Preserve `linux-runtime-v0.12.0-rc.1` and `linux-runtime-v0.12.0-rc.2` and the `linux-runtime-v*-rc.*` release trigger. Source package `0.12.0` does not mean the runtime RC has become stable. Do not remove `-rc.N` from a runtime release without an explicit promotion decision.

This change creates no tag, release, publication, deployment or release date. Record future changes under Unreleased first; use the existing release process and tag namespace only after platform validation and explicit release approval.

## Scope and validation

The added CI checks metadata consistency and dependency-free version-manager safety only, with `contents: read`. Apply/idempotency/stale-source/mismatch checks use temporary fixtures. They do not establish that a native app builds, signs, installs or works on macOS/Windows/Linux. No native packaging or device acceptance was run for this adoption.

Generated Apple projects, vendored/upstream material, historical evidence, protocol/schema/database numbers and dependency versions remain outside product bumps. Existing runtime version mechanisms are retained; there is no UI redesign.

## Adoption base

Source snapshot: [chore/vite-security-2026-10-11 @ d21354b2302a](https://github.com/a1112/CompatForge/commit/d21354b2302ac5c7855906419524182ac6351669). Default branch `main` and all existing repair/tag refs are retained.

Divergent repair chains were not merged or cherry-picked: `fix/peazip-classic-theme`, `fix/managed-msi-install`, `fix/managed-launcher-working-directory`.
