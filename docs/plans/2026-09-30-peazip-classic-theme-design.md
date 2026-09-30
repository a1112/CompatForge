# PeaZip classic-theme compatibility profile

Status: approved by the user on 2026-09-30; implemented, validated in the isolated rolling VM and locally published on 2026-10-01. See the retained deployed-service adapters and ForgeStore publication evidence. The primary checkout's earlier design checkpoint is preserved separately.

## Verified problem and scope

PeaZip 11.3.0's official Windows installer is pinned and installed through managed jobs in the isolated ForgeOS VM. In Wine 11.14, themed Lazarus buttons obscure their OK/Cancel captions. Changing only ThemeManager/ThemeActive to `0` in this application's inactive prefix restored captions. Managed launch job `job-1790758534698-30` subsequently created a ZIP and extracted its English and Chinese files through the GUI; archive CRC and all original/archive/extracted bytes match. The job exited normally. Evidence is in ForgeStore/docs/evidence/2026-09-30-peazip-pending.md.

This manual experiment does not make fresh installs reproducible. The deployed service's lifecycle stage assigns each installation a new generation and snapshots the reviewed application definition. ApplicationDefinition currently has no appearance-profile field. Do not assume an old prefix's registry is inherited.

An initial post-fix extraction attempt triggered PeaZip's command-concatenation guard. Reopening Extract and appending `roundtripfixed` to the default output directory succeeded. Preserve the warning and investigate the exact rejected path/command separately; do not disable the application's guard or claim that a hyphen alone caused the rejection.

## Alternatives

1. **Closed application appearance profile (recommended).** Add an optional, default-omitted `wineAppearance` enum with only `classic` initially. Carry it in reviewed application definitions, their digest and signed market metadata. Apply a fixed, runtime-owned ThemeActive setting within each managed install job. This needs coordinated service/catalogue changes but can be tested across new generations.
2. **Hard-coded PeaZip exception.** Apply the setting based on application ID and artifact hash. Smaller schema change, but obscures behaviour from the recipe and adds a release-specific service exception.
3. **Wine/Lazarus rendering patch.** Fix composited theme-caption rendering upstream or in a pinned runtime pack. Broader impact and more regression work; the current source comparison is an inference and does not yet justify such a patch.

## Recommended contract and execution

Absent `wineAppearance` preserves current serialization and behaviour, including historical definition digests. Unknown enum values fail validation. Only the reviewed PeaZip definition opts in for the first acceptance; do not infer profiles from tags or arbitrary launch environment overrides.

After the generation lease is durable and its runtime/prefix are bound, run a fixed registry-configuration step through the same managed runtime and job supervision. The owned operation writes only HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager\\ThemeActive, a string value `0`, using runtime-owned registry tooling; it cannot accept caller-supplied registry paths, scripts, executables or shell fragments. Read back the exact value before starting the reviewed installer. Cancellation, timeout and failure remain within that job's lifecycle; configuration failure must not activate the staging generation or overwrite the previous selected generation. The executable path, prefix identity and runtime binding must be validated at the authorization boundary. Do not modify a live prefix outside the lease.

Keep provider DLL defaults and all authentication, network, sandbox and TUF controls unchanged. Update/rollback uses each generation's snapshotted reviewed definition. An old default-themed generation stays default-themed; a classic-profile generation retains its own configuration. A profile change is visible in the definition digest and signed target metadata.

## Validation and publication gate

Verify absent-field backward compatibility, closed enum rejection, unchanged provider defaults, profile/digest binding, cross-prefix isolation, and previous-selection preservation on configuration failure/cancellation. Test a fresh managed PeaZip install and market-driven new generation with readable Add/Extract/Settings confirmation buttons. Execute ZIP creation and extraction using ASCII and Chinese names, compare bytes and CRC, test normal exit, restart and rollback, and retain the command-guard investigation.

Only after these checks pass should a signed acceptance receipt and candidate-v11 be prepared with the existing trusted root. Market activation, verified-cache update and rollback must be observed before incrementing the distinct accepted count from 10 to 11. Passwords, full user registries and private signing keys remain outside the repository.
