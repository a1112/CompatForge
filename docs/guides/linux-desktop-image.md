# Linux desktop image interface

This is an internal x86_64 Linux candidate. KWin GUI Save, normal reboot and
three-application acceptance are separate runtime gates; a unit test or Python
file write does not satisfy them. A Wine Bottle is not a security sandbox.

## Build and consume

Build `compatforge-cli` and `compatforge-ffi` from the same exact source commit.
Then run the repository-owned producer (no network, installer execution or root
needed):

```sh
python3 tools/build_linux_desktop_bundle.py \
  --cli /absolute/build/compatforge-cli \
  --library /absolute/build/libcompatforge_ffi.so \
  --source-commit FULL_COMMIT --output /absolute/new/bundle
```

Pin the reported `bundleSha256` independently in ForgeOS. The closed receipt
binds eight fixed paths, modes and hashes, source commit and Cargo lock. Both
client locations contain identical bytes: the desktop contract uses
`/usr/bin/compatforge-cli`; existing OS probes use
`/usr/libexec/forge/compatforge-cli`. The FFI remains at
`/usr/lib/compatforge/libcompatforge.so`.

`packaging/linux/desktop-runtime.json` pins the reviewed Wine 11.14 executable
pair and Noto CJK font already present in the source image. The producer adds
the actual CLI digest to the root-owned `/usr/share/compatforge/linux-desktop.json`.
Upstream application installer URLs, hashes and license sources are recorded in
`packaging/linux/applications.json`; those installers are not bundled or
executed by the image builder. CompatForge has no project-level license
declaration in the source tree; provenance records `NOASSERTION`, and this
candidate does not assert permission for public redistribution.

## Ordinary-user first login

The globally enabled **user** service belongs to `graphical-session.target`.
`ExecStartPre=/usr/libexec/compatforge/user-init` takes no arguments and runs as
the ordinary system account. It checks root ownership, permissions, file types
and the exact system executable/font bytes before using them. It derives the
home from the account database; arbitrary HOME/XDG overrides are not trusted.

The initializer calls the existing `local linux context` command, then the
typed `applications.seed-defaults` API. ForgeOS never creates a CoreConfig or
implements runtime orchestration. Configuration is staged under
`~/.config/.compatforge-init-v1` and published by a directory rename only after
context validation and registry seeding succeed. A private initialization lock
serializes attempts. Interrupted staging is recovered only when its files are
bounded, caller-owned and from the closed preparation file set; unexpected
files and modified user configurations are preserved and rejected.

The private context/service configuration lives in `~/.config/compatforge`;
runtime metadata, managed prefixes and registry live in three disjoint private
directories beneath `~/.local/share/compatforge`. Repeated login does not seed
over existing registrations or rewrite the runtime context. CLI-only updates
may update the small initialization receipt after the new system binary is
verified; runtime/font configuration changes require an explicit migration.

The desktop client forwards only validated local `DISPLAY` and absolute
`XAUTHORITY` for each launch. Application installation callers use the same
typed per-request session allowlist. Desktop integration's 15-second timer
starts and stops with the graphical session; it never selects MIME defaults.

## Font binding

Linux bootstrap/provider v1 accepts optional `bottleFont` with a canonical
absolute regular file, `sha256:` digest and the exact family `Noto Sans CJK SC`.
It verifies bytes and binds them to the plan. Request environment overrides
cannot introduce or replace font evidence; authorization rechecks that binding.
The process layer rechecks the font, links it into the managed prefix and uses
the existing bounded Wine registry commands for a closed substitution set.
Existing macOS contexts keep their default `Heiti SC` behavior. This is not an
arbitrary registry setup or command execution interface.

## Diagnosis and recovery

Use `journalctl --user -u compatforge.service` and
`systemctl --user status compatforge.service`. Missing/mismatched system pins
require a matching verified image, not a local digest bypass. Modified private
configs or runtime-template changes fail with a preservation message: back up
the existing directory and apply a reviewed migration; do not delete the
context or application storage to silence the error. Selecting XFCE remains
available through the login manager. Stopping the service synchronously joins
owned jobs; image replacement and backup remain ForgeOS responsibilities.
