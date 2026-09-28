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

Pin the reported `bundleSha256` independently in ForgeOS. The v2 closed receipt
binds nine fixed paths, modes and hashes, source commit and Cargo lock. Both
client locations contain identical bytes: the desktop contract uses
`/usr/bin/compatforge-cli`; existing OS probes use
`/usr/libexec/forge/compatforge-cli`. The FFI remains at
`/usr/lib/compatforge/libcompatforge.so`. The receipt also pins the private
`/usr/lib/compatforge/compatforge-debug-worker.py` bytes. ForgeOS installs the
separately verified GDB runtime under `/opt/compatforge/debugger` and checks
the image's fixed WineDbg executable and module hashes.

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
bounded, caller-owned, from the closed preparation file set and backed by a
durable intent matching this home and runtime configuration; unexpected
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

## Repeatable acceptance runner

Run these commands **inside the ordinary user's candidate graphical session**,
using the source checkout matching the candidate. Each invocation requires a
new evidence directory and records bounded typed requests/responses and hashes.
The runner never starts a second daemon or calls Wine directly.

```sh
python3 tools/linux_gui_acceptance.py --output /absolute/evidence/transactions \
  exercise --assets /absolute/pinned-installers
python3 tools/linux_gui_acceptance.py --output /absolute/evidence/editor \
  launch --app notepad-plus-plus /home/forge/Documents/中文文档.txt
```

`exercise` installs all three pinned applications, verifies exported launchers,
cancels a second 7-Zip installation, completes an independent update, rolls back,
uninstalls and restores the selected generation. Cancellation waits for the
supervisor's `streamEnded` cleanup acknowledgement, not merely a persisted
terminal job label. A launch receipt gives the job ID. Observe the real window,
edit and save through its UI, record screenshots, then close it or use:

```sh
python3 tools/linux_gui_acceptance.py --output /absolute/evidence/cancel \
  cancel --job JOB_ID
python3 tools/linux_gui_acceptance.py --output /absolute/evidence/before \
  before-reboot /home/forge/Documents/中文文档.txt
```

After a **normal VM reboot**, log in and run:

```sh
python3 tools/linux_gui_acceptance.py --output /absolute/evidence/after \
  after-reboot --before /absolute/evidence/before/before-reboot.json
```

The comparison rejects an unchanged kernel boot ID, a changed selected
generation or a changed/missing observed file. It hashes existing files and
never writes application documents. This proves persistence of the observed
bytes; the associated real UI Save screenshots/notes establish their origin.
Use separate real Windows-file inputs for 7-Zip and SumatraPDF, verify menu/Dock
launches and task grouping, and preserve declined permissions/fault results as
separate evidence. None of these checks substitutes for developer breakpoint
debugging or the desktop's longer stability gates.

## Managed Windows source debugging

The debug provider requires the bundle's worker, the separately pinned GDB
runtime, the fixed WineDbg module and an active graphical user service. After
upgrading an existing user's image from a configuration without the debugger,
run `/usr/libexec/compatforge/user-init --refresh-debugger` as that ordinary
user, then restart `compatforge.service`. The migration verifies the root-owned
template, preserves unrelated settings and refuses a modified user config.
`journalctl --user -u compatforge.service` shows startup failures. The default
image has `debuggerRuntime.sourceMap: {}`; create a reviewed candidate template
with a one-to-one mapping from IDE-visible source paths to installed GDB source
paths before setting C source breakpoints. A compiled-source substitution may
also be needed when the EXE's debug info names a build-machine path. Rebuild
and reverify the image for permanent changes; the isolated acceptance runner
uses a separate test-only service configuration.

Select a managed Ready generation with `applications.generations`, then create
an ordinary-user file such as `~/debug/managed-launch.json`:

```json
{"schemaVersion":"1","command":"launch","target":{"applicationId":"YOUR-APP","generationId":"gen-job-YOUR-SELECTED-GENERATION","launcherId":"main"}}
```

`/usr/bin/compatforge-cli debug-adapter ~/debug/managed-launch.json` speaks
framed DAP on stdin/stdout. The target is bound before the IDE connects; IDE
`launch` arguments cannot change its executable, process, environment or
debugger. For an IDE using [nvim-dap's executable adapter
configuration](https://github.com/mfussenegger/nvim-dap/blob/master/doc/dap.txt),
put the following in Neovim's Lua configuration and replace the absolute launch
file path and name:

```lua
local dap = require('dap')
dap.adapters.compatforge = {
  type = 'executable',
  command = '/usr/bin/compatforge-cli',
  args = { 'debug-adapter', '/home/forge/debug/managed-launch.json' },
}
dap.configurations.c = {
  { type = 'compatforge', request = 'launch', name = 'Managed Windows C app' },
}
```

Open the mapped source path, set a normal line breakpoint and start that
configuration. The adapter accepts only a bounded DAP subset: initialize,
launch, line breakpoints, configurationDone, threads, continue, pause, next,
stepIn/stepOut, stackTrace, scopes, variables and terminate/disconnect. The
initialize reply advertises only configurationDone and terminate. IDE requests
for expression evaluation or a debugger REPL, conditional breakpoints, memory
access, disassembly, host-process attach and IDE terminal execution are
rejected. The WineDbg stub is private to a network namespace; no TCP debugger
port is available to the desktop or host. A client disconnect closes the owned
session and its copied Wine prefix. Source maps expose only reviewed paths;
unknown backend paths are omitted from DAP source fields.

The x64 C acceptance uses `tests/linux_debug_service_acceptance.py` and a
test-only managed installer. See `docs/evidence/2026-09-29-debug-service-v4.md`
for the first real breakpoint checkpoint. The final corrected bundle/image
acceptance must include differing public/backend source paths and explicit
stepIn, stepOut and pause evidence before claiming those operations. MSVC/PDB,
.NET and Windows-native debugging parity are separate gates.
