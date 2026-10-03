# Managed MSI installation

The Linux service can install a reviewed MSI into a new managed generation.
An application definition declares `installer.msi` with architecture, exact
package size, a closed `msiexec` handler and a bounded runtime. The normal
`jobs.submit` install operation receives the local package path. Empty EXE
definitions continue to serialize without MSI fields.

The MSI path has its own 2 GiB package bound. It streams SHA-256 validation,
checks the installer compound-file type and bounded Template Summary
architecture, and stages an immutable package through held directory handles.
The existing PE inspection bound stays at 256 MiB. CFB validation is a format
and architecture check, not a complete MSI database or custom-action audit.

Trusted context policy supplies `wineInstallerTools` entries, separate from
historical runtime bindings. A tool is bound to its runtime pack, SHA-256 and
architecture. Package and tool file descriptors are held, rehashed before
spawn and used through Wine's Unix device paths. Execution reuses the owned
Wine server, generation lease, cancellation, deadline, bounded output and
process-tree cleanup. A zero root exit waits for Wine idle; expected launcher
files must also pass validation before the generation becomes ready.

UI is limited to `none` or `basic`, reboot is suppressed, and raw arguments,
transforms, response files and remote packages are rejected. Optional properties
are limited to `ALLUSERS`, `MSIINSTALLPERUSER`, `INSTALLDIR`, `INSTALLFOLDER` and
`TARGETDIR`, with validated values. Directory overrides currently require an
ASCII C: path without spaces or quotes. Real Wine 11.14 testing found that
space-containing overrides retain outer argv quotes in a property name.
Default MSI destinations such as `Program Files` are unaffected and passed.

Older failed or cancelled generations containing those space overrides remain
readable with their original definition digest. This compatibility branch is
only for retained failure metadata: new registration, installation requests,
parameter generation, ready generations and rollback continue to enforce the
strict rules. No historical record is rewritten or removed.

Unix Wine exit status does not preserve the full Win32 MSI exit code. Every
nonzero exit fails closed; no 3010 mapping or host reboot is performed. Windows
tests validate contracts and existing non-MSI behavior; actual managed MSI
staging and Qalculate! acceptance were exercised on Linux.

The rolling canary is the official Qalculate! 5.12.0 x64 MSI, 70,448,128 bytes,
SHA-256 `f677d8c3c63c7757e6efc7bee7d4ccded725437194dce94485fc3fb713692e25`.
Default installation, arithmetic, unit conversion and GUI persistent-variable
save/reopen passed. A no-space directory override also installed successfully;
five unsuccessful quoted/space overrides are retained. These results do not
establish compatibility for other MSIs or the previously blocked JASP package.
ForgeStore's separate signed-artifact bound remains 1 GiB.

See the implementation plan and
[ForgeStore's Qalculate! rolling report](https://github.com/a1112/ForgeStore/blob/feature/store-core/docs/windows-rolling-20261003-qalculate.md)
for source/binary pins, regression evidence and publication lifecycle. The
market's newest-other-ready rollback selected the no-space canary; a separate
explicit Core rollback restored the original persisted variable. Both paths
were exercised, with all five failed generations retained.
