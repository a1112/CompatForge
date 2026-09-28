# Final isolated ForgeOS v7 managed debugger acceptance

- Immutable raw: `/srv/forge-apps-fast/images/forgeos-windows-apps-debug-v7.raw`, SHA-256 `e6d862887d58335256ab1144a548d7f2140a9d8b6733e9eaddeb3558a34b4741`.
- Isolated test overlay: `/srv/forge-apps-fast/lab/apps-v7`. The raw and original user VM/overlay were not modified. Only this test overlay received a temporary SSH key/service and graphical test login so the acceptance runner could connect.
- CompatForge source `984121897bcb6d82f884ed18be4d7eb3539b22e6`; immutable v5 bundle receipt SHA-256 `6da7d42c134b611b7144a0db3644e258a4988c59d6bcfe97f4fc67cc31573a51`. All nine bundle files matched the receipt's SHA, size and mode.
- [Full DAP receipt](2026-09-29-debug-service-v7.json), SHA-256 `82e4780786044224c12dc4292d41ab11a9ee7f319bb0a94447b79567e4c5abcf`.
- [Ordinary service receipt](2026-09-29-debug-normal-service-v7.json), SHA-256 `18eefe430fe6e252b9278e4c47e8c50f7a34f67b90db5252a04008cbcfce098e`.
- [Normal reboot receipt](2026-09-29-debug-reboot-v7.json), SHA-256 `1b3710651b2d790e9c2122076f45d694f5cc8e2362a42b789f9d9492d89b1883`.

The installed CLI and worker SHA-256 values were
`b0fb6755ec12d552a3846197281e982ccdbc761fffef0b3dfd30030e0f23e332`
and `70c966863f34d12cf98e7e71fe612f61aa86a89fb93d80f282a7c9cd67f0483a`.
The GDB SHA-256 was
`df0a57e867295b94138de7417ef077e64cdc715ea8b7327b16286dfe038b0a24`.
The same x64 MinGW fixture and installer from the v5 checkpoint were copied
into this disposable guest and installed through `applications.upsert` and
`jobs.submit`. The selected Ready generation was `gen-job-1790634842935-1`.

The real CLI's stdio DAP adapter and user service used a separate reviewed
test config with **different** IDE-visible and backend source paths. The
runner observed a source breakpoint, reverse-mapped stack source, `stepIn`
to `outer` and `inner`, `next` to line 8, local `17`, `stepOut` back through
`outer` to `main`, a pause stop during the fixture's sleep, and a later
`RaiseException` stop. The backend reported pause reason `stopped` and
exception reason `signal`; those exact values appear in the receipt. The
gateway rejected `evaluate`, rewrote the internal `attach` response to public
`launch`, and numbered every outgoing DAP response/event monotonically. The
session disconnected cleanly, the debug session directory was empty and
port 25000 was absent from the root network namespace.

The test daemon was stopped and the original `compatforge.service` restored
active with its unmodified default `sourceMap: {}`. A fresh managed debug
launch/disconnect through that **ordinary service** succeeded; the test unit
remained inactive and cleanup checks passed. After an ACPI normal shutdown
and start of the same isolated overlay, the boot ID changed from
`7e9eb488-db10-485b-ace8-9cc90e6143d5` to
`0b0642e3-5b74-4b53-b4c1-77ba24edb320`. The selected generation,
original service config SHA, CLI, worker, GDB and fixture hashes persisted.
Another ordinary-service debug launch/disconnect succeeded after reboot with
no remaining session directory or public debugger listener.

The transcript deliberately contains only bounded DAP message types,
commands, success flags and stop reasons. It omits paths, process IDs,
capabilities and variable dumps except for the fixture's asserted value in
the typed observation. This establishes the observed x64 C/GDB/WineDbg
workflow. It does not establish MSVC/PDB, .NET, full SEH metadata, a complete
IDE UI integration, or Windows-native debugger parity.
