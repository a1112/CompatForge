# Managed DAP acceptance in isolated ForgeOS v5

- Base raw: `/srv/forge-apps-fast/images/forgeos-windows-apps-debug-v5.raw`, SHA-256 `f23bf13628c2ef6c9baf5316bd6cee9c51b617f48dd63611a33a9a285908b2d5`.
- Disposable overlay: `/srv/forge-apps-fast/lab/apps-v5`; original user VM and overlay were not changed.
- CompatForge source `073656e649a2c00f1be0ec710dc3f50c50c70c32`; immutable v3 bundle SHA-256 `058543d5ac6406c7e98ef909f60387306d0a85ca6e58526c4ad15fecf74b67d9`.
- Guest receipt [2026-09-29-debug-service-v5.json](2026-09-29-debug-service-v5.json), SHA-256 `51f58a17a1e6a1ab6a3bcb5e3def35a6c7ce5131b9fcb879e34276300822cf9b`.

The builder compiled `tests/fixtures/windows_debug_probe.c` with MinGW x64,
`-g -O0 -fno-inline`. The EXE SHA-256 was
`ea376c6a96392c9d369cdd392fcace3d53572e16552c4907e3a6fac7829d2f19`.
The test-only managed installer SHA-256 was
`fda570c4e7a0041d95cd33b2d5c2b74b31782cbc3a12aa059c233cde93c3f55b`.
The ordinary-user test configuration used different IDE-visible and backend
source paths, with an exact compiled-source substitution. The installed
`/usr/bin/compatforge-cli` and worker hashes matched the v3 bundle.

The real CLI and user service installed a Ready generation
`gen-job-1790633717734-1`, then ran one DAP session. The acceptance client
observed a main line breakpoint, source reverse mapping, `stepIn` to `outer`
and `inner`, `next` to line 8, local value `17`, `stepOut` back through `outer`
to `main`, a `pause` request while the fixture was sleeping, and a later
`RaiseException` stop. GDB reported the pause stop reason as generic `stopped`
and the exception as `signal`; the receipt records those literal values.
The gateway rejected `evaluate`, translated the internal `attach` reply to
public `launch`, emitted monotonically numbered DAP messages, then completed
disconnect. Root namespace port 25000 was absent and the debug session
directory was empty. The receipt contains only bounded DAP type, command,
success and stop reason, without source paths, process IDs or variable dumps.

The first v5 acceptance run stopped before its final assertion because its
test client retained an earlier `attach` stop event and mistook it for the
pause event. A RED/GREEN test for event sequence filtering corrected the
runner, and the second full run produced the linked passing receipt. The
test service was then stopped and the ordinary `compatforge.service` restored
active; its debug session directory was empty. After a normal ACPI VM reboot,
the [reboot receipt](2026-09-29-debug-reboot-v5.json), SHA-256
`7c8b8a5f9762239298650c6ecfd286ad5c1f481d61604fb6da643e7652276dc2`,
recorded a changed boot ID, the same selected generation and image pins, an
active ordinary service and a fresh managed debug launch/disconnect. The
session directory was again empty and the root namespace had no port 25000
listener. The later v4 bundle/v6 image remains a separate final gate.

The direct worker probe in the isolated v3 guest also observed stepIn,
stepOut, pause reason `stopped`, exception reason `signal`, clean disconnect,
zero owned prefix processes after normal shutdown, SIGTERM and parent crash,
and no port 25000 listener in the root network namespace.
