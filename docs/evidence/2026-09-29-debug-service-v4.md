# Managed Windows debug acceptance in isolated ForgeOS v4

- Base image: `/srv/forge-apps-fast/images/forgeos-windows-apps-debug-v4.raw`, SHA-256 `d6b61bff253ea66af5bdd6ec33dae41b999beaea2033a54c7d482426d322142c` (ForgeOS build receipt).
- Test overlay: `/srv/forge-apps-fast/lab/apps-v4`; original user VM and 6088 were not used.
- CompatForge source commit: `c74859880b447f70947a3ec91436adcbd0af3fea`; v2 `bundle.json` SHA-256 `7d889a3b434dd0be3e1444b4731d0d44578daf04dac42ba6bc401f0947828687`.
- Exact guest receipt: [2026-09-29-debug-service-v4.json](2026-09-29-debug-service-v4.json), SHA-256 `be9a32c750f662ea09552babb746759220a183133cb06d442327868545fbe0d6`.

The x64 symbol fixture came from `tests/fixtures/windows_debug_probe.c`. A test-only installer from `tests/fixtures/windows_debug_installer.c` copied the EXE into a dedicated managed Wine generation. The builder command was:

```sh
x86_64-w64-mingw32-gcc -O2 -o /srv/forge-apps-build/debug-installer.exe /srv/forge-apps-build/debug_installer.c
```

The installed CLI, worker and GDB SHA-256 values matched the bundle and pinned debugger runtime. The guest's normal `compatforge.service` was stopped. `tests/prepare_linux_debug_service.py` created a separate test config from the installed service config with one exact source mapping and the fixture's compiled-source substitution. The test daemon used the same persistent service root:

```sh
systemd-run --user --unit=compatforge-debug-acceptance --collect \
  --setenv=DISPLAY=:0 --setenv=XAUTHORITY=/run/user/1000/xauth_CDwSLG \
  /usr/bin/compatforge-cli service-daemon \
  /home/forge/.config/compatforge/context.json \
  /home/forge/forge-debug-probe/service-debug.json

env DISPLAY=:0 XAUTHORITY=/run/user/1000/xauth_CDwSLG \
  /usr/bin/python3 /home/forge/forge-debug-probe/linux_debug_service_acceptance.py \
  --existing-generation auto \
  --service-config /home/forge/forge-debug-probe/service-debug.json \
  --output /home/forge/forge-debug-probe/service-acceptance-4.json
```

The initial run of the same acceptance script, without `--existing-generation`, submitted the reviewed installer, waited for success and obtained selected generation `gen-job-1790631513090-1`. In the final run the CLI DAP adapter rejected `evaluate`, then observed `inner → outer → main`, a breakpoint stop, step to line 8, local variable `17`, a later `signal` stop from `RaiseException`, and clean disconnect. GDB initially reported the breakpoint as pending before the image loaded; it resolved and stopped at the real breakpoint after continue. The receipt contains a DAP transcript restricted to message type, command, success and stop reason. No process IDs, source paths or debugger output are copied into the transcript.

After disconnect, the root network namespace had no TCP listener on port 25000, and the debug session directory was empty. The test daemon was stopped and the original `compatforge.service` was restarted and observed active; the directory remained empty. Separate v3 worker tests observed zero prefix processes after normal shutdown, SIGTERM and parent SIGKILL.

Limits: Windows `RaiseException` appeared as a GDB DAP `signal` stop, without structured SEH metadata. MSVC/PDB and .NET debugging remain unverified. The default image configuration has an empty source map; source breakpoints for a particular development project require an explicit reviewed mapping. This acceptance does not establish Windows-native debugger feature or performance parity.
