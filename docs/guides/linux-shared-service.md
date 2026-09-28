# Linux shared service and desktop launchers

Run as the logged-in user, with an existing reviewed Linux context and service
configuration. Keep exactly one owner for a service/storage pair. Do not run the
development Tauri `api-session` owner against that pair while the daemon is up.

```text
compatforge-cli service-daemon CONTEXT.json SERVICE.json
compatforge-cli service-call REQUEST.json
compatforge-cli desktop-export
compatforge-cli desktop-launch notepad-plus-plus main -- '/home/forge/中文 文件.txt'
compatforge-cli service-stop
```

`service-call` sends existing typed service operations to the daemon. Requests
are read from a bounded JSON file. Unsupported operations and invalid requests
are recoverable errors. A successful `jobs.submit` response identifies the job;
client exit leaves it owned by the daemon. `jobs.get`, `jobs.list`, `jobs.cancel`
and generation queries work across independent clients. `desktop.launchers`
requires an empty payload and returns selected, verified launcher metadata.

The new framed envelope is documented in ADR 0014 and
`schemas/daemon-reply.schema.json`. `daemon.stop` exists only on this daemon
transport; it requires an empty payload. Success is returned after actual
cleanup, as `result: {"stopped":true}`. Cleanup failure is an error and remains
visible to systemd. The normal reply wait is 65 seconds; stop waits up to 110
seconds, with the packaged systemd stop bound of 120 seconds. A lost response is
not cancellation: query jobs/generations before retrying a mutating operation.

The packaged user unit expects:

- `/usr/bin/compatforge-cli`: pinned executable or a root-owned fixed symlink to
  the verified `/usr/libexec/forge/compatforge-cli` installed by ForgeOS.
- `$HOME/.config/compatforge/context.json`: reviewed local runtime configuration.
- `$HOME/.config/compatforge/service.json`: the chosen persistent service root.
- A standard caller-owned mode 0700 `$XDG_RUNTIME_DIR` supplied by login.

Install `packaging/linux/compatforge.service` to `/usr/lib/systemd/user`, then
enable it for the graphical user session after provisioning those configurations.
The unit never creates a new runtime recipe or silently migrates a different
storage root. A missing configuration fails visibly. Preserve existing prefixes.

Provisioning belongs to CompatForge's validated `local linux context` / Linux
desktop bootstrap interfaces, using the image's pinned runtime bundle, executable
digests, selected runtime-pack digest and user-owned runtime/storage/service roots.
ForgeOS must install the reviewed input/template and invoke that interface as the
user; it must not synthesize `CoreConfig` or Wine internals itself. Automated
first-login provisioning is a Task 4 image gate, not implemented by this unit.
The current explicit fixture/config commands are for integration testing, not a
requirement for ordinary users to edit JSON in the final product.

Install ForgeDesktop's matching sync consumer and timer for automatic launcher
convergence. It uses no command-line path supplied by application metadata and
does not change `mimeapps.list`. Missing/tampered selected executables fail export;
the existing launcher set is retained until diagnosis, and an attempted launch
continues to enforce the stored digest. Normal uninstall removes the selection;
the next successful sync removes only unmodified owned entries.

The literal Exec path and IDs need no quoting because their allowed alphabet
contains no reserved characters. Display titles are separate Name values,
backslashes are escaped there, and `%` in a title is literal. Selected filenames
are expanded by the desktop's `%F` field and are never re-parsed as command text.
For actual Windows filename semantics, NUL/newline/relative paths are rejected;
other filenames still require application acceptance. Clipboard, Chinese fonts,
file saving through the application, KWin grouping and reboot acceptance remain
separate integration checks.
