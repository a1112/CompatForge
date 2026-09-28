# Managed application lifecycle API

Run the existing headless service (`compatforge api-session <core.json>
<service-config.json>`) and send
schema v1 JSON lines on its existing input transport. Keep one service process
open while submitting and polling jobs. A second owner of the same service or
runtime storage root is rejected.

Install and update use the same job request. Select an official installer whose
name and SHA-256 match the application definition. Do not supply installer
argument overrides. Installer `environmentOverrides` accepts only a local
`DISPLAY` (for example `:98`) and an absolute `XAUTHORITY` path. These connect
to the current user's existing authorized display; they do not grant display access
or accept runtime settings such as `WINEPREFIX` or `LD_PRELOAD`.

```json
{"schemaVersion":"1","requestId":"install-7zip","operation":"jobs.submit","payload":{"schemaVersion":"1","applicationId":"7zip","kind":"install","executablePath":"/absolute/downloads/7z2601-x64.exe","environmentOverrides":{"DISPLAY":":98"}}}
{"schemaVersion":"1","requestId":"poll-7zip","operation":"jobs.poll","payload":{"id":"<returned-job-id>","timeoutMilliseconds":1000}}
{"schemaVersion":"1","requestId":"versions-7zip","operation":"applications.generations","payload":{"id":"7zip"}}
```

Use one outstanding `jobs.poll` call per job. A concurrent poll returns the
retryable conflict `job is already being polled`; retry after the first call
returns. Cancellation remains available while a poll waits for an event.

Poll until the returned job is terminal. `succeeded` requires successful runtime
termination, supervisor cleanup, every declared launcher, and committed selection.
`generationId` connects the job to a physical Bottle. `applications.generations`
returns `selectedGeneration`, `generations`, and any pending `operation`.
`applications.list` includes the same generation state beside its summary.
Each generation exposes `status`, `definition.version`, `definitionDigest`,
`runtime.version`, `runtime.selection.packId`, `runtime.selection.packDigest`,
launcher digests, and any error. An update uses a fresh prefix; the prior selected
generation remains selected until the update completes.

Launch uses the installed definition and runtime, even if a newer recipe has
been upserted. File arguments are individual argv entries and can contain spaces
or Unicode:

```json
{"schemaVersion":"1","requestId":"open-pdf","operation":"jobs.submit","payload":{"schemaVersion":"1","applicationId":"sumatrapdf","kind":"launch","launcherId":"main","argumentOverrides":["Z:\\home\\example\\Documents\\中文示例.pdf"],"environmentOverrides":{"DISPLAY":":98"}}}
```

Paths supplied as arguments follow the runtime's existing guest path mappings;
this API does not add host folders or change sandbox permissions. A missing or
changed runtime binding fails with a pinned-runtime error. Restore the installed
runtime configuration before launch or rollback; changing a recipe does not
silently migrate an existing installation.

Rollback and uninstall are typed application operations:

```json
{"schemaVersion":"1","requestId":"rollback-7zip","operation":"applications.rollback","payload":{"applicationId":"7zip","generationId":"<previous-ready-generation-id>"}}
{"schemaVersion":"1","requestId":"uninstall-7zip","operation":"applications.uninstall","payload":{"id":"7zip"}}
```

Rollback reselects a retained verified program generation. Uninstall deactivates
the app. Both preserve prefixes and personal files. Rollback cannot undo user-data
migrations; files created inside one generation stay there and are not copied
into a new prefix automatically. This first version retains at most 32 generations
and refuses another install at the limit. No deletion operation is exposed.

If the service crashes, inspect `operation.quarantined` and
`recoveryCapability`. On Linux, `kernel-boot-identity` means the service can prove
a host reboot has happened. Reboot the host, reopen the service, then call:

```json
{"schemaVersion":"1","requestId":"recover-7zip","operation":"applications.recover","payload":{"id":"7zip"}}
```

Restarting only the service is insufficient. The same boot UUID, an unreadable
UUID, or `recoveryCapability: unavailable` prevents recovery. This first recovery
capability is Linux-only; other hosts have no supported crash-quarantine release
through this API yet. Successful recovery abandons the interrupted generation,
retains its files, and preserves the prior selected version. Normal explicit
service shutdown performs cleanup and records terminal state without requiring
this reboot recovery.

The SumatraPDF 3.6.1 recipe uses `-install -silent -d
C:\Program Files\SumatraPDF` as separate argv entries, matching its declared
launcher. The destination flag follows the
[official installer argument documentation](https://www.sumatrapdfreader.org/docs/Installer-cmd-line-arguments).
An older seeded recipe stays unchanged until explicitly upserted with the reviewed
definition. Portable Sumatra artifacts belong to a separate recipe.

Job history has a separate limit of 4,096 records per service root. At capacity,
new jobs fail with `job history capacity reached (4096)` before any generation or
runtime effects. Existing jobs can still finish, and their records remain
readable and writable across service restart. No history is deleted automatically.

To free capacity, stop the service, back up its service and runtime storage roots,
and move only completed (`succeeded`, `failed`, or `cancelled`) job JSON records
from `service/jobs` to a separate offline archive outside that directory. Keep
any record referenced by a generation's `operation.jobId`, even if its job status
is terminal. Preserve the generation records, Bottle prefixes, runtime storage,
and all personal files. Retain the archived JSON for diagnostics, then reopen the
service and retry. If an older service already exceeded the limit, use the same
offline procedure before reopening; this version does not silently remove those
older records.

`bottles.list`, `bottles.get`, `bottles.create`, and `bottles.restore` summaries
include the additive boolean `managed`. When true, the Bottle is retained by the
application lifecycle and cannot be manually archived. Desktop clients disable
that action. This includes reserved `gen-` names without a current generation
record. Managed summaries bind the physical Bottle ID to its retained definition,
so changing or removing the current recipe does not erase its application or
launcher inventory. `installedLauncherCount` counts existing declared launcher
files; consult `applications.generations` for installation and recovery evidence.
A false `managed` value does not bypass the existing active-job archive checks.

The 4 MiB metadata limit includes pretty-JSON whitespace and the final newline.
An update that exceeds this on-disk size is rejected before replacing the previous
record, retaining the selected generation and readable job history.
