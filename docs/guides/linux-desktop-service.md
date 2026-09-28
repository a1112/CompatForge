# Linux desktop service bootstrap

The desktop and managed clients use the existing `AutomationService` contract.
Linux bootstrap is explicit and separate from the retained macOS local discovery
path. It does not scan `PATH`, download Wine, accept macOS overrides, or register
an unverified runtime automatically.

## Desktop

Prepare a pinned `LinuxProviderConfig` following
[`linux-provider.schema.json`](../../schemas/linux-provider.schema.json). It must
identify the existing Runtime Store, materialized Wine root, exact release,
entrypoint hashes and pack digest. Optional DXVK/Vulkan evidence is preserved and
verified by the Linux provider. Runtime files and the existing active pack must
already satisfy the provider's validation rules.

```text
CompatForge --linux-provider-config /absolute/private/provider.json
```

An optional `--acceptance-root /absolute/private/desktop-state` relocates the
desktop's `storage` and `service` directories for isolated acceptance. The
provider's Runtime Store remains the exact configured store. Storage must be
disjoint from the runtime roots. Without `--linux-provider-config`, Linux reports
the missing argument in the desktop; it does not attempt macOS discovery. The
configuration is bounded to 64 KiB and unknown fields are rejected. Configuration
files must be regular files; symlinks, directories and FIFOs are rejected. Unix
opens are nonblocking and do not follow the final symlink, including replacement
between the type check and open. The configured directory is caller-controlled;
this is not a new system-wide trust boundary or a filesystem sandbox.

Bootstrap probing and service operations run in Tauri blocking workers so disk,
process and job polling work does not run on the UI event loop. The UI still owns
this service's lifetime; a persistent daemon and disconnect recovery are separate
work. Closing the main window or requesting application exit closes worker
admission, rejects queued requests and prevents late bootstrap publication. A
tracked cleanup worker drains requests already in flight, stops all owned jobs
and joins their supervisor workers before exiting (including settings windows).
Bootstrap is idempotent while the service is ready. No runtime replacement or
process cleanup occurs while holding the UI's state lock. Cleanup failures retain
the service and closed admission, show an error, and allow another close action
to retry; failures never count as successful cleanup. `shutdown_and_wait()` is
also available to other Rust owners after they drain their clients, and returns
typed per-job termination/join failures while still attempting every job.

`jobs.poll.timeoutMilliseconds` bounds waiting for the next runtime event only.
After observing a terminal guest exit, polling additionally acknowledges and
joins supervisor cleanup using its existing forced-completion deadline (up to
16 seconds). Clients must budget for both bounds; a zero event timeout does not
mean a terminal poll is instantaneous. This wait runs on the service worker and
holds no job-map mutex. Only successful acknowledgement releases the handle.
Failed cleanup keeps the job `failed` and retains its handle for shutdown;
repeating a normal poll does not repeat the failed cleanup wait. An earlier
`failed` event cannot be erased by a later guest exit code of zero.

## Other local clients

Rust clients can use `bootstrap::select_desktop_context` and
`bootstrap::create_desktop_context`, then construct `AutomationService` with the
returned `CoreConfig`. Both use the same explicit provider and existing provider
evidence checks. `create_desktop_context` is blocking and belongs on a worker.

The existing CLI can create a Linux core configuration and keep the service alive:

```text
compatforge-cli provider linux context /absolute/provider.json /absolute/storage
compatforge-cli api-session /absolute/context.json /absolute/service.json
```

The first command emits the private CoreConfig; save it in a caller-owned private
file and pass that file to the second command. Service requests retain
`schemaVersion`, `requestId`, `operation` and `payload`. Each newline-delimited
request is bounded to 1 MiB **before copying the next input buffer**. CRLF and a
complete final request without newline are accepted. Oversized, malformed or
invalid UTF-8 requests terminate the session with a nonzero error, as do existing
service errors; the client must not keep writing after a terminal transport error.
Before returning on EOF or any read, decode, service, write or flush error, the CLI
explicitly stops and joins its owned jobs. A cleanup failure makes the CLI exit
nonzero even after a clean EOF; when the request loop and cleanup both fail, both
original errors are retained and reported. This is a private owned session, not
a daemon whose applications survive a disconnected client.

This change establishes Linux bootstrap and bounded local transport only. It does
not certify everyday applications, debugger support, or application installation
and removal lifecycle completeness.
