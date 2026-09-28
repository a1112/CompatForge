# ADR 0014: a shared user service and owned Linux desktop entries

Status: accepted for the approved Windows application / debugger / ForgeStore
route. Implementation increment: desktop integration, not debugger acceptance.

## Ownership and transport

One ordinary-user daemon owns both the service and Bottle storage roots. It uses
the existing cross-process leases. Independent launchers cannot each become an
`api-session` owner: that protocol intentionally drains jobs on EOF or a request
error. Its v1 behavior remains unchanged. The separate daemon accepts a single
framed JSON request per connection; disconnect only loses that reply.

The fixed socket is `$XDG_RUNTIME_DIR/compatforge/service.sock`. Both runtime
directories must be canonical, unlinked, caller-owned and mode 0700. The socket
is mode 0600. Client and server authenticate the peer's kernel UID. Root and
setuid clients are rejected. The endpoint lock is exclusive; only a verified
socket returning connection-refused can be removed as stale. Regular files,
linked files, active endpoints and uncertain errors are preserved.

Frames use a four-byte big-endian unsigned length followed by UTF-8 JSON.
Requests are capped at 1 MiB, replies at 16 MiB, and eight concurrent workers.
Connect/read/write deadlines are bounded; request and response frame deadlines
are absolute, preventing a peer from resetting the timeout with partial bytes.
The server polls active jobs independently every 100 ms; idle polls do not write
job records. Per-request errors leave other jobs running. Stop closes admission,
joins workers, drains every supervised process, then returns success or an
explicit cleanup failure. `ExecStop` waits for that result. Abrupt termination
retains the existing quarantine and later-kernel-boot recovery rule.

The endpoint deliberately has the ordinary user's session authority, matching
local Linux application launch. A Wine Bottle is not a security sandbox; this
transport does not create root authority or a host-wide network listener.

## Desktop contract

Only selected Ready generations with their frozen runtime configuration and
verified launcher digests can export entries. Names come from that frozen
definition. Icon names, WM_CLASS hints and MIME support come from closed reviewed
declarations; unknown applications get a generic icon and no inferred MIME types.
These are theme icon names, not copied proprietary application artwork. Actual
KWin task grouping remains a VM acceptance gate.

Desktop Exec uses only `/usr/bin/compatforge-cli desktop-launch APP LAUNCHER -- %F`.
IDs are bounded lowercase ASCII tokens, with reserved IDs rejected. No title,
runtime context path, Wine command, or shell string enters Exec. `%F` occurs once
as a standalone field; each filename becomes one argv element. The client maps
absolute Linux paths to Wine Z-drive paths and forwards only validated local
DISPLAY/XAUTHORITY session values. It rejects control characters and relative
paths. Safe argv transport does not imply Windows applications can represent
every otherwise legal POSIX filename.

ForgeDesktop periodically queries the authenticated client and reconciles only
entries it owns by a versioned digest manifest. Foreign entries and changed user
entries are preserved. MIME support is advertised, with user defaults untouched.
Applications or desktop UI exit independently of the service owner.

## Dependency decision

`rustix = 0.38.44`, features `net`, `process`, `fs`, is now an explicit Linux-only
dependency. The exact version already existed through fs4; it supplies safe
Unix peer-credential, UID, socket and no-follow flag APIs without introducing
unsafe code in this crate. Upstream: https://github.com/bytecodealliance/rustix
and https://crates.io/crates/rustix/0.38.44 . License: Apache-2.0 WITH
LLVM-exception OR Apache-2.0 OR MIT. Keep Cargo.lock and the vendored license
inventory in release packaging. Its Rust minimum 1.63 is below this workspace's
1.78 minimum. No macOS transport behavior changes.

## Specification references and pending gates

- https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html
- https://specifications.freedesktop.org/desktop-entry/latest/value-types.html
- https://specifications.freedesktop.org/desktop-entry/latest/mime-types.html

First real tests must distinguish Rust/consumer unit tests from actual Wine
launch, open-selected-file, icon/task grouping, user-session timer, normal reboot,
and recovery after a different kernel boot. No completion claim for the debugger,
ForgeStore, desktop M3-M5, or the remaining stability/performance matrix follows
from this increment.
