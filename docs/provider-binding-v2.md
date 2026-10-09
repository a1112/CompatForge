Forge provider contract 2.0.0 closes independent review F1/F2. Metadata and lock
JSON retain schemaVersion 1; the four shared CLI commands and bound transport
use major 2. Existing engine requests, responses, jobs and launcher metadata
retain their own v1 schemas. There is no v1 transport fallback or native ABI/
R-SDK change.

The actual `service-daemon` process freezes its own compiled provider report at
startup, with a distinct instance ID. This identity comes from the CLI build,
never configuration or caller data. On each authenticated per-user connection,
the client sends a bounded v2 hello containing the required provider identity
and request ID. The daemon returns its own source/version/capability/schema
identity and instance. Both negotiate before the client sends, or the daemon
dispatches, a business request. That request names the same instance and request
ID on this connection. Every reply carries the frozen identity; any change
after admission is rejected. Legacy daemons cannot decode a hello as a business
request and receive no jobs/applications/desktop request from the v2 client.

Store sends `service-call FILE` a v2 bound invocation containing its fixed lock
and the existing engine request. The actual executing CLI checks itself against
the lock before runtime initialization or connection. Desktop uses
`desktop-export --provider-contract JSON --request-id ID` as distinct argv
elements without shell evaluation. The execution reply contains the actual CLI
identity, admitted daemon identity, request ID, operation and result. Consumers
negotiate both identities and correlation before using results. A replacement
old CLI rejects the new request shape; a replacement v2 CLI with another source
fails its admission check and the response check. An unbound empty export is an
error and cannot remove managed launchers.

`daemon-handshake-v2.schema.json`, `daemon-reply-v2.schema.json`,
`bound-request-v2.schema.json` and `bound-response-v2.schema.json` in `contracts/`
describe separate boundaries. The reusable crate is 2.0.0. Report/lock bytes are
UTF-8 without a BOM; shared raw vectors cover UTF-16/32, BOMs, malformed bytes
and duplicate decoded keys. Domain errors retain the explicit R-SDK interop v1
error-family adapter.

Python lock/OS resource reads pin no-follow directory and leaf descriptors,
use nonblocking open to reject FIFOs, validate owner/type/link count before read,
allocate at most limit+1 bytes and compare descriptor/leaf identity after read.
Root-owned installed files and caller-owned temporary inputs are accepted.
Links, other owners and group/world-writable inputs are rejected. This removes
the inherited OS stat/path/read replacement window.

Composition schema 2 hashes immutable Git blobs for protocol inputs and executes
only frozen source objects, independent of index flags. It also pins the Desktop
resource receipt digest/profile, requires the complete provider pair and
compares every resource to the selected Desktop Git blob using the selected
producer mapping. This proves source resource closure, not reproducible binaries
or an image. R-OS Rust producer remains unconfigured with null pins.

Peer UID, package/source provenance and existing artifact trust remain the
identity boundary. Metadata is not an authorization credential or protection
against arbitrary malicious code running under that trusted identity. No
third-party dependency is added: the service uses the existing local serde-based
contract crate. Tests are synthetic and do not install or run a real service.

A rolling upgrade must drain/stop the prior daemon with its matching prior CLI
before installing the reviewed matched combination. A retained old daemon is
refused, never automatically killed or migrated. Rollback restores a complete
source/artifact combination and matching owner. No default branch, system
service installation, runtime state, engine, Wine or VM change is performed.
