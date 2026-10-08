# Rolling Windows MSI installation integration — proposed design

Status: proposed, execution implementation not approved in this session. Builds on `2026-08-18-phase-2-3-cross-host-validation-design.md`; existing validator is non-executing.

## Problem and required outcome

Rolling JASP 0.97.1 uses an official 1,299,197,952-byte MSI. Service install currently inspects the supplied artifact as PE and exposes no installer handler. Existing closed MSI request/schema bound is 1,073,741,824 bytes, excluding this real package before execution. Real guest service submission additionally fails at the PE inspector 256 MiB bound: `PE image exceeds 268435456 bytes: 1299197952`, job `job-1790744678544-9`. Raising the PE bound would not supply MSI handling and is not proposed. EXE jobs and previously accepted applications must keep their behavior.

A successful result must install the exact verified MSI in a new managed generation, check expected launcher/files, allow real application GUI workflows, and preserve ForgeStore update/rollback. CLI exit alone never grants tested status. JASP source verification and service failure evidence are recorded separately in ForgeStore.

## Alternatives

1. **Recommended:** complete Prepared Install and connect it to service generation jobs. More work across domain, package staging, orchestrator, process and service, but preserves content binding, events and rollback for all MSI candidates.
2. Test-only raw `wine msiexec` invocation. Useful diagnostic, but does not exercise service generations or Store lifecycle and cannot satisfy publication acceptance.
3. Extract MSI CAB or use vendor preinstalled ZIP. Can support portable recipes, but bypasses MSI custom actions and installation semantics. Does not fix the MSI category.

## Proposed contract and data flow

Keep LaunchRequest v1 PE semantics unchanged. Reuse closed `install-request.schema.json`: immutable package path/name/size/SHA-256, `msiexec` install handler, bounded UI/reboot/properties, local runtime constraints. Raise both validator and schema package bound together to 2 GiB, sufficient for the verified JASP package and still explicit/bounded. Do not accept arbitrary argv or external transforms.

Service InstallerDefinition gains a backwards-compatible explicit MSI handler; EXE remains the default. Application registration, Store bridge and serialized recipes must agree on handler and architecture. Inspect MSI as a compound-file package, not PE; hash through bounded streaming and validate recorded size. Stage it in immutable package storage before use. Verify runtime-owned msiexec/Wine/wineserver and map the staged guest package path into the managed prefix without shell interpretation.

Prepared Install authorization must bind package digest, runtime, bottle lease, full plan and context. Revalidate before spawn; changing source bytes, replacing staged package or changing a generation between preparation and spawn must fail closed. Use existing supervisor timeout/cancellation/events. MSI return 3010 records reboot requested, not a host reboot; application files still must validate. Failed generations remain inactive with evidence, and cancellation terminates only that generation's processes.

## Validation gates

- Red/green tests for legacy EXE deserialization/behavior and closed MSI handler rejection (URLs, transforms, shell/response-file arguments, unauthorized properties).
- Validator/schema agreement: accept exact JASP size and 2 GiB boundary, reject 2 GiB + 1, invalid sizes and unsupported package type.
- Package identity, architecture and staging tests; substitution/TOCTOU, wrong SHA, wrong name and wrong size must fail.
- Process lifecycle tests for MSI success, failure, timeout, cancellation and reboot-required results; no success state without expected file checks.
- Real isolated VM: install pinned JASP MSI, import a five-row numeric/Chinese-label CSV, compute descriptives (N=5, mean=3, sample SD=sqrt(2.5)), save/reopen .jasp and verify results. Verify launcher, shutdown and clean generation-scoped termination.
- Signed local Store entry only after verified-cache update, rollback/data preservation and service restart persistence. Preserve current TUF root and monotonic metadata versions. Do not commit installers or signing/authentication keys.

## Remaining evidence and risks

The proposed execution path is not implemented. Four GiB guest RAM is only JASP's documented minimum and includes the desktop; monitor actual memory and preserve OOM failures before considering more RAM/swap. Official preinstalled ZIP is not a substitute for the requested MSI repair. This design does not claim support for MSIX, every MSI custom action, remote public publication or every JASP analysis.
