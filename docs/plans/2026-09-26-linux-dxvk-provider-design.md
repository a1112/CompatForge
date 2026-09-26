# Linux x86_64 DXVK Provider design

- Date: 2026-09-26
- Status: Development-image slice

## Goal

Let the Linux x86_64 local context report a DXVK graphics backend only when
two fixed x64 DLLs and a usable Vulkan device have been verified. Preserve
the Console Preview's WineD3D behavior when DXVK is not requested. ForgeOS
owns image package provenance and sandbox placement; this repository owns
graphics Provider evidence, plan selection, Wine overrides and launch checks.

## Contract

The optional DXVK field in a Linux local-context request names an exact
version, `d3d11.dll`, `dxgi.dll`, and a Vulkan probe executable by relative
paths and SHA-256 values under the already explicit materialized root. The
Provider configuration carries the same closed fields. The two DLLs must be
regular PE32+ x86_64 DLL files from one root-owned directory. The Vulkan probe
must be a regular x86_64 ELF, run with a cleared environment, bounded output
and timeout, and report a Vulkan 1.3+ software device. A changed DLL, failed
probe, wrong architecture, or unrecognized output leaves DXVK unavailable.

The Provider reports WineD3D as before plus DXVK only after the evidence
passes. A D3D11 LaunchRequest can require the `vulkan` capability; the
planner's Linux preference selects DXVK. The plan records the DXVK version and
protected DLL path/digests in its environment. Process startup checks that
`graphics.backend=dxvk` matches the protected environment, the two DLLs are
adjacent to the bound Guest PE, and both digests still match, then uses native
overrides for `d3d11` and `dxgi`. It rejects a missing/changed pair before Wine
spawns. The exact ForgeOS sample then demonstrates actual D3D11 rendering and
DXVK runtime evidence in QEMU; a selected plan alone is insufficient.

## Limits

This slice supports only x64 DLLs next to an immutable Guest PE. It does not
manage general Bottle installs, 32-bit DXVK, D3D12, hardware-driver
certification or arbitrary Windows applications. A software Vulkan device is
the development gate, not a performance claim. The existing local Linux
Console context remains byte-compatible when the optional DXVK field is absent.
