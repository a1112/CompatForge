# Android G0 runtime spike — 2026-09-29

Status: **G0 blocked**. CompatForge Core and an Android APK run in an emulator,
but there is no selected or packaged Box64/Wine/X server runtime. No Windows
program was executed by the APK. This report is a partial feasibility result,
not an Android compatibility certification.

## Verified in this checkout

| Check | Result | Evidence |
|---|---|---|
| Rust workspace checks for `aarch64-linux-android` | Passed after making Android Bottle snapshot/migration explicitly unsupported | `cargo check --workspace --target aarch64-linux-android --locked` |
| Android APK build and install | Passed on emulator, target SDK 36, `arm64-v8a` native libraries | Gradle `:app:connectedDebugAndroidTest`, APK manifest/ABI inspection |
| Rust FFI in an ordinary Android app UID | Passed | `NativeLaunchTest.rustCoreRunsUnderOrdinaryAppUid` |
| Packaged ARM64 launcher `execve` from `nativeLibraryDir` | Passed on this emulator | `NativeLaunchTest.packagedLauncherRunsUnderAppUidButWritableCopyIsDenied` |
| Same executable copied to writable app-private files | Execution denied on this emulator | Same instrumentation test |
| Fixed Windows 7-Zip 26.01 installer PE inspection inside Android | Passed; SHA-256 `d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d`, PE x86_64/Windows GUI | `SevenZipInspectionTest` and `tools/download_gui_assets.py` |
| Windows 7-Zip installation, CLI round trip, GUI interaction, Wine cleanup | Not run; Runtime missing | No Wine/Box64/X server or runtime lock exists |

The connected test XML reports **3 tests, 0 failures, 0 errors, 0 skips** for
`rswitch-api36-x86_64(AVD) - 16`. The final debug APK digest in this run was
`sha256:61df251ada35f9656c32ecbce2307216c21b1baa2d2d83863390c9f65b6dada9`;
the APK is a generated, ignored build artifact and its digest changes with
rebuilds. The test result XML is under
`apps/android/app/build/outputs/androidTest-results/connected/debug/`.
As a fail-closed check, running the connected suite without the fixed 7-Zip
asset deliberately failed the inspection test; rerunning with the asset passed
all three tests.

The emulator identified itself as `sdk_gphone64_x86_64`, API 36, QEMU flag
`1`, 4096-byte pages. It advertises `arm64-v8a` through ARM translation. This
is useful for APK/Kotlin/JNI/permission tests, but it does not establish an
ARM64 device's Box64 JIT, Wine process tree, performance, or 16 KB page behavior.
`llvm-readelf` showed 0x4000 LOAD alignment for the launcher, Rust FFI and JNI
libraries; `zipalign -c -P 16 -v 4` passed for the APK. These are layout checks,
not 16 KB device execution evidence.

Final local verification passed: `cargo fmt --all --check`,
`cargo test --workspace --locked`, `cargo clippy --workspace --all-targets
--locked -- -D warnings`, `cargo check --workspace --target
aarch64-linux-android --locked`, the three connected Android tests, and
`git diff --check`. `scripts/validate_repository.py` is not clean in this
built checkout: its developer-path scan includes ignored generated EXE files
under `target/` and the test-staged 7-Zip EXE under `apps/android/app/build/`.
The default `python` on this host is 3.9 and cannot run that validator; Python
3.12 reached the path scan and reported those generated files. No generated
executables were staged for Git.

## Runtime selection gate

The [upstream Box64 build guidance](https://github.com/ptitSeb/box64/blob/main/docs/COMPILE.md)
and [Winlator source](https://github.com/brunodev85/winlator) provide candidate
components, not a verified runtime for this APK. Winlator's published app
configuration targets [SDK 28](https://github.com/brunodev85/winlator-app/blob/main/app/build.gradle),
while this host targets 36. Android documents the API 29+ restriction on
[executing from writable app home](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission).
The APK native launcher placement is now tested, but Wine's loader, child
processes, libraries, and X server remain untested in this target-SDK setting.

Before declaring G0 passed, select immutable source commits, build and record
the license and digest of every Runtime component, then run `wine --version`,
`wineboot -u`, and Windows `7z.exe` `a/t/x` from this app UID. The plan requires
two fresh Bottle rounds, GUI use of `7zFM.exe`, content checks, and cleanup
evidence for full single-app acceptance. None of those results is claimed here.
