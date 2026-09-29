# Android experimental host

This is an ARM64 Android test host for the CompatForge Rust Core. It does not
include Box64, Wine, an X server, or a Windows application launcher. The APK
cannot run Windows applications yet. See the [G0 report](../../docs/reports/2026-09-29-android-runtime-spike.md).

Requirements: JDK 17, Android SDK 36, NDK 30.0.14904198, CMake 3.22.1, Rust
with `aarch64-linux-android`, and a running emulator or device whose supported
ABIs include `arm64-v8a`. The Gradle wrapper pins Gradle 8.13 and its SHA-256.

On Windows PowerShell, from the repository root:

```powershell
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:ANDROID_SERIAL = 'emulator-5554' # replace with the explicit adb serial
python tools/download_gui_assets.py --cache-root "$env:LOCALAPPDATA\Temp\compatforge-android-assets" --allow-network fetch 7zip
& apps\android\gradlew.bat -p apps/android :app:connectedDebugAndroidTest "-PcompatforgeSevenZip=$env:LOCALAPPDATA\Temp\compatforge-android-assets\7z2601-x64.exe" --console=plain
```

The connected tests check the Rust Android probe, ordinary app UID, APK native
launcher execution, denial of execution from writable app storage, and PE
inspection of the SHA-256-pinned 7-Zip Windows installer. They do **not** run
7-Zip. The asset is staged only in the test APK; it is not bundled in the app.
Omitting `-PcompatforgeSevenZip` makes the inspection test fail, so a missing
asset cannot be reported as a passing acceptance run.

The debug APK is `app/build/outputs/apk/debug/app-debug.apk`. It uses target
SDK 36 and packages only `arm64-v8a` native code. An x86_64 emulator that
advertises ARM64 via translation is suitable for these integration tests but
is not ARM64 hardware or Windows runtime evidence.
