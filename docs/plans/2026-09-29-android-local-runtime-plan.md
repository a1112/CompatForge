# Android Local Runtime Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在一个明确的 ARM64 Android 设备上，用 CompatForge 本地执行 Windows 7-Zip 并保存完整功能验收证据。

**Architecture:** Kotlin 薄客户端通过 JNI 调用现有 Rust Service；Android Provider 绑定已验证的 Box64/Wine、APK 原生 launcher 和本地 X server。保留 PreparedLaunch、PE 绑定和进程清理约束，先证明现代 target SDK 下的原生运行链路，再开发完整 GUI。

**Tech Stack:** Rust stable、Kotlin、Android SDK 36、NDK、JNI、固定构建的 Wine/Box64 与 Android X server、Python 标准库 ADB 协调器。

状态：待评审。以下为未来实现任务与命令，文件目前尚未创建；命令不是已执行成功的声明。G0 Runtime 来源及具体构建选择需实验锁定，不能伪造一个已验证的工具链组合。

---

## Task 1: 修复 Android 编译边界

**Files:**
- Modify: `crates/compatforge-bottle/src/snapshot.rs`
- Inspect/Modify if required: `crates/compatforge-bottle/src/platform.rs`
- Modify: `.github/workflows/ci.yml`

1. 重现：`cargo check --workspace --target aarch64-linux-android --locked`；现有失败为 `snapshot.rs:951` E0599。
2. 为未支持的 Android snapshot 路径增加“返回结构化 unsupported 且不写入目标目录”的测试。先检查现有错误模型；不要给正常目录复制套上迁移成功的标签。
3. 对齐 snapshot 入口、实现和 imports 的 cfg。首期保留 Windows/Linux 的原有安全语义，Android 迁移明确不可用。不要仅将 `target_os = linux` 改成 `unix`。
4. 重跑上述 check，再执行 `cargo test -p compatforge-bottle --locked` 和相关迁移合同测试。
5. 新增安卓 cross-check CI；CI 仅编译目标，不尝试在宿主直接运行 Android ELF。

Exit: workspace 在 Android 目标能检查；不支持的迁移行为明确且不产生部分写入。

## Task 2: 建立最小 Android 测试宿主

**Files:**
- Create: `apps/android/settings.gradle.kts`
- Create: `apps/android/build.gradle.kts`
- Create: `apps/android/gradle.properties`
- Create: `apps/android/gradle/wrapper/gradle-wrapper.properties` 及固定来源 wrapper
- Create: `apps/android/app/build.gradle.kts`
- Create: `apps/android/app/src/main/AndroidManifest.xml`
- Create: `apps/android/app/src/main/java/dev/compatforge/android/MainActivity.kt`
- Create: `apps/android/app/src/androidTest/java/dev/compatforge/android/NativeLaunchTest.kt`
- Modify: `.gitignore`

1. 固定兼容的 Gradle/AGP/Kotlin 版本与下载校验；采用 minSdk 26、compile/target 36、arm64-v8a 主目标。
2. 先编写 instrumentation 测试验证应用 UID、私有目录、系统版本/页大小、原生入口加载和失败结果；这些测试不是 Windows 应用验收。
3. 实现一个仅呈现环境状态与测试结果的 Activity。release 不导出测试入口，不声明 INTERNET/全盘管理权限。
4. `apps/android/gradlew.bat -p apps/android :app:assembleDebug`；固定 `ANDROID_SERIAL` 后执行 `:app:connectedDebugAndroidTest`。
5. 没有设备时记录 blocked；不把 assemble 成功当作设备测试通过。

Exit: 在选定设备的真实 APK UID 中获得原生启动和文件权限证据。

## Task 3: G0 原生运行栈实验，先完成再扩大实现

**Files:**
- Create: `apps/android/app/src/main/cpp/CMakeLists.txt`
- Create: `apps/android/app/src/main/cpp/wine_launcher.cpp`
- Create: `apps/android/app/src/main/cpp/wineserver_launcher.cpp`
- Create: `tools/android/build_runtime.py`
- Create after selection: `tools/android/runtime-sources.lock.json`
- Create: `docs/reports/YYYY-MM-DD-android-runtime-spike.md`

1. 锁定候选 Box64、Wine、loader/库集、X server 的源码提交、许可证与构建方式。缺失构建来源时只报告阻塞，不搬运未知 APK 的 native 库。
2. 先测试 APK 安装位置的原生入口在 target 36、普通 UID 下可运行，再验证 Box64/Wine 库加载及客体子进程。
3. Wine launcher 适配 `[PE, args...]` 和 `[wineboot, -u]`；wineserver launcher 适配 `[-w]`、`[-k]`。用 argv 数组、固定环境、固定路径，不创建 shell wrapper。
4. 错误测试覆盖：运行包被修改、缺少库、不匹配 ABI、未经验证页大小、不可执行路径、Wine child spawn 失败。
5. 使用既有 downloader 获取 7-Zip 固定资产，在 Android 中安装并运行 Windows `7z.exe` 的 a/t/x 三步，验证输出清单。
6. 检查每个原生 ELF/APK 的对齐，再按实际设备页大小测试；需要 16 KB 设备证据才能声称 16 KB 支持。
7. 记录每层 executable、argv、UID、exit、stderr 和清理结果。G0 未通过，不进行 Task 5 的完整界面建设。

Exit: 目标设备上 Wine 初始化、7-Zip CLI 文件往返及 wineserver 清理均真实通过。此时仅为 runtime spike，不是完整 CompatForge 应用验收。

## Task 4: Android Provider 和 Core 接入

**Files:**
- Create: `crates/compatforge-provider-android/Cargo.toml`
- Create: `crates/compatforge-provider-android/src/lib.rs`
- Create: `crates/compatforge-provider-android/tests/provider_contract.rs`
- Create: `crates/compatforge-android-bridge/Cargo.toml`
- Create: `crates/compatforge-android-bridge/src/lib.rs`
- Modify: `Cargo.toml`
- Inspect/Modify if required: `crates/compatforge-process/src/lib.rs`
- Create if public contract change required: `docs/decisions/0013-android-runtime-launch-boundary.md`（写前确认编号未被占用）

1. 先写拒绝测试：非 Android/ARM64、被篡改 Runtime、路径逃逸、未授权原生入口、未知页大小能力、覆盖 Provider 环境、缺少实际 probe。
2. 实现 probe -> receipt -> CoreConfig；只有运行过的能力可以标记 available。显示未就绪不得发布 GUI 可用。
3. 用现有 ServiceRequest/Response 做 JNI bytes 桥；限制消息尺寸、隔离 panic，保证句柄释放不与活跃调用竞争，阻塞调用移出主线程。
4. 写集成测试证明 `PreparedLaunch` 首参数的 PE 绑定保持不变，bootstrap/start/wait/cancel 全部经过相同固定运行包。
5. `cargo test -p compatforge-provider-android --locked` 验证纯合同与拒绝路径；设备 instrumentation 验证真实探测和 JNI 生命周期。
6. `cargo check --workspace --target aarch64-linux-android --locked`；用 NDK linker 实际 `cargo build -p compatforge-android-bridge --target aarch64-linux-android --locked`。
7. 运行既有 process/orchestrator/service 测试，确认没有扩大桌面 Provider 能力声明、改变选择顺序或绕过 PE 哈希校验。

Exit: 同一 Android Service 完成受控 Windows 应用任务的提交、事件、状态查询与取消。

## Task 5: GUI、文件交换和生命周期

**Files:**
- Create: `apps/android/app/src/main/java/dev/compatforge/android/RuntimeSession.kt`
- Create: `apps/android/app/src/main/java/dev/compatforge/android/RuntimeSurface.kt`
- Create: `apps/android/app/src/main/java/dev/compatforge/android/DocumentExchange.kt`
- Create: `apps/android/app/src/androidTest/java/dev/compatforge/android/SessionLifecycleTest.kt`
- Modify: `apps/android/app/src/main/java/dev/compatforge/android/MainActivity.kt`

1. 写失败测试覆盖 SAF URI 导入、中文/空格文件名、输出校验、取消导出、路径穿越、屏幕重建与旧会话恢复。
2. 接入 G0 锁定的 X server；使用本地 Unix socket，将 Surface/触摸/键盘事件绑定到运行会话。
3. 实现单应用启动/停止、日志、SAF 导入导出；Compose 不读写 Bottle 内部结构，不自行启动 Wine。
4. 前台最大一个任务，后台转移触发有界取消；重建重连，强杀恢复时标记 interrupted 并核对清理。
5. 设备运行 Windows `7zFM.exe`，触摸打开菜单/压缩包并进行 GUI 解压；核对屏幕与实际产物。

Exit: Windows GUI 真正出现在 Surface 中，触摸操作改变 Windows 应用状态，业务文件正确。

## Task 6: 单应用验收工具与证据

**Files:**
- Create: `tools/run_android_acceptance.py`
- Create: `tools/summarize_android_acceptance.py`
- Create: `tests/test_android_acceptance.py`
- Create: `schemas/android-acceptance.schema.json`
- Create: `docs/guides/android-local-7zip-acceptance.md`
- Reuse: `tools/download_gui_assets.py`

1. 先写报告拒绝测试：无设备、多个设备未选 serial、未授权设备、模拟器冒充 ARM 实机、资产哈希错误、缺少 GUI 现场确认、文件清单不一致、清理未知。
2. 实现显式 serial 的 ADB 协调；使用受控 instrumentation 导入资产和调用 Service，不通过 `adb shell wine` 绕过应用 UID。
3. 复用 downloader 中的 7zip 元数据；资源仅写仓库外目录，网络获取必须通过显式 `--allow-network`。
4. 同一应用执行两轮全新 Bottle 的 CLI 与 GUI 往返，外加取消/生命周期检查。runId、APK/Runtime/app 哈希和截图哈希必须贯穿报告。
5. `python -S -B -m unittest tests.test_android_acceptance -v`；有效假数据只用于报告单测，不进入实机认证报告。
6. 新工具的预定接口如下；实现后才可执行：

```powershell
python tools/run_android_acceptance.py --serial <serial> --apk <apk> --runtime-lock <lock> --cache-root <external-cache> --output-root <external-evidence> --app 7zip --rounds 2 --allow-network
python tools/summarize_android_acceptance.py --input <external-evidence>/summary.json
```

Exit: 工具能区分 build-only/console-passed/gui-unverified/accepted/failed/blocked，且不能仅靠截图或预填布尔值生成 accepted。

## Task 7: 实机执行与交付

**Files:**
- Create: `docs/reports/YYYY-MM-DD-android-7zip-acceptance.md`
- Modify: `README.md`（仅添加实际实现和验证的范围）

1. 用户提供或连接目标设备，读取 ABI、型号、系统版本、页大小；确认设备满足 G0 的实际能力。
2. 安装本次构建的 APK，运行 Task 6 工具，完成 GUI 现场操作和异常路径。
3. 报告列出通过/失败检查与证据路径；如果没有设备或 G0 尚未通过，明确 unfinished，不编写成功报告。
4. 执行仓库要求：`python scripts/validate_repository.py`、`cargo fmt --all --check`、`cargo test --workspace --locked`、`cargo clippy --workspace --all-targets -- -D warnings`，以及 Android build/cross-check 和受影响测试。
5. 提交前做 `git diff --check`，核对未提交 APK、Runtime、截图、密钥和设备隐私数据。

Exit: 用户收到可安装 APK、可重复验收命令和至少一个真实 Windows 应用的完整结果；没有真机证据时不能宣称安卓支持已完成。
