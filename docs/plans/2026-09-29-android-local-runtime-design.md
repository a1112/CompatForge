# Android 本地运行与 7-Zip 验收设计

日期：2026-09-29。状态：待评审；尚未实现 Android 客户端，尚未完成 Windows 应用实机验收。

## 1. 目标与验收边界

在一个明确记录型号、Android 版本和内存页大小的 ARM64 安卓设备上，由 CompatForge 启动 Windows x64 版 7-Zip，完成压缩、解压、内容校验、GUI 操作和退出清理。运行发生在设备本地，不依赖远程 Windows、root 或系统级 binfmt 注册。

首期交付是 developer-local APK 与一份可复查的应用验收报告。仅认证实际测过的 Device × OS × Runtime digest × App digest 组合，不授予所有 Android 设备兼容等级。APK 安装、Core 编译、原生 Android 测试程序、单独运行 Winlator，均不能代替这项验收。

暂不包括：iOS、D3D 游戏、x86/ARM Windows 应用、应用商店发布、长时间后台运行、音频/手柄、通用运行包下载商店、跨平台 Bottle 迁移。首个 7-Zip GUI 路径使用 Wine 的 X11/GDI 输出和 Android 内嵌 X server/Surface，避免让 D3D/Vulkan 驱动成为首个应用的前置条件。

## 2. 已检查的实际基础

代码基线为 `acc68a9`。当前工作区在检查前干净。

| 位置 | 实际约束 | 设计处理 |
|---|---|---|
| `crates/compatforge-service/src/jobs.rs` | `JobManager` 直接调用 `ProcessSupervisor`，启动失败持久化为失败 Job | 保留 Service API 作为业务入口，不在 Kotlin 重写管理逻辑 |
| `crates/compatforge-orchestrator/src/lib.rs` | 运行绑定只有 executable，没有通用 translator argv 前缀；PE 路径成为 argv[0] | 用固定的 Android Wine launcher 适配，不拼接 shell、不直接在 PE 前插入 Box64 参数 |
| `crates/compatforge-domain/src/lib.rs` | Guest binding 校验要求 PE 路径与首个参数一致 | 保留该约束，launcher 内部完成下一层原生调用 |
| `crates/compatforge-process/src/lib.rs` | Wine bootstrap 调用同一 executable 加 `wineboot -u`；清理另调 wineserver `-w/-k` | 同时提供 Wine 与 wineserver 两种受控 launcher，覆盖初始化、启动、等待和取消 |
| `crates/compatforge-bottle/src/snapshot.rs` | Android 编译进入非 macOS snapshot 分支，却没有 Windows/Linux 专属的 `publish_object` | 首期明确拒绝未实现的 Android 迁移操作；不能仅扩大 Linux cfg 就宣称文件系统语义相同 |
| `crates/compatforge-capability/src/lib.rs` | Android 型号/版本从 `/system/build.prop` 读取，可能未知 | Android 入口补充系统 API 观测并保留来源；读取失败不伪造设备信息 |
| `apps/desktop/src-tauri/src/lib.rs` | 桌面启动依赖 `create_local_context` 的 macOS 路径 | 新 Android 入口构造 Android context，不引用桌面启动代码 |

已执行 `cargo check --workspace --target aarch64-linux-android --locked`，结果失败：`snapshot.rs:951` 调用缺失的 `publish_object`（E0599）。这是实际发现的移植阻塞，不是推测。

另行使用本机 NDK 的 `aarch64-linux-android26-clang.cmd` 作为 linker，执行 `cargo build -p compatforge-ffi --target aarch64-linux-android --locked` 成功。`llvm-readelf -h` 确认产物为 AArch64 ELF64 shared object。这只验证 FFI 依赖子集的编译和链接；它不依赖上述 Bottle 迁移 crate，因此与 workspace 检查失败并不矛盾。尚未在 Android 中加载该库或运行 Windows 应用。

本机检测到 JDK 17、Android SDK API 36/36.1、NDK `30.0.14904198`、Rust `aarch64-linux-android` 编译目标。ADB 未发现连接设备。存在 ARM64 和 x86_64 AVD 配置，但尚未启动，配置存在不证明能在当前主机运行，也不构成实机验证。

本轮只新增设计/计划文档，没有修改实现。仓库总验证脚本用 Python 3.12 运行后仍失败：扫描到了本地 `node_modules` 的链接、开发路径及 `target` 下构建出的 EXE；默认 `python` 为 3.9，不满足仓库 Python 3.11+ 要求。没有删除现有依赖/构建目录或修改验证器来隐藏这些结果。两份新增文档的本地链接和尾随空白另行检查。

## 3. 路线比较与选择

| 路线 | 优点 | 成本/局限 | 选择 |
|---|---|---|---|
| CompatForge APK 集成受控原生 launcher、Box64/Wine 与 X server | Core 能直接掌握启动、文件和退出证据；最终形成独立客户端 | 原生运行栈集成、glibc/Bionic 边界和现代 Android 执行限制必须验证 | 推荐 |
| 调用或修改 Winlator 作为外部伴随应用 | 可较快获得独立的设备可行性对照 | 不同 UID 的存储/生命周期难统一；尚未验证稳定外部控制接口；不能直接算 CompatForge 集成通过 | 仅用于对照或源代码参考 |
| 手机连接远程 Windows | 可绕开本地翻译及图形驱动 | 改变本地运行目标，依赖网络和远程服务 | 本阶段不采用 |

Winlator 已证明 Wine + Box64 的安卓路线可行，但当前上游 `app/build.gradle` 使用 `targetSdkVersion 28`。不能把该项目的运行成功推导成 target SDK 36 下可直接部署。项目首期计划 `minSdk 26 / compileSdk 36 / targetSdk 36`，以实测能力约束支持范围。若现代目标的启动链路尚未打通，报告应停留在阻塞状态，不能静默降到 target 28、root 或 shell UID 来制造成功。

## 4. 最先验证的技术风险：G0

在大量 UI 开发前，用最小 Android 测试宿主验证以下内容：

1. 从 APK 安装位置启动一个为 Android 构建的 ARM64 原生 launcher；确认执行 UID 为应用 UID、SELinux 保持正常模式。
2. launcher 能调用固定构建的 Box64，并处理其原生库依赖。Android Bionic 与 Wine Linux/glibc 用户态的组合方式必须有固定源码、构建参数和运行日志，不能把 Linux ELF 文件重命名成 `.so` 就视为 Android 可执行文件。
3. 验证 Wine 的子进程路径，包括 Wine loader/preloader、wineserver 和 Windows 子进程重新执行。仅 launcher 自身能启动不算通过。
4. 执行 `wine --version`、新 prefix 的 `wineboot -u`、Windows 版 `7z.exe` 的压缩与解压，再执行 wineserver 等待/终止。
5. 在拟认证设备上记录实际页大小和运行结果。ELF/APK 的 16 KB 对齐不等于 Box64/Wine 已通过 16 KB 运行验证；不支持的组合必须在启动前明确拒绝。

实现候选：Android 可用的 Box64 构建配合 APK 内原生入口，或在 APK 内携带已验证的原生 loader 与依赖。最终选择必须由 G0 的结果确定并锁定版本。现阶段没有已验证的 Runtime digest，禁止在配置中填入虚构版本或全零哈希。

Android 限制面向 API 29+ 应用从可写应用目录直接 `execve()`。设计中的原生入口应由 APK 包管理器部署到 `nativeLibraryDir` 等验证可执行的位置，数据资源和受解释/翻译的客体程序留在私有目录。所有后续实际原生 exec 路径仍要逐个验证；这一布局本身不能证明整条链路可用。

G0 未通过时暂停 GUI 整合，保留可重放的失败报告。可以用独立 Winlator 运行作对照，但单独记录，不提升 CompatForge 验收状态。

## 5. 组件与调用链

```text
Kotlin Activity / Surface / SAF
              |
       JNI 字节串桥接
              |
compatforge-android-bridge
              |
Android Provider -> CoreConfig -> AutomationService
                                  |
                         PreparedLaunch / ProcessSupervisor
                                  |
                APK 内 Wine launcher / wineserver launcher
                                  |
                   固定 Box64 + Wine + 私有 Bottle
                                  |
                         7z.exe / 7zFM.exe
                                  |
                   本地 X11 socket -> X server -> Surface
```

建议新增位置：

- `apps/android/`：独立 Gradle/Kotlin 工程，单应用列表、运行页面、文件导入/导出、取消和诊断导出。
- `crates/compatforge-provider-android/`：校验安装来源、运行包、页大小与探测回执；生成 `CoreConfig`，不持有 Android Activity。
- `crates/compatforge-android-bridge/`：最小 JNI API，持有 Service 实例，负责 JSON/bytes、线程、句柄释放与异常隔离。
- `apps/android/app/src/main/cpp/`：固定原生 launcher 和显示适配边界；第三方运行栈单独构建与锁定。
- `tools/run_android_acceptance.py`：宿主 ADB 协调器，限定设备序列号，收集证据并校验业务产物。
- `tools/summarize_android_acceptance.py`：从完整证据计算结果，不接受 CLI `--passed` 之类人工捷径。

JNI 桥接调用现有 Rust Service 类型即可；不要求扩展稳定 C ABI。现有 FFI 可独立作为交叉链接检查对象。若实现必须改变公共 Schema/ABI，先补充 ADR 和兼容性设计，不能以未知字段绕过现有严格解析。

## 6. 启动契约与进程生命周期

Android `RuntimeBinding.executable` 指向受控 Wine launcher，`wineserver_executable` 指向受控 wineserver launcher。两者接受现有参数语义，均使用 argv 数组传递，不经 shell。

- 应用启动：Wine launcher 收到 `[PE 路径, 应用参数...]`。
- Bottle 初始化：同一 launcher 收到 `[wineboot, -u]`。
- 等待与取消：wineserver launcher 收到 `[-w]` 或 `[-k]`。
- 运行包根、Wine 路径、Box64 路径与 digest 通过 Provider 的固定配置绑定，不能由应用自定义环境覆盖。
- APK 原生入口本身与 Runtime Pack 分别校验；当前 Core 的 runtime executable digest 必须绑定实际启动的 launcher，不能拿 Wine 文件的哈希代替。
- launcher 必须校验后续 Wine/Box64/库集，与 pack digest 一致；不能只校验第一层 wrapper。
- 保留 `PreparedLaunch` 的 inspection、原始 PE 绑定和启动前复验。

延续 Bottle 排他租约和有序 RuntimeEvent。跟踪每次会话的实际进程身份与启动时间、prefix、socket；取消仅终止本会话。不能使用全局 `pkill wine` 或仅凭 PID 大小/进程名判定归属。Wine daemon 脱离初始进程组、Android 限制 `/proc` 可见性、应用被强制停止后的恢复都需测试。无法确定清理完成时返回 cleanup unknown/failed，不生成“零残留”结论。

首期最多一个活跃任务，只承诺前台运行。Activity 重建时可重接同一会话，真正进入后台时请求有界取消；不保证未保存的客体编辑内容保留。系统强杀后，下次进入应用先核对会话和租约，旧运行任务标记 interrupted，不能直接当作成功。后台保活服务属于后续阶段，需要单独选择符合用途的服务类型。

## 7. 显示、文件与权限

首期引入固定版本的 Android X server 适配，使用应用本地 Unix socket，支持 X11 基本窗口、GDI 绘制和鼠标键盘事件。显示组件来源、许可证、构建与 API 契约在 G0/G1 锁定；不从零实现完整 X server。WineD3D/Vulkan 不作为 7-Zip 基础功能通过的必需能力，未测则保持 unavailable。

Surface 必须验证：绘制完成、尺寸变化、触摸坐标换算、点击/双击、菜单和键盘。只在 Compose 页面画一个“运行中”标签不能证明 Windows GUI 显示。

文件通过 SAF 选择后复制到应用私有 staging，校验并固定内容，再映射到 Bottle 工作目录。`content://` URI 不能当作 POSIX 路径传给 Wine。输出先落私有目录，完成校验后通过 SAF 导出；不申请全盘管理权限，不默认映射手机根目录。

第一版运行 APK不声明 `INTERNET`，资源由宿主下载并经测试入口导入，显示使用本地 socket；以实际权限清单检查网络隔离，不能仅凭 `NetworkPolicy::Deny` 字段宣称内核已执行限制。调试入口仅限 debug/instrumentation，不在 release 暴露任意命令执行组件。

## 8. 第一个应用：固定 Windows x64 版 7-Zip

复用 `tools/download_gui_assets.py` 中既有 `7zip` 资产，不额外维护一份可漂移的下载清单：

- 版本：7-Zip 26.01，文件 `7z2601-x64.exe`。
- 上游：`https://www.7-zip.org/a/7z2601-x64.exe`。
- 仓库记录的 SHA-256：`d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d`。
- 在设备 Wine 中用 `/S` 安装；检查 installer 的实际 PE 架构，并将它所需的 Wine/WoW64 能力作为 gate，不能根据文件名假设安装器所有阶段都是 x64。
- 安装后记录并复验 `7z.exe`、`7zFM.exe`、依赖 DLL 与必要资源；启动已安装文件使用现有 `bottleInPlace`，保留相邻 DLL。

若资产不可获取、哈希不匹配或安装器需要未支持的组件，报 asset/runtime blocked。不能自动改用最新版或替换成安卓原生 7-Zip。

### 自动化业务验证

每轮创建新 Bottle 和独立工作目录，生成 UTF-8 文本、中文名称、带空格名称、空文件及固定二进制文件。保存路径、长度和 SHA-256 清单。

通过 Windows `7z.exe` 依次执行以下等价 argv（均由结构化调用发起）：

```text
7z.exe a -t7z C:\CompatForge\work\roundtrip.7z C:\CompatForge\work\input\* -y
7z.exe t C:\CompatForge\work\roundtrip.7z
7z.exe x C:\CompatForge\work\roundtrip.7z -oC:\CompatForge\work\output -y
```

压缩、测试和解压退出码必须为 0。由 Android 原生或宿主端独立 SHA-256 实现比较完整输出路径集合、长度和内容，拒绝缺失文件、额外文件、目录穿越和读取失败。清单比较必须验证中文路径，不只比较文件数量。

### GUI 功能验证

由 CompatForge Service 启动同一 Bottle 的 Windows `7zFM.exe`：

1. 在真实 Surface 上出现并可交互的文件列表。
2. 通过触摸打开菜单、进入测试目录、打开前述压缩包。
3. 在 GUI 内解压到另一个空目录，再由独立 oracle 比对内容。
4. 确认中文文件名可读；所需字体资产同样锁定来源与哈希。
5. 关闭窗口，确认 Job 完成和本会话进程、Wine server、socket、租约均清理。

Android UIAutomator 未必能读取 X server 内的 Win32 控件树。首轮允许用户在真机完成 GUI 操作；工具保存运行中截图/录屏、当前 runId 和操作后产物。截图仅为辅助证据，GUI 功能必须同时有本轮操作产生的产物及明确的现场确认。自动化版本需要 X server 的窗口/输入观察接口，不能预填“人工通过”。

同一应用至少执行两轮全新 Bottle 的正常验收，再执行一轮运行中取消和一轮前后台切换/恢复检查。首次认证严格限定为一个实际设备组合。

## 9. 证据模型与判定

宿主运行工具必须使用显式 `--serial`，多设备不得默认选第一个。没有设备返回 blocked，未经授权的设备返回 device-unauthorized。x86_64 模拟器可验证 Kotlin/JNI/权限与部分 GUI流程，但不能证明 ARM64 Box64 路径；ARM64 模拟器若能运行，也需单独标注 emulated，不能充当物理设备性能证据。

每轮报告记录：源码提交、APK SHA-256、包名/target SDK、设备型号/系统构建/ABI/页大小、物理或模拟器、运行栈全部版本和 digest、PE inspection、安装结果、请求与 LaunchPlan、RuntimeEvent、原生输出、业务 oracle、GUI 确认、截图哈希、清理证据和耗时。

结果分层：`build-only`、`runtime-probed`、`console-passed`、`gui-unverified`、`accepted`、`failed`、`blocked`。自动检查通过但缺少 GUI 操作证据时必须是 `gui-unverified`；没有设备不能是 `accepted`。只有两轮业务和 GUI 正常流程通过，取消/恢复检查通过，且清理状态已知成功，才生成该组合的 `accepted`。

证据保存在仓库外的用户指定目录，报告摘要可纳入 `docs/reports/`。设备标识默认脱敏，记录所需型号/构建信息即可。下载、运行时构建产物和 APK 不提交到源码仓库。

## 10. 实施关卡

| 阶段 | 完成条件 | 失败时处理 |
|---|---|---|
| G0 工具链与原生运行栈 | Android 编译边界清晰；目标 SDK 下真实应用 UID 执行 Wine/7z CLI | 停止 GUI 工作，记录精确阻塞 |
| G1 Provider 与 JNI | 固定 Runtime 的 probe/context/prepare/launch/event/cancel 全链路 | 禁止发布可用能力 |
| G2 GUI 与文件接入 | 7zFM 可操作，SAF 导入/导出和中文路径正确 | 保留 console-passed，不算 GUI 验收 |
| G3 单应用验收 | 两轮 7-Zip 完整流程及异常路径证据齐全 | failed/blocked/unverified，保留原因 |

实现次序和文件清单见 [实施计划](2026-09-29-android-local-runtime-plan.md)。本设计尚待用户确认；设备型号和连接方式待提供。

## 11. 参考依据

- [Android API 29+ 可执行文件限制](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission)。
- [Android 原生代码与 16 KB 页支持](https://developer.android.com/guide/practices/page-sizes)。
- [Android 前台服务类型](https://developer.android.com/develop/background-work/services/fgs/service-types)。
- [Winlator 主项目](https://github.com/brunodev85/winlator)。
- [Winlator app target SDK 配置](https://github.com/brunodev85/winlator-app/blob/main/app/build.gradle)。
- [Winlator 客体启动组件](https://github.com/brunodev85/winlator-app/blob/main/app/src/main/java/com/winlator/xenvironment/components/GuestProgramLauncherComponent.java)。
- [Box64 上游](https://github.com/ptitSeb/box64)。

外部链接于 2026-09-29 检查；main 分支仅用于调研。实际实现必须将所选源代码和二进制锁定到不可变 commit/digest，并核对各组件许可证；现有 upstream 配置不等于 CompatForge 的已验证配置。
