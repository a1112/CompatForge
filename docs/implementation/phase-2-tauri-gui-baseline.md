# Phase 2：Tauri 薄壳与首批 GUI 兼容基线

本阶段把 macOS ARM64 的第一个可审计 GUI 纵向切片落到 Core、C ABI、Tauri 和 opt-in 真实验收。它建立兼容基线，不宣称已经达到完整 Mac-Win 功能或 Tier 1。

## Runtime bootstrap

`cf_macos_local_context_create` 是唯一的 macOS 本地 Runtime 发现真源。它只检查固定候选：CrossOver 应用、Whisky 应用/本地库，以及仓库外 Mac-Win 开发构建；不读取 PATH、不启动 shell、不联网，也不递归扫描。候选必须通过：

1. 绝对路径、普通可执行文件和受限 Mach-O 架构检查；
2. 直接 argv `--version` 探测，要求 `wine-<version>`；
3. wineserver 同样的 bounded probe；
4. Rust `RuntimePackStore` 的 Preview Pack 内容寻址登记与幂等验证；
5. `MacOsProviderSet::probe_with` 的入口哈希、Pack、架构和 Rosetta 证据复验。

Bootstrap 请求只允许 `schemaVersion`、绝对 `runtimeStoreRoot`、绝对 `storageRoot`，以及必须完整出现的 `materializedRoot/wine/wineserver/version` 覆盖四元组。Receipt 只返回来源标签、版本、架构、Pack ID/digest 和能力；私有 Core 配置由 CLI 的可选 context-output 或 FFI opaque handle 持有。

本地 Context 同时发布内容寻址的 Fontconfig 配置，并从固定 macOS 系统字体候选中选择 CJK 字体。Receipt 只披露字体配置摘要、字体文件摘要、回退家族和别名，不披露主机字体路径。受保护 Runtime binding 保存实际路径与摘要；`ProcessSupervisor` 在每次 spawn 前重新计算摘要，拒绝缺项、符号链接或内容变化。

## Launch binding

`immutableArtifact` 继续把 PE 写入内容寻址 Guest Artifact store；`bottleInPlace` 只允许 `<storageRoot>/bottles/<bottleId>/prefix/drive_c` 下的无符号链接普通文件，并把安装后的 EXE、架构、子系统、大小和 SHA-256 绑定进 `LaunchPlan.bottleExecutable`。DLL、插件和相邻资源仍由 Bottle 原位解析，摘要不覆盖它们，因此 Bottle 不等于安全沙箱。`ProcessSupervisor` 在授权、哈希复验后才物化 working directory/WINEPREFIX，并拒绝 symlink/path collision。

Wine prefix 初始化后，Supervisor 把已验证的 CJK 字体以产品专用文件名链接到 `windows/Fonts`，并通过 Wine 自带 `reg` 写入固定的 GDI 字体替换项。来源摘要与注册决策进入 LaunchPlan trace；已有非产品目标、错误链接或缺失 Wine 生命周期都会拒绝启动。Fontconfig 只覆盖宿主字体发现，Bottle 字体与注册表替换才是 Win32 GDI 中文菜单的实际修复层。

## Tauri shell

`apps/desktop` 使用 Tauri 2、Vite 和 TypeScript。主界面是 macOS 风格应用网格，上方提供应用程序、安装器、Bottle、运行记录、兼容环境和设置切换，以及安装状态筛选、搜索和排序。前端只呈现状态并发送用户意图；它不读取 Runtime/Bottle 文件、不持有 PID、不拼装 Wine argv/environment。

Tauri Rust Commands 直接调用 `compatforge-provider-macos`、`compatforge-inspect`、`compatforge-orchestrator` 和 `compatforge-process`。Bootstrap、inspection、PreparedLaunch、start 和事件轮询以异步 Command 离开 WebView 线程；窗口关闭由 Rust 终止活动进程树，并在 20 秒内等待 `exited`。原生文件对话框是唯一开放的插件能力；CSP 禁止远程脚本，默认网络策略继续由 Core 固定为 `deny`。外部 C ABI 与 ABI major `1` 不受壳层替换影响。

本阶段不实现应用商店、完整 Bottle 设置、Recipe 编辑器、D3DMetal 配置、除原生文件选择外的系统桥、签名发布或 notarization。

## GUI evidence

`tools/download_gui_assets.py` 固定官方 URL、重定向主机、流式大小上限和 SHA-256，只有 `--allow-network` 才下载，缓存必须在仓库外。`tools/run_gui_baseline.py` 为 7-Zip、SumatraPDF、Notepad++ 各建独立 Bottle；7-Zip 与 Notepad++ 先以 immutable installer 安装，SumatraPDF 则把固定摘要的官方 portable 字节单次写入 Bottle 固定路径并做有界准备启动，随后三者均以 `bottleInPlace` 启动，并记录 inspection、LaunchPlan、RuntimeEvent、窗口/截图和清理。空白窗口或仅进程启动只能得到 `unverified`。

真实窗口观察优先接受与 RuntimeEvent `started.processId` 相同进程组的目标标题，并在固定窗口出现期限内轮询；macOS 优先使用 CoreGraphics 窗口列表取得窗口 ID，再用该 ID 截取目标窗口，只有在 Wine GUI 脱离原始进程组且仍绑定到已准备 Runtime 身份时才使用全局标题回退。锁屏、Accessibility 或截图设施不可用归为 `test-infrastructure`，目标窗口在可观察桌面上缺失归为 `runtime-regression`，二者不再混写。整屏截图本身不构成通过证据。SumatraPDF 的匿名 inspection/plan 输出位于独立的私有证据子目录，避免同轮截图改变其目录身份；CLI 逐条刷新 RuntimeEvent，并且只在所有工作线程与 Wine 清理完成后输出终端 receipt。

双 Runtime 正式验收的 `--accept-interactive` 必须同时提供仓库外的交互计划、acknowledgement 根和 round ID，由第二终端逐项确认；扩展认证矩阵则可使用仓库外的 v2 `--interaction-evidence` JSON，包含闭集 human attestation、观察者、带时区时间和逐应用检查。两种证据模式互斥，静态 v2 证据不能替代双 Runtime 的实时 challenge/receipt。目标进程残留或 Bottle 清理失败都会阻止 `accepted`。可重复使用 `--app <id>` 仅运行指定应用，以进行有界的兼容性实验。

```json
{
  "schemaVersion": "2",
  "attestation": {
    "mode": "human",
    "observer": "Compatibility Lab",
    "observedAt": "2026-08-18T10:00:00+08:00"
  },
  "applications": {
    "7zip": { "fileList": true, "menus": true, "cjkTextReadable": true },
    "sumatrapdf": { "mainWindow": true, "openDialog": true, "cjkTextReadable": true },
    "notepad-plus-plus": {
      "open": true,
      "edit": true,
      "saveUtf8Chinese": true,
      "cjkTextReadable": true,
      "rereadMatches": true
    }
  }
}
```

默认 CI 只执行 Rust/FFI、仓库合同、TypeScript 检查、Vite/Tauri build、Tauri Rust Test/Clippy 与无 Runtime 的 app smoke；真实下载、Wine 安装、窗口 Accessibility 和截图只在本机显式 opt-in。

## Extended matrix

默认三应用基线之外，资产工具固定 Firefox 152.0.1 与 Krita 5.2.9 的官方 URL、SHA-256、安装位置、启动参数和稳定截图延迟。它们只在显式 `--app firefox` 或 `--app krita` 时运行：Firefox覆盖 Gecko 多进程、浏览器内容和中文渲染；Krita 覆盖大型 NSIS 安装器、COFF 长节名、Qt、OpenGL 工作区和中文界面。

Krita 的兼容环境是资产级请求数据：`QT_OPENGL=desktop`、固定 DPI/缩放、`WINE_D3D_CONFIG=renderer=gl,csmt=0x0` 及当前 Runtime 支持的 Krita 修复开关都会进入 LaunchPlan，不修改全局环境。PE 检查上限为 256 MiB，并仍在读取前检查普通文件、符号链接和大小；COFF 长节名只接受 `/` 后跟十进制数字的标准字符串表引用形式。

Phase 2.1 再加入五个显式认证资产：7-Zip x86（i386）、VLC 3.0.21（Qt/媒体）、WinMerge 2.16.58 x64 portable（MFC/开发工具）、Audacity 3.7.8 x86（wxWidgets/音频）和 Everything 1.4.1.1032 x86（Win32/搜索）。十项矩阵全部固定官方 URL、SHA-256、包类型、安装/物化位置、Guest 架构、窗口标题和人工检查闭集。下载仍是 opt-in，新增资产不进入默认 CI。

每个应用同时输出 `*-compatibility-result.json`，绑定矩阵摘要、软件包摘要（兼容字段名 `installerDigest`）、Runtime Pack 摘要、主机版本/架构和 `gui-interactive-v2` 测试套件。非通过结果必须使用测试策略中的闭集失败分类。`tools/summarize_gui_compatibility.py` 汇总 release gate，并分别统计人工策略阻塞与桌面基础设施阻塞。
