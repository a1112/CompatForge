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

## Launch binding

`immutableArtifact` 继续把 PE 写入内容寻址 Guest Artifact store；`bottleInPlace` 只允许 `<storageRoot>/bottles/<bottleId>/prefix/drive_c` 下的无符号链接普通文件，并把安装后的 EXE、架构、子系统、大小和 SHA-256 绑定进 `LaunchPlan.bottleExecutable`。DLL、插件和相邻资源仍由 Bottle 原位解析，摘要不覆盖它们，因此 Bottle 不等于安全沙箱。`ProcessSupervisor` 在授权、哈希复验后才物化 working directory/WINEPREFIX，并拒绝 symlink/path collision。

## Tauri shell

`apps/desktop` 使用 Tauri 2、Vite 和 TypeScript。主界面是 macOS 风格应用网格，上方提供应用程序、安装器、Bottle、运行记录、兼容环境和设置切换，以及安装状态筛选、搜索和排序。前端只呈现状态并发送用户意图；它不读取 Runtime/Bottle 文件、不持有 PID、不拼装 Wine argv/environment。

Tauri Rust Commands 直接调用 `compatforge-provider-macos`、`compatforge-inspect`、`compatforge-orchestrator` 和 `compatforge-process`。Bootstrap、inspection、PreparedLaunch、start 和事件轮询以异步 Command 离开 WebView 线程；窗口关闭由 Rust 终止活动进程树，并在 20 秒内等待 `exited`。原生文件对话框是唯一开放的插件能力；CSP 禁止远程脚本，默认网络策略继续由 Core 固定为 `deny`。外部 C ABI 与 ABI major `1` 不受壳层替换影响。

本阶段不实现应用商店、完整 Bottle 设置、Recipe 编辑器、D3DMetal 配置、除原生文件选择外的系统桥、签名发布或 notarization。

## GUI evidence

`tools/download_gui_assets.py` 固定官方 URL、重定向主机、流式大小上限和 SHA-256，只有 `--allow-network` 才下载，缓存必须在仓库外。`tools/run_gui_baseline.py` 为 7-Zip、SumatraPDF、Notepad++ 各建独立 Bottle；7-Zip 与 Notepad++ 先以 immutable installer 安装，SumatraPDF 则把固定摘要的官方 portable 字节单次写入 Bottle 固定路径并做有界准备启动，随后三者均以 `bottleInPlace` 启动，并记录 inspection、LaunchPlan、RuntimeEvent、窗口/截图和清理。空白窗口或仅进程启动只能得到 `unverified`。

真实窗口观察只接受与 RuntimeEvent `started.processId` 相同进程组的目标标题，并在 30 秒窗口出现期限内轮询；macOS 优先使用 CoreGraphics 窗口列表取得窗口 ID，再用该 ID 截取目标窗口，整屏截图本身不构成通过证据。SumatraPDF 的匿名 inspection/plan 输出位于独立的私有证据子目录，避免同轮截图改变其目录身份；CLI 逐条刷新 RuntimeEvent，并且只在所有工作线程与 Wine 清理完成后输出终端 receipt。`--accept-interactive` 必须同时提供仓库外的交互计划、acknowledgement 根和 round ID，由第二终端逐项确认 7-Zip 文件列表/菜单、SumatraPDF 主窗口/Open 流程，以及 Notepad++ 打开、编辑、UTF-8 中文保存和复读一致。目标进程残留或 Bottle 清理失败都会阻止 `accepted`。

```json
{
  "schemaVersion": "1",
  "applications": {
    "7zip": { "fileList": true, "menus": true },
    "sumatrapdf": { "mainWindow": true, "openDialog": true },
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
