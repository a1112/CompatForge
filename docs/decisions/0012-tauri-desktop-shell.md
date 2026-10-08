# ADR-0012：桌面壳使用 Tauri 2 与 TypeScript

## 状态

Accepted，2026-08-16。

## 决策

移除 `apps/desktop` 的 Qt 6/QML/C++ 实现，改用 Tauri 2、Vite 和 TypeScript。macOS 主窗口采用应用网格，功能页只保留应用程序、安装器、Bottle、运行记录和兼容环境；设置通过独立的 macOS 风格窗口呈现。

Tauri Rust Commands 在进程内直接调用现有 Rust Core。WebView 只发送用户意图和显示可序列化 view model，不读取 Bottle/Runtime 私有路径、不持有 PID、不构造 Wine 命令，也不削弱 `immutableArtifact`、`bottleInPlace`、Runtime digest 或网络策略门禁。阻塞 Core 调用使用异步 Command；主窗口关闭由 Rust 读取 `closeToBackground` 设置：开启时隐藏窗口并通过托盘恢复，退出应用时终止并等待活动任务。

稳定 C ABI 继续服务外部 C/C++、IPC 和未来非 Rust 客户端；桌面壳替换本身不改变 ABI major `1`，后续应用服务以 additive API `0.12.0` 交付。

## 理由

应用网格和多功能页面需要更灵活的布局、样式与交互迭代。Tauri 能复用 Rust Core，避免新增守护进程协议，同时保留 macOS 原生窗口、系统文件对话框和轻量 WebView。首轮前端使用无框架 TypeScript，降低依赖和状态层复杂度；需求增长后再单独评估框架。

## 后果

- 默认桌面 CI 改为 TypeScript/Vite、Tauri Rust Test/Clippy、`.app` build 和 smoke。
- 当前只承诺 macOS ARM64 真实 GUI 验收；Linux/Windows 继续验证 Core，桌面 WebView 适配另行门控。
- 使用 overlay titlebar 和受限 `dialog:allow-open`；不开放 shell、通用文件系统或网络插件权限。
- Qt 构建依赖、QML、C++ wrapper 和 Qt Test 全部删除。
