# Linux x86_64 Runtime Provider Preview 设计

## 状态

- 日期：2026-09-04
- 状态：已批准，待实施
- 基线：main@7c9561257fe21e0c9e077f3046c3b3785c1c30f2
- 实施分支：agent/linux-x86_64-runtime-provider-preview
- 检查点：Linux x86_64 Runtime Provider Preview / Trusted Console Slice

## 背景与顺序调整

macOS ARM64 M0 soak 仍由 PR #29 独立推进，且尚未取得 canary 与正式 60 周期证据。Linux 工作不会改变该状态，也不会被描述为 M0 或 Phase 2.3 完成。

为避免项目被单一 macOS 实验室阻塞，本检查点从干净的 main@7c95612 并行建立 Linux x86_64 可信启动纵向切片。它不依赖 PR #29 的 soak 实现；PR #29 合并后，本分支再 rebase 到新的 main，然后提交真实 Linux canary 证据。

## 目标

本检查点证明以下闭环可以在 Linux x86_64 上工作：

    显式固定 Wine Runtime
      -> Linux Provider 复验
      -> CoreConfig / RuntimeBinding
      -> PE 检查与 Guest 内容寻址
      -> PreparedLaunch prepare + authorize + spawn 前复验
      -> 真实 Windows Console PE
      -> RuntimeEvent、stdout、退出码与清理证据

首个 Guest 固定为 tests/fixtures/windows_console_smoke.c。成功输出必须且只能出现一次：

    COMPATFORGE_WINDOWS_CONSOLE_OK

## 非目标

本检查点不包含：

- X11 GUI 窗口观察、截图或图形渲染验收；
- Wayland；
- Linux ARM64、FEX、Box64、QEMU 或虚拟机后端；
- DXVK、vkd3d-proton 或 D3D capability probe；
- MSI、真实第三方 Windows 应用或应用兼容性矩阵；
- Desktop/Tauri Linux 打包；
- Wine 下载、分发、自动解包或正式 Runtime materializer；
- 任意不可信 Guest 的安全执行；
- Beta、Tier 1 或 Phase 2.3 完成声明。

当前 SandboxProfile 与 networkPolicy 仍是计划合同，不构成完整的 Linux namespace、seccomp、Landlock 或网络隔离实现。因此，本检查点只允许运行仓库中固定、可审查、现场编译并摘要绑定的 Console fixture。

## 代码与冲突边界

新增：

- crates/compatforge-provider-linux/
- schemas/linux-provider.schema.json
- schemas/linux-bootstrap-request.schema.json
- tools/run_linux_console_preview.py
- tests/test_linux_provider_contracts.py
- Linux Provider 专属 fixture、文档与 workflow（如实施需要）

最小集成修改：

- workspace Cargo.toml 与 Cargo.lock
- apps/cli/Cargo.toml
- apps/cli/src/main.rs
- 独立 Linux CI job 或 workflow

不修改 PR #29 当前所有的 macOS soak/GUI 文件，尤其是：

- tools/run_gui_soak.py
- tests/test_gui_baseline_contracts.py
- tests/test_phase_2_3_contracts.py
- docs/testing.md
- docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md

## Linux Provider 架构

新增 Rust crate compatforge-provider-linux。它只负责：

1. 校验 Linux x86_64 宿主；
2. 复验显式 Runtime Pack、物化入口及实际版本；
3. 产生 CapabilityReport 与精确 RuntimeBinding；
4. 为本地 Preview bootstrap 产生无路径 receipt。

Provider 不负责 Runtime 选择、Guest 选择、策略授权、进程启动或终止。这些继续由现有 Orchestrator、PreparedLaunch 与 Process Supervisor 负责。

CLI 增加：

    compatforge-cli provider linux probe <provider-config.json>
    compatforge-cli provider linux context <provider-config.json> <storage-root>
    compatforge-cli local linux context <bootstrap-request.json>
    compatforge-cli local linux context <bootstrap-request.json> <private-context-output.json>

local linux context 是唯一的本地引导捷径，但仍会注册 Preview Runtime Pack，并经过与显式 Provider 配置相同的复验边界。

## 数据契约

### Bootstrap 请求

linux-bootstrap-request.schema.json 使用 Draft 2020-12、additionalProperties: false，只允许：

- schemaVersion
- runtimeStoreRoot
- storageRoot
- materializedRoot
- wine
- wineserver
- version

本检查点要求 Runtime 四元组 materializedRoot/wine/wineserver/version 全部出现，不提供自动发现模式。

规则：

- runtimeStoreRoot、storageRoot、materializedRoot 必须是绝对路径；
- 三个 canonical root 不得相等或相互包含；
- wine 与 wineserver 必须是无反斜杠、盘符、空段、点段的 portable relative path；
- 所有 JSON 对象拒绝未知字段；
- 所有路径只进入私有输出，不进入公开 receipt。

### Provider 配置

linux-provider.schema.json 保持与 Core binding 相同的身份概念：

    {
      "schemaVersion": "1",
      "runtimeStoreRoot": "/external/runtime-store",
      "wineRuntime": {
        "providerId": "wine-linux-x86-64-preview",
        "packId": "wine-linux-x86-64-local-preview",
        "packDigest": "sha256:...",
        "version": "...",
        "architecture": "x86_64",
        "materializedRoot": "/external/wine-root",
        "wine": {"path": "bin/wine64", "digest": "sha256:..."},
        "wineserver": {"path": "bin/wineserver", "digest": "sha256:..."},
        "capabilities": ["guest-x86_64"],
        "wined3dCapabilities": ["opengl"]
      }
    }

当前 Planner 对所有 Wine LaunchPlan 都要求一个图形选择，因此 Provider 发布与同一 Pack digest 绑定的内建 WineD3D descriptor。它只表示该 Runtime 的可选规划后端，不是 D3D 或 GUI 验收证据。Console summary 必须显式记录 graphicsValidated: false；后续 X11 GUI/D3D probe 才能改变这一状态。

### 公开 receipt

Bootstrap receipt 只包含：

- schemaVersion
- source，本阶段固定为 explicit-override
- version
- architecture，固定为 x86_64
- packId
- packDigest
- capabilities

Receipt 不包含 Runtime、Storage、Wine、Wineserver、临时目录或输出目录的路径。私有 CoreConfig 由调用者明确指定的输出文件或进程内对象持有。

## Runtime Pack Preview 语义

本地 bootstrap 将 Wine 与 Wineserver 入口复制成 Runtime Store 可复验的开发证据，并由现有 RuntimePackStore 生成和安装 manifest/object。Provider 配置中的 materializedRoot 仍指向用户明确选择的完整外部 Wine 分发树。

这不等于完整 Wine 分发已被 Runtime Store 物化，也不构成可重新分发的正式 Runtime Pack。每次 probe 与 context 都必须同时：

- 复验 Store manifest 及其全部对象；
- 复验外部物化入口的 containment、类型、权限、摘要、ELF 与版本。

## 入口与版本复验

在执行任何 Provider 入口前必须完成：

1. canonicalize materializedRoot 和两个入口；
2. 确认 canonical 入口仍位于 canonical root 内；
3. 确认入口是普通文件且具有 Unix executable bit；
4. 计算 SHA-256 并与 Provider 配置一致；
5. 解析有界 ELF header：magic、ELF64、little-endian、EM_X86_64，以及 ET_EXEC 或 ET_DYN；
6. 拒绝 shell wrapper、目录、截断 ELF 和越界 symlink；
7. 分别执行绝对 wine --version 与 wineserver --version；
8. 使用独立 argv，不调用 shell；工作目录固定为 materialized root；环境从空白 allowlist 构造；
9. 每个 probe 最长五秒，输出总量不超过 64 KiB；
10. 两个规范化版本必须与请求中的声明版本相同。

任何失败都生成 unavailable/错误结果，不产生 RuntimeBinding，更不得回退到 PATH、Home、发行版 Wine、网络或其他 Runtime。

## RuntimeBinding

成功快照使用 canonical absolute Wine/Wineserver 路径，并至少携带：

- COMPATFORGE_RUNTIME_PACK
- COMPATFORGE_RUNTIME_PACK_DIGEST
- COMPATFORGE_RUNTIME_EXECUTABLE_SHA256
- COMPATFORGE_WINESERVER_EXECUTABLE_SHA256
- WINEDEBUG=-all
- WINESERVER=<canonical absolute path>

Pack ID/digest 与入口 digest 均进入不可变绑定。PreparedLaunch 在真正 spawn 前重新编译与授权计划，并由现有 Guest/Runtime 复验拒绝引导后发生的内容替换。

## Console canary Runner

新增 tools/run_linux_console_preview.py，只由用户显式调用。它要求显式的：

- CompatForge CLI 绝对路径；
- MinGW compiler 绝对路径；
- Runtime Store、Storage、Wine materialized root 与 Evidence root；
- Wine、Wineserver 相对入口及 Runtime 版本。

Runner 不下载工具或 Runtime，不扫描 PATH，也不在仓库内写证据。

执行流：

1. 校验 Linux x86_64 和所有绝对根目录；
2. 确认 Evidence root 不与仓库、fixture、Runtime Store、Storage 或 Wine root 重叠；
3. 使用固定参数把 windows_console_smoke.c 编译为仓库外 x86_64 PE；
4. 调用 compatforge-cli inspect 并取得 Guest digest；
5. 调用 local linux context，保存公开 bootstrap receipt 与私有 context；
6. 写入摘要绑定、无参数、无额外环境、networkPolicy: deny 的 LaunchRequest；
7. 把 supervisor.maximumRuntimeMilliseconds 固定为 60,000；
8. 运行 prepared-plan 并保存计划；
9. 运行 prepared-launch 并保存 RuntimeEvent JSONL；
10. 复验事件顺序、stdout marker、退出码和 cleanup；
11. 生成无路径 public summary。

networkPolicy: deny 在此阶段只记录策略意图；由于完整 Linux 网络隔离尚未实现，固定 fixture 本身不得包含网络行为。

## 成功条件

一次 canary 只有同时满足以下条件才可通过：

- Provider 报告精确绑定的 Wine Runtime available；
- Planner 选择 wine、native 与同一 Runtime 的 wined3d；
- LaunchPlan 的 Pack/Guest digest 与 receipt/inspection 一致；
- RuntimeEvent sequence 严格递增，首事件为 started；
- stdout 中 COMPATFORGE_WINDOWS_CONSOLE_OK 恰好出现一次；
- 最终 exited 事件为 code 0、success: true；
- 没有 failed、timed-out 或 grace-period-expired；
- Bottle-scoped Wineserver stop 完成，唯一测试 prefix 不再有受管进程；
- cleanup 失败不会被成功退出码覆盖；
- 所有证据位于仓库外，Git 工作区保持干净。

## 失败分类

- contract：未知字段、非法 ID/digest、相对根路径、路径重叠或不支持的 capability；
- integrity：Pack/object/入口/Guest 摘要漂移、ELF 不匹配、symlink escape 或版本不一致；
- unsupported-host：非 Linux x86_64；
- test-infrastructure：缺少显式 MinGW、CLI、Runtime 文件，或受控 helper 无法建立；
- execution：Wine/Guest 非零退出、缺少或重复 marker、事件损坏、超时；
- cleanup：Wineserver、进程组或测试 prefix 生命周期未闭合。

所有错误 fail closed；不进行 Runtime、路径、命令或 capability 降级。

## 测试策略

### Rust 单元与集成测试

覆盖：

- serde deny_unknown_fields 与 schema version；
- 必填 Runtime 四元组；
- 三个根目录、relative path、symlink 与文件类型；
- ELF magic/class/endian/machine/type/truncation；
- executable bit、digest 与 Pack Store 漂移；
- Linux x86_64 host gate；
- 精确 probe argv、空环境、cwd、超时、输出上限及版本匹配；
- CapabilityReport、RuntimeBinding 和 path-free receipt；
- bootstrap 后、spawn 前的 Runtime 与 Guest mutation。

命令执行通过可注入的 ProbeCommand 边界测试；Windows/macOS CI 不需要伪装为 Linux 或执行 ELF。

### 离线 Linux CI

Ubuntu job 使用仓库内受控源码构建小型 ELF helper，建立合成 Runtime Store，覆盖真实 Linux 文件权限、ELF 与子进程探测边界，但不冒充真实 Wine 语义。

门禁至少包括：

- Repository contract validator；
- schema contract；
- cargo fmt --check；
- cargo test --workspace；
- Linux Provider Rust tests；
- tests/test_linux_provider_contracts.py；
- release CLI build 与新命令帮助检查。

CI 不下载 Wine，不扫描 Runner 已安装 Wine，也不把合成 helper 结果标记为 real canary。

### Linux x86_64 实机 canary

真实 canary 必须在用户控制的 Linux x86_64 主机上运行，显式提供固定 Wine 与 MinGW。X11/display 会话只记录为 metadata，不是 Console 成功前提。

公开 summary 只包含：

- schemaVersion 与 checkpoint；
- host OS/architecture；
- x11 或 headless session 标签；
- Runtime Pack ID、版本、digest；
- Guest digest；
- RuntimeEvent kinds；
- exit code 与 cleanup 状态；
- consoleValidated: true；
- graphicsValidated: false。

绝对路径、私有 CoreConfig、LaunchPlan 和详细日志只保存在仓库外 evidence root。

## 阶段状态与后续

- 仅离线契约与 CI 通过：implemented-awaiting-linux-canary
- 真实 Linux canary 通过：linux-console-preview-passed
- 任一状态均不代表 Beta、Tier 1、GUI 或任意应用兼容

下一独立检查点是 Linux x86_64 X11 GUI Probe：固定 Win32 window-text fixture、EWMH 观察、受控截图、确定性字体、生命周期和图形能力证据。Wayland 与 Linux ARM64/FEX 继续后置。

## 合并策略

本分支先完成设计、实现、评审和离线 CI。PR #29 关闭前保持独立，不改变 macOS 精确证据基线。PR #29 合并后 rebase 到新 main，解决 Cargo/CLI/CI 的机械冲突，再在 Linux x86_64 主机执行真实 canary。只有 canary 证据通过后，检查点才可标记为 linux-console-preview-passed。
