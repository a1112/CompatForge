# macOS 本机双 Runtime 完整兼容性验收设计

## 状态

- 日期：2026-08-21
- 基线：CompatForge `f70c103f346f74d4b9c13f41be33edd36eb8833e`
- 交付级别：开发者本机预览
- 主机：Apple Silicon macOS + Rosetta
- Runtime：CrossOver 与 Whisky
- 应用：7-Zip、SumatraPDF、Notepad++

本设计建立本机兼容性证据闭环。它不构成公测、通用兼容、Tier 1、发行或安全沙箱声明。

## 目标

在一台 Apple Silicon Mac 上，以同一 CompatForge Core、Service API 和 Tauri 桌面壳完成以下验收：

1. CrossOver 与 Whisky 均完成受限发现、Preview Pack 登记、复验和 Console PE 启动；
2. 两种 Runtime 分别完成三个 GUI 应用的下载、安装、启动、人工交互、退出和清理；
3. 所有应用资产来自固定官方 URL，并在执行前验证大小、重定向边界和 SHA-256；
4. 每条路径保留结构化环境、LaunchPlan、RuntimeEvent、窗口、交互结果和清理证据；
5. 在新的空工作根重复完整矩阵，证明结果不是偶然成功。

验收矩阵共八条路径，每条执行两轮：

| Runtime | Console | 7-Zip | SumatraPDF | Notepad++ |
|---|---:|---:|---:|---:|
| CrossOver | 必须 | 必须 | 必须 | 必须 |
| Whisky | 必须 | 必须 | 必须 | 必须 |

## 范围与所有权

本阶段只修改 CompatForge。ForgeOS、ForgeTools 和 Mac-Win 保持只读，避免提前改变跨仓库契约。

明确排除：

- Developer ID 签名、公证、DMG、自动更新和公开下载；
- 对外公测或公开兼容性声明；
- D3DMetal/GPTK 分发；
- ForgeOS 集成或 ABI major 变更；
- 应用商店、Recipe 编辑器和完整 Bottle 管理；
- 修改开发者真实 Wine 安装。

## 架构

现有分层保持不变，不新增第二套启动逻辑：

- Rust Core 与 Service API 是 Runtime、inspection、Bottle、PreparedLaunch、进程监督和事件的唯一真源；
- Tauri 桌面壳只发送用户意图并呈现状态，不读取 Wine/Bottle 文件，不拼装 Wine argv 或环境；
- 验收工具负责固定资产下载、矩阵编排、人工检查提示和证据汇总，不替代 Core；
- 缓存、Runtime Store、Core Storage、Bottle、截图和证据全部位于仓库外。

每个 Runtime 与应用组合使用独立可变状态：

```text
Runtime
  └─ Application
      ├─ 独立 Bottle
      ├─ 独立 Work Root
      └─ 独立 Evidence
```

CrossOver 与 Whisky 不共享可变 Bottle。按 SHA-256 寻址且只读的官方安装包缓存可以共享。

## 执行流程

1. 记录 Mac 型号、macOS、芯片、Rosetta、Rust、Node、Python 和工具版本；
2. 要求 Python 3.11+，记录实际解释器绝对路径，不依赖可能指向旧版本的环境默认值；
3. 从固定候选位置分别发现 CrossOver 与 Whisky，并绑定 `wine`、`wineserver`、版本和文件摘要；
4. 两种 Runtime 分别运行一次确定性 Console PE，验证 Core 启动链；
5. 构建并启动同一个 Tauri App；
6. 对每个 Runtime，按 7-Zip、SumatraPDF、Notepad++ 顺序执行：
   - 仅在显式允许网络时从固定官方 URL 下载；
   - 验证重定向主机、流式大小上限和固定 SHA-256；
   - 为组合建立独立 Bottle；
   - 以 `immutableArtifact` 启动安装器；
   - 以 `bottleInPlace` 启动安装后的程序；
   - 完成人工交互检查；
   - 终止进程树并验证无残留；
7. 在新的空工作根重复全部八条路径；
8. 比较两轮脱敏结构化摘要并生成阶段报告。

## 应用验收

- 7-Zip：文件列表可见，菜单可打开并响应；
- SumatraPDF：主窗口可见，Open 流程可用；
- Notepad++：可打开、编辑、以 UTF-8 保存中文，并重新读取为相同内容。

窗口出现或进程启动本身不能得到通过结论。交互证据缺失时结果必须是 `unverified`。

## 结果与错误模型

每条路径只能得到以下结果之一：

- `accepted`：启动、指定交互、退出和清理全部完成；
- `failed`：发现确定性的产品、Runtime 或工具故障；
- `unverified`：进程或窗口出现，但人工行为证据不完整；
- `blocked`：本机前提不满足，例如 Rosetta、Wine、编译器或网络不可用。

问题使用固定归属：`environment`、`runtime`、`core`、`desktop`、`application` 或 `cleanup`。

约束：

- 不允许一个 Runtime 失败后静默切换另一个 Runtime；
- 下载重定向、大小或摘要不匹配时拒绝执行；
- 一条应用失败不抹掉其他路径证据，但阶段整体不能完成；
- 篡改测试只能操作隔离副本；
- 清理仅限本次创建且通过身份复核的目录；
- 只有稳定复现并归属 CompatForge 的问题才进入代码修复。

## 证据边界

失败后保留日志、LaunchPlan、RuntimeEvent 和脱敏摘要。截图、安装包、Bottle、本机绝对路径和 Runtime 安装内容不提交 Git。

仓库只保存：

- 测试定义与固定资产摘要；
- 脱敏结果 Schema/格式；
- 阶段报告与已知限制；
- 可复现的最小 CompatForge 修复和回归测试。

## 测试层级

### 仓库自动门禁

- Rust workspace、Python contracts、Tauri Rust、TypeScript/Vite 和 repository validator 全绿；
- 下载器默认禁网；
- URL、重定向、大小与摘要负向测试通过。

### Mac 环境门禁

- Apple Silicon、Rosetta、CrossOver、Whisky、MinGW、Rust、Node 和 Python 3.11+ 全部记录并通过；
- 两种 Runtime 的 `wine` 与 `wineserver` 均通过架构、版本和摘要复验。

### 真实矩阵

- 两条 Console 路径；
- 六条 GUI 路径；
- 新空工作根中的完整重复运行。

### 负向与清理

- Wine、wineserver、Guest PE 或下载文件内容变化均在启动前拒绝；
- 每条路径退出后无受管进程、wineserver 或 Bottle 锁残留；
- 仓库保持干净，外部证据目录可独立归档和清除。

## 退出标准

阶段完成必须同时满足：

1. 十六次真实运行全部为 `accepted`；
2. 两轮脱敏结构化摘要一致；
3. 无未归类失败、无清理失败；
4. 最终修复提交的 Windows 与 macOS CI 全绿；
5. 阶段报告记录精确 CompatForge SHA、Mac 环境、两个 Runtime、三个应用版本、证据摘要和已知限制；
6. 不对外宣称通用兼容、Tier 1 或发行就绪。

阶段通过后，再选择签名公证设计或 ForgeOS 对 CompatForge 0.12 Service API 的集成设计。

## 已知本地基线说明

Windows 工作站的默认 `python` 是 Python 3.9.11，不满足仓库的 Python 3.11+ 前提，并会在导入 `dataclass(slots=True)` 时失败。使用明确的 Python 3.12.13 解释器后，converter、repository validator、`cargo fmt` 和完整 Rust workspace 测试均通过。实施与验收命令必须记录并使用实际受支持解释器，不把旧解释器失败误判为迁移证据损坏。
