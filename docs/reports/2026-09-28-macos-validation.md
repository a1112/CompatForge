# macOS 本机测试与验收记录

## 结论

- 日期：2026-09-28，Asia/Shanghai。
- 基线：`acc68a90ad5dfd0131a4e43b1bb603b5d8a131bd` 加本轮未提交修复。
- 自动代码门禁：通过。
- 桌面窗口行为：通过本轮列出的操作检查。
- CrossOver Console：通过；三个 GUI 应用的窗口、截图、退出与清理检查通过。
- **完整双 Runtime 验收未通过**：WhiskyWine 官方下载源不可用；没有生成交互确认 receipts，没有执行双 Runtime 两轮矩阵及其负向隔离门禁。

此前在 macOS 26.5.2 上开始的运行因主机重启而中断，临时证据已丢失。本报告的自动测试和 GUI 基线均在重启后的 macOS 27.0 上重新执行，不复用旧系统的结论。

## 本机环境

| 项目 | 本轮值 |
| --- | --- |
| macOS | `27.0 (26A428)` |
| CPU 架构 | `arm64` |
| Rosetta | x86_64 Provider 夹具与真实 Wine Console 均可执行 |
| Rust | `1.94.1` |
| Node.js | `24.13.0` |
| Python | `3.12.13` |
| CrossOver | `26.3.0`，官方试用版 |
| Wine | `11.0-8726-g2e2f5fca349` |
| Whisky | `2.3.5` 应用已安装；Wine 依赖未安装成功 |
| MinGW | Homebrew `mingw-w64 14.0.0_3` |

用户授权后通过 Homebrew 安装了 CrossOver、Whisky 和 MinGW。Whisky 应用内安装依赖失败；再次请求其内置的官方地址 `https://data.getwhisky.app/Wine/Libraries.tar.gz` 返回 HTTP 404。官方[维护公告](https://docs.getwhisky.app/maintenance-notice)也说明 WhiskyWine 已停止更新。本轮没有以其他 Wine、第三方 fork 或未知二进制冒充 Whisky 运行时。

系统升级后，环境变量 `SDKROOT` 指向 Command Line Tools 的 macOS 27 SDK，而所选 Xcode 链接器不能识别其 `arm64e.x1-macos` 描述。Provider C 夹具使用所选 Xcode 自带的 macOS 26.5 SDK，通过显式 `-isysroot` 完成编译；没有修改全局 SDK 配置。

## 自动门禁

| 检查 | 结果 |
| --- | --- |
| Python 全量 `unittest discover -s tests` | 703 项，691 通过、12 按平台/文件系统条件跳过，0 失败 |
| Rust workspace `--all-targets --locked` | 266 通过、2 个显式真实运行时测试 ignored |
| Tauri Rust tests | 11 通过 |
| workspace 与 Tauri Rustfmt | 通过 |
| workspace 与 Tauri Clippy，`-D warnings` | 通过 |
| TypeScript 检查与 Vite 生产构建 | 通过 |
| Tauri `.app` 构建及打包后 smoke | 通过 |
| repository validator | 通过 |
| `git diff --check` | 通过 |
| x86_64 Provider 夹具 | Pack 安装、probe、context、plan、launch、terminate、exited 全部通过 |

Python 全量测试及 validator 在包含当前修复的干净源码副本中执行。副本具有独立 Git index 和 HEAD，以满足 Git blob/attributes 契约；构建缓存位于副本之外。测试输出经管道收集，避免副作用审计将预先打开的可写日志文件判为越界描述符。没有为适应依赖目录而放宽 repository validator。

## 本轮修复

1. 补齐 macOS `RunEvent::Reopen`：后台隐藏后，从 Finder/Dock 重开应用可恢复原主窗口。
2. 修正桌面 Rust 格式，并将窗口设置测试移至独立 `cfg(test)` 模块，避免生产环境访问契约误扫测试临时目录。
3. 同步窗口最小化、最大化、状态查询和关闭操作的精确权限契约。
4. 修复 macOS 测试对 `/proc/self/fd`、文件系统大小写行为的 Linux 假设；保留描述符泄漏和大小写碰撞检查。
5. 修复迁移测试的恢复扫描计数及只读父目录描述符审计；写操作仍必须位于批准的输出根内。
6. 为 SumatraPDF 官方重定向添加精确域名 `files.sumatrapdfreader.org`。仍要求 HTTPS、固定文件 SHA-256，并新增 HTTP 降级和相似恶意域名拒绝测试。
7. 支持 CrossOver 的 `lib/wine/x86_64-unix/ntdll.so` 布局及观察器的相对库路径，同时拒绝库文件逃逸出物化运行时根。

## 桌面操作验收

使用隔离的 Provider 夹具与独立设置目录，通过原生 UI 操作检查：

- 运行环境重新发现成功，应用目录显示 3 个默认应用。
- 最大化后按钮变为“还原”，还原后变回“最大化”。
- 设置窗口独立打开，关闭设置不退出主窗口。
- 启用“关闭后保留后台”后，主窗口关闭隐藏，原进程保留。
- 从 Finder 重开 `.app` 后，同一进程恢复原主窗口。
- `Command-Q` 正常退出，进程检查确认不存在残留。

这些结果证明桌面壳操作行为；不替代真实 Windows 应用兼容性认证。最小化、托盘菜单恢复及有活动 Windows 任务时的退出没有单独取得本轮操作证据。

## CrossOver 真实应用基线

| 应用 | 窗口 | 非空截图 | 生命周期退出 | Bottle 清理及零残留 | 最终状态 |
| --- | --- | --- | --- | --- | --- |
| Console fixture | 不适用 | 不适用 | exit 0 | runner 成功 | `success: true` |
| 7-Zip 26.01 | 通过 | 通过 | 通过 | 通过 | `unverified` / compatibility `blocked` |
| SumatraPDF 3.6.1 Portable | 通过 | 通过 | 通过 | 通过 | `unverified` / compatibility `blocked` |
| Notepad++ 8.9.6.2 | 通过 | 通过 | 通过 | 通过 | `unverified` / compatibility `blocked` |

三款 GUI 的 `interactive-behavior` 均为 `blocked`：未运行交互确认 helper，也未把截图或诊断性启动转换为人工签署。截图中的中文菜单可见，但没有据此声明打开对话框、文件列表操作或中文编辑保存回读通过。SumatraPDF 使用现有固定摘要便携程序和 pinned 执行路径，未退回可变路径执行。

CLI SHA-256：`cd3b52488e667504a2640c1221f55f40ec42629a417a31ae8d4b7af4ac590613`。

桌面可执行文件 SHA-256：`53e62621f71b05c3f7cceb437cde1a59824dd40c5beb82539fc7d0f2a2e4ab04`。

## 交接边界

原始日志、截图、Runtime 派生副本、固定安装器和汇总 JSON 保存在仓库外的本机持久证据目录。验收与诊断进程已退出；GUI runner 报告三个 Bottle 清理成功且没有残留。报告不包含开发者绝对路径，也不将安装器或 Runtime 内容提交 Git。

完整门禁仍需：取得来源可核验的 WhiskyWine，重新通过双 Runtime 发现预检，使用全新隔离根执行 16 条路径、12 份逐项交互 receipts、两轮投影一致性以及四项负向隔离检查。步骤见[双 Runtime 验收指南](../guides/macos-local-dual-runtime-acceptance.md)。

本轮没有提交、推送或声明远端 CI 通过，也没有签名公证、制作 DMG 或发布兼容评级。

## WhiskyWine 官方重试与原源码构建补充

同日再次请求 Whisky 应用内使用的官方 `Libraries.tar.gz` 和 `WhiskyWineVersion.plist` 地址，两者均返回 HTTP 404。

已从 `Whisky-App/wine` 的 `7.7` 分支下载固定源码快照；对应提交为 `a92f7f06c4cff7291578e58eb95284b00e322799`，压缩包 SHA-256 为 `3959fa6e2b2200f55c2ecb4f389fba01e0d478e03038620cec466c7e1ca31d54`。源码解包、x86_64 FreeType 构建及 Wine 64 位配置均成功。FreeType 2.14.3 源码 SHA-256 与 Homebrew 公式固定值 `36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f` 一致。

本机完整 Wine 编译仍未完成。Apple Clang 21 拒绝旧汇编中的公开标签；LLVM 17 编译了该目标。现行 MinGW 14 的 UCRT 接口与源码不兼容，因此使用原项目构建脚本固定的 Homebrew MinGW 11.0.1 bottle 作隔离重试，其 SHA-256 为 `3a9ccfa83474eebd0139d97b37d552e460f2ab4c1cccf170d76e214d9950792d`。最终构建在 `dlls/winecrt0/32on64_ldt.o` 停止：当前可用 LLVM 17 不接受 macOS 目标的 `-mabi=ms`。原构建脚本所依赖的定制 `cx-llvm` 已不在对应 Homebrew tap 中。配置另报告缺少 Wine preloader 和 GnuTLS；即使绕过当前编译错误，仍需解决并验证这些组件。

本轮没有将半成品安装进 Whisky，也没有修改原 Wine 源码。MinGW 已恢复为本轮原先安装的 14.0.0_3；源码、依赖构建和日志保留在仓库外，供继续移植或采用可验证的原始运行时包时复核。**完整双 Runtime 门禁仍保持未通过。**
