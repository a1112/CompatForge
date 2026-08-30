# macOS 双 Runtime developer-local 验收报告

## 结论

- status: `accepted`
- executedAt: `2026-08-30 Asia/Shanghai`
- sourceCommit: `e6c7ffa5c321a7521c64b1844d41b96c7d1c8e5b`
- branch: `agent/macos-local-dual-runtime-acceptance`
- worktree: `dirty`; 本报告绑定上述基线提交及本地未提交验收修复，不声明远端 CI 状态。
- matrix: `16/16 accepted`
- acknowledgements: `12/12 GUI receipts`
- console: `4/4 automatic results`
- comparison: `roundsEqual: true`, `status: accepted`
- cleanup: `zero cleanup failure`
- negative status: `accepted`

## 主机与工具链

| 项目 | 复核值 |
| --- | --- |
| Mac | `Mac15,11` |
| macOS | `26.5.2 (25F84)` |
| architecture | `arm64` |
| Rosetta | `available`; `arch -x86_64 /usr/bin/true` 退出 0 |
| Rust | `rustc 1.97.1`; `cargo 1.97.1` |
| Node.js | `26.4.0` |
| npm | `11.17.0` |
| Python | `3.14.6` |
| CompatForge CLI SHA-256 | `d56362a438a242e1c046f5bed54d399f9bf604ba13341f1ea3e6f60050cf04be` |
| CompatForge desktop executable SHA-256 | `bf5382d9f2421ffb7152fb4800b0271070ff3e31fc7713b8b77d7994594a4343` |

## Runtime 与应用身份

| Runtime | source | version | pack SHA-256 |
| --- | --- | --- | --- |
| CrossOver | `crossover-interactive-derived`; GUI bootstrap `explicit-override` | `11.0-8726-g2e2f5fca349` | `c55b50fab2c701cc68dfeb3208907a065cabc28f310a18245aa00eb218c4f4cb` |
| Whisky | `whisky-interactive-derived`; GUI bootstrap `explicit-override` | `7.7` | `77ce93e14f4dcbbd291b16b1cee5f027466edf60d331ed4fec2328a33400eea2` |

| 应用 | version | installer/guest SHA-256 |
| --- | --- | --- |
| Console guest | fixed smoke fixture | `71eab53f74fbc65e9a906f94304dd6f7a3c9bcfe59a71d55cc966bfdb1815686` |
| 7-Zip | `26.01` | `d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d` |
| SumatraPDF | `3.6.1` | `719f689b34f47be8ca105ce8484948474dafde0e106bab599e4a89326070c3d0` |
| Notepad++ | `8.9.6.2` | `7c243203265ce8fdac76c839bf744ae35dcf620760eb97c2ea279af498560e45` |

## 16 路径结果

| round | Runtime | application | status |
| --- | --- | --- | --- |
| round-1 | crossover | console | accepted |
| round-1 | crossover | 7zip | accepted |
| round-1 | crossover | sumatrapdf | accepted |
| round-1 | crossover | notepad-plus-plus | accepted |
| round-1 | whisky | console | accepted |
| round-1 | whisky | 7zip | accepted |
| round-1 | whisky | sumatrapdf | accepted |
| round-1 | whisky | notepad-plus-plus | accepted |
| round-2 | crossover | console | accepted |
| round-2 | crossover | 7zip | accepted |
| round-2 | crossover | sumatrapdf | accepted |
| round-2 | crossover | notepad-plus-plus | accepted |
| round-2 | whisky | console | accepted |
| round-2 | whisky | 7zip | accepted |
| round-2 | whisky | sumatrapdf | accepted |
| round-2 | whisky | notepad-plus-plus | accepted |

两轮规范脱敏投影逐字节相等，投影 SHA-256 为
`30bb4c5415aaec13b2d69f6dca1185057fb9bcebd3d11bcbb3517911bad0c599`。
全部 GUI 结果均为 `windowAvailable: true`、`cleanup: true`；四次 Desktop
结果均为 `accepted` 且退出码为 0。

## GUI 与中文验收

- 7-Zip：两种 Runtime、两轮均完成文件列表选择和菜单交互。
- SumatraPDF：两种 Runtime、两轮的主窗口及打开对话框中文均为可读字形；固定便携安装流程记录了显式 `installerTerminationRequested: true`，应用退出与清理仍为成功。
- Notepad++：两种 Runtime、两轮均打开、编辑和保存 UTF-8 中文文件；宿主重读匹配，`cjkTextReadable: true`。
- CJK 字体仅复制并注册到每个验收 Bottle；未修改系统字体配置。

## 负向隔离

`negative-summary.json` 的脱敏 SHA-256 为
`d6b643b74b4a691d662d1574a25d86d06ef4b16f65bc6a48248bf7c06ae7481e`。

| caseId | Runtime | expected rejection | status |
| --- | --- | --- | --- |
| wine-bytes-changed | crossover | `runtime-architecture-invalid` | accepted |
| wineserver-bytes-changed | whisky | `runtime-architecture-invalid` | accepted |
| console-guest-bytes-changed | crossover | `core-inspection-refused` | accepted |
| cached-installer-bytes-changed | whisky | `cached-asset-digest-mismatch` | accepted |

四个 mutation 均未执行被篡改载荷；源 guest、固定安装器与 sentinel 保持不变，临时副本已清理。

## 本机端口与代码门禁

- `127.0.0.1:1421` 真实监听并返回 `HTTP 200`，响应为中文入口页面；验证完成后监听已停止。
- `127.0.0.1:1420` 无监听且连接失败。
- repository validator、`git diff --check`、291 项 macOS 验收聚焦测试、Rust workspace 全目标测试、Rustfmt、Clippy、前端离线安装与生产构建均通过。

## 清理与后续决定

验收结束后没有与本轮外部证据根、两个 GUI observer 或 Desktop 可执行文件关联的残留进程；1420 与 1421 均无监听。原始运行证据、应用图像、安装器和 Bottle 内容保留在仓库外，不进入 Git。

nextStage: developer-local 验收证据已完成；本地修改仍需独立代码复核、提交、推送和精确 head 的远端 CI，之后才能决定是否进入下一阶段设计。

## 闭集非声明

- `scope`: 本门禁仅为 local-only/developer-local；不是 public beta、public release 或发布门禁。
- `distribution`: 本门禁不签名、不 notarize、不生成或分发 DMG。
- `coverage`: 本门禁不证明所有 Windows 应用、主机或 Runtime 可用。
- `repositories`: 本门禁不修改也不授权修改 ForgeOS、ForgeTools 或 Mac-Win。
