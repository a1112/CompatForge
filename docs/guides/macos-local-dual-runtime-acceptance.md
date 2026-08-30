# Apple Silicon 双 Runtime 本地验收

本指南只用于 CompatForge 的 **developer-local** 阶段验收。它要求同一台 Apple Silicon Mac 上的 CrossOver 与 Whisky 分别完成 Console、7-Zip、SumatraPDF、Notepad++，并完整重复两轮。它不是 public beta，不包含签名、notarize、DMG 或发布，不证明所有 Windows 应用兼容，也不修改 ForgeOS、ForgeTools 或 Mac-Win。

## 1. 前置检查

开始前应满足以下全部条件；任何一项不满足都记为 `blocked/environment`，不要降低门禁：

- 主机是 Apple Silicon `arm64`，外部磁盘有足够空间容纳四组隔离根、两个 Runtime 的临时 Bottle、安装器和证据；
- Rosetta 已安装并可执行 x86_64 程序；安装 Rosetta 是需要操作者明确同意许可的系统变更；
- CrossOver 与 Whisky 均已安装在发现器的固定候选位置并可被验证，验收不搜索 `PATH`；
- 使用 Python 3.11+，后续所有 Python 命令都使用同一个明确的 `python3 -S -B` 解释器；
- 明确提供可执行的 MinGW cross compiler，例如 `/absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc`；
- Rust stable、`aarch64-apple-darwin` target、Cargo 与 Tauri 2 构建依赖已就绪；
- Node.js 24、npm 与 Vite 依赖已就绪；
- CompatForge CLI 与 Tauri `.app` 已从当前提交构建完成；
- 默认禁用网络。依赖安装和 Runtime 安装不属于这次验收；固定 GUI 资产只有在单独的显式 opt-in 阶段才可联网。

检查主机、解释器、Rosetta、工具链与磁盘：

```text
uname -m
python3 -S -B -c 'import platform,sys; print(sys.executable); print(sys.version); assert sys.version_info >= (3,11); assert platform.machine() == "arm64"'
arch -x86_64 /usr/bin/true
test -x /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc
rustc --version
rustup target list --installed
node --version
npm --version
df -h /absolute/external
```

若 `arch -x86_64 /usr/bin/true` 失败，在了解许可与系统影响后，由操作者单独执行以下系统命令，然后重新检查；不要让验收脚本自行安装 Rosetta：

```text
sudo /usr/sbin/softwareupdate --install-rosetta --agree-to-license
```

## 2. 外部根与清理边界

以下六类输入必须是绝对路径，位于 CompatForge 仓库和整个 FOS sibling 树之外，彼此不重叠，任何祖先或叶子都不得是 symlink/reparse point：

- `cache-root`：资产准备前不存在或为空；标准编排时只保存固定 URL 与 SHA-256 通过校验的三个安装器；
- `runtime-store-root`、`storage-root`、`work-root`：开始时不存在或为空；
- `interaction-plan-root`：只读，只能含 `round-1|round-2` × `crossover|whisky` 四个规范 JSON 计划；计划仅列出 required checks，不能含观察结果或 boolean；
- `acknowledgement-root`：开始时只含空的 `challenges` 与 `receipts` 子目录；第二终端 helper 和编排器共同绑定其 identity，不能复用旧根；
- CLI、Tauri 可执行文件、MinGW、Console guest 与 negative sentinel 也使用明确的绝对路径，且不与上述根重叠。

工具会在 `round/runtime/console|gui|desktop` 下隔离写入。只允许清理工具创建并重新校验 identity 的叶子；禁止 `rm -rf` 广泛目录、未解析变量、仓库根、FOS 根或任一 Runtime 安装。重新运行必须选择新的空 `runtime-store-root`、`storage-root` 和 `work-root`，不要复用失败根。

Screenshots、安装器、Bottle、Runtime 内容、`summary.json`、projection、绝对路径或其他原始证据都不得提交 Git；阶段报告只能采用复核后的脱敏投影。

## 3. 先构建与运行离线门禁

先在当前提交运行代码门禁并构建 CLI/Tauri；失败时停止，不进入 Runtime 验收：

```text
python3 -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v
python3 -S -B scripts/validate_repository.py
cargo fmt --all -- --check
cargo test --offline --workspace --all-targets --locked
npm ci --offline --prefix apps/desktop
npm run build --prefix apps/desktop
cargo build --offline --release --locked -p compatforge-cli
CARGO_NET_OFFLINE=true npm run tauri --prefix apps/desktop -- build --bundles app
```

将本次构建出的 CLI 与 `CompatForge.app/Contents/MacOS/CompatForge` 放到或引用为明确的只读路径。构建步骤需要的依赖应在验收开始前准备；验收阶段默认不授权任意网络下载。

## 4. 发现一次双 Runtime

从仓库根只执行一次无网络发现预检：

```text
python3 -S -B tools/discover_macos_wine.py --all
```

输出必须是 `schemaVersion: "1"`，严格包含按 `crossover`、`whisky` 排列的两个已验证 Runtime。少一个、顺序或身份异常都停止；不要用环境变量或额外 CLI flag 绕过发现。

## 5. 显式 opt-in 获取固定资产

先离线查看固定资产清单：

```text
python3 -S -B tools/download_gui_assets.py list --cache-root /absolute/external/cache
```

只有操作者明确批准本阶段联网时，才逐个执行以下固定 app id。下载器内部固定 URL、大小上限和 SHA-256；不要用 `curl`、浏览器或任意 URL 替代：

```text
python3 -S -B tools/download_gui_assets.py fetch 7zip --cache-root /absolute/external/cache --allow-network
python3 -S -B tools/download_gui_assets.py fetch sumatrapdf --cache-root /absolute/external/cache --allow-network
python3 -S -B tools/download_gui_assets.py fetch notepad-plus-plus --cache-root /absolute/external/cache --allow-network
```

三个固定资产获取完成后必须关闭网络。双轮编排及其余所有阶段都不得使用或追加 `--allow-network`。

## 6. 独立准备交互确认

[交互计划模板](../../examples/macos-dual-runtime-interactions.json)包含四条独立记录。每条 `document` 都是运行器实际接受的 `schemaVersion: "1"` 计划，需以规范紧凑 JSON 加换行分别写到其相对 `planPath`。同时新建 acknowledgement 根及其两个空子目录：

```text
/absolute/external/interactions/round-1/crossover.json
/absolute/external/interactions/round-1/whisky.json
/absolute/external/interactions/round-2/crossover.json
/absolute/external/interactions/round-2/whisky.json
```

从仓库根用已通过 validator 的模板生成四份规范计划，并创建全新的空 acknowledgement 子目录：

```text
python3 -S -B -c 'import json,pathlib; source=json.loads(pathlib.Path("examples/macos-dual-runtime-interactions.json").read_text(encoding="utf-8")); root=pathlib.Path("/absolute/external/interactions"); [(root / record["planPath"]).parent.mkdir(parents=True,exist_ok=True) or (root / record["planPath"]).write_text(json.dumps(record["document"],ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8",newline="\n") for record in source["records"]]'
mkdir -p /absolute/external/acknowledgements/challenges /absolute/external/acknowledgements/receipts
```

计划中没有 `true`/`false`、nonce、challenge digest 或任何观察结论，因此预填计划不能产生 `accepted`。准备 `/absolute/external/acknowledgements/challenges` 与 `/absolute/external/acknowledgements/receipts` 两个空目录后，在第二终端只启动一次 watch helper；它会按固定顺序等待全部 12 个 GUI challenge：

```text
python3 -S -B tools/confirm_macos_gui_interactions.py \
  --interaction-plan-root /absolute/external/interactions \
  --acknowledgement-root /absolute/external/acknowledgements
```

helper 出现 challenge 后，才在已显示的应用窗口执行对应动作：7-Zip 的 `fileList`/`menus`；SumatraPDF 的 `mainWindow`/`openDialog`；Notepad++ 的 `open`/`edit`/`saveUtf8Chinese`/`cjkTextReadable`/`rereadMatches`。其中 `cjkTextReadable` 必须依据应用内中文实际显示为可读字形（不是方框）确认；每完成一项立即在第二终端确认，不要提前确认、批量确认或在应用关闭后凭记忆确认。否定回答或超时保持 `unverified`，错误 identity、digest、nonce、重复/跨轮 receipt 或 unsafe entry 为 `failed`。Console 由无头 runner 自动验证，不需要人工 receipt。

## 7. 执行两轮矩阵

使用全部必需参数执行标准离线编排；所有占位符都替换为本机绝对路径：

```text
python3 -S -B tools/run_macos_dual_runtime_acceptance.py \
  --compatforge-cli /absolute/external/build/compatforge-cli \
  --desktop-app /absolute/external/build/CompatForge.app/Contents/MacOS/CompatForge \
  --cc /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc \
  --cache-root /absolute/external/cache \
  --runtime-store-root /absolute/external/runtime-store \
  --storage-root /absolute/external/storage \
  --work-root /absolute/external/evidence \
  --interaction-plan-root /absolute/external/interactions \
  --acknowledgement-root /absolute/external/acknowledgements
```

保持编排器离线，不启用网络参数。编排器会再绑定所发现 Runtime、四份 plan 与 acknowledgement 根的 identity，依次运行每个 `round/runtime` 的 Console、GUI 和 Desktop，并打印精确 Tauri 命令。GUI runner 只有在观察到应用窗口后才发布 challenge；完成对应交互并立即确认。桌面壳必须人工正常关闭并确认进程树已清理，才允许继续下一个组合。watch helper 只启动这一次，直到写出 12 receipts 后退出。

失败必须归入闭集 `environment|runtime|core|desktop|application|cleanup`，状态只能是 `accepted|failed|unverified|blocked`。修复环境或代码后使用全新的空输出根重跑整个两轮矩阵，不在旧证据上续跑。

## 8. 负向隔离检查

正常矩阵通过后，用新的空输出根、已缓存的固定 7-Zip 安装器、独立 Console guest 和 sentinel 运行负向检查；另为 `/absolute/external/negative/acknowledgements` 准备空的 `challenges` 与 `receipts` 子目录。该模式始终离线：

```text
python3 -S -B tools/run_macos_dual_runtime_acceptance.py \
  --compatforge-cli /absolute/external/build/compatforge-cli \
  --desktop-app /absolute/external/build/CompatForge.app/Contents/MacOS/CompatForge \
  --cc /absolute/external/toolchains/bin/x86_64-w64-mingw32-gcc \
  --cache-root /absolute/external/cache \
  --runtime-store-root /absolute/external/negative/runtime-store \
  --storage-root /absolute/external/negative/storage \
  --work-root /absolute/external/negative/evidence \
  --interaction-plan-root /absolute/external/interactions \
  --acknowledgement-root /absolute/external/negative/acknowledgements \
  --negative-checks \
  --console-guest /absolute/external/inputs/windows-console-smoke.exe \
  --negative-sentinel /absolute/external/inputs/negative-sentinel.txt
```

`negative-summary.json` 的 `accepted` 表示四个受控 mutation 均按预期被拒绝、源文件与 sentinel 未变且临时副本已清理；它不表示应用兼容。

## 9. 精确退出门禁

仅当以下条件同时成立，当前 developer-local 阶段才完成：

- `2 runtimes × (console + 3 GUI) × 2 rounds = 16 paths` 全部为 `accepted`：其中必须有 12 receipts 与 4 Console 自动结果；
- `round-1/round-projection.json` 与 `round-2/round-projection.json` 的规范脱敏字节相等，`comparison.json` 为 `roundsEqual: true` 且 `status: accepted`；
- 16 条路径达到 zero cleanup failure，三个 GUI 应用的 `cleanup` 全为 `true`，Desktop 正常退出；
- 没有任何 `unverified`、`blocked` 或 `failed`；
- `negative-summary.json` 的四个 mutation 均为预期拒绝且总状态为 `accepted`；
- 原始证据、Screenshots、安装器、Bottle、Runtime 和绝对路径留在仓库外，只将审核后的脱敏阶段报告用于交接。

这仍然不是 public beta，也不是签名/notarize/DMG/发布门禁；它不证明其他 Windows 应用或其他主机可用，不授权修改 ForgeOS、ForgeTools 或 Mac-Win。

## 10. 闭集非声明

阶段报告必须保留以下四条原文，不得用更强的发布或跨仓声明替换：

- `scope`: 本门禁仅为 local-only/developer-local；不是 public beta、public release 或发布门禁。
- `distribution`: 本门禁不签名、不 notarize、不生成或分发 DMG。
- `coverage`: 本门禁不证明所有 Windows 应用、主机或 Runtime 可用。
- `repositories`: 本门禁不修改也不授权修改 ForgeOS、ForgeTools 或 Mac-Win。
