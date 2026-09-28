import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./styles.css";
import "./settings.css";

type PaneId = "general" | "runtime" | "bottles" | "automation" | "diagnostics" | "accessibility" | "appearance";

interface ServiceSettings {
  schemaVersion: "1";
  automaticRuntimeDiscovery: boolean;
  launchAtLogin: boolean;
  closeToBackground: boolean;
  defaultWindowsVersion: "windows7" | "windows10" | "windows11";
  defaultGuestArchitecture: "i386" | "x86_64";
  captureScreenshots: boolean;
  retainDiagnosticsDays: number;
  maximumParallelJobs: number;
  automaticRollback: boolean;
  reducedMotion: boolean;
  compactApplicationGrid: boolean;
}

interface RuntimeSnapshot {
  runtimeReady: boolean;
  runtimeStatus: string;
  capabilities: Array<{ id: string; label: string; status: string; available: boolean }>;
  receipt?: Record<string, unknown>;
}

interface BottleSummary {
  managed: boolean;
  id: string;
  status: string;
  applicationIds: string[];
  installedLauncherCount: number;
}

interface BottleArchive {
  archiveId: string;
  bottleId: string;
  archivedAtMilliseconds: number;
}

interface JobRecord { id: string; status: string; }
interface ServiceResponse<T> { result: T; }

const panes: Array<{ id: PaneId; label: string; icon: string; hint: string }> = [
  { id: "general", label: "通用", icon: "⚙", hint: "启动与窗口" },
  { id: "runtime", label: "运行环境", icon: "◉", hint: "Wine 与 Rosetta" },
  { id: "bottles", label: "Bottle", icon: "B", hint: "存储与归档" },
  { id: "automation", label: "自动化", icon: "⌁", hint: "任务与回滚" },
  { id: "diagnostics", label: "诊断", icon: "⌘", hint: "证据与保留" },
  { id: "accessibility", label: "辅助功能", icon: "人", hint: "动效" },
  { id: "appearance", label: "外观", icon: "◐", hint: "主界面密度" },
];

const root = document.querySelector<HTMLDivElement>("#settings-app")!;
if (!root) throw new Error("missing settings root");
const currentWindow = getCurrentWindow();

let pane: PaneId = "general";
let searchText = "";
let settings: ServiceSettings | null = null;
let runtime: RuntimeSnapshot | null = null;
let bottles: BottleSummary[] = [];
let archives: BottleArchive[] = [];
let jobs: JobRecord[] = [];
let busy = false;
let errorText = "";
let sequence = 0;

function escapeHtml(value: unknown): string {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

async function api<T>(operation: string, payload: unknown = {}): Promise<T> {
  sequence += 1;
  const response = await invoke<ServiceResponse<T>>("service_call", {
    request: { schemaVersion: "1", requestId: `settings-${Date.now()}-${sequence}`, operation, payload },
  });
  return response.result;
}

function switchControl(field: keyof ServiceSettings, value: boolean): string {
  return `<button class="mac-switch ${value ? "on" : ""}" role="switch" aria-checked="${value}" data-setting="${field}"><span></span></button>`;
}

function row(title: string, description: string, control: string): string {
  return `<div class="settings-row"><div><h3>${title}</h3><p>${description}</p></div><div class="settings-control">${control}</div></div>`;
}

function generalPane(): string {
  if (!settings) return loadingCard();
  return `${paneHeader("通用", "配置应用启动与窗口行为。")}<section class="settings-card">${row("自动发现运行环境", "启动 CompatForge 时从受限候选创建 Runtime Context。", switchControl("automaticRuntimeDiscovery", settings.automaticRuntimeDiscovery))}${row("登录时打开", "登录 macOS 后打开应用管理窗口。", switchControl("launchAtLogin", settings.launchAtLogin))}${row("关闭后保留后台", "主窗口关闭时保留服务；退出应用仍会终止受管任务。", switchControl("closeToBackground", settings.closeToBackground))}</section><section class="settings-note">网络策略、路径约束与 spawn 前复验属于 Core 安全边界，无法在设置中关闭。</section>`;
}

function runtimePane(): string {
  if (!settings) return loadingCard();
  const cards = runtime?.capabilities.map((item) => `<div class="runtime-setting-card"><i class="${item.available ? "available" : ""}"></i><div><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.status)}</span></div></div>`).join("") ?? "";
  return `${paneHeader("运行环境", runtime?.runtimeStatus ?? "等待 Runtime Context")}<div class="runtime-setting-grid">${cards}</div><section class="settings-card">${row("默认 Windows 版本", "新建适配任务采用的应用兼容目标。", `<select data-select-setting="defaultWindowsVersion"><option value="windows7" ${settings.defaultWindowsVersion === "windows7" ? "selected" : ""}>Windows 7</option><option value="windows10" ${settings.defaultWindowsVersion === "windows10" ? "selected" : ""}>Windows 10</option><option value="windows11" ${settings.defaultWindowsVersion === "windows11" ? "selected" : ""}>Windows 11</option></select>`)}${row("默认 Guest 架构", "可由具体 Application 定义覆盖。", `<select data-select-setting="defaultGuestArchitecture"><option value="x86_64" ${settings.defaultGuestArchitecture === "x86_64" ? "selected" : ""}>x86_64</option><option value="i386" ${settings.defaultGuestArchitecture === "i386" ? "selected" : ""}>i386</option></select>`)}</section>`;
}

function bottlesPane(): string {
  return `${paneHeader("Bottle", "查看活动 Bottle，并管理可恢复归档。")}<section class="settings-card bottle-settings-list">${bottles.length ? bottles.map((bottle) => `<div class="settings-row"><div><h3>${escapeHtml(bottle.id)}</h3><p>${escapeHtml(bottle.applicationIds.join("、") || "未绑定应用")} · ${bottle.installedLauncherCount} 个入口${bottle.managed ? " · 托管版本，由应用统一管理" : ""}</p></div><button class="plain-button danger-text" data-archive-bottle="${escapeHtml(bottle.id)}"${bottle.managed ? ' disabled title="托管版本保留应用和恢复数据，不能直接归档"' : ""}>归档</button></div>`).join("") : '<div class="settings-empty">还没有活动 Bottle</div>'}</section><h2 class="settings-subheading">最近归档</h2><section class="settings-card">${archives.length ? archives.map((archive) => `<div class="settings-row"><div><h3>${escapeHtml(archive.bottleId)}</h3><p>${new Date(archive.archivedAtMilliseconds).toLocaleString("zh-CN")}</p></div><button class="plain-button" data-restore-archive="${escapeHtml(archive.archiveId)}">恢复</button></div>`).join("") : '<div class="settings-empty">没有可恢复归档</div>'}</section>`;
}

function automationPane(): string {
  if (!settings) return loadingCard();
  const currentSettings = settings;
  return `${paneHeader("自动化", "控制无界面调试任务的并发和失败恢复。")}<section class="settings-card">${row("最大并行任务", "同一服务进程允许同时运行的 install、launch 或试验任务。", `<select data-number-setting="maximumParallelJobs">${[1, 2, 4, 8, 16].map((value) => `<option value="${value}" ${currentSettings.maximumParallelJobs === value ? "selected" : ""}>${value}</option>`).join("")}</select>`)}${row("失败时自动回滚", "适配事务失败后优先恢复上一个已验证状态。", switchControl("automaticRollback", currentSettings.automaticRollback))}</section><section class="settings-stat"><strong>${jobs.filter((job) => !["succeeded", "failed", "cancelled"].includes(job.status)).length}</strong><span>当前活动任务</span><strong>${jobs.length}</strong><span>已持久化任务</span></section>`;
}

function diagnosticsPane(): string {
  if (!settings) return loadingCard();
  return `${paneHeader("诊断", "管理视觉证据和本地任务记录的保留策略。")}<section class="settings-card">${row("捕获兼容性截图", "视觉验收任务允许保存仓库外截图证据。", switchControl("captureScreenshots", settings.captureScreenshots))}${row("记录保留天数", "过期记录可由维护任务清理；0 表示仅当前会话。", `<input class="number-field" type="number" min="0" max="3650" value="${settings.retainDiagnosticsDays}" data-number-setting="retainDiagnosticsDays" />`)}</section>`;
}

function accessibilityPane(): string {
  if (!settings) return loadingCard();
  return `${paneHeader("辅助功能", "减少不必要的界面运动。")}<section class="settings-card">${row("减弱动态效果", "缩短主窗口卡片与状态变化动画。", switchControl("reducedMotion", settings.reducedMotion))}</section>`;
}

function appearancePane(): string {
  if (!settings) return loadingCard();
  return `${paneHeader("外观", "保持应用管理界面紧凑、清晰。")}<section class="settings-card">${row("紧凑应用网格", "减少图标内边距与应用间距，显示更多应用。", switchControl("compactApplicationGrid", settings.compactApplicationGrid))}<div class="appearance-preview"><span class="preview-icon">7z</span><span class="preview-icon pdf">PDF</span><span class="preview-icon green">N++</span><div><strong>应用程序</strong><p>设置只影响前端密度，不修改 Core 执行策略。</p></div></div></section>`;
}

function paneHeader(title: string, description: string): string {
  return `<header class="settings-pane-header"><h1>${title}</h1><p>${escapeHtml(description)}</p></header>`;
}

function loadingCard(): string { return '<section class="settings-card settings-empty">正在读取 Service API…</section>'; }

function paneContent(): string {
  if (pane === "runtime") return runtimePane();
  if (pane === "bottles") return bottlesPane();
  if (pane === "automation") return automationPane();
  if (pane === "diagnostics") return diagnosticsPane();
  if (pane === "accessibility") return accessibilityPane();
  if (pane === "appearance") return appearancePane();
  return generalPane();
}

function render(): void {
  const visiblePanes = panes.filter((item) => `${item.label} ${item.hint}`.toLowerCase().includes(searchText.toLowerCase()));
  root.innerHTML = `<div class="settings-window"><aside class="settings-sidebar"><div class="settings-drag-region"></div><label class="settings-search"><span>⌕</span><input type="search" placeholder="搜索" value="${escapeHtml(searchText)}" /></label><div class="settings-product"><span class="settings-app-icon">CF</span><div><strong>CompatForge</strong><small>API 0.12 · ABI 1</small></div></div><nav>${visiblePanes.map((item) => `<button data-pane="${item.id}" class="${pane === item.id ? "selected" : ""}"><i>${item.icon}</i><span><strong>${item.label}</strong><small>${item.hint}</small></span></button>`).join("")}</nav></aside><main class="settings-content"><div class="settings-content-drag"></div>${paneContent()}</main>${busy ? '<div class="settings-saving"><span></span>正在保存…</div>' : ""}${errorText ? `<div class="settings-error">${escapeHtml(errorText)}<button data-dismiss-error>×</button></div>` : ""}</div>`;
}

async function loadAll(): Promise<void> {
  [runtime, settings, bottles, archives, jobs] = await Promise.all([
    invoke<RuntimeSnapshot>("state_snapshot"),
    api<ServiceSettings>("settings.get"),
    api<BottleSummary[]>("bottles.list"),
    api<BottleArchive[]>("bottles.archives.list"),
    api<JobRecord[]>("jobs.list"),
  ]);
}

async function saveSettings(): Promise<void> {
  if (!settings) return;
  settings = await api<ServiceSettings>("settings.update", settings);
}

async function perform(action: () => Promise<void>): Promise<void> {
  busy = true; errorText = ""; render();
  try { await action(); } catch (error) { errorText = String(error); }
  busy = false; render();
}

root.addEventListener("mousedown", (event) => {
  const target = event.target as Element;
  if (event.button === 0 && target.closest(".settings-drag-region,.settings-content-drag") && !target.closest("button,input,select")) {
    event.preventDefault(); void currentWindow.startDragging();
  }
});

root.addEventListener("input", (event) => {
  const input = event.target as HTMLInputElement;
  if (input.closest(".settings-search")) { searchText = input.value; render(); }
});

root.addEventListener("change", async (event) => {
  if (!settings) return;
  const target = event.target as HTMLInputElement | HTMLSelectElement;
  const stringField = target.dataset.selectSetting as "defaultWindowsVersion" | "defaultGuestArchitecture" | undefined;
  const numberField = target.dataset.numberSetting as "maximumParallelJobs" | "retainDiagnosticsDays" | undefined;
  if (stringField) (settings[stringField] as string) = target.value;
  if (numberField) settings[numberField] = Number(target.value);
  if (stringField || numberField) await perform(saveSettings);
});

root.addEventListener("click", async (event) => {
  const target = (event.target as HTMLElement).closest<HTMLElement>("button,[data-pane]");
  if (!target) return;
  if (target.dataset.pane) pane = target.dataset.pane as PaneId;
  else if (target.dataset.setting && settings) { const field = target.dataset.setting as keyof ServiceSettings; (settings[field] as boolean) = !(settings[field] as boolean); await perform(saveSettings); }
  else if (target.dataset.archiveBottle) await perform(async () => { await api("bottles.archive", { id: target.dataset.archiveBottle }); await loadAll(); });
  else if (target.dataset.restoreArchive) await perform(async () => { await api("bottles.restore", { archiveId: target.dataset.restoreArchive }); await loadAll(); });
  else if (target.dataset.dismissError !== undefined) errorText = "";
  render();
});

async function start(): Promise<void> {
  render();
  try { await loadAll(); } catch (error) { errorText = String(error); }
  render();
}

void start();
