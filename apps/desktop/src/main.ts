import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open } from "@tauri-apps/plugin-dialog";
import "./styles.css";

type ViewId = "applications" | "installers" | "bottles" | "jobs" | "runtime";
type FilterId = "all" | "installed" | "installable" | "running" | "recent";
type ModalState = { kind: "application"; appId: string } | { kind: "job"; jobId: string } | null;

interface CapabilityView {
  id: string;
  label: string;
  status: string;
  available: boolean;
}

interface RuntimeSnapshot {
  runtimeReady: boolean;
  runtimeStatus: string;
  smokeMode: boolean;
  capabilities: CapabilityView[];
  receipt?: Record<string, unknown>;
  error?: string;
}

interface InstallerDefinition {
  fileName: string;
  sha256?: string;
  arguments?: string[];
}

interface LauncherDefinition {
  id: string;
  name: string;
  executable: string;
  arguments?: string[];
  environment?: Record<string, string>;
}

interface ApplicationDefinition {
  schemaVersion: "1";
  id: string;
  name: string;
  version: string;
  publisher: string;
  category: string;
  bottleId: string;
  installer?: InstallerDefinition;
  launchers: LauncherDefinition[];
  compatibilityRating: string;
  tags?: string[];
}

interface ApplicationSummary {
  application: ApplicationDefinition;
  status: "installable" | "installed" | "installing" | "running" | "failed";
  installed: boolean;
  activeJobIds: string[];
  lastJobId?: string;
}

interface BottleSummary {
  id: string;
  status: "ready" | "empty" | "archived";
  applicationIds: string[];
  installedLauncherCount: number;
}

interface RuntimeEvent {
  sequence: number;
  elapsedMilliseconds: number;
  kind: string;
  processId?: number;
  exit?: { code?: number; success: boolean };
  message?: string;
}

interface JobRecord {
  id: string;
  applicationId: string;
  kind: "install" | "launch" | "compatibility-test" | "adaptation-trial";
  status: "preparing" | "running" | "cancelling" | "succeeded" | "failed" | "cancelled";
  createdAtMilliseconds: number;
  updatedAtMilliseconds: number;
  inspection?: Record<string, unknown>;
  launchPlan?: Record<string, unknown>;
  events?: RuntimeEvent[];
  error?: string;
}

interface ServiceResponse<T> {
  schemaVersion: "1";
  requestId: string;
  operation: string;
  result: T;
}

interface UiSettings {
  reducedMotion: boolean;
  compactApplicationGrid: boolean;
}

const navigation: Array<{ id: ViewId; label: string }> = [
  { id: "applications", label: "应用程序" },
  { id: "installers", label: "安装器" },
  { id: "bottles", label: "Bottle" },
  { id: "jobs", label: "运行记录" },
  { id: "runtime", label: "兼容环境" },
];

const filters: Array<{ id: FilterId; label: string }> = [
  { id: "all", label: "全部" },
  { id: "installed", label: "已安装" },
  { id: "installable", label: "可安装" },
  { id: "running", label: "运行中" },
  { id: "recent", label: "最近使用" },
];

const root = document.querySelector<HTMLDivElement>("#app")!;
if (!root) throw new Error("missing #app root");
const appWindow = getCurrentWindow();

let runtime: RuntimeSnapshot = {
  runtimeReady: false,
  runtimeStatus: "正在连接 Rust Core…",
  smokeMode: false,
  capabilities: [],
};
let applications: ApplicationSummary[] = [];
let bottles: BottleSummary[] = [];
let jobs: JobRecord[] = [];
let uiSettings: UiSettings = { reducedMotion: false, compactApplicationGrid: true };
let currentView: ViewId = "applications";
let currentFilter: FilterId = "all";
let searchText = "";
let sortDirection: "asc" | "desc" = "asc";
let modal: ModalState = null;
let menuOpen = false;
let busy = false;
let transientError = "";
let requestSequence = 0;
let maximized = false;

function maximizeIcon(): string {
  return maximized
    ? '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M6 5h10v10H6zM4 8H3v9h9v-1" /></svg>'
    : '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="4" y="4" width="12" height="12" rx="1" /></svg>';
}

function updateMaximizeButton(): void {
  const button = root.querySelector<HTMLButtonElement>('[data-action="window-toggle-maximize"]');
  if (!button) return;
  const label = maximized ? "还原" : "最大化";
  button.setAttribute("aria-label", label);
  button.title = label;
  button.innerHTML = maximizeIcon();
}

async function syncMaximizedState(): Promise<void> {
  try {
    maximized = await appWindow.isMaximized();
    updateMaximizeButton();
  } catch (error) {
    transientError = String(error);
    render();
  }
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function requestId(operation: string): string {
  requestSequence += 1;
  return `desktop-${operation.replaceAll(".", "-")}-${Date.now()}-${requestSequence}`;
}

async function api<T>(operation: string, payload: unknown = {}): Promise<T> {
  const response = await invoke<ServiceResponse<T>>("service_call", {
    request: { schemaVersion: "1", requestId: requestId(operation), operation, payload },
  });
  return response.result;
}

function isTerminal(job: JobRecord): boolean {
  return ["succeeded", "failed", "cancelled"].includes(job.status);
}

function activeJobs(): JobRecord[] {
  return jobs.filter((job) => !isTerminal(job));
}

function appForJob(job: JobRecord): ApplicationSummary | undefined {
  return applications.find((application) => application.application.id === job.applicationId);
}

function iconClass(id: string): string {
  if (id === "7zip") return "icon-sevenzip";
  if (id === "sumatrapdf") return "icon-sumatra";
  if (id === "notepad-plus-plus") return "icon-notepad";
  return "icon-generic";
}

function iconContent(application: ApplicationDefinition): string {
  if (application.id === "7zip") return "7z";
  if (application.id === "sumatrapdf") return "PDF";
  if (application.id === "notepad-plus-plus") return "N++";
  return application.name.slice(0, 2).toUpperCase();
}

function statusLabel(status: ApplicationSummary["status"]): string {
  return {
    installable: "可安装",
    installed: "已安装",
    installing: "正在安装",
    running: "运行中",
    failed: "需要处理",
  }[status];
}

function statusClass(application: ApplicationSummary): string {
  if (application.status === "running" || application.status === "installing") return "status-running";
  if (application.status === "installed") return "status-installed";
  if (application.status === "failed") return "status-error";
  return "status-installable";
}

function visibleApplications(): ApplicationSummary[] {
  const recent = new Set(jobs.slice(0, 12).map((job) => job.applicationId));
  return applications
    .filter((summary) => {
      if (currentFilter === "installed") return summary.installed;
      if (currentFilter === "installable") return !summary.installed;
      if (currentFilter === "running") return summary.activeJobIds.length > 0;
      if (currentFilter === "recent") return recent.has(summary.application.id);
      return true;
    })
    .filter((summary) => {
      const app = summary.application;
      return `${app.name} ${app.version} ${app.publisher} ${app.bottleId}`
        .toLowerCase()
        .includes(searchText.toLowerCase());
    })
    .sort((left, right) => {
      const compared = left.application.name.localeCompare(right.application.name, "zh-CN");
      return sortDirection === "asc" ? compared : -compared;
    });
}

function appTile(summary: ApplicationSummary): string {
  const app = summary.application;
  return `<button class="app-tile" data-action="open-app" data-app-id="${escapeHtml(app.id)}"
    aria-label="${escapeHtml(app.name)}，${statusLabel(summary.status)}">
    <span class="app-icon ${iconClass(app.id)}" aria-hidden="true"><span>${escapeHtml(iconContent(app))}</span></span>
    <span class="app-name">${escapeHtml(app.name)}</span>
    <span class="app-meta ${statusClass(summary)}">${summary.activeJobIds.length ? '<i class="activity-dot"></i>' : ""}${escapeHtml(app.version)} · ${statusLabel(summary.status)}</span>
  </button>`;
}

function applicationsView(): string {
  const visible = visibleApplications();
  return `<section class="library-section" aria-labelledby="my-apps-title">
    <div class="section-heading"><h2 id="my-apps-title">我的应用</h2><span></span></div>
    ${visible.length ? `<div class="app-grid">${visible.map(appTile).join("")}</div>` : '<div class="empty-state"><div class="empty-symbol">⌕</div><h3>没有符合条件的应用</h3><p>应用可由自动化 API 登记，刷新后会出现在这里。</p></div>'}
  </section>
  <section class="recent-section"><div class="section-heading"><h2>最近活动</h2><span></span></div>${recentActivity()}</section>`;
}

function recentActivity(): string {
  if (!jobs.length) return '<p class="section-placeholder">安装、启动和兼容性调试任务会显示在这里。</p>';
  return `<div class="activity-row">${jobs.slice(0, 5).map((job) => {
    const app = appForJob(job)?.application;
    return `<button class="activity-item" data-action="open-job" data-job-id="${escapeHtml(job.id)}"><span class="event-dot ${isTerminal(job) ? "event-done" : ""}"></span><span>${escapeHtml(app?.name ?? job.applicationId)} · ${jobKindLabel(job.kind)}</span><time>${jobStatusLabel(job.status)}</time></button>`;
  }).join("")}</div>`;
}

function installersView(): string {
  return `<section class="feature-page"><div class="page-intro"><div><h2>应用安装</h2><p>安装器定义来自 Application API；Core 固定校验文件名和 SHA-256。</p></div></div>
    <div class="feature-card-grid">${applications.map((summary) => {
      const app = summary.application;
      return `<article class="feature-card"><span class="mini-app-icon ${iconClass(app.id)}">${escapeHtml(iconContent(app))}</span>
        <div class="feature-card-copy"><h3>${escapeHtml(app.name)} ${escapeHtml(app.version)}</h3><p>${escapeHtml(app.installer?.fileName ?? "未配置安装器")}</p><span class="badge ${statusClass(summary)}">${statusLabel(summary.status)}</span></div>
        <button class="secondary-button" data-action="install-app" data-app-id="${escapeHtml(app.id)}" ${busy || !runtime.runtimeReady || !!activeJobs().length || !app.installer ? "disabled" : ""}>选择并安装</button></article>`;
    }).join("")}</div>
    <div class="security-note"><strong>自动化入口</strong><span>同一 jobs.submit 接口可提交 install、launch、compatibility-test 和 adaptation-trial。</span></div></section>`;
}

function bottlesView(): string {
  return `<section class="feature-page"><div class="page-intro"><div><h2>Bottle 管理</h2><p>创建、查询、可恢复归档和恢复均由 Service API 持久化。</p></div></div>
    <div class="bottle-grid">${bottles.length ? bottles.map((bottle) => `<article class="bottle-card"><div class="bottle-glyph">B</div><div><h3>${escapeHtml(bottle.id)}</h3><p>${escapeHtml(bottle.applicationIds.join("、") || "未绑定应用")} · ${bottle.installedLauncherCount} 个入口</p></div><span class="badge">${bottle.status === "ready" ? "就绪" : "空 Bottle"}</span><button class="secondary-button compact-action" data-action="archive-bottle" data-bottle-id="${escapeHtml(bottle.id)}" ${activeJobs().length ? "disabled" : ""}>归档</button></article>`).join("") : '<div class="empty-state"><h3>还没有 Bottle</h3><p>开始安装应用时将自动创建。</p></div>'}</div>
    <div class="security-note warning"><strong>安全说明</strong><span>Bottle 不是安全沙箱；相邻 DLL、插件和资源不包含在 EXE 摘要内。</span></div></section>`;
}

function jobsView(): string {
  return `<section class="feature-page event-page"><div class="page-intro"><div><h2>运行与自动化记录</h2><p>inspection、LaunchPlan、RuntimeEvent 与错误均保存在 Job 记录中。</p></div></div>
    <div class="event-table" role="table"><div class="event-table-head"><span>应用</span><span>任务</span><span>状态</span><span>事件</span><span>更新时间</span></div>
    ${jobs.length ? jobs.map((job) => `<button class="event-table-row" data-action="open-job" data-job-id="${escapeHtml(job.id)}"><span>${escapeHtml(appForJob(job)?.application.name ?? job.applicationId)}</span><span>${jobKindLabel(job.kind)}</span><span>${jobStatusLabel(job.status)}</span><span>${job.events?.length ?? 0}</span><span>${new Date(job.updatedAtMilliseconds).toLocaleTimeString("zh-CN")}</span></button>`).join("") : '<div class="empty-table">还没有任务记录</div>'}</div></section>`;
}

function runtimeView(): string {
  return `<section class="feature-page"><div class="page-intro"><div><h2>兼容环境</h2><p>${escapeHtml(runtime.runtimeStatus)}</p></div><button class="primary-button" data-action="bootstrap" ${busy || activeJobs().length ? "disabled" : ""}>重新发现 Runtime</button></div>
    <div class="capability-grid">${runtime.capabilities.map((capability) => `<article class="capability-card"><span class="capability-icon"></span><div><h3>${escapeHtml(capability.label)}</h3><p>${escapeHtml(capability.status)}</p></div><i class="availability ${capability.available ? "available" : ""}"></i></article>`).join("")}</div>
    <div class="receipt-card"><h3>Bootstrap Receipt</h3><pre>${escapeHtml(runtime.receipt ? JSON.stringify(runtime.receipt, null, 2) : "尚未生成")}</pre></div></section>`;
}

function viewContent(): string {
  if (currentView === "installers") return installersView();
  if (currentView === "bottles") return bottlesView();
  if (currentView === "jobs") return jobsView();
  if (currentView === "runtime") return runtimeView();
  return applicationsView();
}

function modalContent(): string {
  const currentModal = modal;
  if (!currentModal) return "";
  if (currentModal.kind === "job") {
    const job = jobs.find((candidate) => candidate.id === currentModal.jobId);
    if (!job) return "";
    return `<div class="modal-backdrop" data-action="close-modal"><section class="modal-panel prepared-modal" data-modal-panel role="dialog" aria-modal="true"><header><div><span class="eyebrow">${escapeHtml(job.id)}</span><h2>${jobKindLabel(job.kind)} · ${jobStatusLabel(job.status)}</h2></div><button class="icon-button" data-action="close-modal">×</button></header>
      <div class="prepared-columns"><div><h3>PE Inspection</h3><pre>${escapeHtml(job.inspection ? JSON.stringify(job.inspection, null, 2) : "—")}</pre></div><div><h3>LaunchPlan</h3><pre>${escapeHtml(job.launchPlan ? JSON.stringify(job.launchPlan, null, 2) : job.error ?? "—")}</pre></div></div>
      <footer><button class="secondary-button" data-action="close-modal">关闭</button>${!isTerminal(job) ? `<button class="danger-button" data-action="cancel-job" data-job-id="${escapeHtml(job.id)}">终止任务</button>` : ""}</footer></section></div>`;
  }
  const summary = applications.find((candidate) => candidate.application.id === currentModal.appId);
  if (!summary) return "";
  const app = summary.application;
  const primary = summary.activeJobIds.length
    ? `<button class="danger-button" data-action="cancel-job" data-job-id="${escapeHtml(summary.activeJobIds[0])}">终止</button>`
    : summary.installed
      ? `<button class="primary-button" data-action="launch-app" data-app-id="${escapeHtml(app.id)}" ${busy ? "disabled" : ""}>启动</button>`
      : `<button class="primary-button" data-action="install-app" data-app-id="${escapeHtml(app.id)}" ${busy || !app.installer ? "disabled" : ""}>选择安装器</button>`;
  return `<div class="modal-backdrop" data-action="close-modal"><section class="modal-panel app-modal" data-modal-panel role="dialog" aria-modal="true"><header><div class="modal-app-heading"><span class="mini-app-icon ${iconClass(app.id)}">${escapeHtml(iconContent(app))}</span><div><span class="eyebrow">${escapeHtml(app.bottleId)}</span><h2>${escapeHtml(app.name)}</h2><p>${escapeHtml(app.publisher)} · ${escapeHtml(app.version)}</p></div></div><button class="icon-button" data-action="close-modal">×</button></header>
    <dl class="detail-list"><div><dt>启动入口</dt><dd>${escapeHtml(app.launchers[0]?.executable ?? "—")}</dd></div><div><dt>兼容等级</dt><dd>${escapeHtml(app.compatibilityRating)}</dd></div><div><dt>启动模式</dt><dd>${summary.installed ? "bottleInPlace" : "immutableArtifact"}</dd></div><div><dt>当前状态</dt><dd>${statusLabel(summary.status)}</dd></div></dl><footer><button class="secondary-button" data-action="close-modal">关闭</button>${primary}</footer></section></div>`;
}

function render(): void {
  const active = activeJobs();
  root.innerHTML = `<div class="window-shell"><header class="titlebar"><div class="brand"><span class="brand-mark" aria-hidden="true"><i></i></span><h1>${navigation.find((item) => item.id === currentView)?.label}</h1></div>
    <button class="runtime-pill ${runtime.runtimeReady ? "ready" : ""}" data-action="go-runtime"><i></i><span>${runtime.runtimeReady ? "运行环境就绪" : "等待运行环境"}</span></button><div class="titlebar-spacer"></div>
    <label class="search-box"><span></span><input id="app-search" type="search" value="${escapeHtml(searchText)}" placeholder="搜索应用" /></label>
    <button class="toolbar-button" data-action="refresh" aria-label="刷新">↻</button><div class="menu-anchor"><button class="toolbar-button menu-button" data-action="toggle-menu">•••</button>${menuOpen ? `<div class="popover-menu"><button data-action="open-settings">设置…</button><button data-action="go-runtime">兼容环境</button><button data-action="go-jobs">自动化记录</button><hr><button data-action="cancel-all" ${active.length ? "" : "disabled"}>终止所有任务</button></div>` : ""}</div>
    <div class="window-controls" role="group" aria-label="窗口控制"><button type="button" class="window-control" data-action="window-minimize" aria-label="最小化" title="最小化"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10h12" /></svg></button><button type="button" class="window-control" data-action="window-toggle-maximize" aria-label="${maximized ? "还原" : "最大化"}" title="${maximized ? "还原" : "最大化"}">${maximizeIcon()}</button><button type="button" class="window-control close" data-action="window-close" aria-label="关闭" title="关闭"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m5 5 10 10M15 5 5 15" /></svg></button></div></header>
    <nav class="primary-nav">${navigation.map((item) => `<button data-action="navigate" data-view="${item.id}" class="${currentView === item.id ? "selected" : ""}">${item.label}</button>`).join("")}</nav>
    ${currentView === "applications" ? `<div class="filter-bar"><div class="filters">${filters.map((filter) => `<button data-action="filter" data-filter="${filter.id}" class="${currentFilter === filter.id ? "selected" : ""}">${filter.label}</button>`).join("")}</div><button class="sort-button" data-action="sort">名称 <span>${sortDirection === "asc" ? "⌃" : "⌄"}</span></button></div>` : `<div class="context-strip">${escapeHtml(runtime.runtimeStatus)}</div>`}
    <main id="main-content">${viewContent()}</main><footer class="status-bar"><span><i class="${active.length ? "running" : ""}"></i>${applications.length} 个应用 · ${active.length} 个活动任务</span><div><button data-action="refresh">↻&nbsp; 刷新 API</button><span class="footer-divider"></span><button class="terminate-link" data-action="cancel-all" ${active.length ? "" : "disabled"}>⊙&nbsp; 全部终止</button></div></footer>
    ${busy ? '<div class="busy-indicator"><span></span><em>正在处理…</em></div>' : ""}${transientError || runtime.error ? `<div class="error-toast"><div><strong>操作未完成</strong><p>${escapeHtml(transientError || runtime.error)}</p></div><button data-action="dismiss-error">×</button></div>` : ""}${modalContent()}</div>`;
}

function jobKindLabel(kind: JobRecord["kind"]): string {
  return { install: "安装", launch: "启动", "compatibility-test": "兼容性测试", "adaptation-trial": "适配试验" }[kind];
}

function jobStatusLabel(status: JobRecord["status"]): string {
  return { preparing: "准备中", running: "运行中", cancelling: "终止中", succeeded: "已完成", failed: "失败", cancelled: "已终止" }[status];
}

function isTitlebarDragTarget(target: EventTarget | null): boolean {
  return target instanceof Element && !!target.closest(".titlebar") && !target.closest("button,input,label,a,select,textarea,[data-no-drag]");
}

async function refreshData(): Promise<void> {
  if (!runtime.runtimeReady) return;
  [applications, bottles, jobs, uiSettings] = await Promise.all([
    api<ApplicationSummary[]>("applications.list"),
    api<BottleSummary[]>("bottles.list"),
    api<JobRecord[]>("jobs.list"),
    api<UiSettings>("settings.get"),
  ]);
  document.documentElement.classList.toggle("reduced-motion", uiSettings.reducedMotion);
  document.documentElement.classList.toggle("compact-grid", uiSettings.compactApplicationGrid);
}

async function perform(action: () => Promise<void>): Promise<void> {
  busy = true;
  transientError = "";
  render();
  try {
    await action();
  } catch (error) {
    transientError = String(error);
  } finally {
    busy = false;
    render();
  }
}

async function bootstrap(): Promise<void> {
  runtime = await invoke<RuntimeSnapshot>("bootstrap_runtime");
  await refreshData();
}

async function chooseExecutable(): Promise<string | null> {
  const selected = await open({ multiple: false, directory: false, filters: [{ name: "Windows 可执行文件", extensions: ["exe"] }] });
  return typeof selected === "string" ? selected : null;
}

async function submitJob(appId: string, kind: JobRecord["kind"], executablePath?: string): Promise<void> {
  await api<JobRecord>("jobs.submit", { schemaVersion: "1", applicationId: appId, kind, ...(executablePath ? { executablePath } : {}) });
  modal = null;
  await refreshData();
}

root.addEventListener("input", (event) => {
  const input = event.target as HTMLInputElement;
  if (input.id === "app-search") { searchText = input.value; const main = document.querySelector<HTMLElement>("#main-content"); if (main) main.innerHTML = applicationsView(); }
});

root.addEventListener("mousedown", (event) => {
  if (event.button !== 0 || !isTitlebarDragTarget(event.target)) return;
  event.preventDefault();
  void appWindow.startDragging();
});

root.addEventListener("click", async (event) => {
  const target = (event.target as HTMLElement).closest<HTMLElement>("[data-action]");
  if (!target || target.hasAttribute("disabled")) return;
  const action = target.dataset.action;
  if (action === "window-minimize" || action === "window-toggle-maximize" || action === "window-close") {
    try {
      if (action === "window-minimize") await appWindow.minimize();
      else if (action === "window-toggle-maximize") {
        await appWindow.toggleMaximize();
        await syncMaximizedState();
      } else await appWindow.close();
    } catch (error) {
      transientError = String(error);
      render();
    }
    return;
  }
  if (action === "navigate") currentView = (target.dataset.view ?? "applications") as ViewId;
  else if (action === "filter") currentFilter = (target.dataset.filter ?? "all") as FilterId;
  else if (action === "sort") sortDirection = sortDirection === "asc" ? "desc" : "asc";
  else if (action === "toggle-menu") menuOpen = !menuOpen;
  else if (action === "go-runtime") { currentView = "runtime"; menuOpen = false; }
  else if (action === "go-jobs") { currentView = "jobs"; menuOpen = false; }
  else if (action === "open-settings") { menuOpen = false; await perform(async () => invoke("open_settings")); }
  else if (action === "refresh") await perform(refreshData);
  else if (action === "bootstrap") await perform(bootstrap);
  else if (action === "open-app") modal = { kind: "application", appId: target.dataset.appId ?? "" };
  else if (action === "open-job") modal = { kind: "job", jobId: target.dataset.jobId ?? "" };
  else if (action === "install-app") { const path = await chooseExecutable(); if (path) await perform(() => submitJob(target.dataset.appId ?? "", "install", path)); }
  else if (action === "launch-app") await perform(() => submitJob(target.dataset.appId ?? "", "launch"));
  else if (action === "cancel-job") await perform(async () => { await api("jobs.cancel", { id: target.dataset.jobId }); await refreshData(); });
  else if (action === "cancel-all") await perform(async () => { for (const job of activeJobs()) await api("jobs.cancel", { id: job.id }); await refreshData(); });
  else if (action === "archive-bottle") await perform(async () => { await api("bottles.archive", { id: target.dataset.bottleId }); await refreshData(); });
  else if (action === "close-modal") modal = null;
  else if (action === "dismiss-error") { transientError = ""; runtime = await invoke("clear_error"); }
  render();
});

async function start(): Promise<void> {
  render();
  void appWindow.onResized(() => { void syncMaximizedState(); });
  await syncMaximizedState();
  try {
    runtime = await invoke<RuntimeSnapshot>("state_snapshot");
    if (!runtime.smokeMode) await bootstrap();
  } catch (error) {
    transientError = String(error);
  }
  render();
  window.setInterval(async () => {
    const active = activeJobs();
    if (!active.length || busy) return;
    try {
      for (const job of active) await api("jobs.poll", { id: job.id, timeoutMilliseconds: 0 });
      await refreshData();
      render();
    } catch (error) {
      transientError = String(error);
      render();
    }
  }, 300);
}

void start();
