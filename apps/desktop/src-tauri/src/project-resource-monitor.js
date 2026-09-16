(() => {
  'use strict';
  if (window.top !== window || window.__projectResourceMonitor) return;
  if (!['tauri:', 'asset:'].includes(location.protocol) &&
      !['localhost', '127.0.0.1', '[::1]', 'tauri.localhost'].includes(location.hostname)) return;
  window.__projectResourceMonitor = true;
  const mount = () => {
    const host = document.createElement('div');
    host.id = 'project-resource-monitor';
    host.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:2147483000;';
    const root = host.attachShadow({ mode: 'open' });
    root.innerHTML = `<style>
      :host{font:12px/1.5 system-ui,sans-serif;color:#eef2ff;color-scheme:dark}
      button{font:inherit;color:inherit;cursor:pointer;border:1px solid #64748b;border-radius:7px;padding:5px 10px;background:#182334}
      button:focus-visible{outline:2px solid #60a5fa;outline-offset:2px}
      section{background:#182334;border:1px solid #64748b;border-radius:9px;padding:12px;margin-bottom:6px;width:250px;box-shadow:0 4px 20px #0004}
      section[hidden]{display:none}h2{font-size:13px;margin:0 0 8px}dl{margin:0;display:grid;grid-template-columns:1fr auto;gap:5px 12px}dd{margin:0;font-variant-numeric:tabular-nums}p{color:#cbd5e1;font-size:11px;margin:8px 0 0}footer{text-align:right}
    </style><section id="details" hidden><h2>应用资源消耗</h2><dl>
      <dt>CPU</dt><dd data-value="cpu">采样中</dd><dt>内存（RSS）</dt><dd data-value="memory">采样中</dd>
      <dt>磁盘读取</dt><dd data-value="read">采样中</dd><dt>磁盘写入</dt><dd data-value="write">采样中</dd>
      <dt>进程数</dt><dd data-value="count">—</dd><dt>GPU</dt><dd>不可用</dd></dl>
      <p>范围：本应用及当前子进程。CPU 按整机容量计；内存为各进程 RSS 之和，可能含共享页。GPU 尚无可靠采样源。</p><p id="status" role="status">正在采样…</p>
    </section><footer><button type="button" aria-expanded="false" aria-controls="details">资源监控</button></footer>`;
    document.body.append(host);
    const button = root.querySelector('button');
    const details = root.querySelector('section');
    const status = root.querySelector('#status');
    button.addEventListener('click', () => {
      details.hidden = !details.hidden;
      button.setAttribute('aria-expanded', String(!details.hidden));
    });
    root.addEventListener('keydown', event => {
      if (event.key === 'Escape') { details.hidden = true; button.setAttribute('aria-expanded', 'false'); button.focus(); }
    });
    const bytes = value => {
      if (!Number.isFinite(value) || value < 0) return '不可用';
      const units = ['B', 'KiB', 'MiB', 'GiB'];
      let i = 0;
      while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
      return `${value.toFixed(i ? 1 : 0)} ${units[i]}`;
    };
    const write = (key, value) => { root.querySelector(`[data-value="${key}"]`).textContent = value; };
    let timer, busy = false, stopped = false, lastSuccess = null;
    const sample = async () => {
      clearTimeout(timer);
      if (stopped || document.hidden || busy) return;
      busy = true;
      try {
        const data = await window.__TAURI_INTERNALS__.invoke('project_resource_snapshot');
        if (stopped || document.hidden) return;
        const cpu = Number.isFinite(data.cpuPercent) ? `${data.cpuPercent.toFixed(1)}%` : '采样中';
        write('cpu', cpu); write('memory', bytes(data.memoryBytes));
        write('read', data.readBytesPerSecond == null ? '采样中' : `${bytes(data.readBytesPerSecond)}/s`);
        write('write', data.writeBytesPerSecond == null ? '采样中' : `${bytes(data.writeBytesPerSecond)}/s`);
        write('count', String(data.processCount));
        lastSuccess = new Date().toLocaleTimeString();
        status.textContent = `更新于 ${lastSuccess} · 每 2 秒采样`;
        button.textContent = `CPU ${cpu} · ${bytes(data.memoryBytes)}`;
      } catch (_) {
        status.textContent = lastSuccess ? `采样失败，保留 ${lastSuccess} 的数据` : '资源监控暂不可用';
        button.textContent = '资源监控 · 暂不可用';
      } finally {
        busy = false;
        if (!stopped && !document.hidden) timer = setTimeout(sample, 2000);
      }
    };
    document.addEventListener('visibilitychange', () => {
      clearTimeout(timer);
      if (!document.hidden) sample();
    });
    window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); });
    window.addEventListener('pageshow', () => { stopped = false; sample(); });
    sample();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, { once: true });
  else mount();
})();
