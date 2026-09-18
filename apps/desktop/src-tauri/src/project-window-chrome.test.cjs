const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
const sandbox = { module: { exports: {} } };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'project-window-chrome.js'), 'utf8'), sandbox);
const { dragRegion, canResize, cornerRadius, install } = sandbox.module.exports;

class Target {
  listeners = new Map();
  addEventListener(name, fn) { const list = this.listeners.get(name) || []; list.push(fn); this.listeners.set(name, list); }
  removeEventListener(name, fn) { this.listeners.set(name, (this.listeners.get(name) || []).filter(v => v !== fn)); }
  dispatchEvent(event) { for (const fn of this.listeners.get(event.type) || []) { fn(event); if (event.stopped) break; } }
}
class Element extends Target {
  attrs = new Map(); children = []; hidden = false;
  style = { setProperty(key, value) { this[key] = value; }, getPropertyValue(key) { return this[key] || ''; }, getPropertyPriority() { return ''; }, removeProperty(key) { delete this[key]; } };
  constructor(value, clickable = false) { super(); if (value != null) this.attrs.set('data-tauri-drag-region', value); this.clickable = clickable; }
  getAttribute(key) { return this.attrs.get(key) ?? null; }
  setAttribute(key, value) { this.attrs.set(key, value); }
  removeAttribute(key) { this.attrs.delete(key); }
  matches() { return this.clickable; }
  appendChild(child) { this.children.push(child); }
  attachShadow() { this.shadow = new Element(); return this.shadow; }
  remove() { this.removed = true; }
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture({ macos = false, decorated = false, resizable = true, maximized = false, fullscreen = false, reject = false } = {}) {
  const win = new Target(), doc = new Target(), calls = [];
  const state = { decorated, resizable, maximized, fullscreen, focused: true, maximizable: true };
  Object.assign(win, {
    top: win, location: { protocol: 'tauri:', hostname: 'localhost' },
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options?.detail; } },
    requestAnimationFrame: fn => setImmediate(fn), cancelAnimationFrame: clearImmediate,
    __TAURI_INTERNALS__: { invoke: async (command, args) => {
      calls.push({ command: command.split('|')[1], args });
      if (reject) throw new Error('permission denied');
      return state[command.split('|')[1].replace('is_', '')];
    } }
  });
  Object.assign(doc, { readyState: 'complete', documentElement: new Element(), createElement: () => new Element() });
  const controller = install(win, doc, macos);
  function event(type, path, extra = {}) {
    const e = { type, button: 0, detail: 1, pointerType: 'mouse', clientX: 40, clientY: 20, composedPath: () => path,
      preventDefault() { this.prevented = true; }, stopImmediatePropagation() { this.stopped = true; }, ...extra };
    win.dispatchEvent(e); return e;
  }
  const actions = () => calls.filter(c => !c.command.startsWith('is_'));
  return { win, doc, calls, state, controller, event, actions };
}
test('deep regions accept passive descendants; self regions require direct hits', () => {
  const text = new Element();
  assert.equal(dragRegion([text, new Element('deep')]), true);
  assert.equal(dragRegion([text, new Element('')]), false);
  assert.equal(dragRegion([new Element('true')]), true);
});
test('interactive elements, shadow paths and explicit opt-out block drag', () => {
  assert.equal(dragRegion([new Element(null, true), new Element('deep')]), false);
  assert.equal(dragRegion([new Element('deep', true)]), false);
  assert.equal(dragRegion([new Element(), new Element('false'), new Element('deep')]), false);
  assert.equal(dragRegion([{}, new Element(null, true), new Element('deep')]), false);
});
test('resize is disabled for native, fixed, maximized and fullscreen windows', () => {
  const base = { decorated: false, resizable: true, maximized: false, fullscreen: false };
  assert.equal(canResize(base), true);
  for (const change of [{ decorated: true }, { resizable: false }, { maximized: true }, { fullscreen: true }]) assert.equal(canResize({ ...base, ...change }), false);
  assert.equal(canResize(null), false);
});
test('rounded content matches desktop radius and becomes square when filling the screen', () => {
  assert.equal(cornerRadius({ decorated: false }, false), 8);
  assert.equal(cornerRadius({ decorated: false }, true), 10);
  for (const state of [{ decorated: true }, { maximized: true }, { fullscreen: true }, null]) assert.equal(cornerRadius(state, false), 0);
});
test('corner clipping follows maximize/restore and cleans up after disposal', async () => {
  const f = fixture(); await tick(); const style = f.doc.documentElement.style;
  assert.equal(style['clip-path'], 'inset(0 round 8px)');
  f.state.maximized = true; f.controller.refresh(); await tick(); await tick();
  assert.equal(style['clip-path'], 'inset(0 round 0px)');
  f.state.maximized = false; f.controller.refresh(); await tick(); await tick();
  assert.equal(style['border-radius'], '8px');
  f.controller.destroy(); assert.equal(style['clip-path'], undefined);
});
test('one drag and one maximize per gesture despite pointer/mouse/dblclick listeners', async () => {
  const f = fixture(); await tick(); const path = [new Element('deep')];
  const pointer = f.event('pointerdown', path);
  assert.equal(pointer.stopped, true); assert.equal(pointer.prevented, undefined);
  f.event('mousedown', path);
  f.event('mousedown', path, { detail: 2 });
  f.event('dblclick', path, { detail: 2 });
  assert.deepEqual(f.actions().map(c => c.command), ['start_dragging', 'internal_toggle_maximize']);
  f.controller.destroy();
});
test('macOS double click waits for mouseup and cancels when the pointer moves', async () => {
  const f = fixture({ macos: true }); await tick(); const path = [new Element('deep')];
  f.event('mousedown', path, { detail: 2 }); assert.equal(f.actions().length, 0);
  f.event('mouseup', path, { detail: 2, clientX: 42 }); assert.equal(f.actions().length, 0);
  f.event('mousedown', path, { detail: 2 }); f.event('mouseup', path, { detail: 2 });
  assert.equal(f.actions()[0].command, 'internal_toggle_maximize'); f.controller.destroy();
});
test('right clicks, controls, decorated and fullscreen windows preserve application events', async () => {
  for (const options of [{ decorated: true }, { fullscreen: true }, {}]) {
    const f = fixture(options); await tick();
    const path = [new Element(options.decorated || options.fullscreen ? 'deep' : null, !options.decorated && !options.fullscreen), new Element('deep')];
    assert.equal(f.event('mousedown', path).stopped, undefined);
    assert.equal(f.event('mousedown', [new Element('deep')], { button: 2 }).stopped, undefined);
    assert.equal(f.actions().length, 0); f.controller.destroy();
  }
});
test('eight resize edges call native directions and hide after maximizing', async () => {
  const f = fixture(); await tick(); const edges = f.doc.documentElement.children[0];
  assert.equal(edges.style.display, 'block');
  const handles = edges.shadow.children; assert.equal(handles.length, 8);
  for (const handle of handles) handle.dispatchEvent({ type: 'pointerdown', button: 0, preventDefault() {}, stopImmediatePropagation() {} });
  assert.deepEqual(f.actions().map(c => c.args.direction), ['North', 'NorthEast', 'East', 'SouthEast', 'South', 'SouthWest', 'West', 'NorthWest']);
  f.state.maximized = true; f.controller.refresh(); await tick(); await tick();
  assert.equal(edges.style.display, 'none'); f.controller.destroy();
});
test('errors leave native handlers usable and never create active resize edges', async () => {
  const f = fixture({ reject: true }); await tick();
  assert.equal(f.event('mousedown', [new Element('deep')]).stopped, undefined);
  assert.equal(f.doc.documentElement.children[0].style.display, 'none'); f.controller.destroy();
});
test('dispose before asynchronous state reads finish removes listeners and ignores late results', async () => {
  const f = fixture(); f.controller.destroy(); await tick();
  assert.equal(f.doc.documentElement.attrs.size, 0);
  assert.equal(f.doc.documentElement.children[0].removed, true);
  assert.equal([...f.win.listeners.values()].flat().length, 0);
  assert.equal(f.win.__projectWindowChrome, undefined);
});
test('installation is idempotent and rejects remote documents and subframes', () => {
  const f = fixture(); assert.equal(install(f.win, f.doc, false), undefined); f.controller.destroy();
  f.win.location = { protocol: 'https:', hostname: 'example.com' }; assert.equal(install(f.win, f.doc, false), undefined);
  f.win.location.hostname = 'localhost'; f.win.top = {}; assert.equal(install(f.win, f.doc, false), undefined);
});
