const { test, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { stripTypeScriptTypes } = require('node:module');

const sourcePath = path.join(__dirname, '../src/main.ts');
const source = fs.readFileSync(sourcePath, 'utf8');
const imports = source.match(/^import .*;$/gm);
assert.deepEqual(imports, [
  'import { invoke } from "@tauri-apps/api/core";',
  'import { getCurrentWindow } from "@tauri-apps/api/window";',
  'import { open } from "@tauri-apps/plugin-dialog";',
  'import "./styles.css";',
]);
// Execute the complete entrypoint with only its four imports replaced by mocks.
const code = stripTypeScriptTypes(source.replace(/^import .*;$/gm, ''), { mode: 'strip' });
const tick = () => new Promise(resolve => setImmediate(resolve));
const fixtures = new Set();

function deferred() {
  let resolve;
  const promise = new Promise(complete => { resolve = complete; });
  return { promise, resolve };
}

function job(id, status = 'running') {
  return {
    id, applicationId: 'synthetic-app', kind: 'launch', status,
    createdAtMilliseconds: 0, updatedAtMilliseconds: 0, events: [],
  };
}

async function fixture(initialJobs = [job('one')]) {
  const state = { jobs: initialJobs };
  const handlers = {};
  const calls = [];
  const errors = [];
  const listeners = new Map();
  const classes = new Map();
  const root = {
    innerHTML: '',
    querySelector: () => null,
    addEventListener(name, listener) { listeners.set(name, listener); },
  };
  const timers = new Map();
  let now = 0;
  let nextTimer = 0;
  const clock = {
    setInterval(callback, milliseconds) {
      const id = ++nextTimer;
      timers.set(id, { callback, milliseconds, due: now + milliseconds });
      return id;
    },
    clearInterval(id) { timers.delete(id); },
    async advance(milliseconds) {
      const end = now + milliseconds;
      for (;;) {
        const next = [...timers.values()].sort((left, right) => left.due - right.due)[0];
        if (!next || next.due > end) break;
        now = next.due;
        next.due += next.milliseconds;
        const pending = next.callback();
        if (pending?.catch) pending.catch(error => errors.push(error));
        await tick();
      }
      now = end;
      await tick();
    },
  };
  const runtime = { runtimeReady: true, runtimeStatus: 'synthetic', smokeMode: false, capabilities: [] };
  const allowedOperations = new Set(['applications.list', 'bottles.list', 'jobs.list', 'settings.get', 'jobs.poll']);
  const invoke = async (command, args) => {
    if (command === 'state_snapshot' || command === 'bootstrap_runtime') return structuredClone(runtime);
    assert.equal(command, 'service_call', 'only synthetic read/poll commands are permitted');
    const request = args.request;
    assert.ok(allowedOperations.has(request.operation), `blocked operation ${request.operation}`);
    calls.push(structuredClone(request));
    let result;
    if (handlers[request.operation]) result = await handlers[request.operation](request.payload);
    else if (request.operation === 'jobs.list') result = state.jobs;
    else if (request.operation === 'settings.get') result = { reducedMotion: false, compactApplicationGrid: true };
    else if (request.operation === 'jobs.poll') result = { events: [] };
    else result = [];
    return { schemaVersion: '1', requestId: request.requestId, operation: request.operation, result: structuredClone(result) };
  };
  const appWindow = { onResized: async () => () => {}, isMaximized: async () => false };
  vm.runInNewContext(code, {
    document: {
      querySelector: selector => selector === '#app' ? root : null,
      documentElement: { classList: { toggle: (name, value) => classes.set(name, value) } },
    },
    window: clock,
    Element: class {},
    invoke,
    getCurrentWindow: () => appWindow,
    open: async () => { throw new Error('file dialogs are forbidden in this fixture'); },
  }, { filename: sourcePath });
  await tick();
  assert.equal(timers.size, 1, 'actual entrypoint must finish its synthetic bootstrap');
  const value = {
    root, state, handlers, clock, errors, classes, calls,
    requests: operation => calls.filter(call => call.operation === operation),
    click(action) {
      const target = { dataset: { action }, hasAttribute: () => false, closest() { return this; } };
      return listeners.get('click')({ target });
    },
    dispose() { timers.clear(); fixtures.delete(value); },
  };
  fixtures.add(value);
  return value;
}

afterEach(() => {
  for (const fixture of fixtures) {
    assert.deepEqual(fixture.errors, [], 'unexpected unhandled callback failure');
    fixture.dispose();
  }
});

test('one automatic polling cycle remains pending after ten timer ticks', async () => {
  const f = await fixture();
  const pending = deferred();
  f.handlers['jobs.poll'] = () => pending.promise;

  await f.clock.advance(3_000);

  assert.equal(f.requests('jobs.poll').length, 1);
  pending.resolve({ events: [] });
  await tick();
  await f.clock.advance(300);
  assert.equal(f.requests('jobs.poll').length, 2);
});

test('the polling cycle includes its pending four-way data refresh', async () => {
  const f = await fixture();
  const pending = deferred();
  f.handlers['jobs.list'] = () => pending.promise;

  await f.clock.advance(3_000);

  assert.equal(f.requests('jobs.poll').length, 1);
  assert.equal(f.requests('jobs.list').length, 2, 'one initial load plus one pending cycle refresh');
  pending.resolve(f.state.jobs);
  await tick();
  await f.clock.advance(300);
  assert.equal(f.requests('jobs.poll').length, 2);
});

test('a slow second job cannot cause new cycles to repoll the first job', async () => {
  const f = await fixture([job('one'), job('two')]);
  const pending = deferred();
  f.handlers['jobs.poll'] = payload => payload.id === 'two' ? pending.promise : { events: [] };

  await f.clock.advance(3_000);

  assert.deepEqual(f.requests('jobs.poll').map(call => call.payload.id), ['one', 'two']);
  pending.resolve({ events: [] });
  await tick();
});

test('a rejected job poll releases the cycle for the next timer tick', async () => {
  const f = await fixture();
  let attempts = 0;
  f.handlers['jobs.poll'] = () => {
    if (attempts++ === 0) throw new Error('Synthetic poll failure');
    return { events: [] };
  };
  await f.clock.advance(300);
  assert.match(f.root.innerHTML, /Synthetic poll failure/);

  await f.clock.advance(300);

  assert.equal(attempts, 2);
  assert.equal(f.requests('jobs.list').length, 2);
});

test('a failed data refresh also releases the cycle for retry', async () => {
  const f = await fixture();
  let attempts = 0;
  f.handlers['jobs.list'] = () => {
    if (attempts++ === 0) throw new Error('Synthetic refresh failure');
    return f.state.jobs;
  };
  await f.clock.advance(300);
  assert.match(f.root.innerHTML, /Synthetic refresh failure/);

  await f.clock.advance(300);

  assert.equal(attempts, 2);
  assert.equal(f.requests('jobs.poll').length, 2);
});

test('idle and terminal-only lists issue no automatic job polls', async () => {
  for (const status of [null, 'succeeded', 'failed', 'cancelled']) {
    const f = await fixture(status ? [job('done', status)] : []);
    await f.clock.advance(3_000);
    assert.equal(f.requests('jobs.poll').length, 0);
    assert.deepEqual(f.errors, []);
    f.dispose();
  }
});

test('a rejected refresh waits for its pending sibling IPC before releasing the cycle', async () => {
  const f = await fixture();
  const pending = deferred();
  f.handlers['applications.list'] = () => { throw new Error('Synthetic mixed refresh failure'); };
  f.handlers['jobs.list'] = () => pending.promise;

  await f.clock.advance(3_000);

  assert.equal(f.requests('jobs.poll').length, 1);
  assert.equal(f.requests('jobs.list').length, 2);
  pending.resolve(f.state.jobs);
  await tick();
  assert.match(f.root.innerHTML, /Synthetic mixed refresh failure/);
  delete f.handlers['applications.list'];
  delete f.handlers['jobs.list'];
  await f.clock.advance(300);
  assert.equal(f.requests('jobs.poll').length, 2);
});

test('a manual refresh keeps the existing busy gate and polling resumes afterward', async () => {
  const f = await fixture();
  const pending = deferred();
  f.handlers['applications.list'] = () => pending.promise;
  const action = f.click('refresh');
  await f.clock.advance(900);
  assert.equal(f.requests('jobs.poll').length, 0);
  pending.resolve([]);
  await action;

  await f.clock.advance(300);

  assert.equal(f.requests('jobs.poll').length, 1);
});

test('healthy polling preserves sequential jobs, request contracts and terminal stopping', async () => {
  const f = await fixture([job('one'), job('two')]);
  f.handlers['jobs.poll'] = payload => {
    if (payload.id === 'two') f.state.jobs = [job('one', 'succeeded'), job('two', 'cancelled')];
    return { events: [] };
  };
  await f.clock.advance(300);
  assert.deepEqual(f.requests('jobs.poll').map(call => call.payload), [
    { id: 'one', timeoutMilliseconds: 0 }, { id: 'two', timeoutMilliseconds: 0 },
  ]);
  assert.equal(new Set(f.calls.map(call => call.requestId)).size, f.calls.length);
  assert.ok(f.calls.every(call => call.schemaVersion === '1'));
  assert.equal(f.classes.get('compact-grid'), true);
  assert.match(f.root.innerHTML, /0 个活动任务/);

  await f.clock.advance(3_000);

  assert.equal(f.requests('jobs.poll').length, 2);
});
