import { test, expect } from '@jest/globals';
import { HumanizedInputError, humanizedClick, humanizedPressAndHold, humanizedScroll } from '../../lib/humanized-input.js';

// A deterministic fake of the Playwright surface the humanized layer touches.
function fakePage({
  hits = [],
  observed = { clicked: true, pressed: true, released: true, rendered: true },
  failEvaluate = false,
  hangMove = false,
  hangProbeRead = false,
  hangHitTest = false,
} = {}) {
  const calls = [];
  const hitQueue = [...hits];
  const box = { x: 100, y: 200, width: 120, height: 30 };
  const probeHandle = {
    async evaluate(fn) {
      if (fn.name !== 'readDeliveryProbe') throw new Error(`unexpected probe evaluate ${fn.name}`);
      calls.push('read');
      if (hangProbeRead) return new Promise(() => {});
      if (failEvaluate) throw new Error('Execution context was destroyed');
      return observed;
    },
    async dispose() { calls.push('dispose'); },
  };
  const locator = {
    async scrollIntoViewIfNeeded() {},
    async boundingBox() { return box; },
    async evaluate(fn, point) {
      calls.push(`hit:${Math.round(point.x)},${Math.round(point.y)}`);
      if (hangHitTest) return new Promise(() => {});
      if (failEvaluate) throw new Error('evaluate failed');
      return hitQueue.length ? hitQueue.shift() : { checked: true, hit: true, under: 'button' };
    },
    async evaluateHandle(fn) {
      if (fn.name !== 'armDeliveryProbe') throw new Error(`unexpected evaluateHandle ${fn.name}`);
      calls.push('arm');
      return probeHandle;
    },
  };
  const page = {
    viewportSize() { return { width: 1280, height: 720 }; },
    mouse: {
      async move(x, y) {
        if (hangMove) return new Promise(() => {});
        calls.push(`move:${Math.round(x)},${Math.round(y)}`);
      },
      async down() { calls.push('down'); },
      async up() { calls.push('up'); },
      async wheel(dx, dy) { calls.push(`wheel:${dx},${dy}`); },
    },
  };
  return { page, locator, calls, box };
}

const opts = { random: () => 0.5, sleep: async () => {}, profile: 'fast' };

test('humanized click verifies the hit target, probes delivery, and reports both', async () => {
  const { page, locator, calls, box } = fakePage();
  const state = { pointer: { x: 10, y: 10 } };
  const result = await humanizedClick(page, locator, state, opts);
  expect(result.mode).toBe('humanized');
  expect(result.hit).toEqual({ checked: true, hit: true, under: 'button' });
  expect(result.delivered).toBe(true);
  const hitCall = calls.find(c => c.startsWith('hit:'));
  const [x, y] = hitCall.slice(4).split(',').map(Number);
  expect(x).toBeGreaterThanOrEqual(box.x);
  expect(x).toBeLessThanOrEqual(box.x + box.width);
  expect(y).toBeGreaterThanOrEqual(box.y);
  expect(y).toBeLessThanOrEqual(box.y + box.height);
  // hit test happens after the pointer arrived and before the press
  expect(calls.indexOf(hitCall)).toBeGreaterThan(calls.findIndex(c => c.startsWith('move:')));
  expect(calls.indexOf(hitCall)).toBeLessThan(calls.indexOf('down'));
  expect(calls.indexOf('arm')).toBeLessThan(calls.indexOf('down'));
  expect(calls.indexOf('read')).toBeGreaterThan(calls.indexOf('up'));
  expect(calls).toContain('dispose');
});

test('re-aims once when another element is under the pointer, then presses', async () => {
  const { page, locator, calls } = fakePage({ hits: [{ checked: true, hit: false, under: 'div.overlay' }] });
  const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, opts);
  expect(result.hit).toEqual({ checked: true, hit: true, under: 'button', retargeted: true });
  expect(calls.filter(c => c.startsWith('hit:'))).toHaveLength(2);
  expect(calls).toContain('down');
});

test('refuses to press blind when the target stays covered', async () => {
  const covered = { checked: true, hit: false, under: 'div.modal-backdrop' };
  const { page, locator, calls } = fakePage({ hits: [covered, covered] });
  let error;
  try { await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, opts); } catch (err) { error = err; }
  expect(error).toBeInstanceOf(HumanizedInputError);
  expect(error.code).toBe('target_obscured');
  expect(error.statusCode).toBe(409);
  expect(error.hit.under).toBe('div.modal-backdrop');
  expect(error.hint).toMatch(/humanized:false/);
  expect(calls).not.toContain('down');
});

test('strictHitTarget:false presses anyway and reports the miss', async () => {
  const covered = { checked: true, hit: false, under: 'div.serp-overlay' };
  const { page, locator, calls } = fakePage({ hits: [covered, covered] });
  const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, strictHitTarget: false });
  expect(result.hit.hit).toBe(false);
  expect(calls).toContain('down');
});

test('fails with retry-safe click_not_delivered when no part of the press reached the element', async () => {
  const { page, locator, calls } = fakePage({ observed: { clicked: false, pressed: false, released: false, rendered: true } });
  let error;
  try { await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, opts); } catch (err) { error = err; }
  expect(error).toBeInstanceOf(HumanizedInputError);
  expect(error.code).toBe('click_not_delivered');
  expect(error.statusCode).toBe(409);
  expect(error.delivered).toBe(false);
  expect(error.retrySafe).toBe(true);
  expect(calls).toContain('dispose');
});

test('a press that reached the element without a click is unconfirmed and never marked retry-safe', async () => {
  for (const pointer of [{ pressed: true, released: true }, { pressed: true, released: false }, { pressed: false, released: true }]) {
    const { page, locator } = fakePage({ observed: { clicked: false, ...pointer, rendered: true } });
    let error;
    try { await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, opts); } catch (err) { error = err; }
    expect(error).toBeInstanceOf(HumanizedInputError);
    expect(error.code).toBe('click_unconfirmed');
    expect(error.statusCode).toBe(409);
    expect(error.retrySafe).toBe(false);
    expect(error.pointer).toEqual(pointer);
    expect(error.hint).toMatch(/before retrying/);
    expect(error.hint).not.toMatch(/humanized:false/);
  }
});

test('a target that is gone or no longer rendered after the press reports delivered:null, not a failure', async () => {
  for (const pressed of [true, false]) {
    const { page, locator } = fakePage({ observed: { clicked: false, pressed, released: pressed, rendered: false } });
    const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, opts);
    expect(result.delivered).toBeNull();
  }
});

test('a page that stays busy after the press yields delivered:null within the probe bound', async () => {
  const { page, locator, calls } = fakePage({ hangProbeRead: true });
  const started = Date.now();
  const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, probeTimeoutMs: 20 });
  expect(result.delivered).toBeNull();
  expect(Date.now() - started).toBeLessThan(1000);
  expect(calls).toContain('up');
});

test('a hung hit test degrades to an unchecked hit and still presses', async () => {
  const { page, locator, calls } = fakePage({ hangHitTest: true });
  const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, probeTimeoutMs: 20 });
  expect(result.hit).toEqual({ checked: false, reason: 'probe_timeout' });
  expect(calls).toContain('down');
  expect(result.delivered).toBe(true);
});

test('reports delivered:null instead of failing when the probe cannot be read', async () => {
  const { page, locator } = fakePage({ failEvaluate: true });
  const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, opts);
  expect(result.delivered).toBeNull();
  expect(result.hit).toEqual({ checked: false, reason: 'evaluate_failed' });
});

test('double click needs at least one delivered click', async () => {
  const { page, locator, calls } = fakePage();
  const result = await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, doubleClick: true });
  expect(result.delivered).toBe(true);
  expect(calls.filter(c => c === 'down')).toHaveLength(2);
});

test('every pointer dispatch runs through the dispatch guard', async () => {
  const { page, locator, calls } = fakePage();
  let guarded = 0;
  const dispatch = async (operation) => { guarded += 1; return operation(); };
  await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, dispatch });
  const pointerCalls = calls.filter(c => c.startsWith('move:') || c === 'down' || c === 'up').length;
  expect(guarded).toBe(pointerCalls);
});

test('a hung pointer move surfaces the guard error instead of hanging the step', async () => {
  const { page, locator, calls } = fakePage({ hangMove: true });
  const dispatch = (operation) => Promise.race([
    operation(),
    new Promise((_, reject) => setTimeout(() => reject(Object.assign(new Error('mouse sequence timed out after 5ms'), { code: 'input_dispatch_timeout' })), 5)),
  ]);
  let error;
  try { await humanizedClick(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, dispatch }); } catch (err) { error = err; }
  expect(error.code).toBe('input_dispatch_timeout');
  expect(calls).not.toContain('down');
});

test('press-and-hold checks the hit target before pressing and guards its dispatches', async () => {
  const covered = { checked: true, hit: false, under: 'div.sheet' };
  const { page, locator, calls } = fakePage({ hits: [covered, covered] });
  let error;
  try { await humanizedPressAndHold(page, locator, { pointer: { x: 10, y: 10 } }, { ...opts, holdMs: 200 }); } catch (err) { error = err; }
  expect(error.code).toBe('target_obscured');
  expect(calls).not.toContain('down');

  const ok = fakePage();
  let guarded = 0;
  const result = await humanizedPressAndHold(ok.page, ok.locator, { pointer: { x: 10, y: 10 } }, { ...opts, holdMs: 200, dispatch: async op => { guarded += 1; return op(); } });
  expect(result.holdMs).toBe(200);
  expect(result.hit.hit).toBe(true);
  expect(guarded).toBe(ok.calls.filter(c => c.startsWith('move:') || c === 'down' || c === 'up').length);
});

test('scroll pulses run through the dispatch guard', async () => {
  const { page, calls } = fakePage();
  let guarded = 0;
  await humanizedScroll(page, 'down', 300, { ...opts, dispatch: async op => { guarded += 1; return op(); } });
  expect(guarded).toBe(calls.filter(c => c.startsWith('wheel:')).length);
  expect(guarded).toBeGreaterThan(0);
});
