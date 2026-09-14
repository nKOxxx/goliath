const PROFILES = {
  fast: { moveMinMs: 70, moveMaxMs: 180, hesitateMinMs: 30, hesitateMaxMs: 100, keyMinMs: 25, keyMaxMs: 85 },
  balanced: { moveMinMs: 120, moveMaxMs: 320, hesitateMinMs: 60, hesitateMaxMs: 220, keyMinMs: 45, keyMaxMs: 145 },
  deliberate: { moveMinMs: 220, moveMaxMs: 520, hesitateMinMs: 120, hesitateMaxMs: 420, keyMinMs: 70, keyMaxMs: 210 },
};

function between(random, min, max) {
  return min + random() * (max - min);
}

function integer(random, min, max) {
  return Math.floor(between(random, min, max + 1));
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function cubicBezier(start, control1, control2, end, t) {
  const inverse = 1 - t;
  return {
    x: (inverse ** 3) * start.x + 3 * (inverse ** 2) * t * control1.x + 3 * inverse * (t ** 2) * control2.x + (t ** 3) * end.x,
    y: (inverse ** 3) * start.y + 3 * (inverse ** 2) * t * control1.y + 3 * inverse * (t ** 2) * control2.y + (t ** 3) * end.y,
  };
}

export function humanizedOptions(value) {
  if (!value) return { enabled: false, profile: 'balanced', visualize: false };
  if (value === true) return { enabled: true, profile: 'balanced', visualize: false };
  if (typeof value !== 'object') return { enabled: false, profile: 'balanced', visualize: false };
  const profile = Object.hasOwn(PROFILES, value.profile) ? value.profile : 'balanced';
  return { enabled: value.enabled !== false, profile, visualize: value.visualize === true };
}

async function installPointerVisualizer(frame) {
  await frame.evaluate(() => {
    const cursorId = '__goliath_hands_pointer__';
    if (document.getElementById(cursorId)) return;

    const cursor = document.createElement('div');
    cursor.id = cursorId;
    cursor.setAttribute('aria-hidden', 'true');
    Object.assign(cursor.style, {
      position: 'fixed',
      left: '0',
      top: '0',
      width: '18px',
      height: '18px',
      border: '2px solid rgba(255, 255, 255, 0.96)',
      borderRadius: '50%',
      boxShadow: '0 0 0 1px rgba(12, 10, 18, 0.82), 0 0 18px rgba(159, 122, 234, 0.9)',
      transform: 'translate(-50%, -50%)',
      transition: 'opacity 180ms ease',
      opacity: '0',
      pointerEvents: 'none',
      zIndex: '2147483647',
    });
    (document.documentElement || document.body).appendChild(cursor);

    let hideTimer;
    const showAt = (event) => {
      cursor.style.left = `${event.clientX}px`;
      cursor.style.top = `${event.clientY}px`;
      cursor.style.opacity = '1';
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => { cursor.style.opacity = '0'; }, 1800);
    };
    const pulseAt = (event) => {
      showAt(event);
      const pulse = document.createElement('div');
      pulse.setAttribute('aria-hidden', 'true');
      Object.assign(pulse.style, {
        position: 'fixed',
        left: `${event.clientX}px`,
        top: `${event.clientY}px`,
        width: '22px',
        height: '22px',
        border: '2px solid rgba(159, 122, 234, 0.95)',
        borderRadius: '50%',
        transform: 'translate(-50%, -50%) scale(0.55)',
        pointerEvents: 'none',
        zIndex: '2147483646',
      });
      (document.documentElement || document.body).appendChild(pulse);
      const animation = pulse.animate([
        { opacity: 0.95, transform: 'translate(-50%, -50%) scale(0.55)' },
        { opacity: 0, transform: 'translate(-50%, -50%) scale(2.7)' },
      ], { duration: 520, easing: 'cubic-bezier(0.2, 0.8, 0.2, 1)' });
      animation.finished.then(() => pulse.remove()).catch(() => pulse.remove());
    };

    document.addEventListener('mousemove', showAt, true);
    document.addEventListener('mousedown', pulseAt, true);
  });
}

async function ensurePointerVisualizer(page) {
  const frames = typeof page.frames === 'function' ? page.frames() : [];
  await Promise.all(frames.map(frame => installPointerVisualizer(frame).catch(() => {})));
}

/**
 * Raised when a humanized pointer action cannot be verified against the page:
 * the pointer is not over the target (`target_obscured`) or no click event
 * reached the target element (`click_not_delivered`). Both map to HTTP 409 so an
 * agent sees a structured failure instead of an `ok: true` that changed nothing.
 */
export class HumanizedInputError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'HumanizedInputError';
    this.code = code;
    this.statusCode = 409;
    Object.assign(this, details);
  }
}

export function pointerTrajectory(start, end, { random = Math.random, steps } = {}) {
  const distance = Math.hypot(end.x - start.x, end.y - start.y);
  const pointCount = steps || clamp(Math.round(distance / 22), 12, 42);
  const bend = between(random, -0.22, 0.22) * Math.max(60, distance);
  const control1 = {
    x: start.x + (end.x - start.x) * between(random, 0.2, 0.4) - bend * 0.25,
    y: start.y + (end.y - start.y) * between(random, 0.15, 0.35) + bend,
  };
  const control2 = {
    x: start.x + (end.x - start.x) * between(random, 0.65, 0.85) + bend * 0.2,
    y: start.y + (end.y - start.y) * between(random, 0.6, 0.85) - bend * 0.45,
  };
  const points = [];
  for (let index = 1; index <= pointCount; index++) {
    const t = index / pointCount;
    const point = cubicBezier(start, control1, control2, end, t);
    const taper = Math.sin(Math.PI * t);
    points.push({
      x: point.x + between(random, -1.25, 1.25) * taper,
      y: point.y + between(random, -1.25, 1.25) * taper,
    });
  }
  points[points.length - 1] = { ...end };
  return points;
}

function runtime(options = {}) {
  const random = options.random || Math.random;
  const sleep = options.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const record = options.record || (() => {});
  // Every browser-side pointer dispatch goes through `dispatch` so the server can
  // bound it (see withInputDispatchTimeout in server.js). A hung page.mouse call
  // then fails the step with input_dispatch_timeout instead of running into the
  // handler timeout, which destroys the whole session (#11, #14).
  const dispatch = options.dispatch || (operation => operation());
  // Page-side checks (hit test, delivery probe) are observations, not actions. A
  // page that stays busy must not turn one into a hang that reaches the handler
  // timeout, so each is bounded and a timeout degrades to "unknown".
  const probeTimeoutMs = Number.isFinite(options.probeTimeoutMs) ? options.probeTimeoutMs : PROBE_TIMEOUT_MS;
  const probe = operation => boundedProbe(operation, probeTimeoutMs);
  const profileName = Object.hasOwn(PROFILES, options.profile) ? options.profile : 'balanced';
  return { random, sleep, record, dispatch, probe, profile: PROFILES[profileName], profileName };
}

const PROBE_TIMEOUT_MS = 2000;

function boundedProbe(operation, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error(`page probe timed out after ${ms}ms`), { code: 'probe_timeout' })), ms);
    timer.unref?.();
  });
  return Promise.race([Promise.resolve().then(operation), timeout]).finally(() => clearTimeout(timer));
}

// Runs inside the page: is the element under the pointer the target (or part of it)?
// Frame content is skipped because elementFromPoint there uses frame-local coordinates.
function hitTestInPage(el, point) {
  if (window !== window.top) return { checked: false, reason: 'frame' };
  const describe = node => {
    if (!node || node.nodeType !== 1) return String((node && node.nodeName) || 'none');
    const classes = typeof node.className === 'string' ? node.className.trim().split(/\s+/).filter(Boolean).slice(0, 3) : [];
    return node.tagName.toLowerCase() + (node.id ? `#${node.id}` : '') + (classes.length ? `.${classes.join('.')}` : '');
  };
  const under = document.elementFromPoint(point.x, point.y);
  if (!under) return { checked: true, hit: false, under: 'none' };
  let hit = under === el || el.contains(under);
  if (!hit && under.tagName === 'LABEL') hit = under.control === el || under.contains(el);
  if (!hit) {
    // Targets inside shadow roots: document.elementFromPoint stops at the host.
    let root = el.getRootNode();
    while (!hit && root && root.host) {
      hit = root.host === under || root.host.contains(under);
      root = root.host.getRootNode();
    }
  }
  return { checked: true, hit, under: describe(under) };
}

// Runs inside the page. Records whether the press and the click reached the
// element. Listeners sit on the element (so targets inside closed shadow roots
// still count) and on window in the capture phase (so a page that stops the
// click on its way down, as many UI libraries do after acting on pointerup,
// still counts as delivered). The probe lives only in the returned handle; no
// property is left on the element.
function armDeliveryProbe(el) {
  const probe = { el, clicked: false, pressed: false, released: false, listeners: [] };
  const seen = new WeakSet();
  const listen = (target, type, key) => {
    const handler = event => {
      if (seen.has(event)) return;
      if (target !== el && !event.composedPath().includes(el)) return;
      seen.add(event);
      probe[key] = true;
    };
    target.addEventListener(type, handler, true);
    probe.listeners.push([target, type, handler]);
  };
  for (const target of [window, el]) {
    listen(target, 'click', 'clicked');
    listen(target, 'pointerdown', 'pressed');
    listen(target, 'mousedown', 'pressed');
    listen(target, 'pointerup', 'released');
    listen(target, 'mouseup', 'released');
  }
  return probe;
}

function readDeliveryProbe(probe) {
  for (const [target, type, handler] of probe.listeners) target.removeEventListener(type, handler, true);
  const { el } = probe;
  return {
    clicked: probe.clicked,
    pressed: probe.pressed,
    released: probe.released,
    rendered: el.isConnected && el.getClientRects().length > 0,
  };
}

function probeFailure(err) {
  return { checked: false, reason: err?.code === 'probe_timeout' ? 'probe_timeout' : 'evaluate_failed' };
}

async function verifyPointerOverTarget(page, locator, state, target, box, rt) {
  let hit;
  try {
    hit = await rt.probe(() => locator.evaluate(hitTestInPage, { x: target.x, y: target.y }));
  } catch (err) {
    return probeFailure(err);
  }
  if (!hit.checked || hit.hit) return hit;
  // One corrective re-aim: the layout may have shifted while the pointer travelled.
  let freshBox;
  try {
    freshBox = await rt.probe(() => locator.boundingBox());
  } catch {
    return hit;
  }
  if (!freshBox || freshBox.width <= 0 || freshBox.height <= 0) return hit;
  const retarget = targetPoint(freshBox, rt.random);
  await movePointer(page, state, retarget, { random: rt.random, sleep: rt.sleep, record: rt.record, dispatch: rt.dispatch, profile: rt.profileName });
  target.x = retarget.x;
  target.y = retarget.y;
  try {
    const second = await rt.probe(() => locator.evaluate(hitTestInPage, { x: target.x, y: target.y }));
    return { ...second, retargeted: true };
  } catch (err) {
    return { ...probeFailure(err), retargeted: true };
  }
}

async function movePointer(page, state, end, options = {}) {
  const rt = runtime(options);
  const viewport = page.viewportSize?.() || { width: 1280, height: 720 };
  const start = state.pointer || {
    x: between(rt.random, viewport.width * 0.25, viewport.width * 0.75),
    y: between(rt.random, viewport.height * 0.25, viewport.height * 0.75),
  };
  const points = pointerTrajectory(start, end, { random: rt.random });
  const duration = between(rt.random, rt.profile.moveMinMs, rt.profile.moveMaxMs);
  for (const [index, point] of points.entries()) {
    await rt.dispatch(() => page.mouse.move(point.x, point.y));
    state.pointer = point;
    rt.record('pointermove', { x: Math.round(point.x), y: Math.round(point.y) });
    if (index < points.length - 1) {
      const progress = (index + 1) / points.length;
      const easingWeight = 0.55 + Math.abs(progress - 0.5) * 1.3;
      await rt.sleep(Math.max(2, duration / points.length * easingWeight * between(rt.random, 0.7, 1.3)));
    }
  }
  return { start, end, points: points.length, durationMs: Math.round(duration) };
}

function targetPoint(box, random) {
  const insetX = Math.min(box.width * 0.22, 12);
  const insetY = Math.min(box.height * 0.22, 10);
  return {
    x: between(random, box.x + insetX, box.x + Math.max(insetX, box.width - insetX)),
    y: between(random, box.y + insetY, box.y + Math.max(insetY, box.height - insetY)),
  };
}

export const HOLD_MS_MIN = 200;
export const HOLD_MS_MAX = 15000;

export function parseHoldMs(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const holdMs = Number(value);
  if (!Number.isFinite(holdMs) || holdMs < HOLD_MS_MIN || holdMs > HOLD_MS_MAX) {
    const error = new Error(`holdMs must be between ${HOLD_MS_MIN} and ${HOLD_MS_MAX} milliseconds`);
    error.statusCode = 400;
    throw error;
  }
  return holdMs;
}

export async function humanizedClick(page, locator, state, options = {}) {
  const rt = runtime(options);
  if (options.visualize) await ensurePointerVisualizer(page);
  const strictHitTarget = options.strictHitTarget !== false;
  await locator.scrollIntoViewIfNeeded?.({ timeout: 3000 });
  const box = await locator.boundingBox();
  if (!box || box.width <= 0 || box.height <= 0) throw new Error('Element not visible (no bounding box)');
  const target = targetPoint(box, rt.random);
  const movement = await movePointer(page, state, target, {
    random: rt.random,
    sleep: rt.sleep,
    record: rt.record,
    dispatch: rt.dispatch,
    profile: rt.profileName,
  });
  await rt.sleep(between(rt.random, rt.profile.hesitateMinMs, rt.profile.hesitateMaxMs));

  const microMoves = integer(rt.random, 0, 2);
  for (let index = 0; index < microMoves; index++) {
    const micro = { x: target.x + between(rt.random, -2.2, 2.2), y: target.y + between(rt.random, -1.8, 1.8) };
    await rt.dispatch(() => page.mouse.move(micro.x, micro.y));
    state.pointer = micro;
    target.x = micro.x;
    target.y = micro.y;
    rt.record('pointermove', { x: Math.round(micro.x), y: Math.round(micro.y), micro: true });
    await rt.sleep(between(rt.random, 18, 65));
  }

  // The direct path gets Playwright's actionability checks for free. The humanized
  // path pressed blind at a point computed before the pointer travelled, so a
  // shifted layout, an overlay, or a covered control produced ok:true and no click.
  const hit = await verifyPointerOverTarget(page, locator, state, target, box, rt);
  if (hit.checked && !hit.hit && strictHitTarget) {
    throw new HumanizedInputError(
      `Pointer is over "${hit.under}" instead of the target element`,
      'target_obscured',
      { hit, hint: 'Something covers or moved the target. Call snapshot and retry, or send humanized:false to use the direct click path.' },
    );
  }

  let probe = null;
  try {
    probe = await rt.probe(() => locator.evaluateHandle(armDeliveryProbe));
  } catch {
    probe = null;
  }

  let observed = null;
  const clickCount = options.doubleClick ? 2 : 1;
  try {
    for (let click = 0; click < clickCount; click++) {
      await rt.dispatch(() => page.mouse.down());
      rt.record('pointerdown', { button: 'left' });
      await rt.sleep(between(rt.random, 45, 135));
      await rt.dispatch(() => page.mouse.up());
      rt.record('pointerup', { button: 'left' });
      if (click + 1 < clickCount) await rt.sleep(between(rt.random, 85, 180));
    }
    if (probe) {
      try {
        observed = await rt.probe(() => probe.evaluate(readDeliveryProbe));
      } catch {
        // The page navigated, tore the context down, or stayed busy past the
        // probe bound. None of these proves the click failed.
        observed = null;
      }
    }
  } finally {
    if (probe) rt.probe(() => probe.dispose()).catch(() => {});
  }

  // delivered: true when a click event reached the target; null when that cannot
  // be known (no probe, unreadable probe, or the target is gone or no longer
  // rendered, which is itself a sign the press did something).
  const delivered = !observed ? null : observed.clicked ? true : observed.rendered ? false : null;
  if (delivered === false && (observed.pressed || observed.released)) {
    // The press reached the target, so the page may already have acted on
    // pointerdown or pointerup. Retrying blind could repeat that action.
    throw new HumanizedInputError(
      'The press reached the target element but no click event followed',
      'click_unconfirmed',
      { hit, delivered, pointer: { pressed: observed.pressed, released: observed.released }, retrySafe: false, hint: 'The page may already have acted on the press. Call snapshot and check the page before retrying.' },
    );
  }
  if (delivered === false) {
    throw new HumanizedInputError(
      'No part of the pointer press reached the target element',
      'click_not_delivered',
      { hit, delivered, pointer: { pressed: false, released: false }, retrySafe: true, hint: 'Nothing from the press reached the target, so it did not act on it. Call snapshot and retry, or send humanized:false to use the direct click path.' },
    );
  }
  return { mode: 'humanized', profile: rt.profileName, pathPoints: movement.points, hit, delivered, visualized: options.visualize === true };
}

export async function humanizedPressAndHold(page, locator, state, options = {}) {
  const holdMs = parseHoldMs(options.holdMs);
  if (holdMs === undefined) {
    const error = new Error(`holdMs must be between ${HOLD_MS_MIN} and ${HOLD_MS_MAX} milliseconds`);
    error.statusCode = 400;
    throw error;
  }
  const rt = runtime(options);
  if (options.visualize) await ensurePointerVisualizer(page);
  try {
    await locator.scrollIntoViewIfNeeded?.({ timeout: 3000 });
  } catch {
    // Linux/Xvfb Camoufox often never reports layout as "stable". The hold
    // still proceeds from the current bounding box when the element is on screen.
  }
  const box = await locator.boundingBox();
  if (!box || box.width <= 0 || box.height <= 0) throw new Error('Element not visible (no bounding box)');
  const target = targetPoint(box, rt.random);
  const movement = await movePointer(page, state, target, {
    random: rt.random,
    sleep: rt.sleep,
    record: rt.record,
    dispatch: rt.dispatch,
    profile: rt.profileName,
  });
  await rt.sleep(between(rt.random, rt.profile.hesitateMinMs, rt.profile.hesitateMaxMs));
  const hit = await verifyPointerOverTarget(page, locator, state, target, box, rt);
  if (hit.checked && !hit.hit && options.strictHitTarget !== false) {
    throw new HumanizedInputError(
      `Pointer is over "${hit.under}" instead of the target element`,
      'target_obscured',
      { hit, hint: 'Something covers or moved the target. Call snapshot and retry.' },
    );
  }
  await rt.dispatch(() => page.mouse.down());
  rt.record('pointerdown', { button: 'left' });
  let elapsed = 0;
  const minX = box.x + 1;
  const maxX = box.x + Math.max(1, box.width - 1);
  const minY = box.y + 1;
  const maxY = box.y + Math.max(1, box.height - 1);
  while (elapsed < holdMs) {
    const x = clamp(target.x + between(rt.random, -2, 2), minX, maxX);
    const y = clamp(target.y + between(rt.random, -2, 2), minY, maxY);
    await rt.dispatch(() => page.mouse.move(x, y));
    state.pointer = { x, y };
    rt.record('pointermove', { x: Math.round(x), y: Math.round(y), hold: true });
    const step = Math.min(75, holdMs - elapsed);
    await rt.sleep(step);
    elapsed += step;
  }
  await rt.dispatch(() => page.mouse.up());
  rt.record('pointerup', { button: 'left' });
  return { mode: 'humanized', profile: rt.profileName, pathPoints: movement.points, holdMs: elapsed, hit, visualized: options.visualize === true };
}

export async function humanizedType(page, text, options = {}) {
  const rt = runtime(options);
  let typed = 0;
  for (const character of Array.from(text)) {
    await page.keyboard.type(character);
    typed += 1;
    rt.record('key', { category: /\s/.test(character) ? 'space' : 'character' });
    let delay = between(rt.random, rt.profile.keyMinMs, rt.profile.keyMaxMs);
    if (/\s/.test(character)) delay += between(rt.random, 45, 180);
    if (/[.,!?;:]/.test(character)) delay += between(rt.random, 90, 280);
    await rt.sleep(delay);
  }
  return { mode: 'humanized', profile: rt.profileName, characters: typed };
}

export async function humanizedScroll(page, direction, amount, options = {}) {
  const rt = runtime(options);
  const vertical = direction === 'up' || direction === 'down';
  const sign = direction === 'up' || direction === 'left' ? -1 : 1;
  const magnitude = Math.max(1, Math.abs(Number(amount) || 500));
  const pulses = integer(rt.random, 7, 14);
  const weights = Array.from({ length: pulses }, (_, index) => Math.sin(Math.PI * (index + 1) / (pulses + 1)) + 0.18);
  const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
  let moved = 0;
  for (const weight of weights) {
    const delta = sign * Math.max(1, Math.round(magnitude * weight / totalWeight));
    await rt.dispatch(() => page.mouse.wheel(vertical ? 0 : delta, vertical ? delta : 0));
    moved += delta;
    rt.record('wheel', { deltaX: vertical ? 0 : delta, deltaY: vertical ? delta : 0 });
    await rt.sleep(between(rt.random, 24, 90));
  }
  return { mode: 'humanized', profile: rt.profileName, pulses, distance: moved };
}
