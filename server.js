import { VirtualDisplay } from 'camoufox-js/dist/virtdisplay.js';
import { firefox } from 'playwright-core';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import { expandMacro } from './lib/macros.js';
import { loadConfig } from './lib/config.js';
import { normalizePlaywrightProxy, createProxyPool, buildProxyUrl } from './lib/proxy.js';
import { createFlyHelpers } from './lib/fly.js';
import { createPluginEvents, loadPlugins } from './lib/plugins.js';
import { requireAuth, requireApiKey, accessKeyMiddleware, timingSafeCompare as _timingSafeCompare, isLoopbackAddress as _isLoopbackAddress } from './lib/auth.js';
import { windowSnapshot, filterInteractive, clampSnapshotWindow } from './lib/snapshot.js';
import {
  MAX_DOWNLOAD_INLINE_BYTES,
  clearTabDownloads,
  clearSessionDownloads,
  attachDownloadListener,
  getDownloadsList,
} from './lib/downloads.js';
import { extractPageImages } from './lib/images.js';
import { extractDeterministic, validateSchema as validateExtractSchema } from './lib/extract.js';
import { extractSemantic, validateSemanticSchema } from './lib/extract.js';
import { buildSemanticSnapshot, createReadinessTracker } from './lib/semantic.js';
import { planAction, validateContract, validatePostconditions, verifyPostconditions } from './lib/action-contracts.js';
import { createCheckpoint, deleteCheckpoint, listCheckpoints, readCheckpoint } from './lib/checkpoints.js';
import { findPausedHandoff, findPausedHandoffInSession, handoffPausedError, pausedHandoff } from './lib/handoff.js';
import { resolveRefTarget, targetFrameOrigin, validateSecretTarget } from './lib/frame-targets.js';
import { SessionReservationRegistry } from './lib/session-reservations.js';
import { resolveUploadPaths } from './lib/upload-paths.js';
import { writeOutputFile } from './lib/file-output.js';
import {
  ensureTracesDir, resolveTracePath, tracePathFor, makeTraceFilename,
  listUserTraces, statTrace, deleteTrace, sweepOldTraces,
} from './lib/tracing.js';

import {
  initMetrics, getRegister, isMetricsEnabled, createMetric,
  startMemoryReporter, stopMemoryReporter,
} from './lib/metrics.js';
import { actionFromReq, classifyError } from './lib/request-utils.js';
import { cleanupOrphanedTempFiles, cleanupStaleFirefoxProfiles } from './lib/tmp-cleanup.js';
import { coalesceInflight } from './lib/inflight.js';
import { createReporter, createTabHealthTracker, collectResourceSnapshot, classifyProxyError, browserProcessTreeRssMb } from './lib/reporter.js';
import { mountDocs } from './lib/openapi.js';
import { initSentry, captureException as sentryCaptureException, setupExpressErrorHandler as setupSentryErrorHandler, flush as sentryFlush } from './lib/sentry.js';
import { prepareExternalCamoufoxExecutable } from './lib/camoufox-executable.js';
import { HumanizedInputError, humanizedClick, humanizedPressAndHold, humanizedOptions, humanizedScroll, humanizedType, parseHoldMs } from './lib/humanized-input.js';
import { coerceHandsSteps, HandsError, computeHandBudgetMs } from './lib/hands.js';
import { approvalRequiredResponse, classifyDangerousAction, normalizeActionLabel } from './lib/dangerous-actions.js';
import {
  checkSessionPolicy,
  normalizeSessionPolicy,
  originFromUrl,
  sessionPolicyViolationError,
} from './lib/session-policy.js';
import { behaviorReport, createBehaviorTracker, recordBehaviorEvent } from './lib/behavior.js';
import { applyFingerprintCoherence } from './lib/fingerprint.js';
import tui from './lib/tui.js';
import {
  beginSessionActivity,
  endSessionActivity,
  removeSessionIfCurrent,
  sessionCanBeReaped,
  sessionHasPausedHandoff,
} from './lib/session-lifecycle.js';

const CONFIG = loadConfig();
function selectAllowedDuration(value, allowed, fallback) {
  const requested = Number(value);
  return allowed.find(duration => duration === requested) ?? fallback;
}
const runtimeInterval = (...args) => {
  const timer = globalThis.setInterval(...args);
  if (CONFIG.nodeEnv === 'test') timer.unref();
  return timer;
};

// --- Crash reporter (opt-in, anonymized GitHub issues) ---
import { readFileSync } from 'fs';
const _pkgVersion = (() => { try { return JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version; } catch { return 'unknown'; } })();

// --- Sentry error tracking ---
initSentry({ ...CONFIG, version: _pkgVersion });
const reporter = createReporter({ ...CONFIG, version: _pkgVersion });
function _countTabs() {
  let total = 0;
  for (const session of sessions.values()) {
    for (const group of session.tabGroups.values()) total += group.size;
  }
  return total;
}
function _browserPid() {
  try { return browser?.process?.()?.pid ?? null; } catch { return null; }
}
function _resourceOpts() {
  return { sessionCount: sessions.size, tabCount: _countTabs(), browserPid: _browserPid() };
}
if (CONFIG.nodeEnv !== 'test') reporter.startWatchdog(30_000, () => {
  const summary = [];
  for (const [sid, session] of sessions) {
    const tabUrls = [];
    for (const group of session.tabGroups.values()) {
      for (const tab of group.values()) {
        try {
          const url = tab.page?.url?.() || 'unknown';
          tabUrls.push(url);
        } catch { tabUrls.push('error'); }
      }
    }
    if (tabUrls.length > 0) summary.push({ session: sid, tabs: tabUrls.length, urls: tabUrls });
  }
  return { resourceOpts: _resourceOpts(), sessions: summary.length, summary };
});

// --- Plugin event bus ---
const pluginEvents = createPluginEvents();

// --- Shared auth middleware ---
const authMiddleware = () => requireAuth(CONFIG);
const operatorAuthMiddleware = () => requireApiKey(CONFIG);

const {
  requestsTotal, requestDuration, pageLoadDuration, snapshotBytes,
  activeTabsGauge, tabLockQueueDepth,
  tabLockTimeoutsTotal,
  failuresTotal, browserRestartsTotal, tabsDestroyedTotal,
  sessionsExpiredTotal, tabsReapedTotal, tabsRecycledTotal,
  policyViolationsTotal,
} = await initMetrics({ enabled: CONFIG.prometheusEnabled });

// --- Structured logging ---
function log(level, msg, fields = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields,
  };
  const line = JSON.stringify(entry);
  if (level === 'error') {
    process.stderr.write(line + '\n');
  } else {
    process.stdout.write(line + '\n');
  }
}

const app = express();
app.use(express.json({ limit: '100kb' }));
const traceIoRateLimit = rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, res, _next, options) => res.status(options.statusCode).json({
    error: 'too many trace requests',
    code: 'rate_limited',
  }),
});

// Request logging + metrics middleware
app.use((req, res, next) => {
  const reqId = crypto.randomUUID().slice(0, 8);
  req.reqId = reqId;
  req.startTime = Date.now();

  const userId = req.body?.userId || req.query?.userId || '-';
  if (req.path !== '/health') {
    log('info', 'req', { reqId, method: req.method, path: req.path, userId });
  }

  const action = actionFromReq(req);
  reporter.trackRoute(`${req.method} ${req.route?.path || '[unmatched]'}`);
  const done = requestDuration.startTimer({ action });

  const origEnd = res.end.bind(res);
  res.end = function (...args) {
    const ms = Date.now() - req.startTime;
    const isErrorStatus = res.statusCode >= 400;
    requestsTotal.labels(action, isErrorStatus ? 'error' : 'success').inc();
    done();

    if (req.path !== '/health') {
      log('info', 'res', { reqId, status: res.statusCode, ms });
    }

    return origEnd(...args);
  };

  next();
});

// --- Horizontal scaling (Fly.io multi-machine) ---
const fly = createFlyHelpers(CONFIG);
const FLY_MACHINE_ID = fly.machineId;

// Route tab requests to the owning machine via fly-replay header.
app.use('/tabs/:tabId', fly.replayMiddleware(log));

// Access-key middleware: gates every route when GOLIATH_ACCESS_KEY is set.
// Exempts /health (Docker healthcheck) and routes that have their own
// dedicated keys (cookie import -> GOLIATH_API_KEY, /stop -> GOLIATH_ADMIN_KEY)
// so each key gates a distinct surface. When unset, behavior is unchanged.
app.use(accessKeyMiddleware(CONFIG));

// Session policy enforcement is centralized so legacy and native tab routes
// cannot drift apart. Target-frame and dangerous-category checks are repeated
// at the resolved action choke points below.
app.use((req, res, next) => {
  try {
    enforceRequestSessionPolicy(req);
    next();
  } catch (err) {
    sendError(res, err);
  }
});

const ALLOWED_URL_SCHEMES = ['http:', 'https:'];

// Interactive roles to include - exclude combobox to avoid opening complex widgets
// (date pickers, dropdowns) that can interfere with navigation
const INTERACTIVE_ROLES = [
  'button', 'link', 'textbox', 'checkbox', 'radio',
  'menuitem', 'tab', 'searchbox', 'slider', 'spinbutton', 'switch'
  // 'combobox' excluded - can trigger date pickers and complex dropdowns
];

// Patterns to skip (date pickers, calendar widgets -- NOT expiration/expiry fields)
const SKIP_PATTERNS = [
  /datepicker/i, /date.?picker/i, /calendar/i, /^date$/i
];

// Iframe support: URL patterns to SKIP (tracking, analytics, pixels)
const IFRAME_SKIP_PATTERNS = [
  /web-pixel/i, /analytics/i, /tracking/i, /gtm/i, /facebook/i,
  /doubleclick/i, /google.*tag/i, /hotjar/i, /segment/i, /sentry/i,
  /recaptcha/i, /gstatic/i, /app-bridge/i, /extensions\.shopifycdn/i,
];
const MAX_IFRAMES_TO_PROCESS = 8;
const IFRAME_SNAPSHOT_TIMEOUT_MS = 3000;

// timingSafeCompare and isLoopbackAddress imported from lib/auth.js
const timingSafeCompare = _timingSafeCompare;
const isLoopbackAddress = _isLoopbackAddress;

// Custom error for stale/unknown element refs -- returned as 422 instead of 500
class StaleRefsError extends Error {
  constructor(ref, maxRef, totalRefs) {
    super(`Unknown ref: ${ref} (valid refs: e1-${maxRef}, ${totalRefs} total). Refs reset after navigation - call snapshot first.`);
    this.name = 'StaleRefsError';
    this.code = 'stale_refs';
    this.ref = ref;
  }
}

function safeError(err) {
  if (CONFIG.nodeEnv === 'production') {
    log('error', 'internal error', { error: err.message, stack: err.stack });
    return 'Internal server error';
  }
  return err.message;
}

// Send error response with appropriate status code (422 for stale refs, 500 otherwise)
function sendError(res, err, extraFields = {}) {
  const status = err instanceof StaleRefsError ? 422 : (err.statusCode || 500);
  const body = { error: safeError(err), ...extraFields };
  if (err instanceof StaleRefsError) {
    body.code = 'stale_refs';
    body.ref = err.ref;
  }
  if (err.code) body.code = err.code;
  if (err.code === 'policy_violation') {
    body.action = err.action;
    body.origin = err.origin;
    body.category = err.category;
    body.reason = err.reason;
  }
  if (err.handoff) body.handoff = err.handoff;
  if (err instanceof HumanizedInputError) {
    if (err.hit) body.hit = err.hit;
    if (err.delivered !== undefined) body.delivered = err.delivered;
    if (err.pointer) body.pointer = err.pointer;
    if (typeof err.retrySafe === 'boolean') body.retrySafe = err.retrySafe;
    if (err.hint) body.hint = err.hint;
  }
  // Report unexpected 500s to Sentry (skip intentional admission-control 503s)
  if (status >= 500 && !err.statusCode) {
    sentryCaptureException(err, {
      path: res.req?.originalUrl,
      method: res.req?.method,
      userId: res.req?.query?.userId || res.req?.body?.userId,
      reqId: res.req?.reqId,
    });
  }
  res.status(status).json(body);
}

function validateUrl(url) {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_URL_SCHEMES.includes(parsed.protocol)) {
      return `Blocked URL scheme: ${parsed.protocol} (only http/https allowed)`;
    }
    return null;
  } catch {
    return `Invalid URL: ${url}`;
  }
}

function policyForUser(userId, session = null) {
  const key = normalizeUserId(userId);
  return sessionPolicies.get(key) || session?.policy || null;
}

function recordSessionPolicyViolation({ userId, tabId = null, decision }) {
  const payload = {
    userId: normalizeUserId(userId),
    tabId,
    action: decision.action || 'unknown',
    origin: decision.origin || null,
    category: decision.category || 'policy',
    reason: decision.reason || 'denied',
  };
  policyViolationsTotal.labels(payload.action, payload.category).inc();
  pluginEvents.emit('session:policy:violation', payload);
  log('warn', 'session policy violation', payload);
}

function assertSessionPolicy({ userId, session = null, tabId = null, action, origin, dangerousCategory, enforceOrigin = true }) {
  const policy = policyForUser(userId, session);
  const decision = checkSessionPolicy(policy, { action, origin, dangerousCategory, enforceOrigin });
  if (decision.allowed) return decision;
  recordSessionPolicyViolation({ userId, tabId, decision });
  throw sessionPolicyViolationError(decision);
}

function canonicalPolicyAction(action) {
  const normalized = String(action || '').trim().toLowerCase();
  if (normalized === 'type_secret') return 'type';
  if (normalized === 'scrollintoview') return 'scroll';
  if (normalized === 'select_option') return 'select';
  if (normalized === 'uncheck') return 'check';
  return normalized;
}

function assertSemanticActionPolicy({ userId, session, tabId, action, node, snapshot }) {
  const frameUrl = node?.provenance?.frame?.url || snapshot?.url || null;
  const origin = originFromUrl(frameUrl);
  let dangerous = null;
  if (action?.kind === 'click') {
    dangerous = classifyDangerousAction({ kind: 'click', element: node?.name, role: node?.role, url: frameUrl });
  } else if (action?.kind === 'press' && isEnterKey(action?.key)) {
    dangerous = classifyDangerousAction({ kind: 'submit', element: node?.name, role: node?.role, url: frameUrl });
  }
  assertSessionPolicy({
    userId,
    session,
    tabId,
    action: canonicalPolicyAction(action?.kind),
    origin,
    dangerousCategory: dangerous?.category,
  });
}

function requestTabTarget(req) {
  const native = req.path.match(/^\/tabs\/([^/]+)(?:\/(.*))?$/);
  if (native && native[1] !== 'open' && native[1] !== 'group') {
    return { tabId: native[1], operation: native[2] || '' };
  }
  const targetId = req.body?.targetId || req.query?.targetId;
  return targetId ? { tabId: String(targetId), operation: null } : null;
}

function originForTabTarget(tabState, ref = null) {
  if (ref) {
    const target = resolveRefTarget(tabState.page, ref, tabState.refs);
    if (target.ok) return targetFrameOrigin(target);
    return null;
  }
  try { return originFromUrl(tabState.page.url()); } catch { return null; }
}

function enforceRequestSessionPolicy(req) {
  const userId = req.body?.userId ?? req.query?.userId;
  if (userId === undefined || userId === null || !policyForUser(userId, sessions.get(normalizeUserId(userId)))) return;
  const key = normalizeUserId(userId);
  const session = sessions.get(key) || null;

  const check = (action, { tabId = null, origin = null, enforceOrigin = true } = {}) => {
    if (!action) return;
    assertSessionPolicy({ userId: key, session, tabId, action: canonicalPolicyAction(action), origin, enforceOrigin });
  };

  if (req.path === '/tabs' && req.method === 'GET') {
    check('list_tabs', { enforceOrigin: false });
    return;
  }
  if ((req.path === '/tabs' || req.path === '/tabs/open') && req.method === 'POST') {
    check('create_tab', { enforceOrigin: false });
    if (req.body?.url) check('navigate', { origin: req.body.url });
    return;
  }
  if (req.path.startsWith('/tabs/group/') && req.method === 'DELETE') {
    check('close_tab', { enforceOrigin: false });
    return;
  }

  if (req.path === '/navigate') {
    check('navigate', { tabId: req.body?.targetId, origin: req.body?.url });
    return;
  }
  if (req.path === '/snapshot') {
    const found = session && findTab(session, req.query?.targetId);
    if (found) check('snapshot', { tabId: req.query.targetId, origin: originForTabTarget(found.tabState) });
    return;
  }
  if (req.path === '/act') {
    const found = session && findTab(session, req.body?.targetId);
    if (found) {
      check(req.body?.kind, {
        tabId: req.body.targetId,
        origin: originForTabTarget(found.tabState, req.body?.ref),
      });
    }
    return;
  }

  const target = requestTabTarget(req);
  if (!target) {
    return;
  }

  const found = session && findTab(session, target.tabId);
  if (!found) return;
  const { tabState } = found;
  const currentOrigin = originForTabTarget(tabState);
  const targetOrigin = originForTabTarget(tabState, req.body?.ref);
  const operation = target.operation || '';

  if (!operation && req.method === 'DELETE') {
    check('close_tab', { tabId: target.tabId, enforceOrigin: false });
    return;
  }
  if (operation === 'actions/plan' || operation === 'actions/execute') return;
  if (operation === 'hands') {
    for (const step of Array.isArray(req.body?.steps) ? req.body.steps : []) {
      check(step?.action, { tabId: target.tabId, origin: originForTabTarget(tabState, step?.ref) });
    }
    return;
  }
  if (operation === 'navigate') {
    if (req.body?.url) check('navigate', { tabId: target.tabId, origin: req.body.url });
    return;
  }
  if (operation === 'back' || operation === 'forward') {
    check('navigate', { tabId: target.tabId, origin: null });
    return;
  }
  if (operation === 'refresh') {
    check('navigate', { tabId: target.tabId, origin: currentOrigin });
    return;
  }

  const operationActions = {
    snapshot: 'snapshot', observe: 'observe', events: 'events', handoff: 'handoff', workflow: 'workflow',
    wait: 'wait', click: 'click', upload: 'upload', type: 'type', press: 'press', scroll: 'scroll',
    behavior: 'behavior', viewport: 'viewport', links: 'links', downloads: 'downloads', images: 'images',
    screenshot: 'screenshot', stats: 'stats', evaluate: 'evaluate', extract: 'extract',
  };
  const action = operationActions[operation];
  if (action) {
    check(action, { tabId: target.tabId, origin: req.body?.ref ? targetOrigin : currentOrigin });
  } else if (operation) {
    // Unknown plugin tab routes still inherit origin confinement. Their action
    // name remains default-allow unless core adds it to the validated schema.
    check(operation.replace(/[^a-z0-9]+/gi, '_'), { tabId: target.tabId, origin: currentOrigin });
  }
}

async function installSessionPolicyNavigationGuard(context, userId) {
  if (typeof context?.route !== 'function') return;
  await context.route('**/*', async route => {
    const request = route.request();
    if (!request.isNavigationRequest()) return route.continue();
    const policy = policyForUser(userId);
    const decision = checkSessionPolicy(policy, { action: 'navigate', origin: request.url() });
    if (decision.allowed) return route.continue();
    recordSessionPolicyViolation({ userId, decision });
    const key = normalizeUserId(userId);
    const record = { decision, at: Date.now() };
    recentPolicyNavigationViolations.set(key, record);
    const expiry = setTimeout(() => {
      if (recentPolicyNavigationViolations.get(key) === record) recentPolicyNavigationViolations.delete(key);
    }, 5000);
    expiry.unref();
    return route.abort('blockedbyclient');
  });
}

// isLoopbackAddress -- now imported from lib/auth.js (see top of file)

// Import cookies into a user's browser context (Playwright cookies format)
// POST /sessions/:userId/cookies { cookies: Cookie[] }
//
// SECURITY:
// Cookie injection moves this from "anonymous browsing" to "authenticated browsing".
/**
 * @openapi
 * /sessions/{userId}/cookies:
 *   post:
 *     tags: [Sessions]
 *     summary: Import cookies into a user session
 *     description: Import cookies for authenticated browsing. Requires BearerAuth in production.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: Session owner identifier.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [cookies]
 *             properties:
 *               cookies:
 *                 type: array
 *                 maxItems: 500
 *                 items:
 *                   type: object
 *                   required: [name, value, domain]
 *                   properties:
 *                     name:
 *                       type: string
 *                     value:
 *                       type: string
 *                     domain:
 *                       type: string
 *                     path:
 *                       type: string
 *                     expires:
 *                       type: number
 *                     httpOnly:
 *                       type: boolean
 *                     secure:
 *                       type: boolean
 *                     sameSite:
 *                       type: string
 *                       enum: [Strict, Lax, None]
 *     responses:
 *       200:
 *         description: Cookies imported.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 userId:
 *                   type: string
 *                 count:
 *                   type: integer
 *       400:
 *         description: Invalid cookie data.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Forbidden.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/sessions/:userId/cookies', authMiddleware(), express.json({ limit: '512kb' }), async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!req.body || !('cookies' in req.body)) {
      return res.status(400).json({ error: 'Missing "cookies" field in request body' });
    }
    const cookies = req.body.cookies;
    if (!Array.isArray(cookies)) {
      return res.status(400).json({ error: 'cookies must be an array' });
    }

    if (cookies.length > 500) {
      return res.status(400).json({ error: 'Too many cookies. Maximum 500 per request.' });
    }

    const invalid = [];
    for (let i = 0; i < cookies.length; i++) {
      const c = cookies[i];
      const missing = [];
      if (!c || typeof c !== 'object') {
        invalid.push({ index: i, error: 'cookie must be an object' });
        continue;
      }
      if (typeof c.name !== 'string' || !c.name) missing.push('name');
      if (typeof c.value !== 'string') missing.push('value');
      if (typeof c.domain !== 'string' || !c.domain) missing.push('domain');
      if (missing.length) invalid.push({ index: i, missing });
    }
    if (invalid.length) {
      return res.status(400).json({
        error: 'Invalid cookie objects: each cookie must include name, value, and domain',
        invalid,
      });
    }

    const allowedFields = ['name', 'value', 'domain', 'path', 'expires', 'httpOnly', 'secure', 'sameSite'];
    const sanitized = cookies.map(c => {
      const clean = {};
      for (const k of allowedFields) {
        if (c[k] !== undefined) clean[k] = c[k];
      }
      return clean;
    });

    const session = await getSession(userId);
    await session.context.addCookies(sanitized);
    const result = { ok: true, userId: String(userId), count: sanitized.length };
    log('info', 'cookies imported', { reqId: req.reqId, userId: String(userId), count: sanitized.length });
    pluginEvents.emit('session:cookies:import', { userId: String(userId), count: sanitized.length });
    res.json(result);
  } catch (err) {
    failuresTotal.labels(classifyError(err), 'set_cookies').inc();
    log('error', 'cookie import failed', { reqId: req.reqId, error: err.message });
    res.status(500).json({ error: safeError(err) });
  }
});

let browser = null;
let _lastBrowserPid = null; // Track PID independently for force-kill after close
let _browserClosePromise = null; // Shared promise for concurrent close serialization
let _lastBrowserRestartAt = 0; // Timestamp of last browser relaunch (for stale tab detection)
// userId -> { context, tabGroups: Map<sessionKey, Map<tabId, TabState>>, lastAccess }
// TabState = { page, refs: Map<refId, {role, name, nth}>, visitedUrls: Set, downloads: Array, toolCalls: number }
// Note: sessionKey was previously called listItemId - both are accepted for backward compatibility
const sessions = new Map();
// Runtime-only operator policy registry. Policies survive browser-session
// teardown during this process so recreating an identity cannot drop its lane.
const sessionPolicies = new Map();
const recentPolicyNavigationViolations = new Map();

const SESSION_TIMEOUT_MS = CONFIG.sessionTimeoutMs;
const MAX_SNAPSHOT_NODES = 500;
const TAB_INACTIVITY_MS = CONFIG.tabInactivityMs;
const MAX_SESSIONS = CONFIG.maxSessions;
const MAX_TABS_PER_SESSION = CONFIG.maxTabsPerSession;
const MAX_TABS_GLOBAL = CONFIG.maxTabsGlobal;
const HANDLER_TIMEOUT_MS = Math.min(10 * 60_000, Math.max(1_000, Number(CONFIG.handlerTimeoutMs) || 30_000));
const MAX_CONCURRENT_PER_USER = CONFIG.maxConcurrentPerUser;
const PAGE_CLOSE_TIMEOUT_MS = 5000;
const NAVIGATE_TIMEOUT_MS = CONFIG.navigateTimeoutMs;
const BUILDREFS_TIMEOUT_MS = selectAllowedDuration(
  CONFIG.buildrefsTimeoutMs,
  [1_000, 2_500, 5_000, 12_000, 30_000, 60_000],
  12_000,
);
const NATIVE_MEM_RESTART_THRESHOLD_MB = CONFIG.nativeMemRestartThresholdMb;
let _nativeMemBaseline = null; // RSS - heapUsed at first idle measurement
const FAILURE_THRESHOLD = 3;
const MAX_CONSECUTIVE_TIMEOUTS = 3;
const TAB_LOCK_TIMEOUT_MS = 35000; // Must be > HANDLER_TIMEOUT_MS so active op times out first



// Proper mutex for tab serialization. The old Promise-chain lock on timeout proceeded
// WITHOUT the lock, allowing concurrent Playwright operations that corrupt CDP state.
class TabLock {
  constructor() {
    this.queue = [];
    this.active = false;
  }

  acquire(timeoutMs) {
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null };
      entry.timer = setTimeout(() => {
        const idx = this.queue.indexOf(entry);
        if (idx !== -1) this.queue.splice(idx, 1);
        tabLockTimeoutsTotal.inc();
        refreshTabLockQueueDepth();
        reject(new Error('Tab lock queue timeout'));
      }, timeoutMs);
      this.queue.push(entry);
      refreshTabLockQueueDepth();
      this._tryNext();
    });
  }

  release() {
    this.active = false;
    this._tryNext();
    refreshTabLockQueueDepth();
  }

  _tryNext() {
    if (this.active || this.queue.length === 0) return;
    this.active = true;
    const entry = this.queue.shift();
    clearTimeout(entry.timer);
    refreshTabLockQueueDepth();
    entry.resolve();
  }

  drain() {
    this.active = true;
    for (const entry of this.queue) {
      clearTimeout(entry.timer);
      entry.reject(new Error('Tab destroyed'));
    }
    this.queue = [];
    refreshTabLockQueueDepth();
  }
}

// Per-tab locks to serialize operations on the same tab
const tabLocks = new Map(); // tabId -> TabLock

function getTabLock(tabId) {
  if (!tabLocks.has(tabId)) tabLocks.set(tabId, new TabLock());
  return tabLocks.get(tabId);
}

// Timeout is INSIDE the lock so each operation gets its full budget
// regardless of how long it waited in the queue.
async function withTabLock(tabId, operation, timeoutMs = HANDLER_TIMEOUT_MS, { onTimeout = null } = {}) {
  const lock = getTabLock(tabId);
  await lock.acquire(TAB_LOCK_TIMEOUT_MS);
  const operationPromise = Promise.resolve().then(operation);
  try {
    return await withTimeout(operationPromise, timeoutMs, 'action');
  } catch (error) {
    if (error?.code === 'operation_timeout') {
      if (onTimeout) await onTimeout(error).catch(() => {});
      // A timeout reports a deadline, not cancellation. Keep the lock until the
      // underlying operation settles so handoff cannot claim the tab is paused
      // while a timed-out mutation is still changing it.
      await operationPromise.catch(() => {});
    }
    throw error;
  } finally {
    lock.release();
  }
}

async function withTabMutationLock(tabId, tabState, operation, timeoutMs = HANDLER_TIMEOUT_MS) {
  return withTabLock(tabId, async () => {
    const handoff = pausedHandoff(tabState);
    if (handoff) throw handoffPausedError(handoff);
    return operation();
  }, timeoutMs, {
    onTimeout: async () => {
      const page = tabState?.page;
      if (!page || page.isClosed?.() || typeof page.close !== 'function') return;
      await withTimeout(
        page.close({ runBeforeUnload: false }),
        PAGE_CLOSE_TIMEOUT_MS,
        'timed-out mutation page close',
      );
    },
  });
}

async function withTabGroupMutationLocks(tabEntries, operation, index = 0) {
  if (index >= tabEntries.length) return operation();
  const [tabId, tabState] = tabEntries[index];
  return withTabMutationLock(tabId, tabState, () => withTabGroupMutationLocks(tabEntries, operation, index + 1));
}

const MAX_OPERATION_TIMEOUT_MS = 10 * 60_000;
const OPERATION_TIMEOUT_POLL_MS = 250;

async function withTimeout(promise, ms, label) {
  const timeoutMs = Number(ms);
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_OPERATION_TIMEOUT_MS) {
    throw new Error(`${label} timeout must be between 1 and ${MAX_OPERATION_TIMEOUT_MS}ms`);
  }
  let timer;
  try {
    const deadline = Date.now() + timeoutMs;
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setInterval(() => {
          if (Date.now() >= deadline) {
            clearInterval(timer);
            reject(Object.assign(new Error(`${label} timed out after ${timeoutMs}ms`), {
              code: 'operation_timeout',
            }));
          }
        }, OPERATION_TIMEOUT_POLL_MS);
      }),
    ]);
  } finally {
    clearInterval(timer);
  }
}

// Pointer dispatch can hang indefinitely inside the browser (#11). Bound it so
// a hung mouse action fails fast, with a code the central error handler can
// tell apart from a navigation stall (which signals a poisoned proxy session).
const MOUSE_DISPATCH_TIMEOUT_MS = 5000;
async function withInputDispatchTimeout(operation) {
  try {
    return await withTimeout(operation(), MOUSE_DISPATCH_TIMEOUT_MS, 'mouse sequence');
  } catch (err) {
    if (err.code === 'operation_timeout') err.code = 'input_dispatch_timeout';
    throw err;
  }
}

// Handed to lib/humanized-input.js so every humanized pointer dispatch gets the
// same 5s bound as the direct mouse sequence. Before this, a hung page.mouse call
// inside a humanized click ran into the 30s handler timeout and destroyed the session.
const boundedDispatch = (operation) => withInputDispatchTimeout(operation);

function requestTimeoutMs(baseMs = HANDLER_TIMEOUT_MS) {
  return proxyPool?.canRotateSessions ? Math.max(baseMs, 180000) : baseMs;
}

const userConcurrency = new Map();

async function withUserLimit(userId, operation) {
  const key = normalizeUserId(userId);
  let state = userConcurrency.get(key);
  if (!state) {
    state = { active: 0, queue: [] };
    userConcurrency.set(key, state);
  }
  if (state.active >= MAX_CONCURRENT_PER_USER) {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('User concurrency limit reached, try again')), 30000);
      state.queue.push(() => { clearTimeout(timer); resolve(); });
    });
  }
  state.active++;
  healthState.activeOps++;
  try {
    const result = await operation();
    healthState.lastSuccessfulNav = Date.now();
    return result;
  } finally {
    healthState.activeOps--;
    state.active--;
    if (state.queue.length > 0) {
      const next = state.queue.shift();
      next();
    }
    if (state.active === 0 && state.queue.length === 0) {
      userConcurrency.delete(key);
    }
  }
}

async function safePageClose(page) {
  if (!page || page.isClosed()) return;
  try {
    await Promise.race([
      page.close({ runBeforeUnload: false }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('page close timed out')), PAGE_CLOSE_TIMEOUT_MS)),
    ]);
  } catch (e) {
    log('warn', 'page close timed out or failed, force-closing', { error: e.message });
    try { await page.close({ runBeforeUnload: false }); } catch (_) {}
    page.removeAllListeners();
  }
}

// Detect host OS for fingerprint generation
function getHostOS() {
  const platform = os.platform();
  if (platform === 'darwin') return 'macos';
  if (platform === 'win32') return 'windows';
  return 'linux';
}

// Proxy strategy for outbound browsing.
const proxyPool = createProxyPool(CONFIG.proxy);

if (proxyPool) {
  log('info', 'proxy pool created', {
    mode: proxyPool.mode,
    host: proxyPool.canRotateSessions ? CONFIG.proxy.backconnectHost : CONFIG.proxy.host,
    ports: proxyPool.canRotateSessions ? [CONFIG.proxy.backconnectPort] : CONFIG.proxy.ports,
    poolSize: proxyPool.size,
    country: CONFIG.proxy.country || null,
    state: CONFIG.proxy.state || null,
    city: CONFIG.proxy.city || null,
  });
} else {
  log('info', 'no proxy configured');
}

const BROWSER_IDLE_TIMEOUT_MS = selectAllowedDuration(
  CONFIG.browserIdleTimeoutMs,
  [1_000, 30_000, 60_000, 300_000, 600_000, 1_800_000, 3_600_000],
  300_000,
);
let browserIdleTimer = null;
let browserLaunchPromise = null;
let browserWarmRetryTimer = null;

function scheduleBrowserIdleShutdown() {
  if (browserIdleTimer || sessions.size > 0 || !browser) return;
  browserIdleTimer = setTimeout(async () => {
    browserIdleTimer = null;
    if (sessions.size === 0 && browser) {
      log('info', 'browser idle shutdown (no sessions)');
      await closeBrowserFully('idle_shutdown');
    }
  }, BROWSER_IDLE_TIMEOUT_MS);
}

function clearBrowserIdleTimer() {
  if (browserIdleTimer) {
    clearTimeout(browserIdleTimer);
    browserIdleTimer = null;
  }
}

// Detects errors that retrying cannot recover from (e.g., Camoufox binary
// missing because postinstall was skipped). The user must run
// `npx camoufox-js fetch` and restart; looping on this wastes resources
// and buries the actionable error under noise.
//
// Sentinel: matches the human-readable message thrown by camoufox-js's
// FileNotFoundError in dist/pkgman.js (Version.fromPath). FileNotFoundError
// is not exported from the public API, so substring matching is the only
// available hook. If the upstream message changes, this regex needs an
// update; the dependency range in package.json controls exposure.
function isFatalInstallError(err) {
  return /Version information not found/i.test(err?.message || '');
}

function goliathInstallRemediation() {
  if (CONFIG.camoufoxExecutablePath) {
    return 'verify GOLIATH_EXECUTABLE points to a Camoufox bundle with properties.json, version.json, and fontconfig/';
  }
  return 'run `npx camoufox-js fetch` then restart the server';
}

function scheduleBrowserWarmRetry(delayMs = 5000) {
  if (browserWarmRetryTimer || browser || browserLaunchPromise) return;
  browserWarmRetryTimer = setTimeout(async () => {
    browserWarmRetryTimer = null;
    try {
      const start = Date.now();
      await ensureBrowser();
      log('info', 'background browser warm retry succeeded', { ms: Date.now() - start });
    } catch (err) {
      if (isFatalInstallError(err)) {
        log('error', 'browser unavailable: Goliath binaries are not installed; aborting retry loop', {
          error: err.message,
          remediation: goliathInstallRemediation(),
        });
        return;
      }
      log('warn', 'background browser warm retry failed', { error: err.message, nextDelayMs: delayMs });
      scheduleBrowserWarmRetry(Math.min(delayMs * 2, 30000));
    }
  }, delayMs);
}

// --- Browser health tracking ---
const healthState = {
  consecutiveNavFailures: 0,
  lastSuccessfulNav: Date.now(),
  isRecovering: false,
  activeOps: 0,
};

function recordNavSuccess() {
  healthState.consecutiveNavFailures = 0;
  healthState.lastSuccessfulNav = Date.now();
}

function recordNavFailure() {
  healthState.consecutiveNavFailures++;
  return healthState.consecutiveNavFailures >= FAILURE_THRESHOLD;
}

async function restartBrowser(reason) {
  if (healthState.isRecovering) return;
  healthState.isRecovering = true;
  browserRestartsTotal.labels(reason).inc();
  log('error', 'restarting browser', { reason, failures: healthState.consecutiveNavFailures });
  pluginEvents.emit('browser:restart', { reason });
  try {
    await closeAllSessions(`browser_restart:${reason}`, { clearDownloads: true, clearLocks: true });
    await closeBrowserFully(`browser_restart:${reason}`);
    pluginEvents.emit('browser:closed', { reason });
    browserLaunchPromise = null;
    await ensureBrowser();
    healthState.consecutiveNavFailures = 0;
    healthState.lastSuccessfulNav = Date.now();
    log('info', 'browser restarted successfully');
  } catch (err) {
    log('error', 'browser restart failed', { error: err.message });
  } finally {
    healthState.isRecovering = false;
  }
}

function getTotalTabCount() {
  let total = 0;
  for (const session of sessions.values()) {
    try {
      // Use real Playwright page count so leaked pages exert backpressure
      // on MAX_TABS_GLOBAL, surfacing leaks before Firefox starves.
      total += session.context.pages().length;
    } catch (_) {
      // Context is dead — fall back to bookkeeping count for this session.
      for (const group of session.tabGroups.values()) total += group.size;
    }
  }
  return total;
}

// Virtual display for WebGL support and fewer headless-only fingerprints.
// Xvfb gives Firefox a real X display with GLX, enabling software-rendered WebGL
// via Mesa llvmpipe. Without this, WebGL returns "no context" -- a massive bot signal.
let virtualDisplay = null;
let browserLaunchProxy = null;
let externalCamoufoxLaunch = null;

function getExternalGoliathLaunch() {
  if (!CONFIG.camoufoxExecutablePath) return null;
  if (!externalCamoufoxLaunch) {
    externalCamoufoxLaunch = prepareExternalCamoufoxExecutable(CONFIG.camoufoxExecutablePath, {
      cacheDir: CONFIG.camoufoxCacheDir,
    });
    log('info', 'using external Camoufox executable', {
      executablePath: externalCamoufoxLaunch.executablePath,
      resourceDir: externalCamoufoxLaunch.resourceDir,
    });
  }
  return externalCamoufoxLaunch;
}

async function probeGoogleSearch(candidateBrowser) {
  let context = null;
  try {
    context = await candidateBrowser.newContext({
      viewport: { width: 1280, height: 720 },
      permissions: ['geolocation'],
    });
    const page = await context.newPage();
    await page.goto('https://www.google.com/', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(1200);
    await page.goto('https://www.google.com/search?q=weather%20today', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(4000);

    const blocked = await isGoogleSearchBlocked(page);
    return {
      ok: !blocked && isGoogleSerp(page.url()),
      url: page.url(),
      blocked,
    };
  } finally {
    await context?.close().catch(() => {});
  }
}

function attachBrowserCleanup(candidateBrowser, localVirtualDisplay) {
  const origClose = candidateBrowser.close.bind(candidateBrowser);
  candidateBrowser.close = async (...args) => {
    await origClose(...args);
    browserLaunchProxy = null;
    if (localVirtualDisplay) {
      localVirtualDisplay.kill();
      if (virtualDisplay === localVirtualDisplay) virtualDisplay = null;
    }
  };
}

/**
 * Close browser with full process-tree cleanup. Handles the race where
 * browser.close() fails/hangs but process tree survives.
 *
 * Serialized: concurrent callers await the same promise (no double-close).
 *
 * Order: capture PID -> close browser -> force-kill survivors ->
 * clean temp profiles -> verify FD/handle drop.
 */
async function closeBrowserFully(reason) {
  if (_browserClosePromise) return _browserClosePromise;
  _browserClosePromise = _closeBrowserFullyImpl(reason);
  try {
    return await _browserClosePromise;
  } finally {
    _browserClosePromise = null;
  }
}

async function _closeBrowserFullyImpl(reason) {
  const b = browser;
  if (!b) return;
  clearBrowserIdleTimer();

  // Capture PID before nulling browser ref -- we need it for force-kill
  const pid = _lastBrowserPid;
  const preCloseFds = _countOpenFds();
  const preCloseHandles = _countActiveHandles();

  // Null the ref so new requests don't use a dying browser
  browser = null;
  _lastBrowserPid = null;

  // Close through Playwright (sends CDP Browser.close, then SIGKILL process group)
  let closeTimer;
  try {
    await Promise.race([
      b.close(),
      new Promise((_, reject) => { closeTimer = setTimeout(() => reject(new Error('browser.close() timeout')), 10000); }),
    ]);
  } catch (err) {
    log('warn', 'browser.close() failed or timed out', { reason, error: err.message, pid });
  } finally {
    clearTimeout(closeTimer);
  }

  // Force-kill browser survivors. Playwright's Firefox launcher can return no
  // process PID, so fall back to scanning the container for Goliath/Xvfb.
  if (pid) {
    await _forceKillProcessTree(pid, reason);
  }
  await _forceKillBrowserProcesses(reason, pid);

  // Clean up stale Firefox temp profiles (enable_cache: true accumulates data)
  try {
    const cleaned = cleanupStaleFirefoxProfiles();
    if (cleaned.removed > 0) {
      log('info', 'cleaned stale firefox profiles after browser close', cleaned);
    }
  } catch { /* best effort */ }

  // Reset native memory baseline so next browser measures from fresh
  reporter.resetNativeMemBaseline();
  _nativeMemBaseline = null;

  // Verify cleanup: check FD/handle counts dropped (after force-kill completes)
  const postCloseFds = _countOpenFds();
  const postCloseHandles = _countActiveHandles();
  if (postCloseFds !== null && preCloseFds !== null) {
    const fdDelta = postCloseFds - preCloseFds;
    // After close we expect fewer FDs. If more leaked, warn.
    if (fdDelta > 10) {
      log('warn', 'FD leak detected after browser close', {
        reason, preCloseFds, postCloseFds, delta: fdDelta,
        preCloseHandles, postCloseHandles,
      });
    }
  }
  log('info', 'browser closed fully', {
    reason, pid, preCloseFds, postCloseFds, preCloseHandles, postCloseHandles,
  });
}

/**
 * Force-kill a browser process tree by PID. On Linux, kills the process group
 * (SIGKILL -pid) then scans /proc for any orphaned children.
 */
async function _forceKillProcessTree(pid, reason) {
  if (!pid || pid <= 1) return;

  // Kill the specific browser process first (positive PID = single process)
  try {
    process.kill(pid, 'SIGKILL');
    log('info', 'sent SIGKILL to browser process', { pid, reason });
  } catch (err) {
    if (err.code !== 'ESRCH') {
      log('warn', 'failed to kill browser process', { pid, error: err.message });
    }
  }

  // Then try the process group (Playwright launches with detached:true on Linux,
  // making the browser a process group leader)
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // ESRCH = group doesn't exist (browser wasn't a group leader), which is fine
  }

  // Wait for kernel to reparent children to PID 1 before scanning
  await new Promise(r => setTimeout(r, 200));

  // On Linux: scan /proc for orphaned children that escaped the process group
  // (reparented to PID 1 by init/systemd, common with Firefox content processes).
  // Also checks PPid === Node PID for containerized environments without init.
  if (process.platform === 'linux') {
    const myPid = process.pid;
    // Snapshot the current browser PID to avoid killing a newly launched browser
    const currentBrowserPid = _lastBrowserPid;
    try {
      const procDirs = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
      const orphans = [];
      for (const procPid of procDirs) {
        const numPid = parseInt(procPid);
        // Never kill ourselves, the old PID (already killed), or the new browser
        if (numPid === myPid || numPid === pid || numPid === currentBrowserPid) continue;
        try {
          const status = fs.readFileSync(`/proc/${procPid}/status`, 'utf8');
          const ppidMatch = status.match(/PPid:\s+(\d+)/);
          const ppid = ppidMatch ? parseInt(ppidMatch[1]) : -1;
          // Orphaned to init (PID 1) or reparented to us (Node is PID 1 in containers)
          if (ppid === 1 || ppid === myPid) {
            const cmdline = fs.readFileSync(`/proc/${procPid}/cmdline`, 'utf8');
            // Firefox-specific: binary name or Gecko child process marker
            if (/firefox-esr|firefox|goliath|libxul\.so|GeckoChildProcess/i.test(cmdline)) {
              orphans.push(numPid);
            }
          }
        } catch { /* process vanished or permission denied */ }
      }
      if (orphans.length > 0) {
        log('warn', 'killing orphaned browser child processes', { orphans, reason });
        for (const orphanPid of orphans) {
          try { process.kill(orphanPid, 'SIGKILL'); } catch { /* already dead */ }
        }
      }
    } catch (err) {
      log('warn', 'failed to scan for orphaned browser processes', { error: err.message });
    }
  }

  // Give the OS a moment to reclaim resources
  await new Promise(r => setTimeout(r, 300));
}

async function _forceKillBrowserProcesses(reason, excludePid = null) {
  if (process.platform !== 'linux') return;
  const myPid = process.pid;
  const victims = [];
  try {
    const procDirs = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
    for (const procPid of procDirs) {
      const numPid = parseInt(procPid);
      if (numPid === myPid || numPid === excludePid) continue;
      try {
        const cmdline = fs.readFileSync(`/proc/${procPid}/cmdline`, 'utf8');
        if (/goliath-bin|\/usr\/bin\/Xvfb\b/.test(cmdline)) {
          victims.push(numPid);
        }
      } catch { /* process vanished or permission denied */ }
    }
  } catch (err) {
    log('warn', 'failed to scan for browser survivor processes', { reason, error: err.message });
    return;
  }

  if (victims.length > 0) {
    log('warn', 'killing browser survivor processes', { reason, victims });
    for (const victimPid of victims) {
      try { process.kill(victimPid, 'SIGKILL'); } catch { /* already dead */ }
    }
    await new Promise(r => setTimeout(r, 300));
  }
}

function _countOpenFds() {
  try {
    if (process.platform === 'linux') return fs.readdirSync('/proc/self/fd').length;
  } catch { /* unavailable */ }
  return null;
}

function _countActiveHandles() {
  try { return process._getActiveHandles().length; } catch { return null; }
}

// Camoufox's native cursor animation ("humanize") intermittently hangs pointer
// input at the browser boundary: page.mouse.move never resolves, the handler
// timeout fires, and the session is torn down (#11). Goliath's own humanized
// input layer (lib/humanized-input.js) provides humanized pointer/key cadence,
// so the native animation stays off unless explicitly re-enabled.
const NATIVE_HUMANIZE = process.env.GOLIATH_NATIVE_HUMANIZE === '1';

async function launchBrowserInstance() {
  const hostOS = getHostOS();
  const maxAttempts = proxyPool?.launchRetries ?? 1;
  let lastError = null;
  const externalGoliath = getExternalGoliathLaunch();

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const launchProxy = proxyPool
      ? proxyPool.getLaunchProxy(proxyPool.canRotateSessions ? `browser-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}` : undefined)
      : null;

    let localVirtualDisplay = null;
    let vdDisplay = undefined;
    let candidateBrowser = null;

    try {
      if (os.platform() === 'linux') {
        localVirtualDisplay = pluginCtx.createVirtualDisplay();
        vdDisplay = await localVirtualDisplay.get();
        log('info', 'xvfb virtual display started', { display: vdDisplay, attempt });
      }
    } catch (err) {
      log('warn', 'xvfb not available, falling back to headless', { error: err.message, attempt });
      localVirtualDisplay = null;
    }

    const useVirtualDisplay = !!vdDisplay;
    log('info', 'launching goliath', {
      hostOS,
      attempt,
      maxAttempts,
      geoip: !!launchProxy,
      proxyMode: proxyPool?.mode || null,
      proxyServer: launchProxy?.server || null,
      proxySession: launchProxy?.sessionId || null,
      proxyPoolSize: proxyPool?.size || 0,
      virtualDisplay: useVirtualDisplay,
    });

    try {
      const { launchOptions } = await import('camoufox-js');
      const options = await launchOptions({
        executable_path: externalGoliath?.executablePath,
        headless: useVirtualDisplay ? false : true,
        os: hostOS,
        humanize: NATIVE_HUMANIZE,
        enable_cache: true,
        proxy: launchProxy,
        geoip: !!launchProxy,
        virtual_display: vdDisplay,
      });
      options.proxy = normalizePlaywrightProxy(options.proxy);
      await pluginEvents.emitAsync('browser:launching', { options });

      candidateBrowser = await firefox.launch(options);

      if (proxyPool?.canRotateSessions) {
        const probe = await probeGoogleSearch(candidateBrowser);
        if (!probe.ok) {
          log('warn', 'browser launch google probe failed', {
            attempt,
            maxAttempts,
            proxySession: launchProxy?.sessionId || null,
            url: probe.url,
          });
          if (attempt < maxAttempts) {
            await candidateBrowser.close().catch(() => {});
            if (localVirtualDisplay) localVirtualDisplay.kill();
            continue;
          }
          // Last attempt: accept browser in degraded mode rather than death-spiraling.
          // Non-Google sites will still work; Google requests will get blocked responses.
          log('error', 'all proxy sessions Google-blocked, accepting browser in degraded mode', {
            maxAttempts,
            proxySession: launchProxy?.sessionId || null,
          });
        }
      }

      virtualDisplay = localVirtualDisplay;
      browserLaunchProxy = launchProxy;
      _lastBrowserPid = candidateBrowser.process?.()?.pid ?? null;
      browser = candidateBrowser; // publish AFTER PID is captured
      _lastBrowserRestartAt = Date.now();
      attachBrowserCleanup(browser, localVirtualDisplay);
      pluginEvents.emit('browser:launched', { browser, display: vdDisplay });

      log('info', 'goliath launched', {
        attempt,
        maxAttempts,
        virtualDisplay: useVirtualDisplay,
        proxyMode: proxyPool?.mode || null,
        proxyServer: launchProxy?.server || null,
        proxySession: launchProxy?.sessionId || null,
      });
      return browser;
    } catch (err) {
      lastError = err;
      log('warn', 'goliath launch attempt failed', {
        attempt,
        maxAttempts,
        error: err.message,
        proxySession: launchProxy?.sessionId || null,
      });
      await candidateBrowser?.close().catch(() => {});
      if (localVirtualDisplay) localVirtualDisplay.kill();
    }
  }

  throw lastError || new Error('Failed to launch a usable browser');
}

async function ensureBrowser() {
  clearBrowserIdleTimer();
  if (browser && !browser.isConnected()) {
    failuresTotal.labels('browser_disconnected', 'internal').inc();
    log('warn', 'browser disconnected, clearing dead sessions and relaunching', {
      deadSessions: sessions.size,
    });
    await closeAllSessions('browser_disconnected', { clearDownloads: true, clearLocks: true });
    await closeBrowserFully('browser_disconnected');
  }
  if (browser) return browser;
  if (browserLaunchPromise) return browserLaunchPromise;
  const launchTimeoutMs = proxyPool?.launchTimeoutMs ?? 60000;
  browserLaunchPromise = Promise.race([
    launchBrowserInstance(),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`Browser launch timeout (${Math.round(launchTimeoutMs / 1000)}s)`)), launchTimeoutMs)),
  ]).finally(() => { browserLaunchPromise = null; });
  return browserLaunchPromise;
}

// Helper to normalize userId to string (JSON body may parse as number)
function normalizeUserId(userId) {
  return String(userId);
}

const sessionCreations = new Map();
const sessionReservations = new SessionReservationRegistry();

function clearSessionLocks(session) {
  if (!session?.tabGroups) return;
  for (const [, group] of session.tabGroups) {
    for (const tabId of group.keys()) {
      const lock = tabLocks.get(tabId);
      if (lock) {
        lock.drain();
        tabLocks.delete(tabId);
      }
    }
  }
  refreshTabLockQueueDepth();
}

async function closeSession(userId, session, {
  reason = 'session_closed',
  clearDownloads = true,
  clearLocks = true,
} = {}) {
  if (!session) return;

  const key = normalizeUserId(userId);

  for (const [groupId, group] of session.tabGroups?.entries?.() || []) {
    for (const [tabId, tabState] of group) {
      const handoff = pausedHandoff(tabState);
      if (!handoff) continue;
      tabState.handoff = { ...handoff, status: 'terminated', completedAt: new Date().toISOString(), terminationReason: reason };
      log('warn', 'paused handoff terminated by unavoidable session teardown', { userId: key, groupId, tabId, reason });
      pluginEvents.emit('tab:handoff:terminated', { userId: key, groupId, tabId, handoff: tabState.handoff, reason });
    }
  }

  // Drain locks BEFORE closing context — queued operations get clean "Tab destroyed"
  // (410) instead of messy "Target page closed" (500) errors.
  if (clearLocks) {
    clearSessionLocks(session);
  }

  if (clearDownloads) {
    await clearSessionDownloads(session).catch(() => {});
  }

  for (const group of session.tabGroups?.values?.() || []) {
    for (const tabState of group.values()) {
      disposeTabState(tabState, reason);
    }
  }

  await pluginEvents.emitAsync('session:destroying', { userId: key, reason });
  if (session.tracePath) {
    try {
      await session.context.tracing.stop({ path: session.tracePath });
      log('info', 'tracing saved', { userId: key, path: session.tracePath });
    } catch (err) {
      log('warn', 'tracing.stop failed', { userId: key, error: err.message });
    }
  }

  await session.context.close().catch(() => {});
  removeSessionIfCurrent(sessions, key, session);
  await pluginEvents.emitAsync('session:destroyed', { userId: key, reason });

  refreshActiveTabsGauge();
}

async function closeAllSessions(reason, { clearDownloads = true, clearLocks = true } = {}) {
  const openSessions = Array.from(sessions.entries());
  for (const [userId, session] of openSessions) {
    await closeSession(userId, session, { reason, clearDownloads, clearLocks });
  }
}

async function closeReapableSession(userId, session, reason) {
  const key = normalizeUserId(userId);
  const tabEntries = Array.from(session.tabGroups?.values?.() || [])
    .flatMap(group => Array.from(group.entries()))
    .sort(([a], [b]) => a.localeCompare(b));
  let closed = false;
  try {
    await withTabGroupMutationLocks(tabEntries, async () => {
      if (sessions.get(key) !== session || !sessionCanBeReaped(session)) return;
      session._closing = true;
      await closeSession(key, session, { reason, clearDownloads: true, clearLocks: false });
      closed = true;
    });
  } catch (err) {
    if (err?.statusCode !== 423) log('warn', 'atomic session reaper skipped', { userId: key, reason, error: err.message });
  }
  if (closed) clearSessionLocks(session);
  return closed;
}

async function getSession(userId, { trace = false, storageState = null, reservation = null } = {}) {
  const key = normalizeUserId(userId);
  sessionReservations.assertAvailable(key, reservation);
  let session = sessions.get(key);
  if (reservation && session) {
    throw Object.assign(new Error('target session already exists'), { statusCode: 409, code: 'session_exists' });
  }
  
  // Check if existing session's context is still alive
  if (session) {
    if (session._closing) {
      // Session is being torn down by reaper/expiry -- treat as dead
      session = null;
    } else {
      try {
        // Lightweight probe: pages() is synchronous-ish and throws if context is dead
        session.context.pages();
      } catch (err) {
        log('warn', 'session context dead, recreating', { userId: key, error: err.message });
        await closeSession(key, session, { reason: 'dead_context', clearDownloads: true, clearLocks: true });
        session = null;
      }
    }
  }
  
  if (!session) {
    session = await coalesceInflight(sessionCreations, key, async () => {
      sessionReservations.assertAvailable(key, reservation);
      if (sessions.has(key)) {
        throw Object.assign(new Error('target session already exists'), { statusCode: 409, code: 'session_exists' });
      }
      if (sessions.size >= MAX_SESSIONS) {
        throw Object.assign(
          new Error('Maximum concurrent sessions reached'),
          { statusCode: 503, code: 'admission_rejected' }
        );
      }
      // Memory admission control (Fly.io only) — reject new sessions when
      // system memory is critically low. 503 tells Fly Proxy to try another machine.
      if (FLY_MACHINE_ID) {
        const freeMem = os.freemem();
        const totalMem = os.totalmem();
        if ((1 - freeMem / totalMem) >= 0.90) {
          log('warn', 'memory admission rejected', {
            usedPct: ((1 - freeMem / totalMem) * 100).toFixed(1),
            freeMb: Math.round(freeMem / 1048576),
            sessions: sessions.size,
          });
          throw Object.assign(
            new Error('Server memory pressure — try again shortly'),
            { statusCode: 503, code: 'admission_rejected' }
          );
        }
      }
      const b = await ensureBrowser();
      const contextOptions = {
        viewport: { width: 1280, height: 720 },
        permissions: ['geolocation'],
      };
      if (storageState) contextOptions.storageState = storageState;
      // When geoip is active (proxy configured), goliath auto-configures
      // locale/timezone/geolocation from the proxy IP. Without proxy, use defaults.
      if (!CONFIG.proxy.host) {
        contextOptions.locale = 'en-US';
        contextOptions.timezoneId = 'America/Los_Angeles';
        contextOptions.geolocation = { latitude: 37.7749, longitude: -122.4194 };
      }
      let sessionProxy = null;
      if (proxyPool?.canRotateSessions) {
        sessionProxy = proxyPool.getNext(`ctx-${key}-${crypto.randomUUID().replace(/-/g, '').slice(0, 8)}`);
        contextOptions.proxy = normalizePlaywrightProxy(sessionProxy);
        log('info', 'session proxy assigned', { userId: key, sessionId: sessionProxy.sessionId });
      } else if (proxyPool) {
        sessionProxy = proxyPool.getNext();
        contextOptions.proxy = normalizePlaywrightProxy(sessionProxy);
        log('info', 'session proxy assigned', { userId: key, proxy: sessionProxy.server });
      }
      await pluginEvents.emitAsync('session:creating', { userId: key, contextOptions });
      const context = await b.newContext(contextOptions);
      await installSessionPolicyNavigationGuard(context, key);
      await applyFingerprintCoherence(context);

      let tracePath = null;
      if (trace) {
        const traceDir = ensureTracesDir(CONFIG.tracesDir, key);
        tracePath = tracePathFor(CONFIG.tracesDir, key, makeTraceFilename());
        try {
          await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
          log('info', 'tracing enabled for session', { userId: key, traceDir, tracePath });
        } catch (err) {
          log('warn', 'tracing.start failed; session will not be traced', { userId: key, error: err.message });
          tracePath = null;
        }
      }

      const created = {
        context,
        tabGroups: new Map(),
        secrets: new Map(),
        policy: sessionPolicies.get(key) || null,
        lastAccess: Date.now(),
        activeOperations: 0,
        proxySessionId: sessionProxy?.sessionId || null,
        tracePath,
      };
      sessions.set(key, created);
      await pluginEvents.emitAsync('session:created', { userId: key, context });
      log('info', 'session created', {
        userId: key,
        proxyMode: proxyPool?.mode || null,
        proxyServer: sessionProxy?.server || browserLaunchProxy?.server || null,
        proxySession: sessionProxy?.sessionId || browserLaunchProxy?.sessionId || null,
      });
      return created;
    });
  }
  session.lastAccess = Date.now();
  return session;
}

function getTabGroup(session, listItemId) {
  let group = session.tabGroups.get(listItemId);
  if (!group) {
    group = new Map();
    session.tabGroups.set(listItemId, group);
  }
  return group;
}

function isDeadContextError(err) {
  const msg = err && err.message || '';
  return msg.includes('Target page, context or browser has been closed') ||
         msg.includes('browser has been closed') ||
         msg.includes('Context closed') ||
         msg.includes('Browser closed');
}

function isTimeoutError(err) {
  const msg = err && err.message || '';
  return msg.includes('timed out after') ||
         (msg.includes('Timeout') && msg.includes('exceeded'));
}

function isTabLockQueueTimeout(err) {
  return err && err.message === 'Tab lock queue timeout';
}

function isTabDestroyedError(err) {
  return err && err.message === 'Tab destroyed';
}

// Centralized error handler for route catch blocks.
// Auto-destroys dead browser sessions and returns appropriate status codes.
function isProxyError(err) {
  if (!err) return false;
  const msg = err.message || '';
  return msg.includes('NS_ERROR_PROXY') || msg.includes('proxy connection') || msg.includes('Proxy connection');
}

function handleRouteError(err, req, res, extraFields = {}) {
  const policyUserId = req.body?.userId || req.query?.userId;
  const recentPolicyViolation = policyUserId && recentPolicyNavigationViolations.get(normalizeUserId(policyUserId));
  if (recentPolicyViolation
      && Date.now() - recentPolicyViolation.at < 5000
      && /ERR_BLOCKED_BY_CLIENT|blockedbyclient/i.test(String(err?.message || ''))) {
    recentPolicyNavigationViolations.delete(normalizeUserId(policyUserId));
    return sendError(res, sessionPolicyViolationError(recentPolicyViolation.decision), extraFields);
  }
  const failureType = classifyError(err);
  const action = actionFromReq(req);
  failuresTotal.labels(failureType, action).inc();

  const userId = req.body?.userId || req.query?.userId;
  const tabId = req.body?.tabId || req.query?.tabId || req.params?.tabId;
  if (tabId) {
    pluginEvents.emit('tab:error', { userId, tabId, error: err });
  }
  if (userId && isDeadContextError(err)) {
    destroySession(userId, { reason: 'dead_context', force: true });
  }
  // Proxy errors mean the session is dead -- rotate at context level.
  // Destroy the user's session so the next request gets a fresh context with a new proxy.
  if (isProxyError(err) && proxyPool?.canRotateSessions && userId) {
    log('warn', 'proxy error detected, destroying user session for fresh proxy on next request', {
      action, userId, error: err.message,
    });
    browserRestartsTotal.labels('proxy_error').inc();
    destroySession(userId);
  }
  // Navigation-related timeouts can poison the proxy session (e.g., Cloudflare holding
  // the connection open for 30s). The browser context shares a single proxy session, so
  // one poisoned page kills all subsequent navigations in that context. Destroy the
  // entire session so the next request gets a fresh BrowserContext + proxy.
  const NAVIGATION_TIMEOUT_ACTIONS = new Set(['click', 'navigate', 'open_url']);
  // A hung pointer dispatch (#11) is a browser-side input failure, not a
  // poisoned proxy session -- keep the session and let the tab-level
  // consecutive-timeout accounting below handle it.
  const inputDispatchTimeout = err?.code === 'input_dispatch_timeout';
  if (isTimeoutError(err) && userId && NAVIGATION_TIMEOUT_ACTIONS.has(action) && !inputDispatchTimeout) {
    log('warn', 'navigation timeout — destroying session for fresh proxy', {
      action, userId, error: err.message,
    });
    browserRestartsTotal.labels('navigation_timeout').inc();
    destroySession(userId);
  }
  // Track consecutive timeouts per tab and auto-destroy stuck tabs
  // (for non-navigation timeouts like type, scroll that don't poison the proxy)
  if (userId && isTimeoutError(err) && (!NAVIGATION_TIMEOUT_ACTIONS.has(action) || inputDispatchTimeout)) {
    const tabId = req.body?.tabId || req.query?.tabId || req.params?.tabId;
    const session = sessions.get(normalizeUserId(userId));
    if (session && tabId) {
      const found = findTab(session, tabId);
      if (found) {
        found.tabState.consecutiveTimeouts++;
        if (found.tabState.consecutiveTimeouts >= MAX_CONSECUTIVE_TIMEOUTS) {
          log('warn', 'auto-destroying tab after consecutive timeouts', { tabId, count: found.tabState.consecutiveTimeouts });
          destroyTab(session, tabId, 'consecutive_timeouts', userId);
        }
      }
    }
  }
  // Lock queue timeout = tab is stuck. Destroy immediately.
  if (userId && isTabLockQueueTimeout(err)) {
    const session = sessions.get(normalizeUserId(userId));
    if (session && tabId) {
      destroyTab(session, tabId, 'lock_queue', userId);
    }
    return res.status(503).json({ error: 'Tab unresponsive and has been destroyed. Open a new tab.', code: 'tab_destroyed', ...extraFields });
  }
  // Tab was destroyed while this request was queued in the lock
  if (isTabDestroyedError(err)) {
    return res.status(410).json({ error: 'Tab was destroyed. Open a new tab.', ...extraFields });
  }
  // Dead context = session torn down (by proxy error, timeout, or reaper) while this op
  // was in flight. The ROOT CAUSE was already reported — this is a cascade error.
  // Return 503 (retriable) so the client retries with a fresh session.
  if (isDeadContextError(err)) {
    return res.status(503).json({ error: 'Browser session expired. Retry to get a fresh session.', code: 'session_expired', ...extraFields });
  }
  // --- Frustration detection: report when a tab hits a streak of failures ---
  // Individual failures are noise. 3+ consecutive = the site is persistently broken.
  const FRUSTRATION_TYPES = new Set(['timeout', 'dead_context', 'nav_aborted']);
  if (FRUSTRATION_TYPES.has(failureType) && userId && tabId) {
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (found) {
      const ts = found.tabState;
      ts.consecutiveFailures = (ts.consecutiveFailures || 0) + 1;
      if (!ts.failureJournal) ts.failureJournal = [];
      ts.failureJournal.push({ type: failureType, action, at: Date.now() });
      if (ts.failureJournal.length > 20) ts.failureJournal = ts.failureJournal.slice(-20);

      if (ts.consecutiveFailures === 3) {
        const _proxyErr = classifyProxyError(err?.message);
        reporter.reportHang(action, req.startTime ? Date.now() - req.startTime : 0, {
          error: err,
          healthSnapshot: ts.healthTracker ? ts.healthTracker.snapshot() : undefined,
          healthTracker: ts.healthTracker || null,
          resourceOpts: _resourceOpts(),
          proxy: proxyPool ? {
            configured: true,
            type: proxyPool.mode || null,
            authConfigured: !!CONFIG.proxy?.username,
            error: _proxyErr.proxyError,
            tlsError: _proxyErr.proxyTlsError,
          } : { configured: false },
          context: {
            failureType,
            consecutiveFailures: ts.consecutiveFailures,
            toolCalls: ts.toolCalls,
            journal: ts.failureJournal.map(j => `${j.type}:${j.action}`),
          },
        });
      }
    }
  }
  sendError(res, err, extraFields);
}

function destroyTab(session, tabId, reason, userId, { force = false } = {}) {
  const found = findTab(session, tabId);
  if (found && pausedHandoff(found.tabState) && !force) {
    log('warn', 'tab teardown skipped during human handoff', { tabId, userId: userId || null, reason });
    return false;
  }
  const lock = tabLocks.get(tabId);
  if (lock) {
    lock.drain();
    tabLocks.delete(tabId);
    refreshTabLockQueueDepth();
  }
  for (const [listItemId, group] of session.tabGroups) {
    if (group.has(tabId)) {
      const tabState = group.get(tabId);
      log('warn', 'destroying stuck tab', { tabId, listItemId, toolCalls: tabState.toolCalls, reason: reason || 'unknown' });
      disposeTabState(tabState, reason || 'destroyed');
      safePageClose(tabState.page);
      group.delete(tabId);
      if (group.size === 0) session.tabGroups.delete(listItemId);
      refreshActiveTabsGauge();
      if (reason) tabsDestroyedTotal.labels(reason).inc();
      pluginEvents.emit('tab:destroyed', { userId: userId || null, tabId, reason: reason || 'unknown' });
      return true;
    }
  }
  return false;
}

/**
 * Recycle the oldest (least-used) tab in a session to free a slot.
 * Closes the old tab's page and removes it from its group.
 * Returns { recycledTabId, recycledFromGroup } or null if no tab to recycle.
 */
async function recycleOldestTab(session, reqId, userId) {
  let oldestTab = null;
  let oldestGroup = null;
  let oldestGroupKey = null;
  let oldestTabId = null;
  for (const [gKey, group] of session.tabGroups) {
    for (const [tid, ts] of group) {
      if (pausedHandoff(ts)) continue;
      if (!oldestTab || ts.toolCalls < oldestTab.toolCalls) {
        oldestTab = ts;
        oldestGroup = group;
        oldestGroupKey = gKey;
        oldestTabId = tid;
      }
    }
  }
  if (!oldestTab) return null;

  disposeTabState(oldestTab, 'recycled');
  await safePageClose(oldestTab.page);
  oldestGroup.delete(oldestTabId);
  if (oldestGroup.size === 0) session.tabGroups.delete(oldestGroupKey);
  const lock = tabLocks.get(oldestTabId);
  if (lock) { lock.drain(); tabLocks.delete(oldestTabId); }
  refreshTabLockQueueDepth();
  tabsRecycledTotal.inc();
  pluginEvents.emit('tab:recycled', { userId: userId || null, tabId: oldestTabId });
  log('info', 'tab recycled (limit reached)', { reqId, recycledTabId: oldestTabId, recycledFromGroup: oldestGroupKey });
  return { recycledTabId: oldestTabId, recycledFromGroup: oldestGroupKey };
}

function destroySession(userId, { reason = 'destroy_session', force = false } = {}) {
  const key = normalizeUserId(userId);
  const session = sessions.get(key);
  if (!session) return false;
  const paused = findPausedHandoffInSession(session);
  if (paused && !force) {
    log('warn', 'session teardown skipped during human handoff', { userId: key, tabId: paused.tabId, reason });
    return false;
  }
  log('warn', 'destroying dead session', { userId: key, reason, force });
  sessions.delete(key);
  closeSession(key, session, { reason, clearDownloads: true, clearLocks: true }).catch(() => {});
  return true;
}

function findTab(session, tabId) {
  for (const [listItemId, group] of session.tabGroups) {
    if (group.has(tabId)) {
      const tabState = group.get(tabId);
      return { tabState, listItemId, group };
    }
  }
  return null;
}

// Return 404 or 410 depending on whether the browser restarted recently.
// 410 Gone tells clients the tab existed but the browser crashed — create a new one.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function tabNotFoundResponse(res, tabId) {
  // Only return 410 for tabs that look like valid UUIDs (plausibly created by this server),
  // belonged to this machine, and were lost in a recent browser restart.
  // Random/invalid strings like 'non-existent-tab' always get 404.
  if (_lastBrowserRestartAt && (Date.now() - _lastBrowserRestartAt < 300_000) && UUID_RE.test(tabId) && fly.isLocalTab(tabId)) {
    return res.status(410).json({
      error: 'Tab no longer exists (browser was restarted). Create a new tab.',
      code: 'browser_restarted',
    });
  }
  return res.status(404).json({ error: 'Tab not found' });
}

function createTabState(page) {
  const healthTracker = createTabHealthTracker(page);
  return {
    page,
    refs: new Map(),
    visitedUrls: new Set(),
    downloads: [],
    toolCalls: 0,
    consecutiveTimeouts: 0,
    consecutiveFailures: 0,
    failureJournal: [],
    healthTracker,
    lastSnapshot: null,
    lastRequestedUrl: null,
    googleRetryCount: 0,
    navigateAbort: null,
    pressureObservedAt: Date.now(),
    pressureObservedToolCalls: 0,
    pointer: null,
    behavior: createBehaviorTracker(),
    readinessTracker: createReadinessTracker(page),
    semanticSnapshots: new Map(),
    lastSemanticSnapshot: null,
    semanticListeners: new Set(),
    actionContracts: new Map(),
    workflowSteps: [],
    handoff: null,
  };
}

function disposeTabState(tabState, reason = 'closed') {
  if (!tabState || tabState._semanticDisposed) return;
  tabState._semanticDisposed = true;
  tabState.readinessTracker?.dispose?.();
  for (const listener of tabState.semanticListeners || []) {
    try { listener({ type: 'tab_closed', reason }); } catch {}
    try { listener.close?.(); } catch {}
  }
  tabState.semanticListeners?.clear?.();
  tabState.actionContracts?.clear?.();
}

const HANDOFF_BLOCKED_PATHS = new Set([
  '/navigate', '/click', '/type', '/press', '/scroll', '/viewport',
  '/back', '/forward', '/refresh', '/evaluate', '/actions/execute',
  '/hands', '/upload',
]);

app.use('/tabs/:tabId', (req, res, next) => {
  if (!HANDOFF_BLOCKED_PATHS.has(req.path)) return next();
  const userId = req.body?.userId || req.query?.userId;
  const session = userId && sessions.get(normalizeUserId(userId));
  const found = session && findTab(session, req.params.tabId);
  const handoff = found && pausedHandoff(found.tabState);
  if (handoff) {
    return res.status(423).json({ error: 'tab paused for human handoff', handoff });
  }

  // A successful legacy mutation invalidates the current semantic view and all
  // contracts planned against it. Semantic execution captures its own successor
  // snapshot atomically and therefore manages invalidation itself.
  if (found && req.path !== '/actions/execute') {
    res.once('finish', () => {
      if (res.statusCode < 400) {
        found.tabState.lastSemanticSnapshot = null;
        found.tabState.actionContracts.clear();
      }
    });
  }
  next();
});

/**
 * Attach a popup handler to a managed page so that popups (target=_blank,
 * window.open) become tracked tabs rather than orphaned pages. (JO-2456)
 *
 * The handler registers the popup in the same session's '__popups__' tab group
 * and recursively attaches itself to the new page.
 */
function attachPopupHandler(page, userId, sessionKey) {
  page.on('popup', (popupPage) => {
    const key = normalizeUserId(userId);
    const currentSession = sessions.get(key);
    if (!currentSession || currentSession._closing) return;

    const popupTabId = fly.makeTabId();
    const popupTabState = createTabState(popupPage);
    attachDownloadListener(popupTabState, popupTabId, log, pluginEvents, key);
    const popupGroup = getTabGroup(currentSession, sessionKey || '__popups__');
    popupGroup.set(popupTabId, popupTabState);
    currentSession.lastAccess = Date.now();
    refreshActiveTabsGauge();
    log('info', 'popup registered as managed tab', { userId: key, tabId: popupTabId, url: popupPage.url() });
    pluginEvents.emit('tab:created', { userId: key, tabId: popupTabId, page: popupPage, url: popupPage.url() });
    // Recursively handle popups from the popup
    attachPopupHandler(popupPage, userId, sessionKey);
  });
}

function pressureHash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

function pressureLockState(tabId) {
  const lock = tabLocks.get(tabId);
  return {
    active: Boolean(lock?.active),
    queued: Number(lock?.queue?.length || 0),
  };
}

async function goliathPressureCleanup(options = {}) {
  const now = Date.now();
  const minIdleMs = Math.max(0, Number(options.minIdleMs ?? 10 * 60 * 1000));
  const maxTabsToClose = Math.max(0, Number(options.maxTabsToClose ?? 4));
  const minTabsPerSession = Math.max(0, Number(options.minTabsPerSession ?? 1));
  const dryRun = options.dryRun !== false;
  const closeEmptySessions = options.closeEmptySessions !== false;
  const before = { sessions: sessions.size, tabs: getTotalTabCount() };
  const sessionTabCounts = new Map();
  for (const [userId, session] of sessions) {
    let count = 0;
    for (const group of session.tabGroups.values()) count += group.size;
    sessionTabCounts.set(userId, count);
  }
  const preserved = {
    handoff_paused: 0,
    locked: 0,
    session_minimum: 0,
    first_observation: 0,
    recently_active: 0,
    below_min_idle: 0,
  };
  const candidates = [];

  for (const [userId, session] of sessions) {
    for (const [listItemId, group] of session.tabGroups) {
      for (const [tabId, tabState] of group) {
        if (pausedHandoff(tabState)) {
          preserved.handoff_paused += 1;
          continue;
        }
        const lockState = pressureLockState(tabId);
        if (lockState.active || lockState.queued > 0) {
          preserved.locked += 1;
          continue;
        }

        if ((sessionTabCounts.get(userId) || 0) <= minTabsPerSession) {
          preserved.session_minimum += 1;
          continue;
        }

        if (!Number.isFinite(tabState.pressureObservedAt)) {
          tabState.pressureObservedAt = now;
          tabState.pressureObservedToolCalls = tabState.toolCalls;
          preserved.first_observation += 1;
          continue;
        }

        if (tabState.pressureObservedToolCalls !== tabState.toolCalls) {
          tabState.pressureObservedAt = now;
          tabState.pressureObservedToolCalls = tabState.toolCalls;
          preserved.recently_active += 1;
          continue;
        }

        const idleMs = now - tabState.pressureObservedAt;
        if (idleMs < minIdleMs) {
          preserved.below_min_idle += 1;
          continue;
        }

        candidates.push({
          userId,
          session,
          listItemId,
          group,
          tabId,
          tabState,
          idleMs,
          toolCalls: tabState.toolCalls,
        });
      }
    }
  }

  candidates.sort((a, b) => (b.idleMs - a.idleMs) || (a.toolCalls - b.toolCalls));
  const selected = candidates.slice(0, maxTabsToClose);
  const selectedSummary = selected.map((item) => ({
    session: pressureHash(item.userId),
    tab: pressureHash(item.tabId),
    group: pressureHash(item.listItemId),
    idleMs: item.idleMs,
    toolCalls: item.toolCalls,
  }));
  const closed = [];

  if (!dryRun) {
    for (const item of selected) {
      try {
        await withTabMutationLock(item.tabId, item.tabState, async () => {
          if (!item.group.has(item.tabId)) return;
          if ((sessionTabCounts.get(item.userId) || 0) <= minTabsPerSession) return;
          if (item.tabState.navigateAbort) item.tabState.navigateAbort.abort();
          await clearTabDownloads(item.tabState).catch(() => {});
          disposeTabState(item.tabState, 'pressure_cleanup');
          await safePageClose(item.tabState.page);
          item.group.delete(item.tabId);
          sessionTabCounts.set(item.userId, Math.max(0, (sessionTabCounts.get(item.userId) || 0) - 1));
          tabsReapedTotal.inc();
          pluginEvents.emit('tab:reaped', { userId: item.userId, tabId: item.tabId, listItemId: item.listItemId, reason: 'pressure_cleanup', idleMs: item.idleMs });
          log('info', 'tab reaped (pressure cleanup)', { userId: item.userId, tabId: item.tabId, listItemId: item.listItemId, idleMs: item.idleMs, toolCalls: item.toolCalls });
          closed.push({ session: pressureHash(item.userId), tab: pressureHash(item.tabId), group: pressureHash(item.listItemId), idleMs: item.idleMs, toolCalls: item.toolCalls });
        });
      } catch (err) {
        if (err?.statusCode !== 423) throw err;
        preserved.handoff_paused += 1;
      }
    }

    for (const [userId, session] of Array.from(sessions.entries())) {
      for (const [listItemId, group] of Array.from(session.tabGroups.entries())) {
        if (group.size === 0) session.tabGroups.delete(listItemId);
      }
      if (closeEmptySessions && session.tabGroups.size === 0 && sessionCanBeReaped(session)) {
        session._closing = true;
        await closeSession(userId, session, { reason: 'pressure_cleanup_empty_session', clearDownloads: true, clearLocks: true });
        sessionsExpiredTotal.inc();
        log('info', 'session closed (pressure cleanup empty)', { userId });
      }
    }

    refreshTabLockQueueDepth();
    refreshActiveTabsGauge();
    if (sessions.size === 0) scheduleBrowserIdleShutdown();
  }

  return {
    ok: true,
    dryRun,
    minIdleMs,
    maxTabsToClose,
    minTabsPerSession,
    before,
    candidates: candidates.length,
    selected: selectedSummary,
    closed,
    preserved,
    after: { sessions: sessions.size, tabs: getTotalTabCount() },
  };
}

async function isGoogleUnavailable(page) {
  if (!page || page.isClosed()) return false;
  const bodyText = await page.evaluate(() => document.body?.innerText?.slice(0, 600) || '').catch(() => '');
  return /Unable to connect|502 Bad Gateway or Proxy Error|Goliath can't establish a connection/.test(bodyText);
}

async function rotateGoogleTab(userId, sessionKey, tabId, previousTabState, reason, reqId) {
  if (!previousTabState?.lastRequestedUrl || !isGoogleSearchUrl(previousTabState.lastRequestedUrl)) return null;
  if ((previousTabState.googleRetryCount || 0) >= 3) return null;

  browserRestartsTotal.labels(reason).inc(); // track rotation events (not a full restart)

  // Rotate at context level -- create a fresh context with a new proxy session
  // instead of restarting the entire browser (which kills ALL sessions/tabs).
  const key = normalizeUserId(userId);
  const oldSession = sessions.get(key);
  if (oldSession) {
    await closeSession(key, oldSession, { reason: 'google_rotate_context', clearDownloads: true, clearLocks: true });
  }
  const session = await getSession(userId);
  const group = getTabGroup(session, sessionKey);
  const page = await session.context.newPage();
  const tabState = createTabState(page);
  tabState.googleRetryCount = (previousTabState.googleRetryCount || 0) + 1;
  tabState.lastRequestedUrl = previousTabState.lastRequestedUrl;
  attachDownloadListener(tabState, tabId, log, pluginEvents, userId);
  group.set(tabId, tabState);
  attachPopupHandler(page, userId, sessionKey);
  refreshActiveTabsGauge();

  log('warn', 'replaying google search on fresh context (per-context proxy rotation)', {
    reqId,
    tabId,
    retryCount: tabState.googleRetryCount,
    url: tabState.lastRequestedUrl,
    proxySession: session.proxySessionId || null,
  });

  await withPageLoadDuration('navigate', () => page.goto('https://www.google.com/', { waitUntil: 'domcontentloaded', timeout: 30000 }));
  tabState.visitedUrls.add('https://www.google.com/');
  await page.waitForTimeout(1200);
  await withPageLoadDuration('navigate', () => page.goto(tabState.lastRequestedUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }));
  tabState.visitedUrls.add(tabState.lastRequestedUrl);
  return { session, tabState };
}

function refreshActiveTabsGauge() {
  activeTabsGauge.set(getTotalTabCount());
}

function refreshTabLockQueueDepth() {
  let queued = 0;
  for (const lock of tabLocks.values()) {
    if (lock?.queue) queued += lock.queue.length;
  }
  tabLockQueueDepth.set(queued);
}

async function withPageLoadDuration(action, fn) {
  const end = pageLoadDuration.startTimer();
  try {
    return await fn();
  } finally {
    end();
  }
}



async function waitForPageReady(page, options = {}) {
  const {
    timeout = 10000,
    waitForNetwork = true,
    waitForHydration = true,
    settleMs = 200,
    hydrationPollMs = 250,
    hydrationTimeoutMs = Math.min(timeout, 10000),
  } = options;
  
  try {
    await page.waitForLoadState('domcontentloaded', { timeout });
    
    if (waitForNetwork) {
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {
        log('warn', 'networkidle timeout, continuing');
      });
    }
    
    if (waitForHydration) {
      const maxIterations = Math.max(1, Math.floor(hydrationTimeoutMs / hydrationPollMs));
      await page.evaluate(async ({ maxIterations, hydrationPollMs }) => {
        for (let i = 0; i < maxIterations; i++) {
          const entries = performance.getEntriesByType('resource');
          const recentEntries = entries.slice(-5);
          const netQuiet = recentEntries.every(e => (performance.now() - e.responseEnd) > 400);
          
          if (document.readyState === 'complete' && netQuiet) {
            await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
            break;
          }
          await new Promise(r => setTimeout(r, hydrationPollMs));
        }
      }, { maxIterations, hydrationPollMs }).catch(() => {
        log('warn', 'hydration wait failed, continuing');
      });
    }
    
    if (settleMs > 0) {
      await page.waitForTimeout(settleMs);
    }
    
    // Auto-dismiss common consent/privacy dialogs
    await dismissConsentDialogs(page);
    
    return true;
  } catch (err) {
    log('warn', 'page ready failed', { error: err.message });
    return false;
  }
}

async function dismissConsentDialogs(page) {
  // Common consent/privacy dialog selectors (matches Swift WebView.swift patterns)
  const dismissSelectors = [
    // OneTrust (very common)
    '#onetrust-banner-sdk button#onetrust-accept-btn-handler',
    '#onetrust-banner-sdk button#onetrust-reject-all-handler',
    '#onetrust-close-btn-container button',
    // Generic patterns
    'button[data-test="cookie-accept-all"]',
    'button[aria-label="Accept all"]',
    'button[aria-label="Accept All"]',
    'button[aria-label="Close"]',
    'button[aria-label="Dismiss"]',
    // Dialog close buttons
    'dialog button:has-text("Close")',
    'dialog button:has-text("Accept")',
    'dialog button:has-text("I Accept")',
    'dialog button:has-text("Got it")',
    'dialog button:has-text("OK")',
    // GDPR/CCPA specific
    '[class*="consent"] button[class*="accept"]',
    '[class*="consent"] button[class*="close"]',
    '[class*="privacy"] button[class*="close"]',
    '[class*="cookie"] button[class*="accept"]',
    '[class*="cookie"] button[class*="close"]',
    // Overlay close buttons
    '[class*="modal"] button[class*="close"]',
    '[class*="overlay"] button[class*="close"]',
  ];
  
  for (const selector of dismissSelectors) {
    try {
      const button = page.locator(selector).first();
      if (await button.isVisible({ timeout: 100 })) {
        await button.click({ timeout: 1000 }).catch(() => {});
        log('info', 'dismissed consent dialog', { selector });
        await page.waitForTimeout(300); // Brief pause after dismiss
        break; // Only dismiss one dialog per page load
      }
    } catch (e) {
      // Selector not found or not clickable, continue
    }
  }
}

// --- Google SERP detection ---
function isGoogleSerp(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.includes('google.') && parsed.pathname === '/search';
  } catch {
    return false;
  }
}

function isGoogleSearchUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.includes('google.') && parsed.pathname === '/search';
  } catch {
    return false;
  }
}

async function isGoogleSearchBlocked(page) {
  if (!page || page.isClosed()) return false;

  const url = page.url();
  if (url.includes('google.com/sorry/')) return true;

  const bodyText = await page.evaluate(() => document.body?.innerText?.slice(0, 600) || '').catch(() => '');
  return /Our systems have detected unusual traffic|About this page|If you're having trouble accessing Google Search|SG_REL/.test(bodyText);
}

// --- Google SERP: combined extraction (refs + snapshot in one DOM pass) ---
// Returns { refs: Map, snapshot: string }
async function extractGoogleSerp(page) {
  const refs = new Map();
  if (!page || page.isClosed()) return { refs, snapshot: '' };
  
  const start = Date.now();
  
  const alreadyRendered = await page.evaluate(() => !!document.querySelector('#rso h3, #search h3, #rso [data-snhf]')).catch(() => false);
  if (!alreadyRendered) {
    try {
      await page.waitForSelector('#rso h3, #search h3, #rso [data-snhf]', { timeout: 5000 });
    } catch {
      try {
        await page.waitForSelector('#rso a[href]:not([href^="/search"]), #search a[href]:not([href^="/search"])', { timeout: 2000 });
      } catch {}
    }
  }
  
  const extracted = await page.evaluate(() => {
    const snapshot = [];
    const elements = [];
    let refCounter = 1;

    function escapeQuotedSnapshotText(value) {
      return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]+/g, ' ');
    }
    
    function addRef(role, name) {
      const id = 'e' + refCounter++;
      elements.push({ id, role, name });
      return id;
    }
    
    snapshot.push('- heading "' + escapeQuotedSnapshotText(document.title) + '"');
    
    const searchInput = document.querySelector('input[name="q"], textarea[name="q"]');
    if (searchInput) {
      const name = 'Search';
      const refId = addRef('searchbox', name);
      snapshot.push('- searchbox "' + name + '" [' + refId + ']: ' + (searchInput.value || ''));
    }
    
    const navContainer = document.querySelector('div[role="navigation"], div[role="list"]');
    if (navContainer) {
      const navLinks = navContainer.querySelectorAll('a');
      if (navLinks.length > 0) {
        snapshot.push('- navigation:');
        navLinks.forEach(a => {
          const text = (a.textContent || '').trim();
          if (!text || text.length < 1) return;
          if (/^\d+$/.test(text) && parseInt(text) < 50) return;
          const refId = addRef('link', text);
          snapshot.push('  - link "' + text + '" [' + refId + ']');
        });
      }
    }
    
    const resultContainer = document.querySelector('#rso') || document.querySelector('#search');
    if (resultContainer) {
      const resultBlocks = resultContainer.querySelectorAll(':scope > div');
      for (const block of resultBlocks) {
        const h3 = block.querySelector('h3');
        const mainLink = h3 ? h3.closest('a') : null;
        
        if (h3 && mainLink) {
          const title = h3.textContent.trim();
          const href = mainLink.href;
          const cite = block.querySelector('cite');
          const displayUrl = cite ? cite.textContent.trim() : '';
          
          let snippet = '';
          for (const sel of ['[data-sncf]', '[data-content-feature="1"]', '.VwiC3b', 'div[style*="-webkit-line-clamp"]', 'span.aCOpRe']) {
            const el = block.querySelector(sel);
            if (el) { snippet = el.textContent.trim().slice(0, 300); break; }
          }
          if (!snippet) {
            const allText = block.textContent.trim().replace(/\s+/g, ' ');
            const titleLen = title.length + (displayUrl ? displayUrl.length : 0);
            if (allText.length > titleLen + 20) {
              snippet = allText.slice(titleLen).trim().slice(0, 300);
            }
          }
          
          const refId = addRef('link', title);
          snapshot.push('- link "' + escapeQuotedSnapshotText(title) + '" [' + refId + ']:');
          snapshot.push('  - /url: ' + href);
          if (displayUrl) snapshot.push('  - cite: ' + displayUrl);
          if (snippet) snapshot.push('  - text: ' + snippet);
        } else {
          const blockLinks = block.querySelectorAll('a[href^="http"]:not([href*="google.com/search"])');
          if (blockLinks.length > 0) {
            const blockText = block.textContent.trim().replace(/\s+/g, ' ').slice(0, 200);
            if (blockText.length > 10) {
              snapshot.push('- group:');
              snapshot.push('  - text: ' + blockText);
              blockLinks.forEach(a => {
                const linkText = (a.textContent || '').trim().slice(0, 100);
                if (linkText.length > 2) {
                  const refId = addRef('link', linkText);
                  snapshot.push('  - link "' + escapeQuotedSnapshotText(linkText) + '" [' + refId + ']:');
                  snapshot.push('    - /url: ' + a.href);
                }
              });
            }
          }
        }
      }
    }
    
    const paaItems = document.querySelectorAll('[jsname="Cpkphb"], div.related-question-pair');
    if (paaItems.length > 0) {
      snapshot.push('- heading "People also ask"');
      paaItems.forEach(q => {
        const text = (q.textContent || '').trim().slice(0, 150);
        if (text) {
          const refId = addRef('button', text);
          snapshot.push('  - button "' + escapeQuotedSnapshotText(text) + '" [' + refId + ']');
        }
      });
    }
    
    const nextLink = document.querySelector('#botstuff a[aria-label="Next page"], td.d6cvqb a, a#pnnext');
    if (nextLink) {
      const refId = addRef('link', 'Next');
      snapshot.push('- navigation "pagination":');
      snapshot.push('  - link "Next" [' + refId + ']');
    }
    
    return { snapshot: snapshot.join('\n'), elements };
  });
  
  const seenCounts = new Map();
  for (const el of extracted.elements) {
    const key = `${el.role}:${el.name}`;
    const nth = seenCounts.get(key) || 0;
    seenCounts.set(key, nth + 1);
    refs.set(el.id, { role: el.role, name: el.name, nth });
  }
  
  log('info', 'extractGoogleSerp', { elapsed: Date.now() - start, refs: refs.size });
  return { refs, snapshot: extracted.snapshot };
}

const REFRESH_READY_TIMEOUT_MS = 2500;
const frameKeys = new WeakMap();

function frameKeyFor(page, frame) {
  if (frame === page.mainFrame()) return 'main';
  let key = frameKeys.get(frame);
  if (!key) {
    key = `frame_${crypto.randomUUID()}`;
    frameKeys.set(frame, key);
  }
  return key;
}

async function buildRefs(page) {
  const refs = new Map();
  
  if (!page || page.isClosed()) {
    log('warn', 'buildRefs: page closed or invalid');
    return refs;
  }
  
  // Google SERP fast path -- skip ariaSnapshot entirely
  const url = page.url();
  if (isGoogleSerp(url)) {
    const { refs: googleRefs } = await extractGoogleSerp(page);
    return googleRefs;
  }
  
  const start = Date.now();
  
  // Hard total timeout on the entire buildRefs operation
  let timerId;
  const timeoutPromise = new Promise((_, reject) => {
    timerId = setTimeout(() => reject(new Error('buildRefs_timeout')), BUILDREFS_TIMEOUT_MS);
  });
  
  try {
    const result = await Promise.race([
      _buildRefsInner(page, refs, start),
      timeoutPromise
    ]);
    clearTimeout(timerId);
    return result;
  } catch (err) {
    clearTimeout(timerId);
    if (err.message === 'buildRefs_timeout') {
      log('warn', 'buildRefs: total timeout exceeded', { elapsed: Date.now() - start });
      return refs;
    }
    throw err;
  }
}

async function _buildRefsInner(page, refs, start) {
  await waitForPageReady(page, {
    timeout: REFRESH_READY_TIMEOUT_MS,
    waitForNetwork: false,
    waitForHydration: false,
    settleMs: 100,
  });
  
  // Budget remaining time for ariaSnapshot
  const elapsed = Date.now() - start;
  const remaining = BUILDREFS_TIMEOUT_MS - elapsed;
  if (remaining < 2000) {
    log('warn', 'buildRefs: insufficient time for ariaSnapshot', { elapsed });
    return refs;
  }
  
  const contexts = await captureAriaContexts(page, { mainTimeoutMs: Math.min(remaining - 1000, 5000) });
  return buildRefsFromContexts(contexts, refs);
}

function hasInteractiveAria(yaml) {
  return INTERACTIVE_ROLES.some(role => new RegExp(`^\\s*-\\s+${role}`, 'im').test(yaml));
}

async function captureAriaContexts(page, { mainTimeoutMs = 5000 } = {}) {
  if (!page || page.isClosed()) {
    return [];
  }
  await waitForPageReady(page, {
    timeout: REFRESH_READY_TIMEOUT_MS,
    waitForNetwork: false,
    waitForHydration: false,
    settleMs: 100,
  });
  const mainFrame = page.mainFrame();
  let mainYaml;
  try {
    mainYaml = await mainFrame.locator('body').ariaSnapshot({ timeout: mainTimeoutMs });
  } catch (err) {
    log('warn', 'getAriaSnapshot failed', { error: err.message });
    return [];
  }
  if (!mainYaml) return [];

  const contexts = [{
    frame: mainFrame,
    frameKey: 'main',
    frameName: null,
    frameUrl: mainFrame.url(),
    label: null,
    yaml: mainYaml,
  }];
  const childFrames = page.frames().filter(frame => frame !== mainFrame);
  let iframesProcessed = 0;
  for (const frame of childFrames) {
    if (iframesProcessed >= MAX_IFRAMES_TO_PROCESS) break;
    const frameUrl = frame.url();
    const frameName = frame.name();
    if (IFRAME_SKIP_PATTERNS.some(p => p.test(frameUrl) || p.test(frameName))) continue;
    try {
      const frameYaml = await frame.locator('body').ariaSnapshot({ timeout: IFRAME_SNAPSHOT_TIMEOUT_MS });
      if (!frameYaml || frameYaml.trim().length < 10) continue;
      if (!hasInteractiveAria(frameYaml)) continue;
      iframesProcessed++;
      let label = frameName || '';
      if (!label) {
        try { label = new URL(frameUrl).hostname; } catch { label = 'iframe'; }
      }
      label = label.replace(/card-fields-/, '').replace(/-[a-z0-9]{10,}$/, '');
      contexts.push({
        frame,
        frameKey: frameKeyFor(page, frame),
        frameName: frameName || null,
        frameUrl,
        label,
        yaml: frameYaml,
      });
    } catch (error) {
      log('debug', 'iframe snapshot failed', { frameName, error: error.message?.slice(0, 80) });
    }
  }
  return contexts;
}

function buildRefsFromContexts(contexts, refs = new Map()) {
  let refCounter = refs.size + 1;
  for (const context of contexts) {
    const seenCounts = new Map();
    for (const line of context.yaml.split('\n')) {
      if (refCounter > MAX_SNAPSHOT_NODES) return refs;
      const match = line.match(/^\s*-\s+(\w+)(?:\s+"([^"]*)")?/);
      if (!match) continue;
      const [, role, name] = match;
      const normalizedRole = role.toLowerCase();
      if (normalizedRole === 'combobox' || !INTERACTIVE_ROLES.includes(normalizedRole)) continue;
      if (name && SKIP_PATTERNS.some(pattern => pattern.test(name))) continue;
      const normalizedName = name || '';
      const key = `${normalizedRole}:${normalizedName}`;
      const nth = seenCounts.get(key) || 0;
      seenCounts.set(key, nth + 1);
      refs.set(`e${refCounter++}`, {
        role: normalizedRole,
        name: normalizedName,
        nth,
        frame: context.frame,
        frameKey: context.frameKey,
        frameName: context.frameName,
        frameUrl: context.frameUrl,
      });
    }
  }
  return refs;
}

function annotateAriaSnapshot(ariaYaml, refs, frameKey = 'main') {
  if (!ariaYaml || !(refs instanceof Map) || refs.size === 0) return ariaYaml || '';
  const refsByKey = new Map();
  for (const [refId, info] of refs) {
    refsByKey.set(`${info.frameKey || 'main'}:${info.role}:${info.name}:${info.nth}`, refId);
  }
  const counts = new Map();
  return ariaYaml.split('\n').map(line => {
    const match = line.match(/^(\s*-\s+)(\w+)(\s+"([^"]*)")?(.*)$/);
    if (!match) return line;
    const [, prefix, role, nameMatch, name, suffix] = match;
    const normalizedRole = role.toLowerCase();
    if (normalizedRole === 'combobox' || (name && SKIP_PATTERNS.some(pattern => pattern.test(name)))) return line;
    if (!INTERACTIVE_ROLES.includes(normalizedRole)) return line;
    const normalizedName = name || '';
    const countKey = `${normalizedRole}:${normalizedName}`;
    const nth = counts.get(countKey) || 0;
    counts.set(countKey, nth + 1);
    const refId = refsByKey.get(`${frameKey}:${normalizedRole}:${normalizedName}:${nth}`);
    return refId ? `${prefix}${role}${nameMatch || ''} [${refId}]${suffix}` : line;
  }).join('\n');
}

function formatAriaContexts(contexts, refs = null) {
  return contexts.map(context => {
    const yaml = refs ? annotateAriaSnapshot(context.yaml, refs, context.frameKey) : context.yaml;
    if (context.frameKey === 'main') return yaml;
    const marker = `[frame-key=${context.frameKey}] [frame-url=${encodeURIComponent(context.frameUrl || '')}]`;
    return `- iframe "${context.label || 'iframe'}" ${marker}:\n${yaml.split('\n').map(line => `  ${line}`).join('\n')}`;
  }).join('\n');
}

async function getAriaSnapshot(page) {
  const contexts = await captureAriaContexts(page);
  return contexts.length ? formatAriaContexts(contexts) : null;
}

function redactSecretValues(text, session) {
  let redacted = String(text || '');
  for (const secret of session?.secrets?.values?.() || []) {
    if (secret?.value) redacted = redacted.split(secret.value).join('[REDACTED_SECRET]');
  }
  return redacted;
}

async function captureSemanticObservation(tabState, { since = null, goalSelector = null, session = null } = {}) {
  const pageUrl = tabState.page.url();
  let annotatedYaml;
  if (isGoogleSerp(pageUrl)) {
    const google = await extractGoogleSerp(tabState.page);
    tabState.refs = google.refs;
    annotatedYaml = google.snapshot;
  } else {
    const contexts = await captureAriaContexts(tabState.page);
    tabState.refs = buildRefsFromContexts(contexts);
    annotatedYaml = formatAriaContexts(contexts, tabState.refs);
  }
  annotatedYaml = redactSecretValues(annotatedYaml, session);
  tabState.lastSnapshot = annotatedYaml;
  const readiness = await tabState.readinessTracker.sample({ goalSelector });
  const previous = (since && tabState.semanticSnapshots.get(since)) || tabState.lastSemanticSnapshot || null;
  const snapshot = buildSemanticSnapshot({ yaml: annotatedYaml, url: pageUrl, previous, readiness });
  tabState.semanticSnapshots.set(snapshot.snapshotId, snapshot);
  tabState.lastSemanticSnapshot = snapshot;
  while (tabState.semanticSnapshots.size > 10) {
    tabState.semanticSnapshots.delete(tabState.semanticSnapshots.keys().next().value);
  }
  const event = {
    type: 'semantic_snapshot',
    snapshotId: snapshot.snapshotId,
    baseSnapshotId: snapshot.baseSnapshotId,
    changes: snapshot.changes,
    readiness,
    capturedAt: snapshot.capturedAt,
  };
  for (const listener of tabState.semanticListeners) {
    try { listener(event); } catch { tabState.semanticListeners.delete(listener); }
  }
  return snapshot;
}

function refToLocator(page, ref, refs) {
  const target = resolveRefTarget(page, ref, refs);
  if (!target.ok) {
    log('warn', 'refToLocator: target unavailable', { ref, reason: target.reason });
    return null;
  }
  return target.locator;
}

async function refreshTabRefs(tabState, options = {}) {
  const {
    reason = 'refresh',
    timeoutMs = null,
    preserveExistingOnEmpty = true,
  } = options;

  const beforeUrl = tabState.page?.url?.() || '';
  const existingRefs = tabState.refs instanceof Map ? tabState.refs : new Map();
  const refreshPromise = buildRefs(tabState.page);

  let refreshedRefs;
  if (timeoutMs) {
    const timeoutLabel = `${reason}_refs_timeout`;
    refreshedRefs = await Promise.race([
      refreshPromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error(timeoutLabel)), timeoutMs)),
    ]);
  } else {
    refreshedRefs = await refreshPromise;
  }

  const afterUrl = tabState.page?.url?.() || beforeUrl;
  if (preserveExistingOnEmpty && refreshedRefs.size === 0 && existingRefs.size > 0 && beforeUrl === afterUrl) {
    log('warn', 'preserving previous refs after empty rebuild', {
      reason,
      url: afterUrl,
      previousRefs: existingRefs.size,
    });
    return existingRefs;
  }

  return refreshedRefs;
}


/**
 * @openapi
 * /health:
 *   get:
 *     tags: [System]
 *     summary: Health check
 *     description: Detailed health with tab/session counts and failure tracking.
 *     responses:
 *       200:
 *         description: Healthy.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 engine:
 *                   type: string
 *                 browserConnected:
 *                   type: boolean
 *                 browserRunning:
 *                   type: boolean
 *                 activeTabs:
 *                   type: integer
 *                 activeSessions:
 *                   type: integer
 *                 consecutiveFailures:
 *                   type: integer
 *       503:
 *         description: Unhealthy or recovering.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 recovering:
 *                   type: boolean
 */
app.get('/health', (req, res) => {
  if (healthState.isRecovering) {
    return res.status(503).json({ ok: false, engine: 'goliath', recovering: true });
  }
  const running = browser !== null && (browser.isConnected?.() ?? false);
  const mem = process.memoryUsage();
  const rssMb = Math.round(mem.rss / 1048576);
  const heapUsedMb = Math.round(mem.heapUsed / 1048576);
  const nativeMemMb = rssMb - heapUsedMb;
  res.json({ 
    ok: true, 
    engine: 'goliath',
    browserConnected: running,
    browserRunning: running,
    activeTabs: getTotalTabCount(),
    activeSessions: sessions.size,
    consecutiveFailures: healthState.consecutiveNavFailures,
    memory: { rssMb, heapUsedMb, nativeMemMb },
    ...(FLY_MACHINE_ID ? { machineId: FLY_MACHINE_ID } : {}),
  });
});

/**
 * @openapi
 * /metrics:
 *   get:
 *     tags: [System]
 *     summary: Prometheus metrics
 *     description: Returns Prometheus text exposition format. Requires PROMETHEUS_ENABLED=1.
 *     responses:
 *       200:
 *         description: Prometheus metrics.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       404:
 *         description: Metrics disabled.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/metrics', async (_req, res) => {
  const reg = getRegister();
  if (!reg) {
    res.status(404).json({ error: 'Prometheus metrics disabled. Set PROMETHEUS_ENABLED=1 to enable.' });
    return;
  }
  res.set('Content-Type', reg.contentType);
  res.send(await reg.metrics());
});

/**
 * @openapi
 * /pressure/cleanup:
 *   post:
 *     tags: [System]
 *     summary: Proactive memory-pressure cleanup
 *     description: |
 *       Closes tabs observed idle across multiple checks while preserving tabs
 *       with active/queued operations. Never returns URLs, titles, cookies,
 *       page text, or user IDs. Defaults to dry-run mode.
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               dryRun:
 *                 type: boolean
 *                 default: true
 *                 description: When true, returns candidates without closing them.
 *               minIdleMs:
 *                 type: number
 *                 default: 600000
 *                 description: Minimum idle time (ms) before a tab is eligible.
 *               maxTabsToClose:
 *                 type: number
 *                 default: 4
 *                 description: Maximum tabs to close per invocation.
 *               minTabsPerSession:
 *                 type: number
 *                 default: 1
 *                 description: Preserve at least this many tabs per session.
 *               closeEmptySessions:
 *                 type: boolean
 *                 default: true
 *                 description: Close sessions left with zero tabs after cleanup.
 *     responses:
 *       200:
 *         description: Cleanup result with before/after counts and hashed metadata.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 dryRun:
 *                   type: boolean
 *                 before:
 *                   type: object
 *                   properties:
 *                     sessions:
 *                       type: integer
 *                     tabs:
 *                       type: integer
 *                 after:
 *                   type: object
 *                   properties:
 *                     sessions:
 *                       type: integer
 *                     tabs:
 *                       type: integer
 *                 candidates:
 *                   type: integer
 *                 closed:
 *                   type: array
 *                   items:
 *                     type: object
 *                 preserved:
 *                   type: object
 */
app.post('/pressure/cleanup', authMiddleware(), async (req, res) => {
  try {
    const result = await goliathPressureCleanup(req.body || {});
    log('info', 'pressure cleanup', {
      dryRun: result.dryRun,
      beforeTabs: result.before.tabs,
      afterTabs: result.after.tabs,
      candidates: result.candidates,
      closed: result.closed.length,
      preserved: result.preserved,
    });
    res.json(result);
  } catch (err) {
    log('error', 'pressure cleanup failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Create new tab
/**
 * @openapi
 * /tabs:
 *   post:
 *     tags: [Tabs]
 *     summary: Create a new tab
 *     description: Creates a tab in the given session. Optionally navigates to an initial URL.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, sessionKey]
 *             properties:
 *               userId:
 *                 type: string
 *                 description: Session owner.
 *               sessionKey:
 *                 type: string
 *                 description: Tab group identifier.
 *               listItemId:
 *                 type: string
 *                 description: Legacy alias for sessionKey.
 *               url:
 *                 type: string
 *                 description: Optional initial URL.
 *               trace:
 *                 type: boolean
 *                 description: Enable Playwright tracing for this session (screenshots, DOM snapshots, network). Must be set on first tab creation; cannot be added to an existing session.
 *     responses:
 *       200:
 *         description: Tab created.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tabId:
 *                   type: string
 *                 url:
 *                   type: string
 *       400:
 *         description: Missing required fields.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Tab limit reached.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Cannot enable tracing on an existing session.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs', async (req, res) => {
  try {
    const { userId, sessionKey, listItemId, url, trace } = req.body;
    // Accept both sessionKey (preferred) and listItemId (legacy) for backward compatibility
    const resolvedSessionKey = sessionKey || listItemId;
    if (!userId || !resolvedSessionKey) {
      return res.status(400).json({ error: 'userId and sessionKey required' });
    }

    // Session overflow redirect (Fly.io only) — if this machine is above its
    // fair share of sessions and the user doesn't already have one here,
    // bounce back through the Fly Proxy to land on a less-loaded machine.
    if (FLY_MACHINE_ID) {
      const PER_MACHINE_SESSION_CAP = Math.max(3, Math.ceil(MAX_SESSIONS / 3));
      const key = normalizeUserId(userId);
      const isReplayed = !!req.headers['fly-replay-src'];
      if (sessions.size >= PER_MACHINE_SESSION_CAP && !sessions.has(key) && !isReplayed) {
        log('info', 'session overflow redirect', {
          userId: key, sessions: sessions.size, cap: PER_MACHINE_SESSION_CAP,
        });
        res.set('fly-replay', `app=${CONFIG.flyAppName || 'goliath'}`);
        return res.status(307).send();
      }
    }

    const result = await withTimeout((async () => {
      const existing = sessions.get(normalizeUserId(userId));
      if (trace && existing && !existing.tracePath) {
        throw Object.assign(
          new Error('trace must be set on session creation. DELETE /sessions/:userId first to restart with tracing.'),
          { statusCode: 409 },
        );
      }
      let session = await getSession(userId, { trace: !!trace });
      let activitySession = session;
      beginSessionActivity(activitySession);
      try {
        let totalTabs = 0;
        for (const group of session.tabGroups.values()) totalTabs += group.size;

        // Recycle oldest tab when limits are reached instead of rejecting
        if (totalTabs >= MAX_TABS_PER_SESSION || getTotalTabCount() >= MAX_TABS_GLOBAL) {
          const recycled = await recycleOldestTab(session, req.reqId, userId);
          if (!recycled) {
            throw Object.assign(new Error('Maximum tabs per session reached'), { statusCode: 429 });
          }
        }

        const group = getTabGroup(session, resolvedSessionKey);

        let page = await session.context.newPage();
        const tabId = fly.makeTabId();
        let tabState = createTabState(page);
        attachDownloadListener(tabState, tabId, log, pluginEvents, userId);
        group.set(tabId, tabState);
        attachPopupHandler(page, userId, resolvedSessionKey);
        refreshActiveTabsGauge();

        if (url) {
          const urlErr = validateUrl(url);
          if (urlErr) throw Object.assign(new Error(urlErr), { statusCode: 400 });
          tabState.lastRequestedUrl = url;
          try {
            await withPageLoadDuration('open_url', () => page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }));
          } catch (navErr) {
            if ((isProxyError(navErr) || isTimeoutError(navErr)) && proxyPool?.canRotateSessions) {
              log('warn', 'tab create navigate failed, retrying with fresh proxy', {
                reqId: req.reqId, tabId, error: navErr.message,
              });
              browserRestartsTotal.labels('proxy_retry').inc();
              const key = normalizeUserId(userId);
              const oldSession = sessions.get(key);
              if (oldSession) {
                endSessionActivity(activitySession);
                activitySession = null;
                await closeSession(key, oldSession, { reason: 'proxy_retry_rotate', clearDownloads: true, clearLocks: true });
              }
              session = await getSession(userId, { trace: !!trace });
              activitySession = session;
              beginSessionActivity(activitySession);
              const retryGroup = getTabGroup(session, resolvedSessionKey);
              const retryPage = await session.context.newPage();
              page = retryPage;
              tabState = createTabState(retryPage);
              tabState.lastRequestedUrl = url;
              attachDownloadListener(tabState, tabId, log, pluginEvents, userId);
              retryGroup.set(tabId, tabState);
              attachPopupHandler(retryPage, userId, resolvedSessionKey);
              refreshActiveTabsGauge();
              await withPageLoadDuration('open_url', () => retryPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }));
            } else {
              throw navErr;
            }
          }
          tabState.visitedUrls.add(url);
        }

        pluginEvents.emit('tab:created', { userId, tabId, page, url: page.url() });
        log('info', 'tab created', { reqId: req.reqId, tabId, userId, sessionKey: resolvedSessionKey, url: page.url() });
        return { tabId, url: page.url() };
      } finally {
        if (activitySession) endSessionActivity(activitySession);
      }
    })(), requestTimeoutMs(), 'tab create');

    res.json(result);
  } catch (err) {
    log('error', 'tab create failed', { reqId: req.reqId, error: err.message });
    // SSL certificate errors on initial navigation — non-retriable
    const isSslError = err.message && (
      err.message.includes('SEC_ERROR') ||
      err.message.includes('SSL_ERROR') ||
      err.message.includes('MOZILLA_PKIX_ERROR')
    );
    if (isSslError) {
      return res.status(502).json({
        error: `SSL certificate error: ${err.message.split('\n')[0]}`,
        code: 'ssl_error',
        recoverable: false,
      });
    }
    // Memory pressure / max sessions → bounce through LB to another machine
    if (FLY_MACHINE_ID && err.statusCode === 503) {
      res.set('fly-replay', `app=${CONFIG.flyAppName || 'goliath'}`);
      return res.status(503).json({ error: safeError(err), code: err.code || 'admission_rejected' });
    }
    handleRouteError(err, req, res);
  }
});

// Navigate
/**
 * @openapi
 * /tabs/{tabId}/navigate:
 *   post:
 *     tags: [Navigation]
 *     summary: Navigate a tab to a URL or macro
 *     description: Navigate to a URL or expand a search macro. Auto-creates tab if not found.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *               url:
 *                 type: string
 *               macro:
 *                 type: string
 *                 description: Search macro (e.g. @google_search).
 *               query:
 *                 type: string
 *                 description: Search query for macro.
 *               sessionKey:
 *                 type: string
 *               listItemId:
 *                 type: string
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Navigation result with snapshot.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/navigate', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId, url, macro, query, sessionKey, listItemId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });

    let session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, tabId);
    session.lastAccess = Date.now();

    const result = await withUserLimit(userId, () => withTimeout((async () => {
      await ensureBrowser();
      const resolvedSessionKey = sessionKey || listItemId || found.listItemId || 'default';
      let tabState = found.tabState;
      tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;

      let targetUrl = url;
      if (macro && macro !== '__NO__' && macro !== 'none' && macro !== 'null') {
        targetUrl = expandMacro(macro, query) || url;
      }
      
      if (!targetUrl) throw new Error('url or macro required');
      
      const urlErr = validateUrl(targetUrl);
      if (urlErr) throw new Error(urlErr);
      assertSessionPolicy({ userId, session, tabId, action: 'navigate', origin: targetUrl });
      
      return await withTabMutationLock(tabId, tabState, async () => {
        const currentSessionKey = found?.listItemId || resolvedSessionKey;
        const isGoogleSearch = isGoogleSearchUrl(targetUrl);

        const navigateCurrentPage = async () => {
          tabState.lastRequestedUrl = targetUrl;
          const ac = tabState.navigateAbort = new AbortController();
          const gotoP = withPageLoadDuration('navigate', () => tabState.page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }));
          try {
            await Promise.race([
              gotoP,
              new Promise((_, reject) => ac.signal.addEventListener('abort', () => reject(new Error('Navigation aborted: tab deleted')), { once: true })),
            ]);
            tabState.visitedUrls.add(targetUrl);
            tabState.lastSnapshot = null;
          } catch (err) {
            gotoP.catch(() => {}); // suppress unhandled rejection from still-pending goto
            throw err;
          } finally {
            tabState.navigateAbort = null;
          }
        };

        const prewarmGoogleHome = async () => {
          if (!isGoogleSearch || tabState.visitedUrls.has('https://www.google.com/')) return;
          await withPageLoadDuration('navigate', () => tabState.page.goto('https://www.google.com/', { waitUntil: 'domcontentloaded', timeout: 30000 }));
          tabState.visitedUrls.add('https://www.google.com/');
          await tabState.page.waitForTimeout(1200);
        };

        const recreateTabOnFreshContext = async () => {
          const previousRetryCount = tabState.googleRetryCount || 0;
          browserRestartsTotal.labels('google_search_block').inc();
          // Rotate at context level -- destroy this user's session and create
          // a fresh one with a new proxy session. Does NOT restart the browser.
          const key = normalizeUserId(userId);
          const oldSession = sessions.get(key);
          if (oldSession) {
            await closeSession(key, oldSession, { reason: 'google_blocked_context_rotate', clearDownloads: true, clearLocks: true });
          }
          session = await getSession(userId);
          const group = getTabGroup(session, currentSessionKey);
          const page = await session.context.newPage();
          tabState = createTabState(page);
          tabState.googleRetryCount = previousRetryCount + 1;
          attachDownloadListener(tabState, tabId, log, pluginEvents, userId);
          group.set(tabId, tabState);
          attachPopupHandler(page, userId, currentSessionKey);
          refreshActiveTabsGauge();
        };

        if (isGoogleSearch && proxyPool?.canRotateSessions) {
          await prewarmGoogleHome();
        }

        // Navigate with transparent retry on proxy/timeout errors.
        // If the proxy is blocked or the page times out, destroy the session,
        // get a fresh proxy, and retry once before failing to the caller.
        try {
          await navigateCurrentPage();
        } catch (navErr) {
          if ((isProxyError(navErr) || isTimeoutError(navErr)) && proxyPool?.canRotateSessions) {
            log('warn', 'navigate failed, retrying with fresh proxy session', {
              reqId: req.reqId, tabId, error: navErr.message,
            });
            browserRestartsTotal.labels('proxy_retry').inc();
            await recreateTabOnFreshContext();
            if (isGoogleSearch) await prewarmGoogleHome();
            await navigateCurrentPage();
          } else {
            throw navErr;
          }
        }

        if (isGoogleSearch && proxyPool?.canRotateSessions && await isGoogleSearchBlocked(tabState.page)) {
          log('warn', 'google search blocked, rotating browser proxy session', {
            reqId: req.reqId,
            tabId,
            url: tabState.page.url(),
            proxySession: browserLaunchProxy?.sessionId || null,
          });
          await recreateTabOnFreshContext();
          await prewarmGoogleHome();
          await navigateCurrentPage();
        }
        
        // For Google SERP: skip eager ref building during navigate.
        // Results render asynchronously after DOMContentLoaded -- the snapshot
        // call will wait for and extract them.
        if (isGoogleSerp(tabState.page.url())) {
          tabState.refs = new Map();
          return { ok: true, tabId, url: tabState.page.url(), refsAvailable: false, googleSerp: true };
        }

        if (isGoogleSearch && await isGoogleSearchBlocked(tabState.page)) {
          return { ok: false, tabId, url: tabState.page.url(), refsAvailable: false, googleBlocked: true };
        }
        
        tabState.refs = await buildRefs(tabState.page);
        return { ok: true, tabId, url: tabState.page.url(), refsAvailable: tabState.refs.size > 0 };
      }, requestTimeoutMs());
    })(), requestTimeoutMs(), 'navigate'));
    
    log('info', 'navigated', { reqId: req.reqId, tabId, url: result.url });
    pluginEvents.emit('tab:navigated', { userId: req.body.userId, tabId, url: result.url, prevUrl: null });
    res.json(result);
  } catch (err) {
    log('error', 'navigate failed', { reqId: req.reqId, tabId, error: err.message });
    const is400 = err.message && (err.message.startsWith('Blocked URL scheme') || err.message === 'url or macro required');
    if (is400) {
      return res.status(400).json({ error: safeError(err) });
    }
    // SSL certificate errors — site has a bad/self-signed cert. Non-retriable.
    const isSslError = err.message && (
      err.message.includes('SEC_ERROR') ||
      err.message.includes('SSL_ERROR') ||
      err.message.includes('MOZILLA_PKIX_ERROR')
    );
    if (isSslError) {
      return res.status(502).json({
        error: `SSL certificate error: ${err.message.split('\n')[0]}`,
        code: 'ssl_error',
        recoverable: false,
      });
    }
    handleRouteError(err, req, res);
  }
});

// Snapshot
/**
 * @openapi
 * /tabs/{tabId}/snapshot:
 *   get:
 *     tags: [Content]
 *     summary: Accessibility snapshot
 *     description: Returns accessibility tree with element refs. Supports pagination via offset.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *       - name: format
 *         in: query
 *         schema:
 *           type: string
 *           enum: [text, json]
 *           default: text
 *       - name: offset
 *         in: query
 *         schema:
 *           type: integer
 *         description: Character offset for paginated retrieval.
 *       - name: filter
 *         in: query
 *         schema:
 *           type: string
 *           enum: [interactive]
 *         description: >-
 *           Reduce the snapshot to agent-actionable content before windowing:
 *           lines with element refs, iframe boundaries, headings, and their
 *           tree ancestors. Refs remain valid; text-only content is dropped.
 *           Pagination offsets refer to the filtered text.
 *       - name: maxChars
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 2000
 *           maximum: 80000
 *         description: Per-request window budget in characters (default 80000).
 *       - name: includeScreenshot
 *         in: query
 *         schema:
 *           type: string
 *           enum: ['true', 'false']
 *     responses:
 *       200:
 *         description: Snapshot.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 url:
 *                   type: string
 *                 snapshot:
 *                   type: string
 *                 refsCount:
 *                   type: integer
 *                 truncated:
 *                   type: boolean
 *                 totalChars:
 *                   type: integer
 *                 hasMore:
 *                   type: boolean
 *                 nextOffset:
 *                   type: integer
 *                 filter:
 *                   type: string
 *                   description: Present when a filter was applied.
 *                 fullChars:
 *                   type: integer
 *                   description: Unfiltered snapshot length, for measuring savings.
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/snapshot', async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const format = req.query.format || 'text';
    const offset = parseInt(req.query.offset) || 0;
    const filter = req.query.filter;
    if (filter !== undefined && filter !== 'interactive') {
      return res.status(400).json({ error: "filter must be 'interactive'" });
    }
    const windowChars = clampSnapshotWindow(req.query.maxChars);
    const applyFilter = (yaml) => {
      if (filter !== 'interactive') return { yaml, extra: {} };
      const filtered = filterInteractive(yaml);
      return { yaml: filtered.text, extra: { filter: 'interactive', fullChars: filtered.fullChars } };
    };
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;

    // Cached chunk retrieval for offset>0 requests
    if (offset > 0 && tabState.lastSnapshot) {
      const cached = applyFilter(tabState.lastSnapshot);
      const win = windowSnapshot(cached.yaml, offset, windowChars);
      const response = { url: tabState.page.url(), snapshot: win.text, refsCount: tabState.refs.size, truncated: win.truncated, totalChars: win.totalChars, hasMore: win.hasMore, nextOffset: win.nextOffset, ...cached.extra };
      if (req.query.includeScreenshot === 'true') {
        const pngBuffer = await tabState.page.screenshot({ type: 'png' });
        response.screenshot = { data: pngBuffer.toString('base64'), mimeType: 'image/png' };
      }
      log('info', 'snapshot (cached offset)', { reqId: req.reqId, tabId: req.params.tabId, offset, totalChars: win.totalChars });
      return res.json(response);
    }

    const result = await withUserLimit(userId, () => withTimeout((async () => {
      if (proxyPool?.canRotateSessions && isGoogleSearchUrl(tabState.lastRequestedUrl || '')) {
        const blocked = await isGoogleSearchBlocked(tabState.page);
        const unavailable = !blocked && await isGoogleUnavailable(tabState.page);
        if (blocked || unavailable) {
          const rotated = await rotateGoogleTab(userId, found.listItemId, req.params.tabId, tabState, blocked ? 'google_search_block_snapshot' : 'google_search_unavailable_snapshot', req.reqId);
          if (rotated) {
            tabState.page = rotated.tabState.page;
            tabState.refs = rotated.tabState.refs;
            tabState.visitedUrls = rotated.tabState.visitedUrls;
            tabState.downloads = rotated.tabState.downloads;
            tabState.toolCalls = rotated.tabState.toolCalls;
            tabState.consecutiveTimeouts = rotated.tabState.consecutiveTimeouts;
            tabState.lastSnapshot = rotated.tabState.lastSnapshot;
            tabState.lastRequestedUrl = rotated.tabState.lastRequestedUrl;
            tabState.googleRetryCount = rotated.tabState.googleRetryCount;
          }
        }
      }

      const pageUrl = tabState.page.url();
      
      // Google SERP fast path -- DOM extraction instead of ariaSnapshot
      if (isGoogleSerp(pageUrl)) {
        const { refs: googleRefs, snapshot: googleSnapshot } = await extractGoogleSerp(tabState.page);
        tabState.refs = googleRefs;
        tabState.lastSnapshot = googleSnapshot;
        snapshotBytes.labels('google_serp').observe(Buffer.byteLength(googleSnapshot, 'utf8'));
        const serp = applyFilter(googleSnapshot);
        const win = windowSnapshot(serp.yaml, 0, windowChars);
        const response = {
          url: pageUrl,
          snapshot: win.text,
          refsCount: tabState.refs.size,
          truncated: win.truncated,
          totalChars: win.totalChars,
          hasMore: win.hasMore,
          nextOffset: win.nextOffset,
          ...serp.extra,
        };
        if (req.query.includeScreenshot === 'true') {
          const pngBuffer = await tabState.page.screenshot({ type: 'png' });
          response.screenshot = { data: pngBuffer.toString('base64'), mimeType: 'image/png' };
        }
        return response;
      }

      const ariaContexts = await captureAriaContexts(tabState.page);
      tabState.refs = buildRefsFromContexts(ariaContexts);
      const annotatedYaml = redactSecretValues(formatAriaContexts(ariaContexts, tabState.refs), session);

      tabState.lastSnapshot = annotatedYaml;
      if (annotatedYaml) snapshotBytes.labels('full').observe(Buffer.byteLength(annotatedYaml, 'utf8'));
      const fresh = applyFilter(annotatedYaml);
      const win = windowSnapshot(fresh.yaml, 0, windowChars);

      const response = {
        url: tabState.page.url(),
        snapshot: win.text,
        refsCount: tabState.refs.size,
        truncated: win.truncated,
        totalChars: win.totalChars,
        hasMore: win.hasMore,
        nextOffset: win.nextOffset,
        ...fresh.extra,
      };

      if (req.query.includeScreenshot === 'true') {
        const pngBuffer = await tabState.page.screenshot({ type: 'png' });
        response.screenshot = { data: pngBuffer.toString('base64'), mimeType: 'image/png' };
      }

      return response;
    })(), requestTimeoutMs(), 'snapshot'));

    pluginEvents.emit('tab:snapshot', { userId: req.query.userId, tabId: req.params.tabId, snapshot: result.snapshot });
    log('info', 'snapshot', { reqId: req.reqId, tabId: req.params.tabId, url: result.url, snapshotLen: result.snapshot?.length, refsCount: result.refsCount, hasScreenshot: !!result.screenshot, truncated: result.truncated });
    res.json(result);
  } catch (err) {
    log('error', 'snapshot failed', { reqId: req.reqId, tabId: req.params.tabId, error: err.message });
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /tabs/{tabId}/observe:
 *   post:
 *     tags: [Content]
 *     summary: Capture versioned semantic state
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId: { type: string }
 *               since: { type: string }
 *               goalSelector: { type: string }
 *     responses:
 *       200:
 *         description: Semantic snapshot with stable identities, diffs, readiness, and provenance.
 *       404:
 *         description: Tab not found.
 */
app.post('/tabs/:tabId/observe', express.json({ limit: '256kb' }), async (req, res) => {
  try {
    const { userId, since = null, goalSelector = null } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId);
    session.lastAccess = Date.now();
    const snapshot = await withUserLimit(userId, () => withTabLock(req.params.tabId, () =>
      withTimeout(captureSemanticObservation(found.tabState, { since, goalSelector, session }), requestTimeoutMs(), 'semantic_observe')
    ));
    pluginEvents.emit('tab:semantic', { userId, tabId: req.params.tabId, snapshotId: snapshot.snapshotId, changes: snapshot.changes.length });
    res.json(snapshot);
  } catch (err) {
    log('error', 'semantic observe failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /tabs/{tabId}/events:
 *   get:
 *     tags: [Content]
 *     summary: Subscribe to semantic change events
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *       - name: userId
 *         in: query
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Server-sent event stream.
 *         content:
 *           text/event-stream:
 *             schema: { type: string }
 *       404:
 *         description: Tab not found.
 */
app.get('/tabs/:tabId/events', async (req, res) => {
  const userId = req.query.userId;
  const session = userId && sessions.get(normalizeUserId(userId));
  const found = session && findTab(session, req.params.tabId);
  if (!found) return tabNotFoundResponse(res, req.params.tabId);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();
  const send = event => res.write(`event: semantic\ndata: ${JSON.stringify(event)}\n\n`);
  send.close = () => res.end();
  found.tabState.semanticListeners.add(send);
  send({ type: 'connected', snapshotId: found.tabState.lastSemanticSnapshot?.snapshotId || null });
  const heartbeat = runtimeInterval(() => res.write(': keepalive\n\n'), 15_000);
  req.on('close', () => {
    clearInterval(heartbeat);
    found.tabState.semanticListeners.delete(send);
  });
});

/**
 * @openapi
 * /tabs/{tabId}/handoff:
 *   get:
 *     tags: [Browser]
 *     summary: Get human handoff status
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *       - name: userId
 *         in: query
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Current handoff state. }
 *       404: { description: Tab not found. }
 *   post:
 *     tags: [Browser]
 *     summary: Pause for or resume after human handoff
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, action]
 *             properties:
 *               userId: { type: string }
 *               action: { type: string, enum: [request, resume, cancel] }
 *               reason: { type: string }
 *     responses:
 *       200: { description: Updated handoff state. }
 *       404: { description: Tab not found. }
 */
app.get('/tabs/:tabId/handoff', async (req, res) => {
  const session = req.query.userId && sessions.get(normalizeUserId(req.query.userId));
  const found = session && findTab(session, req.params.tabId);
  if (!found) return tabNotFoundResponse(res, req.params.tabId);
  res.json({ handoff: found.tabState.handoff, vncPluginRequired: true });
});

app.post('/tabs/:tabId/handoff', async (req, res) => {
  try {
    const { userId, action, reason = 'human assistance requested' } = req.body;
    const session = userId && sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId);
    if (!['request', 'resume', 'cancel'].includes(action)) return res.status(400).json({ error: 'action must be request, resume, or cancel' });
    const handoff = await withTabLock(req.params.tabId, async () => {
      const current = sessions.get(normalizeUserId(userId));
      const lockedFound = current && findTab(current, req.params.tabId);
      if (!lockedFound || lockedFound.tabState !== found.tabState) {
        throw Object.assign(new Error('Tab not found'), { statusCode: 404, code: 'tab_not_found' });
      }
      const previous = lockedFound.tabState.handoff;
      lockedFound.tabState.handoff = action === 'request' ? {
        handoffId: `handoff_${crypto.randomUUID()}`,
        status: 'paused',
        reason,
        requestedAt: new Date().toISOString(),
      } : {
        ...(previous || { handoffId: `handoff_${crypto.randomUUID()}`, requestedAt: new Date().toISOString() }),
        status: action === 'resume' ? 'resumed' : 'cancelled',
        completedAt: new Date().toISOString(),
      };
      return lockedFound.tabState.handoff;
    });
    pluginEvents.emit('tab:handoff', { userId, tabId: req.params.tabId, ...handoff });
    res.json({ handoff, vncPluginRequired: true });
  } catch (err) {
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /tabs/{tabId}/actions/plan:
 *   post:
 *     tags: [Interaction]
 *     summary: Plan and policy-check a semantic action
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, snapshotId, action]
 *             properties:
 *               userId: { type: string }
 *               snapshotId: { type: string }
 *               action: { type: object }
 *               policy: { type: object }
 *     responses:
 *       200: { description: Action contract and policy decision. }
 *       404: { description: Tab, snapshot, or target not found. }
 *       409: { description: Requested snapshot is no longer current. }
 */
app.post('/tabs/:tabId/actions/plan', express.json({ limit: '256kb' }), async (req, res) => {
  try {
    const { userId, snapshotId, action, policy } = req.body;
    if (!userId || !snapshotId || !action?.nodeId) return res.status(400).json({ error: 'userId, snapshotId, and action.nodeId are required' });
    if (!['click', 'type', 'type_secret', 'press'].includes(action.kind)) return res.status(400).json({ error: 'action.kind must be click, type, type_secret, or press' });
    if (action.kind === 'type_secret' && !action.secretId) return res.status(400).json({ error: 'action.secretId is required for type_secret' });
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId);
    const snapshot = found.tabState.semanticSnapshots.get(snapshotId);
    if (!snapshot) return res.status(404).json({ error: 'semantic snapshot not found' });
    if (found.tabState.lastSemanticSnapshot?.snapshotId !== snapshotId) {
      return res.status(409).json({ error: 'semantic snapshot is no longer current', status: 'rejected_stale' });
    }
    const node = snapshot.nodes.find(item => item.id === action.nodeId);
    if (!node) return res.status(404).json({ error: 'semantic target not found' });
    assertSemanticActionPolicy({ userId, session, tabId: req.params.tabId, action, node, snapshot });
    const contract = planAction({ action, node, snapshot, policy });
    found.tabState.actionContracts.set(contract.contractId, contract);
    res.json(contract);
  } catch (err) {
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /tabs/{tabId}/actions/execute:
 *   post:
 *     tags: [Interaction]
 *     summary: Execute and verify an action contract
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, contractId, postconditions]
 *             properties:
 *               userId: { type: string }
 *               contractId: { type: string }
 *               confirm: { type: boolean }
 *               postconditions:
 *                 type: array
 *                 minItems: 1
 *                 maxItems: 20
 *                 description: Every condition is required to pass. URL patterns use bounded literal matching with optional ^ and $ anchors; regular expressions are not evaluated.
 *                 items:
 *                   oneOf:
 *                     - type: object
 *                       additionalProperties: false
 *                       required: [kind, pattern]
 *                       properties:
 *                         kind: { type: string, enum: [url_matches] }
 *                         pattern: { type: string, minLength: 1, maxLength: 512 }
 *                     - type: object
 *                       additionalProperties: false
 *                       required: [kind]
 *                       minProperties: 2
 *                       properties:
 *                         kind: { type: string, enum: [node_exists] }
 *                         nodeId: { type: string, minLength: 1, maxLength: 256 }
 *                         name: { type: string, minLength: 1, maxLength: 256 }
 *                         role: { type: string, minLength: 1, maxLength: 256 }
 *                     - type: object
 *                       additionalProperties: false
 *                       required: [kind, text]
 *                       properties:
 *                         kind: { type: string, enum: [text_contains] }
 *                         text: { type: string, minLength: 1, maxLength: 512 }
 *     responses:
 *       200: { description: Execution and verification result. }
 *       400: { description: Missing or invalid postconditions. }
 *       409: { description: Contract stale, blocked, or awaiting confirmation. }
 *       423: { description: Tab paused for human handoff. }
 */
app.post('/tabs/:tabId/actions/execute', express.json({ limit: '256kb' }), async (req, res) => {
  try {
    const { userId, contractId, confirm = false, postconditions } = req.body;
    if (!userId || !contractId) return res.status(400).json({ error: 'userId and contractId are required' });
    const postconditionValidation = validatePostconditions(postconditions);
    if (!postconditionValidation.ok) return res.status(400).json({ error: postconditionValidation.error, code: 'invalid_postconditions' });
    const session = userId && sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId);
    const { tabState } = found;
    if (tabState.handoff?.status === 'paused') return res.status(423).json({ error: 'tab paused for human handoff', handoff: tabState.handoff });
    const contract = tabState.actionContracts.get(contractId);
    const validation = validateContract(contract, { snapshot: tabState.lastSemanticSnapshot, confirm });
    if (!validation.ok) return res.status(409).json(validation);

    let result;
    try {
      result = await withUserLimit(userId, () => withTabMutationLock(req.params.tabId, tabState, async () => {
        const lockedValidation = validateContract(contract, { snapshot: tabState.lastSemanticSnapshot, confirm });
        if (!lockedValidation.ok) return lockedValidation;
        contract.status = 'executing';
        const sourceSnapshot = tabState.semanticSnapshots.get(contract.snapshotId);
        const freshSnapshot = await captureSemanticObservation(tabState, { since: contract.snapshotId, session });
        if (!sourceSnapshot || freshSnapshot.stateHash !== sourceSnapshot.stateHash) {
          return { ok: false, status: 'rejected_stale', reasons: ['page_changed_since_plan'], snapshot: freshSnapshot };
        }
        const freshNode = freshSnapshot.nodes.find(node => node.id === contract.target.nodeId);
        if (!freshNode || freshNode.identityConfidence < 0.75) {
          return { ok: false, status: 'rejected_stale', reasons: ['target_missing_or_uncertain'], snapshot: freshSnapshot };
        }
        const freshFrame = freshNode.provenance?.frame;
        if (freshFrame?.key !== contract.target.frameKey || freshFrame?.url !== contract.target.frameUrl) {
          return { ok: false, status: 'rejected_stale', reasons: ['target_frame_changed'], snapshot: freshSnapshot };
        }
        assertSemanticActionPolicy({
          userId,
          session,
          tabId: req.params.tabId,
          action: contract.action,
          node: freshNode,
          snapshot: freshSnapshot,
        });
        const ref = freshNode.ref;
        const target = ref ? resolveRefTarget(tabState.page, ref, tabState.refs) : { ok: false, reason: 'ref_not_found' };
        if (!target.ok) return { ok: false, status: 'rejected_stale', reasons: [target.reason || 'target_not_resolvable'] };
        if (contract.action.kind === 'click') await target.locator.click({ timeout: 10_000 });
        else if (contract.action.kind === 'type') await target.locator.fill(String(contract.action.text ?? ''));
        else if (contract.action.kind === 'type_secret') {
          const secret = session.secrets.get(contract.action.secretId);
          const targetValidation = validateSecretTarget(secret, target);
          if (!targetValidation.ok) {
            return { ok: false, status: 'blocked', reasons: [targetValidation.reason] };
          }
          await target.locator.fill(secret.value);
        }
        else if (contract.action.kind === 'press') await target.locator.press(String(contract.action.key || 'Enter'));
        else return { ok: false, status: 'unsupported_action', reasons: ['unsupported_action'] };
        tabState.lastSnapshot = null;
        const nextSnapshot = await captureSemanticObservation(tabState, { session });
        const verification = verifyPostconditions(postconditions, { url: tabState.page.url(), snapshot: nextSnapshot });
        tabState.workflowSteps.push({
          kind: contract.action.kind,
          target: { role: contract.target.role, name: contract.target.name },
          ...(contract.action.key ? { key: contract.action.key } : {}),
          ...(contract.action.kind === 'type_secret' ? { secretId: contract.action.secretId } : {}),
          sourceSnapshotId: contract.snapshotId,
          resultSnapshotId: nextSnapshot.snapshotId,
          verified: verification.verified,
          recordedAt: new Date().toISOString(),
        });
        if (tabState.workflowSteps.length > 100) tabState.workflowSteps.shift();
        return {
          ok: true,
          status: verification.verified ? 'executed_verified' : 'executed_but_unverified',
          snapshot: nextSnapshot,
          verification,
        };
      }));
    } catch (err) {
      contract.status = 'failed_unknown_effect';
      throw err;
    }
    contract.status = result.ok ? 'executed' : result.status;
    pluginEvents.emit('tab:action:contract', { userId, tabId: req.params.tabId, contractId, status: result.status });
    res.status(result.ok ? 200 : 409).json(result);
  } catch (err) {
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /tabs/{tabId}/workflow:
 *   get:
 *     tags: [Content]
 *     summary: Compile successful contract actions into a reusable workflow
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *       - name: userId
 *         in: query
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Semantic workflow steps without secret values. }
 *       404: { description: Tab not found. }
 */
app.get('/tabs/:tabId/workflow', async (req, res) => {
  const session = req.query.userId && sessions.get(normalizeUserId(req.query.userId));
  const found = session && findTab(session, req.params.tabId);
  if (!found) return tabNotFoundResponse(res, req.params.tabId);
  res.json({
    version: 1,
    generatedAt: new Date().toISOString(),
    steps: found.tabState.workflowSteps,
    replayPolicy: 're-plan every step against fresh semantic state; never replay refs directly',
  });
});

// Wait for page ready
/**
 * @openapi
 * /tabs/{tabId}/wait:
 *   post:
 *     tags: [Interaction]
 *     summary: Wait for a selector or timeout
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *               selector:
 *                 type: string
 *               timeout:
 *                 type: integer
 *                 description: Max wait in ms.
 *     responses:
 *       200:
 *         description: Wait completed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/wait', async (req, res) => {
  try {
    const { userId, timeout = 10000, waitForNetwork = true } = req.body;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    const ready = await waitForPageReady(tabState.page, { timeout, waitForNetwork });
    
    res.json({ ok: true, ready });
  } catch (err) {
    log('error', 'wait failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Click
/**
 * @openapi
 * /tabs/{tabId}/click:
 *   post:
 *     tags: [Interaction]
 *     summary: Click an element
 *     description: Click by element ref, CSS selector, or coordinates.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *               ref:
 *                 type: string
 *                 description: Element ref ID (e.g. "e3").
 *               selector:
 *                 type: string
 *                 description: CSS selector fallback.
 *               doubleClick:
 *                 type: boolean
 *               holdMs:
 *                 type: number
 *                 minimum: 200
 *                 maximum: 15000
 *                 description: Sustained pointer-down duration in milliseconds. Explicitly enables press-and-hold instead of a tap.
 *               humanized:
 *                 description: Use curved pointer motion, hesitation, micro-movements, and variable click timing.
 *                 oneOf:
 *                   - type: boolean
 *                   - type: object
 *                     properties:
 *                       enabled:
 *                         type: boolean
 *                       profile:
 *                         type: string
 *                         enum: [fast, balanced, deliberate]
 *                       visualize:
 *                         type: boolean
 *                         description: Show a temporary pointer and click pulse in the page for live viewers.
 *               coordinates:
 *                 type: object
 *                 properties:
 *                   x:
 *                     type: number
 *                   y:
 *                     type: number
 *               confirm:
 *                 type: boolean
 *                 description: >
 *                   Required to click a control classified as dangerous (send, pay, publish,
 *                   delete, sign, confirm, transfer, change password). Without it the route
 *                   returns an ApprovalRequired body instead of clicking.
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: >
 *           Click result with optional post-action snapshot, or an ApprovalRequired body
 *           (`status: approval_required`) when the target is a dangerous control and
 *           `confirm` was not true. For humanized clicks, `input.hit` reports the element
 *           found under the pointer before the press and `input.delivered` whether a click
 *           event reached the target (`null` when that cannot be known: the page navigated,
 *           removed or hid the element, or stayed busy past the 2 s probe bound).
 *         content:
 *           application/json:
 *             schema:
 *               anyOf:
 *                 - type: object
 *                 - $ref: '#/components/schemas/ApprovalRequired'
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: >
 *           Humanized click could not be verified. `code: target_obscured`: another
 *           element sits under the pointer after one corrective re-aim, and nothing was
 *           pressed. `code: click_not_delivered`: no pointer or click event reached the
 *           target (`retrySafe: true`). `code: click_unconfirmed`: the press reached the
 *           target but no click followed, so the page may already have acted
 *           (`retrySafe: false`; check the page before retrying). The body carries `hit`,
 *           `delivered`, `pointer`, `retrySafe`, and a `hint`.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/click', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId, ref, selector, doubleClick = false } = req.body;
    let holdMs;
    try {
      holdMs = parseHoldMs(req.body.holdMs);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    if (holdMs !== undefined && doubleClick) {
      return res.status(400).json({ error: 'holdMs cannot be combined with doubleClick' });
    }
    const inputConfig = humanizedOptions(req.body.humanized);
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    if (!ref && !selector) {
      return res.status(400).json({ error: 'ref or selector required' });
    }
    
    let inputResult = { mode: 'direct' };
    let dangerousAnnotation = null;
    const result = await withUserLimit(userId, () => withTabMutationLock(tabId, tabState, async () => {
      const clickStart = Date.now();
      const remainingBudget = () => Math.max(0, HANDLER_TIMEOUT_MS - 2000 - (Date.now() - clickStart));
      // Full mouse event sequence for stubborn JS click handlers (mirrors Swift WebView.swift)
      // Dispatches: mouseover -> mouseenter -> mousedown -> mouseup -> click
      const dispatchMouseSequence = (locator) => withInputDispatchTimeout(async () => {
        const box = await locator.boundingBox();
        if (!box) throw new Error('Element not visible (no bounding box)');
        
        const x = box.x + box.width / 2;
        const y = box.y + box.height / 2;
        
        // Move mouse to element (triggers mouseover/mouseenter)
        await tabState.page.mouse.move(x, y);
        await tabState.page.waitForTimeout(50);
        
        // Full click sequence
        await tabState.page.mouse.down();
        await tabState.page.waitForTimeout(50);
        await tabState.page.mouse.up();
        
        log('info', 'mouse sequence dispatched', { x: x.toFixed(0), y: y.toFixed(0) });
      });
      
      // On Google SERPs, skip the normal click attempt (always intercepted by overlays)
      // and go directly to force click -- saves 5s timeout per click
      const onGoogleSerp = isGoogleSerp(tabState.page.url());
      
      const doClick = async (locatorOrSelector, isLocator) => {
        const locator = isLocator ? locatorOrSelector : tabState.page.locator(locatorOrSelector);

        if (holdMs !== undefined) {
          inputResult = await humanizedPressAndHold(tabState.page, locator, tabState, {
            holdMs,
            profile: inputConfig.profile,
            visualize: inputConfig.visualize,
            record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
            dispatch: boundedDispatch,
          });
          return;
        }

        if (inputConfig.enabled) {
          inputResult = await humanizedClick(tabState.page, locator, tabState, {
            profile: inputConfig.profile,
            visualize: inputConfig.visualize,
            doubleClick,
            // Google SERPs are always overlay-intercepted; keep pressing there like the
            // direct force-click path does, the delivery probe still reports the truth.
            strictHitTarget: !onGoogleSerp,
            record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
            dispatch: boundedDispatch,
          });
          return;
        }
        
        if (onGoogleSerp) {
          try {
            await locator.click({ timeout: 3000, force: true, clickCount: doubleClick ? 2 : 1 });
          } catch (forceErr) {
            log('warn', 'google force click failed, trying mouse sequence');
            await dispatchMouseSequence(locator);
          }
          return;
        }
        
        try {
          // First try normal click (respects visibility, enabled, not-obscured)
          await locator.click({ timeout: 3000, clickCount: doubleClick ? 2 : 1 });
        } catch (err) {
          // Fallback 1: If intercepted by overlay, retry with force
          if (err.message.includes('intercepts pointer events')) {
            log('warn', 'click intercepted, retrying with force');
            try {
              await locator.click({ timeout: 3000, force: true, clickCount: doubleClick ? 2 : 1 });
            } catch (forceErr) {
              // Fallback 2: Full mouse event sequence for stubborn JS handlers
              log('warn', 'force click failed, trying mouse sequence');
              await dispatchMouseSequence(locator);
            }
          } else if (err.message.includes('not visible') || err.message.toLowerCase().includes('timeout')) {
            // Fallback 2: Element not responding to click, try mouse sequence
            log('warn', 'click timeout, trying mouse sequence');
            await dispatchMouseSequence(locator);
          } else {
            throw err;
          }
        }
      };
      
      let clickTarget;
      let clickTargetIsLocator = false;
      if (ref) {
        let locator = refToLocator(tabState.page, ref, tabState.refs);
        if (!locator) {
          // Use tight timeout (4s max) to leave budget for click + post-click buildRefs
          log('info', 'auto-refreshing refs before click', { ref, hadRefs: tabState.refs.size });
          try {
            const preClickBudget = Math.min(4000, remainingBudget());
            tabState.refs = await refreshTabRefs(tabState, { reason: 'pre_click', timeoutMs: preClickBudget });
          } catch (e) {
            if (e.message === 'pre_click_refs_timeout' || e.message === 'buildRefs_timeout') {
              log('warn', 'pre-click buildRefs timed out, proceeding without refresh');
            } else {
              throw e;
            }
          }
          locator = refToLocator(tabState.page, ref, tabState.refs);
        }
        if (!locator) {
          const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none';
          throw new StaleRefsError(ref, maxRef, tabState.refs.size);
        }
        clickTarget = locator;
        clickTargetIsLocator = true;
      } else {
        clickTarget = tabState.page.locator(selector);
        clickTargetIsLocator = true;
      }

      // Brake: refuse clicks on send/pay/publish/delete/sign/confirm controls unless confirmed.
      const guard = await guardDangerousAction(tabState, { kind: 'click', ref, selector, confirm: req.body.confirm, locator: clickTarget, userId, tabId });
      if (guard.decision === 'approval_required') return { approvalRequired: guard.dangerous };
      dangerousAnnotation = guard.dangerous;

      await doClick(clickTarget, clickTargetIsLocator);
      
      // If clicking on a Google SERP, wait for potential navigation to complete
      if (onGoogleSerp) {
        try {
          await tabState.page.waitForLoadState('domcontentloaded', { timeout: 3000 });
        } catch {}
        await tabState.page.waitForTimeout(200);
        // Skip buildRefs here -- SERP clicks typically navigate to a new page,
        // and the caller always requests /snapshot next which rebuilds refs.
        tabState.lastSnapshot = null;
        tabState.refs = new Map();
        const newUrl = tabState.page.url();
        tabState.visitedUrls.add(newUrl);
        return { ok: true, url: newUrl, refsAvailable: false };
      } else {
        await tabState.page.waitForTimeout(500);
      }
      tabState.lastSnapshot = null;
      // buildRefs after click -- use remaining budget (min 2s) so we don't blow the handler timeout.
      // If it times out, return without refs (caller's next /snapshot will rebuild them).
      const postClickBudget = Math.max(2000, remainingBudget());
      try {
        tabState.refs = await refreshTabRefs(tabState, { reason: 'post_click', timeoutMs: postClickBudget });
      } catch (e) {
        if (e.message === 'post_click_refs_timeout' || e.message === 'buildRefs_timeout') {
          log('warn', 'post-click buildRefs timed out, returning without refs', { budget: postClickBudget, elapsed: Date.now() - clickStart });
          tabState.refs = new Map();
        } else {
          throw e;
        }
      }
      
      const newUrl = tabState.page.url();
      tabState.visitedUrls.add(newUrl);
      return { ok: true, url: newUrl, refsAvailable: tabState.refs.size > 0 };
    }));
    
    if (result.approvalRequired) return refuseDangerous(req, res, { userId, tabId, dangerous: result.approvalRequired, route: 'click', extra: { ref, selector } });
    if (!inputConfig.enabled) recordBehaviorEvent(tabState.behavior, 'click', { mode: 'direct' });
    result.input = inputResult;
    result.behavior = behaviorReport(tabState.behavior);
    if (dangerousAnnotation) result.dangerous = dangerousAnnotation;
    log('info', 'clicked', { reqId: req.reqId, tabId, url: result.url, inputMode: inputResult.mode });
    pluginEvents.emit('tab:click', { userId: req.body.userId, tabId, ref: req.body.ref, selector: req.body.selector, humanized: inputConfig.enabled });
    res.json(result);
  } catch (err) {
    log('error', 'click failed', { reqId: req.reqId, tabId, error: err.message });
    if (err.message?.includes('timed out')) {
      try {
        const session = sessions.get(normalizeUserId(req.body.userId));
        const found = session && findTab(session, tabId);
        if (found?.tabState?.page && !found.tabState.page.isClosed()) {
          found.tabState.refs = await refreshTabRefs(found.tabState, { reason: 'click_timeout' });
          found.tabState.lastSnapshot = null;
          return res.status(500).json({
            error: safeError(err),
            hint: 'The page may have changed. Call snapshot to see the current state and retry.',
            url: found.tabState.page.url(),
            refsCount: found.tabState.refs.size,
          });
        }
      } catch (refreshErr) {
        log('warn', 'post-timeout refresh failed', { error: refreshErr.message });
      }
    }
    handleRouteError(err, req, res);
  }
});

// Attach files from the configured upload root. This deliberately bypasses the
// native operating-system dialog while preserving the same user-visible flow.
/**
 * @openapi
 * /tabs/{tabId}/upload:
 *   post:
 *     tags: [Interaction]
 *     summary: Attach files to an upload control
 *     description: Files must resolve inside GOLIATH_UPLOADS_DIR. Supports an existing input[type=file] or a ref/selector that opens a file chooser.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, path]
 *             properties:
 *               userId:
 *                 type: string
 *               path:
 *                 oneOf:
 *                   - type: string
 *                   - type: array
 *                     items:
 *                       type: string
 *               ref:
 *                 type: string
 *               selector:
 *                 type: string
 *               timeout:
 *                 type: integer
 *                 default: 12000
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Files attached.
 *       400:
 *         description: Invalid or disallowed upload path.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Forbidden.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/upload', authMiddleware(), async (req, res) => {
  const tabId = req.params.tabId;
  try {
    const { userId, ref, selector, path: requestedPath } = req.body;
    const timeout = Number.isFinite(req.body.timeout) && req.body.timeout > 0
      ? Math.min(req.body.timeout, 30000)
      : 12000;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    if (!requestedPath) return res.status(400).json({ error: 'path required' });

    const requestedPaths = Array.isArray(requestedPath) ? requestedPath : [requestedPath];
    if (requestedPaths.length === 0 || requestedPaths.length > 20) {
      return res.status(400).json({ error: 'path must contain between 1 and 20 files' });
    }
    const paths = await resolveUploadPaths({ uploadsDir: CONFIG.uploadsDir, filePaths: requestedPaths });

    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, tabId);
    session.lastAccess = Date.now();
    const { tabState } = found;
    tabState.toolCalls++;
    tabState.consecutiveTimeouts = 0;
    tabState.consecutiveFailures = 0;

    const result = await withUserLimit(userId, () => withTabMutationLock(tabId, tabState, async () => {
      const page = tabState.page;
      const directInput = page.locator('input[type="file"]').first();
      let via = null;

      if (await directInput.count() > 0) {
        await directInput.setInputFiles(paths, { timeout: Math.min(timeout, 5000) });
        via = 'input';
      } else {
        let trigger = null;
        if (ref) {
          trigger = refToLocator(page, ref, tabState.refs);
          if (!trigger) {
            tabState.refs = await refreshTabRefs(tabState, { reason: 'pre_upload', timeoutMs: 4000 });
            trigger = refToLocator(page, ref, tabState.refs);
          }
          if (!trigger) {
            const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none';
            throw new StaleRefsError(ref, maxRef, tabState.refs.size);
          }
        } else if (selector) {
          trigger = page.locator(selector);
        } else {
          return Promise.reject(Object.assign(
            new Error('No file input is present; provide a ref or selector for the upload trigger.'),
            { statusCode: 400 },
          ));
        }

        const chooserPromise = page.waitForEvent('filechooser', { timeout }).catch(() => null);
        await trigger.click({ timeout: Math.min(timeout, 5000) });

        const deadline = Date.now() + Math.max(1000, timeout - 1000);
        while (Date.now() < deadline) {
          if (await directInput.count() > 0) {
            await directInput.setInputFiles(paths, { timeout: 5000 });
            via = 'mounted_input';
            break;
          }
          const chooser = await Promise.race([
            chooserPromise,
            page.waitForTimeout(250).then(() => null),
          ]);
          if (chooser) {
            await chooser.setFiles(paths);
            via = 'filechooser';
            break;
          }
        }
        if (!via) {
          const chooser = await chooserPromise;
          if (chooser) {
            await chooser.setFiles(paths);
            via = 'filechooser';
          }
        }
      }

      if (!via) {
        throw Object.assign(new Error('Upload trigger did not expose a file input or chooser.'), { statusCode: 422 });
      }

      await page.waitForTimeout(500);
      tabState.lastSnapshot = null;
      try {
        tabState.refs = await refreshTabRefs(tabState, { reason: 'post_upload', timeoutMs: 4000 });
      } catch {
        tabState.refs = new Map();
      }
      return { ok: true, attached: paths.length, via, refsAvailable: tabState.refs.size > 0 };
    }));

    log('info', 'uploaded', { reqId: req.reqId, tabId, count: paths.length, via: result.via });
    pluginEvents.emit('tab:upload', { userId, tabId, count: paths.length });
    res.json(result);
  } catch (err) {
    log('error', 'upload failed', { reqId: req.reqId, tabId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Type
/**
 * @openapi
 * /tabs/{tabId}/type:
 *   post:
 *     tags: [Interaction]
 *     summary: Type text into an element
 *     description: Types text into a focused element or a specific ref/selector.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, text]
 *             properties:
 *               userId:
 *                 type: string
 *               ref:
 *                 type: string
 *               selector:
 *                 type: string
 *               text:
 *                 type: string
 *               clear:
 *                 type: boolean
 *                 description: Clear field before typing.
 *               mode:
 *                 type: string
 *                 enum: [fill, keyboard]
 *               delay:
 *                 type: integer
 *                 description: Fixed per-character delay for keyboard mode when humanized is disabled.
 *               humanized:
 *                 description: Type with variable per-character and punctuation-aware pauses.
 *                 oneOf:
 *                   - type: boolean
 *                   - type: object
 *                     properties:
 *                       enabled:
 *                         type: boolean
 *                       profile:
 *                         type: string
 *                         enum: [fast, balanced, deliberate]
 *               submit:
 *                 type: boolean
 *                 description: Press Enter after typing.
 *               confirm:
 *                 type: boolean
 *                 description: >
 *                   Required when submit/pressEnter would submit a form whose submit control
 *                   or action URL is classified as dangerous; otherwise the route returns an
 *                   ApprovalRequired body before typing anything.
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: >
 *           Type result, or an ApprovalRequired body (`status: approval_required`) when
 *           the submit is dangerous and `confirm` was not true.
 *         content:
 *           application/json:
 *             schema:
 *               anyOf:
 *                 - type: object
 *                 - $ref: '#/components/schemas/ApprovalRequired'
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/type', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId, ref, selector, text, mode = 'fill', delay = 30, submit = false, pressEnter = false } = req.body;
    const inputConfig = humanizedOptions(req.body.humanized);
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    if (mode !== 'fill' && mode !== 'keyboard') {
      return res.status(400).json({ error: "mode must be 'fill' or 'keyboard'" });
    }
    if (typeof text !== 'string') {
      return res.status(400).json({ error: 'text is required' });
    }
    // keyboard mode: ref/selector are optional (types into current focus)
    if (mode === 'fill' && !ref && !selector) {
      return res.status(400).json({ error: 'ref or selector required for mode=fill' });
    }
    const shouldSubmit = submit || pressEnter;
    
    let inputResult = { mode: mode === 'keyboard' ? 'keyboard-fixed-delay' : 'fill' };
    let dangerousAnnotation = null;
    const typeOutcome = await withTabMutationLock(tabId, tabState, async () => {
      // Resolve and focus the target if ref/selector provided
      let locator = null;
      if (ref) {
        locator = refToLocator(tabState.page, ref, tabState.refs);
        if (!locator) {
          log('info', 'auto-refreshing refs before type', { ref, hadRefs: tabState.refs.size, mode });
          tabState.refs = await refreshTabRefs(tabState, { reason: 'type' });
          locator = refToLocator(tabState.page, ref, tabState.refs);
        }
        if (!locator) { const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none'; throw new StaleRefsError(ref, maxRef, tabState.refs.size); }
      }

      // Brake: a submitting type (Enter) is checked before any text is entered, so a
      // refused request leaves the field untouched.
      if (shouldSubmit) {
        const guard = await guardDangerousAction(tabState, {
          kind: 'type_submit', ref, selector, confirm: req.body.confirm, submitContext: true,
          locator: locator || (selector ? tabState.page.locator(selector) : null),
          userId, tabId,
        });
        if (guard.decision === 'approval_required') return { approvalRequired: guard.dangerous };
        dangerousAnnotation = guard.dangerous;
      }
      
      if (inputConfig.enabled) {
        if (locator) {
          if (mode === 'fill') await locator.fill('', { timeout: 10000 });
          await locator.focus({ timeout: 10000 });
        } else if (selector) {
          if (mode === 'fill') await tabState.page.fill(selector, '', { timeout: 10000 });
          await tabState.page.focus(selector, { timeout: 10000 });
        }
        inputResult = await humanizedType(tabState.page, text, {
          profile: inputConfig.profile,
          record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
        });
      } else if (mode === 'fill') {
        if (locator) {
          await locator.fill(text, { timeout: 10000 });
        } else {
          await tabState.page.fill(selector, text, { timeout: 10000 });
        }
      } else {
        // keyboard mode -- char-by-char real key events (required for Ember/contenteditable)
        if (locator) {
          await locator.focus({ timeout: 10000 });
        } else if (selector) {
          await tabState.page.focus(selector, { timeout: 10000 });
        }
        await tabState.page.keyboard.type(text, { delay });
      }
      if (shouldSubmit) {
        await tabState.page.keyboard.press('Enter');
        recordBehaviorEvent(tabState.behavior, 'key', { category: 'submit' });
      }
      return { ok: true };
    });
    if (typeOutcome?.approvalRequired) return refuseDangerous(req, res, { userId, tabId, dangerous: typeOutcome.approvalRequired, route: 'type', extra: { ref, selector } });
    
    if (!inputConfig.enabled) recordBehaviorEvent(tabState.behavior, 'type', { mode });
    pluginEvents.emit('tab:type', { userId: req.body.userId, tabId, text: req.body.text, ref: req.body.ref, mode: req.body.mode || 'fill', humanized: inputConfig.enabled });
    const typeResponse = { ok: true, input: inputResult, behavior: behaviorReport(tabState.behavior) };
    if (dangerousAnnotation) typeResponse.dangerous = dangerousAnnotation;
    res.json(typeResponse);
  } catch (err) {
    log('error', 'type failed', { reqId: req.reqId, error: err.message });
    if (err.message?.includes('timed out') || err.message?.includes('not an <input>')) {
      try {
        const session = sessions.get(normalizeUserId(req.body.userId));
        const found = session && findTab(session, tabId);
        if (found?.tabState?.page && !found.tabState.page.isClosed()) {
          found.tabState.refs = await refreshTabRefs(found.tabState, { reason: 'type_timeout' });
          found.tabState.lastSnapshot = null;
          return res.status(500).json({
            error: safeError(err),
            hint: 'The page may have changed. Call snapshot to see the current state and retry.',
            url: found.tabState.page.url(),
            refsCount: found.tabState.refs.size,
          });
        }
      } catch (refreshErr) {
        log('warn', 'post-timeout refresh failed', { error: refreshErr.message });
      }
    }
    handleRouteError(err, req, res);
  }
});

// Press key
/**
 * @openapi
 * /tabs/{tabId}/press:
 *   post:
 *     tags: [Interaction]
 *     summary: Press a keyboard key
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, key]
 *             properties:
 *               userId:
 *                 type: string
 *               key:
 *                 type: string
 *                 description: Key name (e.g. "Enter", "Escape", "Tab").
 *               confirm:
 *                 type: boolean
 *                 description: Required to press Enter when the focused form's submit control or action is classified as dangerous.
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: >
 *           Key pressed, or an ApprovalRequired body (`status: approval_required`) when Enter
 *           would submit something dangerous and `confirm` was not true.
 *         content:
 *           application/json:
 *             schema:
 *               anyOf:
 *                 - type: object
 *                   properties:
 *                     ok:
 *                       type: boolean
 *                 - $ref: '#/components/schemas/ApprovalRequired'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/press', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId, key } = req.body;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    let dangerousAnnotation = null;
    const pressOutcome = await withTabMutationLock(tabId, tabState, async () => {
      // Brake: Enter submits whatever is focused, so it is judged like a submit.
      if (isEnterKey(key)) {
        const guard = await guardDangerousAction(tabState, { kind: 'submit', confirm: req.body.confirm, submitContext: true, userId, tabId: req.params.tabId });
        if (guard.decision === 'approval_required') return { approvalRequired: guard.dangerous };
        dangerousAnnotation = guard.dangerous;
      }
      await tabState.page.keyboard.press(key);
      recordBehaviorEvent(tabState.behavior, 'key', { category: 'press' });
      return { ok: true };
    });
    if (pressOutcome?.approvalRequired) return refuseDangerous(req, res, { userId, tabId, dangerous: pressOutcome.approvalRequired, route: 'press', extra: { key } });
    
    pluginEvents.emit('tab:press', { userId, tabId, key });
    res.json(dangerousAnnotation ? { ok: true, dangerous: dangerousAnnotation } : { ok: true });
  } catch (err) {
    log('error', 'press failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Scroll
/**
 * @openapi
 * /tabs/{tabId}/scroll:
 *   post:
 *     tags: [Interaction]
 *     summary: Scroll the page
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *               direction:
 *                 type: string
 *                 description: '"up" or "down" (default "down").'
 *               amount:
 *                 type: integer
 *                 description: Pixels to scroll.
 *               humanized:
 *                 description: Split the scroll into variable, eased wheel pulses.
 *                 oneOf:
 *                   - type: boolean
 *                   - type: object
 *                     properties:
 *                       enabled:
 *                         type: boolean
 *                       profile:
 *                         type: string
 *                         enum: [fast, balanced, deliberate]
 *                       visualize:
 *                         type: boolean
 *                         description: Show a temporary pointer and click pulse in the page for live viewers.
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Scroll result.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/scroll', async (req, res) => {
  try {
    const { userId, direction = 'down', amount = 500 } = req.body;
    const inputConfig = humanizedOptions(req.body.humanized);
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    let inputResult = { mode: 'direct', pulses: 1 };
    await withTabMutationLock(req.params.tabId, tabState, async () => {
      if (inputConfig.enabled) {
        inputResult = await humanizedScroll(tabState.page, direction, amount, {
          profile: inputConfig.profile,
          record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
          dispatch: boundedDispatch,
        });
      } else {
        const isVertical = direction === 'up' || direction === 'down';
        const delta = (direction === 'up' || direction === 'left') ? -amount : amount;
        await tabState.page.mouse.wheel(isVertical ? 0 : delta, isVertical ? delta : 0);
        recordBehaviorEvent(tabState.behavior, 'wheel', { deltaX: isVertical ? 0 : delta, deltaY: isVertical ? delta : 0 });
      }
      await tabState.page.waitForTimeout(300);
    });
    
    pluginEvents.emit('tab:scroll', { userId, tabId: req.params.tabId, direction, amount, humanized: inputConfig.enabled });
    res.json({ ok: true, input: inputResult, behavior: behaviorReport(tabState.behavior) });
  } catch (err) {
    log('error', 'scroll failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// --- Dangerous-action brake ---------------------------------------------------
// Classification lives in lib/dangerous-actions.js (pure). These helpers gather
// what the classifier needs through Playwright's utility world (ariaSnapshot,
// getAttribute, count), never through page-world JavaScript: a hostile page
// cannot override prototype getters to blind the brake. Lookup failures fail
// CLOSED (classified as unresolved_target).

const DANGEROUS_DESCRIBE_TIMEOUT_MS = 2500;
const TEXT_ENTRY_ROLES = new Set(['textbox', 'searchbox', 'combobox', 'spinbutton', 'slider']);
const ENTER_KEYS = new Set(['enter', 'numpadenter']);
const ARIA_ROOT_RE = /^\s*-\s+([a-z]+)(?:\s+"((?:[^"\\]|\\.)*)")?/;
const ARIA_CONTROL_RE = /^\s*-\s+(?:button|link|menuitem)\s+"((?:[^"\\]|\\.)*)"/gm;
const MAX_NEARBY_CONTROLS = 20;

function dangerousActionsMode() {
  return CONFIG.dangerousActionsMode || 'confirm';
}

function isEnterKey(key) {
  return typeof key === 'string' && ENTER_KEYS.has(key.trim().toLowerCase());
}

function unescapeAria(value) {
  return String(value || '').replace(/\\(["\\])/g, '$1');
}

function parseAriaRoot(yaml) {
  const line = String(yaml || '').split('\n').find(entry => entry.trim());
  const match = line && ARIA_ROOT_RE.exec(line);
  return match ? { role: match[1], name: unescapeAria(match[2]) } : null;
}

function ariaControlNames(yaml, max = MAX_NEARBY_CONTROLS) {
  const names = [];
  const re = new RegExp(ARIA_CONTROL_RE.source, 'gm');
  let match;
  while ((match = re.exec(String(yaml || ''))) && names.length < max) names.push(unescapeAria(match[1]));
  return names;
}

// Accessible role/name of the element itself (not of its descendants).
async function describeTarget(locator) {
  const yaml = await locator.first().ariaSnapshot({ timeout: DANGEROUS_DESCRIBE_TIMEOUT_MS });
  return parseAriaRoot(yaml) || { role: null, name: '' };
}

// For Enter-key submits: the owning form's submit control and resolved action
// URL, or for form-less composers (chat UIs) the buttons in the nearest
// container, so "Write a message" + Enter is judged by the "Send" button next to it.
async function describeSubmitContext(page, locator) {
  const opts = { timeout: DANGEROUS_DESCRIBE_TIMEOUT_MS };
  const target = (locator || page.locator(':focus')).first();
  const form = target.locator('xpath=ancestor-or-self::form[1]');
  if (await form.count() > 0) {
    let submitControl = form.locator('button[type="submit"], input[type="submit"]').first();
    if (await submitControl.count() === 0) submitControl = form.locator('button:not([type])').first();
    const name = await submitControl.count() > 0 ? (await describeTarget(submitControl)).name : '';
    const candidates = ariaControlNames(await form.ariaSnapshot(opts));
    const rawAction = await form.getAttribute('action', opts);
    let formAction = '';
    if (rawAction) {
      try { formAction = new URL(rawAction, page.url()).href; } catch { formAction = rawAction; }
    }
    return { name, candidates, formAction };
  }
  const container = target.locator('xpath=ancestor::*[.//button or .//*[@role="button"]][1]');
  if (await container.count() > 0) {
    return { name: '', candidates: ariaControlNames(await container.ariaSnapshot(opts)), formAction: '' };
  }
  return { name: '', candidates: [], formAction: '' };
}

// An approval is bound to what was refused: same kind, category, element, and
// domain on the same tab. `confirm: true` for anything else is refused again, so
// a ref that re-resolved to a different control after the human answered
// cannot ride on the earlier approval.
function approvalKey(dangerous, fallbackElement) {
  return [dangerous.kind, dangerous.category, normalizeActionLabel(dangerous.element || fallbackElement || ''), dangerous.domain || ''].join('|');
}

/**
 * Decide whether an interaction may proceed. Call inside the tab lock once the
 * target has been resolved so ref names come from fresh refs.
 *
 * @returns {Promise<{decision:'allow'|'approval_required'|'annotate', dangerous:object|null}>}
 */
async function guardDangerousAction(tabState, { kind, ref, selector, locator, confirm = false, submitContext = false, userId, tabId }) {
  const mode = dangerousActionsMode();
  const policy = policyForUser(userId);
  const hasDangerousPolicyDenies = Object.values(policy?.dangerousActions || {}).includes('deny');
  if (mode === 'off' && !hasDangerousPolicyDenies) return { decision: 'allow', dangerous: null };
  let element = '';
  let role = null;
  let formAction = '';
  let candidates;
  let unresolved = false;
  const refEntry = ref && tabState.refs instanceof Map ? tabState.refs.get(ref) : null;
  if (refEntry) {
    element = refEntry.name || '';
    role = refEntry.role || null;
  }
  try {
    if (submitContext) {
      // A targeted submit may point at the control itself (a "Send" button) or at
      // the field being submitted; judge the control by name, the field by its form.
      element = '';
      if (locator) {
        const described = await describeTarget(locator);
        if (described.role && !TEXT_ENTRY_ROLES.has(described.role) && described.name) {
          element = described.name;
          role = described.role;
        }
      }
      const context = await describeSubmitContext(tabState.page, locator);
      if (!element) {
        element = context.name;
        role = context.name ? 'button' : null;
      }
      candidates = context.candidates;
      formAction = context.formAction;
    } else if (locator && !element) {
      const described = await describeTarget(locator);
      element = described.name;
      role = described.role || role;
    }
  } catch (err) {
    unresolved = true;
    log('warn', 'dangerous-action: target lookup failed', { kind, ref, selector, error: err.message });
  }
  // Clicking into a field only focuses it; the submit brake covers what Enter does next.
  if (!submitContext && !unresolved && role && TEXT_ENTRY_ROLES.has(role)) return { decision: 'allow', dangerous: null };

  let url = '';
  try { url = tabState.page.url(); } catch {}
  const dangerous = classifyDangerousAction({ kind, element, candidates, role, url, formAction, unresolved });
  if (!dangerous) return { decision: 'allow', dangerous: null };

  let policyOrigin = originFromUrl(url);
  if (ref) {
    const target = resolveRefTarget(tabState.page, ref, tabState.refs);
    policyOrigin = target.ok ? targetFrameOrigin(target) : null;
  }
  assertSessionPolicy({
    userId,
    tabId,
    action: canonicalPolicyAction(kind),
    origin: policyOrigin,
    dangerousCategory: dangerous.category,
  });
  if (mode === 'off') return { decision: 'allow', dangerous: null };

  const key = approvalKey(dangerous, ref || selector);
  let decision = 'approval_required';
  if (mode === 'annotate') {
    decision = 'annotate';
  } else if (confirm === true && tabState.lastRefusal?.key === key) {
    decision = 'annotate';
    tabState.lastRefusal = null;
  } else {
    tabState.lastRefusal = { key, at: Date.now() };
    if (confirm === true) {
      dangerous.hint = 'confirm was set, but no matching refusal exists on this tab (nothing was refused yet, or the target or its classification changed since). Review this refusal, then retry with "confirm": true.';
    }
  }
  log('info', 'dangerous-action classified', {
    kind, decision, category: dangerous.category, risk: dangerous.risk, element: dangerous.element,
    domain: dangerous.domain, source: dangerous.source, selector: selector || undefined, ref: ref || undefined,
  });
  return { decision, dangerous };
}

function refuseDangerous(req, res, { userId, tabId, dangerous, route, extra = {}, hint }) {
  pluginEvents.emit('tab:approval_required', {
    userId, tabId, action: dangerous.action, kind: dangerous.kind, category: dangerous.category,
    risk: dangerous.risk, element: dangerous.element, domain: dangerous.domain, source: dangerous.source, ...extra,
  });
  log('info', `${route} refused: approval required`, { reqId: req.reqId, tabId, category: dangerous.category, element: dangerous.element, source: dangerous.source });
  return res.json(approvalRequiredResponse(dangerous, { hint }));
}

// --- Hands ("voodoo hands"): multi-step form automation primitives ----------

async function resolveHandLocator(tabState, step) {
  if (step.selector) {
    return tabState.page.locator(step.selector);
  }
  let locator = refToLocator(tabState.page, step.ref, tabState.refs);
  if (!locator) {
    log('info', 'hands: auto-refreshing refs before step', { ref: step.ref, hadRefs: tabState.refs.size });
    tabState.refs = await refreshTabRefs(tabState, { reason: 'hands', timeoutMs: 8000 });
    locator = refToLocator(tabState.page, step.ref, tabState.refs);
  }
  if (!locator) {
    const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none';
    throw new StaleRefsError(step.ref, maxRef, tabState.refs.size);
  }
  return locator;
}

async function handsClick(tabState, locator, inputConfig, doubleClick = false) {
  if (inputConfig.enabled) {
    return await humanizedClick(tabState.page, locator, tabState, {
      profile: inputConfig.profile,
      visualize: inputConfig.visualize,
      doubleClick,
      strictHitTarget: !isGoogleSerp(tabState.page.url()),
      record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
      dispatch: boundedDispatch,
    });
  }
  const dispatchMouseSequence = () => withInputDispatchTimeout(async () => {
    const box = await locator.boundingBox();
    if (!box) throw new Error('Element not visible (no bounding box)');
    const x = box.x + box.width / 2;
    const y = box.y + box.height / 2;
    await tabState.page.mouse.move(x, y);
    await tabState.page.waitForTimeout(50);
    const clicks = doubleClick ? 2 : 1;
    for (let c = 0; c < clicks; c++) {
      await tabState.page.mouse.down();
      await tabState.page.waitForTimeout(50);
      await tabState.page.mouse.up();
      if (c + 1 < clicks) await tabState.page.waitForTimeout(85);
    }
  });
  try {
    await locator.click({ timeout: 3000, clickCount: doubleClick ? 2 : 1 });
    recordBehaviorEvent(tabState.behavior, 'click', { mode: 'direct', doubleClick });
    return { mode: 'direct' };
  } catch (err) {
    if (err.message.includes('intercepts pointer events')) {
      try {
        await locator.click({ timeout: 3000, force: true, clickCount: doubleClick ? 2 : 1 });
        recordBehaviorEvent(tabState.behavior, 'click', { mode: 'force', doubleClick });
        return { mode: 'force' };
      } catch {
        await dispatchMouseSequence();
        recordBehaviorEvent(tabState.behavior, 'click', { mode: 'mouse-sequence', doubleClick });
        return { mode: 'mouse-sequence' };
      }
    }
    if (err.message.includes('not visible') || err.message.toLowerCase().includes('timeout')) {
      await dispatchMouseSequence();
      recordBehaviorEvent(tabState.behavior, 'click', { mode: 'mouse-sequence', doubleClick });
      return { mode: 'mouse-sequence' };
    }
    throw err;
  }
}

async function handsType(tabState, step, inputConfig, preResolved = null) {
  const { text, mode = 'fill', submit = false, pressEnter = false } = step;
  const shouldSubmit = submit || pressEnter;
  let inputResult = { mode: mode === 'keyboard' ? 'keyboard-fixed-delay' : 'fill' };

  // Fill mode always resolves its target. Keyboard mode resolves and focuses a
  // target only when ref/selector is supplied; otherwise it types into the
  // current focus, mirroring the existing /type route.
  let locator = preResolved;
  if (!locator && (mode === 'fill' || step.ref || step.selector)) {
    locator = await resolveHandLocator(tabState, step);
  }

  if (inputConfig.enabled) {
    if (locator) {
      await locator.fill('', { timeout: 10000 });
      await locator.focus({ timeout: 10000 });
    }
    inputResult = await humanizedType(tabState.page, text, {
      profile: inputConfig.profile,
      record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
    });
  } else if (mode === 'fill') {
    await locator.fill(text, { timeout: 10000 });
  } else {
    if (locator) await locator.focus({ timeout: 10000 });
    await tabState.page.keyboard.type(text, { delay: 30 });
  }

  if (shouldSubmit) {
    await tabState.page.keyboard.press('Enter');
    recordBehaviorEvent(tabState.behavior, 'key', { category: 'submit' });
  }
  return inputResult;
}

async function handsSelect(tabState, step) {
  const locator = await resolveHandLocator(tabState, step);
  await locator.selectOption(step.values, { timeout: 10000 });
  return { values: step.values };
}

async function handsCheck(tabState, step) {
  const locator = await resolveHandLocator(tabState, step);
  await locator.setChecked(true, { timeout: 10000 });
  return { checked: true };
}

async function handsWait(tabState, step) {
  await tabState.page.waitForTimeout(step.ms);
  return { ms: step.ms };
}

async function handsScroll(tabState, step, inputConfig) {
  if (inputConfig.enabled) {
    return await humanizedScroll(tabState.page, step.direction, step.amount, {
      profile: inputConfig.profile,
      record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
      dispatch: boundedDispatch,
    });
  }
  const isVertical = step.direction === 'up' || step.direction === 'down';
  const delta = (step.direction === 'up' || step.direction === 'left') ? -step.amount : step.amount;
  await tabState.page.mouse.wheel(isVertical ? 0 : delta, isVertical ? delta : 0);
  recordBehaviorEvent(tabState.behavior, 'wheel', { deltaX: isVertical ? 0 : delta, deltaY: isVertical ? delta : 0 });
  return { mode: 'direct' };
}

async function handsPress(tabState, step) {
  await tabState.page.keyboard.press(step.key);
  recordBehaviorEvent(tabState.behavior, 'key', { category: 'press' });
  return { key: step.key };
}

async function handsSubmit(tabState, step, inputConfig, preResolved = null) {
  if (step.ref || step.selector) {
    const locator = preResolved || await resolveHandLocator(tabState, step);
    await handsClick(tabState, locator, inputConfig);
    return { mode: 'click' };
  }
  await tabState.page.keyboard.press('Enter');
  recordBehaviorEvent(tabState.behavior, 'key', { category: 'submit' });
  return { mode: 'enter' };
}

/**
 * Dangerous-action brake for one hand step. Only click, submit, submitting
 * type, and Enter press steps can have side effects worth braking on. The
 * resolved locator is returned so execution targets exactly the element the
 * brake judged.
 */
async function guardHandStep(tabState, step, { userId, tabId }) {
  const confirm = step.confirm === true;
  const hasTarget = Boolean(step.ref || step.selector);
  if (step.action === 'click') {
    const locator = await resolveHandLocator(tabState, step);
    return { ...(await guardDangerousAction(tabState, { kind: 'click', ref: step.ref, selector: step.selector, locator, confirm, userId, tabId })), locator };
  }
  if (step.action === 'submit') {
    const locator = hasTarget ? await resolveHandLocator(tabState, step) : null;
    // Targeted or not, a submit is judged by the control's own name and its form.
    const guard = await guardDangerousAction(tabState, { kind: 'submit', ref: step.ref, selector: step.selector, locator, confirm, submitContext: true, userId, tabId });
    return { ...guard, locator };
  }
  if (step.action === 'type' && (step.submit || step.pressEnter)) {
    const locator = (step.mode !== 'keyboard' || hasTarget) ? await resolveHandLocator(tabState, step) : null;
    return { ...(await guardDangerousAction(tabState, { kind: 'type_submit', ref: step.ref, selector: step.selector, locator, confirm, submitContext: true, userId, tabId })), locator };
  }
  if (step.action === 'press' && isEnterKey(step.key)) {
    return { ...(await guardDangerousAction(tabState, { kind: 'submit', confirm, submitContext: true, userId, tabId })), locator: null };
  }
  return { decision: 'allow', dangerous: null, locator: null };
}

async function executeHandStep(tabState, step, inputConfig, locator = null) {
  switch (step.action) {
    case 'click':
      return await handsClick(tabState, locator || await resolveHandLocator(tabState, step), inputConfig, step.doubleClick);
    case 'type':
      return await handsType(tabState, step, inputConfig, locator);
    case 'select':
      return await handsSelect(tabState, step);
    case 'check':
      return await handsCheck(tabState, step);
    case 'wait':
      return await handsWait(tabState, step);
    case 'scroll':
      return await handsScroll(tabState, step, inputConfig);
    case 'press':
      return await handsPress(tabState, step);
    case 'submit':
      return await handsSubmit(tabState, step, inputConfig, locator);
    default:
      throw new HandsError(`unsupported action "${step.action}"`);
  }
}

/**
 * @openapi
 * /tabs/{tabId}/hands:
 *   post:
 *     tags: [Interaction]
 *     summary: Execute an ordered list of UI actions (a "hand") in one request
 *     description: >
 *       Multi-step form automation primitive ("voodoo hands"): run an ordered list
 *       of click, type, select, check, wait, scroll, press, and submit steps against
 *       a single tab in one native request. Stops at the first failing step and
 *       reports its index. Preferred over repeated single-action calls for filling
 *       multi-field forms.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, steps]
 *             properties:
 *               userId:
 *                 type: string
 *               steps:
 *                 type: array
 *                 minItems: 1
 *                 maxItems: 20
 *                 description: Ordered list of action steps to execute.
 *                 items:
 *                   type: object
 *                   required: [action]
 *                   properties:
 *                     action:
 *                       type: string
 *                       enum: [click, type, select, check, wait, scroll, press, submit]
 *                     ref:
 *                       type: string
 *                       description: Element ref from a snapshot (e.g. "e3").
 *                     selector:
 *                       type: string
 *                       description: CSS selector. Required for action "select" (native <select> is not exposed as an a11y ref); optional fallback otherwise.
 *                     text:
 *                       type: string
 *                       maxLength: 3000
 *                     value:
 *                       type: string
 *                     values:
 *                       type: array
 *                       items:
 *                         type: string
 *                     mode:
 *                       type: string
 *                       enum: [fill, keyboard]
 *                     submit:
 *                       type: boolean
 *                     pressEnter:
 *                       type: boolean
 *                     doubleClick:
 *                       type: boolean
 *                     direction:
 *                       type: string
 *                       enum: [up, down, left, right]
 *                     amount:
 *                       type: integer
 *                     key:
 *                       type: string
 *                     ms:
 *                       type: integer
 *                       description: Wait duration. Values over 5000 are clamped to 5000.
 *                     confirm:
 *                       type: boolean
 *                       description: User approved this specific dangerous step (after it was refused on this tab).
 *               humanized:
 *                 description: Use humanized pointer/key timing across the hand.
 *                 oneOf:
 *                   - type: boolean
 *                   - type: object
 *                     properties:
 *                       enabled:
 *                         type: boolean
 *                       profile:
 *                         type: string
 *                         enum: [fast, balanced, deliberate]
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: >
 *           Hand result with per-step outcomes. When a click/submit step targets a
 *           dangerous control without confirm, the hand stops before that step with
 *           `status: approval_required`, `approvalRequired` (an ApprovalRequired body
 *           plus `step`), and `failedStep`.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Bad request (invalid steps).
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/hands', async (req, res) => {
  const tabId = req.params.tabId;

  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });

    let steps;
    try {
      steps = coerceHandsSteps(req.body.steps);
    } catch (err) {
      if (err instanceof HandsError) {
        return res.status(400).json({ error: err.message, code: err.code, stepIndex: err.stepIndex });
      }
      throw err;
    }

    const inputConfig = humanizedOptions(req.body.humanized);
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();

    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;

    const results = [];
    let abortedAt = null;
    let approvalRequired = null;

    // Budget scaling for hands. Humanized interaction is deliberately slow — a
    // single humanized click on a live browser traverses a real pointer path +
    // scroll-into-view + hesitation, and the observed cost is ~7-12s per click
    // when elements are spread across the page (grid forms). A multi-click
    // humanized hand therefore legitimately needs well beyond the flat
    // HANDLER_TIMEOUT_MS. Size the budget by step count × profile and, for
    // humanized hands, do NOT clamp to the tab-lock window — the per-step
    // handDeadline below already self-terminates cleanly so no hung step can
    // hold the lock indefinitely; we only bound the worst case with a generous
    // per-hand ceiling. Non-humanized (fast) hands keep the tight default.
    // The math lives in lib/hands.js computeHandBudgetMs() so it's unit-testable.
    const profile = inputConfig.enabled ? inputConfig.profile : 'fast';
    const handBudgetMs = computeHandBudgetMs({
      profile,
      stepCount: steps.length,
      humanizedEnabled: inputConfig.enabled,
      handlerTimeoutMs: HANDLER_TIMEOUT_MS,
    });
    // Use the mutation-aware lock so a queued handoff request is ordered before
    // the hand and rechecked immediately before the first step executes.
    const result = await withUserLimit(userId, () => withTabMutationLock(tabId, tabState, async () => {
      // Computed inside the lock so time spent waiting in the user concurrency
      // queue does not eat the budget. Kept below handBudgetMs so the
      // standard withTimeout() wins cleanly for any single hung step.
      const handDeadline = Date.now() + Math.max(1000, handBudgetMs - 2000);
      for (let i = 0; i < steps.length; i++) {
        if (Date.now() > handDeadline) {
          results.push({ index: i, action: '__timeout__', ok: false, error: 'hand budget exceeded; split into smaller hands' });
          abortedAt = i;
          break;
        }
        const step = steps[i];
        try {
          const guard = await guardHandStep(tabState, step, { userId, tabId });
          if (guard.decision === 'approval_required') {
            approvalRequired = guard.dangerous;
            // Keep `action` as the step's action name (results[] contract); the
            // human-readable label lives in the top-level approvalRequired body.
            const { action: _label, ...refusal } = approvalRequiredResponse(guard.dangerous, {
              hint: guard.dangerous.hint || 'Ask the user, then re-run the remaining steps with "confirm": true on this step.',
            });
            results.push({ index: i, action: step.action, ...refusal });
            abortedAt = i;
            break;
          }
          const out = await executeHandStep(tabState, step, inputConfig, guard.locator);
          results.push({ index: i, action: step.action, ok: true, ...(guard.dangerous ? { dangerous: guard.dangerous } : {}), ...out });
          // Invalidate refs after any step that may navigate, so the next ref resolution rebuilds.
          if (step.action === 'click' || step.action === 'submit' || (step.action === 'type' && (step.submit || step.pressEnter))) {
            tabState.lastSnapshot = null;
            tabState.refs = new Map();
          }
        } catch (err) {
          if (err?.code === 'policy_violation') throw err;
          results.push({ index: i, action: step.action, ok: false, error: safeError(err), ...(err.code ? { code: err.code } : {}) });
          abortedAt = i;
          break;
        }
      }
      return { ok: abortedAt === null, completed: results.filter(r => r.ok).length, total: steps.length, url: tabState.page.url() };
    }, handBudgetMs));

    result.results = results;
    if (abortedAt !== null) result.failedStep = abortedAt;
    if (approvalRequired) {
      result.status = 'approval_required';
      result.approvalRequired = { ...approvalRequired, step: abortedAt };
      pluginEvents.emit('tab:approval_required', {
        userId, tabId, action: approvalRequired.action, kind: approvalRequired.kind, category: approvalRequired.category,
        risk: approvalRequired.risk, element: approvalRequired.element, domain: approvalRequired.domain, source: approvalRequired.source, step: abortedAt,
      });
      log('info', 'hands stopped: approval required', { reqId: req.reqId, tabId, step: abortedAt, category: approvalRequired.category, element: approvalRequired.element });
    }
    pluginEvents.emit('tab:hands', { userId, tabId, steps: steps.length, completed: result.completed, humanized: inputConfig.enabled });
    res.json(result);
  } catch (err) {
    log('error', 'hands failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /tabs/{tabId}/behavior:
 *   get:
 *     tags: [Interaction]
 *     summary: Get behavioral timing telemetry
 *     description: >
 *       Reports bounded, in-memory event timing diversity for the tab. The assessment
 *       is a local heuristic and does not claim acceptance by third-party bot detectors.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Behavioral timing report.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/behavior', async (req, res) => {
  const userId = req.query.userId;
  const session = sessions.get(normalizeUserId(userId));
  const found = session && findTab(session, req.params.tabId);
  if (!found) return tabNotFoundResponse(res, req.params.tabId);
  session.lastAccess = Date.now();
  res.json({ ok: true, tabId: req.params.tabId, ...behaviorReport(found.tabState.behavior) });
});

// Viewport
/**
 * @openapi
 * /tabs/{tabId}/viewport:
 *   post:
 *     tags: [Interaction]
 *     summary: Set the page viewport size
 *     description: >
 *       Physically resizes the page via Playwright's `page.setViewportSize`,
 *       triggering a real layout reflow. Use for responsive testing —
 *       `window.resizeTo()` is a no-op on non-popup windows.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, width, height]
 *             properties:
 *               userId:
 *                 type: string
 *               width:
 *                 type: integer
 *                 minimum: 100
 *                 maximum: 4000
 *               height:
 *                 type: integer
 *                 minimum: 100
 *                 maximum: 4000
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Viewport set.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 width:
 *                   type: integer
 *                 height:
 *                   type: integer
 *       400:
 *         description: Width or height missing or out of range.
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/viewport', async (req, res) => {
  try {
    const { userId, width, height } = req.body;
    if (!Number.isFinite(width) || !Number.isFinite(height) || width < 100 || height < 100 || width > 4000 || height > 4000) {
      return res.status(400).json({ error: 'width and height required (100..4000 px)' });
    }
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return res.status(404).json({ error: 'Tab not found' });
    session.lastAccess = Date.now();

    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;

    await withTabMutationLock(req.params.tabId, tabState, async () => {
      await tabState.page.setViewportSize({ width: Math.round(width), height: Math.round(height) });
      await tabState.page.waitForTimeout(150);
    });

    pluginEvents.emit('tab:viewport', { userId, tabId: req.params.tabId, width, height });
    res.json({ ok: true, width: Math.round(width), height: Math.round(height) });
  } catch (err) {
    log('error', 'viewport failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Back
/**
 * @openapi
 * /tabs/{tabId}/back:
 *   post:
 *     tags: [Navigation]
 *     summary: Go back
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Navigated back.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 url:
 *                   type: string
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/back', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId } = req.body;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    const result = await withTabMutationLock(tabId, tabState, async () => {
      try {
        await tabState.page.goBack({ timeout: 20000 });
      } catch (navErr) {
        // NS_BINDING_CANCELLED_OLD_LOAD: Firefox cancels the old load when going back.
        // The navigation itself succeeded -- just the prior page's load was interrupted.
        if (navErr.message && navErr.message.includes('NS_BINDING_CANCELLED')) {
          log('info', 'goBack cancelled old load (expected)', { reqId: req.reqId, tabId });
        } else {
          throw navErr;
        }
      }
      tabState.refs = await buildRefs(tabState.page);
      return { ok: true, url: tabState.page.url() };
    });
    
    res.json(result);
  } catch (err) {
    log('error', 'back failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Forward
/**
 * @openapi
 * /tabs/{tabId}/forward:
 *   post:
 *     tags: [Navigation]
 *     summary: Go forward
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Navigated forward.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 url:
 *                   type: string
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/forward', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId } = req.body;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    const result = await withTabMutationLock(tabId, tabState, async () => {
      await tabState.page.goForward({ timeout: 10000 });
      tabState.refs = await buildRefs(tabState.page);
      return { ok: true, url: tabState.page.url() };
    });
    
    res.json(result);
  } catch (err) {
    log('error', 'forward failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Refresh
/**
 * @openapi
 * /tabs/{tabId}/refresh:
 *   post:
 *     tags: [Navigation]
 *     summary: Refresh page
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId]
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Page refreshed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 url:
 *                   type: string
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/refresh', async (req, res) => {
  const tabId = req.params.tabId;
  
  try {
    const { userId } = req.body;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    const result = await withTabMutationLock(tabId, tabState, async () => {
      await tabState.page.reload({ timeout: 30000 });
      tabState.refs = await buildRefs(tabState.page);
      return { ok: true, url: tabState.page.url() };
    });
    
    res.json(result);
  } catch (err) {
    log('error', 'refresh failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Get links
/**
 * @openapi
 * /tabs/{tabId}/links:
 *   get:
 *     tags: [Content]
 *     summary: Extract page links
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Links extracted.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 links:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       text:
 *                         type: string
 *                       href:
 *                         type: string
 *                       ref:
 *                         type: string
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/links', async (req, res) => {
  try {
    const userId = req.query.userId;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) {
      log('warn', 'links: tab not found', { reqId: req.reqId, tabId: req.params.tabId, userId, hasSession: !!session });
      return tabNotFoundResponse(res, req.params.tabId);
    }
    session.lastAccess = Date.now();
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    const result = await withTabLock(req.params.tabId, async () => {
      const allLinks = await tabState.page.evaluate(() => {
        const links = [];
        document.querySelectorAll('a[href]').forEach(a => {
          const href = a.href;
          const text = a.textContent?.trim().slice(0, 100) || '';
          if (href && href.startsWith('http')) {
            links.push({ url: href, text });
          }
        });
        return links;
      });
      
      const total = allLinks.length;
      const paginated = allLinks.slice(offset, offset + limit);
      
      return {
        links: paginated,
        pagination: { total, offset, limit, hasMore: offset + limit < total }
      };
    });
    
    res.json(result);
  } catch (err) {
    log('error', 'links failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Get captured downloads
/**
 * @openapi
 * /tabs/{tabId}/downloads:
 *   get:
 *     tags: [Content]
 *     summary: List tab downloads
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Downloads list.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 downloads:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       filename:
 *                         type: string
 *                       url:
 *                         type: string
 *                       state:
 *                         type: string
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/downloads', async (req, res) => {
  try {
    const userId = req.query.userId;
    const includeData = req.query.includeData === 'true';
    const consume = req.query.consume === 'true';
    const maxBytesRaw = Number(req.query.maxBytes);
    const maxBytes = Number.isFinite(maxBytesRaw) && maxBytesRaw > 0 ? maxBytesRaw : MAX_DOWNLOAD_INLINE_BYTES;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();

    const { tabState } = found;
    tabState.toolCalls++;

    const downloads = await getDownloadsList(tabState, { includeData, maxBytes });

    if (consume) {
      await clearTabDownloads(tabState);
    }

    res.json({ tabId: req.params.tabId, downloads });
  } catch (err) {
    failuresTotal.labels(classifyError(err), 'downloads').inc();
    log('error', 'downloads failed', { reqId: req.reqId, error: err.message });
    res.status(500).json({ error: safeError(err) });
  }
});

// Get image elements from current page
/**
 * @openapi
 * /tabs/{tabId}/images:
 *   get:
 *     tags: [Content]
 *     summary: Extract page images
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Images extracted.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 images:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       src:
 *                         type: string
 *                       alt:
 *                         type: string
 *                       width:
 *                         type: integer
 *                       height:
 *                         type: integer
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/images', async (req, res) => {
  try {
    const userId = req.query.userId;
    const includeData = req.query.includeData === 'true';
    const maxBytesRaw = Number(req.query.maxBytes);
    const limitRaw = Number(req.query.limit);
    const maxBytes = Number.isFinite(maxBytesRaw) && maxBytesRaw > 0 ? maxBytesRaw : MAX_DOWNLOAD_INLINE_BYTES;
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(Math.floor(limitRaw), 20) : 8;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();

    const { tabState } = found;
    tabState.toolCalls++;

    const images = await extractPageImages(tabState.page, { includeData, maxBytes, limit });

    res.json({ tabId: req.params.tabId, images });
  } catch (err) {
    failuresTotal.labels(classifyError(err), 'images').inc();
    log('error', 'images failed', { reqId: req.reqId, error: err.message });
    res.status(500).json({ error: safeError(err) });
  }
});

// Screenshot
/**
 * @openapi
 * /tabs/{tabId}/screenshot:
 *   get:
 *     tags: [Content]
 *     summary: Take a screenshot
 *     description: Returns a PNG screenshot. When path is set, writes the PNG and returns JSON metadata instead of image bytes.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *       - name: fullPage
 *         in: query
 *         required: false
 *         schema:
 *           type: boolean
 *       - name: path
 *         in: query
 *         required: false
 *         description: Destination PNG path. Relative paths resolve from GOLIATH_WORKSPACE when set, otherwise GOLIATH_SCREENSHOTS_DIR.
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Screenshot PNG, or JSON metadata when path is set.
 *         content:
 *           image/png:
 *             schema:
 *               type: string
 *               format: binary
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 path:
 *                   type: string
 *                 bytes:
 *                   type: integer
 *                 fullPage:
 *                   type: boolean
 *       400:
 *         description: Invalid output path.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/screenshot', async (req, res) => {
  try {
    const userId = req.query.userId;
    const fullPage = req.query.fullPage === 'true';
    const savePath = typeof req.query.path === 'string' ? req.query.path.trim() : '';
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();

    const { tabState } = found;
    const buffer = await tabState.page.screenshot({ type: 'png', fullPage });
    pluginEvents.emit('tab:screenshot', { userId, tabId: req.params.tabId, buffer });
    if (!savePath) {
      res.set('Content-Type', 'image/png');
      return res.send(buffer);
    }
    const dest = await writeOutputFile(savePath, buffer, {
      workspaceDir: CONFIG.workspaceDir,
      screenshotsDir: CONFIG.screenshotsDir,
    });
    res.json({ path: dest, bytes: buffer.length, fullPage });
  } catch (err) {
    log('error', 'screenshot failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Stats
/**
 * @openapi
 * /tabs/{tabId}/stats:
 *   get:
 *     tags: [Tabs]
 *     summary: Tab statistics
 *     description: Returns tab metadata including URL, tool call count, visited URLs, download/failure counts.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Tab stats.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tabId:
 *                   type: string
 *                 url:
 *                   type: string
 *                 toolCalls:
 *                   type: integer
 *                 visitedUrls:
 *                   type: array
 *                   items:
 *                     type: string
 *                 downloadCount:
 *                   type: integer
 *                 consecutiveFailures:
 *                   type: integer
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/tabs/:tabId/stats', async (req, res) => {
  try {
    const userId = req.query.userId;
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);
    session.lastAccess = Date.now();
    
    const { tabState, listItemId } = found;
    res.json({
      tabId: req.params.tabId,
      sessionKey: listItemId,
      listItemId, // Legacy compatibility
      url: tabState.page.url(),
      visitedUrls: Array.from(tabState.visitedUrls),
      downloadsCount: Array.isArray(tabState.downloads) ? tabState.downloads.length : 0,
      toolCalls: tabState.toolCalls,
      refsCount: tabState.refs.size
    });
  } catch (err) {
    log('error', 'stats failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Evaluate JavaScript in page context
/**
 * @openapi
 * /tabs/{tabId}/evaluate:
 *   post:
 *     tags: [Interaction]
 *     summary: Evaluate JavaScript in tab
 *     description: Runs arbitrary JS in the page context and returns the result.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, expression]
 *             properties:
 *               userId:
 *                 type: string
 *               expression:
 *                 type: string
 *                 description: JavaScript expression to evaluate.
 *     responses:
 *       423:
 *         description: Tab paused for human handoff.
 *       200:
 *         description: Evaluation result.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 result: {}
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/evaluate', authMiddleware(), express.json({ limit: '1mb' }), async (req, res) => {
  try {
    const { userId, expression } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    if (!expression) return res.status(400).json({ error: 'expression is required' });

    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);

    session.lastAccess = Date.now();
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;

    pluginEvents.emit('tab:evaluate', { userId, tabId: req.params.tabId, expression });
    const result = await withTabMutationLock(req.params.tabId, tabState, () => tabState.page.evaluate(expression));
    pluginEvents.emit('tab:evaluated', { userId, tabId: req.params.tabId, result });
    log('info', 'evaluate', { reqId: req.reqId, tabId: req.params.tabId, userId, resultType: typeof result });
    res.json({ ok: true, result });
  } catch (err) {
    log('error', 'evaluate failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Structured extraction using temporary refs or durable semantic node IDs
/**
 * @openapi
 * /tabs/{tabId}/extract:
 *   post:
 *     tags: [Content]
 *     summary: Provenance-aware structured data extraction via JSON Schema
 *     description: |
 *       Legacy mode resolves `x-ref` hints against the latest accessibility snapshot.
 *       Semantic mode resolves durable `x-node-id` bindings against a versioned semantic
 *       snapshot and returns confidence plus per-field evidence. Array schemas can supply
 *       row bindings in `x-items`. No model fallback runs inside this endpoint.
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, schema]
 *             properties:
 *               userId:
 *                 type: string
 *               snapshotId:
 *                 type: string
 *                 description: Semantic snapshot ID returned by POST /tabs/{tabId}/observe.
 *               mode:
 *                 type: string
 *                 enum: [legacy, semantic, deterministic_then_model]
 *                 description: deterministic_then_model currently reports deterministic unresolved fields without invoking a model.
 *               schema:
 *                 type: object
 *                 description: |
 *                   JSON Schema with object properties or an array of objects. Each property
 *                   may bind using `x-ref` (legacy) or `x-node-id` (semantic). Semantic array
 *                   schemas use `x-items`, an array of property-to-node-ID binding maps.
 *                 additionalProperties: true
 *     responses:
 *       200:
 *         description: Extraction succeeded.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 data:
 *                   description: Extracted object or array matching the requested schema.
 *                 confidence:
 *                   type: number
 *                 evidence:
 *                   description: Per-field source snapshot and node provenance.
 *                 unresolvedFields:
 *                   type: array
 *                   items: { type: string }
 *                 snapshotId:
 *                   type: string
 *                 modelUsage:
 *                   nullable: true
 *                   description: Reserved model-fallback usage; currently always null.
 *       400:
 *         description: Missing userId, missing schema, or invalid schema.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Requested temporary refs or semantic snapshot are unavailable.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                 snapshot:
 *                   type: string
 *                   nullable: true
 *       422:
 *         description: Extraction failed (e.g. required ref not found).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 error:
 *                   type: string
 *                 snapshot:
 *                   type: string
 *                   nullable: true
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/:tabId/extract', express.json({ limit: '256kb' }), async (req, res) => {
  try {
    const { userId, schema, snapshotId, mode } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    if (!schema) return res.status(400).json({ error: 'schema is required' });

    const semanticMode = Boolean(snapshotId || mode === 'semantic' || mode === 'deterministic_then_model');
    const check = semanticMode ? validateSemanticSchema(schema) : validateExtractSchema(schema);
    if (!check.ok) return res.status(400).json({ error: check.error });

    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    if (!found) return tabNotFoundResponse(res, req.params.tabId || req.body?.tabId);

    session.lastAccess = Date.now();
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0;

    if (semanticMode) {
      let semanticSnapshot = snapshotId ? tabState.semanticSnapshots.get(snapshotId) : tabState.lastSemanticSnapshot;
      if (!semanticSnapshot) {
        semanticSnapshot = await withUserLimit(userId, () => withTabLock(req.params.tabId, () => captureSemanticObservation(tabState, { session })));
      }
      if (!semanticSnapshot) return res.status(409).json({ error: 'semantic snapshot unavailable -- call POST /tabs/:tabId/observe first' });
      const result = extractSemantic({ schema, snapshot: semanticSnapshot });
      return res.json({ ok: true, ...result, modelUsage: null });
    }

    if (!tabState.refs || tabState.refs.size === 0) {
      return res.status(409).json({
        error: 'no refs available -- call GET /tabs/:tabId/snapshot first to build the ref table',
        snapshot: tabState.lastSnapshot || null,
      });
    }

    try {
      const data = extractDeterministic({ schema, refs: tabState.refs });
      log('info', 'extract', { reqId: req.reqId, tabId: req.params.tabId, userId, keys: Object.keys(data) });
      res.json({ ok: true, data });
    } catch (extractErr) {
      log('warn', 'extract failed', { reqId: req.reqId, error: extractErr.message });
      res.status(422).json({ ok: false, error: extractErr.message, snapshot: tabState.lastSnapshot || null });
    }
  } catch (err) {
    failuresTotal.labels(classifyError(err), 'extract').inc();
    log('error', 'extract error', { reqId: req.reqId, error: err.message });
    res.status(500).json({ error: safeError(err) });
  }
});

// Close tab
/**
 * @openapi
 * /tabs/{tabId}:
 *   delete:
 *     tags: [Tabs]
 *     summary: Close a tab
 *     parameters:
 *       - name: tabId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Tab closed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *       423:
 *         description: Tab paused for human handoff.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.delete('/tabs/:tabId', async (req, res) => {
  try {
    const userId = req.query.userId || req.body?.userId;
    if (!userId) return res.status(400).json({ error: 'userId required (query or body)' });
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, req.params.tabId);
    const handoff = found && pausedHandoff(found.tabState);
    if (handoff) return res.status(423).json({ error: 'tab paused for human handoff', handoff });
    if (found) {
      await withTabMutationLock(req.params.tabId, found.tabState, async () => {
        const current = findTab(session, req.params.tabId);
        if (!current || current.tabState !== found.tabState) return;
        if (found.tabState.navigateAbort) found.tabState.navigateAbort.abort();
        await clearTabDownloads(found.tabState);
        disposeTabState(found.tabState, 'closed');
        await safePageClose(found.tabState.page);
        found.group.delete(req.params.tabId);
        if (found.group.size === 0) session.tabGroups.delete(found.listItemId);
        const lock = tabLocks.get(req.params.tabId);
        if (lock) {
          lock.drain();
          tabLocks.delete(req.params.tabId);
        }
      });
      refreshActiveTabsGauge();
      log('info', 'tab closed', { reqId: req.reqId, tabId: req.params.tabId, userId });
    }
    res.json({ ok: true });
  } catch (err) {
    log('error', 'tab close failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Close tab group
/**
 * @openapi
 * /tabs/group/{listItemId}:
 *   delete:
 *     tags: [Tabs]
 *     summary: Close all tabs in a group
 *     parameters:
 *       - name: listItemId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Group closed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 closed:
 *                   type: integer
 *       423:
 *         description: A tab in the group is paused for human handoff.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Session not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.delete('/tabs/group/:listItemId', async (req, res) => {
  try {
    const userId = req.query.userId || req.body?.userId;
    if (!userId) return res.status(400).json({ error: 'userId required (query or body)' });
    const session = sessions.get(normalizeUserId(userId));
    const group = session?.tabGroups.get(req.params.listItemId);
    const paused = findPausedHandoff(group);
    if (paused) {
      return res.status(423).json({
        error: 'tab group contains a tab paused for human handoff',
        tabId: paused.tabId,
        handoff: paused.handoff,
      });
    }
    if (group) {
      const tabEntries = Array.from(group.entries()).sort(([a], [b]) => a.localeCompare(b));
      await withTabGroupMutationLocks(tabEntries, async () => {
        const currentGroup = session.tabGroups.get(req.params.listItemId);
        if (currentGroup !== group) return;
        for (const [, tabState] of tabEntries) {
          await clearTabDownloads(tabState);
          disposeTabState(tabState, 'group_closed');
          await safePageClose(tabState.page);
        }
        session.tabGroups.delete(req.params.listItemId);
        for (const [tabId] of tabEntries) {
          const lock = tabLocks.get(tabId);
          if (lock) lock.drain();
          tabLocks.delete(tabId);
        }
      });
      refreshTabLockQueueDepth();
      refreshActiveTabsGauge();
      log('info', 'tab group closed', { reqId: req.reqId, listItemId: req.params.listItemId, userId });
    }
    res.json({ ok: true });
  } catch (err) {
    log('error', 'tab group close failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// List trace files for a session
/**
 * @openapi
 * /sessions/{userId}/traces:
 *   get:
 *     tags: [Sessions]
 *     summary: List trace files
 *     description: Returns all Playwright trace zip files for the given user session, sorted newest first.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: Session owner identifier.
 *     responses:
 *       200:
 *         description: Trace list.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 traces:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       filename:
 *                         type: string
 *                       sizeBytes:
 *                         type: integer
 *                       createdAt:
 *                         type: number
 *                       modifiedAt:
 *                         type: number
 *       403:
 *         description: Forbidden.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many trace requests.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/sessions/:userId/traces', authMiddleware(), traceIoRateLimit, async (req, res) => {
  try {
    const userId = normalizeUserId(req.params.userId);
    const traces = await listUserTraces(CONFIG.tracesDir, userId);
    res.json({ traces });
  } catch (err) {
    log('error', 'list traces failed', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Stream one trace file
/**
 * @openapi
 * /sessions/{userId}/traces/{filename}:
 *   get:
 *     tags: [Sessions]
 *     summary: Download a trace file
 *     description: Streams a Playwright trace zip for viewing in trace.playwright.dev.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: Session owner identifier.
 *       - name: filename
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: Trace zip filename.
 *     responses:
 *       200:
 *         description: Trace zip stream.
 *         content:
 *           application/zip:
 *             schema:
 *               type: string
 *               format: binary
 *       400:
 *         description: Invalid filename.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Trace not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Forbidden.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many trace requests.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.get('/sessions/:userId/traces/:filename', authMiddleware(), traceIoRateLimit, async (req, res) => {
  try {
    const userId = normalizeUserId(req.params.userId);
    const full = resolveTracePath(CONFIG.tracesDir, userId, req.params.filename);
    if (!full) return res.status(400).json({ error: 'invalid filename' });
    const st = await statTrace(full);
    if (!st) return res.status(404).json({ error: 'not found' });
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Length', String(st.size));
    const stream = fs.createReadStream(full);
    stream.on('error', (err) => {
      if (!res.headersSent) res.status(404).json({ error: 'not found' });
      else res.destroy();
    });
    stream.pipe(res);
  } catch (err) {
    log('error', 'stream trace failed', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// Delete one trace file
/**
 * @openapi
 * /sessions/{userId}/traces/{filename}:
 *   delete:
 *     tags: [Sessions]
 *     summary: Delete a trace file
 *     description: Removes a specific Playwright trace zip from the server.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: Session owner identifier.
 *       - name: filename
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *         description: Trace zip filename.
 *     responses:
 *       200:
 *         description: Trace deleted.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *       400:
 *         description: Invalid filename.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Trace not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Forbidden.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many trace requests.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.delete('/sessions/:userId/traces/:filename', authMiddleware(), traceIoRateLimit, async (req, res) => {
  try {
    const userId = normalizeUserId(req.params.userId);
    const full = resolveTracePath(CONFIG.tracesDir, userId, req.params.filename);
    if (!full) return res.status(400).json({ error: 'invalid filename' });
    try {
      await deleteTrace(full);
    } catch (err) {
      if (err.code === 'ENOENT') return res.status(404).json({ error: 'not found' });
      throw err;
    }
    res.json({ ok: true });
  } catch (err) {
    log('error', 'delete trace failed', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

/**
 * @openapi
 * /sessions/{userId}/secrets:
 *   post:
 *     tags: [Sessions]
 *     summary: Register a domain-scoped in-memory secret
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [secretId, value, allowedOrigins]
 *             properties:
 *               secretId: { type: string }
 *               value: { type: string, writeOnly: true }
 *               allowedOrigins: { type: array, items: { type: string } }
 *     responses:
 *       200: { description: Secret registered without echoing its value. }
 *       404: { description: Session not found. }
 */
app.post('/sessions/:userId/secrets', authMiddleware(), async (req, res) => {
  const userId = normalizeUserId(req.params.userId);
  const session = sessions.get(userId);
  if (!session) return res.status(404).json({ error: 'session not found' });
  const { secretId, value, allowedOrigins } = req.body;
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(String(secretId || '')) || typeof value !== 'string' || value.length === 0 || value.length > 10_000 || !Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
    return res.status(400).json({ error: 'secretId, non-empty string value (max 10000 chars), and non-empty allowedOrigins are required' });
  }
  let normalizedOrigins;
  try {
    normalizedOrigins = [...new Set(allowedOrigins.map(origin => {
      const parsed = new URL(origin);
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== origin) throw new Error('invalid origin');
      return parsed.origin;
    }))];
  } catch {
    return res.status(400).json({ error: 'allowedOrigins must contain exact HTTP(S) origins without paths' });
  }
  session.secrets.set(secretId, { value, allowedOrigins: normalizedOrigins, createdAt: new Date().toISOString() });
  pluginEvents.emit('session:secret:registered', { userId, secretId, allowedOrigins: normalizedOrigins });
  res.json({ ok: true, secretId, allowedOrigins: normalizedOrigins });
});

/**
 * @openapi
 * /sessions/{userId}/policy:
 *   get:
 *     tags: [Sessions]
 *     summary: Get the runtime capability policy for a session identity
 *     description: Returns the operator-managed, runtime-only policy or null when unrestricted.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Current policy state.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userId: { type: string }
 *                 policy:
 *                   allOf:
 *                     - $ref: '#/components/schemas/SessionPolicy'
 *                   nullable: true
 *       403: { description: Dedicated operator authentication failed. }
 *   post:
 *     tags: [Sessions]
 *     summary: Set or replace a runtime capability policy for a session identity
 *     description: Works before the browser session exists. When GOLIATH_API_KEY is configured, only that dedicated key is accepted. The shared access key cannot administer policies.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SessionPolicy'
 *     responses:
 *       200: { description: Policy set or replaced. }
 *       400: { description: Invalid policy. }
 *       403: { description: Dedicated operator authentication failed. }
 *   delete:
 *     tags: [Sessions]
 *     summary: Remove a runtime capability policy from a session identity
 *     description: Restores unrestricted behavior for the identity without deleting its browser session.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Policy removed. }
 *       403: { description: Dedicated operator authentication failed. }
 */
app.get('/sessions/:userId/policy', operatorAuthMiddleware(), (req, res) => {
  const userId = normalizeUserId(req.params.userId);
  res.json({ userId, policy: sessionPolicies.get(userId) || null });
});

app.post('/sessions/:userId/policy', operatorAuthMiddleware(), (req, res) => {
  try {
    const userId = normalizeUserId(req.params.userId);
    if (!userId || userId.length > 200) return res.status(400).json({ error: 'userId must be 1 to 200 characters' });
    const policy = normalizeSessionPolicy(req.body);
    sessionPolicies.set(userId, policy);
    const session = sessions.get(userId);
    if (session) session.policy = policy;
    pluginEvents.emit('session:policy:updated', { userId, policy });
    res.json({ ok: true, userId, policy });
  } catch (err) {
    sendError(res, err);
  }
});

app.delete('/sessions/:userId/policy', operatorAuthMiddleware(), (req, res) => {
  const userId = normalizeUserId(req.params.userId);
  const removed = sessionPolicies.delete(userId);
  const session = sessions.get(userId);
  if (session) session.policy = null;
  pluginEvents.emit('session:policy:cleared', { userId });
  res.json({ ok: true, userId, removed });
});

/**
 * @openapi
 * /sessions/{userId}/secrets/{secretId}:
 *   delete:
 *     tags: [Sessions]
 *     summary: Revoke an in-memory secret
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *       - name: secretId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Secret revoked. }
 *       404: { description: Session or secret not found. }
 */
app.delete('/sessions/:userId/secrets/:secretId', authMiddleware(), async (req, res) => {
  const session = sessions.get(normalizeUserId(req.params.userId));
  if (!session || !session.secrets.delete(req.params.secretId)) return res.status(404).json({ error: 'secret not found' });
  res.json({ ok: true });
});

/**
 * @openapi
 * /sessions/{userId}/checkpoints:
 *   get:
 *     tags: [Sessions]
 *     summary: List storage-state checkpoints
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Checkpoint list. }
 *   post:
 *     tags: [Sessions]
 *     summary: Create a storage-state checkpoint
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               checkpointId: { type: string }
 *     responses:
 *       200: { description: Checkpoint metadata and limitations. }
 *       404: { description: Session not found. }
 *       409: { description: Named checkpoint already exists. }
 */
app.get('/sessions/:userId/checkpoints', authMiddleware(), async (req, res) => {
  try {
    res.json({ checkpoints: await listCheckpoints(CONFIG.checkpointsDir, normalizeUserId(req.params.userId), {
      onWarning: detail => log('warn', 'checkpoint file skipped', detail),
    }) });
  } catch (err) { handleRouteError(err, req, res); }
});

app.post('/sessions/:userId/checkpoints', authMiddleware(), async (req, res) => {
  try {
    const userId = normalizeUserId(req.params.userId);
    const session = sessions.get(userId);
    if (!session) return res.status(404).json({ error: 'session not found' });
    const urls = session.context.pages().map(page => page.url());
    const checkpoint = await createCheckpoint({
      baseDir: CONFIG.checkpointsDir,
      userId,
      context: session.context,
      checkpointId: req.body?.checkpointId,
      metadata: { urls },
      onWarning: detail => log('warn', 'checkpoint file skipped', detail),
    });
    pluginEvents.emit('session:checkpoint', { userId, checkpointId: checkpoint.checkpointId });
    res.json({
      checkpointId: checkpoint.checkpointId,
      createdAt: checkpoint.createdAt,
      metadata: checkpoint.metadata,
      limitations: checkpoint.limitations,
    });
  } catch (err) {
    if (err.message === 'invalid checkpointId') return res.status(400).json({ error: err.message });
    if (err.message === 'checkpoint already exists') return res.status(409).json({ error: err.message });
    handleRouteError(err, req, res);
  }
});

/**
 * @openapi
 * /sessions/{userId}/checkpoints/{checkpointId}:
 *   delete:
 *     tags: [Sessions]
 *     summary: Delete a storage-state checkpoint
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *       - name: checkpointId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Checkpoint deleted. }
 *       404: { description: Checkpoint not found. }
 */
app.delete('/sessions/:userId/checkpoints/:checkpointId', authMiddleware(), async (req, res) => {
  try {
    const deleted = await deleteCheckpoint(CONFIG.checkpointsDir, normalizeUserId(req.params.userId), req.params.checkpointId, {
      onWarning: detail => log('warn', 'checkpoint file skipped', detail),
    });
    if (!deleted) return res.status(404).json({ error: 'checkpoint not found' });
    res.json({ ok: true });
  } catch (err) { handleRouteError(err, req, res); }
});

/**
 * @openapi
 * /sessions/{userId}/forks:
 *   post:
 *     tags: [Sessions]
 *     summary: Fork a session from a storage-state checkpoint
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [checkpointId, newUserId]
 *             properties:
 *               checkpointId: { type: string }
 *               newUserId: { type: string }
 *               url: { type: string }
 *               sessionKey: { type: string }
 *     responses:
 *       200: { description: New isolated session and tab. }
 *       404: { description: Checkpoint not found. }
 *       409: { description: Target session already exists. }
 */
app.post('/sessions/:userId/forks', authMiddleware(), async (req, res) => {
  let forkSession = null;
  let targetUserId = null;
  let reservation = null;
  let createdByFork = false;
  try {
    const sourceUserId = normalizeUserId(req.params.userId);
    const { checkpointId, newUserId, sessionKey = 'fork', url } = req.body;
    if (!checkpointId || !newUserId) return res.status(400).json({ error: 'checkpointId and newUserId are required' });
    targetUserId = normalizeUserId(newUserId);
    reservation = sessionReservations.reserve(targetUserId, {
      sessionExists: sessions.has(targetUserId),
      creationPending: sessionCreations.has(targetUserId),
    });
    if (!reservation) return res.status(409).json({ error: 'target session already exists or is reserved' });
    const checkpoint = await readCheckpoint(CONFIG.checkpointsDir, sourceUserId, checkpointId, {
      onWarning: detail => log('warn', 'checkpoint file skipped', detail),
    });
    if (!checkpoint) return res.status(404).json({ error: 'checkpoint not found' });
    const targetUrl = url || checkpoint.metadata?.urls?.[0] || 'about:blank';
    if (targetUrl !== 'about:blank') {
      const urlError = validateUrl(targetUrl);
      if (urlError) return res.status(400).json({ error: urlError });
    }
    const session = await getSession(targetUserId, { storageState: checkpoint.state, reservation });
    forkSession = session;
    createdByFork = true;
    const page = await session.context.newPage();
    if (targetUrl !== 'about:blank') await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: NAVIGATE_TIMEOUT_MS });
    const tabId = fly.makeTabId();
    const tabState = createTabState(page);
    attachDownloadListener(tabState, tabId, log, pluginEvents, targetUserId);
    getTabGroup(session, sessionKey).set(tabId, tabState);
    attachPopupHandler(page, targetUserId, sessionKey);
    refreshActiveTabsGauge();
    pluginEvents.emit('session:forked', { sourceUserId, targetUserId, checkpointId, tabId });
    res.json({
      ok: true,
      userId: targetUserId,
      tabId,
      url: page.url(),
      checkpointId,
      limitations: checkpoint.limitations,
    });
  } catch (err) {
    if (createdByFork && forkSession && targetUserId && sessions.get(targetUserId) === forkSession) {
      await closeSession(targetUserId, forkSession, { reason: 'fork_failed', clearDownloads: true, clearLocks: true }).catch(() => {});
    }
    handleRouteError(err, req, res);
  } finally {
    if (targetUserId && reservation) sessionReservations.release(targetUserId, reservation);
  }
});

// Close session
/**
 * @openapi
 * /sessions/{userId}:
 *   delete:
 *     tags: [Sessions]
 *     summary: Destroy a user session
 *     description: Closes all tabs and cleans up state for the given userId.
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session destroyed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 closed:
 *                   type: integer
 *       404:
 *         description: Session not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       423:
 *         description: Session contains a tab paused for human handoff.
 */
app.delete('/sessions/:userId', authMiddleware(), async (req, res) => {
  try {
    const userId = normalizeUserId(req.params.userId);
    const session = sessions.get(userId);
    if (session) {
      const paused = findPausedHandoffInSession(session);
      if (paused) {
        return res.status(423).json({
          error: 'session contains a tab paused for human handoff',
          tabId: paused.tabId,
          handoff: paused.handoff,
        });
      }
      const tabEntries = Array.from(session.tabGroups.values())
        .flatMap(group => Array.from(group.entries()))
        .sort(([a], [b]) => a.localeCompare(b));
      await withTabGroupMutationLocks(tabEntries, async () => {
        if (sessions.get(userId) !== session) return;
        await closeSession(userId, session, { reason: 'api_delete_session', clearDownloads: true, clearLocks: true });
      });
      log('info', 'session closed', { userId });
    }
    if (sessions.size === 0) scheduleBrowserIdleShutdown();
    res.json({ ok: true });
  } catch (err) {
    log('error', 'session close failed', { error: err.message });
    handleRouteError(err, req, res);
  }
});

// Cleanup stale sessions
runtimeInterval(async () => {
  const now = Date.now();
  for (const [userId, session] of Array.from(sessions.entries())) {
    if (sessionCanBeReaped(session) && now - session.lastAccess > SESSION_TIMEOUT_MS) {
      const idleMs = now - session.lastAccess;
      if (await closeReapableSession(userId, session, 'session_timeout')) {
        sessionsExpiredTotal.inc();
        pluginEvents.emit('session:expired', { userId, idleMs });
        log('info', 'session expired', { userId });
      }
    }
  }
  // When all sessions gone, start idle timer to kill browser
  if (sessions.size === 0) {
    scheduleBrowserIdleShutdown();
  }
  refreshTabLockQueueDepth();
}, 60_000);

// Memory pressure eviction (Fly.io only) — evict oldest session when RAM is high.
// Prevents Goliath OOM by proactively freeing BrowserContexts.
if (FLY_MACHINE_ID) {
  const MEMORY_HIGH_WATERMARK = 0.80;
  runtimeInterval(async () => {
    let totalMem = os.totalmem();
    let freeMem = os.freemem();
    let usedRatio = 1 - (freeMem / totalMem);

    // Evict sessions in a loop until memory drops below the watermark
    // or no more sessions remain. closeSession is async but memory
    // reclamation (context.close → Firefox frees pages) starts immediately.
    let evicted = 0;
    while (usedRatio >= MEMORY_HIGH_WATERMARK && sessions.size > 0) {
      let oldestKey = null;
      let oldestAccess = Infinity;
      for (const [key, session] of sessions) {
        if (!sessionCanBeReaped(session)) continue;
        if (session.lastAccess < oldestAccess) {
          oldestAccess = session.lastAccess;
          oldestKey = key;
        }
      }
      if (!oldestKey) break;
      const session = sessions.get(oldestKey);
      const idleMs = Date.now() - session.lastAccess;
      log('warn', 'memory pressure eviction', {
        userId: oldestKey,
        usedPct: (usedRatio * 100).toFixed(1),
        freeMb: Math.round(freeMem / 1048576),
        idleMs,
        sessions: sessions.size,
      });
      if (await closeReapableSession(oldestKey, session, 'memory_pressure')) {
        sessionsExpiredTotal.inc();
        evicted++;
      } else {
        break;
      }
      // Re-check after marking session for closure
      freeMem = os.freemem();
      usedRatio = 1 - (freeMem / totalMem);
    }
  }, 30_000);
}

// Per-tab inactivity reaper — close tabs idle for TAB_INACTIVITY_MS
runtimeInterval(async () => {
  const now = Date.now();
  for (const [userId, session] of sessions) {
    if (!sessionCanBeReaped(session)) continue;
    for (const [listItemId, group] of session.tabGroups) {
      for (const [tabId, tabState] of group) {
        const lockState = pressureLockState(tabId);
        if (lockState.active || lockState.queued > 0) continue;
        if (!tabState._lastReaperCheck) {
          tabState._lastReaperCheck = now;
          tabState._lastReaperToolCalls = tabState.toolCalls;
          continue;
        }
        if (tabState.toolCalls === tabState._lastReaperToolCalls) {
          const idleMs = now - tabState._lastReaperCheck;
          if (idleMs >= TAB_INACTIVITY_MS) {
            try {
              await withTabMutationLock(tabId, tabState, async () => {
                if (group.get(tabId) !== tabState || !sessionCanBeReaped(session)) return;
                if (tabState.toolCalls !== tabState._lastReaperToolCalls) return;
                tabsReapedTotal.inc();
                log('info', 'tab reaped (inactive)', { userId, tabId, listItemId, idleMs, toolCalls: tabState.toolCalls });
                disposeTabState(tabState, 'inactive');
                await safePageClose(tabState.page);
                group.delete(tabId);
                refreshActiveTabsGauge();
              });
            } catch (err) {
              if (err?.statusCode !== 423) log('warn', 'tab inactivity reaper skipped', { userId, tabId, error: err.message });
            }
          }
        } else {
          tabState._lastReaperCheck = now;
          tabState._lastReaperToolCalls = tabState.toolCalls;
        }
      }
      if (group.size === 0) {
        session.tabGroups.delete(listItemId);
      }
    }
    // Clean up sessions with zero tabs remaining -- free browser context memory
    if (session.tabGroups.size === 0 && sessionCanBeReaped(session)) {
      if (await closeReapableSession(userId, session, 'tab_reaper_empty_session')) {
        log('info', 'session empty after tab reaper, closing', { userId });
        sessionsExpiredTotal.inc();
      }
    }
  }
  if (sessions.size === 0) scheduleBrowserIdleShutdown();
}, 60_000);

// Orphan page reaper -- force-closes Playwright pages that survived a safePageClose
// timeout or were otherwise dropped from tabGroups tracking. Without this, leaked
// pages starve Firefox of DOM threads and eventually block new tab creation.
runtimeInterval(() => {
  let reaped = 0;
  for (const session of sessions.values()) {
    if (session._closing) continue;
    let contextPages;
    try {
      contextPages = session.context.pages();
    } catch (_) {
      continue; // context already dead
    }
    const registered = new Set();
    for (const group of session.tabGroups.values()) {
      for (const tabState of group.values()) registered.add(tabState.page);
    }
    for (const page of contextPages) {
      if (!registered.has(page)) {
        reaped++;
        page.removeAllListeners();
        page.close({ runBeforeUnload: false }).catch(() => {});
      }
    }
  }
  if (reaped > 0) log('warn', 'orphan page reaper closed leaked pages', { reaped });
}, 60_000);

// Idle memory pressure restart -- when all sessions are gone, kill the browser
// process immediately if either Node native memory or the Goliath process tree
// is large. This prevents idle Firefox children from holding most of the VM RAM
// while Node reports zero sessions/tabs.
runtimeInterval(() => {
  if (sessions.size > 0 || !browser) return;
  const mem = process.memoryUsage();
  const nativeMemMb = Math.round((mem.rss - mem.heapUsed) / 1048576);
  const browserRssMb = browserProcessTreeRssMb(_browserPid());

  if (browserRssMb !== null && browserRssMb >= CONFIG.browserRssRestartThresholdMb) {
    log('warn', 'browser rss pressure, restarting browser', {
      browserRssMb,
      thresholdMb: CONFIG.browserRssRestartThresholdMb,
    });
    browserRestartsTotal.labels('browser_rss_pressure').inc();
    closeBrowserFully('browser_rss_pressure').catch((err) => {
      log('error', 'browser rss pressure browser close failed', { error: err.message });
    });
    return;
  }

  if (_nativeMemBaseline === null) {
    _nativeMemBaseline = nativeMemMb;
    return;
  }
  const growth = nativeMemMb - _nativeMemBaseline;
  if (growth >= NATIVE_MEM_RESTART_THRESHOLD_MB) {
    log('warn', 'native memory pressure, restarting browser', {
      baselineMb: _nativeMemBaseline,
      currentMb: nativeMemMb,
      growthMb: growth,
      thresholdMb: NATIVE_MEM_RESTART_THRESHOLD_MB,
    });
    browserRestartsTotal.labels('memory_pressure').inc();
    closeBrowserFully('memory_pressure').catch((err) => {
      log('error', 'memory pressure browser close failed', { error: err.message });
    });
  }
}, 30_000);

// =============================================================================
// OpenClaw-compatible endpoint aliases
// These allow goliath to be used as a profile backend for OpenClaw's browser tool
// =============================================================================

// GET / - Status (passive -- does not launch browser)
/**
 * @openapi
 * /:
 *   get:
 *     tags: [System]
 *     summary: Server status
 *     description: Returns basic server liveness and browser state.
 *     responses:
 *       200:
 *         description: Server status.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 enabled:
 *                   type: boolean
 *                 running:
 *                   type: boolean
 *                 engine:
 *                   type: string
 *                 browserConnected:
 *                   type: boolean
 *                 browserRunning:
 *                   type: boolean
 */
app.get('/', (req, res) => {
  const running = browser !== null && (browser.isConnected?.() ?? false);
  res.json({ 
    ok: true,
    enabled: true,
    running,
    engine: 'goliath',
    browserConnected: running,
    browserRunning: running,
  });
});

// GET /tabs - List all tabs (OpenClaw expects this)
/**
 * @openapi
 * /tabs:
 *   get:
 *     tags: [Tabs]
 *     summary: List open tabs
 *     description: Returns all tabs for a given userId.
 *     parameters:
 *       - name: userId
 *         in: query
 *         schema:
 *           type: string
 *         description: Filter by session owner.
 *     responses:
 *       200:
 *         description: Tab list.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 running:
 *                   type: boolean
 *                 tabs:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       tabId:
 *                         type: string
 *                       targetId:
 *                         type: string
 *                       url:
 *                         type: string
 *                       title:
 *                         type: string
 *                       listItemId:
 *                         type: string
 */
app.get('/tabs', async (req, res) => {
  try {
    const userId = req.query.userId;
    const session = sessions.get(normalizeUserId(userId));
    
    if (!session) {
      return res.json({ running: true, tabs: [] });
    }
    
    const tabs = [];
    for (const [listItemId, group] of session.tabGroups) {
      for (const [tabId, tabState] of group) {
        tabs.push({
          targetId: tabId,
          tabId,
          url: tabState.page.url(),
          title: await tabState.page.title().catch(() => ''),
          listItemId
        });
      }
    }
    
    res.json({ running: true, tabs });
  } catch (err) {
    log('error', 'list tabs failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// POST /tabs/open - Open tab (alias for POST /tabs, OpenClaw format)
/**
 * @openapi
 * /tabs/open:
 *   post:
 *     tags: [Legacy]
 *     summary: Open tab (OpenClaw format)
 *     deprecated: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, url]
 *             properties:
 *               userId:
 *                 type: string
 *               url:
 *                 type: string
 *               listItemId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Tab opened.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/tabs/open', async (req, res) => {
  try {
    const { url, userId, listItemId = 'default' } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    if (!url) {
      return res.status(400).json({ error: 'url is required' });
    }
    
    const urlErr = validateUrl(url);
    if (urlErr) return res.status(400).json({ error: urlErr });
    
    let session = await getSession(userId);
    
    // Recycle oldest tab when limits are reached instead of rejecting
    let totalTabs = 0;
    for (const g of session.tabGroups.values()) totalTabs += g.size;
    if (totalTabs >= MAX_TABS_PER_SESSION || getTotalTabCount() >= MAX_TABS_GLOBAL) {
      const recycled = await recycleOldestTab(session, req.reqId, userId);
      if (!recycled) {
        return res.status(429).json({ error: 'Maximum tabs per session reached' });
      }
    }
    
    let group = getTabGroup(session, listItemId);
    
    let page = await session.context.newPage();
    const tabId = fly.makeTabId();
    let tabState = createTabState(page);
    attachDownloadListener(tabState, tabId, log, pluginEvents, userId);
    group.set(tabId, tabState);
    attachPopupHandler(page, userId, listItemId);
    refreshActiveTabsGauge();
    
    try {
      await withPageLoadDuration('open_url', () => page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }));
    } catch (navErr) {
      if ((isProxyError(navErr) || isTimeoutError(navErr)) && proxyPool?.canRotateSessions) {
        log('warn', 'tab open failed, retrying with fresh proxy', {
          reqId: req.reqId, tabId, error: navErr.message,
        });
        browserRestartsTotal.labels('proxy_retry').inc();
        const key = normalizeUserId(userId);
        const oldSession = sessions.get(key);
        if (oldSession) {
          await closeSession(key, oldSession, { reason: 'proxy_retry_rotate', clearDownloads: true, clearLocks: true });
        }
        session = await getSession(userId);
        group = getTabGroup(session, listItemId);
        page = await session.context.newPage();
        tabState = createTabState(page);
        attachDownloadListener(tabState, tabId, log, pluginEvents, userId);
        group.set(tabId, tabState);
        attachPopupHandler(page, userId, listItemId);
        refreshActiveTabsGauge();
        await withPageLoadDuration('open_url', () => page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }));
      } else {
        throw navErr;
      }
    }
    tabState.visitedUrls.add(url);
    
    log('info', 'openclaw tab opened', { reqId: req.reqId, tabId, url: page.url() });
    res.json({ 
      ok: true,
      targetId: tabId,
      tabId,
      url: page.url(),
      title: await page.title().catch(() => '')
    });
  } catch (err) {
    log('error', 'openclaw tab open failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// POST /start - Start browser (OpenClaw expects this)
/**
 * @openapi
 * /start:
 *   post:
 *     tags: [Browser]
 *     summary: Start browser
 *     description: Ensures the browser process is running. Idempotent.
 *     responses:
 *       200:
 *         description: Browser started.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 profile:
 *                   type: string
 *       500:
 *         description: Launch failed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/start', async (req, res) => {
  try {
    await ensureBrowser();
    res.json({ ok: true, profile: 'goliath' });
  } catch (err) {
    failuresTotal.labels('browser_launch', 'start').inc();
    res.status(500).json({ ok: false, error: safeError(err) });
  }
});

// POST /stop - Stop browser (OpenClaw expects this)
/**
 * @openapi
 * /stop:
 *   post:
 *     tags: [Browser]
 *     summary: Stop browser
 *     description: Privileged force-stop that terminates active human handoffs with an audited termination event, closes all sessions, and stops the browser. Requires x-admin-key header.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Browser stopped.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 stopped:
 *                   type: boolean
 *                 profile:
 *                   type: string
 *       403:
 *         description: Forbidden.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/stop', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || !timingSafeCompare(adminKey, CONFIG.adminKey)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    await closeAllSessions('admin_stop', { clearDownloads: true, clearLocks: true });
    await closeBrowserFully('admin_stop');
    res.json({ ok: true, stopped: true, profile: 'goliath' });
  } catch (err) {
    res.status(500).json({ ok: false, error: safeError(err) });
  }
});

// POST /navigate - Navigate (OpenClaw format with targetId in body)
/**
 * @openapi
 * /navigate:
 *   post:
 *     tags: [Legacy]
 *     summary: Navigate (OpenClaw format)
 *     description: Navigate with targetId in body instead of path param.
 *     deprecated: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, url]
 *             properties:
 *               userId:
 *                 type: string
 *               targetId:
 *                 type: string
 *               url:
 *                 type: string
 *     responses:
 *       200:
 *         description: Navigation result.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       423:
 *         description: Tab paused for human handoff.
 */
app.post('/navigate', async (req, res) => {
  try {
    const { targetId, url, userId } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    if (!url) {
      return res.status(400).json({ error: 'url is required' });
    }
    
    const urlErr = validateUrl(url);
    if (urlErr) return res.status(400).json({ error: urlErr });
    
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, targetId);
    if (!found) {
      return tabNotFoundResponse(res, req.params.tabId || targetId);
    }
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    const result = await withTabMutationLock(targetId, tabState, async () => {
      await withPageLoadDuration('navigate', () => tabState.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }));
      tabState.visitedUrls.add(url);
      tabState.lastSnapshot = null;
      
      // Google SERP: defer extraction to snapshot call
      if (isGoogleSerp(tabState.page.url())) {
        tabState.refs = new Map();
        return { ok: true, targetId, url: tabState.page.url(), googleSerp: true };
      }
      
      tabState.refs = await buildRefs(tabState.page);
      return { ok: true, targetId, url: tabState.page.url() };
    });
    
    res.json(result);
  } catch (err) {
    log('error', 'openclaw navigate failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// GET /snapshot - Snapshot (OpenClaw format with query params)
/**
 * @openapi
 * /snapshot:
 *   get:
 *     tags: [Legacy]
 *     summary: Snapshot (OpenClaw format)
 *     description: Snapshot with targetId/userId as query params.
 *     deprecated: true
 *     parameters:
 *       - name: targetId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *       - name: userId
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *       - name: format
 *         in: query
 *         schema:
 *           type: string
 *       - name: offset
 *         in: query
 *         schema:
 *           type: integer
 *       - name: includeScreenshot
 *         in: query
 *         schema:
 *           type: string
 *           enum: ['true', 'false']
 *     responses:
 *       200:
 *         description: Snapshot.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       423:
 *         description: Tab paused for human handoff.
 */
app.get('/snapshot', async (req, res) => {
  try {
    const { targetId, userId, format = 'text' } = req.query;
    const offset = parseInt(req.query.offset) || 0;
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, targetId);
    if (!found) {
      return tabNotFoundResponse(res, req.params.tabId || targetId);
    }
    
    const { tabState } = found;
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;

    // Cached chunk retrieval
    if (offset > 0 && tabState.lastSnapshot) {
      const win = windowSnapshot(tabState.lastSnapshot, offset);
      const response = { ok: true, format: 'aria', targetId, url: tabState.page.url(), snapshot: win.text, refsCount: tabState.refs.size, truncated: win.truncated, totalChars: win.totalChars, hasMore: win.hasMore, nextOffset: win.nextOffset };
      if (req.query.includeScreenshot === 'true') {
        const pngBuffer = await tabState.page.screenshot({ type: 'png' });
        response.screenshot = { data: pngBuffer.toString('base64'), mimeType: 'image/png' };
      }
      return res.json(response);
    }

    const pageUrl = tabState.page.url();
    
    // Google SERP fast path
    if (isGoogleSerp(pageUrl)) {
      const { refs: googleRefs, snapshot: googleSnapshot } = await extractGoogleSerp(tabState.page);
      tabState.refs = googleRefs;
      tabState.lastSnapshot = googleSnapshot;
      snapshotBytes.labels('google_serp').observe(Buffer.byteLength(googleSnapshot, 'utf8'));
      const annotatedYaml = googleSnapshot;
      const win = windowSnapshot(annotatedYaml, 0);
      const response = {
        ok: true, format: 'aria', targetId, url: pageUrl,
        snapshot: win.text, refsCount: tabState.refs.size,
        truncated: win.truncated, totalChars: win.totalChars,
        hasMore: win.hasMore, nextOffset: win.nextOffset,
      };
      if (req.query.includeScreenshot === 'true') {
        const pngBuffer = await tabState.page.screenshot({ type: 'png' });
        response.screenshot = { data: pngBuffer.toString('base64'), mimeType: 'image/png' };
      }
      return res.json(response);
    }
    
    tabState.refs = await buildRefs(tabState.page);
    
    const ariaYaml = await getAriaSnapshot(tabState.page);
    
    // Annotate YAML with ref IDs
    let annotatedYaml = ariaYaml || '';
    if (annotatedYaml && tabState.refs.size > 0) {
      const refsByKey = new Map();
      for (const [refId, el] of tabState.refs) {
        const key = `${el.role}:${el.name || ''}`;
        if (!refsByKey.has(key)) refsByKey.set(key, refId);
      }
      
      const lines = annotatedYaml.split('\n');
      annotatedYaml = lines.map(line => {
        const match = line.match(/^(\s*)-\s+(\w+)(?:\s+"([^"]*)")?/);
        if (match) {
          const [, indent, role, name] = match;
          const key = `${role}:${name || ''}`;
          const refId = refsByKey.get(key);
          if (refId) {
            return line.replace(/^(\s*-\s+\w+)/, `$1 [${refId}]`);
          }
        }
        return line;
      }).join('\n');
    }

    annotatedYaml = redactSecretValues(annotatedYaml, session);
    tabState.lastSnapshot = annotatedYaml;
    if (annotatedYaml) snapshotBytes.labels('full').observe(Buffer.byteLength(annotatedYaml, 'utf8'));
    const win = windowSnapshot(annotatedYaml, 0);

    const response = {
      ok: true,
      format: 'aria',
      targetId,
      url: tabState.page.url(),
      snapshot: win.text,
      refsCount: tabState.refs.size,
      truncated: win.truncated,
      totalChars: win.totalChars,
      hasMore: win.hasMore,
      nextOffset: win.nextOffset,
    };

    if (req.query.includeScreenshot === 'true') {
      const pngBuffer = await tabState.page.screenshot({ type: 'png' });
      response.screenshot = { data: pngBuffer.toString('base64'), mimeType: 'image/png' };
    }

    res.json(response);
  } catch (err) {
    log('error', 'openclaw snapshot failed', { reqId: req.reqId, error: err.message });
    handleRouteError(err, req, res);
  }
});

// POST /act - Combined action endpoint (OpenClaw format)
// Routes to click/type/scroll/press/etc based on 'kind' parameter
/**
 * @openapi
 * /act:
 *   post:
 *     tags: [Legacy]
 *     summary: Combined action (OpenClaw format)
 *     description: Routes to click/type/scroll/press/etc based on "kind" parameter.
 *     deprecated: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [userId, kind]
 *             properties:
 *               userId:
 *                 type: string
 *               kind:
 *                 type: string
 *                 description: 'Action kind: click, type, scroll, scrollIntoView, press, hold, select_option, drag, hover, wait, or close.'
 *               targetId:
 *                 type: string
 *               ref:
 *                 type: string
 *               selector:
 *                 type: string
 *               text:
 *                 type: string
 *               key:
 *                 type: string
 *               holdMs:
 *                 type: number
 *                 minimum: 200
 *                 maximum: 15000
 *               timeMs:
 *                 type: number
 *               direction:
 *                 type: string
 *               value:
 *                 type: string
 *               values:
 *                 type: array
 *                 items:
 *                   type: string
 *               sourceRef:
 *                 type: string
 *               sourceSelector:
 *                 type: string
 *               targetRef:
 *                 type: string
 *               targetSelector:
 *                 type: string
 *     responses:
 *       200:
 *         description: Action result.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       400:
 *         description: Bad request.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Tab not found.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       423:
 *         description: Tab paused for human handoff.
 */
app.post('/act', async (req, res) => {
  try {
    const { kind, targetId, userId, ...params } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    
    if (!kind) {
      return res.status(400).json({ error: 'kind is required' });
    }
    
    const session = sessions.get(normalizeUserId(userId));
    const found = session && findTab(session, targetId);
    if (!found) {
      return tabNotFoundResponse(res, req.params.tabId || targetId);
    }
    
    const { tabState } = found;
    if (tabState.handoff?.status === 'paused') {
      return res.status(423).json({ error: 'tab paused for human handoff', handoff: tabState.handoff });
    }
    tabState.toolCalls++; tabState.consecutiveTimeouts = 0; tabState.consecutiveFailures = 0;
    
    const result = await withTabMutationLock(targetId, tabState, async () => {
      switch (kind) {
        case 'hold': {
          const holdMs = parseHoldMs(params.holdMs ?? params.timeMs);
          if (holdMs === undefined) {
            const error = new Error('holdMs or timeMs is required');
            error.statusCode = 400;
            throw error;
          }
          const { ref, selector } = params;
          if (!ref && !selector) {
            throw new Error('ref or selector required');
          }
          let holdTarget;
          if (ref) {
            let locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              log('info', 'auto-refreshing refs before hold (openclaw)', { ref, hadRefs: tabState.refs.size });
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) {
              const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none';
              throw new StaleRefsError(ref, maxRef, tabState.refs.size);
            }
            holdTarget = locator;
          } else {
            holdTarget = tabState.page.locator(selector);
          }
          const holdGuard = await guardDangerousAction(tabState, { kind: 'click', ref, selector, locator: holdTarget, confirm: params.confirm, userId, tabId: targetId });
          if (holdGuard.decision === 'approval_required') return { approvalRequired: holdGuard.dangerous, extra: { ref, selector } };
          await humanizedPressAndHold(tabState.page, holdTarget, tabState, {
            holdMs,
            profile: 'fast',
            record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
            dispatch: boundedDispatch,
          });
          await tabState.page.waitForTimeout(500);
          tabState.refs = await buildRefs(tabState.page);
          return { ok: true, targetId, url: tabState.page.url(), holdMs, ...(holdGuard.dangerous ? { dangerous: holdGuard.dangerous } : {}) };
        }

        case 'click': {
          const { ref, selector, doubleClick } = params;
          if (!ref && !selector) {
            throw new Error('ref or selector required');
          }
          let actTarget;
          
          const doClick = async (locatorOrSelector, isLocator) => {
            const locator = isLocator ? locatorOrSelector : tabState.page.locator(locatorOrSelector);
            const clickHoldMs = parseHoldMs(params.holdMs);
            if (clickHoldMs !== undefined) {
              await humanizedPressAndHold(tabState.page, locator, tabState, {
                holdMs: clickHoldMs,
                profile: 'fast',
                record: (type, detail) => recordBehaviorEvent(tabState.behavior, type, detail),
                dispatch: boundedDispatch,
              });
              return;
            }
            const clickOpts = { timeout: 3000 };
            if (doubleClick) clickOpts.clickCount = 2;
            
            try {
              await locator.click(clickOpts);
            } catch (err) {
              if (err.message.includes('intercepts pointer events')) {
                await locator.click({ ...clickOpts, force: true });
              } else {
                throw err;
              }
            }
          };
          
          if (ref) {
            let locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              log('info', 'auto-refreshing refs before click (openclaw)', { ref, hadRefs: tabState.refs.size });
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) { const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none'; throw new StaleRefsError(ref, maxRef, tabState.refs.size); }
            actTarget = locator;
          } else {
            actTarget = tabState.page.locator(selector);
          }
          const guard = await guardDangerousAction(tabState, { kind: 'click', ref, selector, locator: actTarget, confirm: params.confirm, userId, tabId: targetId });
          if (guard.decision === 'approval_required') return { approvalRequired: guard.dangerous, extra: { ref, selector } };
          await doClick(actTarget, true);
          
          await tabState.page.waitForTimeout(500);
          tabState.refs = await buildRefs(tabState.page);
          return { ok: true, targetId, url: tabState.page.url(), ...(guard.dangerous ? { dangerous: guard.dangerous } : {}) };
        }
        
        case 'type': {
          const { ref, selector, text, submit, mode = 'fill', delay = 30 } = params;
          if (mode === 'fill' && !ref && !selector) {
            throw new Error('ref or selector required for mode=fill');
          }
          if (typeof text !== 'string') {
            throw new Error('text is required');
          }
          if (mode !== 'fill' && mode !== 'keyboard') {
            throw new Error("mode must be 'fill' or 'keyboard'");
          }
          
          let locator = null;
          if (ref) {
            locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              log('info', 'auto-refreshing refs before type (openclaw)', { ref, hadRefs: tabState.refs.size, mode });
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) { const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none'; throw new StaleRefsError(ref, maxRef, tabState.refs.size); }
          }
          let actDangerous = null;
          if (submit) {
            const guard = await guardDangerousAction(tabState, {
              kind: 'type_submit', ref, selector, confirm: params.confirm, submitContext: true,
              locator: locator || (selector ? tabState.page.locator(selector) : null),
              userId, tabId: targetId,
            });
            if (guard.decision === 'approval_required') return { approvalRequired: guard.dangerous, extra: { ref, selector } };
            actDangerous = guard.dangerous;
          }
          
          if (mode === 'fill') {
            if (locator) {
              await locator.fill(text, { timeout: 10000 });
            } else {
              await tabState.page.fill(selector, text, { timeout: 10000 });
            }
          } else {
            if (locator) {
              await locator.focus({ timeout: 10000 });
            } else if (selector) {
              await tabState.page.focus(selector, { timeout: 10000 });
            }
            await tabState.page.keyboard.type(text, { delay });
          }
          if (submit) await tabState.page.keyboard.press('Enter');
          return { ok: true, targetId, ...(actDangerous ? { dangerous: actDangerous } : {}) };
        }
        
        case 'press': {
          const { key } = params;
          if (!key) throw new Error('key is required');
          let pressDangerous = null;
          if (isEnterKey(key)) {
            const guard = await guardDangerousAction(tabState, { kind: 'submit', confirm: params.confirm, submitContext: true, userId, tabId: targetId });
            if (guard.decision === 'approval_required') return { approvalRequired: guard.dangerous, extra: { key } };
            pressDangerous = guard.dangerous;
          }
          await tabState.page.keyboard.press(key);
          return { ok: true, targetId, ...(pressDangerous ? { dangerous: pressDangerous } : {}) };
        }
        
        case 'scroll':
        case 'scrollIntoView': {
          const { ref, direction = 'down', amount = 500 } = params;
          if (ref) {
            let locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) { const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none'; throw new StaleRefsError(ref, maxRef, tabState.refs.size); }
            await locator.scrollIntoViewIfNeeded({ timeout: 5000 });
          } else {
            const isVertical = direction === 'up' || direction === 'down';
            const delta = (direction === 'up' || direction === 'left') ? -amount : amount;
            await tabState.page.mouse.wheel(isVertical ? 0 : delta, isVertical ? delta : 0);
          }
          await tabState.page.waitForTimeout(300);
          return { ok: true, targetId };
        }
        
        case 'hover': {
          const { ref, selector } = params;
          if (!ref && !selector) throw new Error('ref or selector required');
          
          if (ref) {
            let locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) { const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none'; throw new StaleRefsError(ref, maxRef, tabState.refs.size); }
            await locator.hover({ timeout: 5000 });
          } else {
            await tabState.page.locator(selector).hover({ timeout: 5000 });
          }
          return { ok: true, targetId };
        }

        case 'select_option': {
          const { ref, selector, value, values } = params;
          const requestedValues = values ?? value;
          if (!ref && !selector) throw Object.assign(new Error('ref or selector required'), { statusCode: 400 });
          if (requestedValues === undefined || requestedValues === null) {
            throw Object.assign(new Error('value or values required'), { statusCode: 400 });
          }

          let locator;
          if (ref) {
            locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) {
              const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none';
              throw new StaleRefsError(ref, maxRef, tabState.refs.size);
            }
          } else {
            locator = tabState.page.locator(selector);
          }

          const selected = await locator.selectOption(requestedValues, { timeout: 10000 });
          tabState.lastSnapshot = null;
          return { ok: true, targetId, selected };
        }

        case 'drag': {
          const { sourceRef, sourceSelector, targetRef, targetSelector } = params;
          if ((!sourceRef && !sourceSelector) || (!targetRef && !targetSelector)) {
            throw Object.assign(
              new Error('sourceRef/sourceSelector and targetRef/targetSelector are required'),
              { statusCode: 400 },
            );
          }

          const resolveLocator = async (ref, selector) => {
            if (selector) return tabState.page.locator(selector);
            let locator = refToLocator(tabState.page, ref, tabState.refs);
            if (!locator) {
              tabState.refs = await buildRefs(tabState.page);
              locator = refToLocator(tabState.page, ref, tabState.refs);
            }
            if (!locator) {
              const maxRef = tabState.refs.size > 0 ? `e${tabState.refs.size}` : 'none';
              throw new StaleRefsError(ref, maxRef, tabState.refs.size);
            }
            return locator;
          };

          const source = await resolveLocator(sourceRef, sourceSelector);
          const target = await resolveLocator(targetRef, targetSelector);
          await source.dragTo(target, { timeout: 10000 });
          await tabState.page.waitForTimeout(300);
          tabState.lastSnapshot = null;
          tabState.refs = await buildRefs(tabState.page);
          return { ok: true, targetId, refsAvailable: tabState.refs.size > 0 };
        }
        
        case 'wait': {
          const { timeMs, text, loadState } = params;
          if (timeMs) {
            await tabState.page.waitForTimeout(timeMs);
          } else if (text) {
            await tabState.page.waitForSelector(`text=${text}`, { timeout: 30000 });
          } else if (loadState) {
            await tabState.page.waitForLoadState(loadState, { timeout: 30000 });
          }
          return { ok: true, targetId, url: tabState.page.url() };
        }
        
        case 'close': {
          disposeTabState(tabState, 'legacy_close');
          await safePageClose(tabState.page);
          found.group.delete(targetId);
          { const _l = tabLocks.get(targetId); if (_l) _l.drain(); tabLocks.delete(targetId); }
          return { ok: true, targetId };
        }
        
        default:
          throw new Error(`Unsupported action kind: ${kind}`);
      }
    });
    
    if (kind !== 'wait') {
      tabState.lastSemanticSnapshot = null;
      tabState.actionContracts.clear();
    }
    if (result?.approvalRequired) return refuseDangerous(req, res, { userId, tabId: targetId, dangerous: result.approvalRequired, route: 'act', extra: result.extra });
    res.json(result);
  } catch (err) {
    log('error', 'act failed', { reqId: req.reqId, kind: req.body?.kind, error: err.message });
    handleRouteError(err, req, res);
  }
});

// Periodic stats beacon (every 5 min)
runtimeInterval(() => {
  const mem = process.memoryUsage();
  let totalTabs = 0;
  for (const [, session] of sessions) {
    for (const [, group] of session.tabGroups) {
      totalTabs += group.size;
    }
  }
  log('info', 'stats', {
    sessions: sessions.size,
    tabs: totalTabs,
    rssBytes: mem.rss,
    heapUsedBytes: mem.heapUsed,
    uptimeSeconds: Math.floor(process.uptime()),
    browserConnected: browser?.isConnected() ?? false,
  });
}, 5 * 60_000);

// Active health probe -- detect hung browser even when isConnected() lies
runtimeInterval(async () => {
  if (!browser || healthState.isRecovering) return;
  const timeSinceSuccess = Date.now() - healthState.lastSuccessfulNav;
  // Skip probe if operations are in flight AND last success was recent.
  // If it's been >120s since any successful operation, probe anyway --
  // active ops are likely stuck on a frozen browser and will time out eventually.
  if (healthState.activeOps > 0 && timeSinceSuccess < 120000) {
    log('info', 'health probe skipped, operations active', { activeOps: healthState.activeOps });
    return;
  }
  if (timeSinceSuccess < 120000) return;
  
  if (healthState.activeOps > 0) {
    log('warn', 'health probe forced despite active ops', { activeOps: healthState.activeOps, timeSinceSuccessMs: timeSinceSuccess });
  }
  
  let testContext;
  try {
    testContext = await browser.newContext();
    const page = await testContext.newPage();
    await page.goto('about:blank', { timeout: 5000 });
    await page.close();
    await testContext.close();
    healthState.lastSuccessfulNav = Date.now();
  } catch (err) {
    failuresTotal.labels('health_probe', 'internal').inc();
    log('warn', 'health probe failed', { error: err.message, timeSinceSuccessMs: timeSinceSuccess });
    if (testContext) await testContext.close().catch(() => {});
    restartBrowser('health probe failed').catch(() => {});
  }
}, 60_000);

// Crash logging
process.on('uncaughtException', (err) => {
  pluginEvents.emit('browser:error', { error: err });
  log('error', 'uncaughtException', { error: err.message, stack: err.stack });
  reporter.reportCrash(err, { resourceOpts: _resourceOpts() });
  sentryCaptureException(err, { type: 'uncaughtException' });
  sentryFlush(2000).finally(() => process.exit(1));
});
process.on('unhandledRejection', (reason) => {
  log('error', 'unhandledRejection', { reason: String(reason) });
  if (reason instanceof Error) {
    sentryCaptureException(reason, { type: 'unhandledRejection' });
  }
});

// Graceful shutdown
let shuttingDown = false;

async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('info', 'shutting down', { signal });
  await pluginEvents.emitAsync('server:shutdown', { signal });

  const forceTimeout = setTimeout(() => {
    log('error', 'shutdown timed out, forcing exit');
    process.exit(1);
  }, 10000);
  forceTimeout.unref();

  server.close();
  stopMemoryReporter();

  await closeAllSessions(`shutdown:${signal}`, {
    clearDownloads: false,
    clearLocks: false,
  });

  await closeBrowserFully(`shutdown:${signal}`);
  await reporter.stop();
  await sentryFlush(2000);
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Idle self-shutdown REMOVED -- it was racing with min_machines_running=2
// and stopping machines that Fly couldn't auto-restart fast enough, leaving
// only 1 machine to handle all browser traffic (causing timeouts for users).
// Fly's auto_stop_machines=false + min_machines_running=2 handles scaling.

const PORT = CONFIG.port;
pluginEvents.emit('server:starting', { port: PORT });

// Load plugins before starting the server
const pluginCtx = {
  sessions,
  config: CONFIG,
  log,
  events: pluginEvents,
  auth: authMiddleware,
  ensureBrowser,
  getSession,
  destroySession,
  closeSession,
  withUserLimit,
  safePageClose,
  normalizeUserId,
  validateUrl,
  safeError,
  buildProxyUrl,
  proxyPool,
  failuresTotal,
  metricsRegistry: getRegister,
  createMetric,
  /** Factory for Xvfb virtual display. Plugins can replace this to customise resolution/args. */
  createVirtualDisplay: () => new VirtualDisplay(),
  /** The upstream VirtualDisplay class -- plugins can subclass it. */
  VirtualDisplay,
};
const loadedPlugins = await loadPlugins(app, pluginCtx);

// --- OpenAPI docs (after all routes are registered) ---
mountDocs(app);

// --- Sentry Express error handler (after all routes, before app.listen) ---
setupSentryErrorHandler(app);

/** Render a human-facing summary only when stdout is an interactive terminal. */
function printStartupBanner() {
  if (!process.stdout.isTTY) return;

  const guarded = Boolean(CONFIG.accessKey);
  tui.banner(`v${_pkgVersion}`);
  tui.kv([
    ['Server', `http://localhost:${PORT}`],
    ['Docs', `http://localhost:${PORT}/docs`],
    ['Plugins', loadedPlugins.length ? loadedPlugins.join(', ') : 'none'],
    ['Access key', guarded ? tui.style.green('set') : tui.style.yellow('not set')],
  ]);
  tui.line();
  if (!guarded) {
    tui.warn('GOLIATH_ACCESS_KEY is not set — do not expose this port beyond localhost.');
    tui.line();
  }
}

let server = null;
if (CONFIG.nodeEnv !== 'test') {
server = app.listen(PORT, CONFIG.bindHost, async () => {
  printStartupBanner();
  startMemoryReporter();
  refreshActiveTabsGauge();
  refreshTabLockQueueDepth();
  pluginEvents.emit('server:started', { port: PORT, host: CONFIG.bindHost, pid: process.pid, plugins: loadedPlugins });
  if (FLY_MACHINE_ID) {
    log('info', 'server started (fly)', { host: CONFIG.bindHost, port: PORT, pid: process.pid, machineId: FLY_MACHINE_ID, nodeVersion: process.version });
  } else {
    log('info', 'server started', { host: CONFIG.bindHost, port: PORT, pid: process.pid, nodeVersion: process.version });
  }
  const tmpCleanup = cleanupOrphanedTempFiles({ tmpDir: os.tmpdir() });
  if (tmpCleanup.removed > 0) {
    log('info', 'cleaned up orphaned goliath temp files', tmpCleanup);
  }
  const profileCleanup = cleanupStaleFirefoxProfiles();
  if (profileCleanup.removed > 0) {
    log('info', 'cleaned up stale firefox profiles on startup', profileCleanup);
  }

  // Periodic temp profile cleanup every 10 minutes
  setInterval(() => {
    try {
      const cleaned = cleanupStaleFirefoxProfiles();
      if (cleaned.removed > 0) {
        log('info', 'periodic firefox profile cleanup', cleaned);
      }
    } catch { /* best effort */ }
  }, 10 * 60 * 1000).unref();
  const traceSweep = sweepOldTraces({
    baseDir: CONFIG.tracesDir,
    ttlMs: CONFIG.tracesTtlHours * 3600 * 1000,
    maxBytesPerFile: CONFIG.tracesMaxBytes,
  });
  if (traceSweep.removedTtl > 0 || traceSweep.removedOversized > 0) {
    log('info', 'swept old traces', traceSweep);
  }
  // Pre-warm browser so first request doesn't eat a 6-7s cold start
  try {
    const start = Date.now();
    await ensureBrowser();
    log('info', 'browser pre-warmed', { ms: Date.now() - start });
    scheduleBrowserIdleShutdown();
  } catch (err) {
    if (isFatalInstallError(err)) {
      log('error', 'browser pre-warm aborted: Goliath binaries are not installed', {
        error: err.message,
        remediation: goliathInstallRemediation(),
      });
    } else {
      log('error', 'browser pre-warm failed (will retry in background)', { error: err.message });
      scheduleBrowserWarmRetry();
    }
  }
  // Idle self-shutdown removed -- Fly manages machine lifecycle via fly.toml.
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    log('error', 'port in use', { port: PORT });
    process.exit(1);
  }
  log('error', 'server error', { error: err.message });
  process.exit(1);
});
}

const __testing = CONFIG.nodeEnv === 'test' ? {
  config: CONFIG,
  sessions,
  sessionReservations,
  tabLocks,
  closeReapableSession,
  withTabLock,
  withTabMutationLock,
  installSessionPolicyNavigationGuard,
  pluginEvents,
  setBrowser(value) { browser = value; },
} : null;

export { app, server, __testing };
