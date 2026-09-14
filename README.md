# Goliath

![Goliath social preview](assets/goliath-social-preview-1280x640.png)

**Hermes-native browser hands for AI agents.**

Goliath gives AI agents a real browser when their normal tools hit a wall. A harness keeps reasoning; Goliath supplies persistent Firefox-based browser sessions with configurable anti-detection measures and the human interactions needed to finish the job: sign documents, complete forms, upload files, work through courses, handle complex controls, and continue across authenticated sessions.

Those measures can reduce ordinary automation fingerprints, but they do not guarantee that a site, CAPTCHA, or bot-detection system will accept a session.

Goliath is built first for Hermes: it prints ready-to-paste `config.yaml`, keeps a stable browser identity for each Hermes agent, and starts and stops with the harness over stdio. It also speaks standard MCP for Claude, Codex, Cursor, and other agent harnesses, with REST/OpenAPI available when needed. “Hermes-native” means first-class configuration and lifecycle integration; Goliath remains an independent project and a portable MCP server.

## Quickstart

Requirement: Node.js 22+. The one-time setup downloads about 300 MB for the browser engine.

```bash
npx -y @mechanica-labs/goliath@0.2.2 install
npx -y @mechanica-labs/goliath@0.2.2 doctor
```

If you already have a compatible Camoufox executable, set `GOLIATH_EXECUTABLE=/absolute/path/to/camoufox` instead of running `npx camoufox-js fetch`.

`goliath install` downloads and verifies Camoufox, proves the public MCP/browser/Hands path against Example Domain, and safely configures detected Codex, Claude Code, Cursor, Hermes, and OpenClaw installations. It records the exact original and managed Goliath entries for entry-level rollback and uninstall, refuses to overwrite unmanaged entries unless a specific restorable client is named with `--replace-existing`, and can be previewed with `--dry-run`.

On Debian/Ubuntu, `goliath install` installs the GTK, X11, Mesa, font, and Xvfb packages required by the browser when it is run as root or with passwordless sudo. Without those packages, `goliath doctor` reports the missing shared libraries instead of declaring the runtime ready. In Docker or other locked-down containers, the browser may also need a compatible sandbox/security profile.

Use `goliath setup` when you only want ready-to-paste Hermes YAML plus JSON for another MCP client. The generated Hermes command is pinned and self-contained:

```yaml
mcp_servers:
  goliath:
    command: "npx"
    args: ["-y", "@mechanica-labs/goliath@0.2.2", "mcp"]
    env:
      GOLIATH_USER_ID: "personal-assistant"
```

Restart Hermes after adding the configuration. The MCP process checks for an existing local server and starts one when needed, then shuts down the server it owns when Hermes disconnects. There is no daemon to install or manage. Keep `GOLIATH_USER_ID` stable for each agent so its authenticated browser profile persists across tasks.

Managed harness pins can be refreshed with `goliath upgrade` and removed with `goliath uninstall`. Uninstall leaves browser profiles, uploads, cookies, traces, and the shared Camoufox runtime in place.

See the [Hermes-native harness setup guide](https://github.com/Mechanica-Labs/goliath/blob/main/docs/HARNESS_SETUP.md) for the full Hermes workflow, JSON-based MCP clients, remote-server configuration, uploads, and troubleshooting.

## REST quick start

For direct API use, run `npx goliath serve` after the npm Quickstart. The server listens on `http://127.0.0.1:9377` by default; API docs are at `/docs`.

```bash
curl -X POST http://127.0.0.1:9377/tabs \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent-1","sessionKey":"task-1","url":"https://example.com"}'
```

`goliath serve` installs a missing browser engine automatically; `npx camoufox-js fetch` is the explicit equivalent. Snapshot refs reset when a page navigates or materially changes, so request a fresh snapshot before retrying a stale ref.

Screenshots default to PNG bytes. Pass `path` to write a file instead and get JSON `{ path, bytes, fullPage }`. Relative paths resolve from `GOLIATH_WORKSPACE` when set, otherwise `GOLIATH_SCREENSHOTS_DIR` (`~/.goliath/screenshots`). Paths must stay inside the workspace or screenshot directory.

```bash
curl -o page.png 'http://127.0.0.1:9377/tabs/TAB_ID/screenshot?userId=agent-1'
curl 'http://127.0.0.1:9377/tabs/TAB_ID/screenshot?userId=agent-1&fullPage=true&path=shots/page.png'
```

## Server lifecycle

Goliath can run in the foreground for a harness or supervisor, or manage a background process that is health-checked before the command returns:

```bash
npx goliath serve    # foreground
npx goliath up       # background
npx goliath status
npx goliath logs     # add -f to follow
npx goliath restart
npx goliath down
```

Background state is stored in `.goliath/` beside the installed package or checkout. A failed startup is stopped automatically and reports the tail of its log.

## Agent capabilities

Snapshots support `filter=interactive` (drops non-actionable text, keeps element refs, headings, iframe boundaries, and their tree ancestors — the response reports `fullChars` so the reduction is measurable) and `maxChars` (per-request window budget, paginated with `offset`).

- Observe: accessibility snapshots, versioned semantic state, screenshots, links, images, structured extraction, downloads, and tab statistics.
- Act: click, type, press and hold, press keys, hover, scroll, wait, select options, drag and drop, navigate, resize the viewport, and attach files.
- Remember: isolate state by `userId`, group tabs by `sessionKey`, restore browser profiles, and fork explicit storage checkpoints.
- Hand off: enable the optional noVNC plugin when a human must complete MFA, OAuth consent, CAPTCHA, or another visual step.
- Integrate: use standard MCP, the REST API, or the generated OpenAPI document.

API documentation is available at `/docs`; the machine-readable contract is served at `/openapi.json` and committed as `openapi.json`.

## Secure file uploads

Agents may only attach regular files that resolve inside `GOLIATH_UPLOADS_DIR`, which defaults to `~/.goliath/uploads`. Absolute paths are required. Directory traversal and symlinks escaping the configured root are rejected.

```bash
mkdir -p ~/.goliath/uploads
cp ./invoice.pdf ~/.goliath/uploads/

curl -X POST 'http://127.0.0.1:9377/tabs/TAB_ID/upload' \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent-1","path":"/absolute/path/to/.goliath/uploads/invoice.pdf"}'
```

If the page does not already contain an `input[type=file]`, include the ref or selector of the button that opens its file chooser.

## Network security

Goliath binds to `127.0.0.1` by default. Binding beyond loopback requires `GOLIATH_ACCESS_KEY`; send it as `Authorization: Bearer <key>` on every request except `/health`. Put TLS in front of the service when traffic leaves the machine.

```bash
GOLIATH_BIND_HOST=0.0.0.0 \
GOLIATH_ACCESS_KEY='replace-with-a-long-random-secret' \
npm start
```

The Docker image binds to `0.0.0.0`, so remote API calls require a key:

```bash
docker build -t goliath .
docker run --rm -p 9377:9377 \
  -e GOLIATH_ACCESS_KEY='replace-with-a-long-random-secret' \
  goliath
```

The normal interaction loop is: create a tab, navigate, request a snapshot, act using element references such as `e1`, then request a fresh snapshot after navigation.

## Semantic state and safe actions

`POST /tabs/:tabId/observe` adds a durable, versioned layer above temporary `eN` refs. It returns best-effort semantic node IDs, changes from the prior observation, readiness confidence and reasons, affordances, provenance, capability limits, and prompt-injection signals. Refs and semantic identities retain their exact browsing-frame provenance. Observation work is bounded to 512,000 accessibility-snapshot characters and 1,000 nodes, and prior-state matching uses bounded indexes rather than an all-pairs scan. Page content is always labeled untrusted.

```bash
# Observe. Save snapshotId and the desired node ID from this response.
curl -sS -X POST http://127.0.0.1:9377/tabs/TAB_ID/observe \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","goalSelector":"main"}'

# Plan against that exact state, then execute the returned contract.
curl -sS -X POST http://127.0.0.1:9377/tabs/TAB_ID/actions/plan \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","snapshotId":"SNAPSHOT_ID","action":{"kind":"click","nodeId":"NODE_ID"},"policy":{"allowedOrigins":["https://example.com"]}}'

curl -sS -X POST http://127.0.0.1:9377/tabs/TAB_ID/actions/execute \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","contractId":"CONTRACT_ID","confirm":true,"postconditions":[{"kind":"url_matches","pattern":"/next$"}]}'
```

Successful legacy mutations invalidate outstanding semantic contracts. Execution requires 1–20 valid postconditions, verifies all of them (AND semantics), and rejects empty, malformed, or unsupported conditions. A `node_exists` condition with several selectors requires one node to satisfy every supplied selector. URL postconditions use bounded literal matching with optional leading `^` and trailing `$` anchors; arbitrary regular expressions are not evaluated. Use `GET /tabs/:tabId/events?userId=agent1` for observation events and `GET /tabs/:tabId/workflow?userId=agent1` for successful semantic steps as a replayable role/name workflow.

Semantic extraction binds JSON Schema properties to `x-node-id` values and returns per-field evidence, confidence, and unresolved fields. `deterministic_then_model` currently reports unresolved fields with `modelUsage: null`; it never silently sends page content to a model.

### Secrets, checkpoints, forks, and human handoff

Register credentials through the authenticated REST API or another trusted channel, not an agent prompt. Values are held in memory, never echoed, and `type_secret` contracts can use them only on the exact live HTTP(S) origin of the target frame. Frame navigation invalidates the contract, and opaque frame origins fail closed.

```bash
curl -sS -X POST http://127.0.0.1:9377/sessions/agent1/checkpoints \
  -H 'Content-Type: application/json' -d '{"checkpointId":"before_checkout"}'

curl -sS -X POST http://127.0.0.1:9377/sessions/agent1/forks \
  -H 'Content-Type: application/json' \
  -d '{"checkpointId":"before_checkout","newUserId":"agent1-branch","url":"https://example.com/cart"}'

curl -sS -X POST http://127.0.0.1:9377/tabs/TAB_ID/handoff \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","action":"request","reason":"complete MFA"}'
```

Checkpoints contain cookies, local storage, and IndexedDB and are stored under the application-owned `~/.goliath/checkpoints/` directory. They do not clone live DOM, the JavaScript heap, open connections, or remote server state. Malformed checkpoint files are skipped with structured warnings so one bad file cannot poison the store. Checkpoint writes use per-checkpoint filesystem locks, and forks atomically reserve `newUserId`; forks create isolated contexts from the supplied state, which takes precedence over any old persistence profile for the destination user. Human handoff serializes with mutations and pauses mutating tab routes, individual-tab and tab-group deletion, session deletion, and automatic timeout/pressure reaping until it is resumed or cancelled. Privileged whole-server shutdown remains an explicit forced-teardown boundary and emits handoff-termination events.

Semantic safety is fail-closed at the browser boundary: contracts are tied to one snapshot, domain policies run before execution, page instructions remain untrusted, and registered values are redacted from accessibility and semantic snapshots. Screenshot and arbitrary-evaluation endpoints remain privileged and can observe rendered data, so do not expose them to untrusted callers.

## Humanized input and telemetry

Click, type, and scroll requests accept `"humanized": true`. The API then uses curved pointer trajectories, bounded jitter and hesitation, variable key timing, or eased wheel pulses instead of a single instant automation event. An object form can select the `fast`, `balanced`, or `deliberate` profile. Set `"visualize": true` in that object to show a temporary pointer and click pulse in a live VNC viewer.

Click also accepts `"holdMs"` (200 to 15000) for a sustained press-and-hold. That is an interaction primitive for buttons that fill while the pointer stays down. It is not proof that a third-party challenge will accept the session.

```bash
curl -sS -X POST http://localhost:9377/tabs/TAB_ID/click \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","ref":"e1","humanized":{"profile":"balanced","visualize":true}}'

curl -sS -X POST http://localhost:9377/tabs/TAB_ID/click \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","ref":"e1","holdMs":1800,"humanized":true}'

curl -sS 'http://localhost:9377/tabs/TAB_ID/behavior?userId=agent1'
```

A humanized click does not press blind. After the pointer arrives it checks which element is under it (one corrective re-aim if the layout moved) and then confirms that a click event reached the target. The response reports both in `input.hit` and `input.delivered`. When the check fails the route answers `409` instead of `ok: true` for a click that changed nothing. `target_obscured` means nothing was pressed. `click_not_delivered` means no part of the press reached the target, and the body carries `retrySafe: true`. `click_unconfirmed` means the press reached the target but no click followed, so the page may already have acted; the body carries `retrySafe: false`, so check the page before retrying. Every humanized pointer dispatch is bounded like the direct path, so a hung pointer fails the step with `input_dispatch_timeout` and keeps the session. The page-side checks are bounded too: a page that stays busy yields `delivered: null` rather than a hang.

Behavior reports retain at most 512 in-memory events and summarize timing entropy and variance. Their `assessment` is a local diversity heuristic, not proof that a third-party CAPTCHA or bot detector will accept a session.

Sensitive cookie and trace endpoints can additionally use `GOLIATH_API_KEY`; administrative shutdown can use `GOLIATH_ADMIN_KEY`.

Crash and hang reporting is disabled by default and has no built-in destination. To opt in, set both `GOLIATH_CRASH_REPORT_ENABLED=true` and `GOLIATH_CRASH_REPORT_URL` to a trusted HTTPS relay. Goliath sends no telemetry when either setting is absent or the URL is not HTTPS.

## Browser runtime

The product and API are named Goliath; the browser runtime is provided by the public `camoufox-js` package. Goliath stages a complete download before replacing an existing runtime, so an interrupted download leaves the previous working installation intact. Run `goliath doctor` to inspect the installation, or supply an existing compatible executable with `GOLIATH_EXECUTABLE`. `CAMOUFOX_EXECUTABLE`, `CAMOUFOX_EXECUTABLE_PATH`, and `CAMOFOX_EXECUTABLE_PATH` remain compatibility aliases.

The runtime is staged to a temporary file before an existing install is replaced, so a failed or interrupted download leaves the previous working runtime in place. Run `goliath doctor` to check what is installed, verify Linux shared libraries, and confirm that the browser can launch.

Terminal output is animated and colorized when interactive, and switches to plain single-line output when piped or running in CI. Set `NO_COLOR=1` to disable color or `GOLIATH_ASCII=1` to replace box-drawing characters.

## Hands: multi-step form automation

The `POST /tabs/:tabId/hands` route runs an ordered list of UI actions—click,
type, select, check, wait, scroll, press, and submit—against one tab in a single
request. It stops at the first failing step and reports its index, so a form
that used to take six round-trips is one call:

```bash
curl -sS -X POST http://localhost:9377/tabs/TAB_ID/hands \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","steps":[{"action":"type","ref":"e1","text":"Carlos"},{"action":"click","ref":"e2"}]}'
```

MCP clients use the same capability through the `goliath_hands` tool. Full
action reference and constraints are in [AGENTS.md](AGENTS.md#hands-multi-step-workflow).

## Dangerous-action brake

Once an agent has hands, it needs brakes. The fast-path interaction routes
(`/click`, `/type` with Enter, `/press` Enter, `/hands` click/submit/type+Enter/press-Enter
steps, and `/act`; the matching `goliath_click`, `goliath_type`, `goliath_hands`,
`goliath_act` tools) refuse to act on a control whose accessible name reads
like a side effect: send, publish, post, delete, confirm, transfer, withdraw,
sign, pay, purchase, place order, change password, and close synonyms.
Instead of acting, the route returns:

```json
{
  "ok": false,
  "status": "approval_required",
  "action": "Click",
  "kind": "click",
  "category": "send",
  "risk": "external_side_effect",
  "element": "Send",
  "role": "button",
  "domain": "www.linkedin.com",
  "matched": "send",
  "source": "element",
  "hint": "This action looks like it has an external or irreversible effect. Ask the user, then retry the same request with \"confirm\": true."
}
```

The agent harness decides whether a human must approve. To proceed it repeats
the same request with `"confirm": true`. An approval is bound to what was
refused: it must follow a refusal of the same kind, category, element, and
domain on the same tab, is consumed by one use, and a pre-emptive or mismatched
`confirm` (a ref that now resolves to a different control) is refused again with
a hint saying so. The response to an approved action carries a `dangerous`
annotation so it is auditable. A hand stops before the dangerous step (earlier
steps stay applied), reports `status`, `approvalRequired.step`, and
`failedStep`, and resumes only with `confirm: true` on that step; there is no
hand-level approval.

```bash
curl -sS -X POST http://localhost:9377/tabs/TAB_ID/click \
  -H 'Content-Type: application/json' \
  -d '{"userId":"agent1","ref":"e3","confirm":true}'
```

Names are read through Playwright's accessibility layer (`ariaSnapshot`,
isolated from page scripts), never through page-world JavaScript, and labels
are normalized against zero-width characters, combining marks, and common
Cyrillic/Greek homoglyphs. Clicking into a text field is never braked (it only
focuses). An Enter submit is judged by the owning form's submit control and
its resolved `action` URL, or, for form-less chat composers, by the buttons in
the nearest container ("Write a message" + Enter is judged by the "Send" next to
it). If the target's name cannot be read at all, the brake fails closed with
`category: "unresolved_target"`.

`GOLIATH_DANGEROUS_ACTIONS` selects the mode: `confirm` (default) refuses until
confirmed, `annotate` performs the action but labels it in the response, `off`
disables classification. Every refusal emits the `tab:approval_required`
plugin event. The classifier is keyword-based, so it is a brake, not a policy
engine: it cannot see intent, and an unlabeled icon button with no accessible
name is allowed. The semantic `/actions/plan` + `/actions/execute` flow shares
the same vocabulary (its risk is never lower than the brake's) and adds origin
policies, prompt-injection signals, and postconditions.

## Session capability policies

Operators can optionally bind a browser identity to a runtime-only capability
policy. With no registered policy, Goliath behaves exactly as before. Unset
policy fields also default to allow, so operators can deny only the surfaces
that matter for a particular identity.

```bash
curl -sS -X POST http://localhost:9377/sessions/agent-business/policy \
  -H "Authorization: Bearer $GOLIATH_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "allowedOrigins":["https://github.com","https://*.github.com"],
    "deniedOrigins":["https://billing.github.com"],
    "actions":{"upload":"deny","evaluate":"deny","screenshot":"deny"},
    "dangerousActions":{"payment":"deny","transfer":"deny","change_password":"deny"}
  }'
```

Policies can be registered before the first tab is created. They remain in
memory across browser-session teardown and recreation, but they are not written
to the profile and do not survive a Goliath process restart. Use
`GET /sessions/:userId/policy` to inspect a policy and
`DELETE /sessions/:userId/policy` to restore unrestricted behavior.

When `GOLIATH_API_KEY` is configured, policy administration requires that exact
operator key. `GOLIATH_ACCESS_KEY` remains valid for ordinary agent requests but
cannot set, replace, inspect, or remove policies. Without a dedicated API key,
the existing access-key or loopback-only authentication behavior applies.

Origin rules accept exact HTTP(S) origins and scheme-pinned, subdomain-only
wildcards such as `https://*.example.com`. Wildcards do not match the apex
origin. Denied origins take precedence, and opaque or unavailable frame origins
fail closed whenever origin rules exist. Top-level and iframe navigation is also
blocked at the browser request boundary. Browser back and forward operations
are refused under an origin-scoped policy because their destination cannot be
verified before navigation. Closing tabs remains available for cleanup unless
`close_tab` is explicitly denied.

Supported action keys are `behavior`, `check`, `click`, `close_tab`,
`create_tab`, `downloads`, `evaluate`, `events`, `extract`, `handoff`, `hover`,
`images`, `links`, `list_tabs`, `navigate`, `observe`, `press`, `screenshot`,
`scroll`, `select`, `semantic`, `snapshot`, `stats`, `submit`, `type`, `upload`,
`viewport`, `wait`, and `workflow`. Supported dangerous categories are
`change_password`, `payment`, `transfer`, `sign`, `delete`, `send`, `publish`,
`confirm`, and `unresolved_target`. A dangerous-category deny is a hard deny:
`confirm: true` and `GOLIATH_DANGEROUS_ACTIONS=off` cannot override it.

Violations return HTTP 403 with `code: "policy_violation"`, increment
`goliath_policy_violations_total{action,category}`, and emit the
`session:policy:violation` plugin event.

## MCP and plugins

Bundled plugins provide YouTube transcript extraction, persistent session storage, and optional noVNC access. Enable or configure them in `goliath.config.json`. The [VNC plugin guide](plugins/vnc/README.md) includes a localhost-safe Docker command and a live humanized-input example.

```bash
npm run plugin list
npm run plugin install https://github.com/example/goliath-plugin
```

## Development

```bash
GOLIATH_SKIP_DOWNLOAD=1 npm install
npm run build
npm run generate-openapi
npm test
npm run benchmark:behavior
npm run benchmark
```

After changing a REST route, update its `@openapi` block and regenerate `openapi.json`. See [AGENTS.md](AGENTS.md) for the route and plugin contribution rules.

The behavior benchmark runs 26 local synthetic gates across semantic, spatial, timing, grid, multi-step, unfamiliar-schema, typing, and scrolling cases. It uses deterministic gate solvers to measure the interaction layer, so its pass rate does not measure autonomous reasoning or real CAPTCHA acceptance. TLS/JA3 and IP reputation also require separate external validation.

`npm run benchmark` is the complementary core execution suite: it drives a running Goliath server through its public REST API against localhost fixtures and reports correctness, end-to-end latency (p50/p95), and API-call cost per primitive (tab creation, snapshot refs, ref clicks, Hands forms, navigation, multi-tab, session-state continuity, dynamic controls). It needs a working browser runtime, so it is opt-in rather than part of `npm test`. See [benchmarks/README.md](benchmarks/README.md).

## Licensing

Goliath's original source is MIT licensed. Camoufox and `camoufox-js` are MPL-2.0 licensed; other dependencies retain their respective licenses. See [NOTICE.md](NOTICE.md).
