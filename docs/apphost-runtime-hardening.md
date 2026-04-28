# AppHost runtime hardening

This document describes the current AppHost runtime boundary for local out-of-process apps.

## Scope

AppHost runs installed apps as local child processes. The current hardening layer makes launch
behavior explicit and adds operator visibility. PR-206 adds a sandbox policy and reporting model,
but the default providers still do not add a hard operating-system sandbox.

The current boundary provides:

- signed bundle and catalog verification before install and update;
- per-app install, data, cache, and run directories;
- a minimal launch environment with AppHost variables only;
- combined stdout/stderr capture in an app-owned `process.log`;
- token-redacted runtime status and bounded process-log tail APIs;
- sandbox policy parsing, provider selection, and token-free sandbox status reporting;
- measured AppHost-managed data/cache usage with positive-quota enforcement at launch/restart
  boundaries;
- best-effort process-log size bounding at lifecycle and status checkpoints;
- best-effort owner-only permissions on POSIX app data, cache, run, and process-log files;
- bounded in-session restart attempts when a manifest opts in to `on-failure`.

The current boundary does not provide containers, WASM isolation, seccomp, chroot, jails, Windows
Job Object restrictions, browser origin isolation, or network isolation by default. A third-party
app still runs as a local process under the same operating-system user as the daemon unless a future
provider explicitly reports an enforced sandbox.

## Sandbox policy

App manifests may declare:

```properties
sandbox.mode=none|restricted-process|wasm-preview
sandbox.required=false
```

Missing `sandbox.mode` defaults to `none`, and missing `sandbox.required` defaults to `false`.
Unknown modes and malformed booleans fail manifest validation.

`sandbox.mode=none` is the backward-compatible launch path. The app runs as it did before PR-206,
and API/Shell surfaces report that no OS sandbox isolation is active.

`sandbox.mode=restricted-process` requests the v1 restricted-process provider. The default provider
is intentionally best-effort: it verifies AppHost's sanitized environment, explicit installed-bundle
working directory, and app-scoped data/cache/run directories. It does not create a container,
seccomp profile, chroot, jail, Windows Job Object policy, or network/filesystem mediation layer.
Runtime status therefore reports `supportLevel=best-effort`, not `enforced`.

`sandbox.mode=wasm-preview` is parsed as a reserved future mode. The default host has no WASM
provider. If `sandbox.required=true`, starting such an app fails with `unsupported_sandbox`; if it
is optional, AppHost may report the mode as unsupported instead of claiming isolation.

`sandbox.required=true` means AppHost must reject launch when no provider can support the requested
mode. It does not upgrade a best-effort provider into hard isolation. Operators should read the
reported `supportLevel`, `provider`, `active`, and warnings fields to understand what actually
happened on the current host.

## Launch environment

AppHost clears the inherited environment before launch and rebuilds a small environment. Unix
launches get a deterministic base `PATH`. Windows launches keep the system root, command
interpreter, safe base `PATH`, and temporary-directory variables needed by common tools.

Every app launch receives:

```text
CRYPTAD_APP_ID
CRYPTAD_APP_NAME
CRYPTAD_APP_VERSION
CRYPTAD_APP_DATA_DIR
CRYPTAD_APP_CACHE_DIR
CRYPTAD_APP_RUN_DIR
CRYPTAD_APP_TOKEN
CRYPTAD_APP_PERMISSIONS
CRYPTAD_APP_UI_MODE
CRYPTAD_APP_UI_ENTRY   # only when the manifest declares a UI entry
```

`CRYPTAD_APP_TOKEN` is for process-originated Platform API authentication. It is injected only into
the child process environment. App processes should present it with `X-Crypta-App-Token`; the bridge
also accepts `Authorization: Bearer` when the Bearer value matches a live app token. Unrelated
Bearer credentials stay on the host/operator path. The token is not exposed to static browser UI,
Web Shell bootstrap JSON, app API summaries, runtime status JSON, process-log tail responses, or app
audit entries.

The token authenticates only the currently running app instance. A stopped app or a previous run's
token does not authenticate. The verified app principal contains the app id and manifest
permissions, never the token itself. See [app-permissions-and-audit.md](app-permissions-and-audit.md)
for the capability matrix and audit surface.

Static browser UI uses a separate app browser session issued by the app-owned UI bootstrap route.
That session is not an AppHost launch token, is not injected into the child process environment,
and does not change process-token behavior.

AppHost does not inject daemon datastore paths, trusted-key files, catalog roots, signing material,
or the daemon's current working directory. The child process working directory is the installed app
bundle root.

## Runtime files

The layout keeps app state separated by purpose:

| Area | Purpose |
| --- | --- |
| installed bundle | Immutable copied app files verified at install/update time. |
| data directory | Persistent mutable app data. |
| cache directory | Rebuildable mutable app cache. |
| run directory | Session-scoped runtime files such as `process.log`. |

Platform APIs describe these locations conceptually only. API responses must not include absolute
installed, data, cache, or run paths.

On POSIX filesystems, AppHost applies owner-only permissions where practical:

- directories: `rwx------`;
- sensitive files such as `process.log`: `rw-------`.

On filesystems without POSIX attributes, AppHost falls back to the platform default and continues
running. That fallback is not a security boundary.

## Data, cache, and log quotas

App manifests can declare:

```properties
quota.data.bytes=0
quota.cache.bytes=0
```

Both fields are optional non-negative byte counts. AppHost enforces only positive values. A missing
field and an explicit `0` mean unlimited or no explicit app quota, so existing first-party bundles
that declare zero quotas remain installable and startable.

Quota checks apply only to AppHost-managed app data and cache directories. AppHost measures regular
files without following symlinks. It reports path-free warnings when a scan skips symlinks or cannot
inspect all entries. An app that is already over a positive data or cache quota, or whose enforced
quota area cannot be measured completely, cannot be started manually or by automatic restart until
usage falls below the limit and measurement completes.

The managed `process.log` file is bounded by host policy, not manifest metadata. AppHost applies the
limit on a best-effort basis before launch, after process exit, before automatic restart, and before
runtime status or process-log APIs return. When the file exceeds the limit, AppHost keeps the tail
plus a small redaction overlap so recent diagnostics remain available and a bounded log read can
still redact a token or known AppHost path split by the display boundary. The limit does not make app
output a trusted secret store; token and path redaction still happen before log text leaves AppHost.

Quota status is token-free and path-free. Runtime status and app summaries expose data/cache usage,
raw manifest quota values, effective positive limits, enforcement booleans, over-limit booleans,
process-log size/limit metadata, and warning strings safe for Web Shell display.

## Runtime status and logs

The Platform API exposes process-level status:

```text
GET /api/v1/apps/{appId}/runtime
GET /api/v1/apps/{appId}/logs?maxBytes=65536
```

Runtime status reports `STOPPED`, `RUNNING`, `EXITED`, `CRASHED`, or `RESTARTING`, plus process id,
start time, last exit code/time, restart attempt counters, log availability when known, quota
status, and display-safe runtime warnings.
It also reports a `sandbox` object containing the requested mode, whether the manifest requires it,
the provider name, the support level, whether sandbox isolation is active, and token-free warnings.

Process-log tailing is bounded. The default is small, and AppHost clamps oversized requests to its
hard maximum. Missing logs return a stable unavailable snapshot. Log responses include text and
metadata only; they do not include the runtime log path. The on-disk `process.log` may be slightly
larger than the display limit because AppHost retains redaction overlap before the visible tail.

App-originated Platform API decisions are recorded separately in a bounded process-local audit log.
The Apps API exposes recent entries through `GET /api/v1/apps/{appId}/audit`; those entries omit
launch tokens, browser session tokens, query strings, request bodies, form passwords, and
filesystem paths.

Before returning process-log text, AppHost redacts:

- the exact current launch token when the app is running;
- obvious `CRYPTAD_APP_TOKEN=...` or `CRYPTAD_APP_TOKEN:...` assignments printed by the app.

Apps can still write secrets to their own files or to other process output. Log redaction is a
defense-in-depth measure, not a general secret scanner.

## Restart policy

App manifests can declare:

```properties
app.restart.policy=never|on-failure
app.restart.maxAttempts=0
app.restart.backoff.ms=0
```

Defaults preserve existing behavior: `policy=never`, `maxAttempts=0`, and `backoff.ms=0`.

When `policy=on-failure`, AppHost restarts only after a non-zero process exit, only within the
current daemon session, and only up to `app.restart.maxAttempts`. Each restart gets a fresh launch
token. Explicit operator stop suppresses automatic restart.

AppHost also applies a bounded rolling restart-storm guard. The default guard suppresses automatic
restart after five restart attempts within five minutes and records a runtime warning. Manual start
is still allowed unless a positive data or cache quota is currently exceeded or cannot be measured
completely.

This is minimal restart plumbing, not a persistent supervisor. AppHost does not recover restart
state across daemon restarts, does not run app-provided health checks, and does not retry forever.

## Remaining risks

Third-party apps remain trusted local code. AppHost enforces positive data/cache quotas for its own
managed mutable directories and bounds managed process logs, but it does not provide OS-level CPU,
memory, network, or arbitrary filesystem isolation. Apps can still consume resources available to
the daemon user unless the operating system or operator environment limits them outside AppHost.

Future sandbox work may add stronger platform-specific controls such as process containment,
network restrictions, syscall filters, filesystem mediation, or real WASM execution. Those are out
of scope for the current runtime hardening layer.
