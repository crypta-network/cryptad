# AppHost runtime hardening

This document describes the current AppHost runtime boundary for local out-of-process apps.

## Scope

AppHost runs installed apps as local child processes. The current hardening layer makes launch
behavior explicit and adds operator visibility, but it does not add an operating-system sandbox.

The current boundary provides:

- signed bundle and catalog verification before install and update;
- per-app install, data, cache, and run directories;
- a minimal launch environment with AppHost variables only;
- combined stdout/stderr capture in an app-owned `process.log`;
- token-redacted runtime status and bounded process-log tail APIs;
- best-effort owner-only permissions on POSIX app data, cache, run, and process-log files;
- bounded in-session restart attempts when a manifest opts in to `on-failure`.

The current boundary does not provide containers, WASM isolation, seccomp, chroot, jails, Windows
Job Object restrictions, per-app browser sessions, or network isolation. A third-party app still
runs as a local process under the same operating-system user as the daemon.

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

`CRYPTAD_APP_TOKEN` is for app-originated Platform API authentication. It is injected only into the
child process environment. It is not exposed to static browser UI, Web Shell bootstrap JSON, app
API summaries, runtime status JSON, or process-log tail responses.

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

## Runtime status and logs

The Platform API exposes process-level status:

```text
GET /api/v1/apps/{appId}/runtime
GET /api/v1/apps/{appId}/logs?maxBytes=65536
```

Runtime status reports `STOPPED`, `RUNNING`, `EXITED`, `CRASHED`, or `RESTARTING`, plus process id,
start time, last exit code/time, restart attempt counters, and log availability when known.

Process-log tailing is bounded. The default is small, and AppHost clamps oversized requests to its
hard maximum. Missing logs return a stable unavailable snapshot. Log responses include text and
metadata only; they do not include the runtime log path.

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

This is minimal restart plumbing, not a persistent supervisor. AppHost does not recover restart
state across daemon restarts, does not run app-provided health checks, and does not retry forever.

## Remaining risks

Third-party apps remain trusted local code. They can consume CPU, memory, disk, and network
resources available to the daemon user unless the operating system or operator environment limits
them outside AppHost.

Future sandbox work may add stronger platform-specific controls such as process containment,
network restrictions, syscall filters, browser isolation, or capability-specific app sessions.
Those are out of scope for the current runtime hardening layer.
