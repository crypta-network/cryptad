# App secret and identity vault

This document describes the app-facing secret and identity vault model for local Cryptad apps.

## Scope

The app vault is a local Platform API capability boundary for app secrets and app identities. It is
not a remote key-management service, a hardware-backed secure enclave, a browser credential store,
or an OS process sandbox. AppHost sandboxing, app-owned browser origins, and app-token
authorization still apply as separate controls.

The vault capability names are:

| Capability | Purpose |
| --- | --- |
| `vault.secrets.read` | Read app-granted secret metadata and secret values. |
| `vault.secrets.write` | Create, update, rotate, or delete app-owned secret values. |
| `vault.identities.read` | Read app-granted identity metadata and public identity material. |
| `vault.identities.create` | Create app-owned identities. |
| `vault.identities.use` | Use an app-granted identity for signing or identity-scoped work without exporting private material. |
| `vault.identities.manage` | Rename, rotate, disable, delete, or change grants for identities within the app's allowed scope. |

`app.permissions` remains the app's grant request. The Platform API authorization path remains
server-side and default-deny: a valid process token or browser session is not enough unless the
installed app's manifest and local grant state allow the required vault capability.

## App-owned and shared identities

An app-owned identity is created for one app. The app can use it only through the vault APIs and
only while its active grant still includes the required identity capability. App-owned identities
are the normal choice for app-local publishing profiles, signing keys, or account material that
should not be shared with other apps.

A shared identity is operator-controlled identity material that more than one app may be allowed to
read or use. Shared identity access requires an explicit grant to each app. A grant to one app does
not imply access by another app, even when both apps are signed by the same publisher or installed
from the same catalog.

Apps should treat identity private material as non-exportable. `vault.identities.use` is the
preferred shape for signing or identity-bound operations because the app asks Cryptad to perform
the operation and does not receive the private key bytes.

## Process and browser restrictions

App process calls authenticate with the current AppHost launch token in `CRYPTAD_APP_TOKEN`.
Cryptad injects that token only into the child process environment. The token is not exposed in
static UI bootstrap JSON, Web Shell bootstrap, app summaries, app audit entries, runtime status,
process-log responses, release-certification output, or diagnostics.

Static browser UI calls authenticate with the browser app session from app-owned UI bootstrap and
send it with `X-Crypta-App-Session`. Browser sessions are not process launch tokens and do not
grant host/operator authority. Browser sessions are bound to one installed static app, its current
manifest permissions, and the expected app UI origin.

Vault APIs must not return process launch tokens, browser session tokens, local-admin form
passwords, raw secret values in audit entries, identity private keys, seed phrases, recovery
phrases, host filesystem paths, catalog scratch paths, or signing-key material through UI
bootstrap, Web Shell summaries, logs, diagnostics, or release evidence.

Static browser UI can request vault-backed operations only through Platform API calls authorized
for that app browser principal. It cannot bypass process/browser restrictions by reading AppHost
environment variables or local vault files.

## At-rest local protection limits

Vault data is local node data at rest. Local protection depends on the host operating system, the
daemon account, filesystem permissions, backups, disk encryption, and operator handling. It does
not protect against malware running as the same OS user, a compromised daemon process, a debugger
attached to the process, a stolen unlocked account, or plaintext values that an app intentionally
copies into its own files or network requests.

Cryptad should avoid exposing vault storage paths and raw vault values through APIs and reports,
but path redaction and log redaction are not a general secret scanner. Apps remain responsible for
not printing secrets, identity seeds, recovery phrases, or private identity material to their own
logs.

## Grant lifecycle

Vault grants are evaluated against the active installed app manifest and local grant state.

During update, existing grants remain usable only for capabilities that the updated manifest still
declares. Newly added vault capabilities are permission deltas and require the same install/update
review path as other new app permissions. Removing a vault capability from the manifest makes the
corresponding grant inactive for that installed version.

Rollback restores the immutable installed bundle. It does not roll back vault records, app data,
cache, process logs, browser state, or operator grant decisions. After rollback, effective vault
access is recalculated from the rolled-back manifest and current local grant state.

Uninstall revokes active process tokens, browser sessions, and app grants, and the default v1
policy purges app-owned secret values for that app id. A later reinstall is a new grant lifecycle
event: the app must request capabilities in its manifest, and the operator or policy gate must
grant them again before vault APIs are available. Reinstall must not silently recover shared-identity
grants or app-owned secret values from a previous install.

Other app-owned vault records should either be removed during uninstall or retained only through an
explicit, operator-visible retention policy. Retained records must not become accessible to a new
install until that install receives fresh grants.

## Audit and redaction

Vault authorization decisions should be visible in the app audit model with the app id,
authentication source, route family, action, required capabilities, decision, status, and reason
code. Audit entries must not include raw secret values, identity private keys, seed phrases,
recovery phrases, request bodies, full query strings, app process tokens, browser session tokens,
form passwords, or local filesystem paths.

Release-certification and developer-tooling output may record the vault capability names and
path-free counts or booleans. It must redact secret values, private identity material, recovery
phrases, private insert URIs, command-line key material, app/session/process tokens, local vault
paths, and raw request bodies.

## Future extension point

The vault model is intentionally small enough to support future app families without exporting raw
private material. Content publishing can use identities for author signatures, social apps can use
shared identities for profiles or contact-level signing, and mail apps can use vault-managed
account identities or per-recipient secrets. New content, social, or mail routes should add their
own capability checks while keeping the same process/browser restrictions, grant lifecycle, audit,
and redaction rules.
