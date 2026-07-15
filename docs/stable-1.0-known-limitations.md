# Stable 1.0 known limitations

This page is the human-readable companion to
`tools/release-certification/stable-1.0-known-limitations.json`. The JSON file is the
machine-readable input used by the unified `certify.py stable-readiness` component; this page
explains how release managers should interpret each classification.

Stable 1.0 known limitations are not a place to hide blockers. Every open limitation must be one
of these classifications:

| Classification | Meaning |
| --- | --- |
| `allowed-for-stable-1.0` | Explicitly bounded limitation that may ship in Stable 1.0 if the readiness domains pass. |
| `requires-waiver-before-stable` | Limitation that is not currently allowed and needs a valid release-manager waiver before Stable promotion. |
| `blocks-stable-1.0` | Limitation that blocks Stable 1.0 while open. |
| `beta-only` | Limitation acceptable only during beta. It blocks Stable 1.0 while open. |
| `resolved` | Historical limitation retained for auditability. It does not affect readiness. |

## Allowed for Stable 1.0

These limitations are allowed only because they are narrow, documented, and do not remove a
security, privacy, recovery, support, app-data, or compatibility guarantee.

| Limitation | Boundary |
| --- | --- |
| Trust Graph Local RC remains local-scope. | It is local advisory trust, not global WebOfTrust, routing policy, global moderation, crawling, or legacy WoT compatibility. |
| Social Inbox is not legacy-protocol compatible. | It is a local threaded social/message reference app, not Freetalk/Sone compatibility, encrypted mail transport, global moderation, or daemon-core social storage. |
| Freemail-like migration is future app/service work. | Stable 1.0 can document mail-like migration as a future app or service path, but must not claim Freemail compatibility. |
| Third-party intake remains beta-limited. | At least one sample third-party app must pass the full intake flow from submission through beta catalog install smoke. |

## Warning-only examples

Some UI polish or accessibility findings can remain warnings when they are deterministic, tracked,
and not connected to security, privacy, recovery, support-bundle redaction, app-data loss,
catalog recovery, Platform API compatibility, or first-party app install/update/rollback.

Warnings should name an owner and follow-up, but they must not downgrade a blocker.

## Stable blockers

The following limitation classes block Stable 1.0 while open:

- no rollback path;
- no app-data backup/export for stable first-party apps;
- no security advisory or denylist response;
- no Platform API stable compatibility window;
- no support bundle redaction;
- no known issues tracker;
- no catalog rollback, mirror, or recovery path;
- no live or multi-node evidence;
- no third-party submission path at all;
- any redaction failure.

## Beta-only limitations

`beta-only` means the limitation is acceptable only before Stable 1.0. Open beta-only limitations
always make the Stable readiness decision `not-ready`.

Examples include relying on fixture-only evidence, using test signing as promotion evidence,
shipping without live/multi-node proof, or leaving a beta-only app-data/export gap in a
stable-channel first-party app.

## Waivers

Stable waivers are intentionally narrow. A waiver must have an id, evidence id, scope
`stable-1.0`, rationale, approver, owner, expiry, and references. It must not target a
non-waivable blocker.

Redaction findings, critical security failures, missing Platform API stable baseline, stable API
breaking changes without deprecation/migration, missing previous-candidate upgrade evidence, and
unresolved critical known issues are non-waivable.

## Stable RC copy-through

The [Stable 1.0 RC release-freeze workflow](stable-1.0-rc-execution-and-release-freeze.md) freezes
the exact policy-recognized allowed-limitation records produced by Stable readiness. Each record
must also appear in `stable-1.0-rc-known-limitations.json` and prominently in the generated RC
release-note draft with its boundary, owner, and review or exit condition intact. A missing or
changed copy is freeze drift and makes the RC `no-go`.

Allowed limitations remain separate from `go-with-waivers`. A beta-only or disallowed limitation
cannot be copied into the RC as an allowed limitation, and a freeze exception cannot reclassify or
waive it.

## Redaction

Known limitations and release notes must never include private insert URIs, private keys, app
tokens, browser session tokens, authorization headers, cookies, raw fetched content, raw app-data,
raw social messages, raw profile documents, raw trust statements, identity material, absolute local
paths, `.DS_Store`, `._*`, or `__MACOSX/` entries.

If a limitation needs to refer to private material, use a redacted class name, digest, count,
status, or relative artifact label instead.
