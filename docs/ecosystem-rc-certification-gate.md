# Ecosystem RC certification gate

This document defines the final ecosystem release-candidate certification gate used by release
managers before promoting a Cryptad release candidate.

## Gate identity

PR-258 records final ecosystem release-candidate readiness with:

| Item | Identifier | Purpose |
| --- | --- | --- |
| Ecosystem gate | `ecosystem.rc-certification` | Summarizes whether the release-candidate evidence set is complete enough to promote. |
| Matrix row | `ecosystem-rc-certification-gate` | Shows the release-manager checklist result in `ecosystem-certification-matrix.json` and `ecosystem-certification-matrix.md`. |

The gate is a summary over the existing release evidence. It does not replace the detailed matrix
rows for interop, performance, app platform, app review, public-beta hardening, network-scale soak,
multi-node beta soak, third-party developer beta, operator RC recovery, live-network beta, legacy
retirement, or redaction.

## Release-candidate requirements

A release-candidate run must produce the normal certification outputs:

```text
build/release-certification/release-certification-summary.json
build/release-certification/release-certification-report.md
build/release-certification/history-comparison.json
build/release-certification/history-comparison.md
build/release-certification/ecosystem-certification-matrix.json
build/release-certification/ecosystem-certification-matrix.md
build/release-certification/artifacts/
```

Run the wrapper in strict mode after the required source gates have produced their summaries:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --previous-summary build/release-certification-history/latest-summary.json \
  --out-dir build/release-certification
```

The `ecosystem.rc-certification` gate must treat these conditions as release-candidate blockers
unless an allowed release-manager waiver applies:

- required evidence is missing, skipped, malformed, or failing;
- required evidence regresses from a previous certified `pass` to `fail`, `missing`, or `skip`;
- an ecosystem gate reports a release-blocking failure;
- the matrix leaves required evidence, emitted ecosystem gates, first-party apps, or required docs
  unmapped;
- a non-synthetic matrix row has no existing docs path;
- the matrix, summary, report, or copied artifacts fail redaction checks;
- the network-scale RC soak summary is missing, stale, malformed, failing, or uses an unsanitized
  schema;
- required multi-node beta soak evidence is missing, stale, malformed, failing, or was generated
  from the developer-only self-test topology in a production promotion run;
- third-party developer beta evidence is missing, failing, or reports a redaction finding in the
  public developer docs, checked-in sample, review notes, or generated summary fields;
- live-network beta is marked required but any required `live-network-beta.*` evidence is missing,
  skipped, or failing.

The `ecosystem-rc-certification-gate` row should make the final release-manager action obvious:
promote, resolve blockers, attach missing evidence, or record an approved waiver for a waivable
gap. A promoted release record should preserve the sanitized summary, report, matrix, history
comparison, waiver records, and copied public artifacts.

Production beta candidates surface this gate again in
[production-beta-go-no-go-dashboard.md](production-beta-go-no-go-dashboard.md). The dashboard rolls
the ecosystem RC gate, matrix blocker count, waiver usage, redaction status, live-network evidence,
network-scale soak, and multi-node beta soak into the final `go`, `no-go`, or
`go-with-waivers` launch decision.

## Network-scale soak evidence

The release wrapper generates a fresh deterministic
`build/release-certification/network-scale-soak/summary.json` by default. That default simulated
summary is required release-candidate evidence for `network-scale.rc-soak-summary` and the
`network-scale-soak-and-subscription-budget` matrix row.

Release managers may attach an external network-scale soak summary instead:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --network-scale-soak-summary path/to/redacted-network-scale-summary.json \
  --out-dir build/release-certification
```

`CRYPTAD_CERT_NETWORK_SCALE_SOAK_SUMMARY` is the environment-variable equivalent. The attached
summary may be `simulated-rc-soak` or `live-rc-soak`, but it must use the same redacted schema as
the deterministic collector: bounded app counts, budget skips, queue-pressure skips, update
counts, Trust Graph import counts, budget enforcement booleans, and redaction booleans. It must
not include raw fetched content, request bodies, queue HTML, browser-session tokens, app process
tokens, private insert URIs, raw signatures, raw Trust Graph statement bodies, app-data values,
backup payloads, rejected source strings, or absolute local paths.

A literal 24-hour live soak is optional release-manager evidence. It is represented by the
attached redacted summary and release-log notes, not by ordinary PR, nightly, unit-test, or
Python-only self-test runs.

## Multi-node beta soak evidence

The release wrapper generates a fresh deterministic
`build/release-certification/multi-node-beta-soak/summary.json` by default. A release manager may
select the simulated, hybrid, or live mode for generated evidence:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --multi-node-mode simulated \
  --out-dir build/release-certification
```

Attach an external summary only when the release record already has redacted evidence:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --multi-node-soak-summary path/to/redacted-multi-node-summary.json \
  --out-dir build/release-certification
```

`CRYPTAD_CERT_MULTI_NODE_SOAK_SUMMARY` is the environment-variable equivalent. The attached summary
must use `kind=cryptad-multi-node-beta-soak-summary`, identify `simulated`, `hybrid`, or `live`
mode, and keep scenario evidence metadata-only. Production beta promotion requires passing
`multi-node-beta.*` evidence unless the release manager records an explicit non-promotable
emergency/test run. The row `multi-node-beta-soak-and-upgrade-drill` covers:

```text
multi-node-beta.soak
multi-node-beta.upgrade-drill
multi-node-beta.catalog-channel-update
multi-node-beta.app-install-update-rollback
multi-node-beta.app-data-migration
multi-node-beta.backup-restore
multi-node-beta.subscription-pressure
multi-node-beta.trust-graph-import
multi-node-beta.social-inbox-multi-source
multi-node-beta.support-bundle-drill
multi-node-beta.redaction
```

Multi-node evidence must not include private insert URIs, private keys, form passwords, app or
browser-session tokens, raw fetched content, raw app-data values, support bundle bodies, local
absolute paths, previous-candidate archive paths, or CI secret names/values.

## Third-party developer beta evidence

The app-platform smoke summary records `third-party-developer.*` evidence for the public external
developer workflow. Release-candidate runs require:

```text
third-party-developer.beta-program
third-party-developer.docs
third-party-developer.template
third-party-developer.sample-app-flow
third-party-developer.submission-checklist
third-party-developer.compatibility-window
third-party-developer.feedback-workflow
third-party-developer.plugin-author-migration
third-party-developer.redaction
public-beta.support-feedback-loop
public-beta.issue-templates
public-beta.known-issues-tracker
public-beta.feedback-to-backlog
public-beta.release-notes-template
public-beta.redaction-fixtures
```

These items prove the public docs, `hello-stable` template, checked-in sample app, local
lint/compat/submission/pre-review/review/catalog-candidate flow, operator-only rejection path,
feedback issue templates, plugin-author migration notes, and redaction checks are present. They do
not approve arbitrary third-party apps or bypass signed bundle, catalog, review, sandbox,
permission, and consent gates. Redaction findings in the sample app or its `review/*.md` files are
release blockers.

The `public-beta.*` support-feedback-loop rows prove redaction-safe intake docs, issue templates,
known issues, backlog routing, release notes, security handoff, and fixtures. They do not collect
telemetry or raw support bundles.

## Live-network beta optional versus required

Live-network beta certification remains explicit release-manager evidence. The final ecosystem RC
gate treats it as optional when neither `--require-live-network-beta` nor
`CRYPTAD_CERT_REQUIRE_LIVE_NETWORK_BETA=1` is set. In that disabled or optional state, stale live
summaries must not be copied into the release record, and failing optional live evidence is a
warning unless the release plan made live-network beta release-blocking.

When live-network beta is required, the `ecosystem.live-network-beta` gate and
`live-network-beta-certification` matrix row must pass. Required mode expects these evidence ids to
pass:

```text
live-network-beta.preflight
live-network-beta.catalog-usk-fetch
live-network-beta.app-install-update-rollback
live-network-beta.content-fetch
live-network-beta.feed-subscription
live-network-beta.profile-publish
live-network-beta.trust-statement-publish-import
live-network-beta.interop-perf-budget
live-network-beta.redaction
```

`live-network-beta.app-service-score` is optional. It must not be reported as a pass claim when the
score invocation was not requested.

Live-network beta runs must use only a prepared localhost node and disposable fixtures. They must
not route through proxies or record credentials, query strings, fragments, private insert material,
form passwords, browser-session tokens, raw response bodies, or non-localhost endpoint metadata.

## Waiver behavior

Waivers are release-manager decisions, not evidence removal. An active waiver can downgrade an
otherwise blocking evidence item, gate, row, or matrix coverage issue to `warn` when policy allows.
The summary, report, matrix, and history comparison must keep the waiver id, reason, source, and
affected row or evidence visible.

Do not use waivers for redaction findings. Raw secret, raw payload, private URI, token, credential,
or local-path findings remain release blockers even when a waiver references the evidence id, row
id, gate id, or matrix issue id. Expired, unapproved, malformed, or release-candidate-disallowed
structured waivers do not apply; malformed waiver files fail release-candidate mode.

Docs-only presence or link gaps may be waived when release policy allows, but the waiver must name
the accepted risk and expiration. Waivers for compatibility, performance, sandbox enforcement,
review trust, operator RC recovery, network-scale soak, multi-node beta soak, third-party developer
beta, or live-network beta should cite the release plan and the replacement evidence being
accepted.

## Redaction sensitivity

Final ecosystem RC certification artifacts are intended for release records and CI uploads. Feedback
loop artifacts, release notes examples, known issue entries, support-bundle summaries, and issue
template fixtures follow the same rule. Do not publish:

- private signing keys or reviewer keys;
- raw trusted reviewer public key bytes;
- form passwords, app process tokens, or browser-session tokens;
- raw request bodies, feed bodies, social message bodies, trust documents, profile documents, or
  fetched content;
- raw signatures, raw app-service request bodies, raw subject URIs, provider app data, raw app
  data, or backup payload values;
- private insert URIs, private identity material, seed phrases, recovery phrases, catalog scratch
  paths, staged bundle paths, rollback backup paths, store roots, queue HTML, or absolute local
  filesystem paths;
- non-localhost endpoint metadata from live-network beta fixtures.

Use route names, evidence ids, capability labels, fixture presence booleans, counts, hashes,
status labels, reason codes, and sanitized placeholders such as `<repo>`, `<workdir>`, `<home>`,
and `<path>`.

## Out-of-scope claims

Passing `ecosystem.rc-certification` does not claim:

- global network propagation, user adoption, or public availability of every fixture;
- deletion or revocation of already published network bytes;
- global moderation, blocking, routing policy, node-to-node trust propagation, or complete Web of
  Trust behavior;
- legacy WebOfTrust, Freetalk, Sone, Freemail, old plugin ABI, or `FCPPluginMessage`
  compatibility;
- safety of third-party apps beyond the signed catalog, signed bundle, app-review, sandbox,
  permission, consent, and redaction gates actually present in the release evidence;
- production-key handling, real-user content handling, or non-localhost live-node operation;
- performance guarantees beyond the recorded performance smoke, network-scale soak, and multi-node
  beta soak summaries.
