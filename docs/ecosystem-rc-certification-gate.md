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
operator RC recovery, live-network beta, legacy retirement, or redaction.

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
- live-network beta is marked required but any required `live-network-beta.*` evidence is missing,
  skipped, or failing.

The `ecosystem-rc-certification-gate` row should make the final release-manager action obvious:
promote, resolve blockers, attach missing evidence, or record an approved waiver for a waivable
gap. A promoted release record should preserve the sanitized summary, report, matrix, history
comparison, waiver records, and copied public artifacts.

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
review trust, operator RC recovery, network-scale soak, or live-network beta should cite the
release plan and the replacement evidence being accepted.

## Redaction sensitivity

Final ecosystem RC certification artifacts are intended for release records and CI uploads. Do not
publish:

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
  permission, and redaction gates actually present in the release evidence;
- production-key handling, real-user content handling, or non-localhost live-node operation;
- performance guarantees beyond the recorded performance smoke and network-scale soak summaries.
