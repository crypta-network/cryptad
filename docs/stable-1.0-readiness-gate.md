# Stable 1.0 readiness gate

Stable 1.0 readiness is the release-manager gate that answers whether a production beta candidate
can move toward Stable 1.0. It does not replace production beta certification. It consumes the
redacted outputs already produced by the production beta pipeline, release certification,
multi-node soak, network-scale soak, security drills, public beta support loop, and app-platform
checks, then writes a deterministic Stable readiness report.

The gate moves the release question from:

```text
production beta can be operated and supported
```

to:

```text
Stable 1.0 readiness can be measured, reported, and enforced by release tooling
```

## Outputs

The Stable readiness tool writes:

```text
stable-1.0-readiness-summary.json
stable-1.0-readiness-report.md
stable-1.0-known-limitations.json
stable-1.0-blockers.json
```

The JSON summary has `kind=stable-1.0-readiness`, a deterministic decision, Stable domain rows,
blockers, warnings, allowed limitations, disallowed limitations, redaction status, and redacted
input references. It does not include absolute local paths, private insert URIs, private keys,
tokens, cookies, authorization headers, raw content, raw app data, browser sessions, identity
material, or raw Trust Graph/Social/Profile/Feed documents.

## Run the gate

Run the self-test first:

```bash
python3 tools/release-certification/stable_1_0_readiness.py --self-test
```

Run the gate from an existing production beta evidence bundle:

```bash
python3 tools/release-certification/stable_1_0_readiness.py \
  --workspace-root . \
  --out-dir build/stable-1.0-readiness \
  --production-beta-summary build/production-beta-release/reports/production-beta-summary.json \
  --go-no-go-summary build/production-beta-release/reports/go-no-go-dashboard.json \
  --release-certification-summary build/production-beta-release/evidence/ecosystem-rc-certification.json \
  --ecosystem-matrix build/production-beta-release/evidence/ecosystem-certification-matrix.json \
  --app-platform-summary build/production-beta-release/evidence/app-platform-smoke.json \
  --multi-node-beta-soak-summary build/production-beta-release/evidence/multi-node-beta-soak.json \
  --network-scale-soak-summary build/production-beta-release/evidence/network-scale-soak.json \
  --security-drills-summary build/production-beta-release/security-drills/security-drills-summary.json \
  --public-beta-known-issues tools/release-certification/public-beta-known-issues.json \
  --policy tools/release-certification/stable-1.0-readiness-policy.json \
  --stable-known-limitations tools/release-certification/stable-1.0-known-limitations.json
```

The production beta release wrapper can generate the same artifacts under
`reports/stable-1.0-readiness/`:

```bash
tools/release-certification/run-production-beta-release.sh \
  --workspace-root . \
  --out-dir build/production-beta-release \
  --mode production-beta \
  --artifact-base-uri "$CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI" \
  --previous-summary "$PREVIOUS_BETA_CANDIDATE_SUMMARY" \
  --previous-release-certification-summary "$PREVIOUS_RELEASE_CERTIFICATION_SUMMARY" \
  --multi-node-soak-summary "$MULTI_NODE_BETA_SOAK_SUMMARY" \
  --generate-stable-readiness
```

Use `--require-stable-readiness` only for a Stable promotion review. Production beta remains
backward-compatible: Stable readiness is not required by default.

## Decisions

`ready` means the required Stable domains pass, no Stable blocker is open, redaction passed, and
there are no open allowed limitations. Warnings may still be present, but they are not blockers.

`ready-with-allowed-limitations` means the candidate has no Stable blocker and no disallowed
limitation, but the policy explicitly permits one or more bounded limitations to remain visible in
the release record.

`not-ready` means at least one Stable blocker, disallowed limitation, beta-only limitation,
redaction failure, or non-waivable evidence failure remains open.

## Domains

The readiness report covers these domains and evidence ids:

| Domain | Evidence id |
| --- | --- |
| Production beta release state | `stable-1.0.production-beta-state` |
| Platform API 1.0 compatibility | `stable-1.0.platform-api-compatibility` |
| App ecosystem maturity | `stable-1.0.app-ecosystem-maturity` |
| Third-party app intake | `stable-1.0.third-party-intake` |
| Security drills | `stable-1.0.security-drills` |
| Live, multi-node, and network-scale soak | `stable-1.0.live-multi-node-soak` |
| Legacy admin and plugin migration | `stable-1.0.legacy-plugin-migration` |
| Public beta support and feedback | `stable-1.0.support-feedback-readiness` |
| Known limitations | `stable-1.0.known-limitations` |
| Redaction and artifact hygiene | `stable-1.0.redaction` |

The aggregate gate id is `stable-1.0.readiness-gate`.

## Stable requirements

Stable 1.0 requires production beta evidence that is release-capable. A developer dry-run,
fixture-only evidence, non-release summary, test signing, skipped Gradle build, skipped sandbox
tests, skipped live evidence, or skipped previous-candidate upgrade evidence cannot satisfy Stable
promotion.

Platform API 1.0 readiness requires a stable baseline, previous contract snapshot, passing stable
breaking-change check, enforced deprecation/removal windows, explicit experimental/stable
boundaries, and no critical stable-removal waiver.

First-party app readiness covers Queue Manager, Publisher, Site Publisher, Feed Reader, Profile
Publisher, Trust Graph, and Social Inbox. Stable-channel first-party apps must have signed bundles,
trusted review receipts, maintenance metadata, beta quality pass, app-data migration readiness,
backup/restore support, support metadata, and no critical privacy/security diagnostics failures.

Third-party readiness requires at least one sample app to complete submission, pre-review, review
decision, catalog-candidate staging, install-from-beta-catalog smoke, rejection/caution/resubmission
flow, Platform API compatibility validation, and onboarding docs. No third-party app may be
promoted to stable without review receipt and compatibility evidence.

Security readiness requires current passing drill evidence for reviewer key compromise, catalog
signing key rotation, app signing key compromise, malicious catalog entry, vulnerable app version,
emergency replacement app, and support-bundle intake redaction. Advisory, denylist, update
scheduler, catalog, reviewer, and app compromise paths must fail closed.

Live and soak readiness requires live-network smoke, previous-candidate multi-node upgrade drill,
network-scale operation coverage, app install/update/rollback, app-data migration, backup/restore,
content subscription pressure, queue backoff, Trust Graph migration, Social Inbox migration, and
redaction-safe soak artifacts.

Legacy migration readiness requires legacy admin to be maintenance-only, retained FProxy browse
boundaries to be explicit, the old plugin surface to remain frozen, migration cookbook and matrix
coverage, Trust Graph Local RC and Social Inbox RC migration paths, Freemail-like future app/service
wording, and no new in-core plugin API expansion.

Support readiness requires the public beta landing page, support/feedback docs, structured issue
templates, known issue tracker, feedback-to-backlog workflow, beta release notes template,
privacy-preserving support bundle guidance, security reporting handoff, and redaction fixtures.

## Non-waivable blockers

These classes always block Stable 1.0:

- redaction findings involving secrets, private insert URIs, private keys, signing material,
  tokens, cookies, authorization headers, raw content, raw app data, raw Trust/Social/Profile/Feed
  documents, identity material, browser sessions, or absolute local paths;
- production beta summary not promotion-ready or marked non-release;
- production beta go/no-go decision of `no-go`;
- missing or failing release-certification summary;
- missing or failing Platform API 1.0 stable baseline evidence;
- stable API breaking change without a policy-compliant deprecation or migration path;
- stale, missing, fixture-only, non-release, failed, or redaction-unsafe security drill evidence;
- missing previous-candidate upgrade evidence;
- insufficient live, multi-node, or network-scale evidence;
- first-party stable-channel app without signed bundle, trusted review receipt, backup/restore,
  migration readiness, beta-readiness evidence, or support metadata;
- unresolved critical known issue;
- legacy admin mutating path without Web Shell/app replacement or emergency-only classification;
- missing support-bundle redaction guidance;
- missing Stable 1.0 release notes or known limitations list.

Waivers cannot hide redaction findings or any policy-listed non-waivable blocker. Invalid waiver
attempts are reported as Stable blockers.

## Allowed limitations

Allowed limitations are explicit, bounded, and visible in
[stable-1.0-known-limitations.md](stable-1.0-known-limitations.md):

- Trust Graph remains local-scope and is not global WebOfTrust;
- Social Inbox is not legacy Freetalk/Sone protocol compatible;
- Freemail-like migration remains future app/service work;
- third-party app intake can remain beta-limited when at least one sample app passed the full
  intake flow;
- limited UI polish or accessibility warnings may remain when they are not security, privacy,
  recovery, app-data, or support blockers.

## Disallowed limitations

The Stable gate fails on any unresolved limitation in these classes:

- no rollback path;
- no app-data backup/export for stable first-party apps;
- no security advisory, denylist, or response path;
- no Platform API stable compatibility window;
- no support bundle redaction;
- no known issues tracker;
- no catalog rollback, mirror, or recovery path;
- no live or multi-node evidence;
- no third-party submission path at all;
- any redaction failure.

## Integration

Release certification accepts `--stable-readiness-summary` and displays a Stable 1.0 section. Add
`--require-stable-readiness` when certification is being used as a Stable promotion gate. Without
that flag, the Stable section is advisory.

The production beta go/no-go dashboard accepts `--stable-readiness-summary` and
`--require-stable-readiness`. Without the required flag, it displays Stable readiness without
weakening or strengthening production beta go/no-go. With the flag, missing or failing Stable
readiness becomes `no-go`; redaction findings are always non-waivable.
