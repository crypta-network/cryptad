# Platform API compatibility support window

This page defines the active beta support policy for the Platform API 1.0 stable baseline. It is
the operator-facing policy behind the `compatibilityWindow` object in Platform API contract
snapshots and the `platform-api.compatibility-window` release-certification evidence row.

The policy is enforceable, not just descriptive. Production beta release certification fails closed
when the current snapshot lacks support-window metadata, when previous contract history is missing,
or when the stable baseline changes without a future baseline and release-manager evidence.

## Scope

The Platform API 1.0 stable promise covers only descriptors that are members of
`stableBaseline.name=1.0` in the Platform API contract snapshot:

- the 9 stable capabilities listed in
  [platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md);
- the 32 app-facing stable endpoint identities listed in the same reference;
- each stable endpoint's required capability set;
- each stable endpoint's audit/authorization action label;
- each stable endpoint's app-process and app-browser principal access flags;
- the stable baseline identity: name `1.0` and baseline contract version `19`.

The URL namespace remains `/api/v1`. The integer contract version may advance as metadata,
experimental APIs, or future baseline candidates are added. That does not change the Platform API
1.0 stable baseline.

Content profiles such as `crypta.profile.v1`, `crypta.feed.snapshot.v1`,
`crypta.trust.statement.v1`, `crypta.social.message.v1`, and `crypta.social.outbox.v1` are
Crypta app ecosystem document profiles, not Platform API 1.0 stable baseline route guarantees.
They are versioned and release-certified in
[trust-social-content-format-profiles.md](trust-social-content-format-profiles.md), but their
profile status does not add app-facing endpoint or capability membership to the 1.0 stable
baseline.

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

The stable promise explicitly excludes experimental, operator-only, internal, app-vault,
identity-vault, app-service, Trust Graph Local RC, Web Shell-only, legacy plugin, and FProxy browse
surfaces unless a descriptor is already a Platform API 1.0 stable baseline member. Stable-target
apps must not rely on future-baseline or graduation-candidate APIs.

## Compatibility Window Metadata

Current snapshots publish:

```json
{
  "compatibilityWindow": {
    "schemaVersion": 1,
    "baselineName": "1.0",
    "baselineContractVersion": 19,
    "currentContractVersion": 23,
    "supportPhase": "beta",
    "supportWindowStartedRelease": "production-beta",
    "minimumDeprecationWindowContractVersions": 2,
    "minimumScheduledRemovalWindowContractVersions": 2,
    "stableRemovalRequiresNewBaseline": true,
    "stableRemovalRequiresPreviousSnapshot": true,
    "stableRemovalRequiresExplicitWaiver": true,
    "criticalStableRemovalWaiverAllowed": false,
    "experimentalGraduationRequiresReview": true,
    "experimentalGraduationRequiresStableReferenceUpdate": true,
    "previousSnapshotRequiredInProductionBeta": true,
    "policyDocument": "docs/platform-api-compatibility-support-window.md"
  }
}
```

Older snapshots without `compatibilityWindow` remain parseable for developer comparison, but they
are not complete production beta history. In production beta mode, previous contract history must
come from a release-certification summary or a release artifact that includes stable baseline
metadata and the compatibility-window policy object.

## Deprecation And Removal Windows

Stable deprecation metadata is part of the compatibility contract.

A deprecated stable capability or endpoint must include:

```json
{
  "deprecation": {
    "deprecatedSinceContractVersion": 23,
    "removalContractVersion": null,
    "note": "Use the documented replacement."
  }
}
```

A stable item scheduled for removal must include both `deprecatedSinceContractVersion` and
`removalContractVersion`. The removal version must be greater than the deprecation version, and
both windows must meet policy:

- `removalContractVersion - deprecatedSinceContractVersion >= 2`
- `removalContractVersion - currentContractVersion >= 2`

The current snapshot must not mark a stable descriptor as deprecated before the deprecation window
starts. `deprecatedSinceContractVersion` greater than the current contract version is a release
blocker. Release certification also applies the removal-window checks whenever a stable descriptor
publishes `removalContractVersion`, even if its stability label is still `deprecated` rather than
`scheduled-for-removal`.

Concrete examples:

- Current contract `23`, deprecated since `23`, removal `25`: acceptable scheduled-removal runway.
- Deprecated since `23`, removal `24`: blocked because the deprecation window is one contract
  version.
- Current contract `23`, deprecated since `22`, removal `23`: blocked because there is no future
  removal runway.
- Current contract `23`, deprecated since `24`: blocked because the deprecation window has not
  started.
- Scheduled for removal with no deprecation object: blocked.

The `platform-api.contract` release evidence records stable descriptor deprecation metadata in
`details.stableDescriptorDeprecations`. The `platform-api.deprecation-window-policy` row reports
descriptor-level `descriptorErrors` and `descriptorWarnings` so release managers can identify the
exact stable capability or endpoint that violates the window policy. These fields contain only
descriptor identities and contract-version numbers; they must not contain local paths, tokens, raw
app data, raw fetched content, or private insert URIs.

During the active Platform API 1.0 support window, actual removal of a stable baseline member is a
release blocker unless a future documented stable baseline exists and the release policy explicitly
allows migration. Critical stable removals are not waiverable in production beta.

Experimental API deprecation is advisory by default. Strict experimental verification may promote
warnings to errors for an app that targets experimental APIs, but experimental changes do not alter
the Platform API 1.0 stable promise.

## Stable Breaking Changes

`PlatformApiContractVerifier.compareStableBaseline(previous, current)` and the release gate block
these stable API 1.0 regressions:

- stable capability removed;
- stable endpoint removed;
- stable capability or endpoint moved out of the stable baseline;
- stable capability or endpoint reclassified as experimental, internal, or operator-only;
- stable endpoint method or route identity changed;
- stable endpoint required capabilities changed;
- stable endpoint audit/authorization action label changed;
- stable endpoint app-principal access changed;
- stable deprecation or scheduled-removal metadata missing;
- stable deprecation or removal windows shorter than policy;
- stable baseline metadata missing from the current snapshot;
- previous stable baseline metadata missing in production beta mode;
- stable baseline name or baseline contract version changed.

Reports use deterministic finding codes such as `stable_api_capability_removed`,
`stable_api_endpoint_removed`, `stable_api_endpoint_required_capabilities_changed`,
`stable_api_endpoint_app_principal_changed`, `stable_api_deprecation_window_too_short`,
`stable_api_removal_window_too_short`, `stable_baseline_metadata_missing`, and
`stable_baseline_identity_changed`.

## Previous Contract Snapshot Storage

Canonical locations are:

```text
docs/platform-api/contracts/platform-api-1.0-baseline.json
docs/platform-api/contracts/previous-production-beta-contract.json
<out-root>/<release-id>/production-beta/artifacts/legacy/evidence/platform-api-contract-current.json
<out-root>/<release-id>/production-beta/artifacts/legacy/evidence/platform-api-contract-previous.json
<out-root>/<release-id>/production-beta/artifacts/legacy/evidence/platform-api-stable-diff.json
```

Release managers can provide previous history through:

- `inputs.releaseHistory` in the release-run manifest;
- the previous release-certification summary stored in history;
- a previous production beta release artifact;
- a local JSON path used by `crypta-app api diff` during dry-run review.

Behavior by mode:

- developer dry-run: missing or fixture history is a warning and marks the run as non-production
  context;
- release candidate: missing history is a warning unless release history is required by the run;
- production beta: missing previous contract history fails closed unless the gap is a structured,
  non-critical history waiver allowed by release policy.

Fixture and self-test snapshots are never promotion-ready production evidence. Contract and diff
reports must be redacted and must not include local absolute paths, private insert URIs, private
keys, app tokens, browser session tokens, raw fetched content, raw app data, or raw submission ZIP
contents.

## Stable 1.0 maintenance baseline

The Stable RC freeze authenticates the current contract, the immutable Platform API 1.0 baseline,
the stable diff, and this compatibility-window policy by digest. Stable GA must carry those exact
identities into `stable-1.0-maintenance-baseline.json`; authorization cannot waive a changed stable
surface or substitute a newer contract snapshot.

For later maintenance and hotfix releases, compare the candidate against the GA maintenance
baseline as well as any immediately previous production snapshot. Compatible additions and
deprecations still follow this support window, and Platform API 1.0 removals or access/capability
regressions remain non-waivable. A pre-GA API fix requires a new Stable RC freeze and a complete
post-freeze validation cycle.

## Experimental-To-Stable Graduation

The experimental-to-stable graduation process is a future-baseline process. It does not mutate Platform API
1.0.

Graduation states:

1. `experimental`: descriptor is usable only by apps declaring `api.targetStability=experimental`
   and `api.experimentalCapabilitiesAccepted=true`.
2. `candidate`: a release proposal names the target future baseline, such as `1.1`, and records
   rationale, compatibility impact, and reviewer evidence.
3. `reviewed`: verifier tests cover the stable identity, required capabilities, app-principal
   access, and manifest behavior.
4. `documented`: the future stable reference doc is updated with the target baseline membership.
5. `graduated`: the descriptor is stable only for apps targeting a supported stable baseline that
   includes it.

Apps targeting `stable` for Platform API 1.0 cannot use graduation candidates. Release
certification records `platform-api.experimental-graduation-policy` and fails if a graduated
descriptor lacks review evidence, verifier tests, or stable reference documentation.

## Waiver Policy

Waivers may allow a release to proceed with warnings such as:

- an experimental deprecation advisory;
- a non-production history gap in developer dry-run;
- a previous pre-freeze snapshot used for comparison outside production beta;
- documentation lag that does not change stable baseline behavior and has a tracked fix.

Waivers cannot hide:

- critical stable capability or endpoint removal;
- undeclared stable baseline mutation;
- missing current stable baseline or compatibility-window metadata;
- missing previous contract history in production beta when stable comparison is required;
- stable deprecation/removal window violations;
- internal/operator-only APIs accepted for third-party stable apps;
- redaction/security blockers;
- fixture or self-test evidence presented as production beta evidence.

Waived warnings may produce `go-with-waivers`. Non-waivable failures always produce `no-go`.

## App Author Commands

Generate and inspect the current contract:

```bash
crypta-app api snapshot --output build/platform-api-contract.json
crypta-app api policy --contract build/platform-api-contract.json
```

Compare previous and current stable baseline snapshots:

```bash
crypta-app api diff \
  --previous docs/platform-api/contracts/platform-api-1.0-baseline.json \
  --current build/platform-api-contract.json \
  --output build/platform-api-stable-diff.json
```

Verify a stable third-party app:

```bash
crypta-app compat verify \
  --bundle-dir . \
  --contract build/platform-api-contract.json \
  --target-stability stable \
  --strict
```

Stable apps should declare:

```properties
api.targetStability=stable
api.experimentalCapabilitiesAccepted=false
```

Experimental apps should declare:

```properties
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
```

Keep compatibility reports and digests in submission records. Do not attach raw private data,
local paths, raw fetched content, raw app data, submission ZIP contents, keys, tokens, or private
insert URIs.

## Maintenance-release enforcement

The canonical maintenance command compares the current Platform API contract and stable surface
against both the immutable GA baseline and the immediate predecessor. It carries original
deprecation clocks into each successor baseline; a release cannot reset a clock, relabel an
experimental surface as stable, waive a critical stable removal, or use a new baseline to conceal a
breaking change. Candidate-bound, fresh contract and stable-diff evidence is required even for a
security hotfix.

See the [Stable 1.0 maintenance release and security hotfix
path](stable-1.0-maintenance-release-and-hotfix-path.md).

## Lifecycle-bound removal governance

The Stable 1.0 lifecycle gate preserves the earliest authenticated deprecation clock across every
maintenance successor. A later contract or baseline cannot move
`deprecatedSinceContractVersion`, the effective notice time, or scheduled-removal metadata forward
to restart the clock. The public governance timeline binds those values to the original contract
snapshot and records each later observation.

A stable endpoint or capability cannot be removed while an authenticated published build remains
inside its supported lifecycle commitment or while a required stable third-party sample depends on
the surface. Moving a build to `deprecated` is not sufficient by itself; removal remains blocked
until the lifecycle policy, minimum notice, contract history, and dependency checks all pass.
Lifecycle state never rewrites an already published contract snapshot.

See [Stable 1.0 support lifecycle and deprecation governance](stable-1.0-support-lifecycle-and-deprecation-governance.md).
