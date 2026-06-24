# Platform API compatibility support window

This page defines the beta compatibility support policy for third-party apps. It explains what is
release-gated, what is experimental, and how authors should test against Crypta Platform API
contract snapshots.

## Stable baseline expectation

Platform API 1.0 stable baseline membership is documented in
[platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md). Third-party apps that
declare:

```properties
api.targetStability=stable
api.experimentalCapabilitiesAccepted=false
```

and use only stable baseline capabilities should continue to pass compatibility verification across
beta release candidates in the active support window. Release certification treats a stable API
breaking change as a release-blocking failure unless the release notes and compatibility evidence
record an explicit migration plan.

This is a beta support policy, not an indefinite promise. It applies to the active Platform API 1.0
stable baseline during beta and may be replaced by a future documented baseline.

## Experimental API opt-in

App-facing experimental APIs require:

```properties
api.targetStability=experimental
api.experimentalCapabilitiesAccepted=true
```

Experimental APIs may change, warn, or require migration between beta candidates. Reviewers may
accept an experimental app for beta testing, but the app is outside the stable-only support window.
Internal and operator-only APIs are never accepted for third-party app manifests.

## Deprecation and scheduled removal

Deprecations must be visible in the Platform API contract, developer docs, compatibility reports,
and release certification evidence. During beta:

- stable baseline members should not be removed without a new documented baseline or explicit
  release-blocking migration decision;
- deprecated stable members remain callable during their recorded migration window;
- scheduled-for-removal items must include a removal target and replacement guidance;
- experimental APIs may move faster, but authors still need actionable warnings before removal.

## Manifest fields that affect compatibility

Compatibility verification uses:

- `api.minimumVersion`
- `api.maximumTestedVersion`
- `api.targetStability`
- `api.experimentalCapabilitiesAccepted`
- `app.permissions`
- catalog review metadata when a descriptor is being verified

The integer contract version is separate from `/api/v1` and from Cryptad build numbers. The stable
baseline name is `1.0`; current contract snapshots may have larger integer versions.

## Release certification behavior

Release certification requires evidence that stable-only apps still verify against the current
contract. For the third-party developer beta program, the release gates include:

- `third-party-developer.compatibility-window`
- `third-party-developer.template`
- `third-party-developer.sample-app-flow`
- `third-party-developer.redaction`
- the existing app-store submission and review evidence family

Redaction failures, internal/operator-only capability acceptance, or stable baseline regressions
are blockers in production beta mode.

## Author testing window

Before submission, authors should test against:

1. the current local contract snapshot from `crypta-app api snapshot --output ...`;
2. the previous release-candidate snapshot when one is published for comparison;
3. the exact contract file supplied by reviewers when a pre-review finding references one.

Run:

```bash
crypta-app compat verify --bundle-dir . --contract build/platform-api-contract.json --strict
crypta-app test --bundle-dir . --contract build/platform-api-contract.json --strict
```

Keep the resulting status and digests, not raw private data, in submission and feedback issues.

## Catalog and review metadata

Catalog candidates and review metadata may include target stability, minimum contract version,
maximum tested contract version, review status, reviewer trust status, submission id, resubmission
link, and support notes. They must not include submission package bodies, raw rationale text,
private keys, private insert URIs, tokens, raw app data, raw fetched content, or local absolute
paths.
