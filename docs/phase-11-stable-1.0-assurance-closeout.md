# Phase 11 and Stable 1.0 assurance closeout

The original Phase 11 scope, PR-270 through PR-282, is complete. The Stable 1.0 assurance
extension, PR-283 through PR-290, is also complete. PR-290 is the final PR in this sequence: it
closes the dependency-security governance gap between PR-289's exact component inventory and the
existing vulnerability, remediation, publication, and lifecycle authorities.

This is a repository-delivery closeout. It records the implementation and deterministic offline
evidence delivered by the sequence. It does not claim live advisory retrieval, production
disposition authorization, remote publication, public observation, release mutation, or lifecycle
mutation that was not actually performed.

The canonical machine-readable map is
[`tools/release-certification/stable-1.0-assurance-closeout.json`](../tools/release-certification/stable-1.0-assurance-closeout.json).
The rows between the markers below use the same PR identifiers, capability text, ordering, and
delivery-status values. Certification tests compare the two representations exactly.

## Delivered PR map

<!-- stable-1.0-assurance-pr-map:start -->
| PR | Capability | Delivery status |
|---|---|---|
| PR-270 | Production beta hardening | implementation-complete |
| PR-271 | Catalog operations and mirrors | implementation-complete |
| PR-272 | Previous-candidate beta upgrade evidence | implementation-complete |
| PR-273 | App-platform public-beta intake and upgrade evidence | implementation-complete |
| PR-274 | Platform API compatibility window | implementation-complete |
| PR-275 | First-party app and app-platform beta readiness gates | implementation-complete |
| PR-276 | Trust and social content-format profiles | implementation-complete |
| PR-277 | Privacy-preserving beta diagnostics | implementation-complete |
| PR-278 | Production security drill gates | implementation-complete |
| PR-279 | Legacy plugin migration finalization | implementation-complete |
| PR-280 | Public-beta onboarding documentation gate | implementation-complete |
| PR-281 | Public-beta support feedback loop | implementation-complete |
| PR-282 | Stable 1.0 readiness gate | implementation-complete |
| PR-283 | Stable RC freeze and authenticated candidate artifacts | implementation-complete |
| PR-284 | Stable GA exact-byte publication and immutable release root | implementation-complete |
| PR-285 | Stable maintenance and security-hotfix publication | implementation-complete |
| PR-286 | Stable support lifecycle and revocation governance | implementation-complete |
| PR-287 | Security fix intake, backport provenance, and release trains | implementation-complete |
| PR-288 | Private vulnerability lifecycle and coordinated disclosure | implementation-complete |
| PR-289 | Supply-chain inventory and reproducible-build governance | implementation-complete |
| PR-290 | Dependency-vulnerability monitoring and remediation governance | implementation-complete |
<!-- stable-1.0-assurance-pr-map:end -->

The release-evidence tooling unification that followed PR-282 is cross-cutting support for this
map, not an additional numbered assurance capability.

## Evidence classification

The closeout distinguishes three evidence classes:

| Classification | Meaning at closeout |
|---|---|
| `implementation-complete` | The repository contains the command, policies, schemas, engines, gates, protected workflow contracts, publication contracts, tests, and operator documentation required by the applicable PR. |
| `fixture/self-test-complete` | Deterministic offline fixtures and focused self-tests exercise the implemented contract without network access or remote mutation. The exact results belong in the implementation handoff or CI record rather than being invented in this document. |
| `protected-operation-evidence-required` | A real source retrieval, review authorization, release action, publication, observation, case transition, or lifecycle transition is evidenced only by the corresponding protected workflow receipt. Absence of such a receipt from this repository-only change is an operational limitation, not missing implementation. |

The canonical JSON classifies repository delivery as `implementation-complete`, offline
verification as `fixture/self-test-complete`, and production execution as
`protected-operation-evidence-required`. Its remote-operation claim fields are all false because
this closeout does not manufacture production receipts.

## Final assurance chain

The completed Stable 1.0 chain is:

```text
PR-283 authenticated RC freeze
  -> PR-284 exact-byte GA root
  -> PR-285 maintenance and security-hotfix publication
  -> PR-286 lifecycle governance
  -> PR-287 fix and backport provenance
  -> PR-288 private vulnerability case authority
  -> PR-289 component inventory, SBOM, and reproducible-build authority
  -> PR-290 authenticated dependency intelligence, matching, dispositions, and remediation gate
  -> release-certification aggregate promotion decision
```

PR-289 proves what exact components and bytes belong to each Stable build and subject. PR-290
authenticates external dependency intelligence, matches it against those identities, and requires
a bounded disposition. Affected findings remain bound to PR-288 for severity and private case
state, PR-287 for the security fix and release lane, PR-285 for exact publication, and a successor
PR-289 inventory for proof of the fixed bytes. PR-286 remains the sole lifecycle transition
authority.

## Final authorities and gates

The final authority boundaries are:

- PR-289: exact component, dependency, release-subject, SBOM, and reproducible-build identity;
- PR-290: authenticated dependency intelligence, matching, findings, dispositions, monitoring,
  remediation obligations, and dependency promotion status;
- PR-288: opaque private cases, Crypta severity, deadlines, disclosure, and closure;
- PR-287: security-fix intake, provenance, release lane, and completion;
- PR-285: exact maintenance or security-hotfix publication and public observation;
- PR-286: support lifecycle, deprecation, end-of-support, and revocation transitions; and
- PR-284: the immutable Stable GA release root.

The final aggregate gate map includes:

- `ecosystem.rc-certification`;
- `ecosystem.stable-vulnerability`;
- `ecosystem.stable-supply-chain`; and
- `ecosystem.stable-dependency-vulnerability`.

The PR-290 gate is prospective and non-waivable after activation. Historical candidates frozen
before the policy boundary retain their original validation contracts and receipts. New Stable
maintenance and security-hotfix candidates fail closed for unauthenticated or stale intelligence,
snapshot replay or rollback, missing mandatory sources, alias conflicts, ambiguous or unsupported
matching, substituted PR-289 mappings, stale or untrusted dispositions, overdue investigation,
unremediated affected exposure, inconsistent PR-288 binding, PR-287/PR-285 lineage mismatch,
unobserved fixed bytes, publication failure, or redaction failure.

## Canonical verification commands

Run the focused PR-290 suite and the required Stable regression suites:

```bash
python3 tools/release-certification/certify.py stable-dependency-vulnerability --self-test
python3 tools/release-certification/certify.py stable-supply-chain --self-test
python3 tools/release-certification/certify.py stable-vulnerability --self-test
python3 tools/release-certification/certify.py stable-backport --self-test
python3 tools/release-certification/certify.py stable-maintenance --self-test
python3 tools/release-certification/certify.py stable-lifecycle --self-test
python3 tools/release-certification/certify.py stable-ga --self-test
python3 tools/release-certification/certify.py stable-rc --self-test
python3 tools/release-certification/certify.py release-certification --self-test
python3 tools/release-certification/certify.py app-platform-docs --self-test
```

Run the focused PR-289 integration modules:

```bash
PYTHONPATH=tools/release-certification python3 -m unittest -v \
  cryptad_certification.tests.test_release_certification_stable_supply_chain \
  cryptad_certification.tests.test_stable_maintenance_supply_chain \
  cryptad_certification.tests.test_stable_vulnerability_component_scope
```

These commands are side-effect-free. The final implementation handoff and CI record must report
the exact executed counts and results. This document does not claim a result for a command that was
not run.

## Non-blocking protected-operation tasks

Real deployment still requires operators to:

- review and configure the exact production advisory endpoints, producer identities, protected
  environments, and attestation trust roots;
- run the protected producer to create the first live authenticated source snapshot and chain it
  to later editions;
- perform an independent protected disposition review when a real finding requires one;
- exercise PR-288 case intake, PR-287 remediation, PR-285 publication, or PR-286 lifecycle
  authorization when an actual finding creates those obligations;
- publish only the reviewed public-safe PR-290 projection through the authenticated backend; and
- capture a fresh observation of the exact immutable public bytes.

The optional reviewed-vendor source remains disabled until a real structured endpoint or protected
manual-record procedure is approved. No live source retrieval or remote publication was performed
as part of this repository implementation.

These tasks are production operations, not an unfinished assurance PR. The Phase 11 and Stable 1.0
assurance extended sequence is closed with PR-290 as its final PR; no automatic follow-up PR is
required or implied.
