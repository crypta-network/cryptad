---
name: cryptad-git-workflow
description: "Canonical Cryptad Git workflow guide for branching/release rules, integer build versioning/tags, Stable 1.0 protected GA publication, merge policy, PR rules, and strict git identity safeguards."
metadata:
  area: git
  domain: cryptad
---

## When to use
Use this skill whenever you:
- Need the canonical branch/release policy reference.
- Create branches, commits, tags, releases, or hotfixes.
- Resolve merge conflicts or integrate changes between branches.
- Prepare a pull request (even if you won’t open it yet).

## Workflow reference
### Goals
- Keep `main` always releasable and matching the latest production build.
- Use a single integer build number for shipped versions.
- Keep feature work parallel while preserving auditable release/hotfix history.

### Versioning and tags
- The build number is a single integer in `build.gradle.kts` (example: `version = 2`).
- Release/hotfix tags must use `v<build-number>` (example: `v2`).
- If a release/hotfix changes the shipped build, bump `version` to the intended build number.
- Stable 1.0 is a product/API milestone within this integer model. Do not create a `1.0.0` project
  version, semantic-version tag, replacement branch model, or a second build with the same integer
  version but different product bytes.

### Branching model (GitFlow-inspired)
- Primary branches:
  - `main`: production-ready; every commit is release-quality.
  - `develop`: integration branch for the next release.
- Supporting branches:
  - `feature/<name>`: new features/refactors targeting `develop`.
  - `bugfix/<name>`: non-production fixes targeting `develop`.
  - `release/<build-number>`: stabilization branch from `develop`.
  - `hotfix/<build-number>`: emergency production fix branch from `main`.

## Merge and PR policy
- Commit format: Conventional Commits.
- `feature/*` and `bugfix/*` PRs: squash-and-merge is encouraged.
- `release/*` and `hotfix/*` merges:
  - Do not squash or rebase these merges.
  - Merge into `main` with `--no-ff`.
  - Back-merge into `develop` with `--no-ff`.
- The Stable 1.0 protected GA workflow may create or verify the annotated `v<build-number>` tag and
  GitHub Release only after exact-RC validation and environment approval. It never merges the
  release branch. Continue to use explicit release-manager-approved `--no-ff` merges into `main`
  and `develop`.
- The protected Stable 1.0 maintenance workflow applies the same boundary to later routine
  `release/<build-number>` and security `hotfix/<build-number>` candidates: it may create or verify
  the annotated tag and exact public state, but it never creates or merges branches.
  Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md` for the protected sequence and
  verify that the eventual `main` merge contains the tagged shipped commit; a `--no-ff` merge gives
  `main` a distinct merge-commit tip.
- Before a Stable 1.0 maintenance or security-hotfix freeze, use `stable-backport` to classify
  every proposed fix, authenticate its full source/candidate commit identities and provenance,
  carry the prior queue forward, and account for every candidate change. Routine work uses only
  `routine-maintenance`; critical incident work uses only `security-hotfix`. Patch-id equality is
  supporting evidence for a reviewed clean cherry-pick, not authorization. Candidate handoff
  requires `verified` fixes; post-publication completion requires separate `main` and `develop`
  no-ff merge commits on those protected tips' first-parent chains.
- Clean cherry-pick and manual-conflict approval must come from the exact successful protected
  provenance-review workflow artifact; matching caller-selected digests are not approval. Keep the
  authoritative queue protected and upload only its bounded public projection in plaintext.
  Transport full phase and review handoffs only as exact authenticated encrypted envelopes, and
  decrypt them with the shared protected-environment handoff key.
- For a routine train, never reuse `candidateBaseCommit` as proof of its own branch role. The
  protected train workflow freezes the independently resolved protected `develop` tip as
  `developmentLineageCommit`; certification requires the candidate base to be the exact merge
  base with that lineage. Once a fix is landed, its provenance is immutable.
- For a security-hotfix train, freeze the independently resolved protected `main` tip as
  `mainLineageCommit` and require `candidateBaseCommit` to equal it. The tagged publication
  predecessor must remain an ancestor of that tip. Do not branch from the tagged candidate when
  `main` has advanced through its required no-ff reconciliation merge.
- Treat GA as the sole queue genesis. A later published predecessor must authenticate the exact
  `previousStableBackportQueue` and `previousStableBackportValidation`; absence never means “start
  over.” For merge coverage, compare against Git's automatic merge and both parents rather than
  trusting an empty combined diff.
- Cryptad has one authenticated Stable 1.0 publication chain. Historical supported, security-only,
  deprecated, end-of-support, or revoked builds may be policy-qualified upgrade or recovery test
  sources; never create a parallel patch branch, LTS line, or latest pointer for them.
- After publication and the explicit no-squash, `--no-ff` merges, run `stable-backport` in
  `verify-release-completion` mode. Missing `main`/`develop` reconciliation or hotfix merge-back
  remains a carried blocker for the next train. Completion accepts only a merge tree matching
  Git's isolated automatic merge result as reconciled; a manual resolution is not authenticated by
  parent shape or protected-tip reachability alone. Once the graph and protected attestation pass,
  the completion layer records that content-review failure as the exact policy-derived carried
  obligation and marks reconciliation `content-review-required`. The next queue must seed that
  exact row before the published fixes move to `released`, and remains blocked pending separately
  authenticated review.
- Before the next train advances prior fixes to `released`, use an unexpired successful completion
  artifact when available, or reauthenticate the support-lifetime protected completion bundle
  after Actions retention expires. Re-resolve protected `main` and `develop` in both cases and
  carry the resulting predecessor-completion handoff through all train phases.
- Record the published `release/<build>` or `hotfix/<build>` candidate as the merged tip of both
  independent no-ff merge records. Do not describe the `main` merge commit as the tip merged into
  `develop`. A fix provenance commit may be earlier than the publication tip, but it must remain
  an authenticated ancestor. Completion must bind exact protected `main` and `develop` tips and
  consume the receipt-bound frozen validation from the authorized prior workflow phase.
- PR policy: require green CI and at least one approval.
- **Always ask before creating a GitHub pull request.** Do not open PRs without explicit approval.

## Release/hotfix checklist
- [ ] `build.gradle.kts` has the intended integer `version`.
- [ ] CI is green on the release/hotfix branch.
- [ ] Tag created as `v<build-number>`.
- [ ] Merged to `main` with `--no-ff` (no squash), then back-merged to `develop` with `--no-ff`.
- [ ] Branches and tags are pushed.
- [ ] Release notes updated (if applicable).

For Stable 1.0, also verify:

- [ ] The selected RC is the latest successful protected freeze/refreeze for the release/build and
      commit.
- [ ] The protected authorization, promotion plan, and publication receipt bind the same source,
      freeze, archive, product, catalog, validation, notes, and maintenance-baseline digests.
- [ ] An existing tag/Release is accepted only when its target, notes, planned assets, sizes, and
      digests match exactly; conflicting or partial state is recorded as
      `publication-verification-failed` without recovery code mutating it.
- [ ] No test, local default, pull-request workflow, or validate-only run can create a tag, Release,
      branch, public catalog update, update descriptor, or network insert.
- [ ] For a later Stable 1.0 release, `stable-maintenance` authenticated the immutable GA root and
      latest published predecessor, and the protected receipt verifies exact candidate bytes before
      the manual no-squash, `--no-ff` merge-back.
- [ ] `stable-maintenance.backport-release-train` binds the exact accepted fix set, train policy
      and queue, candidate and predecessor, zero-unaccounted coverage result, authorization, and
      unresolved obligations.
- [ ] The post-release completion record authenticates the exact receipt and `main`/`develop`
      merge parents without performing those merges.
- [ ] Any Stable 1.0 support-state change uses the separate protected `support-lifecycle`
      descriptor workflow after authenticating the complete published chain; it does not rewrite a
      tag, Release asset, baseline, receipt, history entry, or historical `core-info.json`.

## Git identity policy (must follow)
### GitHub operation identity
- All GitHub operations for this repository must use the `leumor` account, including PR creation,
  review comments, issue comments, review-thread resolution, release edits, CI inspection, and
  branch pushes.
- Do not rely on the active/default `gh` account. Prefix every manual `gh` command with:
  `GH_TOKEN="$(gh auth token --user leumor)" gh ...`.
- If a GitHub MCP or plugin tool performs a write operation, verify the created PR/comment/review
  author is `leumor`. If it is not `leumor`, delete or close the accidental artifact when possible
  and recreate it as `leumor`.
- If `gh auth token --user leumor` fails, stop and ask the user to authenticate `leumor`; do not
  fall back to another GitHub account.

### Never override authorship/committer identity
- Do not pass `--author` or `--reset-author` to `git commit`.
- Do not set `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, or `GIT_COMMITTER_EMAIL` in commit flows.
- Do not run `git config user.name` / `git config user.email` inside this repository during commit flows.
- Use the existing project/default identity configured for the environment.

### Pre-commit identity check (required)
Before any `git commit` **or** history rewrite, verify identity is configured:
```bash
git config --get user.name
git config --get user.email
```

If either is missing/empty:
1. STOP. Do not proceed with the commit or rewrite.
2. Warn the user and ask them to set identity themselves (agents must not set it).
   Example:
   ```bash
   git config --global user.name "<Your Name>" && git config --global user.email "<you@example.com>"
   ```
3. Resume only after the user confirms identity is set.

### History rewrites
Only rewrite authorship/committer history when explicitly requested by a maintainer.
- Prefer interactive rebase.
- Push with `--force-with-lease`.
- Document rewritten SHAs in the PR.
