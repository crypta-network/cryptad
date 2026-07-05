# Third-party developer beta program

The third-party developer beta program is the public app-author path for building and submitting
Crypta apps without reading daemon internals. It connects the developer CLI, browser SDK, Platform
API 1.0 stable baseline, submission pre-review, reviewer decisions, catalog-candidate generation,
feedback templates, and release-certification evidence into one deterministic workflow.

The program is for external app authors, plugin authors migrating toward app bundles, reviewers who
need reproducible local evidence, and release managers checking that the app ecosystem remains
usable outside first-party development. It is not a hosted public app store, ranking service,
payment system, production signing ceremony, or promise of legacy plugin ABI compatibility.

## Scope

In scope:

- stable-only third-party apps that target Platform API 1.0;
- local `crypta-app` scaffold, test, lint, compatibility, packaging, and submission commands;
- deterministic non-production sample review decisions and catalog-candidate descriptors;
- structured beta feedback, resubmission, compatibility, and plugin migration reports;
- release-certification evidence for the developer beta path.

Out of scope:

- production signing or reviewer private material;
- live-network access during CI self-tests;
- public hosted catalog submission services;
- internal, operator-only, or daemon-private APIs;
- compatibility with the old plugin ABI, old FCP plugin commands, WebOfTrust, Freetalk, Sone, or
  Freemail plugin internals.

## Install `crypta-app`

Build the developer CLI from the repository:

```bash
./gradlew :platform-devtools:installDist
export PATH="$PWD/platform-devtools/build/install/crypta-app/bin:$PATH"
crypta-app --help
```

The CLI works on staged app bundle directories. It does not register a Gradle subproject, install
the app into a running daemon, or contact the Crypta network during local checks.

## Create a stable third-party app

Start with the stable-only sample template:

```bash
crypta-app init \
  --template hello-stable \
  --id org.example.hello \
  --name "Hello Stable" \
  --version 0.1.0 \
  --dir build/dev-apps/hello-stable
cd build/dev-apps/hello-stable
```

`--id` is an alias for `--app-id`. The generated app declares:

```properties
api.targetStability=stable
api.experimentalCapabilitiesAccepted=false
app.permissions=platform.contract.read
```

Use `samples/third-party/hello-stable-app/` as the checked-in non-production reference fixture.
It is intentionally outside the first-party catalog.
The `hello-stable` scaffold also writes `review/*.md` placeholders for the submission command;
edit those files before submitting anything beyond local beta evidence.

## Choose a stability target

Use `api.targetStability=stable` when the app uses only the Platform API 1.0 stable baseline listed
in [platform-api-1.0-stable-reference.md](platform-api-1.0-stable-reference.md). Stable-only apps
must set `api.experimentalCapabilitiesAccepted=false`.

Stable-only apps get the active beta compatibility guarantee documented in
[platform-api-compatibility-support-window.md](platform-api-compatibility-support-window.md):
Platform API 1.0 stable capabilities, stable endpoint identities, required capability sets, and
audit/authorization action labels, and app-principal access flags remain available across production
beta releases unless a future stable baseline and release policy explicitly allow migration. This
is not an indefinite support promise and it does not cover experimental, operator-only, internal,
AppVault, app-service, Trust Graph, Web Shell, or legacy plugin APIs.

Use `api.targetStability=experimental` only when the app knowingly uses app-facing experimental
capabilities and sets `api.experimentalCapabilitiesAccepted=true`. Experimental apps may be
accepted for beta review, but release certification and reviewers treat them as outside the stable
compatibility support window.

Third-party apps must not request internal or operator-only permissions. Pre-review rejects those
capabilities even when the manifest opts into experimental APIs.

## Run local checks

Run strict checks before signing, packaging, or filing a submission issue:

```bash
mkdir -p ../artifacts
crypta-app test --bundle-dir . --strict --json ../artifacts/app-test.json
crypta-app ui lint --bundle-dir . --strict --json ../artifacts/ui-lint.json
crypta-app api snapshot --output ../artifacts/platform-api-contract.json
crypta-app api policy \
  --contract ../artifacts/platform-api-contract.json \
  --output ../artifacts/platform-api-policy.json
crypta-app compat verify \
  --bundle-dir . \
  --contract ../artifacts/platform-api-contract.json \
  --target-stability stable \
  --strict \
  --json ../artifacts/api-compatibility.json
```

`crypta-app test` combines bundle validation, API compatibility verification, and static UI lint
where applicable. The direct commands are useful when a reviewer needs a narrower report.
Reviewers and release managers may also ask for `crypta-app api diff --previous ... --current ...`
when comparing a submitted app against a previous production beta Platform API contract snapshot.

## Package and submit

Complete [third-party-app-submission-checklist.md](third-party-app-submission-checklist.md)
before creating the package. The checklist is the shared author/reviewer source for manifest,
permission, UI lint, sandbox, app-data, backup/restore, service dependency, security, support, and
redaction requirements.

Package the staged bundle and create a deterministic submission package:

```bash
crypta-app pack --bundle-dir . --output ../artifacts/org.example.hello.zip --overwrite
crypta-app submission create \
  --bundle-dir . \
  --output ../artifacts/org.example.hello-submission.zip \
  --submission-type new_app \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/org.example.hello" \
  --permission-rationale review/permission-rationale.md \
  --sandbox-rationale review/sandbox-rationale.md \
  --data-schema review/data-schema.md \
  --backup-restore review/backup-restore.md \
  --security-notes review/security-notes.md \
  --changelog review/changelog.md \
  --non-production \
  --overwrite
crypta-app submission verify --submission ../artifacts/org.example.hello-submission.zip --json
crypta-app submission pre-review \
  --submission ../artifacts/org.example.hello-submission.zip \
  --contract ../artifacts/platform-api-contract.json \
  --output ../artifacts/org.example.hello-pre-review.json \
  --overwrite
```

For beta fixtures and tests, keep `--non-production` set. Production review material is separate
and must not be committed or pasted into issues.

## Review decisions

Review status values have separate meanings:

- `reviewed`: the submitted bundle passed pre-review and a reviewer issued a trusted reviewed
  receipt.
- `caution`: the submitted bundle passed pre-review, but the reviewer recorded a warning that must
  stay visible to catalog consumers.
- `rejected`: the reviewer declined the submission. No reviewed/caution receipt is issued.
- `resubmitted`: the author filed a new submission package that links to the previous submission
  id with `--resubmission-of`.

For local beta fixtures, reviewers can record a non-production decision with deterministic
test-only material:

```bash
crypta-app submission decide \
  --submission ../artifacts/org.example.hello-submission.zip \
  --pre-review ../artifacts/org.example.hello-pre-review.json \
  --decision reviewed \
  --reviewer-key-id dev-reviewer \
  --reviewer-private-key ../artifacts/dev-reviewer-private.der \
  --trusted-reviewer-keys ../artifacts/trusted-reviewer-keys.properties \
  --reason review/decision-reason.md \
  --receipt-output ../artifacts/org.example.hello-review-receipt.properties \
  --transparency-log ../artifacts/review-transparency.jsonl \
  --allow-non-production \
  --overwrite
```

The deterministic beta flow may use test-only reviewer keys with `--allow-non-production`. That
flow proves command wiring; it is not production reviewer trust.

## Public beta intake queue

Public beta reviewers import submitted packages into a local intake queue with
`crypta-app submission intake import`. Developers do not need account credentials or a hosted
portal; the submitted ZIP, public maintainer contact, source URL, source revision, and rationale
files are enough for local beta intake. Reviewers then run:

- `crypta-app submission intake assign` to bind a trusted reviewer key id, display name, timestamp,
  and reason digest to the submission.
- `crypta-app submission intake pre-review` to generate `pre-review.json`,
  `submission-verification.json`, API compatibility, UI lint, redaction-scan, and artifact-manifest
  outputs from queue state.
- `crypta-app submission intake decide` to record `reviewed`, `caution`, `rejected`, or
  `resubmission_requested`.
- `crypta-app submission intake stage-candidate` to stage a reviewed or explicitly allowed caution
  submission into a beta catalog candidate area.

Caution decisions are visible to operators and install consent surfaces. Rejected decisions cannot
create beta catalog candidates. A resubmission must link back to the earlier submission id with
`--resubmission-of`, and the reviewer feedback should be summarized without embedding raw private
material. The queue, transparency export, and release evidence store digests and status values only;
raw ZIP contents, private insert URIs, app tokens, browser session tokens, raw fetched content,
raw app data, and absolute local paths are blocked by redaction.

## Catalog candidates

After a reviewed or caution receipt exists, create a catalog candidate descriptor with:

```bash
crypta-app submission catalog-candidate \
  --submission ../artifacts/org.example.hello-submission.zip \
  --review-receipt ../artifacts/org.example.hello-review-receipt.properties \
  --trusted-reviewer-keys ../artifacts/trusted-reviewer-keys.properties \
  --bundle-uri "crypta:CHK@<artifact-key>/org.example.hello.zip" \
  --artifact-output ../artifacts/org.example.hello-reviewed.zip \
  --summary "Non-production Hello Stable catalog candidate." \
  --output ../artifacts/org.example.hello-catalog-entry.properties \
  --overwrite
```

Catalog candidates are review artifacts. They are not automatically promoted into the first-party
stable catalog and they do not bypass install/update consent, compatibility checks, or reviewer-key
policy.

## Feedback and submission issues

Use the structured GitHub templates:

- `.github/ISSUE_TEMPLATE/developer-beta-feedback.yml` for developer workflow feedback;
- `.github/ISSUE_TEMPLATE/app-submission-beta.yml` for app submission packages;
- `.github/ISSUE_TEMPLATE/app-review-appeal.yml` for review appeals and resubmissions;
- `.github/ISSUE_TEMPLATE/platform-api-compatibility.yml` for compatibility-window issues;
- `.github/ISSUE_TEMPLATE/plugin-migration-feedback.yml` for legacy plugin migration feedback.

Reports should include app id, version, capability names, stable/experimental target, pre-review
status, safe digests, and redacted summaries. Do not paste private keys, private insert URIs,
browser session tokens, authorization headers, raw app data, raw fetched content, raw signatures,
or local absolute paths.

## Compatibility support window

The beta support policy is defined in
[platform-api-compatibility-support-window.md](platform-api-compatibility-support-window.md).
In short: Platform API 1.0 stable baseline compatibility is release-gated for stable-only
third-party apps, experimental APIs are opt-in and may change during beta, and deprecations must be
recorded with migration windows before removal.

App authors should test against the current contract snapshot and the previous candidate snapshot
when one is published for a release candidate. Catalog and review metadata may record the app's
target stability, minimum contract version, maximum tested contract version, review status, and
support notes.

## Security and privacy expectations

Keep developer artifacts deterministic and redacted:

- use `.invalid` hostnames or placeholder `crypta:CHK@<artifact-key>` values in examples;
- keep local development keys outside the repository;
- summarize rationale text in issues instead of pasting sensitive bodies;
- never include production signing keys, reviewer private keys, app tokens, bearer tokens, browser
  session tokens, private insert URIs, raw fetched content, raw app data, or local absolute paths;
- label non-production fixtures and catalog candidates clearly.

Redaction failures in generated release artifacts are release-blocking in production beta mode.

## Sandbox limitations and known limits

The developer beta mock server is an offline app-authoring surface. It can serve deterministic
fixtures for local SDK and UI work, but it does not install apps into AppHost, exercise live network
fetch/insert behavior, validate production sandbox providers, or prove operator grants. Use the
known-limitations page for current beta boundaries:
[app-platform-beta-known-limitations.md](app-platform-beta-known-limitations.md).

## Plugin author migration

Legacy plugin authors should start with
[legacy-plugin-migration-cookbook.md](legacy-plugin-migration-cookbook.md), then check the policy
overview in [legacy-plugin-migration-guide.md](legacy-plugin-migration-guide.md) and
[legacy-plugin-freeze-policy.md](legacy-plugin-freeze-policy.md). Map old plugin patterns to app
manifests, app-owned static UI, durable app data, content subscriptions, AppVault, app services,
and stable Platform API capabilities where possible.

The cookbook path is:

1. Write a migration plan from [templates/plugin-migration-plan.md](templates/plugin-migration-plan.md).
2. Run `crypta-app init` or adapt an existing app template.
3. Declare manifest capabilities, app-data namespaces, content profiles, identity grants, and
   app-service dependencies.
4. Write permission rationale, app-data schema notes, migration notes, backup/restore notes,
   security notes, and redaction policy.
5. Run `crypta-app test`, `crypta-app ui lint`, and `crypta-app compat verify`.
6. Create the submission package, run pre-review, complete reviewer decision, stage a catalog
   candidate when eligible, and install from the beta catalog only after signed bundle, signed
   catalog, review receipt, compatibility, and consent gates pass.

Patterns that require daemon-private hooks, old plugin ABI compatibility, old FCP plugin command
compatibility, raw localhost RPC, raw FProxy scraping, private-key export, unbounded crawling, or
old WebOfTrust/Freetalk/Sone/Freemail internals remain unsupported. Retained FProxy browse behavior
is an emergency and compatibility boundary; it is not a path for new plugin APIs.

## Beta artifacts versus production artifacts

Beta artifacts may use non-production reviewer keys, fixture catalog candidates, synthetic bundle
URIs, and local transparency logs. Production artifacts must use production signing and reviewer
material, production catalog policy, production redaction scans, and the release pipeline described
in [production-beta-release-pipeline.md](production-beta-release-pipeline.md).
