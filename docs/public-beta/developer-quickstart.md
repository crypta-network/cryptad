# Public beta third-party developer quickstart

Use this quickstart to create, test, package, and pre-review a stable third-party app for public
beta intake.

## Scope

The commands below are offline or loopback-local unless a command explicitly says otherwise. They
do not install an app into a running node, publish to the public network, or approve stable catalog
promotion. Source-of-truth details live in
[../developer-beta-toolkit.md](../developer-beta-toolkit.md),
[../third-party-developer-beta-program.md](../third-party-developer-beta-program.md),
[../third-party-app-submission-checklist.md](../third-party-app-submission-checklist.md),
[../app-store-submission-and-review-workflow.md](../app-store-submission-and-review-workflow.md),
[../platform-api-compatibility-support-window.md](../platform-api-compatibility-support-window.md),
and [../platform-api-1.0-stable-reference.md](../platform-api-1.0-stable-reference.md).

## Install `crypta-app`

```bash
./gradlew :platform-devtools:installDist
export CRYPTA_APP="$PWD/platform-devtools/build/install/crypta-app/bin/crypta-app"
"$CRYPTA_APP" --help
```

## Create a stable app

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/hello-stable \
  --template hello-stable \
  --app-id org.example.hello \
  --name "Hello Stable" \
  --version 0.1.0
```

The checked-in sample is documented at
[../../samples/third-party/hello-stable-app/README.md](../../samples/third-party/hello-stable-app/README.md).
It targets `api.targetStability=stable` and uses only `platform.contract.read` by default.

## Run local development

```bash
"$CRYPTA_APP" dev --bundle-dir build/dev-apps/hello-stable
```

The dev server is loopback-local and uses mock Platform API fixtures. It does not prove catalog
install, production signing, live-node permissions, or review trust.

## Run strict checks

```bash
mkdir -p build/artifacts

"$CRYPTA_APP" test \
  --bundle-dir build/dev-apps/hello-stable \
  --strict \
  --json build/artifacts/app-test.json

"$CRYPTA_APP" ui lint \
  --bundle-dir build/dev-apps/hello-stable \
  --strict \
  --json build/artifacts/ui-lint.json

"$CRYPTA_APP" api snapshot \
  --output build/artifacts/platform-api-contract.json

"$CRYPTA_APP" api policy \
  --contract build/artifacts/platform-api-contract.json \
  --output build/artifacts/platform-api-policy.json

"$CRYPTA_APP" compat verify \
  --bundle-dir build/dev-apps/hello-stable \
  --contract build/artifacts/platform-api-contract.json \
  --target-stability stable \
  --strict \
  --json build/artifacts/api-compatibility.json
```

Fix strict test, UI lint, API policy, and compatibility errors before packaging. Do not request
host/operator-only capabilities to work around a failure.

## Generate local development keys

```bash
mkdir -p build/dev-keys

"$CRYPTA_APP" keys generate \
  --key-id dev-local \
  --private-key-file build/dev-keys/dev-local-private.der \
  --public-key-file build/dev-keys/dev-local-public.der \
  --trusted-keys-file build/dev-keys/trusted-app-keys.properties \
  --overwrite
```

Keep development keys out of public reports and production release artifacts. Do not paste private
key bytes into issue templates, docs, support tickets, or command logs.

## Sign, verify, and pack

```bash
"$CRYPTA_APP" sign \
  --bundle-dir build/dev-apps/hello-stable \
  --key-id dev-local \
  --private-key-file build/dev-keys/dev-local-private.der

"$CRYPTA_APP" verify \
  --bundle-dir build/dev-apps/hello-stable \
  --trusted-keys-file build/dev-keys/trusted-app-keys.properties

"$CRYPTA_APP" pack \
  --bundle-dir build/dev-apps/hello-stable \
  --output build/artifacts/org.example.hello.zip \
  --overwrite
```

These commands produce local development evidence. They are not production signing approval.

## Create and verify a submission

```bash
"$CRYPTA_APP" submission create \
  --bundle-dir build/dev-apps/hello-stable \
  --output build/artifacts/org.example.hello-submission.zip \
  --submission-type new_app \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/org.example.hello" \
  --permission-rationale build/dev-apps/hello-stable/review/permission-rationale.md \
  --sandbox-rationale build/dev-apps/hello-stable/review/sandbox-rationale.md \
  --data-schema build/dev-apps/hello-stable/review/data-schema.md \
  --backup-restore build/dev-apps/hello-stable/review/backup-restore.md \
  --security-notes build/dev-apps/hello-stable/review/security-notes.md \
  --changelog build/dev-apps/hello-stable/review/changelog.md \
  --non-production \
  --overwrite

"$CRYPTA_APP" submission verify \
  --submission build/artifacts/org.example.hello-submission.zip \
  --json > build/artifacts/org.example.hello-submission-verify.json

"$CRYPTA_APP" submission pre-review \
  --submission build/artifacts/org.example.hello-submission.zip \
  --contract build/artifacts/platform-api-contract.json \
  --output build/artifacts/org.example.hello-pre-review.json \
  --overwrite
```

`submission verify --json` writes JSON to stdout. Redirect it if you want a file.

## Submit for public beta intake

Attach the submission package and redacted pre-review summary through the public beta process
defined in [app-submission-walkthrough.md](app-submission-walkthrough.md) and
[../app-platform-beta-program.md](../app-platform-beta-program.md). Reviewers import submissions
with the `crypta-app submission intake` commands; developer-created packages are review inputs, not
install approvals.

Beta catalog candidate staging happens after reviewer decision and receipt checks. It is not
automatic stable promotion.

Use [support-and-feedback.md](support-and-feedback.md) for developer beta feedback, Platform API
compatibility reports, app review appeals, support bundle digest fields, known issue ids, and safe
release feedback routing.

## Redaction rules

Do not include private insert URIs, private keys, reviewer private keys, app tokens, browser
session tokens, form passwords, cookies, authorization headers, raw app data, raw user documents,
raw support bundles, raw FProxy HTML, or local absolute paths in submissions, review notes, logs,
issue templates, or release evidence.

The public beta feedback loop is in [support-and-feedback.md](support-and-feedback.md). Developer
feedback should include release id, Cryptad build, Platform API contract version, app id/version,
support bundle digest when relevant, diagnostic summary id when relevant, expected behavior, actual
behavior, and redacted evidence only.
