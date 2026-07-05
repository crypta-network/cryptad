# App platform beta tutorials

Use these offline-first tutorials to create, test, sign, pack, catalog, and review a beta app
without reading Cryptad internals.

For role-based public-beta onboarding before running these tutorials, start with
[public-beta/README.md](public-beta/README.md) and
[public-beta/developer-quickstart.md](public-beta/developer-quickstart.md).

## Prerequisites

Run from the repository root with Java 25 or newer. The flows use the Gradle wrapper and the
installed `crypta-app` launcher:

```bash
./gradlew :platform-devtools:installDist
export CRYPTA_APP="$PWD/platform-devtools/build/install/crypta-app/bin/crypta-app"
"$CRYPTA_APP" --help
```

Keep local development keys outside the repository. The examples below use `$HOME/.crypta-dev/keys`
and URI-safe placeholder Crypta URIs such as `crypta:CHK@...` and
`crypta:USK@.../cryptad-app-catalog.properties`. They are placeholders, not usable public network
keys.

## Tutorial 1: static app from template

Create a minimal static app bundle:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/hello-crypta \
  --template static-basic \
  --app-id hello-crypta \
  --name "Hello Crypta" \
  --version 0.1.0
```

Run the local development server:

```bash
"$CRYPTA_APP" dev --bundle-dir build/dev-apps/hello-crypta
```

`crypta-app dev` binds to `127.0.0.1` by default and uses mock Platform API fixtures. It does not
talk to the public Crypta network, install the app into AppHost, fetch signed catalogs, or prove
live-node permission grants. Use `--fixture-dir` for custom mock JSON fixtures and
`--allow-non-loopback` only for deliberate local-network testing.

In another terminal, run the offline test suite:

```bash
"$CRYPTA_APP" test \
  --bundle-dir build/dev-apps/hello-crypta \
  --strict \
  --json build/dev-apps/hello-crypta-test.json
```

The JSON report uses deterministic, path-redacted output suitable for beta submissions and release
evidence.

## Tutorial 2: queue dashboard or publisher template

Create a queue-dashboard app with the template's default queue capabilities:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/queue-dashboard \
  --template queue-dashboard \
  --app-id queue-dashboard \
  --name "Queue Dashboard" \
  --version 0.1.0
```

The `queue-dashboard` template declares `queue.read` and `queue.write`. Add any extra capability
deliberately with repeated `--permission <capability>` options and update the visible permission
rationale before signing.

Create a publisher app instead when you want a content-insert example:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/local-publisher \
  --template publisher \
  --app-id local-publisher \
  --name "Local Publisher" \
  --version 0.1.0
```

The `publisher` template declares `content.insert`, `queue.read`, and `queue.write`.

Run strict offline checks:

```bash
"$CRYPTA_APP" test \
  --bundle-dir build/dev-apps/queue-dashboard \
  --strict \
  --json build/dev-apps/queue-dashboard-test.json
```

`crypta-app test` runs the app developer checks without network access. It covers staged bundle
validation, manifest and Platform API compatibility checks, static asset safety, UI lint for static
bundles, API compatibility output, and a dev-server smoke check when the bundle can be served by the
mock loopback server.

## Tutorial 3: sign, pack, catalog, and offline USK publication plan

Generate separate local development keys for bundle and catalog signing:

```bash
mkdir -p "$HOME/.crypta-dev/keys"

"$CRYPTA_APP" keys generate \
  --key-id dev-local-bundle \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-public.der" \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties" \
  --overwrite

"$CRYPTA_APP" keys generate \
  --key-id dev-local-catalog \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der" \
  --overwrite
```

Sign and verify the staged bundle:

```bash
"$CRYPTA_APP" sign \
  --bundle-dir build/dev-apps/queue-dashboard \
  --key-id dev-local-bundle \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-bundle-private.der"

"$CRYPTA_APP" verify \
  --bundle-dir build/dev-apps/queue-dashboard \
  --trusted-keys-file "$HOME/.crypta-dev/keys/trusted-app-keys.properties"
```

Pack the signed staged bundle:

```bash
mkdir -p dist/apps dist/catalog

"$CRYPTA_APP" pack \
  --bundle-dir build/dev-apps/queue-dashboard \
  --output dist/apps/queue-dashboard-0.1.0.zip \
  --overwrite
```

Create a catalog entry descriptor. The `crypta:CHK@...` value is a placeholder for the public
immutable artifact URI returned by a reviewed insertion workflow:

```bash
"$CRYPTA_APP" catalog entry \
  --bundle-dir build/dev-apps/queue-dashboard \
  --artifact dist/apps/queue-dashboard-0.1.0.zip \
  --bundle-uri "crypta:CHK@..." \
  --output dist/catalog/queue-dashboard-entry.properties \
  --summary "Inspect and manage local transfer queue state." \
  --homepage "https://example.invalid/apps/queue-dashboard" \
  --source "https://example.invalid/src/queue-dashboard" \
  --license "MIT" \
  --category productivity \
  --channel beta \
  --support-status experimental \
  --deprecation-status none \
  --minimum-crypta-version 1481 \
  --permission-rationale "queue.read=Reads local queue state." \
  --permission-rationale "queue.write=Cancels or reprioritizes selected queue entries." \
  --strict \
  --overwrite
```

Create, sign, and verify the catalog:

```bash
"$CRYPTA_APP" catalog create \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-id dev-queue-dashboard \
  --name "Development Queue Dashboard Catalog" \
  --entry dist/catalog/queue-dashboard-entry.properties \
  --overwrite

"$CRYPTA_APP" catalog sign \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --key-id dev-local-catalog \
  --private-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-private.der"

"$CRYPTA_APP" catalog verify \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --trusted-key-id dev-local-catalog \
  --trusted-public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der"
```

Create a third-party submission package when the app should enter the review workflow before
catalog promotion:

```bash
mkdir -p review dist/submissions

"$CRYPTA_APP" submission create \
  --bundle-dir build/dev-apps/queue-dashboard \
  --output dist/submissions/queue-dashboard-submission.zip \
  --submission-type new_app \
  --permission-rationale review/permission-rationale.md \
  --security-notes review/security-notes.md \
  --changelog review/changelog.md \
  --maintainer-name "Development Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/src/queue-dashboard" \
  --non-production \
  --overwrite
```

The submission workflow packages the staged bundle, rationale files, safe maintainer/source
metadata, and deterministic digests for offline pre-review. See
[app-store-submission-and-review-workflow.md](app-store-submission-and-review-workflow.md) for
reviewer decisions, caution/rejection handling, and catalog-candidate promotion rules.

For the third-party developer beta happy path, start from the stable-only template and checklist:

```bash
"$CRYPTA_APP" init \
  --dir build/dev-apps/hello-stable \
  --template hello-stable \
  --id org.example.hello \
  --name "Hello Stable" \
  --version 0.1.0

"$CRYPTA_APP" test --bundle-dir build/dev-apps/hello-stable --strict
"$CRYPTA_APP" ui lint --bundle-dir build/dev-apps/hello-stable --strict
"$CRYPTA_APP" api snapshot --output build/platform-api-contract.json
"$CRYPTA_APP" compat verify \
  --bundle-dir build/dev-apps/hello-stable \
  --contract build/platform-api-contract.json \
  --strict
"$CRYPTA_APP" submission create \
  --bundle-dir build/dev-apps/hello-stable \
  --output dist/submissions/hello-stable-submission.zip \
  --submission-type new_app \
  --permission-rationale build/dev-apps/hello-stable/review/permission-rationale.md \
  --sandbox-rationale build/dev-apps/hello-stable/review/sandbox-rationale.md \
  --data-schema build/dev-apps/hello-stable/review/data-schema.md \
  --backup-restore build/dev-apps/hello-stable/review/backup-restore.md \
  --security-notes build/dev-apps/hello-stable/review/security-notes.md \
  --changelog build/dev-apps/hello-stable/review/changelog.md \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/org.example.hello" \
  --non-production \
  --transparency-log dist/submissions/review-transparency.jsonl \
  --overwrite
"$CRYPTA_APP" submission verify --submission dist/submissions/hello-stable-submission.zip --json
"$CRYPTA_APP" submission pre-review \
  --submission dist/submissions/hello-stable-submission.zip \
  --contract build/platform-api-contract.json \
  --output dist/submissions/hello-stable-pre-review.json \
  --transparency-log dist/submissions/review-transparency.jsonl \
  --overwrite
# Create local test-only reviewer material for this tutorial receipt.
mkdir -p "$HOME/.crypta-dev/keys"
"$CRYPTA_APP" keys generate \
  --key-id dev-reviewer \
  --private-key-file "$HOME/.crypta-dev/keys/dev-reviewer-private.der" \
  --public-key-file "$HOME/.crypta-dev/keys/dev-reviewer-public.der" \
  --overwrite
python3 - <<'PY'
import base64
from pathlib import Path

key_dir = Path.home() / ".crypta-dev" / "keys"
public_key = base64.b64encode((key_dir / "dev-reviewer-public.der").read_bytes()).decode("ascii")
(key_dir / "trusted-reviewer-keys.properties").write_text(
    "\n".join(
        (
            "trusted.reviewers.version=1",
            "reviewer.1.id=dev-reviewer",
            "reviewer.1.algorithm=Ed25519",
            f"reviewer.1.public.key.base64={public_key}",
            "reviewer.1.display.name=Development Reviewer",
            "reviewer.1.policy.id=crypta-app-review-v1",
            "",
        )
    ),
    encoding="utf-8",
)
PY
"$CRYPTA_APP" submission decide \
  --submission dist/submissions/hello-stable-submission.zip \
  --pre-review dist/submissions/hello-stable-pre-review.json \
  --decision reviewed \
  --reviewer-key-id dev-reviewer \
  --reviewer-private-key "$HOME/.crypta-dev/keys/dev-reviewer-private.der" \
  --trusted-reviewer-keys "$HOME/.crypta-dev/keys/trusted-reviewer-keys.properties" \
  --reason build/dev-apps/hello-stable/review/decision-reason.md \
  --receipt-output dist/submissions/hello-stable-review-receipt.properties \
  --transparency-log dist/submissions/review-transparency.jsonl \
  --allow-non-production \
  --overwrite
"$CRYPTA_APP" review transparency verify --log-file dist/submissions/review-transparency.jsonl
"$CRYPTA_APP" submission catalog-candidate \
  --submission dist/submissions/hello-stable-submission.zip \
  --review-receipt dist/submissions/hello-stable-review-receipt.properties \
  --trusted-reviewer-keys "$HOME/.crypta-dev/keys/trusted-reviewer-keys.properties" \
  --bundle-uri "crypta:CHK@<artifact-key>/hello-stable-0.1.0.zip" \
  --output dist/catalog/hello-stable-candidate.properties \
  --summary "Non-production Hello Stable beta candidate." \
  --transparency-log dist/submissions/review-transparency.jsonl \
  --overwrite
```

The `hello-stable` template declares `api.targetStability=stable`,
`api.experimentalCapabilitiesAccepted=false`, and `platform.contract.read`. The review decision
states are `reviewed`, `caution`, `rejected`, and `resubmission` / `resubmitted`; non-production
fixtures use `--allow-non-production` and deterministic reviewer material only in tests. File
feedback with `docs/third-party-app-submission-checklist.md` and
`docs/third-party-developer-beta-program.md`; release evidence records
`third-party-developer.sample-app-flow` and redaction checks without raw app data, private insert
URIs, browser session tokens, private keys, or local absolute paths.

Stable app authors can inspect the active support-window policy and compare contract snapshots
offline before submitting:

```bash
"$CRYPTA_APP" api policy --contract dist/platform-api-contract.json
"$CRYPTA_APP" api diff \
  --previous docs/platform-api/contracts/previous-production-beta-contract.json \
  --current dist/platform-api-contract.json \
  --output dist/platform-api-stable-diff.json
```

Release evidence records `platform-api.compatibility-window`,
`platform-api.previous-contract-snapshot`, `platform-api.deprecation-window-policy`, and
`platform-api.experimental-graduation-policy`. The policy keeps stable apps on Platform API 1.0
unless a future reviewed baseline is introduced with stable reference updates.

Write an offline Crypta USK publication plan:

```bash
"$CRYPTA_APP" publish-usk \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../cryptad-app-catalog.properties" \
  --output dist/catalog/publish-plan.md \
  --dry-run
```

`crypta-app publish-usk --dry-run` writes a plan. It does not insert catalog bytes, signature
bytes, or app ZIP artifacts into the public Crypta network. Live insertion remains a separate
reviewed release/operator workflow that uses the existing content and queue mechanisms:

```bash
"$CRYPTA_APP" publish-usk --live \
  --catalog-file dist/catalog/cryptad-app-catalog.properties \
  --catalog-signature-file dist/catalog/cryptad-app-catalog.signature \
  --catalog-source "crypta:USK@.../cryptad-app-catalog.properties" \
  --private-insert-uri-env CRYPTAD_FIRST_PARTY_CATALOG_INSERT_URI \
  --node-base-url http://127.0.0.1:8888/api/v1 \
  --form-password-env CRYPTAD_CERT_FORM_PASSWORD \
  --trusted-key-id dev-local-catalog \
  --trusted-public-key-file "$HOME/.crypta-dev/keys/dev-local-catalog-public.der" \
  --output dist/catalog/live-publication-summary.json
```

The live command verifies the signed catalog locally before insertion. It publishes
`cryptad-app-catalog.signature` as the sibling sidecar at the same USK edition as
`cryptad-app-catalog.properties`, and its output is sanitized for release evidence. Keep the
private insert URI, form password, and private signing keys out of shell history, logs, and
uploaded artifacts.

## Tutorial 4: reference app map

The first-party apps are reference points for the beta. Their current manifests declare these key
capabilities:

| App | Demonstrates | Key capabilities |
| --- | --- | --- |
| Queue Manager | Queue read/write and operator queue flow. | `queue.read`, `queue.write` |
| Publisher | Content insert workflow. | `content.insert`, `queue.read`, `queue.write` |
| Site Publisher | Static site publishing pattern. | `content.insert`, `queue.read`, `queue.write` |
| Profile Publisher | AppVault identity, bounded profile document signing, durable draft state, and app-generated document insert. | `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `content.insert.app-document`, `app.data.read`, `app.data.write`, `queue.read`, `queue.write` |
| Social Inbox RC | Social/mail-like threaded inbox reference app with bounded `crypta.social.message.v1` signing, generated outbox inserts, durable USK sources, local channel/search filters, read state, safe author profile links, and operator-approved Trust Graph score annotations. | `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `content.fetch`, `content.subscribe`, `content.insert.app-document`, `app.data.read`, `app.data.write`, `app.services.read`, `app.services.call`, `queue.read`, `queue.write` |
| Feed Reader & Publisher | Durable USK subscription metadata, durable reader state, bounded content fetch, and feed snapshot publish. | `content.fetch`, `content.subscribe`, `content.insert.app-document`, `app.data.read`, `app.data.write`, `queue.read`, `queue.write` |
| Trust Graph Local RC | Durable local trust graph backend, import preview, URI import with stale-preview protection, local anchor lifecycle, bounded score explanations, redacted audit, content subscription management, score, sign, and publish preview. | `trust.read`, `trust.write`, `content.fetch`, `content.subscribe`, `content.insert.app-document`, `vault.identities.read`, `vault.identities.create`, `vault.identities.use`, `app.data.read`, `app.data.write`, `queue.read`, `queue.write` |

Release evidence for the Feed Reader path includes `network-content.subscription-scheduler`,
which proves deterministic scheduler ticks, conservative limits, dedupe, backoff, and redacted
metadata.
Release evidence for the app-service grant path includes `app-services.registry`,
`app-services.grants`, `app-services.trust-score-provider`,
`reference-app.social-inbox-service-grant`, `app-services.web-shell`, and
`app-services.redaction`.

Use the detailed docs before copying a reference pattern:

- [feed-reader-reference-app.md](feed-reader-reference-app.md)
- [social-inbox-reference-app.md](social-inbox-reference-app.md)
- [trust-graph-preview.md](trust-graph-preview.md)
- [app-data-store.md](app-data-store.md)
- [app-secret-and-identity-vault.md](app-secret-and-identity-vault.md)
- [platform-api-contract.md](platform-api-contract.md)

## Tutorial 5: Web Shell onboarding path

The first-party beta catalog appears in Web Shell as a recommended catalog when the runtime or
package configuration provides the catalog source and trusted key hint. Recommended catalog means
"available for explicit operator onboarding." It is not automatic app installation.

The high-level operator flow is:

1. Open the Web Shell Apps area.
2. Inspect the recommended first-party beta catalog entry.
3. Confirm the catalog source and trusted catalog key configuration.
4. Add the catalog recommendation.
5. Refresh the signed catalog source.
6. Inspect each app entry, permissions, review trust, API compatibility, and version delta.
7. Install or update individual apps explicitly.

These checks still apply:

- The catalog source signature and trusted catalog key must verify.
- Signed bundle verification and artifact SHA-256 checks remain separate from catalog trust.
- App review trust and reviewer governance still apply; a review receipt is independent evidence.
- Reviewer trust follows the reviewer key lifecycle and local transparency log records described in
  the governance docs; a catalog listing does not make an unknown reviewer locally trusted.
- Platform API compatibility and permission-delta gates still apply.
- The background update scheduler policy governs check, stage, and apply behavior.
- Manual policy detects candidates but does not stage or apply updates automatically.
- Production catalog channels default to stable browsing and stable-only automation; beta, nightly,
  and deprecated entries require explicit operator selection and deprecated entries are not ordinary
  automatic update candidates.
- Rollback is a bounded safety mechanism after an update is staged or applied; it is not a promise
  that every app state can be restored.
- The ecosystem certification matrix records this docs/tutorial evidence for release managers.
- FProxy browse remains retained; Web Shell catalog onboarding does not remove legacy browse routes.

See [first-party-beta-catalog.md](first-party-beta-catalog.md),
[production-first-party-catalog-channels.md](production-first-party-catalog-channels.md),
[app-catalogs.md](app-catalogs.md), [app-review-governance.md](app-review-governance.md), and
[app-update-lifecycle.md](app-update-lifecycle.md).
