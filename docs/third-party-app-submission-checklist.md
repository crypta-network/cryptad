# Third-party app submission checklist

Use this checklist before creating an app submission package and again before resubmitting after a
review decision. Keep the headings stable so release certification can detect the core sections.

## Manifest validation

- [ ] `cryptad-app.properties` parses with `crypta-app validate --bundle-dir . --strict`.
- [ ] `app.id`, `app.name`, `app.version`, `app.exec`, `app.ui.mode`, and `app.ui.entry` match the
      submitted bundle.
- [ ] `api.minimumVersion` and `api.maximumTestedVersion` are present and match the tested
      Platform API contract range.

## API stability target

- [ ] Stable-only apps declare `api.targetStability=stable`.
- [ ] Stable-only apps declare `api.experimentalCapabilitiesAccepted=false`.
- [ ] Experimental apps declare `api.targetStability=experimental` and
      `api.experimentalCapabilitiesAccepted=true`.
- [ ] Internal and operator-only capabilities are not requested.

## No internal/operator-only permissions

- [ ] Manifest permissions are all app-facing stable or app-facing experimental capabilities.
- [ ] The app does not request `vault.identities.manage` or any other host/operator-only surface.
- [ ] `crypta-app compat verify --bundle-dir . --strict` has no blocker findings.

## Permission rationale

- [ ] Every requested capability has a short reason in `review/permission-rationale.md`.
- [ ] The rationale explains user benefit and the smallest capability set that works.
- [ ] The rationale does not include private keys, private URIs, raw fetched content, raw app data,
      tokens, authorization headers, or local absolute paths.

## UI lint

- [ ] `crypta-app ui lint --bundle-dir . --strict` passes or every warning is explained.
- [ ] Static UI uses the documented browser SDK bootstrap path.
- [ ] Permission disclosure is visible with `data-crypta-permission-summary` when permissions are
      declared.
- [ ] App-owned UI uses documented design-system classes or a documented allowed pattern.

## CSP and remote script policy

- [ ] Static UI loads local scripts and styles only.
- [ ] No remote JavaScript, third-party fonts, tracking pixels, or silent image fetches are used.
- [ ] Any future remote content need is documented for reviewer discussion before submission.

## Sandbox declaration

- [ ] `sandbox.mode` and `sandbox.required` are declared.
- [ ] `review/sandbox-rationale.md` explains the sandbox provider requirement or why the fixture
      has no background runtime behavior.
- [ ] The app does not depend on unsupported host filesystem or localhost RPC access.

## App-data schema declaration

- [ ] Durable app-data use is declared in `review/data-schema.md`.
- [ ] Namespaces, record shapes, and maximum expected sizes are summarized.
- [ ] Apps with no durable data state that no app-data schema exists.

## Data migration declaration

- [ ] Upgrade behavior is documented for any stored app data.
- [ ] Breaking schema changes list a migration path or explain why the beta data can be discarded.
- [ ] Migration notes avoid raw user records and local paths.

## Legacy plugin migration plan

- [ ] Former plugin behavior is documented with
      [templates/plugin-migration-plan.md](templates/plugin-migration-plan.md).
- [ ] The plan lists `legacyPluginId`, `newAppId`, state classes, manifest capabilities,
      app-data namespaces, content subscriptions, identity grants, app-service dependencies,
      migration steps, backup/restore policy, review evidence, redaction policy, and known
      non-goals.
- [ ] WebOfTrust-like, Freetalk/Sone-like, Freemail-like, content publishing, queue/helper,
      identity/profile, diagnostics/support, and app-service patterns follow
      [legacy-plugin-migration-cookbook.md](legacy-plugin-migration-cookbook.md) when applicable.
- [ ] The submission does not claim old plugin ABI/FCP compatibility, WebOfTrust/Freetalk/Sone/
      Freemail protocol compatibility, daemon-private hooks, ambient localhost RPC, raw FProxy
      scraping, private-key export, or unbounded crawling.

## Backup/restore declaration

- [ ] `review/backup-restore.md` states whether app data participates in backup/restore.
- [ ] Restore prerequisites and unsupported cases are listed.
- [ ] Apps with no durable data state that backup/restore is not required.

## Service dependency/grant declaration

- [ ] App-service dependencies and grant bundles are listed when used.
- [ ] Required service capabilities are separate from app manifest permissions.
- [ ] Apps with no service dependencies state that no grants are required.
- [ ] Migrated apps that consume `trust.score` or another service describe provider id, service
      id, scopes, contexts, dependency kind, degrade behavior, grant bundle, and revalidation
      behavior. See [legacy-plugin-migration-cookbook.md](legacy-plugin-migration-cookbook.md).

## Security notes

- [ ] `review/security-notes.md` describes data handling, sensitive boundaries, and network use.
- [ ] The app does not log browser session tokens, bearer tokens, private keys, private insert
      URIs, raw fetched content, raw app data, or authorization headers.
- [ ] Known security limitations are listed honestly.

## Support/maintainer metadata

- [ ] Submission package includes maintainer name, maintainer contact, and source URL.
- [ ] Contact and source metadata are public-safe.
- [ ] Support level and maintenance expectations are described for beta users.

## Redaction and privacy review

- [ ] Issue text, review notes, JSON reports, catalog candidates, and summaries are redacted.
- [ ] Digests, counts, capability names, app ids, and synthetic fixture URIs replace raw bodies.
- [ ] No local absolute paths are included in generated artifacts or issue reports.

## Submission package generation

- [ ] Generated ZIPs, submissions, JSON reports, and receipts are written outside the bundle root.
- [ ] `crypta-app pack --bundle-dir . --output ../artifacts/<app>.zip --overwrite` completes.
- [ ] `crypta-app submission create --bundle-dir . --output ../artifacts/<app>-submission.zip ...`
      completes with all applicable rationale files.
- [ ] Non-production beta fixtures use `--non-production`.

## Pre-review output

- [ ] `crypta-app submission verify --submission ../artifacts/<app>-submission.zip --json` passes.
- [ ] `crypta-app submission pre-review --submission ../artifacts/<app>-submission.zip --output
      ../artifacts/<app>-pre-review.json` passes or returns an understood warning/failure.
- [ ] Pre-review digests match the submission package and bundle digests.

## Public beta intake

- [ ] Reviewers can run `crypta-app submission intake import --queue-dir <queue>
      --submission ../artifacts/<app>-submission.zip`.
- [ ] Reviewer assignment uses `crypta-app submission intake assign` with a trusted reviewer key id
      and an assignment reason file.
- [ ] Queue pre-review uses `crypta-app submission intake pre-review` and writes
      `pre-review.json`, `submission-verification.json`, API compatibility, UI lint,
      redaction-scan, and artifact-manifest outputs.
- [ ] Reviewers record `reviewed`, `caution`, `rejected`, or `resubmission_requested` with
      `crypta-app submission intake decide`.
- [ ] Reviewed submissions can run `crypta-app submission intake stage-candidate`; caution
      submissions require explicit allowance and operator-visible warnings.
- [ ] Rejected submissions cannot stage catalog candidates or install from the beta catalog.
- [ ] Public evidence includes `third-party-intake.queue-schema` through
      `third-party-intake.redaction` and is marked non-production when fixture/test material is
      used.

## Resubmission requirements

- [ ] Rejected or cautionary findings are addressed in the app bundle and review notes.
- [ ] Resubmissions use `--submission-type resubmission` and `--resubmission-of <previous-id>`.
- [ ] The changelog explains the delta from the previous submission without pasting sensitive raw
      artifacts.
