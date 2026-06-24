# Hello Stable third-party sample

Hello Stable is a deterministic non-production sample for the third-party developer beta program.
It is not a first-party catalog app and must not be promoted into the first-party stable catalog.

The sample demonstrates a stable-only Platform API app:

- `api.targetStability=stable`
- `api.experimentalCapabilitiesAccepted=false`
- `app.permissions=platform.contract.read`
- no internal or operator-only permissions
- static UI that uses the documented browser SDK and design-system assets

## Local checks

Run the same commands an external developer would run before submission:

```bash
crypta-app test --bundle-dir samples/third-party/hello-stable-app --strict
crypta-app ui lint --bundle-dir samples/third-party/hello-stable-app --strict
crypta-app api snapshot --output build/hello-stable-platform-api.json
crypta-app compat verify \
  --bundle-dir samples/third-party/hello-stable-app \
  --contract build/hello-stable-platform-api.json \
  --strict
crypta-app pack \
  --bundle-dir samples/third-party/hello-stable-app \
  --output build/org.example.hello.zip \
  --overwrite
crypta-app submission create \
  --bundle-dir samples/third-party/hello-stable-app \
  --output build/org.example.hello-submission.zip \
  --submission-type new_app \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/org.example.hello" \
  --permission-rationale samples/third-party/hello-stable-app/review/permission-rationale.md \
  --sandbox-rationale samples/third-party/hello-stable-app/review/sandbox-rationale.md \
  --data-schema samples/third-party/hello-stable-app/review/data-schema.md \
  --backup-restore samples/third-party/hello-stable-app/review/backup-restore.md \
  --security-notes samples/third-party/hello-stable-app/review/security-notes.md \
  --changelog samples/third-party/hello-stable-app/review/changelog.md \
  --non-production \
  --overwrite
crypta-app submission verify --submission build/org.example.hello-submission.zip --json
crypta-app submission pre-review \
  --submission build/org.example.hello-submission.zip \
  --contract build/hello-stable-platform-api.json \
  --output build/org.example.hello-pre-review.json \
  --overwrite
```

Reviewer decision and catalog-candidate commands use deterministic non-production reviewer keys in
tests only. Do not use production signing or reviewer material with this sample.

See `docs/third-party-developer-beta-program.md`,
`docs/third-party-app-submission-checklist.md`, and
`docs/platform-api-compatibility-support-window.md` before adapting this sample into a real app.
