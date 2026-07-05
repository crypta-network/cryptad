# Plugin author submission flow

This example connects a migration design to the third-party public beta intake flow.

## Author steps

```bash
crypta-app init \
  --template hello-stable \
  --id app-id.example \
  --name "Example Migrated App" \
  --version 0.1.0 \
  --dir build/plugin-migration/app-id.example

crypta-app test --bundle-dir build/plugin-migration/app-id.example --strict --json build/plugin-migration/artifacts/app-test.json
crypta-app ui lint --bundle-dir build/plugin-migration/app-id.example --strict --json build/plugin-migration/artifacts/ui-lint.json
crypta-app api snapshot --output build/plugin-migration/artifacts/platform-api-contract.json
crypta-app compat verify \
  --bundle-dir build/plugin-migration/app-id.example \
  --contract build/plugin-migration/artifacts/platform-api-contract.json \
  --target-stability stable \
  --strict \
  --json build/plugin-migration/artifacts/api-compatibility.json
crypta-app pack \
  --bundle-dir build/plugin-migration/app-id.example \
  --output build/plugin-migration/artifacts/app-id.example.zip \
  --overwrite
crypta-app submission create \
  --bundle-dir build/plugin-migration/app-id.example \
  --output build/plugin-migration/artifacts/app-id.example-submission.zip \
  --submission-type new_app \
  --maintainer-name "Example Maintainer" \
  --maintainer-contact "mailto:maintainer@example.invalid" \
  --source-url "https://example.invalid/app-id.example" \
  --permission-rationale build/plugin-migration/app-id.example/review/permission-rationale.md \
  --sandbox-rationale build/plugin-migration/app-id.example/review/sandbox-rationale.md \
  --data-schema build/plugin-migration/app-id.example/review/data-schema.md \
  --backup-restore build/plugin-migration/app-id.example/review/backup-restore.md \
  --security-notes build/plugin-migration/app-id.example/review/security-notes.md \
  --changelog build/plugin-migration/app-id.example/review/changelog.md \
  --non-production \
  --overwrite
crypta-app submission verify --submission build/plugin-migration/artifacts/app-id.example-submission.zip --json
crypta-app submission pre-review \
  --submission build/plugin-migration/artifacts/app-id.example-submission.zip \
  --contract build/plugin-migration/artifacts/platform-api-contract.json \
  --output build/plugin-migration/artifacts/app-id.example-pre-review.json \
  --overwrite
```

## Review evidence

Former plugin authors should attach the migration plan, manifest capability rationale, app-data
schema, backup/restore notes, app-service dependency rationale, content format notes, and redaction
scan result. Reviewers use the normal decision states: `reviewed`, `caution`, `rejected`, and
`resubmission_requested`.

Reviewed or allowed-caution submissions can stage a catalog candidate. Rejected submissions cannot
stage catalog candidates or install from the beta catalog.
