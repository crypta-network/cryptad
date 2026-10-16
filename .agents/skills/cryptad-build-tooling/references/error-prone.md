# Error Prone reference

Read for Error Prone. Commands and unlinked source paths are relative to the repository root.

## Error Prone
### Key behaviors
- Enabled via `net.ltgt.errorprone` in the shared convention plugin.
- Errors are downgraded to warnings by default (`options.errorprone.allErrorsAsWarnings = true`).

### Report task
- Generate XML reports:
  - `./gradlew errorproneReport`
- Output:
  - Root: `build/reports/errorprone/<task>/<task>.xml` (for example, `compileJava/compileJava.xml`).
  - Leaf: `<module>/build/reports/errorprone/<module>_<task>/<task>.xml` (for example,
    `platform-api/build/reports/errorprone/platform-api_compileJava/compileJava.xml`). Nested
    module separators become underscores in the report directory label.

### Final evidence mode
- `-Pphase12Evidence=true` records actual task outcomes and selected inputs privately and forces the
  required analyzer/test cohort to execute freshly. Ordinary builds keep normal reuse.
- A successful compile/report task is not analyzer-clean evidence: inspect warnings, analyzer
  completion/source coverage and the private task observation. Missing or incomplete reports remain
  unavailable, and cache/up-to-date outcomes remain reuse.
- The private completion observation binds the exact report roster and bytes. Post-edited/copied
  reports cannot inherit an execution clock. Acceptance also requires the reviewed analyzer
  configuration; suppression flags, extra arguments/providers and partial class/filter inputs are
  not full-analysis evidence.

Report generation raises javac's warning/error diagnostic caps to a bounded 10,000, records
`diagnosticsComplete`, and rejects truncated/capped captures for acceptance. The separate 16 MiB
capture bound remains enforced. Emitted warning counts from a truncated historical report do not
prove the complete finding roster.

### Report schema (custom)
- Root element: `<errorproneReport>`
- Per warning: `<diagnostic>` with attributes `severity`, `check`, `file`, `line`, plus `<message>` and optional `<details>`.

### Enforcing errors
- To fail the build on Error Prone errors, set `allErrorsAsWarnings` to `false` in:
  - the shared convention plugin under `build-logic/src/main/`

### Verification refresh on Error Prone bumps
If strict verification blocks resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:classes
```
3) Restore `org.gradle.dependency.verification=strict`
4) Optionally `./gradlew --export-keys`
