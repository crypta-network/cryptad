---
name: cryptad-build-tooling
description: "Maintain formatting and code-quality tooling: Spotless, Gradle dependency verification (verification-metadata), SonarLint, JaCoCo coverage, and SonarCloud uploads."
compatibility: opencode
metadata:
  area: tooling
  domain: cryptad
---

## When to use
Use this skill when you:
- Fix formatting or Spotless failures.
- Update dependencies and need to refresh Gradle dependency verification metadata.
- Run or adjust SonarLint / SonarCloud / JaCoCo coverage tasks.
- Need to analyze a single file with SonarLint.

## Spotless + dependency verification (common failure mode)
When Gradle dependency verification is strict, Spotless may fail to resolve formatter artifacts even with `mavenCentral()`.

### Procedure to refresh verification metadata for Spotless
1) Temporarily set verification to lenient:
- Edit `gradle.properties` → `org.gradle.dependency.verification=lenient`

2) Write verification entries (SHA256 + PGP):
```bash
./gradlew --write-verification-metadata sha256,pgp spotlessApply
```

Optional: force refresh to capture the exact formatter version:
```bash
./gradlew --refresh-dependencies --write-verification-metadata sha256,pgp spotlessApply
```

Faster alternative (no formatting run):
```bash
./gradlew --write-verification-metadata sha256,pgp spotlessInternalRegisterDependencies
```

3) Confirm entries in `gradle/verification-metadata.xml`
- Look for components under `com.google.googlejavaformat` and trusted keys for that group.

4) Restore strict mode:
- Edit `gradle.properties` → `org.gradle.dependency.verification=strict`

5) Validate:
```bash
./gradlew spotlessApply
```

Optional but recommended:
```bash
./gradlew --export-keys
```

Notes:
- Keep Spotless config at the intended formatter version (currently `googleJavaFormat("1.28.0")`).
- Commit updated `gradle/verification-keyring.gpg` and `gradle/verification-keyring.keys` so new environments verify without re-fetching keys.

## SonarLint (Gradle) usage
### Key behaviors
- SonarLint does **not** run during regular lifecycles (`build`, `check`).
- `sonarlintMain` / `sonarlintTest` run only when explicitly requested (task name contains `sonarlint`).
- Default config: `ignoreFailures = true` (non-failing by default).

### Tasks
- Full main sources:
  - `./gradlew sonarlintMain`
- Test sources:
  - `./gradlew sonarlintTest`
- Single file analysis:
  - `./gradlew --quiet sonarlintFile -Psonarlint.file=src/main/java/SevenZip/LzmaAlone.java`
  - Aliases: `-Pfile=...`, `-Psonarlint.sources=...`
  - Report: `build/reports/sonarLint/sonarlintFile/sonarlintFile.xml`

### Verification refresh on SonarLint bumps
If strict verification blocks resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:compileKotlin
```
3) Restore `org.gradle.dependency.verification=strict`
4) Optionally `./gradlew --export-keys`

### Memory note
Gradle daemon heap was increased to reduce OOM during SonarLint indexing:
- `gradle.properties`: `org.gradle.jvmargs=-Xmx8g -XX:MaxMetaspaceSize=2g -Dfile.encoding=UTF-8`

## Error Prone
### Key behaviors
- Enabled via `net.ltgt.errorprone` in the Java/Kotlin convention plugin.
- Errors are downgraded to warnings by default (`options.errorprone.allErrorsAsWarnings = true`).

### Report task
- Generate XML reports:
  - `./gradlew errorproneReport`
- Output:
  - `build/reports/errorprone/<task>/<task>.xml` (e.g., `compileJava/compileJava.xml`, `compileTestJava/compileTestJava.xml`)

### Report schema (custom)
- Root element: `<errorproneReport>`
- Per warning: `<diagnostic>` with attributes `severity`, `check`, `file`, `line`, plus `<message>` and optional `<details>`.

### Enforcing errors
- To fail the build on Error Prone errors, set `allErrorsAsWarnings` to `false` in:
  - `build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts`

### Verification refresh on Error Prone bumps
If strict verification blocks resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:compileKotlin
```
3) Restore `org.gradle.dependency.verification=strict`
4) Optionally `./gradlew --export-keys`

## JaCoCo + SonarCloud coverage
- JaCoCo toolVersion: `0.8.14`
- XML/HTML reports are enabled:
  - XML: `build/reports/jacoco/test/jacocoTestReport.xml`
- `check` depends on:
  - `jacocoTestReport`
  - `jacocoTestCoverageVerification`
- Coverage rule: 80% line coverage (LINE/COVEREDRATIO >= 0.80)
  - Builds do not fail on coverage by default (`isFailOnViolation = false`)

### SonarCloud configuration
- Host: `https://sonarcloud.io`
- Project: `crypta-network_cryptad`
- Org: `crypta-network`
- Coverage is read from the JaCoCo XML path above (`sonar.coverage.jacoco.xmlReportPaths`).
- Upload requires token:
  - Set env `SONAR_TOKEN` (mapped to `sonar.token` by convention; no CLI flag required).

### Typical local runs
- Tests + coverage:
  - `./gradlew test jacocoTestReport`
- Enforced check (non-failing gate):
  - `./gradlew check`
- Upload:
  - `export SONAR_TOKEN=<token>`
  - `./gradlew sonarqube`

### CI minimal step
- `./gradlew test jacocoTestReport sonarqube`

## JUnit 6 + dependency verification
JUnit 6 introduces `org.jspecify:jspecify`. If strict verification blocks resolution, use the verification refresh steps above.
