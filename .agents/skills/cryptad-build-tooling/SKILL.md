---
name: cryptad-build-tooling
description: "Maintain formatting and code-quality tooling: Spotless, SpotBugs, Gradle dependency verification (verification-metadata), SonarLint, JaCoCo coverage, and SonarCloud uploads."
compatibility: opencode
metadata:
  area: tooling
  domain: cryptad
---

## When to use
Use this skill when you:
- Fix formatting or Spotless failures.
- Add, run, or tune SpotBugs Gradle analysis.
- Update dependencies and need to refresh Gradle dependency verification metadata.
- Run or adjust SonarLint / SonarCloud / JaCoCo coverage tasks.
- Need to analyze a single file with SonarLint.

## Spotless + dependency verification (common failure mode)
When Gradle dependency verification is strict, Spotless may fail to resolve formatter artifacts even with `mavenCentral()`.

### Spotless target path outside the project dir
If Spotless fails with an error like:
```text
Spotless error! All target files must be within the project dir.
```
run:
```bash
./gradlew clean
```
then retry Spotless (`./gradlew spotlessJava` or `./gradlew spotlessApply`).

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

## SpotBugs (Gradle) usage
### Current repo wiring
- Version catalog pins SpotBugs at `6.4.8` and exposes a plugin alias in `gradle/libs.versions.toml`.
- Build logic includes the plugin marker dependency in `build-logic/build.gradle.kts`.
- The shared convention plugin applies `com.github.spotbugs` in `build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts`.
- Default behavior is non-blocking: `spotbugs { ignoreFailures = true }`.
- All SpotBugs tasks are configured via `tasks.withType<SpotBugsTask>()` to emit XML reports at `build/reports/spotbugs/<taskName>.xml`.
- Text reports are disabled (`reports.matching { it.name == "text" }`) so findings are read from XML files instead of large stdout dumps.

### Tasks
- Run the main analysis:
  - `./gradlew spotbugsMain`
  - Report: `build/reports/spotbugs/spotbugsMain.xml`
- Run test analysis:
  - `./gradlew spotbugsTest`
  - Report: `build/reports/spotbugs/spotbugsTest.xml`
- SpotBugs tasks are also part of `check` once the plugin is applied.

### Enforcing SpotBugs failures
- To make findings fail the build, set:
  - `spotbugs { ignoreFailures = false }`

### Verification refresh on SpotBugs bumps
If strict verification blocks SpotBugs/plugin marker resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:compileKotlin
```
3) Restore `org.gradle.dependency.verification=strict`
4) Validate:
```bash
./gradlew help
./gradlew spotbugsMain
./gradlew spotbugsTest
```

Confirm `gradle/verification-metadata.xml` contains SpotBugs entries such as:
- component `com.github.spotbugs:com.github.spotbugs.gradle.plugin`
- trusted key/group entries for `com.github.spotbugs`

## SonarLint (Gradle) usage
### Key behaviors
- SonarLint does **not** run during regular lifecycles (`build`, `check`).
- `sonarlintMain` / `sonarlintTest` run only when explicitly requested (task name contains `sonarlint`).
- Default config: `ignoreFailures = true` (non-failing by default).
- `sonarIssues` queries server-side issues from SonarQube/SonarCloud (`/api/issues/search`) for a
  specified rule set and can report issues that local `sonarlintMain`, `sonarlintTest`, and
  `sonarlintFile` do not.
- `sonarIssues` reads the latest uploaded server analysis; after fixing code locally, its issue list
  can remain stale until CI runs analysis successfully and uploads fresh results.

### Tasks
- Full main sources:
  - `./gradlew sonarlintMain`
- Test sources:
  - `./gradlew sonarlintTest`
- Single file analysis:
  - `./gradlew --quiet sonarlintFile -Psonarlint.file=src/main/java/SevenZip/LzmaAlone.java`
  - Aliases: `-Pfile=...`, `-Psonarlint.sources=...`
  - Report: `build/reports/sonarLint/sonarlintFile/sonarlintFile.xml`
- Server-side rule query:
  - `./gradlew sonarIssues -PsonarIssues.rules=java:S1172`
  - Task name is `sonarIssues` (sometimes informally referred to as “sonarlintIssues”).
  - Uses `SONAR_TOKEN` automatically when present (required for private projects).
  - Default report: `build/reports/sonar/issues-page-1.json`
  - Useful properties:
    - `-PsonarIssues.rules=<repo:rule>` (comma-separated supported by API)
    - `-PsonarIssues.page=<n>`
    - `-PsonarIssues.pageSize=<1..500>`
    - `-PsonarIssues.output=<path>`

### Rule-specific investigation workflow
When investigating a specific SonarLint/Sonar rule, always run all three:
1) `./gradlew sonarlintMain`
2) `./gradlew sonarlintTest`
3) `./gradlew sonarIssues -PsonarIssues.rules=<repo:rule>`

Interpretation:
- Local SonarLint tasks (`sonarlintMain`, `sonarlintTest`, optionally `sonarlintFile`) show what the
  current local analyzer run reports.
- `sonarIssues` shows what the server currently reports (may lag until CI analysis completes).

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
