import name.remal.gradle_plugins.sonarlint.SonarLint
import name.remal.gradle_plugins.sonarlint.SonarLintSettings
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.SourceSetContainer

plugins {
  // Apply SonarQube/SonarCloud and SonarLint centrally via convention plugin
  id("org.sonarqube")
  id("name.remal.sonarlint")
  // Error Prone static analysis (Palantir)
  id("com.palantir.suppressible-error-prone")
}

// Central Sonar configuration for all projects applying this convention
sonar {
  properties {
    property("sonar.projectKey", "crypta-network_cryptad")
    property("sonar.organization", "crypta-network")
  }
}

// Minimal SonarLint configuration with optional file scoping via -Psonarlint.sources
extensions.configure<SonarLintSettings>("sonarLint") {
  // default: don't fail builds on findings until CI is configured to be green
  ignoreFailures.convention(true)

  val includeProp =
    providers
      .gradleProperty("sonarlint.sources")
      .orElse(providers.gradleProperty("sonarlint.include"))
      .orElse(providers.gradleProperty("sonar.inclusions"))

  includeProp.orNull?.let { value ->
    // Use Sonar's standard inclusions property so the engine narrows the scope
    sonarProperty("sonar.inclusions", value)
  }
}

// Version can be overridden per-build with -Pcrypta.errorproneVersion
val errorProneVersion = providers.gradleProperty("crypta.errorproneVersion").orElse("2.42.0")

dependencies {
  add("errorprone", "com.google.errorprone:error_prone_core:${errorProneVersion.get()}")
}

// Map our toggle to Palantir's property when not explicitly set
val cryptaErrorProne =
  providers
    .gradleProperty("crypta.errorprone")
    .map { it.equals("true", ignoreCase = true) || it.equals("on", ignoreCase = true) }
    .orElse(true)

if (!cryptaErrorProne.get() && !project.hasProperty("errorProneDisable")) {
  // Palantir plugin looks for this project property
  extensions.extraProperties.set("errorProneDisable", "true")
}

// To tweak Error Prone severities or options, prefer passing properties at
// invocation time, e.g.:
//  -PerrorProneDisable=true                 (disable EP)
//  -PerrorProneSuppress=Check1,Check2       (suppress checks)
//  -PerrorProneApply=Check1,Check2          (auto-fix when supported)

// Demote errors to warnings by default via LTGT typed options (available via Palantir plugin)
tasks.withType(org.gradle.api.tasks.compile.JavaCompile::class.java).configureEach {
  val enabled =
    providers
      .gradleProperty("crypta.errorprone")
      .map { it.equals("true", ignoreCase = true) || it.equals("on", ignoreCase = true) }
      .orElse(true)
  val strict =
    providers
      .gradleProperty("crypta.errorproneStrict")
      .map { it.equals("true", ignoreCase = true) || it.equals("on", ignoreCase = true) }
      .orElse(false)

  options.errorprone.isEnabled.set(enabled.get())
  options.errorprone.disableWarningsInGeneratedCode.set(true)
  if (!strict.get()) {
    options.errorprone.allErrorsAsWarnings.set(true)
  }
}

// Convenience task: run SonarLint on a single file
// Usage:
//   ./gradlew sonarlintFile -Psonarlint.file=src/main/java/SevenZip/LzmaAlone.java
//   (aliases: -Pfile=..., -Psonarlint.sources=...)
val sourceSets = extensions.getByType(SourceSetContainer::class.java)

tasks.register("sonarlintFile", SonarLint::class.java) {
  group = "verification"
  description = "Run SonarLint on a single file (-Psonarlint.file=<path>)."
  // Analyze against main sources by default
  setSource(sourceSets.named("main").get().allSource)
  // Pick a file pattern from properties
  val fileProp =
    providers
      .gradleProperty("sonarlint.file")
      .orElse(providers.gradleProperty("file"))
      .orElse(providers.gradleProperty("sonarlint.sources"))
      .orElse(providers.gradleProperty("sonar.inclusions"))

  val pattern = fileProp.orNull
  if (pattern != null && pattern.isNotBlank()) {
    // Normalize to project-relative path and set it as the only source
    val f = project.layout.projectDirectory.file(pattern).asFile
    if (f.isFile) {
      setSource(f)
    } else {
      // Fall back to include when a glob or directory is provided
      val rel = project.relativePath(f)
      include(rel)
    }
  } else {
    logger.warn("sonarlint.file not specified; use -Psonarlint.file=<path> to scope analysis")
  }
}
