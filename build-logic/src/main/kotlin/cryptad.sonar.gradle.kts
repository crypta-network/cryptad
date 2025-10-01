import name.remal.gradle_plugins.sonarlint.SonarLint
import name.remal.gradle_plugins.sonarlint.SonarLintSettings
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.compile.JavaCompile

plugins {
  // Apply SonarQube/SonarCloud and SonarLint centrally via convention plugin
  id("org.sonarqube")
  id("name.remal.sonarlint")
  // Error Prone static analysis
  id("net.ltgt.errorprone")
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

// Error Prone configuration (applies to all JavaCompile tasks)
val errorProneEnabled =
  providers
    .gradleProperty("crypta.errorprone")
    .map { it.equals("true", ignoreCase = true) || it.equals("on", ignoreCase = true) }
    .orElse(true)

// Version can be overridden per-build with -Pcrypta.errorproneVersion
val errorProneVersion = providers.gradleProperty("crypta.errorproneVersion").orElse("2.33.0")

dependencies {
  add("errorprone", "com.google.errorprone:error_prone_core:${errorProneVersion.get()}")
}

tasks.withType(JavaCompile::class.java).configureEach {
  options.errorprone.isEnabled.set(errorProneEnabled.get())
  // Common, safe defaults
  options.errorprone.disableWarningsInGeneratedCode.set(true)

  // Default to warnings-only so local builds don't fail.
  val strict =
    providers
      .gradleProperty("crypta.errorproneStrict")
      .map { it.equals("true", ignoreCase = true) || it.equals("on", ignoreCase = true) }
      .orElse(false)

  if (!strict.get()) {
    // Demote all Error Prone errors to warnings in non-strict mode
    options.errorprone.errorproneArgs.addAll("-XepAllErrorsAsWarnings")
  }

  // Keep disabled checks as warnings to surface signal
  options.errorprone.errorproneArgs.addAll("-XepAllDisabledChecksAsWarnings")
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
