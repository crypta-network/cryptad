import name.remal.gradle_plugins.sonarlint.SonarLint
import name.remal.gradle_plugins.sonarlint.SonarLintSettings
import org.gradle.api.JavaVersion
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.jvm.toolchain.JavaLanguageVersion

plugins {
  // Apply SonarQube/SonarCloud and SonarLint centrally via convention plugin
  id("org.sonarqube")
  id("name.remal.sonarlint")
}

// Central Sonar configuration for all projects applying this convention
sonar {
  properties {
    property("sonar.projectKey", "crypta-network_cryptad")
    property("sonar.organization", "crypta-network")
    property("sonar.host.url", "https://sonarcloud.io")

    // Point Sonar to the JaCoCo XML report produced by jacocoTestReport
    val jacocoXml =
      layout.buildDirectory
        .file("reports/jacoco/test/jacocoTestReport.xml")
        .get()
        .asFile
        .absolutePath
    property("sonar.coverage.jacoco.xmlReportPaths", jacocoXml)

    // Ensure test/main sources and JUnit XML reports are discoverable during analysis.
    val sourceSets = extensions.getByType<SourceSetContainer>()
    val kotlinExt =
      extensions.findByType(org.jetbrains.kotlin.gradle.dsl.KotlinProjectExtension::class.java)

    val mainSourceDirs =
      (sourceSets.getByName("main").java.srcDirs +
          (kotlinExt?.sourceSets?.getByName("main")?.kotlin?.srcDirs ?: emptySet()))
        .map { it.absolutePath }
        .sorted()
    if (mainSourceDirs.isNotEmpty()) {
      property("sonar.sources", mainSourceDirs.joinToString(","))
    }

    val testSourceDirs =
      (sourceSets.getByName("test").java.srcDirs +
          (kotlinExt?.sourceSets?.getByName("test")?.kotlin?.srcDirs ?: emptySet()))
        .map { it.absolutePath }
        .sorted()
    if (testSourceDirs.isNotEmpty()) {
      property("sonar.tests", testSourceDirs.joinToString(","))
    }

    val testReportDirs =
      tasks
        .withType<org.gradle.api.tasks.testing.Test>()
        .map { it.reports.junitXml.outputLocation.get().asFile.absolutePath }
        .ifEmpty {
          listOf(layout.buildDirectory.dir("test-results/test").get().asFile.absolutePath)
        }
        .distinct()
        .sorted()
    property("sonar.junit.reportPaths", testReportDirs.joinToString(","))

    // Avoid UTF-8 decode warnings on binary fixtures.
    property(
      "sonar.exclusions",
      listOf(
          "**/*.png",
          "**/*.gif",
          "**/*.bmp",
          "**/*.webp",
          "**/*.jpg",
          "**/*.jpeg",
          "**/*.ico",
          "**/*.icns",
          "**/*.pdf",
          "**/*.zip",
          "**/*.jar",
        )
        .joinToString(","),
    )

    // Read token from environment if provided to avoid passing on CLI (modern scanners read
    // sonar.token)
    providers.environmentVariable("SONAR_TOKEN").orNull?.let { token ->
      if (token.isNotBlank()) property("sonar.token", token)
    }
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

  // Ensure Java language level is explicitly provided so rules that depend on
  // the runtime version (e.g., java:S6204 requiring Java 16+) are evaluated
  // consistently, including for single-file analyses.
  val javaExt = project.extensions.findByType(JavaPluginExtension::class.java)
  val sourceVersion = (javaExt?.sourceCompatibility ?: JavaVersion.current()).majorVersion
  val targetVersion = (javaExt?.targetCompatibility ?: JavaVersion.current()).majorVersion
  sonarProperty("sonar.java.source", sourceVersion)
  sonarProperty("sonar.java.target", targetVersion)
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
  // Propagate Java language level explicitly for single-file analysis
  val javaExt = project.extensions.findByType(JavaPluginExtension::class.java)
  val sourceVersion = (javaExt?.sourceCompatibility ?: JavaVersion.current()).majorVersion
  val targetVersion = (javaExt?.targetCompatibility ?: JavaVersion.current()).majorVersion
  // Configure task-scoped Java release for the SonarLint engine
  java { release.set(JavaLanguageVersion.of(sourceVersion.toInt())) }

  // Provide classpath and output directories so Java rules that require
  // semantic information are enabled even for single-file analysis.
  val mainSourceSet = sourceSets.named("main").get()
  java {
    mainOutputDirectories.from(mainSourceSet.output.classesDirs)
    mainClasspath.from(mainSourceSet.runtimeClasspath)
  }
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

// Do not run SonarLint as part of a regular `build`.
// Keep the task available when explicitly requested (any task name containing "sonarlint").
tasks.named("sonarlintMain", SonarLint::class.java).configure {
  onlyIf {
    val explicitlyRequested =
      gradle.startParameter.taskNames.any { it.contains("sonarlint", ignoreCase = true) }
    if (!explicitlyRequested) {
      logger.info(
        "Skipping sonarlintMain during standard builds; run :sonarlintMain explicitly to enable."
      )
    }
    explicitlyRequested
  }
}

tasks.named("sonarlintTest", SonarLint::class.java).configure {
  onlyIf {
    val explicitlyRequested =
      gradle.startParameter.taskNames.any { it.contains("sonarlint", ignoreCase = true) }
    if (!explicitlyRequested) {
      logger.info(
        "Skipping sonarlintTest during standard builds; run :sonarlintTest explicitly to enable."
      )
    }
    explicitlyRequested
  }
}

// Ensure coverage reports exist before publishing analysis.
// Explicitly depend on jacocoTestReport for the SonarQube task; guard optional 'sonar' alias.
tasks.named("sonarqube").configure { dependsOn("jacocoTestReport") }

tasks.findByName("sonar")?.dependsOn("jacocoTestReport")
