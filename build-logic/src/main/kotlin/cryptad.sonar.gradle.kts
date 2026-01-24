import java.io.File
import name.remal.gradle_plugins.sonarlint.SonarLint
import name.remal.gradle_plugins.sonarlint.SonarLintSettings

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
    property(
      "sonar.coverage.jacoco.xmlReportPaths",
      "build/reports/jacoco/test/jacocoTestReport.xml",
    )
    // Use Kotlin-only JUnit reports to avoid KotlinSurefire warnings on Java tests.
    property("sonar.junit.reportPaths", "build/sonar-test-results/kotlin")
    property("sonar.tests", "src/test/java,src/test/kotlin")
    property("sonar.test.inclusions", "src/test/java/**,src/test/kotlin/**")

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

  val fileProp = providers.gradleProperty("sonarlint.file").orElse(providers.gradleProperty("file"))
  fileProp.orNull?.let { value ->
    if (value.startsWith("src/test/")) {
      sonarProperty("sonar.tests", value)
      sonarProperty("sonar.test.inclusions", value)
    } else {
      sonarProperty("sonar.inclusions", value)
    }
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
val sourceSets: SourceSetContainer = extensions.getByType(SourceSetContainer::class.java)
val kotlinTestReportDir = layout.buildDirectory.dir("sonar-test-results/kotlin")
val testResultsDir = layout.buildDirectory.dir("test-results/test")

tasks.register("prepareKotlinTestReports") {
  group = "verification"
  description = "Collect Kotlin JUnit reports for Sonar analysis."
  dependsOn(tasks.withType<Test>())
  inputs.dir(testResultsDir)
  outputs.dir(kotlinTestReportDir)

  doLast {
    val testSourceSet = sourceSets.named("test").get()
    val kotlinTestFiles = testSourceSet.allSource.matching { include("**/*.kt") }.files

    val kotlinClassNames =
      kotlinTestFiles
        .mapNotNull { file ->
          val rootDir =
            testSourceSet.allSource.srcDirs.firstOrNull { srcDir ->
              file.toPath().startsWith(srcDir.toPath())
            }
          rootDir?.toPath()?.relativize(file.toPath())?.toString()
        }
        .map { relativePath ->
          relativePath
            .removeSuffix(".kt")
            .replace(File.separatorChar, '.')
            .replace('/', '.')
            .replace('\\', '.')
        }
        .distinct()

    val reportDir = testResultsDir.get().asFile
    val outputDir = kotlinTestReportDir.get().asFile
    project.delete(outputDir)
    outputDir.mkdirs()

    val reportNames =
      kotlinClassNames
        .flatMap { className -> listOf("TEST-$className.xml", "TESTS-$className.xml") }
        .toSet()

    reportNames.forEach { reportName ->
      val reportFile = File(reportDir, reportName)
      if (reportFile.isFile) {
        reportFile.copyTo(File(outputDir, reportName), overwrite = true)
      }
    }
  }
}

tasks.register("sonarlintFile", SonarLint::class.java) {
  group = "verification"
  description = "Run SonarLint on a single file (-Psonarlint.file=<path>)."
  // Analyze against main sources by default
  setSource(sourceSets.named("main").get().allSource)
  // Propagate the Java language level explicitly for single-file analysis
  val javaExt = project.extensions.findByType(JavaPluginExtension::class.java)
  val targetVersion = (javaExt?.targetCompatibility ?: JavaVersion.current()).majorVersion
  // Configure a task-scoped Java release for the SonarLint engine
  java { release.set(JavaLanguageVersion.of(targetVersion.toInt())) }

  // Provide classpath and output directories, so Java rules that require
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
  if (!pattern.isNullOrBlank()) {
    // Normalize to a project-relative path and set it as the only source
    val f = project.layout.projectDirectory.file(pattern).asFile
    val rel = project.relativePath(f)
    if (f.isFile) {
      setSource(f)
      val isTestSource = rel.startsWith("src/test/")
      if (isTestSource) {
        isTest.set(true)
        val testSourceSet = sourceSets.named("test").get()
        java {
          testOutputDirectories.from(testSourceSet.output.classesDirs)
          testClasspath.from(testSourceSet.runtimeClasspath)
        }
      } else {
        isTest.set(false)
      }
    } else {
      // Fall back to include when a glob or directory is provided
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
tasks.named("sonarqube").configure { dependsOn("jacocoTestReport", "prepareKotlinTestReports") }

tasks.findByName("sonar")?.dependsOn("jacocoTestReport", "prepareKotlinTestReports")
