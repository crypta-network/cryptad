import java.io.File

plugins {
  // Apply Gradle 9 convention plugins from the included build
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  id("cryptad.versioning")
  id("cryptad.buildjar")
  id("cryptad.distribution")
  id("cryptad.runtime")
  id("cryptad.jpackage")
  id("cryptad.sonar")
  application
}

// Update version manually before a new release development starts
version = "3"

val internalLeafProjects =
  listOf(
    project(":foundation-config"),
    project(":foundation-fs"),
    project(":foundation-compat"),
    project(":runtime-spi"),
    project(":thirdparty-onion"),
    project(":thirdparty-legacy"),
    project(":launcher-desktop"),
  )

val internalLeafMainJavaSourceDirs =
  internalLeafProjects.map { leaf -> leaf.layout.projectDirectory.dir("src/main/java") }

val internalLeafMainClassDirs =
  internalLeafProjects.map { leaf -> leaf.layout.buildDirectory.dir("classes/java/main") }

dependencies {
  // implementation
  implementation(project(":foundation-config"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-compat"))
  implementation(project(":runtime-spi"))
  implementation(project(":thirdparty-onion"))
  implementation(project(":thirdparty-legacy"))
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  implementation(libs.commonsLang3)
  implementation(files("libs/wrapper.jar"))
  implementation(libs.pebble)
  implementation(libs.unbescape)
  implementation(libs.slf4jApi)
  // FlatLaf (modern Swing Look & Feel)
  implementation(libs.flatlaf)
  // OS theme detection + change events (no LAF dependency)
  implementation(libs.oshiCore)
  implementation(libs.versionCompare)
  implementation(libs.jfa) { exclude(group = "net.java.dev.jna", module = "jna") }
  // Flatpak/Portal detection via D-Bus
  implementation(libs.dbusCore)
  // CLI parsing and UX
  implementation(libs.picocli)

  // compileOnly
  // Compile-time access to Logback classes for runtime reconfiguration
  compileOnly(libs.logbackClassic)
  // Java source annotations used across the codebase
  compileOnly(libs.jetbrainsAnnotations)

  // runtimeOnly
  runtimeOnly(project(":launcher-desktop"))
  runtimeOnly(libs.dbusTransportNativeUnix)
  runtimeOnly(files("libs/db4o-7.4.58.jar"))
  // SLF4J binding (Logback) for the new Slf4jLoggerHook
  runtimeOnly(libs.logbackClassic)

  // testImplementation
  testImplementation(project(":launcher-desktop"))
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testImplementation(libs.junitPlatformSuite)
  // For tests asserting SLF4J integration
  testImplementation(libs.logbackClassic)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.mockitoJunitJupiter)
  testImplementation(libs.mockitoInline)
  testImplementation(libs.hamcrest)
  testImplementation(libs.objenesis)
  testCompileOnly(libs.jetbrainsAnnotations)

  // testRuntimeOnly
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

val aggregatedSonarSourcePaths =
  (sourceSets.main.get().java.srcDirs + internalLeafMainJavaSourceDirs.map { it.asFile })
    .distinct()
    .joinToString(",") { relativePath(it) }

val aggregatedSonarBinaryPaths =
  (sourceSets.main.get().output.classesDirs.files +
      internalLeafMainClassDirs.map { it.get().asFile })
    .distinct()
    .joinToString(",") { it.absolutePath }

val aggregatedSonarLibraryFiles = sourceSets.main.get().compileClasspath.filter { it.isFile }

val internalLeafJarNames =
  providers.provider {
    internalLeafProjects.map { leaf -> "${leaf.name}-${project.version}.jar" }.toSet()
  }

data class SelectiveLeafRootOutputOwnership(
  val leaf: Project,
  val metadataFile: File,
  val patterns: List<String>,
) {
  val pruneTaskName: String =
    "prune" +
      leaf.name.split("-").joinToString(separator = "") { segment ->
        segment.replaceFirstChar { firstChar ->
          if (firstChar.isLowerCase()) firstChar.titlecase() else firstChar.toString()
        }
      } +
      "RootOutputs"
}

fun parseOwnedRootOutputPatterns(metadataFile: File): List<String> =
  metadataFile.useLines { lines ->
    lines.map(String::trim).filter { it.isNotEmpty() && !it.startsWith("#") }.toList()
  }

val selectiveLeafOwnershipMetadataRelativePath = "gradle/owned-root-output-patterns.txt"

// Every extracted internal leaf declares leaf-owned stale-root-output metadata under
// <leaf>/gradle/owned-root-output-patterns.txt. Even structurally separated package moves need this
// because stale root outputs from earlier builds or branch switches can still shadow leaf outputs
// when buildJar packages sourceSets.main.output before the leaf outputs.
val selectiveLeafRootOutputOwnerships =
  internalLeafProjects.map { leaf ->
    val metadataFile =
      leaf.layout.projectDirectory.file(selectiveLeafOwnershipMetadataRelativePath).asFile
    if (!metadataFile.isFile) {
      throw GradleException(
        "Missing ${relativePath(leaf.projectDir)}/$selectiveLeafOwnershipMetadataRelativePath " +
          "for ${leaf.path}. Add leaf-owned stale-root-output metadata before extracting root " +
          "outputs into this leaf."
      )
    }
    SelectiveLeafRootOutputOwnership(
      leaf = leaf,
      metadataFile = metadataFile,
      patterns = parseOwnedRootOutputPatterns(metadataFile),
    )
  }

val verifySelectiveLeafOwnershipMetadata by
  tasks.registering {
    group = "verification"
    description = "Verifies leaf-owned stale-root-output metadata for selective extractions"
    doLast {
      val currentOwnerships =
        selectiveLeafRootOutputOwnerships.map { ownership ->
          ownership.copy(patterns = parseOwnedRootOutputPatterns(ownership.metadataFile))
        }

      val emptyMetadataFiles =
        currentOwnerships.filter { it.patterns.isEmpty() }.map { relativePath(it.metadataFile) }
      if (emptyMetadataFiles.isNotEmpty()) {
        throw GradleException(
          "Selective leaf ownership metadata must not be empty: " +
            emptyMetadataFiles.sorted().joinToString(", ")
        )
      }

      val duplicatePatternsWithinFile =
        currentOwnerships.mapNotNull { ownership ->
          val duplicatePatterns =
            ownership.patterns.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.sorted()
          if (duplicatePatterns.isEmpty()) {
            null
          } else {
            relativePath(ownership.metadataFile) to duplicatePatterns
          }
        }
      if (duplicatePatternsWithinFile.isNotEmpty()) {
        throw GradleException(
          buildString {
            appendLine("Duplicate patterns found within selective leaf ownership metadata:")
            duplicatePatternsWithinFile.forEach { (metadataPath, duplicatePatterns) ->
              appendLine("$metadataPath: ${duplicatePatterns.joinToString(", ")}")
            }
          }
        )
      }

      val duplicatePatternsAcrossLeaves =
        currentOwnerships
          .flatMap { ownership ->
            ownership.patterns.map { pattern -> pattern to ownership.leaf.path }
          }
          .groupBy(keySelector = { it.first }, valueTransform = { it.second })
          .mapValues { (_, owningLeaves) -> owningLeaves.distinct().sorted() }
          .filterValues { it.size > 1 }
      if (duplicatePatternsAcrossLeaves.isNotEmpty()) {
        throw GradleException(
          buildString {
            appendLine("Duplicate patterns claimed by multiple selective leaf projects:")
            duplicatePatternsAcrossLeaves.toSortedMap().forEach { (pattern, owningLeaves) ->
              appendLine("$pattern: ${owningLeaves.joinToString(", ")}")
            }
          }
        )
      }
    }
  }

val selectiveLeafRootOutputPruneTasks =
  selectiveLeafRootOutputOwnerships.associate { ownership ->
    ownership.leaf.path to
      tasks.register<Delete>(ownership.pruneTaskName) {
        description =
          "Removes stale root outputs for sources extracted into ${ownership.leaf.path} on non-clean builds"
        dependsOn(verifySelectiveLeafOwnershipMetadata)
        outputs.upToDateWhen { false }
        delete(
          fileTree(layout.buildDirectory.dir("classes/java/main")) {
            include(*ownership.patterns.toTypedArray())
          },
          fileTree(layout.buildDirectory.dir("resources/main")) {
            include(*ownership.patterns.toTypedArray())
          },
        )
      }
  }

val pruneFoundationConfigRootOutputs =
  selectiveLeafRootOutputPruneTasks.getValue(":foundation-config")

val pruneSelectiveLeafRootOutputs by
  tasks.registering {
    description =
      "Removes stale root outputs claimed by selectively extracted leaf projects on non-clean builds"
    dependsOn(verifySelectiveLeafOwnershipMetadata)
    dependsOn(selectiveLeafRootOutputPruneTasks.values)
  }

internalLeafProjects.forEach { leaf ->
  leaf.extensions.configure<org.sonarqube.gradle.SonarExtension>("sonar") { isSkipProject = true }
}

tasks.named("copyResourcesToClasses2") { dependsOn(pruneSelectiveLeafRootOutputs) }

tasks.named("compileJava") { dependsOn(pruneSelectiveLeafRootOutputs) }

tasks.named("processResources") { dependsOn(pruneSelectiveLeafRootOutputs) }

tasks.named<org.gradle.jvm.tasks.Jar>("buildJar") {
  dependsOn(pruneSelectiveLeafRootOutputs)
  dependsOn(internalLeafProjects.map { "${it.path}:classes" })
  internalLeafProjects.forEach { leaf ->
    from(
      leaf.extensions
        .getByType(org.gradle.api.tasks.SourceSetContainer::class.java)
        .named("main")
        .map { it.output }
    )
  }
}

tasks.named<Copy>("prepareWrapperLibs") {
  exclude { details -> details.file.name in internalLeafJarNames.get() }
}

tasks.named<JacocoReport>("jacocoTestReport") {
  dependsOn(internalLeafProjects.map { "${it.path}:classes" })
  classDirectories.setFrom(
    files(sourceSets.main.get().output.classesDirs, internalLeafMainClassDirs)
  )
  sourceDirectories.setFrom(
    files(sourceSets.main.get().java.srcDirs, internalLeafMainJavaSourceDirs)
  )
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
  dependsOn(internalLeafProjects.map { "${it.path}:classes" })
  classDirectories.setFrom(
    files(sourceSets.main.get().output.classesDirs, internalLeafMainClassDirs)
  )
  sourceDirectories.setFrom(
    files(sourceSets.main.get().java.srcDirs, internalLeafMainJavaSourceDirs)
  )
}

sonar {
  properties {
    property("sonar.sources", aggregatedSonarSourcePaths)
    property("sonar.java.binaries", aggregatedSonarBinaryPaths)
    property("sonar.java.libraries", aggregatedSonarLibraryFiles)
  }
}

// Utility task to print the project version
tasks.register("printVersion") {
  group = "help"
  description = "Prints the project version"
  doLast { println(project.version.toString()) }
}

// The default from build-logic (512m) is too small for the full test suite on Windows and can
// trigger OOM in long-running integration tests.
tasks.withType<Test>().configureEach { maxHeapSize = "2g" }

// Application entrypoint (used by jpackage). This does not change how we build the wrapper
// distribution; it's only to inform launchers that invoke the launcher main class directly.
// Align with the actual launcher entrypoint in Launcher.java
application { mainClass.set("network.crypta.launcher.Launcher") }

val nodeRuntimeJvmArgs =
  listOf(
    "-Dnetworkaddress.cache.ttl=0",
    "-Dnetworkaddress.cache.negative.ttl=0",
    "-Djava.net.preferIPv4Stack=false",
    "--enable-native-access=ALL-UNNAMED",
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
    "-enableassertions:freenet",
  )

tasks.named<JavaExec>("run") {
  description = "Runs Cryptad daemon via NodeStarter"
  mainClass.set("network.crypta.node.NodeStarter")
  jvmArgs(nodeRuntimeJvmArgs)
}

tasks.register<JavaExec>("runLauncher") {
  group = "application"
  description = "Runs the Cryptad Swing launcher"
  javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(25)) })
  mainClass.set("network.crypta.launcher.Launcher")
  classpath = sourceSets.main.get().runtimeClasspath
  jvmArgs("--enable-native-access=ALL-UNNAMED")
}

// Sonar configuration is applied via the build-logic convention plugin 'cryptad.sonar'
