plugins {
  // Apply Gradle 9 convention plugins from included build
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
version = "2"

dependencies {
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  implementation(files("libs/wrapper.jar"))
  implementation(libs.pebble)
  implementation(libs.unbescape)
  implementation(libs.slf4jApi)
  // Compile-time access to Logback classes for runtime reconfiguration
  compileOnly("ch.qos.logback:logback-classic:1.5.6")
  // Coroutines (Swing Main dispatcher)
  implementation(libs.kotlinxCoroutinesSwing)
  // FlatLaf (modern Swing Look & Feel)
  implementation(libs.flatlaf)
  // OS theme detection + change events (no LAF dependency)
  implementation(libs.jsystemThemeDetector)
  // Flatpak/Portal detection via D-Bus
  implementation(libs.dbusCore)
  runtimeOnly(libs.dbusTransportNativeUnix)
  // CLI parsing and UX
  implementation(libs.picocli)

  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testImplementation(libs.junitPlatformSuite)
  // For tests asserting SLF4J integration
  testImplementation("ch.qos.logback:logback-classic:1.5.6")
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.hamcrest)
  testImplementation(libs.objenesis)

  runtimeOnly(files("libs/db4o-7.4.58.jar"))
  // SLF4J binding (Logback) for the new Slf4jLoggerHook
  runtimeOnly("ch.qos.logback:logback-classic:1.5.6")
}

// Utility task to print the project version
tasks.register("printVersion") {
  group = "help"
  description = "Prints the project version"
  doLast { println(project.version.toString()) }
}

// Application entrypoint (used by jpackage). This does not change how we build the wrapper
// distribution; it's only to inform launchers that invoke the Kotlin main directly.
// Align with actual top-level entry in Launcher.kt
application { mainClass.set("network.crypta.launcher.LauncherKt") }

// Sonar configuration is applied via the build-logic convention plugin 'cryptad.sonar'

// PR3 guard: optional check for legacy Logger usage. Does not fail by default.
// Run: ./gradlew legacyLoggerCheck -PfailOnLegacyLogger=true to fail on matches
tasks.register("legacyLoggerCheck") {
  group = "verification"
  description = "Scans sources for legacy network.crypta.support.Logger usages."
  val fail = providers.gradleProperty("failOnLegacyLogger").orNull == "true"
  doLast {
    val srcDirs = listOf("src/main/java", "src/main/kotlin", "src/test/java", "src/test/kotlin")
    val allowed =
      setOf(
        // Allow the legacy definitions to exist until PR4
        "src/main/java/network/crypta/support/Logger.kt",
        "src/main/java/network/crypta/support/LoggerHook.kt",
        "src/main/java/network/crypta/support/LoggerHookChain.kt",
        "src/main/java/network/crypta/support/VoidLogger.kt",
        "src/main/java/network/crypta/support/Slf4jLoggerHook.kt",
        "src/main/java/network/crypta/support/LogThresholdCallback.java",
      )
    val pattern = Regex("network\\.crypta\\.support\\.Logger")
    val offenders = mutableListOf<String>()
    srcDirs
      .map { file(it) }
      .filter { it.exists() }
      .flatMap { it.walkTopDown().asSequence().toList() }
      .filter { it.isFile && (it.extension == "java" || it.extension == "kt") }
      .forEach { f ->
        val normalized = f.path.replace('\\', '/')
        if (normalized !in allowed) {
          val text = f.readText()
          if (pattern.containsMatchIn(text)) offenders += normalized
        }
      }
    if (offenders.isEmpty()) {
      println("[legacyLoggerCheck] OK: no legacy Logger usages found.")
    } else {
      println("[legacyLoggerCheck] Found ${offenders.size} files using legacy Logger:")
      offenders.take(50).forEach { println(" - $it") }
      if (offenders.size > 50) println(" (and ${offenders.size - 50} more)")
      if (fail) throw GradleException("Legacy Logger usages detected: ${offenders.size}")
    }
  }
}
