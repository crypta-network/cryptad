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
version = "2"

dependencies {
  // implementation
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
  runtimeOnly(libs.dbusTransportNativeUnix)
  runtimeOnly(files("libs/db4o-7.4.58.jar"))
  // SLF4J binding (Logback) for the new Slf4jLoggerHook
  runtimeOnly(libs.logbackClassic)

  // testImplementation
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
