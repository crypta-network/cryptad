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

internalLeafProjects.forEach { leaf ->
  leaf.extensions.configure<org.sonarqube.gradle.SonarExtension>("sonar") { isSkipProject = true }
}

tasks.named<org.gradle.jvm.tasks.Jar>("buildJar") {
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
