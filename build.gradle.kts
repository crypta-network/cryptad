import java.io.IOException
import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  java
  `maven-publish`
  alias(libs.plugins.kotlinJvm)
  id("com.diffplug.spotless") version "7.2.1"
}

// Update version manually before a new release development starts
version = "1"

java {
  sourceCompatibility = JavaVersion.VERSION_21
  targetCompatibility = JavaVersion.VERSION_21
}

val versionBuildDir = file("$projectDir/build/tmp/compileVersion/")
val versionSrc = "network/crypta/node/Version.kt"

repositories { mavenCentral() }

// Allow Kotlin sources to live under src/main/java and src/test/java
// (the project keeps mixed Java/Kotlin in Java source roots)
kotlin {
  sourceSets.getByName("main").kotlin.srcDir("src/main/java")
  sourceSets.getByName("test").kotlin.srcDir("src/test/java")
}

sourceSets {
  main {
    // Rely on Gradle's default directories (src/main/java, src/main/resources)
    // Exclude the templated Version.kt from direct compilation
    java.exclude("network/crypta/node/Version.kt")
    kotlin.exclude("**/Version.kt")
    // Source set configuration
  }
  test {
    // Rely on Gradle's default directories (src/test/java, src/test/resources)
  }
}

tasks.withType<JavaCompile> { options.encoding = "UTF-8" }

tasks.withType<Javadoc> { options.encoding = "UTF-8" }

tasks.withType<KotlinCompile>().configureEach {
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
}

// Spotless configuration for code formatting
spotless {
  java {
    // Use Google Java Format
    googleJavaFormat("1.28.0").reflowLongStrings()
    // Apply to all Java source files
    target("src/**/*.java")
    // Remove unused imports
    removeUnusedImports()
    // Remove the ratchet for now to format all files
    // ratchetFrom("origin/develop")
  }
  kotlin {
    // Format all Kotlin source files with ktfmt (Google style)
    target("**/*.kt")
    // Exclude templated/generated Version.kt which isn't valid Kotlin pre-build
    targetExclude("**/Version.kt")
    ktfmt().googleStyle()
    trimTrailingWhitespace()
    endWithNewline()
  }
  kotlinGradle {
    // Format Gradle Kotlin DSL scripts with ktfmt (Google style)
    target("**/*.gradle.kts")
    ktfmt().googleStyle()
  }
}

// Make compileJava depend on Spotless check and apply formatting to changed files
tasks.compileJava {
  // This will automatically format files that have changes according to git
  dependsOn("spotlessApply")
  // Ensure Kotlin sources compile before Java when Java depends on Kotlin types
  dependsOn(tasks.named("compileKotlin"))
}

val gitrev: String =
  try {
    val cmd = "git rev-parse --short HEAD"
    ProcessBuilder(cmd.split(" "))
      .directory(rootDir)
      .start()
      .inputStream
      .bufferedReader()
      .readText()
      .trim()
  } catch (_: IOException) {
    "@unknown@"
  }

val generateVersionSource by
  tasks.registering(Copy::class) {
    // Always regenerate to ensure fresh version info
    outputs.upToDateWhen { false }

    // Capture version during configuration to avoid deprecation warning
    val buildVersion = project.version.toString()

    // Delete old generated version first to ensure clean generation
    doFirst { delete(versionBuildDir) }

    from(sourceSets["main"].java.srcDirs) {
      include(versionSrc)
      filter { line: String ->
        line.replace("@build_number@", buildVersion).replace("@git_rev@", gitrev)
      }
    }
    into(versionBuildDir)
  }

tasks.named<KotlinCompile>("compileKotlin") {
  dependsOn(generateVersionSource)
  source(versionBuildDir)

  // Force recompilation of Version.kt when build number or git rev changes
  inputs.property("buildNumber", project.version.toString())
  inputs.property("gitRevision", gitrev)

  // Also track the generated file as an input to ensure recompilation
  inputs.files(generateVersionSource)
}

val buildJar by
  tasks.registering(Jar::class) {
    // Ensure both Java and Kotlin compilation have run
    dependsOn(
      tasks.processResources,
      tasks.compileJava,
      tasks.named("compileKotlin"),
      generateVersionSource, // Explicitly depend on version generation
    )

    // Include compiled classes (Java + Kotlin) and resources explicitly to avoid duplicates
    from(sourceSets.main.get().output.classesDirs)
    from(sourceSets.main.get().resources)

    archiveFileName.set("cryptad.jar")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    // Some resources may appear in multiple outputs; exclude duplicates deterministically
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
      attributes(
        "Permissions" to "all-permissions",
        "Application-Name" to "Crypta Daemon",
        "Compiled-With" to
          "${System.getProperty("java.version")} (${System.getProperty("java.vendor")})",
        "Specification-Title" to "Crypta",
        "Specification-Version" to project.version.toString(),
        "Specification-Vendor" to "crypta.network",
        "Implementation-Title" to "Crypta",
        "Implementation-Version" to "${project.version} $gitrev",
        "Implementation-Vendor" to "crypta.network",
      )
    }
  }

tasks.named<Jar>("jar") {
  // Fully disable the default jar task — do not wire any dependencies
  enabled = false
}

// Fail fast with a clear error if someone explicitly asks for :jar
if (gradle.startParameter.taskNames.any { it == "jar" || it.endsWith(":jar") }) {
  throw GradleException("Task 'jar' is disabled. Use ':buildJar' to build cryptad.jar.")
}

// Modern approach using task finalization instead of deprecated listeners
val printHashTask by
  tasks.registering {
    description = "Prints SHA-256 hashes of built JAR files"
    group = "verification"

    doLast {
      fun hash(file: File) {
        val sha256 = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
          val buffer = ByteArray(4096)
          while (true) {
            val read = input.read(buffer)
            if (read == -1) break
            sha256.update(buffer, 0, read)
          }
        }
        println(
          "SHA-256 of ${file.name}: " + sha256.digest().joinToString("") { "%02x".format(it) }
        )
      }

      // Hash the main JAR file
      val jarFile = buildJar.get().outputs.files.singleFile
      if (jarFile.exists()) {
        hash(jarFile)
      }
    }
  }

// Make the hash printing run after the JAR is built
buildJar { finalizedBy(printHashTask) }

// Ensure the standard lifecycle build produces cryptad.jar
tasks.named("build") { dependsOn(buildJar) }

tasks.test {
  // Point tests expecting old layout to new standard resource locations
  systemProperty("test.l10npath_test", "src/test/resources/network/crypta/l10n/")
  systemProperty("test.l10npath_main", "src/main/resources/network/crypta/l10n/")
}

// --- Java Service Wrapper based distribution -----------------------------------------------
// The daemon is intended to run under the Tanuki Java Service Wrapper. We provide tasks to
// download the wrapper, assemble a portable distribution (bin/conf/lib), and package it.

val wrapperVersion = "3.6.2"
val wrapperDeltaPack = "wrapper-delta-pack-$wrapperVersion.tar.gz"
// SourceForge mirror (original host may be unavailable at times)
val wrapperBaseUrl =
  "https://sourceforge.net/projects/wrapper/files/wrapper/Wrapper_3.6.2_20250605/$wrapperDeltaPack/download"

val wrapperWorkDir = layout.buildDirectory.dir("wrapper")
val wrapperExtractDir = layout.buildDirectory.dir("wrapper/extracted")
val wrapperDistDir = layout.buildDirectory.dir("cryptad-dist")
// Seednodes generation settings
val seedrefsZipUrl = "https://codeload.github.com/hyphanet/seedrefs/zip/refs/heads/master"
val seedrefsWorkDir = layout.buildDirectory.dir("seedrefs")
val seedrefsZip = seedrefsWorkDir.map { it.file("seedrefs.zip") }
val seedrefsExtracted = seedrefsWorkDir.map { it.dir("extracted") }
val seednodesOut = layout.buildDirectory.file("generated/seednodes/seednodes.fref")

// Download the Wrapper delta pack
val downloadWrapper by
  tasks.registering {
    group = "distribution"
    description = "Downloads Tanuki Java Service Wrapper delta pack"
    val outFile = wrapperWorkDir.map { it.file(wrapperDeltaPack) }
    outputs.file(outFile)
    doLast {
      val target = outFile.get().asFile
      target.parentFile.mkdirs()
      val url = URI(wrapperBaseUrl).toURL()
      println("Downloading $wrapperBaseUrl -> " + target.absolutePath)
      url.openStream().use { input ->
        Files.copy(input, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
      }
    }
  }

// Extract the delta pack
val extractWrapper by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts the Tanuki Wrapper delta pack"
    dependsOn(downloadWrapper)
    val tarFile = wrapperWorkDir.map { it.file(wrapperDeltaPack) }
    from(tarTree(resources.gzip(tarFile)))
    into(wrapperExtractDir)
  }

// Download seedrefs (zip of repo)
val downloadSeedrefs by
  tasks.registering {
    group = "distribution"
    description = "Downloads hyphanet/seedrefs repository as a zip"
    outputs.file(seedrefsZip)
    doLast {
      val out = seedrefsZip.get().asFile
      out.parentFile.mkdirs()
      val url = URI(seedrefsZipUrl).toURL()
      println("Downloading $seedrefsZipUrl -> " + out.absolutePath)
      url.openStream().use { input ->
        Files.copy(input, out.toPath(), StandardCopyOption.REPLACE_EXISTING)
      }
    }
  }

// Extract seedrefs
val extractSeedrefs by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts seedrefs zip"
    dependsOn(downloadSeedrefs)
    from(zipTree(seedrefsZip.get().asFile))
    into(seedrefsExtracted)
  }

// Concatenate all seedrefs files into one seednodes.fref
val generateSeednodesFile by
  tasks.registering {
    group = "distribution"
    description = "Generates seednodes.fref from hyphanet/seedrefs"
    dependsOn(extractSeedrefs)
    outputs.file(seednodesOut)
    doLast {
      val root = seedrefsExtracted.get().asFile
      val outFile = seednodesOut.get().asFile
      outFile.parentFile.mkdirs()
      val files = root.walkTopDown().filter { it.isFile }.sortedBy { it.name.lowercase() }.toList()
      if (files.isEmpty()) throw GradleException("No files found in extracted seedrefs")
      outFile.printWriter().use { pw ->
        files.forEach { f ->
          val content = f.readText()
          pw.println(content.trim())
          pw.println()
        }
      }
      println(
        "Generated seednodes file at " + outFile.absolutePath + " with " + files.size + " entries"
      )
    }
  }

// Copy platform wrapper binaries and helper files under bin/
val copyWrapperBinaries by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Copies Wrapper binaries into distribution bin/"
    dependsOn(extractWrapper)
    into(wrapperDistDir.map { it.dir("bin") })
    // The delta-pack contains top-level 'wrapper-delta-pack-<ver>/bin/*' — copy those files only.
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/bin") }) {
      include("*")
      // Drop unsupported platforms
      exclude("*aix*")
      exclude("*hpux*")
      exclude("*linux-ppcle*")
      exclude("*solaris*")
      // Drop FreeBSD for now
      exclude("*freebsd*")
      // No Windows support for now
      exclude("*windows*")
      // Drop Windows scripts and misc demo/test helpers
      exclude("**/*.bat")
      exclude("README.txt")
      exclude("demoapp*")
      exclude("testwrapper*")
      exclude("Install*")
      exclude("Uninstall*")
      exclude("Start*")
      exclude("Stop*")
      exclude("Pause*")
      exclude("Resume*")
      exclude("Query*")
      // Drop 32-bit binaries
      exclude("*-x86-32*")
      exclude("*-universal-32*")
      exclude("*-armel-32*")
      exclude("*-armhf-32*")
    }
  }

// Copy runtime jars into lib/ and build a classpath list for wrapper.conf
val prepareWrapperLibs by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Copies runtime jars to lib/ for the wrapper distribution"
    dependsOn(buildJar, extractWrapper)
    into(wrapperDistDir.map { it.dir("lib") })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    // All runtime dependencies
    from(configurations.runtimeClasspath) { exclude("**/wrapper*.jar") }
    // The main jar with canonical name
    from(buildJar) { rename { "cryptad.jar" } }
    // Include all files required by the wrapper from its lib directory (native libs, etc.)
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/lib") }) {
      include("*")
      // Drop unsupported platforms and Windows libs
      exclude("**/*.dll")
      exclude("**/*aix*")
      exclude("**/*hpux*")
      exclude("**/*solaris*")
      exclude("**/*freebsd*")
      exclude("**/*windows*")
      exclude("**/*-ppcle-*")
      // Drop obvious demo/test artifacts if present
      exclude("**/*demo*.*")
      exclude("**/*test*.*")
      // Drop 32-bit native libraries
      exclude("**/*-x86-32.*")
      exclude("**/*-universal-32.*")
      exclude("**/*-armel-32.*")
      exclude("**/*-armhf-32.*")
      // Generic guard: any "-32." variants
      exclude("**/*-32.*")
    }
    // Ensure a predictable wrapper.jar exists (some packs name it with a version suffix)
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/lib") }) {
      include("wrapper*.jar")
      rename { "wrapper.jar" }
    }
  }

// Generate conf/wrapper.conf from template, injecting classpath lines
val generateWrapperConf by
  tasks.registering {
    group = "distribution"
    description = "Generates conf/wrapper.conf from template"
    dependsOn(prepareWrapperLibs)
    val confDir = wrapperDistDir.map { it.dir("conf") }
    outputs.file(confDir.map { it.file("wrapper.conf") })
    doLast {
      val confDirFile = confDir.get().asFile
      confDirFile.mkdirs()
      val template = file("src/main/templates/wrapper.conf.tpl").readText()
      val confFile = confDirFile.resolve("wrapper.conf")
      confFile.writeText(template)
      println("Generated " + confFile.absolutePath)
    }
  }

// Generate bin/cryptad launcher from template
val generateWrapperLaunchers by
  tasks.registering {
    group = "distribution"
    description = "Generates launch scripts from templates"
    dependsOn(copyWrapperBinaries)
    val binDir = wrapperDistDir.map { it.dir("bin") }
    outputs.files(binDir.map { it.file("cryptad") })
    doLast {
      val bin = binDir.get().asFile
      bin.mkdirs()
      val unix = bin.resolve("cryptad")
      val templateL = file("src/main/templates/cryptad.sh.tpl").readText()
      unix.writeText(templateL)
      unix.setExecutable(true)
    }
  }

// Top-level task to assemble the distribution tree under build/cryptad-dist
val assembleCryptadDist by
  tasks.registering {
    group = "distribution"
    description = "Assembles a portable Cryptad distribution under build/cryptad-dist"
    dependsOn(
      copyWrapperBinaries,
      prepareWrapperLibs,
      generateWrapperConf,
      generateWrapperLaunchers,
    )
    doLast {
      println("Cryptad distribution assembled at: ${wrapperDistDir.get().asFile.absolutePath}")
    }
  }

// Clean the cryptad-dist directory before assembling to avoid stale files
val cleanCryptadDist by
  tasks.registering(Delete::class) {
    group = "distribution"
    description = "Cleans the Cryptad distribution directory"
    delete(wrapperDistDir)
    // Backward cleanup of obsolete directory name from earlier builds
    delete(layout.buildDirectory.dir("wrapper-dist"))
  }

// Ensure cleaning runs before copying/creating files
tasks.named("assembleCryptadDist") { dependsOn(cleanCryptadDist) }

copyWrapperBinaries { dependsOn(cleanCryptadDist) }

prepareWrapperLibs { dependsOn(cleanCryptadDist) }

generateWrapperConf { dependsOn(cleanCryptadDist) }

generateWrapperLaunchers { dependsOn(cleanCryptadDist) }

// Package the cryptad-dist as a tar.gz
tasks.register<Tar>("distTarCryptad") {
  group = "distribution"
  description = "Packages the Cryptad distribution as a tar.gz"
  dependsOn(assembleCryptadDist)
  compression = Compression.GZIP
  archiveBaseName.set("cryptad-dist")
  archiveVersion.set(project.version.toString())
  from(wrapperDistDir)
  destinationDirectory.set(layout.buildDirectory.dir("distributions"))
}

// Diagnostic task to print resolved directories
// Use ./gradlew printDirs -Dcryptad.service.mode=service to print service dirs, you may need sudo
// permission
tasks.register<JavaExec>("printDirs") {
  group = "help"
  description = "Print resolved Cryptad directories (config, data, cache, run, logs)"
  dependsOn("classes")
  mainClass.set("network.crypta.tools.PrintDirsKt")
  classpath = sourceSets.main.get().runtimeClasspath
  systemProperties(gradle.startParameter.systemPropertiesArgs)
}

val copyResourcesToClasses2 by
  tasks.registering {
    inputs.files(sourceSets["main"].allSource)
    outputs.dir(layout.buildDirectory.dir("classes/java/main/"))
    dependsOn(generateVersionSource)
    doLast {
      copy {
        from(sourceSets["main"].allSource)
        into(layout.buildDirectory.dir("classes/java/main/"))
        include("network/crypta/l10n/*properties")
        include("network/crypta/l10n/iso-*.tab")
        include("network/crypta/clients/http/staticfiles/**")
        include("network/crypta/clients/http/templates/**")
        include("../dependencies.properties")
      }
      copy {
        from(projectDir)
        into(layout.buildDirectory.dir("classes/java/main/"))
        include("dependencies.properties")
      }
    }
  }

tasks.processResources {
  dependsOn(copyResourcesToClasses2)
  // Include generated seednodes file in resources under seednodes/seednodes.fref
  dependsOn(generateSeednodesFile)
  from(seednodesOut) {
    into("seednodes")
    rename { "seednodes.fref" }
  }
}

val copyTestResourcesToClasses2 by
  tasks.registering {
    inputs.files(sourceSets["test"].allSource)
    outputs.dir(layout.buildDirectory.dir("classes/java/test/"))
    doLast {
      copy {
        from(sourceSets["test"].allSource)
        into(layout.buildDirectory.dir("classes/java/test/"))
        include("network/crypta/client/filter/*/**")
        include("network/crypta/crypt/ciphers/rijndael-gladman-test-data/**")
        include("network/crypta/l10n/*properties")
        include("network/crypta/clients/http/templates/**")
      }
    }
  }

tasks.compileTestJava { dependsOn(copyResourcesToClasses2, copyTestResourcesToClasses2) }

tasks.test {
  if (JavaVersion.current() >= JavaVersion.VERSION_1_9) {
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util.zip=ALL-UNNAMED")
  }
  minHeapSize = "128m"
  maxHeapSize = "512m"
  include("network/crypta/**/*Test.class")
  exclude("network/crypta/**/*$*Test.class")
  systemProperties.putAll(mapOf<String, Any>())
}

tasks.withType<Test> { enableAssertions = false }

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      groupId = "org.freenetproject"
      artifactId = "fred"
      version = gitrev
      from(components["java"])
    }
  }
  repositories {
    maven {
      url = uri("s3://mvn.freenetproject.org/")
      credentials(AwsCredentials::class) {
        accessKey = System.getenv("AWS_ACCESS_KEY_ID")
        secretKey = System.getenv("AWS_SECRET_ACCESS_KEY")
      }
    }
  }
}

val copyRuntimeLibs by
  tasks.registering(Copy::class) {
    into("${layout.buildDirectory.get()}/output/")
    from(configurations.runtimeClasspath)
    from(tasks.jar)
  }

copyRuntimeLibs { dependsOn(tasks.jar) }

dependencies {
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  runtimeOnly(files("libs/db4o-7.4.58.jar"))
  implementation(files("libs/wrapper.jar"))
  implementation(libs.pebble)
  implementation(libs.unbescape)
  implementation(libs.slf4jApi)
  // CLI parsing and UX
  implementation("info.picocli:picocli:4.7.7")

  testImplementation(libs.junit4)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.hamcrest)
  testImplementation(libs.objenesis)
}

tasks.register<Tar>("tar") {
  group = "distribution"
  description =
    "Build a source release, specifically excluding the build directories and gradle wrapper files"
  compression = Compression.BZIP2
  archiveBaseName.set("freenet-sources")
  from(project.rootDir) {
    exclude("**/build")
    exclude("build")
    exclude(".gradle")
  }
  into(archiveBaseName.get())
  isPreserveFileTimestamps = true
  isReproducibleFileOrder = true
  destinationDirectory.set(layout.buildDirectory)
  archiveFileName.set("${archiveBaseName.get()}.tgz")
  doLast {
    ant.invokeMethod(
      "checksum",
      mapOf("file" to "${destinationDirectory.get()}/${archiveFileName.get()}"),
    )
  }
}

tasks.javadoc { isFailOnError = false }
