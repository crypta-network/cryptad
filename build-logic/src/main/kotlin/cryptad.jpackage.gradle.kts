import java.util.jar.JarOutputStream as JJarOutputStream
import java.util.jar.Manifest as JManifest

plugins { java }

/**
 * JPackage integration for Crypta, matching the repo’s custom build style.
 * - Reuses the jlink image produced by cryptad.runtime (build/jre)
 * - Creates an app image via `jpackage --type app-image`
 * - Optionally builds native installers via `jpackage --type <os-default>`
 * - Copies the portable node layout (build/cryptad-dist) into the app image under app/cryptad-dist
 * - Prepares standard resources (LICENSE.txt, EULA.txt, README.txt) from project root
 *
 * This file intentionally avoids duplicating jars under the jpackage image; instead a tiny
 * bootstrap jar is created so we can later rewrite `Crypta.cfg` to reference the jars under
 * `app/cryptad-dist/lib/` + `*.jar` as the runtime classpath.
 */
val jreDir = layout.buildDirectory.dir("jre")
val cryptadDistDir = layout.buildDirectory.dir("cryptad-dist")
val jpackageOutDir = layout.buildDirectory.dir("jpackage")
val jpackageResourcesDir = layout.buildDirectory.dir("jpackage/resources")
val jpackageInputDir = layout.buildDirectory.dir("jpackage/input")

// Compute version string: v<project.version>+<gitRevShort>
fun gitRevShort(): String =
  try {
    val pb = ProcessBuilder("git", "rev-parse", "--short", "HEAD")
    pb.directory(project.rootDir)
    pb.redirectErrorStream(true)
    val p = pb.start()
    p.waitFor(5, TimeUnit.SECONDS)
    val s = p.inputStream.bufferedReader().use { it.readText() }.trim()
    if (p.exitValue() == 0 && s.isNotBlank()) s else "unknown"
  } catch (_: Exception) {
    "unknown"
  }

val appName = "Crypta"
val vendor = "crypta.network"
val appId = "network.crypta.cryptad"

// Windows installer support removed; no UpgradeCode needed.

// jpackage --app-version is strict (e.g., macOS CFBundleVersion must be 1..3 integers separated by
// dots).
/** Returns a numeric app version accepted by jpackage (platform compliant). */
fun numericAppVersion(): String {
  val raw = project.version.toString()
  val m = Regex("\\d+(?:\\.\\d+){0,3}").find(raw)
  var v = (m?.value ?: raw.filter { it.isDigit() }.ifBlank { "1" })
  // Windows installers (MSI/EXE) require 2..4 components in ProductVersion
  if (currentOs() == "win") {
    val parts = v.split('.')
    v =
      when {
        parts.size < 2 -> parts.firstOrNull()?.let { "$it.0" } ?: "1.0"
        parts.size > 4 -> parts.take(4).joinToString(".")
        else -> v
      }
  }
  return v
}

// Prepare resources for jpackage from root files and src/jpackage assets
val prepareJpackageResources by
  tasks.registering(Sync::class) {
    group = "jpackage"
    description = "Collects jpackage resources (icons + legal docs) into build/jpackage/resources"
    from(layout.projectDirectory.dir("src/jpackage"))
    // LICENSE -> LICENSE.txt and EULA.txt; README.md -> README.txt
    from(layout.projectDirectory.file("LICENSE")) { rename { "LICENSE.txt" } }
    from(layout.projectDirectory.file("LICENSE")) { rename { "EULA.txt" } }
    from(layout.projectDirectory.file("README.md")) { rename { "README.txt" } }
    into(jpackageResourcesDir)

    // Fail early if icon for current OS is missing (helps local dev)
    doLast {
      val icon = File(iconPathForOs())
      if (!icon.isFile) {
        throw GradleException("Required jpackage icon not found: ${icon.absolutePath}")
      }
    }
  }

// Helper resolving OS and icon path
/** Detects the current OS as a stable token: mac|win|linux. */
fun currentOs(): String {
  val os = org.gradle.internal.os.OperatingSystem.current()
  return when {
    os.isMacOsX -> "mac"
    os.isWindows -> "win"
    else -> "linux"
  }
}

/** Checks if an executable exists on PATH using platform-appropriate command. */
fun hasExe(name: String): Boolean =
  try {
    val pb =
      ProcessBuilder(
        if (org.gradle.internal.os.OperatingSystem.current().isWindows) listOf("where", name)
        else listOf("which", name)
      )
    pb.redirectErrorStream(true)
    val p = pb.start()
    p.waitFor(3, TimeUnit.SECONDS)
    p.exitValue() == 0
  } catch (_: Exception) {
    false
  }

/** Picks installer type for the current OS; Windows intentionally unsupported. */
fun resolveInstallerType(os: String): String =
  when (os) {
    "mac" -> "dmg"
    else -> if (hasExe("dpkg-deb")) "deb" else if (hasExe("rpmbuild")) "rpm" else "deb"
  }

/** Returns absolute icon path for jpackage matching the current OS. */
fun iconPathForOs(): String =
  when (currentOs()) {
    "mac" -> project.file("src/jpackage/macos/cryptad.icns").absolutePath
    "win" -> project.file("src/jpackage/windows/cryptad.ico").absolutePath
    else -> project.file("src/jpackage/linux/cryptad.png").absolutePath
  }

/** Resolves the `jpackage` executable from the Java 21 toolchain. */
fun resolveJpackageExecutable(): File {
  val toolchains = project.extensions.getByType(JavaToolchainService::class.java)
  val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
  val javaHome = launcher.get().metadata.installationPath.asFile
  val exe =
    javaHome.resolve(
      "bin/jpackage" +
        if (org.gradle.internal.os.OperatingSystem.current().isWindows) ".exe" else ""
    )
  if (!exe.isFile) throw GradleException("jpackage not found in toolchain: $exe")
  return exe
}

/** Deletes any pre-existing output image folder for a clean jpackage run. */
fun cleanExistingImage(outDir: File, os: String) {
  val existing =
    when (os) {
      "mac" -> outDir.resolve("$appName.app")
      else -> outDir.resolve(appName)
    }
  if (existing.exists()) existing.deleteRecursively()
}

/** Creates a minimal bootstrap jar under the provided input dir and returns its file. */
fun createBootstrapJar(inputDir: File): File {
  if (inputDir.exists()) inputDir.deleteRecursively()
  inputDir.mkdirs()
  val stagedMain = File(inputDir, "bootstrap.jar")
  val mf = JManifest()
  mf.mainAttributes.putValue("Manifest-Version", "1.0")
  JJarOutputStream(stagedMain.outputStream(), mf).use { /* empty */ }
  return stagedMain
}

/** Executes a command and streams output; throws on non-zero exit. */
fun execAndLog(args: List<String>) {
  val pb = ProcessBuilder(args)
  pb.redirectErrorStream(true)
  val p = pb.start()
  val output = p.inputStream.bufferedReader().use { it.readText() }
  val code = p.waitFor()
  logger.lifecycle(output.trim())
  if (code != 0) throw GradleException("Command failed ($code): ${args.joinToString(" ")}")
}

// WiX helper removed with Windows installers.

// Build an app image using the toolchain JDK's jpackage
val jpackageImageCryptad by
  tasks.registering {
    group = "jpackage"
    description = "Creates a jpackage app image for Crypta into build/jpackage"
    dependsOn(tasks.named("createJreImage")) // from cryptad.runtime
    dependsOn(tasks.named("assembleCryptadDist")) // from cryptad.distribution
    dependsOn(prepareJpackageResources)

    doLast {
      val jpackage = resolveJpackageExecutable()
      val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
      val os = currentOs()
      val imageName = appName
      val mainClass = "network.crypta.launcher.LauncherKt"

      // We'll point jpackage at our distribution lib dir for the classpath and main jar
      val libDir = cryptadDistDir.get().dir("lib").asFile
      val mainJar = libDir.resolve("cryptad.jar")
      if (!mainJar.isFile) throw GradleException("Missing main JAR at ${mainJar.absolutePath}")

      val inputDir = jpackageInputDir.get().asFile
      val stagedMain = createBootstrapJar(inputDir)

      // Ensure we start from a clean target (jpackage fails if image exists)
      cleanExistingImage(outDir, os)

      val args =
        mutableListOf(
          jpackage.absolutePath,
          "--type",
          "app-image",
          "--name",
          imageName,
          "--app-version",
          numericAppVersion(),
          "--dest",
          outDir.absolutePath,
          "--input",
          inputDir.absolutePath,
          "--main-jar",
          stagedMain.name,
          "--main-class",
          mainClass,
          "--runtime-image",
          jreDir.get().asFile.absolutePath,
          "--resource-dir",
          jpackageResourcesDir.get().asFile.absolutePath,
          "--icon",
          iconPathForOs(),
        )

      // App-image stage must avoid installer-only flags. Do not pass platform-specific
      // packaging options here (e.g., --linux-shortcut, --mac-package-identifier) because
      // jpackage rejects them with --type app-image. Such options are added in the installer task.

      logger.lifecycle("Executing jpackage app-image:\n{}", args.joinToString(" "))
      execAndLog(args)
    }
  }

// Copy the assembled portable distribution into the app image as app/cryptad-dist
val enrichAppImageWithDist by
  tasks.registering {
    group = "jpackage"
    description = "Copies build/cryptad-dist into the jpackage app image under app/cryptad-dist"
    dependsOn(jpackageImageCryptad)
    doLast {
      val os = currentOs()
      val root = jpackageOutDir.get().asFile
      val imageRoot =
        when (os) {
          "mac" -> root.resolve("$appName.app/Contents")
          else -> root.resolve(appName)
        }
      val appDir = imageRoot.resolve("app")
      val target = appDir.resolve("cryptad-dist")
      target.parentFile.mkdirs()
      copy {
        from(cryptadDistDir)
        into(target)
      }
      logger.lifecycle("Copied cryptad-dist -> {}", target.absolutePath)

      // Patch the jpackage launcher config to point classpath to cryptad-dist/lib and correct main
      // class.
      val cfg = appDir.resolve("$appName.cfg")
      if (cfg.isFile) {
        // Compose a fresh config that keeps only the sections we need.
        val out = mutableListOf<String>()
        out += "[Application]"
        out += "app.mainclass=network.crypta.launcher.LauncherKt"
        // Add classpath entries for jars under cryptad-dist/lib
        val jarDir = target.resolve("lib")
        val jars =
          jarDir.listFiles { f -> f.isFile && f.name.endsWith(".jar") }?.sortedBy { it.name }
        out += "app.classpath=\$APPDIR/cryptad-dist/lib/cryptad.jar"
        jars
          ?.filter { it.name != "cryptad.jar" }
          ?.forEach { f -> out += "app.classpath=\$APPDIR/cryptad-dist/lib/${f.name}" }
        out += ""
        out += "[JavaOptions]"
        out += "java-options=-Djpackage.app-version=${numericAppVersion()}"
        cfg.writeText(out.joinToString(System.lineSeparator()))
        logger.lifecycle("Patched launcher cfg -> {}", cfg.absolutePath)
      } else {
        logger.warn("Launcher cfg not found at {}", cfg.absolutePath)
      }
    }
  }

// Build OS-native installer (dmg/msi/deb) using the image created above.
val jpackageInstallerCryptad by
  tasks.registering {
    group = "jpackage"
    description = "Creates a native installer for the current OS"
    dependsOn(enrichAppImageWithDist)
    onlyIf {
      when (currentOs()) {
        "linux" -> hasExe("dpkg-deb") || hasExe("rpmbuild")
        "win" -> false // Windows installers removed
        else -> true
      }
    }
    doLast {
      val jpackage = resolveJpackageExecutable()
      val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }

      val os = currentOs()
      val installerType = resolveInstallerType(os)
      val imagePath =
        when (os) {
          "mac" -> outDir.resolve("$appName.app").absolutePath
          else -> outDir.resolve(appName).absolutePath
        }

      val args =
        mutableListOf(
          jpackage.absolutePath,
          "--type",
          installerType,
          "--name",
          appName,
          "--app-version",
          numericAppVersion(),
          "--dest",
          outDir.absolutePath,
          "--resource-dir",
          jpackageResourcesDir.get().asFile.absolutePath,
          "--app-image",
          imagePath,
          "--vendor",
          vendor,
        )
      if (providers.gradleProperty("jpackageDebug").orNull == "true") args += "--verbose"
      if (os == "mac") args.addAll(listOf("--mac-package-identifier", appId))
      if (os == "linux") args.addAll(listOf("--linux-shortcut", "--linux-menu-group", "Network;Utility;"))

      logger.lifecycle("Executing jpackage installer:\n{}", args.joinToString(" "))
      execAndLog(args)

      // Keep jpackage default filenames (e.g., Crypta-<version>.<ext>)
    }
  }

// Windows MSI installer task removed

// Windows EXE installer task removed

// Aggregate Windows installer task removed

// WiX relink task removed

// Ensure the built app image is fully usable by default builds
// (copies cryptad-dist into the image and patches launcher cfg).
tasks.named("build") { dependsOn(enrichAppImageWithDist) }
