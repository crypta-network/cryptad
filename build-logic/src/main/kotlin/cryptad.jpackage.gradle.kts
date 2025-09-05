import java.util.concurrent.TimeUnit
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import org.gradle.kotlin.dsl.support.serviceOf
import org.gradle.process.ExecOperations

plugins { java }

/**
 * JPackage integration for Crypta, matching the repo’s custom build style.
 * - Reuses the jlink image produced by cryptad.runtime (build/jre)
 * - Creates an app image via `jpackage --type app-image`
 * - Optionally builds native installers via `jpackage --type <os-default>`
 * - Copies the portable node layout (build/cryptad-dist) into the app image under app/cryptad-dist
 * - Prepares standard resources (LICENSE.txt, EULA.txt, README.txt) from project root
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
  } catch (e: Exception) {
    "unknown"
  }

val appName = "Crypta"
val vendor = "crypta.network"
val appId = "network.crypta.cryptad"
val appVersionLabel = providers.provider { "v${project.version}+${gitRevShort()}" }

// jpackage --app-version is strict (e.g., macOS CFBundleVersion must be 1..3 integers separated by
// dots).
fun numericAppVersion(): String {
  val raw = project.version.toString()
  val m = Regex("\\d+(?:\\.\\d+){0,3}").find(raw)
  return (m?.value ?: raw.filter { it.isDigit() }.ifBlank { "1" })
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
  }

// Helper resolving OS and icon path
fun currentOs(): String {
  val os = org.gradle.internal.os.OperatingSystem.current()
  return when {
    os.isMacOsX -> "mac"
    os.isWindows -> "win"
    else -> "linux"
  }
}

fun hasExe(name: String): Boolean =
  try {
    val pb = ProcessBuilder(if (org.gradle.internal.os.OperatingSystem.current().isWindows) listOf("where", name) else listOf("which", name))
    pb.redirectErrorStream(true)
    val p = pb.start()
    p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
    p.exitValue() == 0
  } catch (_: Exception) { false }

fun resolveInstallerType(os: String): String =
  when (os) {
    "mac" -> "dmg"
    "win" -> if (hasExe("candle.exe") && hasExe("light.exe")) "msi" else "exe"
    else -> if (hasExe("dpkg-deb")) "deb" else if (hasExe("rpmbuild")) "rpm" else "deb"
  }

fun iconPathForOs(): String =
  when (currentOs()) {
    "mac" -> project.file("src/jpackage/macos/cryptad.icns").absolutePath
    "win" -> project.file("src/jpackage/windows/cryptad.ico").absolutePath
    else -> project.file("src/jpackage/linux/cryptad.png").absolutePath
  }

// Build an app image using the toolchain JDK's jpackage
val jpackageImageCryptad by
  tasks.registering {
    group = "jpackage"
    description = "Creates a jpackage app image for Crypta into build/jpackage"
    dependsOn(tasks.named("createJreImage")) // from cryptad.runtime
    dependsOn(tasks.named("assembleCryptadDist")) // from cryptad.distribution
    dependsOn(prepareJpackageResources)

    doLast {
      val toolchains = project.serviceOf<JavaToolchainService>()
      val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
      val javaHome = launcher.get().metadata.installationPath.asFile
      val jpackage =
        javaHome.resolve(
          "bin/jpackage" +
            if (org.gradle.internal.os.OperatingSystem.current().isWindows) ".exe" else ""
        )
      if (!jpackage.isFile) throw GradleException("jpackage not found in toolchain: ${jpackage}")

      val outDir = jpackageOutDir.get().asFile
      outDir.mkdirs()

      val os = currentOs()
      val iconArg = listOf("--icon", iconPathForOs())
      val imageName = appName
      val mainClass = "network.crypta.launcher.LauncherKt"

      // We'll point jpackage at our distribution lib dir for the classpath and main jar
      val libDir = cryptadDistDir.get().dir("lib").asFile
      val mainJar = libDir.resolve("cryptad.jar")
      if (!mainJar.isFile) throw GradleException("Missing main JAR at ${mainJar.absolutePath}")

      // Create a tiny bootstrap JAR so jpackage has a --main-jar without copying cryptad.jar
      val inputDir = jpackageInputDir.get().asFile
      if (inputDir.exists()) inputDir.deleteRecursively()
      inputDir.mkdirs()
      val stagedMain = File(inputDir, "bootstrap.jar")
      val mf = Manifest()
      mf.mainAttributes.putValue("Manifest-Version", "1.0")
      JarOutputStream(stagedMain.outputStream(), mf).use { /* empty */ }

      // Ensure we start from a clean target (jpackage fails if image exists)
      run {
        val existing =
          when (os) {
            "mac" -> outDir.resolve("$appName.app")
            else -> outDir.resolve(appName)
          }
        if (existing.exists()) existing.deleteRecursively()
      }

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
        )
      args.addAll(iconArg)

      // OS-specific tweaks
      when (os) {
        "mac" -> {
          args.addAll(listOf("--mac-package-identifier", appId))
        }
        "linux" -> {
          args.addAll(listOf("--linux-shortcut", "--linux-menu-group", "Network;Utility;"))
        }
        "win" -> {
          // No code signing; add menu + shortcut
          args.addAll(listOf("--win-menu", "--win-shortcut"))
        }
      }

      println("Executing jpackage app-image:\n" + args.joinToString(" "))
      project.serviceOf<ExecOperations>().exec { commandLine(args) }
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
      println("Copied cryptad-dist -> ${target.absolutePath}")

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
        println("Patched launcher cfg -> ${cfg.absolutePath}")
      } else {
        println("WARNING: launcher cfg not found at ${cfg.absolutePath}")
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
        else -> true
      }
    }
    doLast {
      val toolchains = project.serviceOf<JavaToolchainService>()
      val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
      val javaHome = launcher.get().metadata.installationPath.asFile
      val jpackage =
        javaHome.resolve(
          "bin/jpackage" +
            if (org.gradle.internal.os.OperatingSystem.current().isWindows) ".exe" else ""
        )
      if (!jpackage.isFile) throw GradleException("jpackage not found in toolchain: ${jpackage}")

      val outDir = jpackageOutDir.get().asFile
      outDir.mkdirs()

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
      // Ensure a stable bundle identifier on macOS
      if (os == "mac") args.addAll(listOf("--mac-package-identifier", appId))
      println("Executing jpackage installer:\n" + args.joinToString(" "))
      project.serviceOf<ExecOperations>().exec { commandLine(args) }

      // Rename the produced installer to include the user-facing version label (v<ver>+<git>)
      val produced = File(outDir, "${appName}-${numericAppVersion()}.${installerType}")
      if (produced.isFile) {
        val labeled = File(outDir, "${appName}-${appVersionLabel.get()}.${produced.extension}")
        produced.copyTo(labeled, overwrite = true)
        println("Renamed installer -> ${labeled.name}")
      } else {
        println(
          "Note: could not find produced installer ${produced.name} to relabel; leaving default name."
        )
      }
    }
  }

// Convenience lifecycle tasks
tasks.register("jpackageAll") {
  group = "jpackage"
  description = "Builds app image and OS installer"
  dependsOn(jpackageInstallerCryptad)
}

// Ensure standard build also creates the jpackage app image and installer (best effort on Linux).
tasks.named("build") {
  dependsOn(jpackageImageCryptad)
  dependsOn(jpackageInstallerCryptad)
}
