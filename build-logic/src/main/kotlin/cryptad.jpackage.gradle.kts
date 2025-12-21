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
    // Copy all standard resources (icons, platform assets, docs)
    from(layout.projectDirectory.dir("src/jpackage"))
    // Linux maintainer scripts for DEB detection are placed at resource root
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("preinst", "prerm", "postinst", "postrm", "postinstall", "postuninstall")
      into("")
    }
    // Shared helper library for maintainer scripts
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("crypta-common.sh")
      into("lib")
    }
    // For RPM: jpackage supports overriding its spec via a file named
    // "<package-name>.spec" in the resource dir (package-name defaults to the application
    // name lowercased; here it is "crypta"). Include our customized spec. We also copy
    // template.spec for completeness, but the concrete package spec takes precedence.
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("crypta.spec", "template.spec")
      into("")
    }
    // RPM payload: place the systemd unit under lib/systemd/system within the resource dir so
    // the spec template copies it into /lib/systemd/system during %install.
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("cryptad.service")
      // Also stage the headless core installer template unit alongside the main service
      include("cryptad-core-install@.service")
      into("lib/systemd/system")
    }
    // Headless core installer script and polkit rule used by post-install scripts (DEB/RPM)
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("cryptad-core-install.sh")
      into("lib")
    }
    from(layout.projectDirectory.dir("src/jpackage/linux/polkit-1")) {
      include("60-cryptad-core-install.rules")
      into("lib/polkit-1")
    }
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

      // Ensure Linux maintainer scripts are executable when present
      if (currentOs() == "linux") {
        val res = jpackageResourcesDir.get().asFile
        listOf(
            "preinst",
            "prerm",
            "postinst",
            "postrm",
            "postinstall",
            "postuninstall",
            "lib/crypta-common.sh",
            "lib/cryptad-core-install.sh",
          )
          .map { File(res, it) }
          .filter { it.isFile }
          .forEach { it.setExecutable(true, true) }
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

/**
 * Picks installer type for the current OS; Windows intentionally unsupported. On Linux, supports
 * override via `-PlinuxInstaller=<deb|rpm>` or env `CRYPTA_LINUX_INSTALLER`. Defaults to preferring
 * rpm when both tools are present.
 */
fun resolveInstallerType(os: String): String =
  when (os) {
    "mac" -> "dmg"
    else -> {
      val override =
        (providers.gradleProperty("linuxInstaller").orNull
            ?: System.getenv("CRYPTA_LINUX_INSTALLER"))
          ?.trim()
          ?.lowercase()
      when (override) {
        "deb" -> "deb"
        "rpm" -> "rpm"
        else ->
          when {
            hasExe("rpmbuild") -> "rpm"
            hasExe("dpkg-deb") -> "deb"
            else -> "deb"
          }
      }
    }
  }

/** Returns absolute icon path for jpackage matching the current OS. */
fun iconPathForOs(): String =
  when (currentOs()) {
    "mac" -> project.file("src/jpackage/macos/cryptad.icns").absolutePath
    "win" -> project.file("src/jpackage/windows/cryptad.ico").absolutePath
    else -> project.file("src/jpackage/linux/cryptad.png").absolutePath
  }

/** Resolves the `jpackage` executable from the Java 25 toolchain. */
fun resolveJpackageExecutable(): File {
  val toolchains = project.extensions.getByType(JavaToolchainService::class.java)
  val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(25)) }
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

      // On macOS, stage the app image under the system temp directory to avoid iCloud/
      // FileProvider extended attributes (FinderInfo) being attached during creation, which
      // makes codesign fail. We then move the completed image back to build/jpackage.
      val destDir =
        if (os == "mac") {
          File(
            System.getProperty("java.io.tmpdir"),
            "crypta-jpackage-${System.currentTimeMillis()}",
          )
        } else outDir
      destDir.mkdirs()

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
          destDir.absolutePath,
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
      try {
        execAndLog(args)
        // If we staged to a temp directory, move the result into the build output dir.
        if (destDir != outDir) {
          val staged = destDir.resolve("$appName.app")
          if (staged.isDirectory) {
            val target = outDir.resolve("$appName.app")
            if (target.exists()) target.deleteRecursively()
            logger.lifecycle("Relocating app image from staging -> {}", target.absolutePath)
            staged.copyRecursively(target, overwrite = true)
            // Best-effort: remove any staging attributes after copy
            try {
              val xattr = File("/usr/bin/xattr")
              if (xattr.canExecute()) {
                ProcessBuilder(xattr.absolutePath, "-cr", target.absolutePath)
                  .redirectErrorStream(true)
                  .start()
                  .waitFor(5, TimeUnit.SECONDS)
              }
            } catch (_: Exception) {}
            destDir.deleteRecursively()
          }
        }
      } catch (e: Exception) {
        // Workaround for macOS codesign failing with FinderInfo xattr on the app bundle root.
        // On some macOS versions, jpackage ad-hoc signs the bundle and codesign rejects
        // com.apple.FinderInfo on the freshly created <App>.app, yielding:
        //   resource fork, Finder information, or similar detritus not allowed
        // If we see a failure and the output image exists, clear xattrs and ad-hoc sign the
        // bundle. When staging is used (destDir != outDir), operate on the staged app and then
        // relocate the fixed bundle into outDir so downstream tasks find it.
        if (os == "mac") {
          val stagedApp = destDir.resolve("$appName.app")
          val finalApp = outDir.resolve("$appName.app")
          val appDir = if (stagedApp.isDirectory) stagedApp else finalApp
          if (appDir.isDirectory) {
            try {
              // Best-effort: remove extended attributes recursively.
              val xattr = File("/usr/bin/xattr")
              if (xattr.canExecute()) {
                val pb = ProcessBuilder(xattr.absolutePath, "-cr", appDir.absolutePath)
                pb.redirectErrorStream(true)
                val p = pb.start()
                val out = p.inputStream.bufferedReader().use { it.readText() }
                p.waitFor(10, TimeUnit.SECONDS)
                logger.lifecycle(
                  "Cleared xattrs on app image (exit ${p.exitValue()}): {}",
                  out.trim(),
                )
              } else {
                logger.warn("xattr tool not available; skipping attribute cleanup")
              }

              // Direct ad-hoc sign the bundle root. jpackage already signed Contents/runtime
              // before failing, so this completes the bundle signature.
              val codesign = File("/usr/bin/codesign")
              if (!codesign.canExecute()) throw GradleException("codesign tool not available")
              val csArgs =
                listOf(codesign.absolutePath, "-s", "-", "-vvvv", "--force", appDir.absolutePath)
              logger.lifecycle(
                "Ad-hoc signing app bundle after xattr cleanup:\n{}",
                csArgs.joinToString(" "),
              )
              execAndLog(csArgs)
              logger.lifecycle("codesign completed; relocating if staged")

              // If we fixed the staged app, relocate it now to the final output dir.
              if (appDir == stagedApp) {
                if (finalApp.exists()) finalApp.deleteRecursively()
                stagedApp.copyRecursively(finalApp, overwrite = true)
                // Remove any staged attrs again just in case
                try {
                  val x = File("/usr/bin/xattr")
                  if (x.canExecute()) {
                    ProcessBuilder(x.absolutePath, "-cr", finalApp.absolutePath)
                      .redirectErrorStream(true)
                      .start()
                      .waitFor(5, TimeUnit.SECONDS)
                  }
                } catch (_: Exception) {}
                // Clean up staging directory
                destDir.deleteRecursively()
                logger.lifecycle("Relocated fixed app image -> {}", finalApp.absolutePath)
              }
            } catch (fixErr: Exception) {
              logger.warn("macOS fallback sign failed: {}", fixErr.message)
              throw e
            }
          } else {
            throw e
          }
        } else {
          throw e
        }
      }
    }
  }

// Copy the assembled portable distribution into the app image as app/cryptad-dist
val enrichAppImageWithDist by
  tasks.registering {
    group = "jpackage"
    description = "Copies cryptad-dist into the jpackage image (mac: Contents/app; linux: lib/app)"
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
      // Where to place the portable distribution inside the app image.
      // jpackage layout differs by OS:
      // - macOS:    Contents/app/
      // - Windows:  app/
      // - Linux:    lib/app/
      val target =
        when (os) {
          "mac" -> appDir.resolve("cryptad-dist")
          "win" -> appDir.resolve("cryptad-dist")
          else -> imageRoot.resolve("lib/app/cryptad-dist")
        }
      target.parentFile.mkdirs()
      copy {
        from(cryptadDistDir)
        into(target)
      }
      logger.lifecycle("Copied cryptad-dist -> {}", target.absolutePath)

      // Ensure Linux uses our provided PNG icon verbatim rather than a downsized copy.
      if (os == "linux") {
        val srcIcon = File(iconPathForOs())
        val dstIcon = imageRoot.resolve("lib/$appName.png")
        try {
          srcIcon.copyTo(dstIcon, overwrite = true)
          logger.lifecycle(
            "Replaced Linux icon -> {} ({} bytes)",
            dstIcon.absolutePath,
            dstIcon.length(),
          )

          // Also place a stable copy and our own .desktop file referencing it, so the desktop
          // entry uses the exact provided icon even if jpackage generates a 32x32 fallback.
          val stableIcon = imageRoot.resolve("lib/cryptad.png")
          srcIcon.copyTo(stableIcon, overwrite = true)
          val desktop = imageRoot.resolve("lib/crypta-$appName.desktop")
          val desktopContent = buildString {
            appendLine("[Desktop Entry]")
            appendLine("Name=$appName")
            appendLine("Comment=$appName")
            appendLine("Exec=/opt/cryptad/crypta/bin/$appName")
            appendLine("Icon=/opt/cryptad/crypta/lib/cryptad.png")
            appendLine("Terminal=false")
            appendLine("Type=Application")
            appendLine("Categories=Network;Utility;")
            appendLine("MimeType=")
            // Ensure GNOME docks associate the window with this entry.
            appendLine("StartupWMClass=network-crypta-launcher-LauncherKt")
            appendLine("X-GNOME-WMClass=network-crypta-launcher-LauncherKt")
          }
          desktop.writeText(desktopContent)
          logger.lifecycle("Wrote Linux desktop entry -> {}", desktop.absolutePath)
        } catch (e: Exception) {
          logger.warn("Failed to finalize Linux icon/desktop: {}", e.message)
        }

        // Also stage systemd units and helper artifacts under lib/ so installers and
        // post-install scripts can find them inside the app image.
        try {
          val serviceSrc = project.file("src/jpackage/linux/cryptad.service")
          if (serviceSrc.isFile) {
            val serviceDst = imageRoot.resolve("lib/systemd/system/cryptad.service")
            serviceDst.parentFile.mkdirs()
            serviceSrc.copyTo(serviceDst, overwrite = true)
            logger.lifecycle("Staged systemd unit -> {}", serviceDst.absolutePath)
          } else {
            logger.warn("Missing systemd unit at {}", serviceSrc.absolutePath)
          }
        } catch (e: Exception) {
          logger.warn("Failed to copy systemd unit: {}", e.message)
        }

        // Stage headless core installer template unit
        try {
          val helperUnitSrc = project.file("src/jpackage/linux/cryptad-core-install@.service")
          if (helperUnitSrc.isFile) {
            val helperUnitDst =
              imageRoot.resolve("lib/systemd/system/cryptad-core-install@.service")
            helperUnitDst.parentFile.mkdirs()
            helperUnitSrc.copyTo(helperUnitDst, overwrite = true)
            logger.lifecycle("Staged core-install unit -> {}", helperUnitDst.absolutePath)
          } else {
            logger.warn("Missing core-install unit at {}", helperUnitSrc.absolutePath)
          }
        } catch (e: Exception) {
          logger.warn("Failed to copy core-install unit: {}", e.message)
        }

        // Stage headless core installer script
        try {
          val helperScriptSrc = project.file("src/jpackage/linux/cryptad-core-install.sh")
          if (helperScriptSrc.isFile) {
            val helperScriptDst = imageRoot.resolve("lib/cryptad-core-install.sh")
            helperScriptDst.parentFile.mkdirs()
            helperScriptSrc.copyTo(helperScriptDst, overwrite = true)
            helperScriptDst.setExecutable(true, true)
            logger.lifecycle("Staged core-install script -> {}", helperScriptDst.absolutePath)
          } else {
            logger.warn("Missing core-install script at {}", helperScriptSrc.absolutePath)
          }
        } catch (e: Exception) {
          logger.warn("Failed to copy core-install script: {}", e.message)
        }

        // Stage polkit rule to allow controlled start of the oneshot helper
        try {
          val polkitSrc = project.file("src/jpackage/linux/polkit-1/60-cryptad-core-install.rules")
          if (polkitSrc.isFile) {
            val polkitDst = imageRoot.resolve("lib/polkit-1/60-cryptad-core-install.rules")
            polkitDst.parentFile.mkdirs()
            polkitSrc.copyTo(polkitDst, overwrite = true)
            logger.lifecycle("Staged polkit rule -> {}", polkitDst.absolutePath)
          } else {
            logger.warn("Missing polkit rule at {}", polkitSrc.absolutePath)
          }
        } catch (e: Exception) {
          logger.warn("Failed to copy polkit rule: {}", e.message)
        }
      }

      // Patch the jpackage launcher config to point classpath to cryptad-dist/lib and correct main
      // class.
      val cfg =
        when (os) {
          // macOS: cfg lives under Contents/app
          "mac" -> appDir.resolve("$appName.cfg")
          // Windows: cfg lives under app/
          "win" -> appDir.resolve("$appName.cfg")
          // Linux: cfg lives under lib/app
          else -> imageRoot.resolve("lib/app/$appName.cfg")
        }
      if (cfg.isFile) {
        // Compose a fresh config that keeps only the sections we need.
        val out = mutableListOf<String>()
        out += "[Application]"
        out += "app.mainclass=network.crypta.launcher.LauncherKt"
        // Add classpath entries for jars under cryptad-dist/lib
        val jarDir = target.resolve("lib")
        val jars =
          jarDir.listFiles { f -> f.isFile && f.name.endsWith(".jar") }?.sortedBy { it.name }
        val cpPrefix =
          if (os == "linux") "\$APPDIR/cryptad-dist/lib/" else "\$APPDIR/cryptad-dist/lib/"
        out += "app.classpath=${cpPrefix}cryptad.jar"
        jars
          ?.filter { it.name != "cryptad.jar" }
          ?.forEach { f -> out += "app.classpath=${cpPrefix}${f.name}" }
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
      if (os == "linux") {
        // Install under a stable path used by our service/scripts and tests
        args.addAll(listOf("--install-dir", "/opt/cryptad"))
      }
      // Also pass icon for installer builds so the packaged icon matches our provided file.
      args.addAll(listOf("--icon", iconPathForOs()))

      logger.lifecycle("Executing jpackage installer:\n{}", args.joinToString(" "))
      execAndLog(args)

      // Keep jpackage default filenames (e.g., Crypta-<version>.<ext>)
    }
  }

// Explicit Linux installer tasks to force a specific package type
val jpackageInstallerRpm by
  tasks.registering {
    group = "jpackage"
    description = "Creates an RPM installer for Linux"
    dependsOn(enrichAppImageWithDist)
    onlyIf { currentOs() == "linux" && hasExe("rpmbuild") }
    doLast {
      val jpackage = resolveJpackageExecutable()
      val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
      val imagePath = outDir.resolve(appName).absolutePath
      val args =
        mutableListOf(
          jpackage.absolutePath,
          "--type",
          "rpm",
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
          "--install-dir",
          "/opt/cryptad",
        )
      // jpackage (JDK 25) does not accept linux post-install flags here; use template.spec
      // override.
      args.addAll(listOf("--icon", iconPathForOs()))
      if (providers.gradleProperty("jpackageDebug").orNull == "true") args += "--verbose"
      logger.lifecycle("Executing jpackage RPM installer:\n{}", args.joinToString(" "))
      execAndLog(args)
    }
  }

val jpackageInstallerDeb by
  tasks.registering {
    group = "jpackage"
    description = "Creates a DEB installer for Linux"
    dependsOn(enrichAppImageWithDist)
    onlyIf { currentOs() == "linux" && hasExe("dpkg-deb") }
    doLast {
      val jpackage = resolveJpackageExecutable()
      val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
      val imagePath = outDir.resolve(appName).absolutePath
      val args =
        mutableListOf(
          jpackage.absolutePath,
          "--type",
          "deb",
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
          "--install-dir",
          "/opt/cryptad",
        )
      // Scripts handled via resource-dir (postinst/postrm) for DEB.
      args.addAll(listOf("--icon", iconPathForOs()))
      if (providers.gradleProperty("jpackageDebug").orNull == "true") args += "--verbose"
      logger.lifecycle("Executing jpackage DEB installer:\n{}", args.joinToString(" "))
      execAndLog(args)
    }
  }

// Convenience task to build all Linux installers available on the host
val jpackageInstallerLinuxAll by
  tasks.registering {
    group = "jpackage"
    description = "Builds all supported Linux installers (deb/rpm)"
    dependsOn(jpackageInstallerDeb)
    dependsOn(jpackageInstallerRpm)
    onlyIf { currentOs() == "linux" && (hasExe("dpkg-deb") || hasExe("rpmbuild")) }
  }

// Windows MSI installer task removed

// Windows EXE installer task removed

// Aggregate Windows installer task removed

// WiX relink task removed

// Ensure the built app image is fully usable by default builds
// (copies cryptad-dist into the image and patches launcher cfg).
tasks.named("build") {
  dependsOn(enrichAppImageWithDist)
  // On Linux, also build native installers (DEB/RPM) when the host has the tools.
  if (currentOs() == "linux") {
    dependsOn(jpackageInstallerLinuxAll)
  }
  // On macOS, also build a DMG installer.
  if (currentOs() == "mac") {
    dependsOn(jpackageInstallerCryptad)
  }
}
