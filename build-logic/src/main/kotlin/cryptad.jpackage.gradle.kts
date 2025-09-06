import java.awt.Image
import java.awt.image.BufferedImage
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import javax.imageio.ImageIO
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

    // Windows-specific resource wiring
    doLast {
      // Map custom Windows assets to what jpackage/WiX expect
      val os = currentOs()
      if (os == "win") {
        val resDir = jpackageResourcesDir.get().asFile
        val winDir = File(resDir, "windows").apply { mkdirs() }

        // 1) WixUIDialogBmp: place at windows/images/WixStdDialog.bmp so WiX uses it
        run {
          val src =
            project.layout.projectDirectory
              .file("src/jpackage/windows/CryptaInstall_Dialog.bmp")
              .asFile
          if (src.isFile) {
            val dst = File(winDir, "images/WixStdDialog.bmp")
            dst.parentFile.mkdirs()
            // Convert to WiX-friendly BMP (BMP3, 493x312, 24-bit) to avoid silent fallback
            try {
              val img = ImageIO.read(src)
              if (img != null) {
                val targetW = 493
                val targetH = 312
                val scaled = BufferedImage(targetW, targetH, BufferedImage.TYPE_3BYTE_BGR)
                val g = scaled.createGraphics()
                try {
                  g.drawImage(
                    img.getScaledInstance(targetW, targetH, Image.SCALE_SMOOTH),
                    0,
                    0,
                    null,
                  )
                } finally {
                  g.dispose()
                }
                ImageIO.write(scaled, "bmp", dst)
              } else {
                // Fallback: raw copy if unreadable (still lets WiX try)
                src.copyTo(dst, overwrite = true)
              }
            } catch (_: Exception) {
              // Fallback on any error
              src.copyTo(dst, overwrite = true)
            }

            // Also place a copy at root images/ for maximum compatibility
            val dstRoot = File(resDir, "images/WixStdDialog.bmp")
            dstRoot.parentFile.mkdirs()
            try {
              dst.copyTo(dstRoot, overwrite = true)
            } catch (_: Exception) {}
          }
        }

        // 1b) WixUIBannerBmp: place at windows/images/WixStdBanner.bmp so WiX uses it
        run {
          val src =
            project.layout.projectDirectory
              .file("src/jpackage/windows/CryptaInstall_Banner.bmp")
              .asFile
          if (src.isFile) {
            val dst = File(winDir, "images/WixStdBanner.bmp")
            dst.parentFile.mkdirs()
            try {
              val img = ImageIO.read(src)
              if (img != null) {
                val targetW = 493
                val targetH = 58
                val scaled = BufferedImage(targetW, targetH, BufferedImage.TYPE_3BYTE_BGR)
                val g = scaled.createGraphics()
                try {
                  g.drawImage(
                    img.getScaledInstance(targetW, targetH, Image.SCALE_SMOOTH),
                    0,
                    0,
                    null,
                  )
                } finally {
                  g.dispose()
                }
                ImageIO.write(scaled, "bmp", dst)
              } else {
                src.copyTo(dst, overwrite = true)
              }
            } catch (_: Exception) {
              src.copyTo(dst, overwrite = true)
            }

            // Also place a copy at root images/
            val dstRoot = File(resDir, "images/WixStdBanner.bmp")
            dstRoot.parentFile.mkdirs()
            try {
              dst.copyTo(dstRoot, overwrite = true)
            } catch (_: Exception) {}
          }
        }

        // 2) ARPPRODUCTICON (Apps & Features icon): define JpIcon in overrides.wxi
        //    Point it to the absolute path of CryptaInstaller_Uninstall.ico in the resource dir
        run {
          val uninstallIco =
            project.layout.projectDirectory
              .file("src/jpackage/windows/CryptaInstaller_Uninstall.ico")
              .asFile
          val dialogBmp =
            project.layout.projectDirectory
              .file("src/jpackage/windows/CryptaInstall_Dialog.bmp")
              .asFile
          if (uninstallIco.isFile) {
            // Copy the ICO into the windows resources directory for a stable absolute path
            val icoInRes = File(winDir, "CryptaInstaller_Uninstall.ico")
            uninstallIco.copyTo(icoInRes, overwrite = true)

            val overrides = File(winDir, "overrides.wxi")
            val bmpInRes = File(winDir, "images/WixStdDialog.bmp")
            val bannerInRes = File(winDir, "images/WixStdBanner.bmp")
            val bmpPath = if (bmpInRes.isFile) bmpInRes.absolutePath.replace("\\", "/") else null
            val bannerPath =
              if (bannerInRes.isFile) bannerInRes.absolutePath.replace("\\", "/") else null
            // Keep the file minimal and additive; users can still override as needed later.
            overrides.writeText(
              buildString {
                appendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
                appendLine(
                  "<!-- Auto-generated by build: sets ARPPRODUCTICON and WixUIDialogBmp on Windows -->"
                )
                appendLine("<?define JpIcon=\"${icoInRes.absolutePath.replace("\\", "/")}\"?>")
                if (bmpPath != null) {
                  appendLine("<?define WixUIDialogBmp=\"${bmpPath}\"?>")
                }
                if (bannerPath != null) {
                  appendLine("<?define WixUIBannerBmp=\"${bannerPath}\"?>")
                }
                appendLine("<Include/>")
              }
            )

            // Duplicate overrides at resource root for jpackage lookups not using OS subdir
            try {
              overrides.copyTo(File(resDir, "overrides.wxi"), overwrite = true)
            } catch (_: Exception) {}
          }
        }

        // 3) Post-MSI script for EXE builds to wrap the custom MSI (copies custom MSI over
        // JpMsiFile)
        run {
          val script = File(resDir, "${appName}-post-msi.wsf")
          val customMsi =
            File(jpackageOutDir.get().asFile, "${appName}-${numericAppVersion()}-custom.msi")
          val wsf = buildString {
            appendLine("<?xml version=\"1.0\"?>")
            appendLine("<job id=\"post-msi\">")
            appendLine("  <script language=\"JScript\"><![CDATA[")
            appendLine("    var sh = WScript.CreateObject(\"WScript.Shell\");")
            appendLine("    var fso = WScript.CreateObject(\"Scripting.FileSystemObject\");")
            appendLine("    var msi = sh.Environment(\"PROCESS\")(\"JpMsiFile\");")
            appendLine("    var src = \"${customMsi.absolutePath.replace("\\", "/")}\";")
            appendLine(
              "    if (msi && fso.FileExists(src)) { try { fso.CopyFile(src, msi, true); } catch (e) {} }"
            )
            appendLine("]]>  </script>")
            appendLine("</job>")
          }
          script.writeText(wsf)
        }
      }
    }
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

fun resolveInstallerType(os: String): String =
  when (os) {
    "mac" -> "dmg"
    // Always produce Windows EXE wrapper when using the generic installer task.
    "win" -> "exe"
    else -> if (hasExe("dpkg-deb")) "deb" else if (hasExe("rpmbuild")) "rpm" else "deb"
  }

fun iconPathForOs(): String =
  when (currentOs()) {
    "mac" -> project.file("src/jpackage/macos/cryptad.icns").absolutePath
    "win" -> project.file("src/jpackage/windows/cryptad.ico").absolutePath
    else -> project.file("src/jpackage/linux/cryptad.png").absolutePath
  }

/**
 * Resolve WiX installation "bin" directory from common environment variables. Recognizes WIX,
 * WIX_HOME, and WIX_PATH. Returns the bin directory when both candle.exe and light.exe are present,
 * or null otherwise.
 */
fun wixBinFromEnv(): File? {
  val names = listOf("WIX", "WIX_HOME", "WIX_PATH")
  for (name in names) {
    val raw = System.getenv(name)?.trim()?.takeIf { it.isNotEmpty() } ?: continue
    val base = File(raw)
    val bin = if (base.name.equals("bin", ignoreCase = true)) base else File(base, "bin")
    val candle = File(bin, "candle.exe")
    val light = File(bin, "light.exe")
    if (candle.isFile && light.isFile) return bin
  }
  return null
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

      // OS-specific tweaks (only flags valid for app-image)
      when (os) {
        "mac" -> {
          args.addAll(listOf("--mac-package-identifier", appId))
        }
        "linux" -> {
          args.addAll(listOf("--linux-shortcut", "--linux-menu-group", "Network;Utility;"))
        }
        "win" -> {
          // For app-image, do NOT pass --win-menu/--win-shortcut (only valid for installer types)
          // We intentionally keep Windows app-image generic here.
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

      // Ensure temp dir is empty for jpackage when we keep it for post-processing (Windows)
      if (os == "win") {
        val tmpDir = jpackageOutDir.get().dir("tmp-installer").asFile
        if (tmpDir.exists()) tmpDir.deleteRecursively()
      }

      // On Windows, verify WiX presence only when building MSI; EXE does not require WiX
      if (os == "win" && installerType == "msi") {
        // Try to locate WiX tools required by jpackage (candle/light)
        fun hasTool(tool: String): Boolean =
          try {
            val pb = ProcessBuilder("where", tool)
            pb.redirectErrorStream(true)
            val p = pb.start()
            p.waitFor(3, TimeUnit.SECONDS)
            p.exitValue() == 0
          } catch (_: Exception) {
            false
          }
        val wixBin = wixBinFromEnv()
        val wixPresent =
          (hasTool("light.exe") && hasTool("candle.exe")) ||
            (wixBin?.let { File(it, "light.exe").isFile && File(it, "candle.exe").isFile } ?: false)
        if (!wixPresent) {
          println(
            "WiX Toolset not found (light.exe/candle.exe). Skipping MSI creation. Install WiX 3.x and ensure it is on PATH or set WIX to the install root to enable MSI builds."
          )
          return@doLast
        }
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
      // Debug mode: keep WiX/jpackage temp + verbose logs
      if (providers.gradleProperty("jpackageDebug").orNull == "true") {
        args.addAll(listOf("--verbose", "--temp", outDir.resolve("tmp-installer").absolutePath))
      }
      // Windows: use a custom installer icon distinct from the app icon
      if (os == "win") {
        val installerIco = project.file("src/jpackage/windows/CryptaInstaller.ico")
        if (installerIco.isFile) {
          args.addAll(listOf("--icon", installerIco.absolutePath))
        }
      }
      // Always keep the temp to allow post-processing (e.g., WiX relink)
      if (os == "win") {
        args.addAll(listOf("--temp", jpackageOutDir.get().dir("tmp-installer").asFile.absolutePath))
      }
      // Ensure a stable bundle identifier on macOS
      if (os == "mac") args.addAll(listOf("--mac-package-identifier", appId))
      // Windows installer UX: per-user by default, allow directory selection, and prompt for
      // desktop shortcut
      if (os == "win")
        args.addAll(
          listOf(
            "--win-per-user-install",
            "--win-menu",
            "--win-dir-chooser",
            "--win-shortcut-prompt",
          )
        )
      println("Executing jpackage installer:\n" + args.joinToString(" "))
      project.serviceOf<ExecOperations>().exec {
        // If WiX is specified via env, prepend its bin directory to PATH so jpackage can find
        // tools.
        if (os == "win") {
          wixBinFromEnv()?.let { bin ->
            val current = System.getenv("PATH") ?: ""
            val sep = ";"
            environment("PATH", bin.absolutePath + sep + current)
            println("Using WiX from WIX env: ${bin.absolutePath}")
          }
        }
        commandLine(args)
      }

      // Keep jpackage default filenames (e.g., Crypta-<version>.<ext>)
    }
  }

// Convenience lifecycle tasks
tasks.register("jpackageInstallerMsiCryptad") {
  group = "jpackage"
  description = "Creates a Windows MSI installer"
  dependsOn(enrichAppImageWithDist)
  onlyIf { currentOs() == "win" }
  doLast {
    val toolchains = project.serviceOf<JavaToolchainService>()
    val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
    val javaHome = launcher.get().metadata.installationPath.asFile
    val jpackage = javaHome.resolve("bin/jpackage" + if (org.gradle.internal.os.OperatingSystem.current().isWindows) ".exe" else "")
    if (!jpackage.isFile) throw GradleException("jpackage not found in toolchain: ${jpackage}")

    val outDir = jpackageOutDir.get().asFile
    outDir.mkdirs()
    val imagePath = jpackageOutDir.get().asFile.resolve(appName).absolutePath
    val args = mutableListOf(
      jpackage.absolutePath,
      "--type","msi",
      "--name", appName,
      "--app-version", numericAppVersion(),
      "--dest", outDir.absolutePath,
      "--resource-dir", jpackageResourcesDir.get().asFile.absolutePath,
      "--app-image", imagePath,
      "--vendor", vendor,
      "--temp", outDir.resolve("tmp-installer").absolutePath,
      "--win-per-user-install","--win-menu","--win-dir-chooser","--win-shortcut-prompt",
    )
    println("Executing jpackage MSI:\n" + args.joinToString(" "))
    project.serviceOf<ExecOperations>().exec { commandLine(args) }
  }
}

tasks.register("jpackageInstallerExeCryptad") {
  group = "jpackage"
  description = "Creates a Windows EXE installer (wraps MSI)"
  dependsOn(enrichAppImageWithDist)
  onlyIf { currentOs() == "win" }
  doLast {
    val toolchains = project.serviceOf<JavaToolchainService>()
    val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
    val javaHome = launcher.get().metadata.installationPath.asFile
    val jpackage = javaHome.resolve("bin/jpackage" + if (org.gradle.internal.os.OperatingSystem.current().isWindows) ".exe" else "")
    if (!jpackage.isFile) throw GradleException("jpackage not found in toolchain: ${jpackage}")

    val outDir = jpackageOutDir.get().asFile
    outDir.mkdirs()
    val imagePath = jpackageOutDir.get().asFile.resolve(appName).absolutePath
    // Ensure temp dir is empty
    outDir.resolve("tmp-installer").let { if (it.exists()) it.deleteRecursively() }

    val args = mutableListOf(
      jpackage.absolutePath,
      "--type","exe",
      "--name", appName,
      "--app-version", numericAppVersion(),
      "--dest", outDir.absolutePath,
      "--resource-dir", jpackageResourcesDir.get().asFile.absolutePath,
      "--app-image", imagePath,
      "--vendor", vendor,
      "--temp", outDir.resolve("tmp-installer").absolutePath,
      "--win-per-user-install","--win-menu","--win-dir-chooser","--win-shortcut-prompt",
    )
    val installerIco = project.file("src/jpackage/windows/CryptaInstaller.ico")
    if (installerIco.isFile) args.addAll(listOf("--icon", installerIco.absolutePath))
    println("Executing jpackage EXE:\n" + args.joinToString(" "))
    // Prepend WiX bin to PATH if present
    wixBinFromEnv()?.let { bin ->
      project.serviceOf<ExecOperations>().exec {
        val current = System.getenv("PATH") ?: ""
        environment("PATH", bin.absolutePath + ";" + current)
        commandLine(args)
      }
    } ?: run {
      project.serviceOf<ExecOperations>().exec { commandLine(args) }
    }

    // Copy final EXE to CryptaInstaller.exe
    val produced = File(outDir, "${appName}-${numericAppVersion()}.exe")
    val finalExe = File(outDir, "CryptaInstaller.exe")
    if (produced.isFile) {
      produced.copyTo(finalExe, overwrite = true)
      println("Final installer -> ${finalExe.name}")
    } else println("WARNING: Could not locate produced EXE at ${produced.name}")
  }
}

tasks.register("jpackageAll") {
  group = "jpackage"
  description = "Builds custom MSI and final EXE (CryptaInstaller.exe)"
  dependsOn(jpackageInstallerMsiCryptad)
  dependsOn(relinkWixUiBitmaps)
  dependsOn(jpackageInstallerExeCryptad)
}

// Windows-only: Relink MSI with custom WiX UI bitmaps (dialog/banner) via light.exe
// -dWixUIDialogBmp
tasks.register("relinkWixUiBitmaps") {
  group = "jpackage"
  description = "Relinks the MSI using WiX to inject custom dialog/banner bitmaps"
  dependsOn(jpackageInstallerCryptad)
  onlyIf { currentOs() == "win" }
  doLast {
    val tmp = jpackageOutDir.get().dir("tmp-installer").asFile
    val cfg = File(tmp, "config")
    val wixobj = File(tmp, "wixobj")
    require(cfg.isDirectory && wixobj.isDirectory) {
      "Missing tmp-installer working directory. Re-run jpackageInstallerCryptad to regenerate."
    }
    val dialogBmp = File(jpackageResourcesDir.get().asFile, "windows/images/WixStdDialog.bmp")
    if (!dialogBmp.isFile) {
      println("No custom dialog bitmap found at ${dialogBmp.absolutePath}; skipping change.")
      return@doLast
    }
    val toolchains = project.serviceOf<JavaToolchainService>()
    // Find WiX tools on PATH or via env (WIX/WIX_HOME/WIX_PATH)
    val wixBin =
      wixBinFromEnv()
        ?: run {
          val pathStr = System.getenv("PATH") ?: ""
          pathStr.split(';').asSequence().map { File(it) }.find { File(it, "light.exe").isFile }
        }
        ?: throw GradleException("WiX Toolset not found to relink MSI")

    val outMsi = File(jpackageOutDir.get().asFile, "${appName}-${numericAppVersion()}-custom.msi")
    val cmd =
      mutableListOf(
        File(wixBin, "light.exe").absolutePath,
        "-nologo",
        "-spdb",
        "-ext",
        "WixUtilExtension",
        "-ext",
        "WixUIExtension",
        "-out",
        outMsi.absolutePath,
        "-b",
        cfg.absolutePath,
        "-sice:ICE27",
        "-sice:ICE91",
        "-loc",
        File(cfg, "MsiInstallerStrings_de.wxl").absolutePath,
        "-loc",
        File(cfg, "MsiInstallerStrings_en.wxl").absolutePath,
        "-loc",
        File(cfg, "MsiInstallerStrings_ja.wxl").absolutePath,
        "-loc",
        File(cfg, "MsiInstallerStrings_zh_CN.wxl").absolutePath,
        "-cultures:en-us",
        "-dWixUIDialogBmp=${dialogBmp.absolutePath}",
        File(wixobj, "main.wixobj").absolutePath,
        File(wixobj, "bundle.wixobj").absolutePath,
        File(wixobj, "ui.wixobj").absolutePath,
        File(wixobj, "ShortcutPromptDlg.wixobj").absolutePath,
        File(wixobj, "InstallDirNotEmptyDlg.wixobj").absolutePath,
      )
    // Conditionally inject banner BMP, if available
    run {
      val bannerBmp = File(jpackageResourcesDir.get().asFile, "windows/images/WixStdBanner.bmp")
      if (bannerBmp.isFile) {
        cmd.add("-dWixUIBannerBmp=${bannerBmp.absolutePath}")
      }
    }
    println("Relinking MSI with WiX:\n" + cmd.joinToString(" "))
    project.serviceOf<ExecOperations>().exec { commandLine(cmd) }
    println("Relinked MSI -> ${outMsi.absolutePath}")
  }
}

// Ensure standard build also creates custom MSI + final EXE wrapper on Windows.
tasks.named("build") {
  dependsOn(jpackageImageCryptad)
  dependsOn(jpackageAll)
}
