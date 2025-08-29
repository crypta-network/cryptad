import java.io.ByteArrayOutputStream
import org.gradle.kotlin.dsl.support.serviceOf

plugins { java }

// We keep our existing custom distribution (assembleCryptadDist) intact.
// This plugin builds a jlink image directly (no external runtime plugin).

val cryptadDistDir = layout.buildDirectory.dir("cryptad-dist")
val jlinkImageDir = layout.buildDirectory.dir("cryptad-jlink-image")

// No application plugin: launchers below invoke the main class directly

// jdeps prefers a versioned jar; copy our custom jar to that name
val syncRuntimeJar by
  tasks.registering {
    group = "build"
    description = "Copies cryptad.jar to build/libs/cryptad-<version>.jar for jdeps"
    dependsOn(tasks.named("buildJar"))
    doLast {
      val libsDir = layout.buildDirectory.dir("libs").get().asFile
      val src = libsDir.resolve("cryptad.jar")
      val dst = libsDir.resolve("cryptad-${project.version}.jar")
      if (!src.isFile) throw GradleException("Expected JAR not found: ${src.absolutePath}")
      src.copyTo(dst, overwrite = true)
    }
  }

// No external runtime plugin configuration; jlink is invoked below

// Our existing bin/cryptad script (Tanuki Wrapper) isn't patched by the plugin.
// Provide a lightweight launcher that always uses the embedded runtime's java.
val generateJlinkLaunchers by
  tasks.registering {
    group = "distribution"
    description = "Generates jlink launchers inside the runtime image"
    // The launcher requires a prepared image; we will depend on our custom image task defined
    // below.
    dependsOn(prepareJlinkImage)
    doLast {
      val image = jlinkImageDir.get().asFile
      val binDir = image.resolve("bin")
      val libDir = image.resolve("lib")
      require(binDir.isDirectory) { "Missing bin/ in jlink image at ${binDir.absolutePath}" }
      require(libDir.isDirectory) { "Missing lib/ in jlink image at ${libDir.absolutePath}" }

      // Unix launcher
      val unix = binDir.resolve("cryptad-jlink")
      unix.writeText(
        $$"""
        |#!/usr/bin/env bash
        |set -euo pipefail
        |SCRIPT_DIR="$(cd "$(dirname \"$0\")" && pwd)"
        |JAVA="$SCRIPT_DIR/java"
        |CLASSPATH="$SCRIPT_DIR/../lib/*"
        |exec "$JAVA" -cp "$CLASSPATH" network.crypta.node.Node "$@"
        |"""
          .trimMargin()
      )
      unix.setReadable(true, false)
      unix.setExecutable(true, false)

      // Windows launcher
      val bat = binDir.resolve("cryptad-jlink.bat")
      bat.writeText(
        """
        |@echo off
        |setlocal enableextensions
        |set SCRIPT_DIR=%~dp0
        |set JAVA=%SCRIPT_DIR%java.exe
        |set CP=%SCRIPT_DIR%..\lib\*
        |"%JAVA%" -cp "%CP" network.crypta.node.Node %*
        |"""
          .trimMargin()
      )
    }
  }

// Discover Java modules with jdeps for the assembled app classpath
val computeJlinkModules by
  tasks.registering {
    group = "distribution"
    description = "Computes required Java modules using jdeps and writes build/jlink/modules.list"
    dependsOn(syncRuntimeJar, tasks.named("assembleCryptadDist"))
    doLast {
      val libsDir = cryptadDistDir.get().dir("lib").asFile
      val cryptadJar = libsDir.resolve("cryptad.jar")
      require(cryptadJar.isFile) { "Missing ${cryptadJar.absolutePath}" }

      val classpath =
        libsDir
          .listFiles { f -> f.isFile && f.name.endsWith(".jar") && f.name != "cryptad.jar" }
          ?.joinToString(File.pathSeparator) { it.absolutePath } ?: ""

      val toolchains = project.extensions.getByType(JavaToolchainService::class.java)
      val launcher =
        toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }.get()
      val javaHome = launcher.metadata.installationPath.asFile
      val jdeps =
        javaHome.resolve(
          "bin/jdeps" +
            if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""
        )

      val args =
        mutableListOf(jdeps.absolutePath, "--ignore-missing-deps", "--print-module-deps", "-q")
      if (classpath.isNotBlank()) {
        args += listOf("-cp", classpath)
      }
      args += cryptadJar.absolutePath

      val out = ByteArrayOutputStream()
      val execOps = project.serviceOf<ExecOperations>()
      val result =
        execOps.exec {
          commandLine(args)
          standardOutput = out
          isIgnoreExitValue = true
        }
      val exit = result.exitValue
      val detected = out.toString().trim().removeSuffix(",")

      val baseline =
        setOf(
          "jdk.crypto.ec",
          "jdk.charsets",
          "jdk.localedata",
          "jdk.unsupported",
          "jdk.zipfs",
          "java.net.http",
          "java.desktop",
        )

      val modules: Set<String> =
        if (exit == 0 && detected.isNotBlank())
          detected.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet() + baseline
        else
          baseline +
            setOf(
              "java.base",
              "java.logging",
              "java.management",
              "java.naming",
              "java.prefs",
              "java.rmi",
              "java.scripting",
              "java.security.jgss",
              "java.security.sasl",
              "java.sql",
              "java.xml",
            )

      val outDir = layout.buildDirectory.dir("jlink").get().asFile
      outDir.mkdirs()
      val modulesFile = outDir.resolve("modules.list")
      modulesFile.writeText(modules.sorted().joinToString(","))
      println(
        "jdeps modules -> ${modulesFile.absolutePath}:\n" + modules.sorted().joinToString(",")
      )
    }
  }

// --- Custom jlink flow for Gradle 9 compatibility ---
// Some runtime plugin variants are not yet Gradle 9 compatible. Provide a direct jlink path.
val createJreImage by
  tasks.registering {
    group = "distribution"
    description = "Creates a minimal JRE with jlink into build/jre"
    dependsOn(computeJlinkModules)
    doLast {
      val toolchains = project.extensions.getByType(JavaToolchainService::class.java)
      val launcher =
        toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }.get()
      val javaHome = launcher.metadata.installationPath.asFile
      val jlink =
        javaHome.resolve(
          "bin/jlink${if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""}"
        )
      val jmods = javaHome.resolve("jmods")

      val jreDir = layout.buildDirectory.dir("jre").get().asFile
      if (jreDir.exists()) jreDir.deleteRecursively()

      val modulesFile = layout.buildDirectory.dir("jlink").get().asFile.resolve("modules.list")
      val modulesArg = if (modulesFile.isFile) modulesFile.readText().trim() else "java.base"

      val args =
        mutableListOf(
          jlink.absolutePath,
          "-v",
          "--strip-debug",
          "--compress",
          "2",
          "--no-header-files",
          "--no-man-pages",
          "--module-path",
          jmods.absolutePath,
          "--add-modules",
          modulesArg,
          "--output",
          jreDir.absolutePath,
        )

      println("Executing jlink: ${args.joinToString(" ")}")
      val execOps = project.serviceOf<ExecOperations>()
      execOps.exec { commandLine(args) }
    }
  }

val prepareJlinkImage by
  tasks.registering {
    group = "distribution"
    description = "Assembles build/cryptad-jlink-image from build/jre and cryptad-dist"
    dependsOn(createJreImage, tasks.named("assembleCryptadDist"))
    doLast {
      val image = jlinkImageDir.get().asFile
      if (image.exists()) image.deleteRecursively()
      image.mkdirs()

      // Copy the jlink runtime to the image root (bin, lib, etc.)
      copy {
        from(layout.buildDirectory.dir("jre"))
        into(image)
      }
      // Merge our app distribution (lib + conf + bin). We include the wrapper binary folder and
      // launch scripts alongside the jlink bin; Gradle copy merges directories, no JRE tools are
      // overwritten because dist/bin doesn't contain them.
      copy {
        from(cryptadDistDir.get().asFile)
        into(image)
        include("lib/**", "conf/**")
      }
      // Bring over wrapper executables and launchers into the image/bin
      copy {
        from(cryptadDistDir.get().asFile.resolve("bin"))
        into(image.resolve("bin"))
        include("**/*")
      }
    }
  }

// Zip the jlink image with predictable name
val distZipCryptadJlink by
  tasks.registering(Zip::class) {
    group = "distribution"
    description = "Packages the jlink runtime image as a zip"
    dependsOn(generateJlinkLaunchers)
    archiveBaseName.set("cryptad-jlink")
    archiveVersion.set("v${project.version}")
    archiveFileName.set("cryptad-jlink-v${project.version}.zip")
    from(jlinkImageDir)
    destinationDirectory.set(layout.buildDirectory.dir("distributions"))
    isPreserveFileTimestamps = true
    isReproducibleFileOrder = true
  }

// Tar.gz counterpart for convenience
val distTarCryptadJlink by
  tasks.registering(Tar::class) {
    group = "distribution"
    description = "Packages the jlink runtime image as a tar.gz"
    dependsOn(generateJlinkLaunchers)
    compression = Compression.GZIP
    archiveBaseName.set("cryptad-jlink")
    archiveVersion.set("v${project.version}")
    archiveFileName.set("cryptad-jlink-v${project.version}.tar.gz")
    from(jlinkImageDir)
    destinationDirectory.set(layout.buildDirectory.dir("distributions"))
    isPreserveFileTimestamps = true
    isReproducibleFileOrder = true
  }

// Aggregate task
tasks.register("distJlinkCryptad") {
  group = "distribution"
  description = "Builds all jlink-based Cryptad distribution archives"
  dependsOn(distZipCryptadJlink, distTarCryptadJlink)
}

// Make the standard 'dist' also produce the jlink archives
tasks.named("dist") { dependsOn("distJlinkCryptad") }
