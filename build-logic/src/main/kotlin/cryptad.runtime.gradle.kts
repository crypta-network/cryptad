import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.kotlin.dsl.support.serviceOf
import org.gradle.process.ExecOperations

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
// No separate jlink-specific launchers; we reuse dist/bin scripts and wrapper binaries

// Discover Java modules with jdeps for the assembled app classpath
@CacheableTask
abstract class ComputeJlinkModules @Inject constructor(
  private val execOps: ExecOperations,
) : DefaultTask() {
  @get:InputFile
  abstract val cryptadJar: RegularFileProperty

  @get:InputFiles
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val classpath: ConfigurableFileCollection

  @get:Input
  abstract val javaLanguageVersion: Property<Int>

  @get:OutputFile
  abstract val modulesFile: RegularFileProperty

  @get:Input
  abstract val baselineModules: ListProperty<String>

  @TaskAction
  fun compute() {
    val jarFile = cryptadJar.get().asFile
    require(jarFile.isFile) { "Missing ${jarFile.absolutePath}" }

    val toolchains = project.extensions.getByType(JavaToolchainService::class.java)
    val launcher =
      toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(javaLanguageVersion.get())) }.get()
    val javaHome = launcher.metadata.installationPath.asFile
    val jdeps =
      javaHome.resolve(
        "bin/jdeps" + if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""
      )

    val classpathArg =
      classpath.files
        .filter { it.isFile && it.extension == "jar" && it.name != jarFile.name }
        .joinToString(File.pathSeparator) { it.absolutePath }

    val args =
      mutableListOf(jdeps.absolutePath, "--ignore-missing-deps", "--print-module-deps", "-q").apply {
        if (classpathArg.isNotBlank()) addAll(listOf("-cp", classpathArg))
        add(jarFile.absolutePath)
      }

    val out = ByteArrayOutputStream()
    val result = execOps.exec {
      commandLine(args)
      standardOutput = out
      isIgnoreExitValue = true
    }
    val exit = result.exitValue
    val detected = out.toString().trim().removeSuffix(",")

    val baseline = baselineModules.get().toSet()
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

    val outFile = modulesFile.get().asFile
    outFile.parentFile.mkdirs()
    outFile.writeText(modules.sorted().joinToString(","))
    println("jdeps modules -> ${outFile.absolutePath}:\n" + modules.sorted().joinToString(","))
  }
}

val computeJlinkModules by
  tasks.registering(ComputeJlinkModules::class) {
    group = "distribution"
    description = "Computes required Java modules using jdeps and writes build/jlink/modules.list"
    dependsOn(syncRuntimeJar, tasks.named("assembleCryptadDist"))

    // Inputs: jars from the assembled distribution
    val libsDirProvider = cryptadDistDir.map { it.dir("lib").asFile }
    cryptadJar.set(project.layout.file(libsDirProvider.map { it.resolve("cryptad.jar") }))
    classpath.from(project.provider {
      val d = libsDirProvider.get()
      d.listFiles { f -> f.isFile && f.name.endsWith(".jar") }?.toList() ?: emptyList()
    })

    // Output
    modulesFile.set(layout.buildDirectory.file("jlink/modules.list"))

    // Toolchain + baseline
    javaLanguageVersion.set(21)
    baselineModules.set(
      listOf(
        "jdk.crypto.ec",
        "jdk.charsets",
        "jdk.localedata",
        "jdk.unsupported",
        "jdk.zipfs",
        "java.net.http",
        "java.desktop",
      )
    )
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
    dependsOn(prepareJlinkImage)
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
    dependsOn(prepareJlinkImage)
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
