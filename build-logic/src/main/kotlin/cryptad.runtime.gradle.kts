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
    // Capture values during configuration to avoid Task.project access at execution
    val libsDir = layout.buildDirectory.dir("libs")
    val versionStr = providers.provider { project.version.toString() }
    doLast {
      val libs = libsDir.get().asFile
      val src = libs.resolve("cryptad.jar")
      val dst = libs.resolve("cryptad-${versionStr.get()}.jar")
      if (!src.isFile) throw GradleException("Expected JAR not found: ${src.absolutePath}")
      src.copyTo(dst, overwrite = true)
    }
  }

// No external runtime plugin configuration; jlink is invoked below

// Our existing bin/cryptad script (Tanuki Wrapper) isn't patched by the plugin.
// No separate jlink-specific launchers; we reuse dist/bin scripts and wrapper binaries

// Discover Java modules with jdeps for the assembled app classpath
@CacheableTask
abstract class ComputeJlinkModules @Inject constructor(private val execOps: ExecOperations) :
  DefaultTask() {
  // The JAR content determines the jdeps output; path should not.
  @get:InputFile @get:Classpath abstract val cryptadJar: RegularFileProperty

  // Treat the classpath as a content-addressed input for caching across machines.
  @get:InputFiles @get:Classpath abstract val classpath: ConfigurableFileCollection

  @get:Input abstract val javaLanguageVersion: Property<Int>
  // Provide JDK home explicitly to avoid accessing Project services during execution
  @get:Input abstract val javaHomePath: Property<String>

  @get:OutputFile abstract val modulesFile: RegularFileProperty

  @get:Input abstract val baselineModules: ListProperty<String>

  @TaskAction
  fun compute() {
    val jarFile = cryptadJar.get().asFile
    require(jarFile.isFile) { "Missing ${jarFile.absolutePath}" }

    val javaHome = File(javaHomePath.get())
    val jdeps =
      javaHome.resolve(
        "bin/jdeps${
              if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""
          }"
      )

    val classpathArg =
      classpath.files
        .filter { it.isFile && it.extension == "jar" && it.name != jarFile.name }
        .joinToString(File.pathSeparator) { it.absolutePath }

    val args =
      mutableListOf(jdeps.absolutePath, "--ignore-missing-deps", "--print-module-deps", "-q")
        .apply {
          if (classpathArg.isNotBlank()) addAll(listOf("-cp", classpathArg))
          add(jarFile.absolutePath)
        }

    val out = ByteArrayOutputStream()
    val result =
      execOps.exec {
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
    classpath.from(
      project.provider {
        val d = libsDirProvider.get()
        d.listFiles { f -> f.isFile && f.name.endsWith(".jar") }?.toList() ?: emptyList()
      }
    )

    // Output
    modulesFile.set(layout.buildDirectory.file("jlink/modules.list"))

    // Toolchain + baseline
    javaLanguageVersion.set(21)
    // Resolve toolchain at configuration time and pass JDK home path as input
    val toolchains = project.serviceOf<JavaToolchainService>()
    val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
    javaHomePath.set(launcher.map { it.metadata.installationPath.asFile.absolutePath })
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
    // Resolve toolchain and static inputs at configuration time to avoid Task.project access
    val toolchains = project.serviceOf<JavaToolchainService>()
    val launcher = toolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
    val javaHomePath = launcher.map { it.metadata.installationPath.asFile.absolutePath }
    val jreDirProvider = layout.buildDirectory.dir("jre")
    val modulesFileProvider = layout.buildDirectory.dir("jlink").map { it.file("modules.list") }
    val execOps = project.serviceOf<ExecOperations>()
    doLast {
      val javaHome = File(javaHomePath.get())
      val jlink =
        javaHome.resolve(
          "bin/jlink${if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""}"
        )
      val jmods = javaHome.resolve("jmods")

      val jreDir = jreDirProvider.get().asFile
      if (jreDir.exists()) jreDir.deleteRecursively()

      val modulesFile = modulesFileProvider.get().asFile
      val modulesArg = if (modulesFile.isFile) modulesFile.readText().trim() else "java.base"

      val args =
        mutableListOf(
          jlink.absolutePath,
          "-v",
          "--strip-debug",
          // Use non-deprecated compression syntax (replaces numeric level 2)
          "--compress",
          "zip-6",
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
