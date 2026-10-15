import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  // Apply precompiled script discovery after the exact static source filters are installed.
  `kotlin-dsl` apply false
  `java-gradle-plugin`
}

pluginManager.apply("org.gradle.kotlin.kotlin-dsl.base")

java {
  toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
  sourceCompatibility = JavaVersion.VERSION_25
  targetCompatibility = JavaVersion.VERSION_25
}

extensions.configure<KotlinJvmProjectExtension> { jvmToolchain(25) }

// This build cannot import its own source-selection helper before compiling that helper.
// Keep configured generated roots intact and bind static sources to the bounded selected roster.
val bootstrapRepository: Path = rootDir.parentFile.toPath().toAbsolutePath().normalize()
val bootstrapRealRepository: Path = bootstrapRepository.toRealPath()
val bootstrapHistory = setOf(".stversions", ".git", "build", ".gradle", "__pycache__", ".cache")
val bootstrapSourceByteLimit = 16 * 1024 * 1024

// Windows execute ACL access does not describe the portable mode sealed by a Unix exporter.
fun bootstrapExecutableBit(path: Path): Boolean? {
  if (!Files.getFileStore(path).supportsFileAttributeView("posix")) return null
  return Files.getPosixFilePermissions(path, NOFOLLOW_LINKS).any {
    it in
      setOf(
        PosixFilePermission.OWNER_EXECUTE,
        PosixFilePermission.GROUP_EXECUTE,
        PosixFilePermission.OTHERS_EXECUTE,
      )
  }
}

fun bootstrapSourceName(value: String): String {
  require(
    value.isNotEmpty() &&
      value.length <= 1024 &&
      !value.startsWith('/') &&
      '\\' !in value &&
      ':' !in value &&
      value.none { it.code < 32 || it.code == 127 } &&
      value.split('/').none { it in setOf("", ".", "..") }
  ) {
    "Unsafe bootstrap source name"
  }
  return value
}

fun bootstrapRelativePath(file: File): Path {
  val path = file.toPath().toAbsolutePath().normalize()
  return when {
    path.startsWith(bootstrapRepository) -> bootstrapRepository.relativize(path)
    path.startsWith(bootstrapRealRepository) -> bootstrapRealRepository.relativize(path)
    else -> error("Source is outside the configured repository")
  }
}

fun bootstrapSourcePath(name: String): Path {
  var path = bootstrapRealRepository
  for (part in bootstrapSourceName(name).split('/')) {
    path = path.resolve(part)
    require(!Files.isSymbolicLink(path)) { "Linked bootstrap source member" }
  }
  require(Files.isRegularFile(path, NOFOLLOW_LINKS) && path.toRealPath() == path) {
    "Missing or aliased bootstrap source member"
  }
  if (Files.getFileStore(path).supportsFileAttributeView("unix")) {
    require((Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L) {
      "Linked bootstrap source member"
    }
  }
  return path
}

fun bootstrapReadSource(name: String): ByteArray {
  val path = bootstrapSourcePath(name)
  val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
  require(before.size() <= bootstrapSourceByteLimit) { "Bootstrap source exceeds limit" }
  val bytes =
    Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(bootstrapSourceByteLimit + 1) }
  val after =
    Files.readAttributes(bootstrapSourcePath(name), BasicFileAttributes::class.java, NOFOLLOW_LINKS)
  require(
    bytes.size.toLong() == before.size() &&
      after.size() == before.size() &&
      after.fileKey() == before.fileKey() &&
      after.lastModifiedTime() == before.lastModifiedTime()
  ) {
    "Bootstrap source changed while reading"
  }
  return bytes
}

fun bootstrapDecode(bytes: ByteArray): String =
  StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT)
    .onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes))
    .toString()

fun bootstrapGit(vararg arguments: String): ByteArray {
  val processBuilder =
    ProcessBuilder(
        listOf(
          "git",
          "-c",
          "safe.directory=",
          "-c",
          "safe.directory=$bootstrapRealRepository",
          "-c",
          "core.fsmonitor=false",
          "-c",
          "core.untrackedCache=false",
          "--no-optional-locks",
        ) + arguments
      )
      .directory(bootstrapRealRepository.toFile())
      .redirectError(ProcessBuilder.Redirect.DISCARD)
  processBuilder.environment().keys.removeIf { it.startsWith("GIT_") }
  val process = processBuilder.start()
  val reader = Executors.newVirtualThreadPerTaskExecutor()
  try {
    val pending =
      reader.submit<ByteArray> {
        process.inputStream.use { it.readNBytes(bootstrapSourceByteLimit + 1) }
      }
    val bytes = pending.get(12, TimeUnit.SECONDS)
    require(
      bytes.size <= bootstrapSourceByteLimit &&
        process.waitFor(3, TimeUnit.SECONDS) &&
        process.exitValue() == 0
    ) {
      "Bootstrap source roster unavailable"
    }
    return bytes
  } finally {
    if (process.isAlive) process.destroyForcibly()
    reader.shutdownNow()
  }
}

fun bootstrapGitNames(bytes: ByteArray): List<String> {
  require(bytes.isEmpty() || bytes.last() == 0.toByte()) { "Invalid bootstrap source roster" }
  val names = bootstrapDecode(bytes).split('\u0000').dropLast(1)
  require(names.size <= 100000 && names.distinct().size == names.size) {
    "Bootstrap source roster exceeds limit"
  }
  return names.map(::bootstrapSourceName)
}

val bootstrapSelectedSources: NavigableSet<String> by lazy {
  val names =
    if (Files.exists(bootstrapRealRepository.resolve(".git"), NOFOLLOW_LINKS)) {
      val tracked = bootstrapGitNames(bootstrapGit("ls-files", "--cached", "-z"))
      val deleted = bootstrapGitNames(bootstrapGit("ls-files", "--deleted", "-z")).toSet()
      val exclusions = bootstrapHistory.sorted().map { ":(exclude,glob)**/$it/**" }
      val untracked =
        bootstrapGitNames(
            bootstrapGit(
              "ls-files",
              "--others",
              "--exclude-standard",
              "-z",
              "--",
              ".",
              *exclusions.toTypedArray(),
            )
          )
          .filter { name -> name.split('/').none { it in bootstrapHistory } }
      ((tracked.toSet() - deleted) + untracked).onEach { bootstrapSourcePath(it) }
    } else {
      val fullSource =
        Files.exists(bootstrapRealRepository.resolve(".cryptad-source-roster.json"), NOFOLLOW_LINKS)
      val manifestName =
        if (fullSource) ".cryptad-source-roster.json" else ".restricted-manifest.json"
      val text = bootstrapDecode(bootstrapReadSource(manifestName))
      val manifest =
        JsonSlurper().parseText(text) as? Map<*, *> ?: error("Invalid bootstrap export roster")
      // Match the existing producers without rewriting their identity-bound manifest bytes.
      val canonical = JsonOutput.toJson(manifest) + if (fullSource) "\n" else ""
      require(text == canonical) { "Noncanonical bootstrap export roster" }
      if (fullSource) {
        require(
          manifest.keys ==
            setOf("schemaVersion", "kind", "sourceCommit", "sourceTree", "sourceClass", "files") &&
            manifest["schemaVersion"] == 1 &&
            manifest["kind"] == "cryptad-source-export" &&
            manifest["sourceClass"] in setOf("committed-source", "working-source") &&
            (manifest["sourceTree"] as? String)?.matches(Regex("[0-9a-f]{40}")) == true
        ) {
          "Invalid bootstrap export roster"
        }
      } else {
        require(
          manifest.keys ==
            setOf("schemaVersion", "kind", "exportPolicy", "sourceCommit", "files") &&
            manifest["schemaVersion"] == 2 &&
            manifest["kind"] == "cryptad-restricted-installation" &&
            manifest["exportPolicy"] == "production-without-test-seams-v1"
        ) {
          "Invalid bootstrap export roster"
        }
      }
      require(
        (manifest["sourceCommit"] as? String)?.matches(
          Regex(if (fullSource) "[0-9a-f]{40}" else "[0-9a-f]{40}|[0-9a-f]{64}")
        ) == true
      ) {
        "Invalid bootstrap export identity"
      }
      val records = manifest["files"] as? Map<*, *> ?: error("Invalid bootstrap export members")
      require(records.isNotEmpty() && records.size <= 100000) {
        "Bootstrap source roster exceeds limit"
      }
      var total = 0L
      records.entries
        .map { (key, value) ->
          val name = bootstrapSourceName(key as? String ?: error("Invalid bootstrap export member"))
          require(name != manifestName) { "Self-referential bootstrap export roster" }
          val record = value as? Map<*, *> ?: error("Invalid bootstrap export member")
          require(
            record.keys == setOf("sha256", "size", "executable") &&
              (record["size"] is Int || record["size"] is Long) &&
              (record["size"] as Number).toLong() in 0L..bootstrapSourceByteLimit.toLong() &&
              record["executable"] is Boolean &&
              (record["sha256"] as? String)?.matches(Regex("[0-9a-f]{64}")) == true
          ) {
            "Invalid bootstrap export member"
          }
          total += (record["size"] as Number).toLong()
          require(total <= 512L * 1024 * 1024) { "Bootstrap source export exceeds limit" }
          val bytes = bootstrapReadSource(name)
          val executable = bootstrapExecutableBit(bootstrapSourcePath(name))
          val digest =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
              "%02x".format(it)
            }
          require(
            bytes.size.toLong() == (record["size"] as Number).toLong() &&
              digest == record["sha256"] &&
              (executable == null || executable == record["executable"])
          ) {
            "Bootstrap source export member changed"
          }
          name
        }
        .toSet()
    }
  require(names.isNotEmpty() && names.size <= 100000) {
    "Empty or oversized bootstrap source roster"
  }
  Collections.unmodifiableNavigableSet(TreeSet(names))
}

val bootstrapSourceExclusion =
  Spec<FileTreeElement> { entry ->
    val sourcePath = entry.file.toPath().toAbsolutePath().normalize()
    val generatedRoot = layout.buildDirectory.get().asFile.toPath().toAbsolutePath().normalize()
    if (sourcePath.startsWith(generatedRoot)) {
      false
    } else {
      val relative = bootstrapRelativePath(entry.file).toString().replace(File.separatorChar, '/')
      if (entry.isDirectory) {
        val prefix = "$relative/"
        bootstrapSelectedSources.ceiling(prefix)?.startsWith(prefix) != true
      } else {
        relative !in bootstrapSelectedSources
      }
    }
  }

extensions.getByType<KotlinJvmProjectExtension>().sourceSets.configureEach {
  kotlin.exclude(bootstrapSourceExclusion)
}

sourceSets.configureEach { java.exclude(bootstrapSourceExclusion) }

pluginManager.apply("org.gradle.kotlin.kotlin-dsl")

tasks.named<ProcessResources>("processResources") {
  doFirst {
    val buildRoot =
      bootstrapRealRepository.resolve(bootstrapRelativePath(layout.buildDirectory.get().asFile))
    val descriptors =
      bootstrapRealRepository
        .resolve(bootstrapRelativePath(destinationDir))
        .resolve("META-INF/gradle-plugins")
    require(descriptors.startsWith(buildRoot) && descriptors != buildRoot) {
      "Generated plugin descriptors outside build directory"
    }
    require(generateSequence(descriptors) { it.parent }.none { Files.isSymbolicLink(it) }) {
      "Linked generated plugin descriptor directory"
    }
    if (Files.exists(descriptors, NOFOLLOW_LINKS)) {
      require(
        Files.isDirectory(descriptors, NOFOLLOW_LINKS) && descriptors.toRealPath() == descriptors
      ) {
        "Invalid generated plugin descriptor directory"
      }
      Files.walk(descriptors).use { entries ->
        var count = 0
        entries.forEach { path ->
          require(++count <= 4096 && !Files.isSymbolicLink(path) && path.toRealPath() == path) {
            "Invalid generated plugin descriptor member"
          }
        }
      }
      // Copy does not remove obsolete descriptors from earlier source selections.
      project.delete {
        delete(descriptors.toFile())
        setFollowSymlinks(false)
      }
    }
  }
}

repositories {
  // Needed to resolve plugin marker artifacts like org.beryx:badass-runtime-plugin
  gradlePluginPortal()
  mavenCentral()
}

val rootSettingsPluginClasspath: Configuration =
  configurations.create("rootSettingsPluginClasspath") {
    isCanBeConsumed = false
    isCanBeResolved = true
    description = "Authenticated plugin classpath executed by the root settings script."
  }
val buildLogicSettingsPluginClasspath: Configuration =
  configurations.create("buildLogicSettingsPluginClasspath") {
    isCanBeConsumed = false
    isCanBeResolved = true
    description = "Authenticated plugin classpath executed by the included-build settings script."
  }

dependencies {
  // Portable archive normalization runs inside Gradle so distribution tasks remain Java-only.
  implementation(libs.commonsCompress)
  // Allow precompiled plugins to apply these without specifying versions in their scripts
  implementation("com.diffplug.spotless:spotless-plugin-gradle:${libs.versions.spotless.get()}")
  implementation(
    "com.github.spotbugs:com.github.spotbugs.gradle.plugin:${libs.versions.spotbugs.get()}"
  )
  implementation(
    "net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:${libs.versions.errorpronePlugin.get()}"
  )
  // SonarQube plugin marker for precompiled convention plugin usage
  implementation("org.sonarqube:org.sonarqube.gradle.plugin:${libs.versions.sonarqube.get()}")
  // name.remal.sonarlint plugin marker so our convention plugin can apply it without a version
  implementation(
    "name.remal.sonarlint:name.remal.sonarlint.gradle.plugin:${libs.versions.remalSonarlint.get()}"
  )
  // SonarLint implementation API for typed configuration in precompiled plugin
  implementation(
    "name.remal.gradle-plugins.sonarlint:sonarlint:${libs.versions.remalSonarlint.get()}"
  )
  val foojayMarker =
    "org.gradle.toolchains.foojay-resolver-convention:" +
      "org.gradle.toolchains.foojay-resolver-convention.gradle.plugin:" +
      libs.versions.foojayResolver.get()
  add(rootSettingsPluginClasspath.name, foojayMarker)
  add(buildLogicSettingsPluginClasspath.name, foojayMarker)

  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

tasks.withType<Test>().configureEach { useJUnitPlatform() }

tasks.withType<KotlinCompile>().configureEach {
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_25)
}

// The included build executes in its own Gradle instance and cannot import its own plugin classes
// while compiling them. Keep this adapter restricted to its JUnit tasks and private evidence.
if (providers.gradleProperty("phase12Evidence").orNull == "true") {
  val evidenceRoot = rootDir.parentFile.toPath().toRealPath()
  val evidenceOutput =
    layout.buildDirectory.file("phase12/task-evidence.json").get().asFile.toPath()
  val evidenceTasks = ConcurrentHashMap<String, Map<String, Any?>>()
  val requestedEvidenceTasks = gradle.startParameter.taskNames.toList()

  fun evidencePath(file: File): String {
    return bootstrapRelativePath(file).toString().replace(File.separatorChar, '/')
  }

  fun evidenceSource(file: File): Map<String, Any> {
    val path = evidenceRoot.resolve(bootstrapRelativePath(file))
    require(generateSequence(path) { it.parent }.none { Files.isSymbolicLink(it) }) {
      "Linked included-build input"
    }
    val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    require(before.isRegularFile && before.size() <= 16 * 1024 * 1024) {
      "Invalid included-build source"
    }
    val hash = MessageDigest.getInstance("SHA-256")
    var size = 0L
    Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
      val buffer = ByteArray(65536)
      while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        size += count
        require(size <= before.size()) { "Growing included-build source" }
        hash.update(buffer, 0, count)
      }
    }
    val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    require(
      size == before.size() &&
        after.size() == before.size() &&
        after.fileKey() == before.fileKey() &&
        after.lastModifiedTime() == before.lastModifiedTime()
    ) {
      "Changing included-build source"
    }
    return mapOf(
      "path" to evidencePath(file),
      "kind" to "file",
      "size" to before.size(),
      "digest" to ("sha256:" + hash.digest().joinToString("") { "%02x".format(it) }),
    )
  }

  fun evidenceReports(task: Test): Map<String, Any> {
    val directory =
      try {
        task.reports.junitXml.outputLocation.orNull?.asFile
      } catch (_: Exception) {
        null
      } ?: return mapOf("reportObservation" to "unavailable", "reportFiles" to emptyList<Any>())
    return try {
      val relative = bootstrapRelativePath(directory)
      val path = evidenceRoot.resolve(relative)
      require(generateSequence(path) { it.parent }.none { Files.isSymbolicLink(it) }) {
        "Linked included-build report directory"
      }
      if (!Files.exists(path, NOFOLLOW_LINKS)) {
        mapOf("reportObservation" to "complete", "reportFiles" to emptyList<Any>())
      } else {
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(before.isDirectory && path.toRealPath() == path) { "Invalid report directory" }
        fun reportNames(): List<String> =
          Files.newDirectoryStream(path).use { stream ->
            val names = mutableListOf<String>()
            var count = 0
            for (file in stream) {
              require(++count <= 4096) { "Too many included-build report directory members" }
              val name = file.fileName.toString()
              if (name.startsWith("TEST-") && name.endsWith(".xml")) names.add(name)
            }
            names.sorted()
          }
        val names = reportNames()
        var total = 0L
        val reports = names.map { name ->
          val file = path.resolve(name)
          val sourceName = evidencePath(file.toFile())
          val bytes = bootstrapReadSource(sourceName)
          total += bytes.size
          require(total <= 256L * 1024 * 1024) { "Included-build reports exceed limit" }
          mapOf(
            "path" to sourceName,
            "size" to bytes.size.toLong(),
            "sha256" to
              ("sha256:" +
                MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                  "%02x".format(it)
                }),
          )
        }
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(
          after.isDirectory &&
            after.fileKey() == before.fileKey() &&
            after.lastModifiedTime() == before.lastModifiedTime() &&
            path.toRealPath() == path &&
            generateSequence(path) { it.parent }.none { Files.isSymbolicLink(it) } &&
            reportNames() == names
        ) {
          "Included-build reports changed while reading"
        }
        mapOf("reportObservation" to "complete", "reportFiles" to reports)
      }
    } catch (_: Exception) {
      mapOf("reportObservation" to "invalid", "reportFiles" to emptyList<Any>())
    }
  }

  fun evidenceToolchain(metadata: JavaInstallationMetadata?): Map<String, String>? {
    if (metadata == null) return null
    return try {
      val installation = metadata.installationPath.asFile.toPath().toRealPath()
      val release = installation.resolve("release")
      val before = Files.readAttributes(release, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
      require(before.isRegularFile && before.size() in 1L..65536L) {
        "Invalid included-build toolchain release"
      }
      val raw = Files.newInputStream(release, NOFOLLOW_LINKS).use { it.readNBytes(65537) }
      val after = Files.readAttributes(release, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
      require(
        raw.size.toLong() == before.size() &&
          after.size() == before.size() &&
          after.fileKey() == before.fileKey() &&
          after.lastModifiedTime() == before.lastModifiedTime()
      ) {
        "Changing included-build toolchain release"
      }
      val architectures =
        Regex("(?m)^OS_ARCH=\"([A-Za-z0-9_+-]{1,32})\"\\r?$")
          .findAll(raw.toString(StandardCharsets.UTF_8))
          .toList()
      require(architectures.size == 1) { "Missing included-build toolchain architecture" }
      mapOf(
        "javaVersion" to metadata.javaRuntimeVersion,
        "javaVendor" to metadata.vendor,
        "javaArch" to architectures.single().groupValues[1],
      )
    } catch (_: Exception) {
      null
    }
  }

  tasks.named<Test>("test") {
    outputs.upToDateWhen { false }
    outputs.doNotCacheIf("Final evidence requires fresh included-build JUnit execution") { true }
  }

  // Observe inputs and native outcomes even when task actions do not run (reuse or NO-SOURCE).
  @Suppress("DEPRECATION")
  gradle.taskGraph.addTaskExecutionListener(
    object : TaskExecutionListener {
      override fun beforeExecute(task: Task) {
        if (task !is Test) return
        val started = System.currentTimeMillis()
        val metadata =
          try {
            val sources =
              sourceSets
                .named("test")
                .get()
                .allSource
                .matching { include("**/*.kt", "**/*.java") }
                .files
            require(sources.size <= 30000) { "Included-build source roster exceeds limit" }
            val cliGetter =
              task.filter.javaClass.methods.single {
                it.name == "getCommandLineIncludePatterns" && it.parameterCount == 0
              }
            val cliIncludes =
              (cliGetter.invoke(task.filter) as Collection<*>).map { it as String }.sorted()
            val junitOptions =
              task.options as? JUnitPlatformOptions
                ?: error("Unexpected included-build test framework")
            val junitSelection =
              mapOf(
                "includeTags" to junitOptions.includeTags.sorted(),
                "excludeTags" to junitOptions.excludeTags.sorted(),
                "includeEngines" to junitOptions.includeEngines.sorted(),
                "excludeEngines" to junitOptions.excludeEngines.sorted(),
              )
            val testClasses =
              task.testClassesDirs.asFileTree.matching { include("**/*.class") }.files
            val candidateInputs = task.candidateClassFiles.files
            val candidateClasses = candidateInputs.filter { it.extension == "class" }
            val candidateNonClasses = candidateInputs.filter { it.extension != "class" }
            require(testClasses.size <= 30000 && candidateInputs.size <= 30000) {
              "Included-build class roster exceeds limit"
            }
            mapOf(
              "toolchain" to evidenceToolchain(task.javaLauncher.orNull?.metadata),
              "sourceFiles" to sources.sortedBy { it.absolutePath }.map { evidenceSource(it) },
              "inputClasses" to candidateClasses.size,
              "filtered" to
                (task.includes.isNotEmpty() ||
                  task.excludes.isNotEmpty() ||
                  task.filter.includePatterns.isNotEmpty() ||
                  task.filter.excludePatterns.isNotEmpty() ||
                  cliIncludes.isNotEmpty() ||
                  junitSelection.values.any { it.isNotEmpty() } ||
                  !task.isScanForTestClasses ||
                  task.dryRun.getOrElse(false)),
              "reportPaths" to
                listOf(evidencePath(task.reports.junitXml.outputLocation.get().asFile)),
              "errorProneEnabled" to false,
              "inputs" to
                mapOf(
                  "kind" to "test",
                  "testClasses" to
                    testClasses.sortedBy { it.absolutePath }.map { evidenceSource(it) },
                  "candidateClasses" to
                    candidateClasses.sortedBy { it.absolutePath }.map { evidenceSource(it) },
                  "candidateNonClasses" to
                    candidateNonClasses.sortedBy { it.absolutePath }.map { evidenceSource(it) },
                  "includes" to task.includes.sorted(),
                  "excludes" to task.excludes.sorted(),
                  "filterIncludes" to task.filter.includePatterns.sorted(),
                  "filterExcludes" to task.filter.excludePatterns.sorted(),
                  "commandLineIncludes" to cliIncludes,
                  "testNameIncludePatterns" to cliIncludes,
                  "junitPlatform" to junitSelection,
                  "scanForTestClasses" to task.isScanForTestClasses,
                  "dryRun" to task.dryRun.getOrElse(false),
                  "failOnNoMatchingTests" to task.filter.isFailOnNoMatchingTests,
                ),
            )
          } catch (_: Exception) {
            mapOf("inputs" to mapOf("observation" to "input-observation-failed"))
          }
        evidenceTasks[task.path] =
          mapOf("taskPath" to task.path, "startedAt" to started, "outcome" to "incomplete") +
            metadata
      }

      override fun afterExecute(task: Task, state: TaskState) {
        if (task !is Test) return
        val completed = System.currentTimeMillis()
        val reports = evidenceReports(task)
        val outcome =
          when {
            state.failure != null -> "failed"
            state.noSource -> "no-source"
            state.skipMessage == "FROM-CACHE" -> "from-cache"
            state.upToDate -> "up-to-date"
            state.skipped -> "skipped"
            else -> "executed"
          }
        evidenceTasks[task.path] =
          evidenceTasks.getOrDefault(task.path, mapOf("taskPath" to task.path)) +
            mapOf(
              "outcome" to outcome,
              "completedAt" to completed,
              "didWork" to state.didWork,
            ) +
            reports
      }
    }
  )

  @Suppress("DEPRECATION")
  gradle.buildFinished {
    val facts =
      mapOf(
        "schemaVersion" to 1,
        "kind" to "phase-12-private-gradle-task-evidence",
        "requestedTasks" to requestedEvidenceTasks,
        "generatedAt" to System.currentTimeMillis(),
        "tasks" to evidenceTasks.values.sortedBy { it["taskPath"] as String },
        "runtime" to
          mapOf(
            "javaVersion" to System.getProperty("java.version"),
            "javaVendor" to System.getProperty("java.vendor"),
            "javaArch" to System.getProperty("os.arch"),
            "filesystem" to Files.getFileStore(evidenceRoot).type(),
            "provider" to evidenceRoot.fileSystem.provider().javaClass.name,
          ),
      )
    val bytes = (JsonOutput.toJson(facts) + "\n").toByteArray(StandardCharsets.UTF_8)
    require(bytes.size <= 8 * 1024 * 1024) { "Included-build task evidence exceeds limit" }
    Files.createDirectories(evidenceOutput.parent)
    require(generateSequence(evidenceOutput) { it.parent }.none { Files.isSymbolicLink(it) }) {
      "Linked included-build evidence output"
    }
    val temporary =
      if (Files.getFileStore(evidenceOutput.parent).supportsFileAttributeView("posix")) {
        Files.createTempFile(
          evidenceOutput.parent,
          ".task-evidence-",
          ".json",
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
        )
      } else {
        Files.createTempFile(evidenceOutput.parent, ".task-evidence-", ".json")
      }
    try {
      Files.write(temporary, bytes)
      Files.move(temporary, evidenceOutput, ATOMIC_MOVE, REPLACE_EXISTING)
    } finally {
      Files.deleteIfExists(temporary)
    }
  }
}

val stableBuildLogicConfigurations =
  setOf(
    "buildLogicSettingsPluginClasspath",
    "compileClasspath",
    "rootSettingsPluginClasspath",
    "runtimeClasspath",
  )

configurations
  .matching { configuration -> configuration.name in stableBuildLogicConfigurations }
  .configureEach {
    resolutionStrategy.failOnDynamicVersions()
    resolutionStrategy.failOnChangingVersions()
  }

tasks.register("exportStableBuildLogicResolution") {
  group = "release certification"
  description = "Exports resolved build-logic and plugin artifacts for Stable build materials."
  val outputFile = layout.buildDirectory.file("stable-supply-chain/resolved-build-logic.json")
  outputs.file(outputFile)
  outputs.upToDateWhen { false }

  doLast {
    fun sha256(file: File): String {
      val digest = MessageDigest.getInstance("SHA-256")
      file.inputStream().buffered().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
          val read = input.read(buffer)
          if (read < 0) break
          digest.update(buffer, 0, read)
        }
      }
      return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    fun purl(value: String): String =
      URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    val configurationRecords = mutableListOf<Map<String, Any?>>()
    val componentRecords = sortedMapOf<String, Map<String, Any?>>()
    val relationshipRecords = mutableListOf<Map<String, Any?>>()
    val artifactRecords = mutableListOf<Map<String, Any?>>()
    stableBuildLogicConfigurations.sorted().forEach { configurationName ->
      val configuration = configurations.getByName(configurationName)
      val resolution = configuration.incoming.resolutionResult
      resolution.allComponents.forEach { component ->
        val identifier = component.id
        if (identifier is ModuleComponentIdentifier) {
          val id =
            "pkg:maven/${purl(identifier.group)}/${purl(identifier.module)}@${purl(identifier.version)}"
          componentRecords[id] =
            linkedMapOf(
              "id" to id,
              "group" to identifier.group,
              "name" to identifier.module,
              "version" to identifier.version,
            )
        }
      }
      resolution.allDependencies.forEach { dependency ->
        when (dependency) {
          is ResolvedDependencyResult -> {
            val from = dependency.from.id
            val selected = dependency.selected.id
            if (from is ModuleComponentIdentifier && selected is ModuleComponentIdentifier) {
              relationshipRecords +=
                linkedMapOf(
                  "configuration" to configurationName,
                  "from" to
                    "pkg:maven/${purl(from.group)}/${purl(from.module)}@${purl(from.version)}",
                  "to" to
                    "pkg:maven/${purl(selected.group)}/${purl(selected.module)}@${purl(selected.version)}",
                  "requested" to dependency.requested.displayName,
                  "constraint" to dependency.isConstraint,
                )
            }
          }
          is UnresolvedDependencyResult ->
            throw GradleException(
              "Unresolved build-logic dependency: ${dependency.requested.javaClass.simpleName}"
            )
        }
      }
      val artifacts = configuration.incoming.artifactView { isLenient = false }.artifacts
      if (artifacts.failures.isNotEmpty()) {
        throw GradleException("Failed to resolve Stable build-logic artifacts")
      }
      artifacts.artifacts.filterIsInstance<ResolvedArtifactResult>().forEach { artifact ->
        val file = artifact.file
        if (!file.isFile) throw GradleException("Build-logic artifact is not a file: ${file.name}")
        val identifier = artifact.id.componentIdentifier
        val componentId =
          if (identifier is ModuleComponentIdentifier) {
            "pkg:maven/${purl(identifier.group)}/${purl(identifier.module)}@${purl(identifier.version)}"
          } else {
            "pkg:generic/gradle-runtime/${purl(file.name)}@${purl(gradle.gradleVersion)}" +
              "?checksum=${sha256(file)}"
          }
        artifactRecords +=
          linkedMapOf(
            "configuration" to configurationName,
            "componentId" to componentId,
            "fileName" to file.name,
            "sha256" to sha256(file),
            "size" to file.length(),
            "attributes" to
              artifact.variant.attributes
                .keySet()
                .associate { attribute ->
                  attribute.name to artifact.variant.attributes.getAttribute(attribute).toString()
                }
                .toSortedMap(),
          )
      }
      configurationRecords +=
        linkedMapOf(
          "name" to configurationName,
          "attributes" to
            configuration.attributes
              .keySet()
              .associate { attribute ->
                attribute.name to configuration.attributes.getAttribute(attribute).toString()
              }
              .toSortedMap(),
        )
    }
    val report =
      linkedMapOf<String, Any?>(
        "schema" to "cryptad-stable-build-logic-resolution-v1",
        "dependencyVerificationMode" to
          gradle.startParameter.dependencyVerificationMode.name.lowercase(),
        "verificationFileDigests" to
          listOf(
              "gradle/verification-metadata.xml",
              "gradle/verification-keyring.gpg",
              "gradle/verification-keyring.keys",
            )
            .associateWith { relativePath ->
              val file = layout.projectDirectory.file(relativePath).asFile
              if (!file.isFile) {
                throw GradleException(
                  "Missing build-logic dependency verification input: $relativePath"
                )
              }
              sha256(file)
            }
            .toSortedMap(),
        "configurations" to
          configurationRecords.sortedBy { record -> record.getValue("name") as String },
        "components" to componentRecords.values.toList(),
        "relationships" to relationshipRecords.sortedBy { record -> JsonOutput.toJson(record) },
        "artifacts" to artifactRecords.sortedBy { record -> JsonOutput.toJson(record) },
      )
    val target = outputFile.get().asFile
    target.parentFile.mkdirs()
    target.writeText(JsonOutput.toJson(report) + "\n", StandardCharsets.UTF_8)
  }
}
