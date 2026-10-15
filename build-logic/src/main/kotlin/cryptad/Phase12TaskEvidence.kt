package cryptad

import com.github.spotbugs.snom.SpotBugsTask
import groovy.json.JsonOutput
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.Task
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.TaskState
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.junitplatform.JUnitPlatformOptions
import org.gradle.jvm.toolchain.JavaInstallationMetadata

/**
 * Private, opt-in observation of Gradle's selected inputs and real task outcomes.
 *
 * Register one instance with `gradle.taskGraph.addTaskExecutionListener(recorder)`, then call
 * [finish] from `gradle.buildFinished`. The latter also runs after a failed task. This listener
 * deliberately uses the execution graph: a doFirst action cannot observe NO-SOURCE or cache hits.
 * This compatibility path requires configuration caching to remain disabled in evidence mode. Its
 * output is private input to the bounded CI projection, never an uploadable artifact.
 */
@Suppress("DEPRECATION")
class Phase12TaskEvidence(
  repositoryRoot: File,
  private val output: File,
  private val requestedTasks: List<String> = emptyList(),
) : org.gradle.api.execution.TaskExecutionListener {
  private val root = repositoryRoot.toPath().toRealPath()
  private val pending = ConcurrentHashMap<String, Map<String, Any?>>()
  private val completed = ConcurrentHashMap<String, Map<String, Any?>>()

  override fun beforeExecute(task: Task) {
    if (!selected(task)) return
    val started = System.currentTimeMillis()
    val metadata =
      try {
        metadata(task)
      } catch (_: Exception) {
        // Keep a failed observation without copying exception messages or diagnostics.
        mapOf("observation" to "input-observation-failed")
      }
    pending[task.path] =
      mapOf("taskPath" to task.path, "startedAt" to started, "inputs" to metadata) +
        metadata.filterKeys {
          it in
            setOf(
              "sourceFiles",
              "inputClasses",
              "filtered",
              "reportPaths",
              "errorProneEnabled",
              "toolchain",
            )
        }
  }

  override fun afterExecute(task: Task, state: TaskState) {
    if (!selected(task)) return
    val before =
      pending.remove(task.path)
        ?: mapOf("taskPath" to task.path, "inputs" to emptyMap<String, Any>())
    val outputs =
      try {
        @Suppress("UNCHECKED_CAST")
        reportSnapshot(
          root.toFile(),
          (before["reportPaths"] as? List<String> ?: error("Missing report paths")).map {
            root.resolve(it).toFile()
          },
          task is Test,
        )
      } catch (_: Exception) {
        mapOf("reportObservation" to "invalid", "reportFiles" to emptyList<Map<String, Any>>())
      }
    completed[task.path] =
      before +
        outputs +
        mapOf(
          "completedAt" to System.currentTimeMillis(),
          "outcome" to
            outcome(
              state.failure != null,
              state.noSource,
              state.skipMessage,
              state.upToDate,
              state.skipped,
            ),
          "didWork" to state.didWork,
        )
  }

  /** Publishes this build atomically; interrupted tasks remain explicitly incomplete. */
  fun finish() {
    val rows =
      (completed.values + pending.values.map { it + mapOf("outcome" to "incomplete") }).sortedBy {
        it["taskPath"] as String
      }
    require(rows.size <= 512) { "Too many evidence tasks" }
    val bytes =
      (JsonOutput.toJson(
          mapOf(
            "schemaVersion" to 1,
            "kind" to "phase-12-private-gradle-task-evidence",
            "tasks" to rows,
            "requestedTasks" to requestedTasks,
            "generatedAt" to System.currentTimeMillis(),
            "runtime" to
              mapOf(
                "javaVersion" to System.getProperty("java.version"),
                "javaVendor" to System.getProperty("java.vendor"),
                "javaArch" to System.getProperty("os.arch"),
                "filesystem" to Files.getFileStore(root).type(),
                "provider" to root.fileSystem.provider().javaClass.name,
              ),
          )
        ) + "\n")
        .toByteArray(Charsets.UTF_8)
    require(bytes.size <= 32 * 1024 * 1024) { "Task evidence exceeds limit" }
    output.parentFile.mkdirs()
    val path = output.toPath().toAbsolutePath()
    require(path.parents().none { Files.isSymbolicLink(it) } && !Files.isSymbolicLink(path)) {
      "Unsafe task evidence parent"
    }
    val temporary =
      if (Files.getFileStore(path.parent).supportsFileAttributeView("posix")) {
        Files.createTempFile(
          path.parent,
          ".task-evidence-",
          ".json",
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
        )
      } else {
        Files.createTempFile(path.parent, ".task-evidence-", ".json")
      }
    try {
      Files.write(temporary, bytes)
      Files.move(temporary, path, ATOMIC_MOVE, REPLACE_EXISTING)
    } finally {
      Files.deleteIfExists(temporary)
    }
  }

  private fun selected(task: Task): Boolean =
    task is JavaCompile || task is Test || task is SpotBugsTask

  private fun metadata(task: Task): Map<String, Any?> =
    when (task) {
      is JavaCompile ->
        mapOf(
          "kind" to "java-compile",
          "sourceFiles" to roster(task.source.files),
          "inputClasses" to 0,
          "filtered" to false,
          "errorProneEnabled" to task.options.errorprone.enabled.getOrElse(false),
          "reportPaths" to
            listOf(
              relative(
                task.project.layout.buildDirectory
                  .file(
                    "reports/errorprone/${task.path.removePrefix(":").replace(':', '_')}/${task.name}.xml"
                  )
                  .get()
                  .asFile
              )
            ),
          "classpath" to classpathRoster(task.classpath.files),
          "incremental" to task.options.isIncremental,
          "compilerArguments" to task.options.compilerArgs.toList(),
          "analyzerConfiguration" to
            task.options.errorprone.run {
              mapOf(
                "enabled" to enabled.getOrElse(false),
                "allErrorsAsWarnings" to allErrorsAsWarnings.getOrElse(false),
                "disableAllChecks" to disableAllChecks.getOrElse(false),
                "disableAllWarnings" to disableAllWarnings.getOrElse(false),
                "allSuggestionsAsWarnings" to allSuggestionsAsWarnings.getOrElse(false),
                "allDisabledChecksAsWarnings" to allDisabledChecksAsWarnings.getOrElse(false),
                "disableWarningsInGeneratedCode" to disableWarningsInGeneratedCode.getOrElse(false),
                "ignoreUnknownCheckNames" to ignoreUnknownCheckNames.getOrElse(false),
                "ignoreSuppressionAnnotations" to ignoreSuppressionAnnotations.getOrElse(false),
                "compilingTestOnlyCode" to compilingTestOnlyCode.getOrElse(false),
                "excludedPaths" to excludedPaths.orNull,
                "checks" to checks.getOrElse(emptyMap()).mapValues { it.value.name },
                "checkOptions" to checkOptions.getOrElse(emptyMap()),
                "extraArgs" to errorproneArgs.getOrElse(emptyList()),
                "errorproneArgumentProviders" to errorproneArgumentProviders.size,
                "compilerArgumentProviders" to
                  task.options.compilerArgumentProviders.map { it.javaClass.name },
                "forkJvmArgumentProviders" to
                  task.options.forkOptions.jvmArgumentProviders.map { it.javaClass.name },
                "forkJvmArguments" to task.options.forkOptions.jvmArgs.orEmpty(),
                "argumentFiles" to roster(argumentFiles.files),
              )
            },
          "compilerVersion" to task.javaCompiler.orNull?.metadata?.languageVersion?.toString(),
          "toolchain" to toolchain(task.javaCompiler.orNull?.metadata),
        )
      is Test ->
        mapOf(
          "kind" to "test",
          "toolchain" to toolchain(task.javaLauncher.orNull?.metadata),
          "sourceFiles" to testSources(task),
          "inputClasses" to task.candidateClassFiles.files.count { it.extension == "class" },
          "filtered" to
            (task.filter.includePatterns.isNotEmpty() ||
              task.filter.excludePatterns.isNotEmpty() ||
              commandLineIncludes(task).isNotEmpty() ||
              task.includes != TEST_CLASS_INCLUDES ||
              task.excludes != TEST_CLASS_EXCLUDES ||
              junitSelection(task).values.any { it.isNotEmpty() } ||
              !task.isScanForTestClasses ||
              task.dryRun.getOrElse(false)),
          "errorProneEnabled" to false,
          "reportPaths" to listOf(relative(task.reports.junitXml.outputLocation.get().asFile)),
          "candidateClasses" to
            roster(task.candidateClassFiles.files.filter { it.extension == "class" }),
          "candidateNonClasses" to
            roster(task.candidateClassFiles.files.filter { it.extension != "class" }),
          "testClasses" to
            roster(task.testClassesDirs.asFileTree.matching { include(CLASS_FILE_PATTERN) }.files),
          "includes" to task.includes.sorted(),
          "excludes" to task.excludes.sorted(),
          "testClassPolicyDigest" to policyDigest(task.includes, task.excludes),
          "filterIncludes" to task.filter.includePatterns.sorted(),
          "filterExcludes" to task.filter.excludePatterns.sorted(),
          "commandLineIncludes" to commandLineIncludes(task),
          "testNameIncludePatterns" to commandLineIncludes(task),
          "junitPlatform" to junitSelection(task),
          "scanForTestClasses" to task.isScanForTestClasses,
          "dryRun" to task.dryRun.getOrElse(false),
          "failOnNoMatchingTests" to task.filter.isFailOnNoMatchingTests,
          "junitXml" to relative(task.reports.junitXml.outputLocation.get().asFile),
        )
      is SpotBugsTask ->
        mapOf(
          "kind" to "spotbugs",
          "toolchain" to toolchain(task.launcher.orNull?.metadata),
          "sourceFiles" to compileSources(task),
          "inputClasses" to
            requireNotNull(task.classes)
              .asFileTree
              .matching { include(CLASS_FILE_PATTERN) }
              .files
              .size,
          "filtered" to
            (task.onlyAnalyze.getOrElse(emptyList()).isNotEmpty() ||
              task.visitors.getOrElse(emptyList()).isNotEmpty() ||
              task.omitVisitors.getOrElse(emptyList()).isNotEmpty() ||
              task.chooseVisitors.getOrElse(emptyList()).isNotEmpty()),
          "errorProneEnabled" to false,
          "reportPaths" to
            listOf(
              relative(
                task.project.layout.buildDirectory
                  .file("reports/spotbugs/${task.name}.xml")
                  .get()
                  .asFile
              )
            ),
          "classes" to
            roster(
              requireNotNull(task.classes).asFileTree.matching { include(CLASS_FILE_PATTERN) }.files
            ),
          "ownedClasses" to
            roster(
              task.project.extensions
                .getByType(SourceSetContainer::class.java)
                .getByName(if (task.name == "spotbugsTest") "test" else "main")
                .output
                .classesDirs
                .asFileTree
                .matching { include(CLASS_FILE_PATTERN) }
                .files
            ),
          "analyzerConfiguration" to
            mapOf(
              "effort" to task.effort.orNull?.name,
              "reportLevel" to task.reportLevel.orNull?.name,
              "extraArgs" to task.extraArgs.getOrElse(emptyList()),
              "jvmArgs" to task.jvmArgs.getOrElse(emptyList()),
              "pluginJarFiles" to roster(task.pluginJarFiles.files),
            ),
          "auxClasspath" to classpathRoster(task.auxClassPaths.files),
          "onlyAnalyze" to task.onlyAnalyze.getOrElse(emptyList()),
          "visitors" to task.visitors.getOrElse(emptyList()),
          "omitVisitors" to task.omitVisitors.getOrElse(emptyList()),
          "chooseVisitors" to task.chooseVisitors.getOrElse(emptyList()),
          "excludeFilter" to roster(listOfNotNull(task.excludeFilter.orNull?.asFile)),
          "includeFilter" to roster(listOfNotNull(task.includeFilter.orNull?.asFile)),
          "baseline" to roster(listOfNotNull(task.baselineFile.orNull?.asFile)),
        )
      else -> error("Unselected task")
    }

  private fun testSources(task: Test): List<Map<String, Any>> {
    val sources =
      task.project.extensions.getByType(SourceSetContainer::class.java).getByName("test")
    return roster(sources.allSource.matching { include("**/*.java", "**/*.kt") }.files)
  }

  private fun compileSources(task: SpotBugsTask): List<Map<String, Any>> {
    val name = if (task.name == "spotbugsTest") "compileTestJava" else "compileJava"
    return roster(task.project.tasks.named(name, JavaCompile::class.java).get().source.files)
  }

  // Gradle exposes CLI --tests on its filter implementation, separately from includePatterns.
  private fun commandLineIncludes(task: Test): List<String> {
    val method =
      task.filter.javaClass.methods.singleOrNull {
        it.name == "getCommandLineIncludePatterns" && it.parameterCount == 0
      } ?: error("Cannot observe command-line test filters")
    val value =
      method.invoke(task.filter) as? Collection<*> ?: error("Invalid command-line test filters")
    return value.map { it as String }.sorted()
  }

  private fun junitSelection(task: Test): Map<String, List<String>> {
    val options = task.options as? JUnitPlatformOptions ?: error("Unexpected test framework")
    return mapOf(
      "includeTags" to options.includeTags.sorted(),
      "excludeTags" to options.excludeTags.sorted(),
      "includeEngines" to options.includeEngines.sorted(),
      "excludeEngines" to options.excludeEngines.sorted(),
    )
  }

  private fun relative(file: File): String {
    val path = file.toPath().toAbsolutePath().normalize()
    require(path.startsWith(root)) { "Report outside repository" }
    return root.relativize(path).toString().replace(File.separatorChar, '/')
  }

  private fun roster(files: Set<File>): List<Map<String, Any>> = roster(files.toList())

  private fun classpathRoster(files: Set<File>): List<Map<String, Any>> {
    require(files.size <= 30000) { "Classpath exceeds limit" }
    return files
      .sortedBy { it.absolutePath }
      .map { file ->
        if (Files.notExists(file.toPath(), NOFOLLOW_LINKS)) {
          mapOf("path" to file.absolutePath, "kind" to "missing")
        } else {
          fingerprint(root.toFile(), file)
        }
      }
  }

  private fun roster(files: List<File>): List<Map<String, Any>> {
    require(files.size <= 30000) { "Input roster exceeds limit" }
    return files.sortedBy { it.absolutePath }.map { file -> fingerprint(root.toFile(), file) }
  }

  companion object {
    private const val CLASS_FILE_PATTERN = "**/*.class"

    /**
     * Captures exact bounded report bytes after task completion; no private hash is exported. Unix
     * link counts permit early hard-link refusal. Providers without that attribute still require
     * the collector's independent link-count check before private report admission.
     */
    fun reportSnapshot(
      repositoryRoot: File,
      outputs: List<File>,
      junit: Boolean,
    ): Map<String, Any> {
      require(outputs.size == 1) { "Unexpected report output roster" }
      val roster = reportRoster(outputs.single(), junit)
      var total = 0L
      val observations =
        roster.files
          .sortedBy { it.absolutePath }
          .map { file ->
            val path = file.toPath()
            val attrs = reportMemberAttributes(path)
            total += attrs.size()
            require(total <= 256L * 1024 * 1024) { "Report bytes exceed limit" }
            val observed = fingerprint(repositoryRoot, file)
            requireSingleReportLink(path, "Changing report links")
            mapOf(
              "path" to observed.getValue("path"),
              "size" to observed.getValue("size"),
              "sha256" to observed.getValue("digest"),
            )
          }
      roster.directory?.verifyUnchanged(roster.files)
      return mapOf("reportObservation" to "complete", "reportFiles" to observations)
    }

    private data class ReportRoster(
      val files: List<File>,
      val directory: ReportDirectory? = null,
    )

    private class ReportDirectory(val path: Path, val before: BasicFileAttributes) {
      fun verifyUnchanged(files: List<File>) {
        val current = junitReportFiles(path).map { it.name }.toSet()
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(
          after.isDirectory &&
            before.fileKey() == after.fileKey() &&
            before.lastModifiedTime() == after.lastModifiedTime() &&
            path.toRealPath() == path &&
            path.parents().none { Files.isSymbolicLink(it) } &&
            current == files.map { it.name }.toSet()
        ) {
          "Changing report roster"
        }
      }
    }

    private fun reportRoster(output: File, junit: Boolean): ReportRoster {
      val path = output.toPath().toAbsolutePath().normalize()
      require(path.parents().none { Files.isSymbolicLink(it) } && !Files.isSymbolicLink(path)) {
        "Linked report output"
      }
      if (Files.notExists(path, NOFOLLOW_LINKS)) return ReportRoster(emptyList())
      if (!junit) return ReportRoster(listOf(output))
      require(Files.isDirectory(path, NOFOLLOW_LINKS) && path.toRealPath() == path) {
        "Invalid report directory"
      }
      val directory =
        ReportDirectory(
          path,
          Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS),
        )
      return ReportRoster(junitReportFiles(path), directory)
    }

    private fun junitReportFiles(directory: Path): List<File> {
      val files = mutableListOf<File>()
      Files.newDirectoryStream(directory).use { entries ->
        var count = 0
        for (entry in entries) {
          require(++count <= 4096) { "Report roster exceeds limit" }
          val name = entry.fileName.toString()
          if (name.startsWith("TEST-") && name.endsWith(".xml")) files.add(entry.toFile())
        }
      }
      return files
    }

    private fun reportMemberAttributes(path: Path): BasicFileAttributes {
      val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
      require(attrs.isRegularFile && attrs.size() <= 16L * 1024 * 1024) {
        "Invalid report member"
      }
      requireSingleReportLink(path, "Linked report member")
      return attrs
    }

    private fun requireSingleReportLink(path: Path, message: String) {
      if (Files.getFileStore(path).supportsFileAttributeView("unix")) {
        require((Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L) {
          message
        }
      }
    }

    /** Refuse javac's truncated diagnostic summary or a capture reaching its declared cap. */
    fun diagnosticsComplete(output: String, diagnosticCount: Int): Boolean =
      diagnosticCount < 10000 &&
        !output.contains("only showing the first") &&
        !Regex("(?m)^10000 (?:warnings|errors)\\s*$").containsMatchIn(output)

    private val TEST_PACKAGES =
      setOf(
        "network/crypta",
        "com/jthemedetecor",
        "com/onionnetworks",
        "org/bitpedia",
        "org/spaceroots",
        "org/sevenzip",
      )
    private val TEST_CLASS_INCLUDES = TEST_PACKAGES.map { "$it/**/*Test.class" }.toSet()
    private val TEST_CLASS_EXCLUDES = TEST_PACKAGES.map { $$"$$it/**/*$*Test.class" }.toSet()

    /** Observes the selected toolchain, separately from the Gradle daemon's runtime facts. */
    fun toolchain(metadata: JavaInstallationMetadata?): Map<String, String>? {
      if (metadata == null) return null
      return try {
        // The installation is selected by Gradle's toolchain owner. Resolve that trusted root once;
        // the release member itself must remain a stable regular file opened without following
        // links.
        val installation = metadata.installationPath.asFile.toPath().toRealPath()
        val release = installation.resolve("release")
        val before = Files.readAttributes(release, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(before.isRegularFile && before.size() in 1L..65536L) { "Invalid toolchain release" }
        val raw = Files.newInputStream(release, NOFOLLOW_LINKS).use { it.readNBytes(65537) }
        val after = Files.readAttributes(release, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(
          raw.size.toLong() == before.size() &&
            after.size() == before.size() &&
            after.fileKey() == before.fileKey() &&
            after.lastModifiedTime() == before.lastModifiedTime()
        ) {
          "Changing toolchain release"
        }
        val architectures =
          Regex("(?m)^OS_ARCH=\"([A-Za-z0-9_+-]{1,32})\"\\r?$")
            .findAll(raw.toString(Charsets.UTF_8))
            .toList()
        require(architectures.size == 1) { "Missing toolchain architecture" }
        mapOf(
          "javaVersion" to metadata.javaRuntimeVersion,
          "javaVendor" to metadata.vendor,
          "javaArch" to architectures.single().groupValues[1],
        )
      } catch (_: Exception) {
        null
      }
    }

    fun policyDigest(includes: Set<String>, excludes: Set<String>): String {
      val bytes =
        JsonOutput.toJson(mapOf("includes" to includes.sorted(), "excludes" to excludes.sorted()))
          .toByteArray(Charsets.UTF_8)
      return "sha256:" +
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    /** Maps native Gradle state without interpreting reuse or non-execution as fresh execution. */
    fun outcome(
      failed: Boolean,
      noSource: Boolean,
      skipMessage: String?,
      upToDate: Boolean,
      skipped: Boolean,
    ): String =
      when {
        failed -> "failed"
        noSource -> "no-source"
        skipMessage == "FROM-CACHE" -> "from-cache"
        upToDate -> "up-to-date"
        skipped -> "skipped"
        else -> "executed"
      }

    /** Fingerprints a stable regular input; directories retain identity without recursive scans. */
    fun fingerprint(repositoryRoot: File, file: File): Map<String, Any> {
      val root = repositoryRoot.toPath().toRealPath()
      val path = file.toPath().toAbsolutePath().normalize()
      require(path.parents().none { Files.isSymbolicLink(it) } && !Files.isSymbolicLink(path)) {
        "Linked task input"
      }
      require(path.toRealPath() == path) { "Aliased task input" }
      val name =
        if (path.startsWith(root)) root.relativize(path).toString().replace(File.separatorChar, '/')
        else path.toString()
      val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
      if (attrs.isDirectory) return mapOf("path" to name, "kind" to "directory")
      require(attrs.isRegularFile && attrs.size() <= 256L * 1024 * 1024) {
        "Unsupported task input"
      }
      val digest = MessageDigest.getInstance("SHA-256")
      var count = 0L
      Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
        val buffer = ByteArray(65536)
        while (true) {
          val read = input.read(buffer)
          if (read < 0) break
          count += read
          require(count <= attrs.size()) { "Growing task input" }
          digest.update(buffer, 0, read)
        }
      }
      val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
      require(path.parents().none { Files.isSymbolicLink(it) } && path.toRealPath() == path) {
        "Aliased task input"
      }
      require(
        count == attrs.size() &&
          after.size() == count &&
          after.fileKey() == attrs.fileKey() &&
          after.lastModifiedTime() == attrs.lastModifiedTime()
      ) {
        "Changing task input"
      }
      return mapOf(
        "path" to name,
        "kind" to "file",
        "size" to count,
        "digest" to ("sha256:" + digest.digest().joinToString("") { "%02x".format(it) }),
      )
    }
  }
}

private fun Path.parents(): Sequence<Path> = generateSequence(parent) { it.parent }
