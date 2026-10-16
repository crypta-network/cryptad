import com.github.spotbugs.snom.SpotBugsTask
import cryptad.ActiveSourceFiles
import cryptad.Phase12TaskEvidence
import java.time.Instant
import javax.xml.stream.XMLOutputFactory
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.execution.TaskExecutionListener
import org.gradle.api.logging.StandardOutputListener
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters
import org.gradle.api.tasks.TaskState
import org.gradle.api.tasks.compile.JavaCompile

plugins {
  java
  jacoco
  id("com.github.spotbugs")
  id("net.ltgt.errorprone")
}

abstract class ErrorProneReportService : BuildService<BuildServiceParameters.None>

data class ErrorProneDiagnostic(
  val file: String,
  val line: Int,
  val severity: String,
  val check: String,
  val message: String,
  val details: String,
)

fun parseErrorProneDiagnostics(output: String): List<ErrorProneDiagnostic> {
  val pattern = Regex("^(.+):(\\d+): (warning|error): \\[(.+)] (.+)$")
  val diagnostics = mutableListOf<ErrorProneDiagnostic>()
  var current: ErrorProneDiagnostic? = null
  val detailsBuffer = StringBuilder()

  fun flush() {
    val diag = current ?: return
    diagnostics.add(diag.copy(details = detailsBuffer.toString().trimEnd()))
    current = null
    detailsBuffer.setLength(0)
  }

  output.lineSequence().forEach { line ->
    val match = pattern.matchEntire(line)
    if (match != null) {
      flush()
      val file = match.groupValues[1]
      val lineNumber = match.groupValues[2].toInt()
      val severity = match.groupValues[3]
      val check = match.groupValues[4]
      val message = match.groupValues[5]
      current = ErrorProneDiagnostic(file, lineNumber, severity, check, message, "")
    } else if (current != null) {
      if (line.isNotBlank()) {
        detailsBuffer.append(line).append('\n')
      }
    }
  }
  flush()
  return diagnostics
}

val libs: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")

val errorproneReportService =
  gradle.sharedServices.registerIfAbsent(
    "errorproneReportService",
    ErrorProneReportService::class,
  ) {
    maxParallelUsages.set(1)
  }

val errorproneReportTask =
  tasks.register("errorproneReport") {
    group = "verification"
    description = "Generates Error Prone XML reports for Java compile tasks."
  }

errorproneReportTask.configure { dependsOn(tasks.withType<JavaCompile>()) }

val errorproneReportEnabled = providers.provider {
  gradle.startParameter.taskNames.any { taskName ->
    taskName == "errorproneReport" || taskName.endsWith(":errorproneReport")
  }
}

// Evidence jobs require new test/analyzer execution while ordinary developer builds retain reuse.
val phase12Evidence = providers.gradleProperty("phase12Evidence").map { it == "true" }.orElse(false)

if (phase12Evidence.get() && project == rootProject) {
  require(!gradle.startParameter.isConfigurationCacheRequested) {
    "Phase 12 task observation requires configuration caching disabled"
  }
  val recorder =
    Phase12TaskEvidence(
      rootDir,
      layout.buildDirectory.file("phase12/task-evidence.json").get().asFile,
      gradle.startParameter.taskNames,
    )
  @Suppress("DEPRECATION") gradle.taskGraph.addTaskExecutionListener(recorder)
  @Suppress("DEPRECATION") gradle.buildFinished { recorder.finish() }
}

tasks.withType<Test>().configureEach {
  if (phase12Evidence.get()) {
    outputs.upToDateWhen { false }
    outputs.doNotCacheIf("Phase 12 requires original test execution") { true }
    // The single opt-in FEC smoke benchmark asserts execution, not a timing threshold.
    systemProperty("test.benchmark", "true")
  }
}

spotbugs { ignoreFailures = true }

val spotbugsExcludeFilter =
  rootProject.layout.projectDirectory.file("build-logic/spotbugs-exclude.xml")

val spotbugsTestExcludeFilter =
  rootProject.layout.projectDirectory.file("build-logic/spotbugs-exclude-test.xml")

tasks.withType<SpotBugsTask>().configureEach {
  // Analysis traverses dependency implementations as well as their public compile signatures.
  // Preserve compile-only annotation inputs and add runtime implementation dependencies.
  val compileAuxiliaryClasspath = auxClassPaths
  val owningSources = sourceSets.named(if (name == "spotbugsTest") "test" else "main")
  auxClassPaths = files(compileAuxiliaryClasspath, owningSources.map { it.runtimeClasspath })
  if (phase12Evidence.get()) {
    outputs.upToDateWhen { false }
    outputs.doNotCacheIf("Phase 12 requires original analyzer execution") { true }
  }
  excludeFilter.set(
    if (name == "spotbugsTest") spotbugsTestExcludeFilter else spotbugsExcludeFilter
  )

  val xmlReport = reports.maybeCreate("xml")
  xmlReport.required.set(true)
  xmlReport.outputLocation.set(layout.buildDirectory.file("reports/spotbugs/$name.xml"))

  reports.matching { it.name == "text" }.configureEach { required.set(false) }
}

java {
  toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
  sourceCompatibility = JavaVersion.VERSION_25
  targetCompatibility = JavaVersion.VERSION_25
}

repositories {
  mavenCentral {
    metadataSources {
      mavenPom()
      artifact()
      ignoreGradleMetadataRedirection()
    }
  }
}

sourceSets.named("main") {
  // Exclude templated Version.java from direct compilation; generated source is compiled instead.
  java.exclude("network/crypta/node/Version.java")
}

val activeSourceRoster = ActiveSourceFiles.selectedRoster(rootProject)

sourceSets.configureEach {
  val owningJava = java
  java.exclude { element ->
    val generatedRoots =
      owningJava.srcDirs
        .filter { it.toPath().startsWith(layout.buildDirectory.get().asFile.toPath()) }
        .toSet()
    ActiveSourceFiles.excludeUnselected(rootDir, element.file, generatedRoots) {
      activeSourceRoster.value
    }
  }
}

dependencies { add("errorprone", libs.findLibrary("errorproneCore").get()) }

tasks.withType<JavaCompile>().configureEach {
  options.encoding = "UTF-8"
  // Surface deprecation/unchecked sites explicitly during compilation.
  options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Xlint:unchecked"))
  options.errorprone.allErrorsAsWarnings.set(true)

  val taskPathLabel = path.removePrefix(":").replace(':', '_').ifBlank { "root" }
  val reportFileProvider = layout.buildDirectory.file("reports/errorprone/$taskPathLabel/$name.xml")
  if (errorproneReportEnabled.get()) {
    // javac's default 100-warning cap otherwise silently truncates analyzer evidence.
    options.compilerArgs.addAll(listOf("-Xmaxwarns", "10000", "-Xmaxerrs", "10000"))
    outputs.file(reportFileProvider)
    outputs.upToDateWhen { false }
    usesService(errorproneReportService)
    outputs.doNotCacheIf("Error Prone reports require original compiler diagnostics") { true }
    // Incremental javac may analyze only changed files even when the task itself executes.
    options.isIncremental = false
  }

  val capturedOutput = StringBuilder()
  var captureOverflow = false
  val capture: (CharSequence) -> Unit = { text ->
    synchronized(capturedOutput) {
      if (capturedOutput.length + text.length <= 16 * 1024 * 1024) capturedOutput.append(text)
      else captureOverflow = true
    }
  }
  val standardOutListener = StandardOutputListener { capture(it) }
  val standardErrListener = StandardOutputListener { capture(it) }

  if (errorproneReportEnabled.get()) {
    val compileTask = this
    @Suppress("DEPRECATION")
    gradle.taskGraph.addTaskExecutionListener(
      object : TaskExecutionListener {
        override fun beforeExecute(task: Task) {}

        override fun afterExecute(task: Task, state: TaskState) {
          if (task == compileTask) {
            logging.removeStandardOutputListener(standardOutListener)
            logging.removeStandardErrorListener(standardErrListener)
          }
        }
      }
    )
  }

  doFirst {
    if (!errorproneReportEnabled.get()) return@doFirst
    // A failed compiler cannot leave an older successful report available to the collector.
    reportFileProvider.get().asFile.delete()
    capturedOutput.setLength(0)
    captureOverflow = false
    logging.addStandardOutputListener(standardOutListener)
    logging.addStandardErrorListener(standardErrListener)
  }

  doLast {
    if (!errorproneReportEnabled.get()) return@doLast
    logging.removeStandardOutputListener(standardOutListener)
    logging.removeStandardErrorListener(standardErrListener)
    check(!captureOverflow) { "Error Prone diagnostic capture exceeded its bound" }

    val diagnostics = parseErrorProneDiagnostics(capturedOutput.toString())
    val diagnosticsComplete =
      Phase12TaskEvidence.diagnosticsComplete(capturedOutput.toString(), diagnostics.size)
    val reportFile = reportFileProvider.get().asFile
    reportFile.parentFile.mkdirs()

    val writer =
      XMLOutputFactory.newInstance().createXMLStreamWriter(reportFile.writer(Charsets.UTF_8))
    writer.writeStartDocument("UTF-8", "1.0")
    writer.writeStartElement("errorproneReport")
    writer.writeAttribute("project", project.path)
    writer.writeAttribute("task", name)
    writer.writeAttribute("generatedAt", Instant.now().toString())
    writer.writeAttribute("compilerCompleted", "true")
    writer.writeAttribute("diagnosticsComplete", diagnosticsComplete.toString())
    writer.writeAttribute("sourceFiles", source.files.count { it.extension == "java" }.toString())
    diagnostics.forEach { diagnostic ->
      writer.writeStartElement("diagnostic")
      writer.writeAttribute("severity", diagnostic.severity)
      writer.writeAttribute("check", diagnostic.check)
      writer.writeAttribute("file", diagnostic.file)
      writer.writeAttribute("line", diagnostic.line.toString())

      writer.writeStartElement("message")
      writer.writeCharacters(diagnostic.message)
      writer.writeEndElement()

      if (diagnostic.details.isNotBlank()) {
        writer.writeStartElement("details")
        writer.writeCharacters(diagnostic.details)
        writer.writeEndElement()
      }
      writer.writeEndElement()
    }
    writer.writeEndElement()
    writer.writeEndDocument()
    writer.flush()
    writer.close()
  }
}

tasks.withType<Javadoc>().configureEach {
  options.encoding = "UTF-8"
  isFailOnError = false
}

// Tests: settings and module opens needed at runtime
tasks.withType<Test>().configureEach {
  useJUnitPlatform()
  // Security-sensitive fixtures reject symlinked ancestors, including macOS /var aliases.
  systemProperty("java.io.tmpdir", File(System.getProperty("java.io.tmpdir")).canonicalPath)
  val sourceRoster = layout.buildDirectory.file("phase12/main-java-sources.txt")
  doFirst {
    val configuredRoot = rootProject.projectDir.toPath().toAbsolutePath().normalize()
    val root = configuredRoot.toRealPath()
    val paths =
      sourceSets
        .getByName("main")
        .allJava
        .files
        .map { file ->
          val selected = file.toPath().toAbsolutePath().normalize()
          val member =
            when {
              selected.startsWith(configuredRoot) -> configuredRoot.relativize(selected)
              selected.startsWith(root) -> root.relativize(selected)
              else -> error("Test source roster escapes repository")
            }
          member.toString().replace(File.separatorChar, '/').also { name ->
            require(name.none { it.code < 32 } && '\\' !in name) { "Unsafe test source name" }
          }
        }
        .sorted()
    require(paths.size <= 30000) { "Test source roster too large" }
    val bytes = (paths.joinToString("\n") + "\n").toByteArray(Charsets.UTF_8)
    require(bytes.size <= 4 * 1024 * 1024) { "Test source roster too large" }
    val output = sourceRoster.get().asFile
    output.parentFile.mkdirs()
    output.writeBytes(bytes)
    systemProperty("cryptad.test.mainJavaSourceRoster", output.absolutePath)
  }
  // Verbose failures: full exception stack traces/causes for easier debugging
  testLogging { exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
  // Open JDK internals used by tests
  if (JavaVersion.current() >= JavaVersion.VERSION_1_9) {
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util.zip=ALL-UNNAMED")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
  }
  // Allow dynamic agent loading for Mockito inline mock-maker (JEP 451).
  jvmArgs("-XX:+EnableDynamicAgentLoading")
  minHeapSize = "128m"
  maxHeapSize = "512m"
  include("network/crypta/**/*Test.class")
  include("com/jthemedetecor/**/*Test.class")
  include("com/onionnetworks/**/*Test.class")
  include("org/bitpedia/**/*Test.class")
  include("org/spaceroots/**/*Test.class")
  include("org/sevenzip/**/*Test.class")
  include("org/spaceroots/**/*Test.class")
  exclude("network/crypta/**/*$*Test.class")
  exclude("com/jthemedetecor/**/*$*Test.class")
  exclude("com/onionnetworks/**/*$*Test.class")
  exclude("org/bitpedia/**/*$*Test.class")
  exclude("org/spaceroots/**/*$*Test.class")
  exclude("org/sevenzip/**/*$*Test.class")
  exclude("org/spaceroots/**/*$*Test.class")
  // Point tests expecting old layout to new standard resource locations
  systemProperty("test.l10npath_test", "src/test/resources/network/crypta/l10n/")
  systemProperty("test.l10npath_main", "foundation-config/src/main/resources/network/crypta/l10n/")
}

// Match prior behavior: disable assertions in tests
tasks.withType<Test>().configureEach { enableAssertions = false }

// JaCoCo setup: use a recent agent and produce XML for Sonar
extensions.configure<JacocoPluginExtension>("jacoco") {
  toolVersion = libs.findVersion("jacoco").get().requiredVersion
}

// Generate XML + HTML reports; ensure reports run after tests
tasks.withType<JacocoReport>().configureEach {
  dependsOn(tasks.withType<Test>())
  reports {
    xml.required.set(true)
    csv.required.set(false)
    html.required.set(true)
  }
}

// Enforce a coverage threshold (80% minimum)
tasks.withType<JacocoCoverageVerification>().configureEach {
  dependsOn(tasks.withType<Test>())
  violationRules {
    // Do not fail the build on coverage violations; still log them
    isFailOnViolation = false
    rule {
      limit {
        counter = "LINE"
        value = "COVEREDRATIO"
        minimum = BigDecimal("0.80")
      }
    }
  }
}

// Integrate coverage checks with the standard lifecycle
tasks.named("check") {
  dependsOn(tasks.withType<JacocoReport>())
  dependsOn(tasks.withType<JacocoCoverageVerification>())
}
