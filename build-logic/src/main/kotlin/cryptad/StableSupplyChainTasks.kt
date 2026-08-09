package cryptad

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

abstract class StableSupplyChainResolutionTask @Inject constructor() : DefaultTask() {
  @get:Input abstract val configurationDescriptors: ListProperty<String>

  @get:Input abstract val vendoredDescriptors: ListProperty<String>

  @get:Input abstract val directInputDescriptors: ListProperty<String>

  @get:InputFiles
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val materialFiles: ConfigurableFileCollection

  @get:Input abstract val releaseVersion: Property<String>

  @get:Input abstract val sourceCommit: Property<String>

  @get:Input abstract val sourceRef: Property<String>

  @get:Input abstract val gitTreeObjectId: Property<String>

  @get:Input abstract val sourceTreeClean: Property<Boolean>

  @get:Input abstract val sourceStatusDigest: Property<String>

  @get:Input abstract val dependencyVerificationMode: Property<String>

  @get:Input abstract val gradleVersion: Property<String>

  @get:Input abstract val jdkIdentity: MapProperty<String, String>

  @get:Input abstract val jdkModules: ListProperty<String>

  @get:Input abstract val releaseTasks: ListProperty<String>

  @get:Input abstract val allowedEnvironmentVariables: ListProperty<String>

  @get:Input abstract val policyDigest: Property<String>

  @get:Internal
  protected val rootProjectDirectory: File
    get() = project.rootProject.rootDir

  protected fun generateDocuments(): StableResolutionDocuments =
    StableSupplyChainResolution.build(
      rootProject = project.rootProject,
      configurationDescriptors = configurationDescriptors.get(),
      vendoredDescriptors = vendoredDescriptors.get(),
      directInputDescriptors = directInputDescriptors.get(),
      materialFiles = materialFiles.files,
      releaseVersion = releaseVersion.get(),
      sourceCommit = sourceCommit.get(),
      sourceRef = sourceRef.get(),
      gitTreeObjectId = gitTreeObjectId.get(),
      sourceTreeClean = sourceTreeClean.get(),
      sourceStatusDigest = sourceStatusDigest.get(),
      dependencyVerificationMode = dependencyVerificationMode.get(),
      gradleVersion = gradleVersion.get(),
      jdk = jdkIdentity.get(),
      jdkModules = jdkModules.get(),
      releaseTasks = releaseTasks.get(),
      allowedEnvironmentVariables = allowedEnvironmentVariables.get(),
      policyDigest = policyDigest.get(),
    )
}

@DisableCachingByDefault(
  because = "The task resolves one project's live Gradle model into a canonical fragment"
)
abstract class ExportStableSupplyChainResolutionFragment @Inject constructor() :
  StableSupplyChainResolutionTask() {
  init {
    outputs.upToDateWhen { false }
  }

  @get:OutputFile abstract val fragmentFile: RegularFileProperty

  @TaskAction
  fun exportFragment() {
    writeCanonicalFile(fragmentFile.get().asFile, generateDocuments().resolutionExport)
  }
}

@DisableCachingByDefault(
  because = "The task authenticates the live Gradle resolution result and writes canonical evidence"
)
abstract class ExportStableSupplyChainResolution @Inject constructor() :
  StableSupplyChainResolutionTask() {
  @get:InputFiles
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val fragmentFiles: ConfigurableFileCollection

  @get:InputFile
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val buildLogicResolutionFile: RegularFileProperty

  @get:OutputFile abstract val resolutionSnapshotFile: RegularFileProperty

  @get:OutputFile abstract val resolutionExportFile: RegularFileProperty

  @get:OutputFile abstract val buildMaterialsFile: RegularFileProperty

  @get:Optional
  @get:InputFile
  @get:PathSensitive(PathSensitivity.NONE)
  abstract val reviewedResolutionExportFile: RegularFileProperty

  @TaskAction
  fun export() {
    val reviewedExport =
      reviewedResolutionExportFile.orNull?.asFile?.let { file ->
        validateReviewedInput(file, "resolution export", resolutionExportFile.get().asFile)
      }
    val documents =
      StableSupplyChainAggregation.aggregate(
        fragmentFiles.files,
        buildLogicResolutionFile.get().asFile,
        generateDocuments(),
        reviewedExport?.readBytes(),
      )
    writeCanonicalFile(resolutionExportFile.get().asFile, documents.resolutionExport)
    writeCanonicalFile(resolutionSnapshotFile.get().asFile, documents.resolutionSnapshot)
    writeCanonicalFile(buildMaterialsFile.get().asFile, documents.buildMaterials)
    logger.lifecycle(
      "Stable dependency export SHA-256: ${StableSupplyChainJson.sha256(documents.resolutionExport)}"
    )
    logger.lifecycle(
      "Stable dependency snapshot SHA-256: ${StableSupplyChainJson.sha256(documents.resolutionSnapshot)}"
    )
    logger.lifecycle(
      "Stable build-material inputs SHA-256: ${StableSupplyChainJson.sha256(documents.buildMaterials)}"
    )
  }

}

@DisableCachingByDefault(
  because = "The task recomputes and compares the live Gradle resolution result byte for byte"
)
abstract class VerifyStableSupplyChainResolution @Inject constructor() :
  StableSupplyChainResolutionTask() {
  @get:InputFiles
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val fragmentFiles: ConfigurableFileCollection

  @get:InputFile
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val buildLogicResolutionFile: RegularFileProperty

  @get:InputFiles
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val expectedDocuments: ConfigurableFileCollection

  @get:Optional
  @get:InputFile
  @get:PathSensitive(PathSensitivity.NONE)
  abstract val reviewedResolutionExportFile: RegularFileProperty

  @get:Optional
  @get:InputFile
  @get:PathSensitive(PathSensitivity.NONE)
  abstract val reviewedResolutionSnapshotFile: RegularFileProperty

  @TaskAction
  fun verify() {
    if (!reviewedResolutionExportFile.isPresent || !reviewedResolutionSnapshotFile.isPresent) {
      throw GradleException(
        "Stable resolution verification requires " +
          "-PstableSupplyChainExpectedResolutionExport=<reviewed-file> and " +
          "-PstableSupplyChainExpectedResolutionSnapshot=<reviewed-file>"
      )
    }
    val expectedByName = expectedDocuments.files.associateBy { file -> file.name }
    val expectedMaterials =
      expectedByName["build-material-inputs.json"]
        ?: throw GradleException("Missing build/stable-supply-chain/build-material-inputs.json")
    val reviewedExport =
      validateReviewedInput(
        reviewedResolutionExportFile.get().asFile,
        "resolution export",
        File(rootProjectDirectory, "build/stable-supply-chain/resolved-dependency-export.json"),
      )
    val reviewedSnapshot =
      validateReviewedInput(
        reviewedResolutionSnapshotFile.get().asFile,
        "resolution snapshot",
        File(rootProjectDirectory, "build/stable-supply-chain/resolved-dependency-snapshot.json"),
      )
    val actual =
      StableSupplyChainAggregation.aggregate(
        fragmentFiles.files,
        buildLogicResolutionFile.get().asFile,
        generateDocuments(),
        reviewedExport.readBytes(),
      )
    compareExact("reviewed resolved dependency export", reviewedExport, actual.resolutionExport)
    compareExact("reviewed resolved dependency snapshot", reviewedSnapshot, actual.resolutionSnapshot)
    compareExact("build-material inputs", expectedMaterials, actual.buildMaterials)
    logger.lifecycle("Stable supply-chain resolution and build-material inputs are current")
  }

  private fun compareExact(label: String, expectedFile: File, actual: ByteArray) {
    if (!expectedFile.isFile) throw GradleException("Missing expected Stable $label")
    val expected = expectedFile.readBytes()
    if (!expected.contentEquals(actual)) {
      throw GradleException(
        "Stable $label drifted: expected ${StableSupplyChainJson.sha256(expected)}, " +
          "resolved ${StableSupplyChainJson.sha256(actual)}. " +
          "Run exportStableSupplyChainResolution and review the exact authenticated change."
      )
    }
  }
}

private fun validateReviewedInput(
  reviewed: File,
  label: String,
  generatedOutput: File,
): File {
  val path = reviewed.toPath().toAbsolutePath().normalize()
  val outputPath = generatedOutput.toPath().toAbsolutePath().normalize()
  if (!reviewed.isFile) throw GradleException("Missing reviewed Stable $label: $reviewed")
  if (pathHasSymbolicLink(path)) {
    throw GradleException("Reviewed Stable $label must not use symbolic links")
  }
  if (path == outputPath || (generatedOutput.exists() && Files.isSameFile(path, outputPath))) {
    throw GradleException("Reviewed Stable $label must not alias the generated build output")
  }
  return path.toFile()
}

private fun pathHasSymbolicLink(path: java.nio.file.Path): Boolean {
  var current: java.nio.file.Path? = path
  while (current != null) {
    if (Files.isSymbolicLink(current)) return true
    current = current.parent
  }
  return false
}

private fun writeCanonicalFile(target: File, bytes: ByteArray) {
  target.parentFile.mkdirs()
  val temporary = File(target.parentFile, ".${target.name}.tmp")
  temporary.writeBytes(bytes)
  try {
    Files.move(
      temporary.toPath(),
      target.toPath(),
      StandardCopyOption.ATOMIC_MOVE,
      StandardCopyOption.REPLACE_EXISTING,
    )
  } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
    Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
  }
}
