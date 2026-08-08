package cryptad

import java.io.File
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.component.ComponentIdentifier
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ModuleComponentSelector
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentSelector
import org.gradle.api.artifacts.result.DependencyResult
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.result.ResolvedComponentResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.artifacts.result.ResolvedVariantResult
import org.gradle.api.artifacts.result.UnresolvedDependencyResult
import org.gradle.api.attributes.AttributeContainer

internal data class StableConfigurationSpec(
  val projectPath: String,
  val configurationName: String,
  val role: String,
) {
  val encoded: String
    get() = listOf(projectPath, configurationName, role).joinToString(SEPARATOR)

  companion object {
    private const val SEPARATOR = "\u001f"

    fun decode(value: String): StableConfigurationSpec {
      val fields = value.split(SEPARATOR)
      require(fields.size == 3) { "Invalid Stable supply-chain configuration descriptor" }
      return StableConfigurationSpec(fields[0], fields[1], fields[2])
    }
  }
}

internal data class StableVendoredComponent(
  val path: String,
  val componentId: String,
  val version: String,
  val role: String,
  val origin: String,
) {
  val encoded: String
    get() = listOf(path, componentId, version, role, origin).joinToString(SEPARATOR)

  companion object {
    private const val SEPARATOR = "\u001f"

    fun decode(value: String): StableVendoredComponent {
      val fields = value.split(SEPARATOR)
      require(fields.size == 5) { "Invalid Stable vendored-component descriptor" }
      return StableVendoredComponent(fields[0], fields[1], fields[2], fields[3], fields[4])
    }
  }
}

internal data class StableDirectInput(
  val name: String,
  val url: String,
  val immutabilityClass: String,
  val expectedSha256: String,
  val localPath: String,
) {
  val encoded: String
    get() = listOf(name, url, immutabilityClass, expectedSha256, localPath).joinToString(SEPARATOR)

  companion object {
    private const val SEPARATOR = "\u001f"

    fun decode(value: String): StableDirectInput {
      val fields = value.split(SEPARATOR)
      require(fields.size == 5) { "Invalid Stable direct-input descriptor" }
      return StableDirectInput(fields[0], fields[1], fields[2], fields[3], fields[4])
    }
  }
}

data class StableResolutionDocuments(
  val resolutionExport: ByteArray,
  val buildMaterials: ByteArray,
)

data class StableAggregatedResolutionDocuments(
  val resolutionExport: ByteArray,
  val resolutionSnapshot: ByteArray,
  val buildMaterials: ByteArray,
)

internal object StableSupplyChainResolution {
  private const val MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
  private val dynamicVersionTokens = listOf("+", "[", "]", "(", ")")

  fun build(
    rootProject: Project,
    configurationDescriptors: List<String>,
    vendoredDescriptors: List<String>,
    directInputDescriptors: List<String>,
    materialFiles: Set<File>,
    releaseVersion: String,
    sourceCommit: String,
    sourceRef: String,
    gitTreeObjectId: String,
    sourceTreeClean: Boolean,
    sourceStatusDigest: String,
    dependencyVerificationMode: String,
    gradleVersion: String,
    jdk: Map<String, String>,
    jdkModules: List<String>,
    releaseTasks: List<String>,
    allowedEnvironmentVariables: List<String>,
    policyDigest: String,
  ): StableResolutionDocuments {
    requireFullGitObjectId(sourceCommit, "source commit")
    requireFullGitObjectId(gitTreeObjectId, "source tree object")
    if (dependencyVerificationMode != "STRICT") {
      throw GradleException(
        "Stable supply-chain export requires Gradle dependency verification mode STRICT; " +
          "found $dependencyVerificationMode"
      )
    }
    if (!policyDigest.matches(Regex("sha256:[0-9a-f]{64}"))) {
      throw GradleException("Stable supply-chain policy digest is malformed")
    }

    val specs =
      configurationDescriptors
        .map(StableConfigurationSpec::decode)
        .distinct()
        .sortedWith(compareBy(StableConfigurationSpec::projectPath, StableConfigurationSpec::role, StableConfigurationSpec::configurationName))
    val vendored =
      vendoredDescriptors
        .map(StableVendoredComponent::decode)
        .distinct()
        .sortedWith(compareBy(StableVendoredComponent::componentId, StableVendoredComponent::path))
    val directInputs =
      directInputDescriptors
        .map(StableDirectInput::decode)
        .distinct()
        .sortedBy(StableDirectInput::name)
    val vendoredByFile =
      vendored.associateBy { descriptor ->
        rootProject.layout.projectDirectory.file(descriptor.path).asFile.canonicalFile
      }

    val components = sortedMapOf<String, Map<String, Any?>>()
    val configurations = mutableListOf<Map<String, Any?>>()
    val relationships = mutableListOf<Map<String, Any?>>()
    val artifacts = mutableListOf<Map<String, Any?>>()

    specs.forEach { spec ->
      val owner =
        rootProject.findProject(spec.projectPath)
          ?: throw GradleException("Unknown project in Stable resolution scope: ${spec.projectPath}")
      val configuration =
        owner.configurations.findByName(spec.configurationName)
          ?: throw GradleException(
            "Missing Stable resolution configuration ${spec.projectPath}:${spec.configurationName}"
          )
      if (!configuration.isCanBeResolved) {
        throw GradleException(
          "Stable resolution configuration is not resolvable: " +
            "${spec.projectPath}:${spec.configurationName}"
        )
      }
      collectConfiguration(
        rootProject,
        configuration,
        spec,
        sourceCommit,
        vendoredByFile,
        components,
        configurations,
        relationships,
        artifacts,
      )
    }
    artifacts
      .groupBy { record ->
        listOf(
          record.getValue("componentId"),
          record.getValue("logicalName"),
          record.getValue("kind"),
          canonicalValueSortKey(record.getValue("variant")),
        )
      }
      .forEach { (identity, records) ->
        val digests = records.map { record -> record.getValue("sha256") as String }.toSet()
        if (digests.size > 1) {
          throw GradleException(
            "Stable component identity collision with different artifact content: " +
              identity.joinToString(":")
          )
        }
      }

    val verificationFiles =
      listOf(
          "gradle/verification-metadata.xml",
          "gradle/verification-keyring.gpg",
          "gradle/verification-keyring.keys",
          "build-logic/gradle/verification-metadata.xml",
          "build-logic/gradle/verification-keyring.gpg",
          "build-logic/gradle/verification-keyring.keys",
        )
        .mapNotNull { relativePath ->
          val file = rootProject.layout.projectDirectory.file(relativePath).asFile
          if (file.isFile) relativePath to sha256(file) else null
        }
        .toMap()

    val snapshotModel =
      sortedMapOf<String, Any?>(
        "schema" to "cryptad-stable-resolved-dependency-export-v1",
        "repository" to "crypta-network/cryptad",
        "releaseBuild" to releaseVersion,
        "sourceCommit" to sourceCommit,
        "authority" to
          sortedMapOf(
            "kind" to "authenticated-resolution-snapshot",
            "dependencyVerificationMode" to dependencyVerificationMode.lowercase(),
            "policyDigest" to policyDigest,
            "verificationFileDigests" to verificationFiles.toSortedMap(),
            "dynamicVersionsAllowed" to false,
            "changingModulesAllowed" to false,
          ),
        "configurations" to
          configurations.sortedWith(
            compareBy(
              { it.getValue("projectPath") as String },
              { it.getValue("role") as String },
              { it.getValue("name") as String },
            )
          ),
        "components" to components.values.toList(),
        "relationships" to relationships.sortedBy(::canonicalSortKey),
        "artifacts" to artifacts.sortedBy(::canonicalSortKey),
      )
    val snapshotBytes = StableSupplyChainJson.encode(snapshotModel)
    enforceDocumentBounds("resolved dependency export", snapshotBytes)

    val materialRecords = collectMaterials(rootProject, materialFiles)
    val vendoredRecords =
      vendored.map { descriptor ->
        val file = rootProject.layout.projectDirectory.file(descriptor.path).asFile
        if (!file.isFile) {
          throw GradleException("Missing vendored Stable build material: ${descriptor.path}")
        }
        sortedMapOf<String, Any?>(
          "componentId" to descriptor.componentId,
          "version" to descriptor.version,
          "path" to descriptor.path,
          "sha256" to sha256(file),
          "size" to file.length(),
          "role" to descriptor.role,
          "origin" to descriptor.origin,
        )
      }
    val directInputRecords =
      directInputs.map { descriptor ->
        val expected = descriptor.expectedSha256.takeIf(String::isNotBlank)
        if (expected != null && !expected.matches(Regex("[0-9a-f]{64}"))) {
          throw GradleException("Invalid expected SHA-256 for direct input ${descriptor.name}")
        }
        val localFile = rootProject.layout.projectDirectory.file(descriptor.localPath).asFile
        val actual = localFile.takeIf(File::isFile)?.let(::sha256)
        val wrapperVerifiedByBootstrap =
          descriptor.name == "gradle-wrapper-distribution" && expected != null && actual == null
        val status =
          when {
            expected == null -> "unverified-missing-expected-digest"
            wrapperVerifiedByBootstrap -> "verified-by-gradle-wrapper"
            actual == null -> "not-present"
            actual == expected -> "verified"
            else -> "digest-mismatch"
          }
        val immutableOrigin =
          descriptor.immutabilityClass in
            setOf("versioned-url", "immutable-git-archive", "immutable-release-asset")
        sortedMapOf<String, Any?>(
          "name" to descriptor.name,
          "url" to descriptor.url,
          "immutabilityClass" to descriptor.immutabilityClass,
          "expectedSha256" to expected,
          "actualSha256" to actual,
          "verificationStatus" to status,
          "promotionBlocking" to
            (status != "verified" && status != "verified-by-gradle-wrapper" || !immutableOrigin),
        )
      }
    val materialSetDigests =
      sortedMapOf(
        "buildLogic" to digestMaterialSet(materialRecords, "build-logic/"),
        "packaging" to digestMaterialSet(materialRecords, "src/jpackage/", "tools/flatpak/"),
        "publicationBackend" to
          digestMaterialSet(materialRecords, "tools/release-certification/publication-backend/"),
        "repositoryConfiguration" to
          digestSelectedMaterials(
            materialRecords,
            setOf(
              "settings.gradle.kts",
              "build.gradle.kts",
              "build-logic/settings.gradle.kts",
              "build-logic/build.gradle.kts",
              "build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts",
            ),
          ),
      )
    val wrapperProperties =
      rootProject.layout.projectDirectory.file("gradle/wrapper/gradle-wrapper.properties").asFile
    val wrapperConfiguration = readWrapperConfiguration(wrapperProperties)

    val buildMaterialWithoutDigest =
      sortedMapOf<String, Any?>(
        "schema" to "cryptad-stable-build-material-inputs-v1",
        "repository" to "crypta-network/cryptad",
        "releaseBuild" to releaseVersion,
        "source" to
          sortedMapOf(
            "commit" to sourceCommit,
            "ref" to sourceRef,
            "gitTreeObjectId" to gitTreeObjectId,
            "clean" to sourceTreeClean,
            "statusDigest" to sourceStatusDigest,
          ),
        "rawResolutionExport" to
          sortedMapOf(
            "path" to "build/stable-supply-chain/resolved-dependency-export.json",
            "sha256" to StableSupplyChainJson.sha256(snapshotBytes),
          ),
        "gradle" to
          sortedMapOf(
            "version" to gradleVersion,
            "wrapperDistributionUrl" to wrapperConfiguration.getValue("distributionUrl"),
            "wrapperDistributionSha256" to wrapperConfiguration["distributionSha256Sum"],
            "dependencyVerificationMode" to dependencyVerificationMode.lowercase(),
            "verificationFileDigests" to verificationFiles.toSortedMap(),
          ),
        "jdk" to
          sortedMapOf<String, Any?>().apply {
            putAll(jdk.toSortedMap())
            put("modules", jdkModules.distinct().sorted())
          },
        "environment" to
          sortedMapOf(
            "allowedVariableNames" to allowedEnvironmentVariables.distinct().sorted(),
            "locale" to java.util.Locale.getDefault().toLanguageTag(),
            "timezone" to java.util.TimeZone.getDefault().id,
            "encoding" to java.nio.charset.Charset.defaultCharset().name(),
            "os" to System.getProperty("os.name"),
            "architecture" to System.getProperty("os.arch"),
          ),
        "releaseTasks" to releaseTasks.distinct().sorted(),
        "materialSetDigests" to materialSetDigests,
        "materials" to materialRecords,
        "vendoredComponents" to vendoredRecords,
        "directInputs" to directInputRecords,
      )
    val recordDigest = StableSupplyChainJson.sha256(StableSupplyChainJson.encode(buildMaterialWithoutDigest))
    val buildMaterialModel = buildMaterialWithoutDigest.toMutableMap().apply { put("recordDigest", recordDigest) }
    val buildMaterialBytes = StableSupplyChainJson.encode(buildMaterialModel)
    enforceDocumentBounds("build-material record", buildMaterialBytes)
    rejectPrivatePaths(rootProject, snapshotBytes, buildMaterialBytes)
    return StableResolutionDocuments(snapshotBytes, buildMaterialBytes)
  }

  private fun collectConfiguration(
    rootProject: Project,
    configuration: Configuration,
    spec: StableConfigurationSpec,
    sourceCommit: String,
    vendoredByFile: Map<File, StableVendoredComponent>,
    components: MutableMap<String, Map<String, Any?>>,
    configurations: MutableList<Map<String, Any?>>,
    relationships: MutableList<Map<String, Any?>>,
    artifacts: MutableList<Map<String, Any?>>,
  ) {
    val result = configuration.incoming.resolutionResult
    val root = result.root
    result.allComponents.sortedBy { component -> stableComponentId(rootProject, component.id, sourceCommit) }.forEach {
      component ->
      val record = componentRecord(rootProject, component, sourceCommit)
      val id = record.getValue("id") as String
      val previous = components.putIfAbsent(id, record)
      if (previous != null && previous != record) {
        throw GradleException("Stable component identity collision with different records: $id")
      }
    }

    result.allDependencies.forEach { dependency ->
      when (dependency) {
        is ResolvedDependencyResult -> {
          validateSelector(dependency)
          relationships +=
            sortedMapOf(
              "projectPath" to spec.projectPath,
              "configuration" to spec.configurationName,
              "role" to spec.role,
              "from" to stableComponentId(rootProject, dependency.from.id, sourceCommit),
              "to" to stableComponentId(rootProject, dependency.selected.id, sourceCommit),
              "requested" to requestedIdentity(dependency),
              "constraint" to dependency.isConstraint,
              "direct" to (dependency.from.id == root.id),
              "selection" to selectionRecord(dependency.selected),
              "selectedVariant" to variantRecord(dependency.resolvedVariant),
            )
        }
        is UnresolvedDependencyResult ->
          throw GradleException(
            "Unresolved Stable dependency in ${spec.projectPath}:${spec.configurationName}: " +
              safeRequestedIdentity(dependency)
          )
        else -> throw GradleException("Unsupported Gradle dependency result in Stable export")
      }
    }

    val artifactCollection = configuration.incoming.artifactView { isLenient = false }.artifacts
    if (artifactCollection.failures.isNotEmpty()) {
      throw GradleException(
        "Artifact resolution failed for ${spec.projectPath}:${spec.configurationName}: " +
          artifactCollection.failures.joinToString("; ") { it.javaClass.simpleName }
      )
    }
    artifactCollection.artifacts
      .filterIsInstance<ResolvedArtifactResult>()
      .sortedWith(compareBy({ it.file.name }, { it.id.componentIdentifier.displayName }))
      .forEach { artifact ->
        val file = artifact.file
        val artifactContent =
          artifactContent(rootProject, artifact.id.componentIdentifier, file, spec)
        val componentId =
          stableArtifactComponentId(rootProject, artifact.id.componentIdentifier, file, sourceCommit, vendoredByFile)
        artifacts +=
          sortedMapOf(
            "projectPath" to spec.projectPath,
            "configuration" to spec.configurationName,
            "role" to spec.role,
            "componentId" to componentId,
            "fileName" to file.name,
            "logicalName" to stableArtifactLogicalName(rootProject, file),
            "kind" to artifactContent.getValue("kind"),
            "sha256" to artifactContent.getValue("sha256"),
            "size" to artifactContent.getValue("size"),
            "variant" to variantRecord(artifact.variant),
          )
      }

    configurations +=
      sortedMapOf(
        "projectPath" to spec.projectPath,
        "name" to spec.configurationName,
        "role" to spec.role,
        "requestedAttributes" to attributes(configuration.attributes),
        "rootComponentId" to stableComponentId(rootProject, root.id, sourceCommit),
      )
  }

  private fun componentRecord(
    rootProject: Project,
    component: ResolvedComponentResult,
    sourceCommit: String,
  ): Map<String, Any?> {
    val identifier = component.id
    val version =
      when (identifier) {
        is ModuleComponentIdentifier -> identifier.version
        is ProjectComponentIdentifier ->
          rootProject.findProject(identifier.projectPath)?.version?.toString()
            ?: throw GradleException("Unknown project component ${identifier.projectPath}")
        else -> throw GradleException("Unsupported component identity in Stable graph: ${identifier.javaClass.name}")
      }
    validateSelectedVersion(version, stableComponentId(rootProject, identifier, sourceCommit))
    return sortedMapOf(
      "id" to stableComponentId(rootProject, identifier, sourceCommit),
      "kind" to if (identifier is ModuleComponentIdentifier) "gradle-module" else "internal-module",
      "group" to (component.moduleVersion?.group ?: "crypta-network"),
      "name" to
        when (identifier) {
          is ModuleComponentIdentifier -> identifier.module
          is ProjectComponentIdentifier -> identifier.projectName
          else -> error("unreachable")
        },
      "version" to version,
    )
  }

  private fun selectionRecord(component: ResolvedComponentResult): Map<String, Any?> =
    sortedMapOf(
      "forced" to component.selectionReason.isForced,
      "conflictResolution" to component.selectionReason.isConflictResolution,
      "selectedByRule" to component.selectionReason.isSelectedByRule,
      "compositeSubstitution" to component.selectionReason.isCompositeSubstitution,
      "constrained" to component.selectionReason.isConstrained,
    )

  private fun stableComponentId(
    rootProject: Project,
    identifier: ComponentIdentifier,
    sourceCommit: String,
  ): String =
    when (identifier) {
      is ModuleComponentIdentifier ->
        "pkg:maven/${purl(identifier.group)}/${purl(identifier.module)}@${purl(identifier.version)}"
      is ProjectComponentIdentifier -> {
        val project =
          rootProject.findProject(identifier.projectPath)
            ?: throw GradleException("Unknown project component ${identifier.projectPath}")
        internalProjectId(project, sourceCommit)
      }
      else -> throw GradleException("Unsupported component identity in Stable graph: ${identifier.javaClass.name}")
    }

  private fun stableArtifactComponentId(
    rootProject: Project,
    identifier: ComponentIdentifier,
    artifact: File,
    sourceCommit: String,
    vendoredByFile: Map<File, StableVendoredComponent>,
  ): String =
    when (identifier) {
      is ModuleComponentIdentifier, is ProjectComponentIdentifier ->
        stableComponentId(rootProject, identifier, sourceCommit)
      else ->
        vendoredByFile[artifact.canonicalFile]?.componentId
          ?: owningProject(rootProject, artifact)?.let { owner ->
            internalProjectId(owner, sourceCommit)
          }
          ?: throw GradleException(
            "Unidentified local artifact in Stable graph: ${artifact.name}; add an exact vendored identity"
          )
    }

  private fun owningProject(rootProject: Project, artifact: File): Project? {
    val artifactPath = artifact.canonicalFile.toPath()
    return rootProject.allprojects
      .map { owner -> owner to owner.layout.buildDirectory.get().asFile.canonicalFile.toPath() }
      .filter { (_, buildPath) -> artifactPath.startsWith(buildPath) }
      .maxByOrNull { (_, buildPath) -> buildPath.nameCount }
      ?.first
  }

  private fun stableArtifactLogicalName(rootProject: Project, artifact: File): String {
    val owner = owningProject(rootProject, artifact) ?: return artifact.name
    val buildRoot = owner.layout.buildDirectory.get().asFile.canonicalFile.toPath()
    val artifactPath = artifact.canonicalFile.toPath()
    val relative = buildRoot.relativize(artifactPath).joinToString("/")
    return "${owner.path}:$relative"
  }

  private fun internalProjectId(project: Project, sourceCommit: String): String =
    "pkg:generic/cryptad-module/${purl(project.name)}@${purl(project.version.toString())}" +
      "?commit=$sourceCommit"

  private fun repositoryRelativePath(rootProject: Project, file: File): String {
    val root = rootProject.rootDir.canonicalFile.toPath()
    val path = file.canonicalFile.toPath()
    return if (path.startsWith(root)) root.relativize(path).joinToString("/") else file.name
  }

  private fun validateSelector(dependency: ResolvedDependencyResult) {
    val requested = dependency.requested
    if (requested is ModuleComponentSelector) {
      val versions =
        listOf(
            requested.version,
            requested.versionConstraint.requiredVersion,
            requested.versionConstraint.preferredVersion,
            requested.versionConstraint.strictVersion,
          )
          .filter(String::isNotBlank)
      if (versions.isEmpty()) {
        throw GradleException("Stable dependency has no requested version: ${requested.group}:${requested.module}")
      }
      versions.forEach { version -> validateSelectedVersion(version, "${requested.group}:${requested.module}") }
    }
  }

  private fun validateSelectedVersion(version: String, identity: String) {
    val lower = version.lowercase()
    if (
      version.isBlank() ||
        lower == "latest" ||
        lower.startsWith("latest.") ||
        lower.contains("snapshot") ||
        dynamicVersionTokens.any(version::contains)
    ) {
      throw GradleException("Stable dependency uses a mutable or invalid version '$version': $identity")
    }
  }

  private fun requestedIdentity(dependency: ResolvedDependencyResult): Map<String, Any?> =
    when (val requested = dependency.requested) {
      is ModuleComponentSelector ->
        sortedMapOf(
          "kind" to "module",
          "group" to requested.group,
          "name" to requested.module,
          "version" to requested.version,
        )
      is ProjectComponentSelector ->
        sortedMapOf("kind" to "project", "buildPath" to requested.buildPath, "projectPath" to requested.projectPath)
      else -> throw GradleException("Unsupported requested dependency selector in Stable graph")
    }

  private fun safeRequestedIdentity(dependency: DependencyResult): String =
    when (val requested = dependency.requested) {
      is ModuleComponentSelector -> "${requested.group}:${requested.module}:${requested.version}"
      is ProjectComponentSelector -> "${requested.buildPath}${requested.projectPath}"
      else -> requested.javaClass.simpleName
    }

  private fun variantRecord(variant: ResolvedVariantResult): Map<String, Any?> =
    sortedMapOf(
      "attributes" to attributes(variant.attributes),
      "capabilities" to
        variant.capabilities
          .map { capability ->
            sortedMapOf(
              "group" to capability.group,
              "name" to capability.name,
              "version" to capability.version,
            )
          }
          .sortedBy(::canonicalSortKey),
    )

  private fun attributes(container: AttributeContainer): Map<String, String> =
    container.keySet().associate { attribute ->
      val value = container.getAttribute(attribute)
      attribute.name to (value?.toString() ?: "")
    }.toSortedMap()

  private fun collectMaterials(rootProject: Project, materialFiles: Set<File>): List<Map<String, Any?>> {
    val root = rootProject.rootDir.canonicalFile.toPath()
    return materialFiles
      .asSequence()
      .filter(File::isFile)
      .map { it.canonicalFile }
      .distinct()
      .map { file ->
        val path = file.toPath()
        if (!path.startsWith(root)) {
          throw GradleException("Stable material is outside the repository: ${file.name}")
        }
        val relativePath = root.relativize(path).joinToString("/")
        sortedMapOf<String, Any?>(
          "path" to relativePath,
          "sha256" to sha256(file),
          "size" to file.length(),
          "role" to materialRole(relativePath),
        )
      }
      .sortedBy { it.getValue("path") as String }
      .toList()
  }

  private fun materialRole(path: String): String =
    when {
      path.startsWith("build-logic/gradle/verification-") -> "dependency-verification"
      path.startsWith("build-logic/") -> "build-logic"
      path.startsWith("gradle/wrapper/") -> "gradle-wrapper"
      path.startsWith("gradle/verification-") -> "dependency-verification"
      path == "gradle/libs.versions.toml" -> "version-catalog"
      path == "settings.gradle.kts" || path.endsWith("/settings.gradle.kts") -> "repository-configuration"
      path.startsWith("src/jpackage/") || path.startsWith("tools/flatpak/") -> "packaging"
      path.startsWith("tools/release-certification/publication-backend/") -> "publication"
      path.startsWith("platform-sdk-js/") || path.startsWith("platform-design-system/") -> "first-party-app-input"
      path.startsWith("apps/") -> "first-party-app-input"
      path.startsWith("libs/") -> "vendored"
      else -> "build-input"
    }

  private fun digestMaterialSet(
    materials: List<Map<String, Any?>>,
    vararg prefixes: String,
  ): String =
    StableSupplyChainJson.sha256(
      StableSupplyChainJson.encode(
        materials.filter { record ->
          val path = record.getValue("path") as String
          prefixes.any(path::startsWith)
        }
      )
    )

  private fun digestSelectedMaterials(
    materials: List<Map<String, Any?>>,
    selectedPaths: Set<String>,
  ): String =
    StableSupplyChainJson.sha256(
      StableSupplyChainJson.encode(
        materials.filter { record -> (record.getValue("path") as String) in selectedPaths }
      )
    )

  private fun readWrapperConfiguration(file: File): Map<String, String?> {
    if (!file.isFile) throw GradleException("Missing Gradle wrapper properties")
    val values = java.util.Properties().apply { file.inputStream().use(::load) }
    val url = values.getProperty("distributionUrl") ?: throw GradleException("Wrapper distributionUrl is missing")
    return sortedMapOf(
      "distributionUrl" to url,
      "distributionSha256Sum" to values.getProperty("distributionSha256Sum"),
    )
  }

  private fun sha256(file: File): String =
    file.inputStream().buffered().use { input ->
      val digest = java.security.MessageDigest.getInstance("SHA-256")
      val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
      while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        digest.update(buffer, 0, read)
      }
      digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

  private fun artifactContent(
    rootProject: Project,
    identifier: ComponentIdentifier,
    file: File,
    spec: StableConfigurationSpec,
  ): Map<String, Any?> {
    if (!file.exists()) {
      val owner =
        if (identifier is ProjectComponentIdentifier) {
          rootProject.findProject(identifier.projectPath)
        } else {
          owningProject(rootProject, file)
        }
      if (owner != null) {
        val buildRoot = owner.layout.buildDirectory.get().asFile.canonicalFile.toPath()
        val expectedPath = file.canonicalFile.toPath()
        val relativeOutput =
          if (expectedPath.startsWith(buildRoot)) buildRoot.relativize(expectedPath).joinToString("/")
          else ""
        val sourceInput =
          when {
            relativeOutput.startsWith("classes/java/") -> owner.file("src/main/java")
            relativeOutput.startsWith("classes/kotlin/") -> owner.file("src/main/kotlin")
            relativeOutput.startsWith("resources/") -> owner.file("src/main/resources")
            else -> owner.file("src/main")
          }
        val hasMatchingInputs =
          sourceInput.takeIf(File::isDirectory)?.walkTopDown()?.any(File::isFile) == true
        if (expectedPath.startsWith(buildRoot) && !hasMatchingInputs) {
          return sortedMapOf(
            "kind" to "absent-empty-project-output",
            "sha256" to StableSupplyChainJson.sha256(StableSupplyChainJson.encode(emptyList<Any>())),
            "size" to 0L,
          )
        }
      }
      throw GradleException(
        "Resolved Stable artifact does not exist: ${spec.projectPath}:${spec.configurationName}:" +
          repositoryRelativePath(rootProject, file)
      )
    }
    if (file.isFile) {
      return sortedMapOf("kind" to "file", "sha256" to sha256(file), "size" to file.length())
    }
    if (!file.isDirectory) throw GradleException("Unsupported resolved artifact kind: ${file.name}")
    val root = file.canonicalFile.toPath()
    val entries =
      file
        .walkTopDown()
        .filter(File::isFile)
        .map { child ->
          val canonical = child.canonicalFile.toPath()
          if (!canonical.startsWith(root)) {
            throw GradleException("Resolved artifact directory contains an escaping path")
          }
          sortedMapOf<String, Any?>(
            "path" to root.relativize(canonical).joinToString("/"),
            "sha256" to sha256(child),
            "size" to child.length(),
          )
        }
        .sortedBy { entry -> entry.getValue("path") as String }
        .toList()
    return sortedMapOf(
      "kind" to "directory",
      "sha256" to StableSupplyChainJson.sha256(StableSupplyChainJson.encode(entries)),
      "size" to entries.sumOf { entry -> entry.getValue("size") as Long },
    )
  }

  private fun canonicalSortKey(value: Map<String, Any?>): String =
    String(StableSupplyChainJson.encode(value), StandardCharsets.UTF_8)

  private fun canonicalValueSortKey(value: Any?): String =
    String(StableSupplyChainJson.encode(value), StandardCharsets.UTF_8)

  private fun purl(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

  private fun requireFullGitObjectId(value: String, label: String) {
    if (!value.matches(Regex("[0-9a-f]{40,64}"))) {
      throw GradleException("Stable $label must be a full hexadecimal Git object id")
    }
  }

  private fun enforceDocumentBounds(label: String, bytes: ByteArray) {
    if (bytes.size > MAX_DOCUMENT_BYTES) {
      throw GradleException("Stable $label exceeds the $MAX_DOCUMENT_BYTES byte bound")
    }
  }

  private fun rejectPrivatePaths(rootProject: Project, vararg documents: ByteArray) {
    val prohibited =
      listOfNotNull(
          rootProject.rootDir.absolutePath,
          System.getProperty("user.home"),
          System.getProperty("java.io.tmpdir"),
          rootProject.gradle.gradleUserHomeDir.absolutePath,
        )
        .map { it.replace('\\', '/') }
        .filter { it.length > 1 }
        .distinct()
    documents.forEach { document ->
      val text = String(document, StandardCharsets.UTF_8).replace('\\', '/')
      prohibited.firstOrNull(text::contains)?.let {
        throw GradleException("Stable supply-chain document contains a prohibited local path")
      }
    }
  }
}
