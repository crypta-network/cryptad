package cryptad

import org.gradle.api.GradleException

/** Projects the lossless Gradle model export into the closed release-certification schema. */
internal object StableSupplyChainSnapshotProjection {
  fun project(
    rawExport: Map<String, Any?>,
    buildMaterials: Map<String, Any?>,
    rawExportBytes: ByteArray,
    reviewedExportMatches: Boolean,
  ): ByteArray {
    val sourceCommit = stringValue(rawExport, "sourceCommit")
    val authority = objectValue(rawExport, "authority")
    val policyDigest = stringValue(authority, "policyDigest")
    val configurations = objectList(rawExport, "configurations")
    val relationships = objectList(rawExport, "relationships")
    val artifacts = objectList(rawExport, "artifacts")
    val components = objectList(rawExport, "components")
    val buildLogic = objectValue(rawExport, "buildLogic")

    val projectedConfigurations =
      configurations.map { configuration -> projectConfiguration(configuration, relationships, artifacts) } +
        projectBuildLogicConfigurations(buildLogic)
    val componentIds =
      buildSet {
        components.forEach { add(stringValue(it, "id")) }
        relationships.forEach {
          add(stringValue(it, "from"))
          add(stringValue(it, "to"))
        }
        artifacts.forEach { add(stringValue(it, "componentId")) }
      }
    val componentsById = components.associateBy { stringValue(it, "id") }
    val rootComponents =
      componentIds.sorted().map { componentId ->
        projectComponent(
          componentId,
          componentsById[componentId],
          configurations,
          relationships,
          artifacts,
          authority,
        )
      }
    val projectedComponents =
      mergeProjectedComponents(rootComponents + projectBuildLogicComponents(buildLogic, authority))

    val modelWithoutDigest =
      sortedMapOf<String, Any?>(
        "schemaVersion" to 1,
        "kind" to "stable-1.0-resolved-dependency-snapshot",
        "sourceCommit" to sourceCommit,
        "policyDigest" to policyDigest,
        "configurations" to
          projectedConfigurations.sortedWith(
            compareBy(
              { stringValue(it, "project") },
              { stringValue(it, "role") },
              { stringValue(it, "name") },
            )
          ),
        "components" to projectedComponents,
        "dependencyVerification" to dependencyVerification(authority),
        "locking" to locking(buildMaterials, rawExportBytes, reviewedExportMatches),
        "materialDigests" to materialDigests(buildMaterials, rawExport, rawExportBytes),
      )
    val snapshotDigest = digestValue(modelWithoutDigest)
    val model = modelWithoutDigest.toMutableMap().apply { put("snapshotDigest", snapshotDigest) }
    return StableSupplyChainJson.encode(model)
  }

  private fun projectBuildLogicConfigurations(
    buildLogic: Map<String, Any?>
  ): List<Map<String, Any?>> {
    val relationships = objectList(buildLogic, "relationships")
    val artifacts = objectList(buildLogic, "artifacts")
    return objectList(buildLogic, "configurations").map { configuration ->
      val name = stringValue(configuration, "name")
      val componentIds =
        buildSet {
            relationships
              .filter { stringValue(it, "configuration") == name }
              .forEach {
                add(stringValue(it, "from"))
                add(stringValue(it, "to"))
              }
            artifacts
              .filter { stringValue(it, "configuration") == name }
              .forEach { add(stringValue(it, "componentId")) }
          }
          .sorted()
      val recordWithoutDigest =
        sortedMapOf<String, Any?>(
          "project" to ":build-logic",
          "name" to name,
          "role" to "build",
          "attributes" to attributeArray(objectValue(configuration, "attributes")),
          "componentIds" to componentIds,
        )
      recordWithoutDigest.toMutableMap().apply {
        put("resolutionDigest", digestValue(recordWithoutDigest))
      }
    }
  }

  private fun projectBuildLogicComponents(
    buildLogic: Map<String, Any?>,
    authority: Map<String, Any?>,
  ): List<Map<String, Any?>> {
    val components = objectList(buildLogic, "components")
    val relationships = objectList(buildLogic, "relationships")
    val artifacts = objectList(buildLogic, "artifacts")
    val componentsById = components.associateBy { stringValue(it, "id") }
    val componentIds =
      buildSet {
        components.forEach { add(stringValue(it, "id")) }
        relationships.forEach {
          add(stringValue(it, "from"))
          add(stringValue(it, "to"))
        }
        artifacts.forEach { add(stringValue(it, "componentId")) }
      }
    val buildLogicVerification = objectValue(buildLogic, "verificationFileDigests")
    val authorityVerification = objectValue(authority, "verificationFileDigests")
    val verificationNames =
      listOf(
        "verification-metadata.xml",
        "verification-keyring.gpg",
        "verification-keyring.keys",
      )
    val strict =
      stringValue(buildLogic, "dependencyVerificationMode") == "strict" &&
        verificationNames.all { fileName ->
          val includedDigest = buildLogicVerification["gradle/$fileName"] as? String
          val rootDigest = authorityVerification["build-logic/gradle/$fileName"] as? String
          includedDigest?.matches(Regex("[0-9a-f]{64}")) == true && includedDigest == rootDigest
        }
    return componentIds.sorted().map { componentId ->
      val source = componentsById[componentId]
      val incoming = relationships.filter { stringValue(it, "to") == componentId }
      val uses = artifacts.filter { stringValue(it, "componentId") == componentId }
      val artifactIdentities =
        uses
          .map { use ->
            sortedMapOf<String, Any?>(
              "logicalName" to stringValue(use, "fileName"),
              "kind" to "build-logic-artifact",
              "sha256" to stringValue(use, "sha256"),
              "attributes" to objectValue(use, "attributes"),
            )
          }
          .distinctBy(::canonicalSortKey)
          .sortedBy(::canonicalSortKey)
      val digests = artifactIdentities.map { stringValue(it, "sha256") }.distinct()
      val artifactDigest =
        if (digests.size == 1) prefixedDigest(digests.single())
        else digestValue(if (artifactIdentities.isEmpty()) source ?: componentId else artifactIdentities)
      val version = source?.get("version") as? String ?: purlVersion(componentId)
      val coordinates =
        if (source == null) "${purlName(componentId)}:$version"
        else "${stringValue(source, "group")}:${stringValue(source, "name")}:$version"
      val attributes =
        uses
          .flatMap { use -> attributeArray(objectValue(use, "attributes")) }
          .distinctBy(::canonicalSortKey)
          .sortedBy(::canonicalSortKey)
      if (attributes.size > 64) {
        throw GradleException("Stable build-logic component $componentId has too many attributes")
      }
      sortedMapOf(
        "componentId" to componentId,
        "componentKind" to "external-module",
        "coordinates" to coordinates,
        "version" to version,
        "selectedVariant" to "variant-set-${digestValue(attributes)}",
        "attributes" to attributes,
        "roles" to listOf("build"),
        "artifactDigest" to artifactDigest,
        "verificationStatus" to
          if (strict && (digests.size == 1 || (source != null && uses.isEmpty()))) "verified"
          else "unverified",
        "changing" to false,
        "direct" to incoming.isEmpty(),
        "parents" to incoming.map { stringValue(it, "from") }.distinct().sorted(),
      )
    }
  }

  private fun mergeProjectedComponents(
    components: List<Map<String, Any?>>
  ): List<Map<String, Any?>> {
    val merged = sortedMapOf<String, Map<String, Any?>>()
    components.forEach { component ->
      val id = stringValue(component, "componentId")
      val previous = merged[id]
      if (previous == null) {
        merged[id] = component
      } else {
        listOf("componentKind", "coordinates", "version", "artifactDigest", "verificationStatus", "changing")
          .forEach { field ->
            if (previous[field] != component[field]) {
              throw GradleException("Stable component $id differs between product and build logic: $field")
            }
          }
        val attributes =
          (objectList(previous, "attributes") + objectList(component, "attributes"))
            .distinctBy(::canonicalSortKey)
            .sortedBy(::canonicalSortKey)
        val roles =
          ((previous["roles"] as? List<*>)?.filterIsInstance<String>().orEmpty() +
              (component["roles"] as? List<*>)?.filterIsInstance<String>().orEmpty())
            .distinct()
            .sortedWith(compareBy(::roleOrder, { it }))
        val parents =
          ((previous["parents"] as? List<*>)?.filterIsInstance<String>().orEmpty() +
              (component["parents"] as? List<*>)?.filterIsInstance<String>().orEmpty())
            .distinct()
            .sorted()
        merged[id] =
          previous.toMutableMap().apply {
            put(
              "selectedVariant",
              "variant-set-${digestValue(listOf(previous["selectedVariant"], component["selectedVariant"]).sortedBy { it.toString() })}",
            )
            put("attributes", attributes)
            put("roles", roles)
            put("direct", booleanValue(previous, "direct") || booleanValue(component, "direct"))
            put("parents", parents)
          }
      }
    }
    return merged.values.toList()
  }

  private fun projectConfiguration(
    configuration: Map<String, Any?>,
    relationships: List<Map<String, Any?>>,
    artifacts: List<Map<String, Any?>>,
  ): Map<String, Any?> {
    val project = stringValue(configuration, "projectPath")
    val name = stringValue(configuration, "name")
    val role = stringValue(configuration, "role")
    val matchingRelationships =
      relationships.filter {
        stringValue(it, "projectPath") == project && stringValue(it, "configuration") == name
      }
    val matchingArtifacts =
      artifacts.filter {
        stringValue(it, "projectPath") == project && stringValue(it, "configuration") == name
      }
    val ids =
      buildSet {
          add(stringValue(configuration, "rootComponentId"))
          matchingRelationships.forEach {
            add(stringValue(it, "from"))
            add(stringValue(it, "to"))
          }
          matchingArtifacts.forEach { add(stringValue(it, "componentId")) }
        }
        .sorted()
    val recordWithoutDigest =
      sortedMapOf<String, Any?>(
        "project" to project,
        "name" to name,
        "role" to role,
        "attributes" to attributeArray(objectValue(configuration, "requestedAttributes")),
        "componentIds" to ids,
      )
    return recordWithoutDigest.toMutableMap().apply {
      put("resolutionDigest", digestValue(recordWithoutDigest))
    }
  }

  private fun projectComponent(
    componentId: String,
    source: Map<String, Any?>?,
    configurations: List<Map<String, Any?>>,
    relationships: List<Map<String, Any?>>,
    artifacts: List<Map<String, Any?>>,
    authority: Map<String, Any?>,
  ): Map<String, Any?> {
    val incoming = relationships.filter { stringValue(it, "to") == componentId }
    val outgoing = relationships.filter { stringValue(it, "from") == componentId }
    val rootConfigurations =
      configurations.filter { stringValue(it, "rootComponentId") == componentId }
    val uses = artifacts.filter { stringValue(it, "componentId") == componentId }
    val variants =
      (incoming.map { objectValue(it, "selectedVariant") } +
          uses.map { objectValue(it, "variant") })
        .distinctBy(::canonicalSortKey)
        .sortedBy(::canonicalSortKey)
    val variantAttributes =
      variants
        .flatMap { variant -> attributeArray(objectValue(variant, "attributes")) }
        .distinctBy(::canonicalSortKey)
        .sortedBy(::canonicalSortKey)
    if (variantAttributes.size > 64) {
      throw GradleException("Stable component $componentId has too many selected attributes")
    }
    val artifactIdentities =
      uses
        .map { use ->
          sortedMapOf<String, Any?>(
            "logicalName" to stringValue(use, "logicalName"),
            "kind" to stringValue(use, "kind"),
            "sha256" to stringValue(use, "sha256"),
            "variant" to objectValue(use, "variant"),
          )
        }
        .distinctBy(::canonicalSortKey)
        .sortedBy(::canonicalSortKey)
    val distinctArtifactDigests = artifactIdentities.map { stringValue(it, "sha256") }.distinct()
    val artifactDigest =
      if (source?.get("kind") == "internal-module") {
        digestValue(artifactIdentities)
      } else if (distinctArtifactDigests.size == 1) {
        prefixedDigest(distinctArtifactDigests.single())
      } else {
        digestValue(if (artifactIdentities.isEmpty()) source ?: componentId else artifactIdentities)
      }
    val version = source?.get("version") as? String ?: purlVersion(componentId)
    val coordinates =
      if (source == null) {
        "${purlName(componentId)}:$version"
      } else {
        "${stringValue(source, "group")}:${stringValue(source, "name")}:$version"
      }
    val roles =
      (incoming.map { stringValue(it, "role") } +
          outgoing.map { stringValue(it, "role") } +
          rootConfigurations.map { stringValue(it, "role") } +
          uses.map { stringValue(it, "role") })
        .distinct()
        .sortedWith(compareBy(::roleOrder, { it }))
        .ifEmpty { listOf("build") }
    val parents = incoming.map { stringValue(it, "from") }.distinct().sorted()
    val strictVerification = stringValue(authority, "dependencyVerificationMode") == "strict"
    val componentKind = componentKind(componentId, source)
    val verificationStatus =
      when (componentKind) {
        "internal-project" -> "authenticated-first-party"
        "vendored-binary" ->
          if (distinctArtifactDigests.size == 1 &&
            checksumFromPurl(componentId) == distinctArtifactDigests.single()
          ) {
            "verified"
          } else {
            "unverified"
          }
        "external-module" ->
          if (strictVerification && distinctArtifactDigests.size == 1) "verified"
          else "unverified"
        else -> error("unreachable")
      }
    return sortedMapOf(
      "componentId" to componentId,
      "componentKind" to componentKind,
      "coordinates" to coordinates,
      "version" to version,
      "selectedVariant" to "variant-set-${digestValue(variants)}",
      "attributes" to variantAttributes,
      "roles" to roles,
      "artifactDigest" to artifactDigest,
      "verificationStatus" to verificationStatus,
      "changing" to false,
      "direct" to incoming.any { booleanValue(it, "direct") },
      "parents" to parents,
    )
  }

  private fun dependencyVerification(authority: Map<String, Any?>): Map<String, Any?> {
    val verification = objectValue(authority, "verificationFileDigests")
    val metadata = verification["gradle/verification-metadata.xml"] as? String
    val keyring = verification["gradle/verification-keyring.gpg"] as? String
    val keys = verification["gradle/verification-keyring.keys"] as? String
    val verified =
      stringValue(authority, "dependencyVerificationMode") == "strict" &&
        listOf(metadata, keyring, keys).all { it?.matches(Regex("[0-9a-f]{64}")) == true }
    return sortedMapOf(
      "status" to if (verified) "verified" else "failed",
      "metadataDigest" to digestOrSentinel(metadata, "missing-verification-metadata"),
      "keyringDigest" to digestOrSentinel(keyring, "missing-verification-keyring"),
      "keyringKeysDigest" to digestOrSentinel(keys, "missing-verification-keyring-keys"),
    )
  }

  private fun locking(
    buildMaterials: Map<String, Any?>,
    rawExportBytes: ByteArray,
    reviewedExportMatches: Boolean,
  ): Map<String, Any?> {
    val lockMaterials =
      objectList(buildMaterials, "materials").filter { material ->
        val path = stringValue(material, "path")
        path.endsWith("gradle.lockfile") || path.endsWith(".lockfile")
      }
    return sortedMapOf(
      "status" to
        when {
          lockMaterials.isNotEmpty() -> "locked"
          reviewedExportMatches -> "authenticated-snapshot"
          else -> "unlocked"
        },
      "snapshotMode" to
        if (lockMaterials.isEmpty()) "authenticated-resolution-snapshot" else "gradle-locking",
      "lockDigest" to
        if (lockMaterials.isEmpty()) prefixedDigest(StableSupplyChainJson.sha256(rawExportBytes))
        else digestValue(lockMaterials.sortedBy { stringValue(it, "path") }),
    )
  }

  private fun materialDigests(
    buildMaterials: Map<String, Any?>,
    rawExport: Map<String, Any?>,
    rawExportBytes: ByteArray,
  ): Map<String, Any?> {
    val materials = objectList(buildMaterials, "materials")
    val byPath = materials.associateBy { stringValue(it, "path") }
    val materialSets = objectValue(buildMaterials, "materialSetDigests")
    val directInputs = objectList(buildMaterials, "directInputs").associateBy { stringValue(it, "name") }
    val wrapperDistribution = directInputs["gradle-wrapper-distribution"]
    val wrapperDistributionDigest =
      wrapperDistribution?.get("actualSha256") as? String
        ?: wrapperDistribution?.get("expectedSha256") as? String
        ?: StableSupplyChainJson.sha256(
          StableSupplyChainJson.canonicalBytes(wrapperDistribution ?: "missing-gradle-distribution")
        )
    val testResolution =
      sortedMapOf(
        "configurations" to
          objectList(rawExport, "configurations").filter { stringValue(it, "role") == "test" },
        "relationships" to
          objectList(rawExport, "relationships").filter { stringValue(it, "role") == "test" },
        "artifacts" to
          objectList(rawExport, "artifacts").filter { stringValue(it, "role") == "test" },
      )
    return sortedMapOf(
      "gradleWrapperJar" to materialDigest(byPath, "gradle/wrapper/gradle-wrapper.jar"),
      "gradleWrapperProperties" to
        materialDigest(byPath, "gradle/wrapper/gradle-wrapper.properties"),
      "gradleDistribution" to prefixedDigest(wrapperDistributionDigest),
      "versionCatalog" to materialDigest(byPath, "gradle/libs.versions.toml"),
      "repositoryConfiguration" to
        prefixedDigest(stringValue(materialSets, "repositoryConfiguration")),
      "verificationMetadata" to materialDigest(byPath, "gradle/verification-metadata.xml"),
      "verificationKeyring" to materialDigest(byPath, "gradle/verification-keyring.gpg"),
      "buildLogic" to prefixedDigest(stringValue(materialSets, "buildLogic")),
      "pluginResolution" to
        materialDigest(byPath, "build-logic/build/stable-supply-chain/resolved-build-logic.json"),
      "testResolution" to digestValue(testResolution),
      "rawResolutionExport" to prefixedDigest(StableSupplyChainJson.sha256(rawExportBytes)),
    )
  }

  private fun materialDigest(
    materials: Map<String, Map<String, Any?>>,
    path: String,
  ): String {
    val digest = materials[path]?.get("sha256") as? String
    return digestOrSentinel(digest, "missing-material:$path")
  }

  private fun attributeArray(attributes: Map<String, Any?>): List<Map<String, String>> =
    attributes.entries
      .mapNotNull { (name, value) ->
        val text = value as? String
        if (name.isBlank() || text.isNullOrBlank()) null else sortedMapOf("name" to name, "value" to text)
      }
      .sortedBy(::canonicalSortKey)

  private fun purlName(componentId: String): String =
    componentId.substringBefore('@').substringAfterLast('/').ifBlank { "unknown-component" }

  private fun componentKind(componentId: String, source: Map<String, Any?>?): String =
    when {
      source?.get("kind") == "internal-module" -> "internal-project"
      source?.get("kind") == "gradle-module" -> "external-module"
      componentId.startsWith("pkg:generic/cryptad-vendored/") -> "vendored-binary"
      else -> throw GradleException("Stable component kind is not closed: $componentId")
    }

  private fun checksumFromPurl(componentId: String): String? =
    componentId
      .substringAfter('?', "")
      .split('&')
      .firstOrNull { parameter -> parameter.startsWith("checksum=") }
      ?.substringAfter('=')
      ?.takeIf { digest -> digest.matches(Regex("[0-9a-f]{64}")) }

  private fun purlVersion(componentId: String): String {
    val version = componentId.substringAfterLast('@', "").substringBefore('?')
    if (version.isBlank()) throw GradleException("Stable component has no exact version: $componentId")
    return version
  }

  private fun digestOrSentinel(value: String?, sentinel: String): String =
    if (value?.matches(Regex("[0-9a-f]{64}")) == true) prefixedDigest(value)
    else digestValue(sentinel)

  private fun prefixedDigest(value: String): String =
    if (value.startsWith("sha256:")) value else "sha256:$value"

  private fun digestValue(value: Any?): String =
    prefixedDigest(StableSupplyChainJson.sha256(StableSupplyChainJson.canonicalBytes(value)))

  private fun roleOrder(role: String): Int =
    when (role) {
      "runtime" -> 0
      "build" -> 1
      "test" -> 2
      "packaging" -> 3
      "publication" -> 4
      else -> throw GradleException("Unknown Stable component role: $role")
    }

  private fun objectList(parent: Map<String, Any?>, name: String): List<Map<String, Any?>> {
    val values = parent[name] as? List<*> ?: throw GradleException("Stable $name must be an array")
    return values.map { value ->
      @Suppress("UNCHECKED_CAST")
      (value as? Map<String, Any?>)
        ?: throw GradleException("Stable $name entry must be an object")
    }
  }

  private fun objectValue(parent: Map<String, Any?>, name: String): Map<String, Any?> {
    @Suppress("UNCHECKED_CAST")
    return (parent[name] as? Map<String, Any?>)
      ?: throw GradleException("Stable $name must be an object")
  }

  private fun stringValue(parent: Map<String, Any?>, name: String): String =
    parent[name] as? String ?: throw GradleException("Stable $name must be a string")

  private fun booleanValue(parent: Map<String, Any?>, name: String): Boolean =
    parent[name] as? Boolean ?: throw GradleException("Stable $name must be a boolean")

  private fun canonicalSortKey(value: Map<String, *>): String =
    String(StableSupplyChainJson.canonicalBytes(value), Charsets.UTF_8)
}
