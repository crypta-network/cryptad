package cryptad

import groovy.json.JsonSlurper
import java.io.File
import org.gradle.api.GradleException

internal object StableSupplyChainAggregation {
  fun aggregate(
    fragments: Set<File>,
    buildLogicResolutionFile: File,
    baseDocuments: StableResolutionDocuments,
    reviewedResolutionExport: ByteArray? = null,
  ): StableAggregatedResolutionDocuments {
    val baseSnapshot = parseObject(baseDocuments.resolutionExport)
    val components = sortedMapOf<String, Map<String, Any?>>()
    val configurations = mutableListOf<Map<String, Any?>>()
    val relationships = mutableListOf<Map<String, Any?>>()
    val artifacts = mutableListOf<Map<String, Any?>>()

    fragments.sortedBy(File::getName).forEach { fragmentFile ->
      if (!fragmentFile.isFile) {
        throw GradleException("Missing Stable project resolution fragment: ${fragmentFile.name}")
      }
      val fragment = parseObject(fragmentFile.readBytes())
      requireSameIdentity(baseSnapshot, fragment, fragmentFile.name)
      objectList(fragment, "components").forEach { component ->
        val id = component["id"] as? String ?: throw GradleException("Fragment component id is missing")
        val previous = components.putIfAbsent(id, component)
        if (previous != null && previous != component) {
          throw GradleException("Stable component identity collision while aggregating: $id")
        }
      }
      configurations += objectList(fragment, "configurations")
      relationships += objectList(fragment, "relationships")
      artifacts += objectList(fragment, "artifacts")
    }
    rejectArtifactContentCollisions(artifacts)
    if (!buildLogicResolutionFile.isFile) {
      throw GradleException("Missing authenticated Stable build-logic resolution report")
    }
    val buildLogicResolution = parseObject(buildLogicResolutionFile.readBytes())
    if (buildLogicResolution["schema"] != "cryptad-stable-build-logic-resolution-v1" ||
      buildLogicResolution["dependencyVerificationMode"] != "strict"
    ) {
      throw GradleException("Stable build-logic resolution report is unauthenticated")
    }

    val aggregateSnapshot =
      sortedMapOf<String, Any?>(
        "schema" to baseSnapshot.getValue("schema"),
        "repository" to baseSnapshot.getValue("repository"),
        "releaseBuild" to baseSnapshot.getValue("releaseBuild"),
        "sourceCommit" to baseSnapshot.getValue("sourceCommit"),
        "authority" to baseSnapshot.getValue("authority"),
        "configurations" to configurations.sortedBy(::canonicalSortKey),
        "components" to components.values.toList(),
        "relationships" to relationships.sortedBy(::canonicalSortKey),
        "artifacts" to artifacts.sortedBy(::canonicalSortKey),
        "buildLogic" to buildLogicResolution,
      )
    val exportBytes = StableSupplyChainJson.encode(aggregateSnapshot)
    if (reviewedResolutionExport != null && !reviewedResolutionExport.contentEquals(exportBytes)) {
      throw GradleException(
        "Stable resolved dependency export differs from the explicit reviewed snapshot: " +
          "reviewed ${StableSupplyChainJson.sha256(reviewedResolutionExport)}, " +
          "current ${StableSupplyChainJson.sha256(exportBytes)}"
      )
    }

    val materials = parseObject(baseDocuments.buildMaterials).toMutableMap()
    val exportBinding = objectValue(materials, "rawResolutionExport").toMutableMap()
    exportBinding["sha256"] = StableSupplyChainJson.sha256(exportBytes)
    materials["rawResolutionExport"] = exportBinding
    val projectedSnapshot =
      StableSupplyChainSnapshotProjection.project(
        aggregateSnapshot,
        materials,
        exportBytes,
        reviewedResolutionExport != null,
      )
    materials["resolvedDependencySnapshot"] =
      sortedMapOf(
        "path" to "build/stable-supply-chain/resolved-dependency-snapshot.json",
        "sha256" to StableSupplyChainJson.sha256(projectedSnapshot),
      )
    materials.remove("recordDigest")
    val recordDigest = StableSupplyChainJson.sha256(StableSupplyChainJson.encode(materials))
    materials["recordDigest"] = recordDigest
    return StableAggregatedResolutionDocuments(
      exportBytes,
      projectedSnapshot,
      StableSupplyChainJson.encode(materials),
    )
  }

  private fun requireSameIdentity(
    base: Map<String, Any?>,
    fragment: Map<String, Any?>,
    fragmentName: String,
  ) {
    listOf("schema", "repository", "releaseBuild", "sourceCommit", "authority").forEach { key ->
      if (base[key] != fragment[key]) {
        throw GradleException("Stable resolution fragment $fragmentName has mismatched $key")
      }
    }
  }

  private fun rejectArtifactContentCollisions(artifacts: List<Map<String, Any?>>) {
    artifacts
      .groupBy { record ->
        listOf(
          record["componentId"],
          record["logicalName"],
          record["kind"],
          canonicalSortKey(objectValue(record, "variant")),
        )
      }
      .forEach { (identity, records) ->
        val digests = records.map { record -> record["sha256"] }.toSet()
        if (digests.size > 1) {
          throw GradleException(
            "Stable component identity collision with different artifact content: " +
              identity.joinToString(":")
          )
        }
      }
  }

  private fun parseObject(bytes: ByteArray): Map<String, Any?> {
    val parsed = JsonSlurper().parse(bytes)
    if (parsed !is Map<*, *>) throw GradleException("Stable resolution JSON must be an object")
    return parsed.entries.associate { entry ->
      val key = entry.key as? String ?: throw GradleException("Stable resolution object key is invalid")
      key to normalize(entry.value)
    }.toSortedMap()
  }

  private fun normalize(value: Any?): Any? =
    when (value) {
      is Map<*, *> ->
        value.entries.associate { entry ->
          val key = entry.key as? String ?: throw GradleException("Stable resolution object key is invalid")
          key to normalize(entry.value)
        }.toSortedMap()
      is Iterable<*> -> value.map(::normalize)
      is Number -> value.toLong()
      is String, is Boolean, null -> value
      else -> throw GradleException("Stable resolution JSON contains an unsupported value")
    }

  private fun objectList(parent: Map<String, Any?>, name: String): List<Map<String, Any?>> {
    val values = parent[name] as? List<*> ?: throw GradleException("Stable fragment $name must be an array")
    return values.map { value ->
      @Suppress("UNCHECKED_CAST")
      (value as? Map<String, Any?>)
        ?: throw GradleException("Stable fragment $name entry must be an object")
    }
  }

  private fun objectValue(parent: Map<String, Any?>, name: String): Map<String, Any?> {
    @Suppress("UNCHECKED_CAST")
    return (parent[name] as? Map<String, Any?>)
      ?: throw GradleException("Stable build-material $name must be an object")
  }

  private fun canonicalSortKey(value: Map<String, Any?>): String =
    String(StableSupplyChainJson.encode(value), Charsets.UTF_8)
}
