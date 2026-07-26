package network.crypta.runtime.updater;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parsed and validated mutable support descriptor for the immutable Stable 1.0 release chain.
 *
 * <p>The descriptor is separate from historical {@code core-info.json} release documents because
 * build support changes after publication. Each accepted edition binds the same trusted update-key
 * scope, the lifecycle ledger digest, the exact published build identities, and its immediate
 * predecessor semantic descriptor digest. Runtime code retains the exact-byte digest but exposes
 * only a bounded public-safe projection to higher layers.
 *
 * @param schemaVersion supported descriptor schema version, currently {@code 1}
 * @param kind exact public artifact kind
 * @param stableMilestone stable product/API milestone, currently {@code 1.0}
 * @param descriptorEdition strictly increasing descriptor edition
 * @param previousDescriptorEdition immediate predecessor edition, or {@code null} for the root
 * @param previousDescriptorDigest semantic SHA-256 of the predecessor descriptor, excluding its
 *     {@code descriptorDigest} field
 * @param ledgerDigest authenticated append-only lifecycle ledger digest
 * @param inventoryDigest authenticated published-release inventory digest
 * @param currentStableBuild single authenticated release-chain tip, or {@code null} only when the
 *     tip is explicitly revoked and no safe current build exists
 * @param minimumSupportedBuild lowest fully supported build when policy defines one
 * @param minimumSecuritySupportedBuild lowest security-supported build when policy defines one
 * @param recommendedBuild authenticated recommended/current build, or {@code null} when an
 *     emergency tip revocation provides recovery guidance instead of a safe replacement
 * @param generatedAt canonical UTC descriptor generation timestamp
 * @param effectiveAt canonical UTC descriptor activation timestamp
 * @param staleAt canonical UTC policy-derived staleness deadline
 * @param updateKeyIdentityDigest lowercase SHA-256 of public update-key identity material
 * @param updateKeyScope normalized public support-lifecycle USK scope
 * @param updateKeyDocName exact support-lifecycle USK document name
 * @param entries ordered exact lifecycle entries for published Stable 1.0 builds
 * @param descriptorDigest semantic SHA-256 of the descriptor excluding this field
 * @param exactBytesDigest runtime-only SHA-256 of the exact fetched bytes
 */
public record CoreSupportLifecycleDescriptor(
    int schemaVersion,
    String kind,
    String stableMilestone,
    long descriptorEdition,
    Long previousDescriptorEdition,
    String previousDescriptorDigest,
    String ledgerDigest,
    String inventoryDigest,
    Integer currentStableBuild,
    Integer minimumSupportedBuild,
    Integer minimumSecuritySupportedBuild,
    Integer recommendedBuild,
    Instant generatedAt,
    Instant effectiveAt,
    Instant staleAt,
    String updateKeyIdentityDigest,
    String updateKeyScope,
    String updateKeyDocName,
    List<CoreSupportLifecycleEntry> entries,
    String descriptorDigest,
    String exactBytesDigest) {

  /** Copies the ordered entry list so later callers cannot mutate validated state. */
  public CoreSupportLifecycleDescriptor {
    entries = List.copyOf(entries);
  }

  /**
   * Returns entries keyed by integer build while preserving authenticated descriptor order.
   *
   * @return new ordered map containing every descriptor entry exactly once
   */
  public Map<Integer, CoreSupportLifecycleEntry> entriesByBuild() {
    LinkedHashMap<Integer, CoreSupportLifecycleEntry> result =
        LinkedHashMap.newLinkedHashMap(entries.size());
    entries.forEach(entry -> result.put(entry.buildVersion(), entry));
    return result;
  }
}
