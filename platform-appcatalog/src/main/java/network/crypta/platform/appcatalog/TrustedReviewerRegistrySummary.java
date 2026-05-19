package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Redacted summary of the local trusted-reviewer registry.
 *
 * <p>The summary exposes registry version, lifecycle counts, and parser/governance warnings. It
 * does not expose the registry path or any public/private key material.
 *
 * <p>This value is used by governance API responses, Web Shell status panels, developer CLI
 * inspection, and release-certification evidence. It answers whether local reviewer trust is
 * configured and how many keys are active, retired, or revoked without exposing the underlying
 * sidecar file or verifier bytes.
 *
 * <p>Warnings are display-safe configuration findings such as missing rotation targets or retired
 * keys without historical windows. They help operators correct local governance state, but the
 * verifier still uses explicit fail-closed trust statuses for receipt evaluation.
 *
 * @param configured whether at least one local reviewer key is configured
 * @param version trusted-reviewer registry format version that was loaded
 * @param counts lifecycle counts keyed by stable lowercase status values
 * @param warnings display-safe registry and lifecycle warnings
 */
public record TrustedReviewerRegistrySummary(
    boolean configured, int version, Map<String, Integer> counts, List<String> warnings) {
  /**
   * Converts this registry summary to JSON-compatible values.
   *
   * <p>The map preserves stable field names for API, CLI, and certification output. It contains no
   * public key bytes, private keys, local registry paths, or raw properties-file content.
   *
   * @return redacted registry summary with counts and warnings
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("configured", configured);
    json.put("version", version);
    json.put("counts", counts);
    json.put("warnings", warnings);
    return json;
  }
}
