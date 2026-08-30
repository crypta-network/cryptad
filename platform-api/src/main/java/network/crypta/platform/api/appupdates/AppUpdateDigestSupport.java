package network.crypta.platform.api.appupdates;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Computes deterministic digests for app-update policy subjects.
 *
 * <p>Update selection, cross-catalog conflict classification, and consent checks compare compact
 * SHA-256 commitments instead of retaining raw policy documents. This helper owns both the JCA
 * encoding details and the canonical conflict-subject projections used by the lifecycle
 * coordinator. Reviewer scope-record identifiers are deliberately excluded from semantic review
 * commitments because equivalent reviewer policies may have different local record identities.
 *
 * <p>The helper is stateless and thread-safe. It always encodes input as UTF-8 and returns a
 * lowercase hexadecimal SHA-256 value. A missing SHA-256 provider is treated as an invalid runtime
 * environment because the Java platform requires that algorithm.
 */
final class AppUpdateDigestSupport {
  /** Closed lowercase SHA-256 encoding accepted from a scoped reviewer decision. */
  private static final String SHA256_HEX_PATTERN = "[0-9a-f]{64}";

  /** Prevents construction of this stateless utility. */
  private AppUpdateDigestSupport() {}

  /**
   * Hashes one already-canonical update-policy subject.
   *
   * <p>This method does not normalize, trim, or otherwise reinterpret the supplied text. That
   * preserves the exact commitments produced before hashing was extracted from the lifecycle
   * service.
   *
   * @param value canonical UTF-8 text whose exact bytes form the digest subject
   * @return lowercase hexadecimal SHA-256 digest of the supplied text
   * @throws NullPointerException if {@code value} is {@code null}
   */
  static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /**
   * Commits to one catalog-local security decision using the Platform API canonical JSON writer.
   *
   * @param securityDecision path-free security decision for one catalog subject
   * @return lowercase hexadecimal SHA-256 digest of the canonical decision
   */
  static String securityDecisionDigest(Map<String, Object> securityDecision) {
    return sha256(PlatformApiJsonWriter.write(securityDecision));
  }

  /**
   * Returns the catalog-independent reviewer-policy commitment for one update candidate.
   *
   * <p>A valid semantic digest supplied by the scoped reviewer decision is already the preferred
   * commitment. Compatibility decisions that do not provide one are projected without the local
   * scope record id and self-digest before canonical hashing.
   *
   * @param candidate verified update candidate containing the reviewer decision
   * @return reviewer-policy semantic digest used for cross-catalog comparison
   */
  static String reviewPolicyDigest(AppUpdateCandidate candidate) {
    Object semanticDigest = candidate.reviewTrust().get("reviewerPolicySemanticDigestSha256");
    if (semanticDigest instanceof String digest && digest.matches(SHA256_HEX_PATTERN)) {
      return digest;
    }
    return sha256(PlatformApiJsonWriter.write(reviewTrustWithoutScopeRecordIdentity(candidate)));
  }

  /**
   * Commits to the conflict-relevant metadata of one update candidate.
   *
   * <p>The ordered projection intentionally matches the historical service implementation so
   * existing conflict-set and consent digests remain stable. Catalog-local reviewer scope record
   * identities are omitted while the reviewer decision's policy semantics remain included.
   *
   * @param candidate verified update candidate whose metadata is being compared
   * @return lowercase hexadecimal SHA-256 digest of the canonical metadata projection
   */
  static String candidateMetadataDigest(AppUpdateCandidate candidate) {
    return sha256(
        PlatformApiJsonWriter.write(
            List.of(
                candidate.channel(),
                candidate.supportStatus(),
                candidate.deprecation(),
                candidate.securityAdvisories(),
                candidate.review(),
                reviewTrustWithoutScopeRecordIdentity(candidate),
                candidate.apiCompatibility(),
                candidate.permissionDelta())));
  }

  /**
   * Projects a reviewer decision onto catalog-independent policy semantics.
   *
   * @param candidate update candidate containing the locally scoped reviewer decision
   * @return insertion-ordered decision without local scope record identity fields
   */
  private static Map<String, Object> reviewTrustWithoutScopeRecordIdentity(
      AppUpdateCandidate candidate) {
    LinkedHashMap<String, Object> semantic = new LinkedHashMap<>(candidate.reviewTrust());
    semantic.remove("reviewerScopeId");
    semantic.remove("reviewerScopeDigestSha256");
    return semantic;
  }
}
