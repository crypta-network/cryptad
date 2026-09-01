package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jetbrains.annotations.Nullable;

/**
 * Host-owned reviewer authorization for one catalog and optional exact app namespace.
 *
 * <p>The scope chooses which reviewer identities from the existing local reviewer registry may
 * satisfy review policy for a catalog. It does not import keys from catalog metadata and does not
 * make recommendations transitive. An empty app scope applies to the named catalog, while a
 * populated app scope narrows authority to one exact application identifier. The accepted
 * reviewer-set digest binds the policy to authenticated transparency evidence; any changed set
 * requires a new local decision and self-digest.
 *
 * @param schemaVersion closed persistent-record schema version
 * @param scopeId stable local identifier for this reviewer decision
 * @param catalogId exact authenticated catalog identifier covered by the scope
 * @param appId optional exact application identifier narrowing the scope
 * @param reviewerFingerprints allowed reviewer key IDs mapped to canonical fingerprints
 * @param acceptedReviewerSetDigestSha256 accepted reviewer-set transparency digest
 * @param status current local lifecycle state of this authorization
 * @param createdAt timestamp when the local scope was first created
 * @param updatedAt timestamp of the most recent local scope decision
 * @param reason bounded operator-supplied reason for the decision
 * @param operatorId bounded local operator audit identifier
 * @param selfDigest digest binding every preceding policy field
 */
public record CatalogReviewerScope(
    int schemaVersion,
    String scopeId,
    String catalogId,
    Optional<String> appId,
    Map<String, String> reviewerFingerprints,
    String acceptedReviewerSetDigestSha256,
    Status status,
    Instant createdAt,
    Instant updatedAt,
    String reason,
    String operatorId,
    String selfDigest) {
  /** Closed persistent schema version emitted for newly created reviewer scopes. */
  public static final int CURRENT_SCHEMA_VERSION = 1;

  /** Local lifecycle for a reviewer scope. */
  public enum Status {
    /** Awaiting an explicit local approval decision. */
    PENDING,
    /** Authorizes routine review decisions within the exact scope. */
    ACTIVE,
    /** Blocks routine work while preserving bounded historical authorization. */
    SUSPENDED,
    /** Permanently blocks routine and historical reviewer authorization. */
    REVOKED,
    /** Retains an audit tombstone without granting authorization. */
    REMOVED;

    /**
     * Parses a persisted case-insensitive lifecycle value.
     *
     * @param value persisted lifecycle text
     * @return parsed closed lifecycle status
     */
    static Status parse(String value) {
      try {
        return valueOf(value.toUpperCase(Locale.ROOT));
      } catch (RuntimeException exception) {
        throw FederatedPolicyRecordSupport.invalid("invalid reviewer scope status", exception);
      }
    }
  }

  /** Validates and normalizes an immutable reviewer scope. */
  public CatalogReviewerScope {
    if (schemaVersion != CURRENT_SCHEMA_VERSION) {
      throw FederatedPolicyRecordSupport.invalid("unsupported reviewer scope schema version");
    }
    scopeId =
        FederatedPolicyRecordSupport.requireId(
            scopeId, "reviewer scope id", FederatedPolicyRecordSupport.LOCAL_ID);
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    appId = Objects.requireNonNull(appId, "appId").map(AppCatalogEntry::normalizeAppId);
    reviewerFingerprints = normalizedReviewers(reviewerFingerprints);
    acceptedReviewerSetDigestSha256 =
        FederatedPolicyRecordSupport.requireDigest(
            acceptedReviewerSetDigestSha256, "reviewer set digest");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    if (updatedAt.isBefore(createdAt)) {
      throw FederatedPolicyRecordSupport.invalid("reviewer scope updatedAt precedes createdAt");
    }
    reason = FederatedPolicyRecordSupport.requireText(reason, "reason", 512);
    operatorId = FederatedPolicyRecordSupport.requireText(operatorId, "operator id", 128);
    String computed =
        FederatedPolicyRecordSupport.digest(
            canonicalWithoutDigest(
                schemaVersion,
                scopeId,
                catalogId,
                appId.orElse(null),
                reviewerFingerprints,
                acceptedReviewerSetDigestSha256,
                status,
                createdAt,
                updatedAt,
                reason,
                operatorId));
    if (selfDigest == null || selfDigest.isBlank()) {
      selfDigest = computed;
    } else if (!computed.equals(
        FederatedPolicyRecordSupport.requireDigest(selfDigest, "reviewer scope self-digest"))) {
      throw FederatedPolicyRecordSupport.invalid("reviewer scope self-digest mismatch");
    }
  }

  /**
   * Returns a catalog-independent digest of the reviewer policy authorized by this record.
   *
   * <p>The persistent {@link #selfDigest()} intentionally binds local record identity, catalog and
   * app scope, lifecycle, timestamps, and operator audit metadata. Those fields must invalidate a
   * retained authorization, but they do not make two otherwise equivalent reviewer sets disagree
   * during cross-catalog conflict classification. This digest binds only the normalized reviewer
   * identities and accepted reviewer-set transparency digest.
   *
   * @return lowercase SHA-256 digest of catalog-independent reviewer semantics
   */
  public String policySemanticDigestSha256() {
    StringBuilder text =
        new StringBuilder()
            .append("schemaVersion=")
            .append(schemaVersion)
            .append('\n')
            .append("reviewerIds=")
            .append(String.join(",", reviewerFingerprints.keySet()))
            .append('\n');
    reviewerFingerprints.forEach(
        (keyId, fingerprint) ->
            text.append("reviewer.").append(keyId).append('=').append(fingerprint).append('\n'));
    return FederatedPolicyRecordSupport.digest(
        text.append("acceptedReviewerSetDigestSha256=")
            .append(acceptedReviewerSetDigestSha256)
            .append('\n')
            .toString());
  }

  /**
   * Creates a scope while deriving its exact self-digest.
   *
   * @param scopeId stable local reviewer-scope identifier
   * @param catalogId exact authenticated catalog identifier
   * @param appId optional exact application namespace restriction
   * @param reviewerFingerprints locally known reviewer IDs and fingerprints
   * @param acceptedReviewerSetDigestSha256 accepted transparency evidence digest
   * @param status initial local lifecycle status
   * @param createdAt local scope creation timestamp
   * @param updatedAt latest local policy-decision timestamp
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identifier
   * @return immutable self-digested reviewer scope
   */
  public static CatalogReviewerScope create(
      String scopeId,
      String catalogId,
      @Nullable String appId,
      Map<String, String> reviewerFingerprints,
      String acceptedReviewerSetDigestSha256,
      Status status,
      Instant createdAt,
      Instant updatedAt,
      String reason,
      String operatorId) {
    return new CatalogReviewerScope(
        CURRENT_SCHEMA_VERSION,
        scopeId,
        catalogId,
        Optional.ofNullable(appId),
        reviewerFingerprints,
        acceptedReviewerSetDigestSha256,
        status,
        createdAt,
        updatedAt,
        reason,
        operatorId,
        null);
  }

  /**
   * Returns whether this active scope accepts one exact locally known reviewer identity.
   *
   * @param requestedCatalogId catalog requesting reviewer authorization
   * @param requestedAppId application namespace requesting authorization
   * @param reviewerKeyId locally known reviewer key identifier
   * @param reviewerFingerprint canonical reviewer key fingerprint
   * @param reviewerSetDigest authenticated reviewer-set evidence digest
   * @return {@code true} when every scope and identity constraint matches
   */
  public boolean authorizes(
      String requestedCatalogId,
      String requestedAppId,
      String reviewerKeyId,
      String reviewerFingerprint,
      String reviewerSetDigest) {
    return status == Status.ACTIVE
        && matches(
            requestedCatalogId,
            requestedAppId,
            reviewerKeyId,
            reviewerFingerprint,
            reviewerSetDigest);
  }

  /**
   * Returns whether this active or suspended scope accepts an exact historical reviewer subject.
   *
   * @param requestedCatalogId catalog associated with retained provenance
   * @param requestedAppId exact retained application namespace
   * @param reviewerKeyId retained review-receipt key identifier
   * @param reviewerFingerprint retained canonical reviewer fingerprint
   * @param reviewerSetDigest retained reviewer-set evidence digest
   * @return {@code true} when current historical policy permits the exact subject
   */
  public boolean authorizesHistorical(
      String requestedCatalogId,
      String requestedAppId,
      String reviewerKeyId,
      String reviewerFingerprint,
      String reviewerSetDigest) {
    return (status == Status.ACTIVE || status == Status.SUSPENDED)
        && matches(
            requestedCatalogId,
            requestedAppId,
            reviewerKeyId,
            reviewerFingerprint,
            reviewerSetDigest);
  }

  /**
   * Compares an exact reviewer subject with this scope independent of lifecycle.
   *
   * @param requestedCatalogId catalog requesting reviewer authorization
   * @param requestedAppId exact application namespace
   * @param reviewerKeyId locally known reviewer key identifier
   * @param reviewerFingerprint canonical reviewer key fingerprint
   * @param reviewerSetDigest authenticated reviewer-set evidence digest
   * @return {@code true} when all scope and identity fields match
   */
  private boolean matches(
      String requestedCatalogId,
      String requestedAppId,
      String reviewerKeyId,
      String reviewerFingerprint,
      String reviewerSetDigest) {
    String normalizedAppId = AppCatalogEntry.normalizeAppId(requestedAppId);
    return catalogId.equals(AppCatalog.normalizeCatalogId(requestedCatalogId))
        && appId.map(normalizedAppId::equals).orElse(true)
        && Objects.equals(reviewerFingerprints.get(reviewerKeyId), reviewerFingerprint)
        && acceptedReviewerSetDigestSha256.equals(reviewerSetDigest);
  }

  /**
   * Returns the complete canonical persisted representation including its self-digest.
   *
   * @return deterministic newline-terminated policy text
   */
  String canonicalText() {
    return canonicalWithoutDigest(
            schemaVersion,
            scopeId,
            catalogId,
            appId.orElse(null),
            reviewerFingerprints,
            acceptedReviewerSetDigestSha256,
            status,
            createdAt,
            updatedAt,
            reason,
            operatorId)
        + "selfDigest="
        + selfDigest
        + '\n';
  }

  /**
   * Builds canonical policy text excluding the self-digest line.
   *
   * @param schemaVersion closed policy schema version
   * @param scopeId stable local reviewer-scope identifier
   * @param catalogId exact authenticated catalog identifier
   * @param appId optional exact application namespace
   * @param reviewerFingerprints normalized reviewer identity map
   * @param acceptedReviewerSetDigestSha256 accepted transparency evidence digest
   * @param status local lifecycle status
   * @param createdAt local scope creation timestamp
   * @param updatedAt latest local policy-decision timestamp
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identifier
   * @return deterministic newline-terminated digest subject
   */
  @SuppressWarnings("java:S107")
  private static String canonicalWithoutDigest(
      int schemaVersion,
      String scopeId,
      String catalogId,
      @Nullable String appId,
      Map<String, String> reviewerFingerprints,
      String acceptedReviewerSetDigestSha256,
      Status status,
      Instant createdAt,
      Instant updatedAt,
      String reason,
      String operatorId) {
    StringBuilder text =
        new StringBuilder()
            .append("schemaVersion=")
            .append(schemaVersion)
            .append('\n')
            .append("scopeId=")
            .append(scopeId)
            .append('\n')
            .append("catalogId=")
            .append(catalogId)
            .append('\n')
            .append("appId=")
            .append(Objects.requireNonNullElse(appId, ""))
            .append('\n')
            .append("reviewerIds=")
            .append(String.join(",", reviewerFingerprints.keySet()))
            .append('\n');
    reviewerFingerprints.forEach(
        (keyId, fingerprint) ->
            text.append("reviewer.").append(keyId).append('=').append(fingerprint).append('\n'));
    return text.append("acceptedReviewerSetDigestSha256=")
        .append(acceptedReviewerSetDigestSha256)
        .append('\n')
        .append("status=")
        .append(status.name().toLowerCase(Locale.ROOT))
        .append('\n')
        .append("createdAt=")
        .append(createdAt)
        .append('\n')
        .append("updatedAt=")
        .append(updatedAt)
        .append('\n')
        .append("reason=")
        .append(reason)
        .append('\n')
        .append("operatorId=")
        .append(operatorId)
        .append('\n')
        .toString();
  }

  /**
   * Validates, sorts, and freezes locally known reviewer identities.
   *
   * @param values reviewer key IDs mapped to canonical fingerprints
   * @return immutable normalized reviewer identity map
   */
  private static Map<String, String> normalizedReviewers(Map<String, String> values) {
    if (values == null || values.isEmpty() || values.size() > 32) {
      throw FederatedPolicyRecordSupport.invalid("reviewer scope must contain 1 to 32 reviewers");
    }
    LinkedHashMap<String, String> normalized = new LinkedHashMap<>();
    values.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            entry -> {
              String keyId =
                  FederatedPolicyRecordSupport.requireId(
                      entry.getKey(), "reviewer key id", FederatedPolicyRecordSupport.KEY_ID);
              normalized.put(
                  keyId,
                  FederatedPolicyRecordSupport.requireDigest(
                      entry.getValue(), "reviewer key fingerprint"));
            });
    if (normalized.values().stream().distinct().count() != normalized.size()) {
      throw FederatedPolicyRecordSupport.invalid(
          "reviewer scope aliases one fingerprint under multiple key ids");
    }
    return Collections.unmodifiableMap(normalized);
  }
}
