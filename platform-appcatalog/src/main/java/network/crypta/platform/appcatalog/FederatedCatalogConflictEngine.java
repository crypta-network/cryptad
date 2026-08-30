package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Deterministically classifies app namespace and version conflicts across verified catalogs.
 *
 * <p>Callers provide path-free subjects built from authenticated catalog, publisher, reviewer, and
 * security-policy state. The engine sorts those subjects, compares every cross-catalog pair, and
 * creates a digest-bound conflict set. Same-version payload and publisher namespace collisions are
 * hard conflicts; exact duplicates and metadata disagreements remain separately visible.
 *
 * <p>Local resolutions bind the exact conflict and complete subject-set digests, so any catalog or
 * policy change makes a decision stale. The engine does not select a catalog lexically, mutate
 * policy, or publish moderation claims. All returned records are immutable and safe to share.
 */
public final class FederatedCatalogConflictEngine {
  /** Field name used when validating publisher fingerprint digests. */
  private static final String PUBLISHER_FINGERPRINT_FIELD = "publisherFingerprint";

  /** Prevents construction of this stateless conflict engine. */
  private FederatedCatalogConflictEngine() {}

  /** Conflict classes ordered from harmless duplication to force-blocking disagreement. */
  public enum Type {
    /** Every bundle, publisher, review, security, and material metadata subject matches. */
    EXACT_DUPLICATE(false),
    /** Bundle identity matches while materially relevant metadata differs. */
    METADATA_DISAGREEMENT(false),
    /** Different versions compete across catalogs under the same app namespace. */
    COMPETING_VERSIONS(false),
    /** Locally accepted reviewer policy semantics differ across catalogs. */
    REVIEWER_POLICY_DISAGREEMENT(false),
    /** Catalog-local security decisions differ for the compared subject. */
    SECURITY_POLICY_DISAGREEMENT(true),
    /** One version names different bundle bytes or bundle types. */
    SAME_VERSION_PAYLOAD_CONFLICT(true),
    /** One app namespace is claimed by unrelated publisher identities. */
    PUBLISHER_NAMESPACE_CONFLICT(true);

    /** Whether this conflict type blocks routine installation and automatic update. */
    private final boolean hard;

    /**
     * Creates a conflict type with its routine-work severity.
     *
     * @param hard whether unresolved instances block routine work
     */
    Type(boolean hard) {
      this.hard = hard;
    }

    /**
     * Returns whether an unresolved instance blocks install and automatic update.
     *
     * @return {@code true} for force-blocking conflict classes
     */
    public boolean hard() {
      return hard;
    }
  }

  /** Closed local resolution vocabulary; no value is a network-wide trust or moderation claim. */
  public enum ResolutionKind {
    /** No local resolution has been selected. */
    UNRESOLVED,
    /** Local policy explicitly blocks every candidate in the set. */
    BLOCKED,
    /** Local policy pins one exact catalog. */
    PIN_CATALOG,
    /** Local policy pins one exact publisher fingerprint. */
    PIN_PUBLISHER,
    /** Local policy prefers one catalog only for a non-hard conflict. */
    PREFER_CATALOG,
    /** Local policy permits equivalent subjects after exact duplicate classification. */
    ALLOW_EXACT_DUPLICATE,
    /** Local policy requires an explicit digest-bound source-switch consent. */
    EXPLICIT_SOURCE_SWITCH_REQUIRED,
    /** Local policy quarantines every subject pending further action. */
    QUARANTINED
  }

  /**
   * Digest-bound local decision that becomes stale whenever any conflict subject changes.
   *
   * @param conflictId deterministic identifier of the conflict being resolved
   * @param subjectSetDigest digest of every exact subject covered by the decision
   * @param kind closed local resolution action selected by the operator
   * @param catalogId optional exact catalog selected by catalog-based actions
   * @param publisherFingerprint optional exact publisher selected by publisher pinning
   * @param decidedAt timestamp of the local operator decision
   * @param reason bounded local audit reason for the decision
   * @param selfDigest digest binding every preceding resolution field
   */
  public record Resolution(
      String conflictId,
      String subjectSetDigest,
      ResolutionKind kind,
      Optional<String> catalogId,
      Optional<String> publisherFingerprint,
      Instant decidedAt,
      String reason,
      String selfDigest) {
    /** Validates and self-digests the exact local resolution. */
    public Resolution {
      text(conflictId, "conflictId");
      digest(subjectSetDigest, "subjectSetDigest");
      Objects.requireNonNull(kind, "kind");
      catalogId =
          Objects.requireNonNull(catalogId, "catalogId").map(AppCatalog::normalizeCatalogId);
      publisherFingerprint =
          Objects.requireNonNull(publisherFingerprint, PUBLISHER_FINGERPRINT_FIELD)
              .map(value -> digest(value, PUBLISHER_FINGERPRINT_FIELD));
      Objects.requireNonNull(decidedAt, "decidedAt");
      text(reason, "reason");
      if ((kind == ResolutionKind.PIN_CATALOG || kind == ResolutionKind.PREFER_CATALOG)
          && catalogId.isEmpty()) {
        throw new AppCatalogException(
            "invalid_catalog_conflict", "catalog resolution requires an exact catalog id");
      }
      if (kind == ResolutionKind.PIN_PUBLISHER && publisherFingerprint.isEmpty()) {
        throw new AppCatalogException(
            "invalid_catalog_conflict", "publisher resolution requires an exact fingerprint");
      }
      String computed =
          sha256(
              String.join(
                      "\n",
                      conflictId,
                      subjectSetDigest,
                      kind.name(),
                      catalogId.orElse(""),
                      publisherFingerprint.orElse(""),
                      decidedAt.toString(),
                      reason)
                  + "\n");
      if (selfDigest == null) {
        selfDigest = computed;
      } else if (!computed.equals(digest(selfDigest, "selfDigest"))) {
        throw new AppCatalogException(
            "invalid_catalog_conflict", "conflict resolution self digest does not match");
      }
    }

    /**
     * Returns whether this decision binds the exact current conflict set.
     *
     * @param conflictSet current deterministic conflict set
     * @return {@code true} when conflict and subject-set identities match
     */
    public boolean appliesTo(ConflictSet conflictSet) {
      return conflictId.equals(conflictSet.conflictId())
          && subjectSetDigest.equals(conflictSet.subjectSetDigest());
    }
  }

  /**
   * One path-free, locally authenticated catalog subject used for conflict comparison.
   *
   * @param catalogId authenticated catalog identifier supplying the candidate
   * @param catalogTrustDigest exact local trust-binding digest for that catalog
   * @param appId normalized application namespace being compared
   * @param version exact candidate version string
   * @param bundleDigest SHA-256 digest of the candidate bundle bytes
   * @param bundleType closed bundle format or media type
   * @param publisherFingerprint canonical publisher public-key fingerprint
   * @param publisherLineageDigest digest of the approved publisher-key lineage
   * @param reviewPolicyDigest catalog-independent digest of the locally accepted reviewer-policy
   *     semantics
   * @param securityDecision bounded catalog security-policy outcome
   * @param metadataDigest digest of materially relevant catalog metadata
   */
  public record Subject(
      String catalogId,
      String catalogTrustDigest,
      String appId,
      String version,
      String bundleDigest,
      String bundleType,
      String publisherFingerprint,
      String publisherLineageDigest,
      String reviewPolicyDigest,
      String securityDecision,
      String metadataDigest) {
    /** Validates and normalizes one path-free conflict subject. */
    public Subject {
      catalogId = AppCatalog.normalizeCatalogId(catalogId);
      appId = AppCatalogEntry.normalizeAppId(appId);
      digest(catalogTrustDigest, "catalogTrustDigest");
      digest(bundleDigest, "bundleDigest");
      digest(publisherFingerprint, PUBLISHER_FINGERPRINT_FIELD);
      digest(publisherLineageDigest, "publisherLineageDigest");
      digest(reviewPolicyDigest, "reviewPolicyDigest");
      digest(metadataDigest, "metadataDigest");
      text(version, "version");
      text(bundleType, "bundleType");
      text(securityDecision, "securityDecision");
    }

    /**
     * Returns the deterministic newline-terminated subject representation.
     *
     * @return canonical conflict-subject digest input
     */
    String canonical() {
      return String.join(
              "\n",
              catalogId,
              catalogTrustDigest,
              appId,
              version,
              bundleDigest,
              bundleType,
              publisherFingerprint,
              publisherLineageDigest,
              reviewPolicyDigest,
              securityDecision,
              metadataDigest)
          + "\n";
    }
  }

  /**
   * One exact conflict set whose digest invalidates stale local resolutions.
   *
   * @param conflictId deterministic identifier derived from the exact conflict subjects
   * @param appId normalized application namespace shared by every subject
   * @param subjectSetDigest digest binding the sorted complete subject set
   * @param types deterministic classifications present in this conflict
   * @param hard whether any classification blocks install or automatic update
   * @param subjects sorted path-free catalog subjects included in the conflict
   */
  public record ConflictSet(
      String conflictId,
      String appId,
      String subjectSetDigest,
      Set<Type> types,
      boolean hard,
      List<Subject> subjects) {
    /** Validates and freezes one complete deterministic conflict set. */
    public ConflictSet {
      text(conflictId, "conflictId");
      appId = AppCatalogEntry.normalizeAppId(appId);
      digest(subjectSetDigest, "subjectSetDigest");
      types = Set.copyOf(types);
      subjects = List.copyOf(subjects);
      if (subjects.size() < 2 || types.isEmpty() || hard != types.stream().anyMatch(Type::hard)) {
        throw new AppCatalogException("invalid_catalog_conflict", "invalid conflict set");
      }
    }
  }

  /**
   * Classifies one app's subjects; an empty result means there is no cross-catalog conflict.
   *
   * @param candidates complete authenticated subjects for one app namespace
   * @return deterministic conflict set, or an empty value for fewer than two subjects
   */
  public static java.util.Optional<ConflictSet> classify(List<Subject> candidates) {
    List<Subject> subjects =
        candidates.stream()
            .sorted(
                java.util.Comparator.comparing(Subject::catalogId)
                    .thenComparing(Subject::canonical))
            .toList();
    if (subjects.size() < 2) {
      return java.util.Optional.empty();
    }
    String appId = subjects.getFirst().appId();
    if (subjects.stream().anyMatch(subject -> !subject.appId().equals(appId))) {
      throw new AppCatalogException("invalid_catalog_conflict", "conflict subjects mix app ids");
    }
    TreeSet<Type> types = new TreeSet<>();
    for (int left = 0; left < subjects.size(); left++) {
      for (int right = left + 1; right < subjects.size(); right++) {
        classifyPair(subjects.get(left), subjects.get(right), types);
      }
    }
    String setDigest = sha256(subjects.stream().map(Subject::canonical).reduce("", String::concat));
    String conflictId = "catalog-conflict-" + setDigest.substring(0, 24);
    return java.util.Optional.of(
        new ConflictSet(
            conflictId, appId, setDigest, types, types.stream().anyMatch(Type::hard), subjects));
  }

  /**
   * Adds every applicable conflict classification for one subject pair.
   *
   * @param left first authenticated conflict subject
   * @param right second authenticated conflict subject
   * @param types mutable classification accumulator
   */
  private static void classifyPair(Subject left, Subject right, Set<Type> types) {
    boolean sameVersion = left.version().equals(right.version());
    boolean samePayload =
        left.bundleDigest().equals(right.bundleDigest())
            && left.bundleType().equals(right.bundleType());
    boolean samePublisher =
        left.publisherFingerprint().equals(right.publisherFingerprint())
            || left.publisherLineageDigest().equals(right.publisherLineageDigest());
    boolean sameSecurityDecision = left.securityDecision().equals(right.securityDecision());
    boolean sameReviewPolicy = left.reviewPolicyDigest().equals(right.reviewPolicyDigest());
    if (!samePublisher) {
      types.add(Type.PUBLISHER_NAMESPACE_CONFLICT);
    }
    if (sameVersion && !samePayload) {
      types.add(Type.SAME_VERSION_PAYLOAD_CONFLICT);
    } else if (!sameVersion) {
      types.add(Type.COMPETING_VERSIONS);
    }
    if (!sameSecurityDecision) {
      types.add(Type.SECURITY_POLICY_DISAGREEMENT);
    }
    if (!sameReviewPolicy) {
      types.add(Type.REVIEWER_POLICY_DISAGREEMENT);
    }
    if (sameVersion && samePayload && samePublisher) {
      if (left.metadataDigest().equals(right.metadataDigest())
          && sameSecurityDecision
          && sameReviewPolicy) {
        types.add(Type.EXACT_DUPLICATE);
      } else {
        types.add(Type.METADATA_DISAGREEMENT);
      }
    }
  }

  /**
   * Requires one lowercase SHA-256 conflict field.
   *
   * @param value digest text to validate
   * @param field field name used in failures
   * @return validated digest text
   */
  private static String digest(String value, String field) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new AppCatalogException("invalid_catalog_conflict", field + " must be SHA-256");
    }
    return value;
  }

  /**
   * Requires one bounded nonblank single-line conflict field.
   *
   * @param value text to validate
   * @param field field name used in failures
   */
  private static void text(String value, String field) {
    if (value == null || value.isBlank() || value.length() > 256 || value.contains("\n")) {
      throw new AppCatalogException("invalid_catalog_conflict", "invalid " + field);
    }
  }

  /**
   * Computes lowercase SHA-256 over exact canonical UTF-8 text.
   *
   * @param value canonical conflict text
   * @return lowercase hexadecimal SHA-256 digest
   */
  private static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
