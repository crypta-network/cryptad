package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Last observed health for a catalog transport endpoint.
 *
 * <p>Health is operational metadata only. It records which endpoint was tried, whether it produced
 * a verified catalog revision, and bounded diagnostic fields. It never includes raw catalog bytes,
 * signatures, scratch paths, private insert URIs, key material, or app data.
 */
public record AppCatalogMirrorHealth(
    AppCatalogMirrorId id,
    AppCatalogSourceRole role,
    AppCatalogFetchStatus lastFetchStatus,
    Optional<Instant> lastAttemptAt,
    Optional<Instant> lastSuccessfulRefreshAt,
    Optional<String> lastFetchErrorCode,
    Optional<String> lastFetchErrorMessage,
    Optional<String> lastResolvedUri,
    Optional<String> lastCatalogDigest,
    Optional<String> lastSignatureKeyId,
    Optional<Instant> lastGeneratedAt,
    Optional<String> lastRollbackReason) {
  /** Maximum persisted characters for endpoint error messages. */
  static final int MAX_ERROR_MESSAGE_CHARS = 512;

  /** Creates validated endpoint health. */
  public AppCatalogMirrorHealth {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(role, "role");
    Objects.requireNonNull(lastFetchStatus, "lastFetchStatus");
    Objects.requireNonNull(lastAttemptAt, "lastAttemptAt");
    Objects.requireNonNull(lastSuccessfulRefreshAt, "lastSuccessfulRefreshAt");
    Objects.requireNonNull(lastFetchErrorCode, "lastFetchErrorCode");
    lastFetchErrorMessage =
        Objects.requireNonNull(lastFetchErrorMessage, "lastFetchErrorMessage")
            .map(AppCatalogMirrorHealth::normalizeErrorMessage);
    Objects.requireNonNull(lastResolvedUri, "lastResolvedUri");
    Objects.requireNonNull(lastCatalogDigest, "lastCatalogDigest");
    Objects.requireNonNull(lastSignatureKeyId, "lastSignatureKeyId");
    Objects.requireNonNull(lastGeneratedAt, "lastGeneratedAt");
    lastRollbackReason =
        Objects.requireNonNull(lastRollbackReason, "lastRollbackReason")
            .map(AppCatalogMirrorHealth::normalizeRollbackReason);
  }

  public AppCatalogMirrorHealth(
      AppCatalogMirrorId id,
      AppCatalogSourceRole role,
      AppCatalogFetchStatus lastFetchStatus,
      Optional<Instant> lastAttemptAt,
      Optional<Instant> lastSuccessfulRefreshAt,
      Optional<String> lastFetchErrorCode,
      Optional<String> lastFetchErrorMessage,
      Optional<String> lastResolvedUri,
      Optional<String> lastCatalogDigest,
      Optional<String> lastSignatureKeyId,
      Optional<Instant> lastGeneratedAt) {
    this(
        id,
        role,
        lastFetchStatus,
        lastAttemptAt,
        lastSuccessfulRefreshAt,
        lastFetchErrorCode,
        lastFetchErrorMessage,
        lastResolvedUri,
        lastCatalogDigest,
        lastSignatureKeyId,
        lastGeneratedAt,
        Optional.empty());
  }

  /**
   * Builds primary health from the legacy single-source refresh metadata.
   *
   * @param metadata legacy refresh metadata
   * @param fetchedCatalog latest stored sidecars
   * @param generatedAt signed catalog generated timestamp
   * @return primary endpoint health
   */
  static AppCatalogMirrorHealth primary(
      AppCatalogSourceRefreshMetadata metadata,
      FetchedCatalog fetchedCatalog,
      Instant generatedAt) {
    return new AppCatalogMirrorHealth(
        AppCatalogMirrorId.PRIMARY,
        AppCatalogSourceRole.PRIMARY,
        metadata.lastFetchStatus(),
        Optional.of(metadata.lastAttemptAt()),
        Optional.of(metadata.lastSuccessfulRefreshAt()),
        metadata.lastFetchErrorCode(),
        metadata.lastFetchErrorMessage(),
        metadata.lastResolvedUri(),
        Optional.of(AppCatalogRevisions.catalogDigest(fetchedCatalog)),
        Optional.of(AppCatalogVerifier.readSignature(fetchedCatalog.signatureBytes()).keyId()),
        Optional.of(generatedAt));
  }

  /**
   * Creates skipped health for an untried endpoint.
   *
   * @param mirror endpoint configuration
   * @return skipped endpoint health
   */
  static AppCatalogMirrorHealth skipped(AppCatalogMirror mirror) {
    return new AppCatalogMirrorHealth(
        mirror.id(),
        mirror.role(),
        AppCatalogFetchStatus.SKIPPED,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  /**
   * Returns health for a failed attempt.
   *
   * @param attemptedAt attempt timestamp
   * @param exception stable catalog failure
   * @param resolvedUri resolved transport URI or fetch key
   * @return updated failed health
   */
  AppCatalogMirrorHealth failedAttempt(
      Instant attemptedAt, AppCatalogException exception, String resolvedUri) {
    return new AppCatalogMirrorHealth(
        id,
        role,
        AppCatalogFetchStatus.FAILED,
        Optional.of(attemptedAt),
        lastSuccessfulRefreshAt,
        Optional.of(exception.errorCode()),
        Optional.ofNullable(exception.getMessage()),
        Optional.ofNullable(resolvedUri),
        lastCatalogDigest,
        lastSignatureKeyId,
        lastGeneratedAt,
        lastRollbackReason);
  }

  /**
   * Returns health for a stale verified candidate.
   *
   * @param attemptedAt attempt timestamp
   * @param resolvedUri resolved transport URI or fetch key
   * @param digest verified catalog digest
   * @param signatureKeyId verified signing key id
   * @param generatedAt signed catalog generated timestamp
   * @return updated stale health
   */
  AppCatalogMirrorHealth staleAttempt(
      Instant attemptedAt,
      String resolvedUri,
      String digest,
      String signatureKeyId,
      Instant generatedAt) {
    boolean hasPreviousSuccess = hasPreviousSuccessfulRevision();
    return new AppCatalogMirrorHealth(
        id,
        role,
        AppCatalogFetchStatus.STALE,
        Optional.of(attemptedAt),
        hasPreviousSuccess ? lastSuccessfulRefreshAt : Optional.empty(),
        Optional.of("failed_stale_revision"),
        Optional.of("mirror returned an older catalog revision"),
        hasPreviousSuccess ? lastResolvedUri : Optional.ofNullable(resolvedUri),
        hasPreviousSuccess ? lastCatalogDigest : Optional.of(digest),
        hasPreviousSuccess ? lastSignatureKeyId : Optional.of(signatureKeyId),
        hasPreviousSuccess ? lastGeneratedAt : Optional.of(generatedAt),
        lastRollbackReason);
  }

  private boolean hasPreviousSuccessfulRevision() {
    return lastSuccessfulRefreshAt.isPresent()
        && lastCatalogDigest.isPresent()
        && lastSignatureKeyId.isPresent()
        && lastGeneratedAt.isPresent();
  }

  /**
   * Returns health for a verified successful attempt.
   *
   * @param refreshedAt refresh timestamp
   * @param resolvedUri resolved transport URI or fetch key
   * @param digest verified catalog digest
   * @param signatureKeyId verified signing key id
   * @param generatedAt signed catalog generated timestamp
   * @return updated success health
   */
  AppCatalogMirrorHealth successfulAttempt(
      Instant refreshedAt,
      String resolvedUri,
      String digest,
      String signatureKeyId,
      Instant generatedAt) {
    return new AppCatalogMirrorHealth(
        id,
        role,
        AppCatalogFetchStatus.SUCCESS,
        Optional.of(refreshedAt),
        Optional.of(refreshedAt),
        Optional.empty(),
        Optional.empty(),
        Optional.ofNullable(resolvedUri),
        Optional.of(digest),
        Optional.of(signatureKeyId),
        Optional.of(generatedAt));
  }

  /**
   * Returns health for an explicit rollback to a verified retained revision.
   *
   * @param refreshedAt rollback timestamp
   * @param resolvedUri resolved transport URI or fetch key stored with the retained revision
   * @param digest verified catalog digest
   * @param signatureKeyId verified signing key id
   * @param generatedAt signed catalog generated timestamp
   * @param rollbackReason operator-entered rollback reason, when supplied
   * @return updated rollback health
   */
  AppCatalogMirrorHealth successfulRollback(
      Instant refreshedAt,
      String resolvedUri,
      String digest,
      String signatureKeyId,
      Instant generatedAt,
      String rollbackReason) {
    return new AppCatalogMirrorHealth(
        id,
        role,
        AppCatalogFetchStatus.SUCCESS,
        Optional.of(refreshedAt),
        Optional.of(refreshedAt),
        Optional.empty(),
        Optional.empty(),
        Optional.ofNullable(resolvedUri),
        Optional.of(digest),
        Optional.of(signatureKeyId),
        Optional.of(generatedAt),
        Optional.ofNullable(rollbackReason));
  }

  private static String normalizeErrorMessage(String value) {
    String singleLine = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
    if (singleLine.length() <= MAX_ERROR_MESSAGE_CHARS) {
      return singleLine;
    }
    return singleLine.substring(0, MAX_ERROR_MESSAGE_CHARS);
  }

  private static String normalizeRollbackReason(String value) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value,
        "lastRollbackReason",
        AppCatalogSidecars.INVALID_CATALOG_SOURCE,
        AppCatalogSidecars.MAX_OPERATOR_REASON_CHARS);
  }
}
