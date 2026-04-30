package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable sync metadata for one configured app catalog source.
 *
 * <p>This record separates a refresh attempt from a verified refresh. A failed fetch, missing
 * signature, or invalid signature updates the attempt fields but does not move {@link
 * #lastSuccessfulRefreshAt()}. That distinction lets the manager keep serving the last verified
 * catalog while the API and Web Shell report the failed sync attempt.
 *
 * <p>Error text is stored only as bounded single-line diagnostic metadata. It is intended for
 * operator-facing status displays and logs, not for reconstructing stack traces or exposing raw
 * transport errors. The resolved URI is likewise diagnostic: for Crypta USK fetches it may show the
 * edition reported by the runtime fetch layer, but catalog signatures remain the trust boundary.
 *
 * @param lastAttemptAt timestamp of the most recent source refresh attempt
 * @param lastSuccessfulRefreshAt timestamp of the most recent verified catalog refresh
 * @param lastFetchStatus status of the most recent refresh attempt
 * @param lastFetchErrorCode stable error code from the last failed attempt, when present
 * @param lastFetchErrorMessage safe diagnostic text from the last failed attempt, when present
 * @param lastResolvedUri transport-reported resolved URI or fetch key, when available
 */
record AppCatalogSourceRefreshMetadata(
    Instant lastAttemptAt,
    Instant lastSuccessfulRefreshAt,
    AppCatalogFetchStatus lastFetchStatus,
    Optional<String> lastFetchErrorCode,
    Optional<String> lastFetchErrorMessage,
    Optional<String> lastResolvedUri) {
  /** Maximum persisted characters for a UI-safe refresh failure message. */
  private static final int MAX_ERROR_MESSAGE_CHARS = 512;

  /**
   * Validates and normalizes refresh metadata.
   *
   * <p>The constructor keeps the record internally consistent. Successful metadata cannot carry an
   * error code or message, and failed messages are normalized before storage so they remain safe
   * for property files and compact API responses.
   */
  AppCatalogSourceRefreshMetadata {
    Objects.requireNonNull(lastAttemptAt, "lastAttemptAt");
    Objects.requireNonNull(lastSuccessfulRefreshAt, "lastSuccessfulRefreshAt");
    Objects.requireNonNull(lastFetchStatus, "lastFetchStatus");
    Objects.requireNonNull(lastFetchErrorCode, "lastFetchErrorCode");
    Objects.requireNonNull(lastFetchErrorMessage, "lastFetchErrorMessage");
    Objects.requireNonNull(lastResolvedUri, "lastResolvedUri");
    lastFetchErrorMessage =
        lastFetchErrorMessage.map(AppCatalogSourceRefreshMetadata::normalizeErrorMessage);
    if (lastFetchStatus == AppCatalogFetchStatus.SUCCESS
        && (lastFetchErrorCode.isPresent() || lastFetchErrorMessage.isPresent())) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "successful catalog fetch metadata must not include an error");
    }
  }

  /**
   * Creates metadata for a newly verified catalog refresh.
   *
   * <p>All attempt and success timestamps point at the same instant because the refresh completed.
   * Error fields are empty, and the resolved URI captures the source location or transport-reported
   * final URI that produced the verified catalog bytes.
   *
   * @param refreshedAt instant when the verified catalog was written
   * @param resolvedUri source URI or transport-resolved fetch key for diagnostics
   * @return success metadata suitable for persisting with verified sidecars
   */
  static AppCatalogSourceRefreshMetadata success(Instant refreshedAt, String resolvedUri) {
    return new AppCatalogSourceRefreshMetadata(
        refreshedAt,
        refreshedAt,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of(resolvedUri));
  }

  /**
   * Returns metadata for a failed refresh attempt without changing the last successful timestamp.
   *
   * <p>The returned value records the new attempt time and stable error details while preserving
   * the previous success time. Managers use this after fetch or verification failures so stored
   * catalog sidecars remain authoritative until a later refresh verifies successfully.
   *
   * @param attemptedAt instant when the failed refresh attempt started
   * @param exception catalog-layer failure containing the stable error code
   * @param resolvedUri source URI or fetch key to report for the failed attempt
   * @return failed-attempt metadata preserving the prior success timestamp
   */
  AppCatalogSourceRefreshMetadata failedAttempt(
      Instant attemptedAt, AppCatalogException exception, String resolvedUri) {
    return new AppCatalogSourceRefreshMetadata(
        attemptedAt,
        lastSuccessfulRefreshAt,
        AppCatalogFetchStatus.FAILED,
        Optional.of(exception.errorCode()),
        Optional.ofNullable(exception.getMessage()),
        Optional.ofNullable(resolvedUri));
  }

  /**
   * Converts error text into bounded single-line status metadata.
   *
   * @param value raw exception message or runtime fetch diagnostic text
   * @return trimmed single-line value capped for property files and API responses
   */
  private static String normalizeErrorMessage(String value) {
    String singleLine = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').trim();
    if (singleLine.length() <= MAX_ERROR_MESSAGE_CHARS) {
      return singleLine;
    }
    return singleLine.substring(0, MAX_ERROR_MESSAGE_CHARS);
  }
}
