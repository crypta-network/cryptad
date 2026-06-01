package network.crypta.platform.appcatalog;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * API-friendly snapshot of one configured catalog source.
 *
 * <p>The snapshot combines source configuration with the latest verified catalog metadata stored on
 * disk. It intentionally exposes source URI text and catalog counts, but not trusted key material
 * or any temporary filesystem paths used for artifact staging.
 *
 * <p>Snapshots are point-in-time values. Listing or refreshing catalogs may create newer snapshots,
 * but an existing instance does not track later source-store writes. The record validates catalog
 * id, source URI, timestamps, and app count so API handlers can serialize it directly without
 * another normalization step.
 *
 * @param catalogId stable catalog identifier
 * @param name human-readable catalog name
 * @param sourceUri configured catalog properties URI
 * @param generatedAt timestamp declared by the catalog producer
 * @param appCount number of app entries currently available
 * @param addedAt timestamp when the source was first configured locally
 * @param refreshedAt timestamp when the stored catalog was last fetched and verified
 * @param lastAttemptAt timestamp when the source was last refresh-attempted
 * @param lastSuccessfulRefreshAt timestamp when the source was last successfully verified
 * @param lastFetchStatus status of the most recent refresh attempt
 * @param lastFetchErrorCode stable error code from the most recent failed refresh attempt
 * @param lastFetchErrorMessage diagnostic message from the most recent failed refresh attempt
 * @param lastResolvedUri source URI or Crypta key used by the last fetch attempt
 * @param signatureKeyId public trusted-key identifier from the verified catalog signature sidecar
 */
public record AppCatalogSourceSnapshot(
    String catalogId,
    String name,
    URI sourceUri,
    Instant generatedAt,
    int appCount,
    Instant addedAt,
    Instant refreshedAt,
    Instant lastAttemptAt,
    Instant lastSuccessfulRefreshAt,
    AppCatalogFetchStatus lastFetchStatus,
    Optional<String> lastFetchErrorCode,
    Optional<String> lastFetchErrorMessage,
    Optional<String> lastResolvedUri,
    Optional<String> signatureKeyId) {
  /**
   * Creates a validated source snapshot.
   *
   * <p>The constructor normalizes identifiers and URI policy to match the source store. It does not
   * verify catalog signatures; callers should build snapshots only from catalogs that have already
   * been authenticated by {@link AppCatalogVerifier}.
   *
   * @param catalogId stable catalog identifier
   * @param name human-readable catalog name
   * @param sourceUri configured catalog properties URI
   * @param generatedAt timestamp declared by the catalog producer
   * @param appCount number of app entries currently available
   * @param addedAt timestamp when the source was first configured locally
   * @param refreshedAt timestamp when the stored catalog was last fetched and verified
   * @param lastAttemptAt timestamp when the source was last refresh-attempted
   * @param lastSuccessfulRefreshAt timestamp when the source was last successfully verified
   * @param lastFetchStatus status of the most recent refresh attempt
   * @param lastFetchErrorCode stable error code from the most recent failed refresh attempt
   * @param lastFetchErrorMessage diagnostic message from the most recent failed refresh attempt
   * @param lastResolvedUri source URI or Crypta key used by the last fetch attempt
   * @param signatureKeyId public trusted-key identifier from the verified catalog signature sidecar
   */
  public AppCatalogSourceSnapshot {
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    name =
        AppCatalogSidecars.requireNonBlankSingleLine(
            name, "catalog.name", AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    sourceUri = AppCatalogSidecars.requireSafeCatalogSourceUri(Objects.requireNonNull(sourceUri));
    Objects.requireNonNull(generatedAt, "generatedAt");
    if (appCount < 0) {
      throw AppCatalogSidecars.invalidEntry("appCount must be >= 0");
    }
    Objects.requireNonNull(addedAt, "addedAt");
    Objects.requireNonNull(refreshedAt, "refreshedAt");
    Objects.requireNonNull(lastAttemptAt, "lastAttemptAt");
    Objects.requireNonNull(lastSuccessfulRefreshAt, "lastSuccessfulRefreshAt");
    Objects.requireNonNull(lastFetchStatus, "lastFetchStatus");
    Objects.requireNonNull(lastFetchErrorCode, "lastFetchErrorCode");
    Objects.requireNonNull(lastFetchErrorMessage, "lastFetchErrorMessage");
    Objects.requireNonNull(lastResolvedUri, "lastResolvedUri");
    Objects.requireNonNull(signatureKeyId, "signatureKeyId");
  }

  static AppCatalogSourceSnapshot of(
      AppCatalog catalog,
      AppCatalogSource source,
      Instant addedAt,
      Instant refreshedAt,
      AppCatalogSourceRefreshMetadata refreshMetadata,
      FetchedCatalog fetchedCatalog) {
    return new AppCatalogSourceSnapshot(
        catalog.catalogId(),
        catalog.name(),
        source.uri(),
        catalog.generatedAt(),
        catalog.entries().size(),
        addedAt,
        refreshedAt,
        refreshMetadata.lastAttemptAt(),
        refreshMetadata.lastSuccessfulRefreshAt(),
        refreshMetadata.lastFetchStatus(),
        refreshMetadata.lastFetchErrorCode(),
        refreshMetadata.lastFetchErrorMessage(),
        refreshMetadata.lastResolvedUri(),
        signatureKeyId(fetchedCatalog));
  }

  private static Optional<String> signatureKeyId(FetchedCatalog fetchedCatalog) {
    if (fetchedCatalog == null) {
      return Optional.empty();
    }
    return Optional.of(AppCatalogVerifier.readSignature(fetchedCatalog.signatureBytes()).keyId());
  }

  /**
   * Returns the configured source transport family.
   *
   * @return normalized source kind derived from {@link #sourceUri()}
   */
  @SuppressWarnings("unused")
  public AppCatalogSourceKind sourceKind() {
    return new AppCatalogSource(sourceUri).kind();
  }
}
