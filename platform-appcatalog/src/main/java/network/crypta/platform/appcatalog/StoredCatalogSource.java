package network.crypta.platform.appcatalog;

import java.time.Instant;

/**
 * Source-store record containing configured source metadata and cached sidecar bytes.
 *
 * <p>The record is package-private because only {@link AppCatalogSourceStore} and {@link
 * AppCatalogManager} need to exchange this persistence shape. It combines the operator-configured
 * source URI, local lifecycle timestamps, and the exact fetched catalog/signature bytes that still
 * need to be verified against the current trusted-key policy before exposure.
 *
 * @param catalogId normalized catalog id for the stored source directory
 * @param source validated source URI used for refresh operations
 * @param addedAt local timestamp when the source was first persisted
 * @param refreshedAt local timestamp when sidecars were last fetched and verified
 * @param refreshMetadata latest fetch attempt metadata
 * @param fetchedCatalog exact catalog and signature bytes cached by the source store
 */
record StoredCatalogSource(
    String catalogId,
    AppCatalogSource source,
    Instant addedAt,
    Instant refreshedAt,
    AppCatalogSourceRefreshMetadata refreshMetadata,
    FetchedCatalog fetchedCatalog) {}
