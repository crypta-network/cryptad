package network.crypta.platform.appcatalog;

import java.util.Objects;

/**
 * Catalog and app identity supplied to a publisher-authorization policy.
 *
 * <p>The catalog manager creates this value only after selecting an entry from an authenticated
 * catalog. A context lets publisher policy bind a verified bundle signer to both the exact catalog
 * ID and the exact app entry; catalog content alone cannot create that local authorization. The
 * extractor passes the same immutable value at initial extraction and retained-plan
 * re-verification.
 *
 * <p>Construction normalizes the catalog ID through the catalog parser's existing rules and keeps
 * the immutable entry value unchanged. The record contains no source URI, key bytes, credentials,
 * or app-owned state, so a policy can use it without expanding the staging directory's ownership or
 * privacy boundary.
 *
 * @param catalogId normalized authenticated catalog identity
 * @param entry exact authenticated catalog entry being authorized
 */
public record AppCatalogBundleVerificationContext(String catalogId, AppCatalogEntry entry) {
  /**
   * Creates a normalized immutable verification context.
   *
   * <p>The constructor rejects a missing entry and applies the same catalog-ID normalization used
   * by catalog lookup and source persistence. It does not verify a catalog, fetch a bundle, or
   * authorize the entry; those operations remain with the catalog manager and publisher policy.
   *
   * @param catalogId authenticated catalog identity to normalize for policy lookup
   * @param entry exact authenticated catalog entry being installed or updated
   * @throws NullPointerException if {@code catalogId} or {@code entry} is {@code null}
   * @throws AppCatalogException if {@code catalogId} is not a valid catalog identity
   */
  public AppCatalogBundleVerificationContext {
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    Objects.requireNonNull(entry, "entry");
  }
}
