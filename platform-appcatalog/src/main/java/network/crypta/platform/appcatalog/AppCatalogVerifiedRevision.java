package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Metadata for one retained verified catalog revision.
 *
 * <p>The revision digest is the SHA-256 digest of the verified catalog properties bytes. Revision
 * metadata is safe for Platform API, Web Shell, support bundles, and release evidence because it
 * excludes raw catalog bytes, signatures, source-store paths, scratch paths, staged paths, private
 * insert URIs, and key material.
 */
public record AppCatalogVerifiedRevision(
    String revisionDigest,
    String catalogId,
    String catalogName,
    Instant generatedAt,
    Instant verifiedAt,
    AppCatalogMirrorId sourceId,
    AppCatalogSourceRole sourceRole,
    Optional<String> resolvedUri,
    String signatureKeyId,
    int appCount,
    int advisoryCount,
    int denylistCount,
    List<String> channels,
    boolean current,
    Optional<String> signatureDigest) {
  /** Creates validated revision metadata. */
  public AppCatalogVerifiedRevision {
    revisionDigest =
        AppCatalogSidecars.requireNonBlankSingleLine(
            revisionDigest, "revisionDigest", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    catalogName =
        AppCatalogSidecars.requireNonBlankSingleLine(
            catalogName, "catalogName", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    Objects.requireNonNull(generatedAt, "generatedAt");
    Objects.requireNonNull(verifiedAt, "verifiedAt");
    Objects.requireNonNull(sourceId, "sourceId");
    Objects.requireNonNull(sourceRole, "sourceRole");
    Objects.requireNonNull(resolvedUri, "resolvedUri");
    signatureKeyId =
        AppCatalogSidecars.requireNonBlankSingleLine(
            signatureKeyId, "signatureKeyId", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    if (appCount < 0 || advisoryCount < 0 || denylistCount < 0) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "revision counts must be non-negative");
    }
    channels = List.copyOf(Objects.requireNonNull(channels, "channels"));
    Objects.requireNonNull(signatureDigest, "signatureDigest");
  }
}
