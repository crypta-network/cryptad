package network.crypta.platform.appcatalog;

import java.util.Objects;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Groups the transport, artifact, extraction, and review-log services used by a catalog manager.
 *
 * <p>This record keeps construction concerns out of {@link AppCatalogManager} while preserving
 * explicit injection for controlled embeddings and deterministic tests. Production factories can
 * assemble the standard network and file-backed implementations, while specialized runtimes can
 * provide transport adapters without expanding the manager's constructor dependency count.
 *
 * <p>The record is an immutable collection of non-null service references; it does not copy or
 * close those services. Individual components can retain state and define their own concurrency
 * guarantees. The bundle itself contains no signing key material and does not represent catalog
 * publication authority. Callers remain responsible for supplying components that share the
 * intended source store, trust policy, and lifecycle.
 *
 * @param fetcher signed-catalog transport
 * @param artifactDownloader bundle artifact transport and digest checker
 * @param bundleExtractor confined ZIP extractor and signed-bundle verifier
 * @param reviewTransparencyLog local app-review transparency log
 */
public record AppCatalogManagerDependencies(
    AppCatalogFetcher fetcher,
    AppCatalogArtifactDownloader artifactDownloader,
    AppCatalogBundleExtractor bundleExtractor,
    AppReviewTransparencyLog reviewTransparencyLog) {

  /**
   * Creates a dependency bundle after validating every service reference.
   *
   * <p>The constructor preserves the supplied instances exactly and performs no I/O or service
   * initialization. This allows callers to share deliberately configured transports and stores,
   * while preventing a partially configured manager from being constructed.
   *
   * @param fetcher signed-catalog transport used to retrieve catalog subjects
   * @param artifactDownloader bundle artifact transport and digest-verification service
   * @param bundleExtractor confined archive extractor and signed-bundle verification boundary
   * @param reviewTransparencyLog local transparency log for authenticated app-review records
   * @throws NullPointerException if any dependency reference is {@code null}
   */
  public AppCatalogManagerDependencies {
    Objects.requireNonNull(fetcher, "fetcher");
    Objects.requireNonNull(artifactDownloader, "artifactDownloader");
    Objects.requireNonNull(bundleExtractor, "bundleExtractor");
    Objects.requireNonNull(reviewTransparencyLog, "reviewTransparencyLog");
  }

  static AppCatalogManagerDependencies defaults(AppCatalogSourceStore sourceStore) {
    return new AppCatalogManagerDependencies(
        new AppCatalogFetcher(),
        new AppCatalogArtifactDownloader(),
        new AppCatalogBundleExtractor(),
        defaultReviewTransparencyLog(sourceStore));
  }

  static AppCatalogManagerDependencies withContentFetchPort(
      AppCatalogSourceStore sourceStore, ContentFetchPort contentFetchPort) {
    return new AppCatalogManagerDependencies(
        new AppCatalogFetcher(contentFetchPort),
        new AppCatalogArtifactDownloader(contentFetchPort),
        new AppCatalogBundleExtractor(),
        defaultReviewTransparencyLog(sourceStore));
  }

  private static AppReviewTransparencyLog defaultReviewTransparencyLog(
      AppCatalogSourceStore sourceStore) {
    return AppReviewTransparencyLog.fileBacked(
        Objects.requireNonNull(sourceStore, "sourceStore").reviewTransparencyLogFile());
  }
}
