package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * Verified temporary staged bundle prepared from a catalog entry.
 *
 * <p>The plan owns a scratch directory that contains the downloaded artifact and extracted bundle.
 * API handlers pass {@link #stagedBundleDirectory()} to AppHost, which copies the bundle into its
 * managed installation tree. After AppHost returns, callers close the plan to remove catalog
 * scratch data without affecting the installed copy.
 *
 * <p>Instances are returned only after catalog signature verification, artifact digest/size checks,
 * safe ZIP extraction, signed-bundle verification, and manifest/catalog id matching have succeeded.
 * The paths are normalized to absolute paths at construction time. The record is immutable, but the
 * filesystem content it points at remains temporary and must not be exposed as a long-lived app
 * location.
 *
 * @param catalogId catalog that supplied the entry
 * @param entry catalog entry selected by the caller
 * @param stagedBundleDirectory extracted signed-bundle root ready for AppHost
 * @param scratchDirectory scratch directory removed when the plan is closed
 * @param bundleVerification exact publisher authorization captured during extraction
 * @param originContext exact authenticated catalog authority captured with the selected revision
 */
public record AppCatalogInstallPlan(
    String catalogId,
    AppCatalogEntry entry,
    Path stagedBundleDirectory,
    Path scratchDirectory,
    AppCatalogBundleVerificationResult bundleVerification,
    Optional<AppCatalogOriginContext> originContext)
    implements AutoCloseable {
  /**
   * Creates a verified installation plan.
   *
   * <p>The constructor normalizes the catalog id and path fields but does not perform bundle
   * verification. Normal runtime callers receive plans from {@link AppCatalogManager}, which has
   * already completed the full verification pipeline.
   *
   * @param catalogId catalog that supplied the entry
   * @param entry catalog entry selected by the caller
   * @param stagedBundleDirectory extracted signed-bundle root ready for AppHost
   * @param scratchDirectory scratch directory removed when the plan is closed
   * @param bundleVerification exact publisher authorization captured during extraction
   * @param originContext exact catalog authority captured with the selected catalog revision
   */
  public AppCatalogInstallPlan {
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    Objects.requireNonNull(entry, "entry");
    stagedBundleDirectory =
        Objects.requireNonNull(stagedBundleDirectory, "stagedBundleDirectory")
            .toAbsolutePath()
            .normalize();
    scratchDirectory =
        Objects.requireNonNull(scratchDirectory, "scratchDirectory").toAbsolutePath().normalize();
    Objects.requireNonNull(bundleVerification, "bundleVerification");
    Objects.requireNonNull(originContext, "originContext");
  }

  /**
   * Creates a compatibility plan without a captured catalog-origin context.
   *
   * <p>This constructor preserves callers that assemble plan fixtures or adapters directly. Plans
   * produced by {@link AppCatalogManager} always use the contextual constructor above; attempting
   * to re-verify a compatibility plan fails the exact-result comparison rather than silently
   * treating missing provenance as current authorization.
   *
   * @param catalogId catalog that supplied the entry
   * @param entry catalog entry selected by the caller
   * @param stagedBundleDirectory extracted signed-bundle root ready for AppHost
   * @param scratchDirectory scratch directory removed when the plan is closed
   * @param bundleVerification exact publisher authorization captured during extraction
   */
  public AppCatalogInstallPlan(
      String catalogId,
      AppCatalogEntry entry,
      Path stagedBundleDirectory,
      Path scratchDirectory,
      AppCatalogBundleVerificationResult bundleVerification) {
    this(
        catalogId,
        entry,
        stagedBundleDirectory,
        scratchDirectory,
        bundleVerification,
        Optional.empty());
  }

  /** Creates a compatibility plan without captured publisher or catalog-origin authorization. */
  public AppCatalogInstallPlan(
      String catalogId, AppCatalogEntry entry, Path stagedBundleDirectory, Path scratchDirectory) {
    this(
        catalogId,
        entry,
        stagedBundleDirectory,
        scratchDirectory,
        AppCatalogBundleVerificationResult.unrecorded(),
        Optional.empty());
  }

  /**
   * Removes the scratch tree associated with the plan.
   *
   * <p>Closing the plan is idempotent when the scratch tree has already been removed. A cleanup
   * failure is reported to the caller so API adapters can log it without changing a successful
   * install or update response after AppHost has already committed state.
   *
   * @throws IOException if the temporary catalog staging tree cannot be removed
   */
  @Override
  public void close() throws IOException {
    AppCatalogBundleExtractor.deleteRecursively(scratchDirectory);
  }
}
