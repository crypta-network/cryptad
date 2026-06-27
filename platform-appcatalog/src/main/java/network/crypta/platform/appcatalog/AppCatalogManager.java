package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Coordinates signed catalog sources, refreshes, artifact staging, and bundle verification.
 *
 * <p>The manager owns no global state. Runtime composition supplies the file-backed store and a
 * trusted-key provider, and API handlers call the manager for catalog operations. Install and
 * update flows stop at {@link AppCatalogInstallPlan}; callers still delegate final installation to
 * AppHost so existing staged-directory semantics and verification policies remain intact.
 *
 * <p>All public methods are synchronized because they read and update a shared source store and
 * create scratch directories below the same root. The manager re-reads trusted keys for each
 * operation through {@link TrustedKeyProvider}, which lets deployments rotate catalog/app signing
 * keys without recreating the manager. It verifies stored sidecars before listing or selecting
 * entries, and it never weakens the signed-bundle verification performed by {@code
 * platform-appdist}.
 */
public final class AppCatalogManager {
  private final AppCatalogSourceStore sourceStore;
  private final TrustedKeyProvider trustedKeyProvider;
  private final AppCatalogFetcher fetcher;
  private final AppReviewTransparencyLog reviewTransparencyLog;
  private final AppCatalogOperations operations;
  private final AppCatalogRefreshCoordinator refreshCoordinator;
  private final AppCatalogInstallPlanner installPlanner;

  /**
   * Creates a manager with default JDK fetch and download helpers.
   *
   * <p>This constructor is the normal runtime entry point. It uses the default no-redirect fetcher,
   * the default artifact downloader, and the standard ZIP extractor. The supplied store determines
   * both persistent catalog state and the scratch root used during install/update staging.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore, TrustedKeyProvider trustedKeyProvider) {
    this(
        sourceStore,
        trustedKeyProvider,
        new AppCatalogFetcher(),
        new AppCatalogArtifactDownloader(),
        new AppCatalogBundleExtractor(),
        defaultReviewTransparencyLog(sourceStore));
  }

  /**
   * Creates a manager with a runtime content fetch port for {@code crypta:} catalog sources.
   *
   * <p>The supplied port is used only as bounded content transport. Catalog signatures and trusted
   * catalog keys remain the authentication boundary for fetched catalogs.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
   * @param contentFetchPort runtime content fetch port for {@code crypta:} sources
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedKeyProvider,
      ContentFetchPort contentFetchPort) {
    this(
        sourceStore,
        trustedKeyProvider,
        new AppCatalogFetcher(contentFetchPort),
        new AppCatalogArtifactDownloader(contentFetchPort),
        new AppCatalogBundleExtractor(),
        defaultReviewTransparencyLog(sourceStore));
  }

  /**
   * Creates a manager with explicit collaborators for tests and controlled embeddings.
   *
   * <p>Supplying collaborators keeps network and filesystem edges deterministic in unit tests while
   * preserving the same orchestration order as production: fetch, verify catalog, download
   * artifact, extract, verify bundle, then return a plan.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
   * @param fetcher catalog source fetcher
   * @param artifactDownloader artifact downloader and digest checker
   * @param bundleExtractor ZIP extractor and signed-bundle verifier
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedKeyProvider,
      AppCatalogFetcher fetcher,
      AppCatalogArtifactDownloader artifactDownloader,
      AppCatalogBundleExtractor bundleExtractor) {
    this(
        sourceStore,
        trustedKeyProvider,
        fetcher,
        artifactDownloader,
        bundleExtractor,
        defaultReviewTransparencyLog(sourceStore));
  }

  /**
   * Creates a manager with explicit collaborators and transparency log.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
   * @param fetcher catalog source fetcher
   * @param artifactDownloader artifact downloader and digest checker
   * @param bundleExtractor ZIP extractor and signed-bundle verifier
   * @param reviewTransparencyLog local review transparency log
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedKeyProvider,
      AppCatalogFetcher fetcher,
      AppCatalogArtifactDownloader artifactDownloader,
      AppCatalogBundleExtractor bundleExtractor,
      AppReviewTransparencyLog reviewTransparencyLog) {
    this.sourceStore = Objects.requireNonNull(sourceStore, "sourceStore");
    this.trustedKeyProvider = Objects.requireNonNull(trustedKeyProvider, "trustedKeyProvider");
    this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
    this.reviewTransparencyLog =
        Objects.requireNonNull(reviewTransparencyLog, "reviewTransparencyLog");
    this.operations =
        new AppCatalogOperations(this.sourceStore, this.trustedKeyProvider, this.fetcher);
    this.refreshCoordinator =
        new AppCatalogRefreshCoordinator(
            this.sourceStore, this.trustedKeyProvider, this.fetcher, this.operations);
    this.installPlanner =
        new AppCatalogInstallPlanner(
            this.sourceStore, this.trustedKeyProvider, artifactDownloader, bundleExtractor);
  }

  /**
   * Returns the local review transparency log used by API gates.
   *
   * @return redacted review transparency log facade
   */
  public AppReviewTransparencyLog reviewTransparencyLog() {
    return reviewTransparencyLog;
  }

  private static AppReviewTransparencyLog defaultReviewTransparencyLog(
      AppCatalogSourceStore sourceStore) {
    return AppReviewTransparencyLog.fileBacked(
        Objects.requireNonNull(sourceStore, "sourceStore").reviewTransparencyLogFile());
  }

  /**
   * Lists all configured catalogs after re-verifying stored sidecars.
   *
   * <p>The returned snapshots are built from authenticated catalog bytes stored on disk. If a
   * stored signature becomes invalid under the current trusted-key policy, the listing fails rather
   * than returning stale metadata from a previous verification.
   *
   * @return source snapshots sorted by catalog id
   * @throws IOException if stored catalog state cannot be read
   */
  public synchronized List<AppCatalogSourceSnapshot> listCatalogs() throws IOException {
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    return sourceStore.list().stream()
        .map(stored -> snapshot(stored, trustedKeys))
        .sorted(java.util.Comparator.comparing(AppCatalogSourceSnapshot::catalogId))
        .toList();
  }

  /**
   * Reads one configured catalog after re-verifying its stored sidecars.
   *
   * <p>This is intentionally scoped to the requested catalog so operator troubleshooting endpoints
   * can still inspect a healthy catalog when another configured catalog has corrupt or untrusted
   * cached sidecars.
   *
   * @param catalogId catalog id to read
   * @return verified source snapshot for the requested catalog
   * @throws IOException if the requested catalog cannot be read or verified
   */
  public synchronized AppCatalogSourceSnapshot catalog(String catalogId) throws IOException {
    StoredCatalogSource stored = sourceStore.read(normalizeCatalogIdForLookup(catalogId));
    return snapshot(stored, trustedKeyProvider.trustedKeys());
  }

  /**
   * Adds a catalog source and immediately verifies its signed catalog.
   *
   * <p>The source is fetched before it is persisted. A catalog id conflict is checked after
   * signature verification so an attacker cannot reserve an id with unsigned or malformed content.
   * Successful additions persist the exact fetched sidecar bytes, not a reserialized catalog model.
   *
   * @param rawSource operator-supplied source path or URI
   * @return stored source snapshot for the new catalog
   * @throws IOException if fetch, signature verification, or persistence fails
   */
  public synchronized AppCatalogSourceSnapshot addSource(String rawSource) throws IOException {
    return addSource(rawSource, null);
  }

  /**
   * Adds a catalog source only if its authenticated catalog id matches an expected id.
   *
   * <p>Recommended-catalog onboarding uses this overload to bind an operator action such as "add
   * the first-party beta catalog" to the catalog id that was actually signed. The source is still
   * fetched and signature-verified before the id comparison, and a mismatch is rejected before any
   * catalog bytes are persisted.
   *
   * @param rawSource operator-supplied source path or URI
   * @param expectedCatalogId expected signed catalog id, or {@code null} for no id constraint
   * @return stored source snapshot for the new catalog
   * @throws IOException if fetching, signature verification, id validation, or persistence fails
   */
  public synchronized AppCatalogSourceSnapshot addSource(String rawSource, String expectedCatalogId)
      throws IOException {
    return operations.addSource(rawSource, expectedCatalogId);
  }

  /**
   * Removes a configured catalog source.
   *
   * <p>Removal affects only the configured source and cached catalog sidecars. Apps already
   * installed from the catalog are left in AppHost and must be managed through app lifecycle APIs.
   *
   * @param catalogId catalog id to remove
   * @throws IOException if the source is missing or cannot be deleted
   */
  public synchronized void remove(String catalogId) throws IOException {
    sourceStore.remove(normalizeCatalogIdForLookup(catalogId));
  }

  /**
   * Refreshes one configured catalog source.
   *
   * <p>Refresh reuses the stored source URI and preserves the original local {@code addedAt}
   * timestamp. The newly fetched catalog must authenticate to the same normalized catalog id;
   * otherwise the refresh is rejected and the previous stored sidecars remain in place.
   *
   * @param catalogId catalog id to refresh
   * @return updated source snapshot after successful verification
   * @throws IOException if fetch, verification, or persistence fails
   */
  public synchronized AppCatalogSourceSnapshot refresh(String catalogId) throws IOException {
    return refresh(catalogId, false);
  }

  /**
   * Refreshes one catalog for urgent advisory propagation.
   *
   * <p>Emergency refresh uses the same primary-then-mirror ordering and verification gates as
   * ordinary refresh. It does not install, update, remove, or roll back apps.
   *
   * @param catalogId catalog id to refresh
   * @return updated source snapshot after successful verification
   * @throws IOException if all endpoints fail or only stale candidates are available
   */
  public synchronized AppCatalogSourceSnapshot emergencyRefresh(String catalogId)
      throws IOException {
    return refresh(catalogId, false);
  }

  /**
   * Refreshes only the primary endpoint, without mirror fallback.
   *
   * @param catalogId catalog id to refresh
   * @return updated source snapshot
   * @throws IOException if the primary source fails verification or persistence
   */
  public synchronized AppCatalogSourceSnapshot refreshPrimaryOnly(String catalogId)
      throws IOException {
    return refresh(catalogId, true);
  }

  private AppCatalogSourceSnapshot refresh(String catalogId, boolean primaryOnly)
      throws IOException {
    return refreshCoordinator.refresh(catalogId, primaryOnly);
  }

  /** Lists primary and mirror endpoints for one catalog. */
  public synchronized List<AppCatalogMirror> listMirrors(String catalogId) throws IOException {
    return operations.listMirrors(catalogId);
  }

  /** Lists endpoint health for one catalog. */
  public synchronized List<AppCatalogMirrorHealth> sourceHealth(String catalogId)
      throws IOException {
    return operations.sourceHealth(catalogId);
  }

  /** Adds one fallback mirror endpoint. */
  public synchronized AppCatalogMirror addMirror(
      String catalogId, String rawMirrorId, String rawSource, int priority, boolean enabled)
      throws IOException {
    return operations.addMirror(catalogId, rawMirrorId, rawSource, priority, enabled);
  }

  /** Updates local mirror metadata. */
  public synchronized AppCatalogMirror updateMirror(
      String catalogId, String mirrorId, String rawSource, Integer priority, Boolean enabled)
      throws IOException {
    return operations.updateMirror(catalogId, mirrorId, rawSource, priority, enabled);
  }

  /** Removes one mirror endpoint. */
  public synchronized void removeMirror(String catalogId, String mirrorId) throws IOException {
    operations.removeMirror(catalogId, mirrorId);
  }

  /** Lists retained rollback candidates for one catalog. */
  public synchronized List<AppCatalogRollbackCandidate> rollbackCandidates(String catalogId)
      throws IOException {
    return operations.rollbackCandidates(catalogId);
  }

  /** Reactivates a retained verified catalog revision. */
  public synchronized AppCatalogSourceSnapshot rollback(
      String catalogId, String revisionDigest, String reason) throws IOException {
    return operations.rollback(catalogId, revisionDigest, reason);
  }

  /** Returns signing-key rotation status for one catalog. */
  public synchronized AppCatalogKeyRotationStatus keyRotationStatus(String catalogId)
      throws IOException {
    return operations.keyRotationStatus(catalogId);
  }

  /**
   * Lists apps from a configured catalog.
   *
   * <p>The catalog is read and verified on each call. The result preserves {@code catalog.entries}
   * order so UI and API clients can display entries deterministically without re-sorting.
   *
   * @param catalogId catalog id to read
   * @return entries in catalog-declared deterministic order
   * @throws IOException if the catalog is missing or fails verification
   */
  public synchronized List<AppCatalogEntry> listApps(String catalogId) throws IOException {
    return readVerifiedCatalog(catalogId).entries();
  }

  /**
   * Returns the signed catalog security policy for one configured catalog.
   *
   * <p>The catalog is verified before the policy is exposed. The returned policy contains only
   * bounded advisory and exact denylist metadata and can be rendered through {@link
   * AppCatalogSecurityPolicy#toJsonValue()} for operator-facing summaries. It does not expose raw
   * catalog bytes, local source-store paths, catalog signatures, trusted-key material, fetched
   * content, or staged bundle paths.
   *
   * @param catalogId catalog id to read
   * @return authenticated catalog security policy
   * @throws IOException if catalog state cannot be read
   */
  public synchronized AppCatalogSecurityPolicy securityPolicy(String catalogId) throws IOException {
    return readVerifiedCatalog(catalogId).securityPolicy();
  }

  /**
   * Returns one catalog app entry.
   *
   * <p>The app id is normalized using the same rules as signed app manifests. Missing catalogs and
   * missing apps remain distinct error codes so API adapters can return stable {@code
   * catalog_not_found} or {@code app_not_found} responses.
   *
   * @param catalogId catalog id to read
   * @param appId app id to select
   * @return selected catalog entry
   * @throws IOException if catalog state cannot be read
   */
  public synchronized AppCatalogEntry getApp(String catalogId, String appId) throws IOException {
    return readVerifiedCatalog(catalogId)
        .entry(appId)
        .orElseThrow(
            () ->
                new AppCatalogException(
                    AppCatalogSidecars.APP_NOT_FOUND, "Catalog app not found."));
  }

  /**
   * Computes the signed catalog security decision for one catalog app entry.
   *
   * <p>The catalog is verified before the decision is derived. The returned value is path-free and
   * suitable for API, Web Shell, CLI, and release-certification summaries.
   *
   * @param catalogId catalog id to read
   * @param appId app id to evaluate
   * @return redacted security decision for the catalog entry
   * @throws IOException if catalog state cannot be read
   */
  public synchronized AppCatalogSecurityDecision securityDecision(String catalogId, String appId)
      throws IOException {
    AppCatalog catalog = readVerifiedCatalog(catalogId);
    AppCatalogEntry entry =
        catalog
            .entry(appId)
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.APP_NOT_FOUND, "Catalog app not found."));
    return catalog.securityPolicy().decisionFor(entry);
  }

  /**
   * Computes the strongest security decision for an installed app version across configured
   * catalogs.
   *
   * <p>Each catalog is verified before its exact-version denylist is considered. The method returns
   * an OK decision when no configured verified catalog denies or warns about the installed version.
   *
   * @param appId installed app id
   * @param version installed app version
   * @return strongest redacted security decision across configured catalogs
   * @throws IOException if catalog state cannot be listed or verified
   */
  public synchronized AppCatalogSecurityDecision installedSecurityDecision(
      String appId, String version) throws IOException {
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    List<AppCatalogSecurityDecision> decisions =
        sourceStore.list().stream()
            .map(stored -> verifyStoredCatalog(stored, trustedKeys))
            .map(
                catalog ->
                    catalog.securityPolicy().decisionForInstalledVersion(normalizedAppId, version))
            .toList();
    return AppCatalogSecurityDecision.combine(decisions);
  }

  /**
   * Downloads, extracts, and verifies one app bundle from a catalog.
   *
   * <p>The returned plan is the only output of the catalog install/update preparation path. The
   * method verifies the catalog entry, downloads the declared artifact, checks size and SHA-256,
   * extracts the ZIP safely, verifies the extracted signed bundle, and confirms manifest id/version
   * match the catalog. If any step fails, the per-operation scratch tree is removed before the
   * failure is rethrown.
   *
   * @param catalogId catalog id containing the app
   * @param appId catalog app id to prepare
   * @return temporary installation plan whose staged directory can be passed to AppHost
   * @throws IOException if catalog lookup, download, extraction, or bundle verification fails
   */
  public synchronized AppCatalogInstallPlan prepareInstallPlan(String catalogId, String appId)
      throws IOException {
    String normalizedCatalogId = normalizeCatalogIdForLookup(catalogId);
    AppCatalogEntry entry = getApp(normalizedCatalogId, appId);
    return installPlanner.prepareInstallPlan(normalizedCatalogId, entry);
  }

  /**
   * Re-verifies a retained installation plan before callers execute staged bundle code.
   *
   * <p>Prepared install plans are verified when they are created, but their scratch directories
   * remain mutable local filesystem state until the plan is applied or closed. Update flows that
   * run app-owned migration commands from the retained stage must call this method immediately
   * before execution so modified staged content is rejected before any process launch. The
   * verification uses the same trusted-key provider and signed-bundle checks as {@link
   * #prepareInstallPlan(String, String)}.
   *
   * @param plan retained installation plan to verify
   * @throws IOException if staged bundle verification or filesystem access fails
   */
  public synchronized void verifyInstallPlan(AppCatalogInstallPlan plan) throws IOException {
    installPlanner.verifyInstallPlan(plan);
  }

  /**
   * Returns whether the current trusted app/catalog key registry contains one key id.
   *
   * <p>Recommended-catalog onboarding uses this as a configuration check before attempting to add a
   * first-party source. It does not expose public key bytes or any trusted-key file paths, and it
   * does not change the verification path: adding or refreshing a catalog still verifies the signed
   * catalog against the full current registry.
   *
   * @param keyId stable catalog signing key id to check
   * @return {@code true} when the current registry contains {@code keyId}
   * @throws IOException if trusted-key configuration cannot be read
   */
  public synchronized boolean hasTrustedCatalogKey(String keyId) throws IOException {
    if (keyId == null || keyId.isBlank()) {
      return false;
    }
    return trustedKeyProvider.trustedKeys().find(keyId.trim()).isPresent();
  }

  private AppCatalog readVerifiedCatalog(String catalogId) throws IOException {
    StoredCatalogSource stored = sourceStore.read(normalizeCatalogIdForLookup(catalogId));
    return verifyStoredCatalog(stored, trustedKeyProvider.trustedKeys());
  }

  static AppCatalogSourceSnapshot snapshot(StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    AppCatalog catalog = verifyStoredCatalog(stored, trustedKeys);
    return AppCatalogSourceSnapshot.of(
        catalog,
        stored.source(),
        stored.addedAt(),
        stored.refreshedAt(),
        stored.refreshMetadata(),
        stored.fetchedCatalog());
  }

  static AppCatalog verifyStoredCatalog(StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    return AppCatalogVerifier.verify(
        stored.fetchedCatalog().catalogBytes(),
        stored.fetchedCatalog().signatureBytes(),
        trustedKeys);
  }

  static String normalizeCatalogIdForLookup(String catalogId) {
    try {
      return AppCatalog.normalizeCatalogId(catalogId);
    } catch (AppCatalogException _) {
      throw new AppCatalogException(AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found.");
    }
  }

  /**
   * Supplies the trusted keys used for catalog and bundle verification.
   *
   * <p>Runtime wiring can reload key files on each operation by implementing this provider as a
   * small adapter over the same trusted-key configuration used by AppHost bundle verification.
   * Implementations should be side-effect-light because the manager calls them while holding its
   * monitor.
   */
  @FunctionalInterface
  public interface TrustedKeyProvider {
    /**
     * Returns the current trusted app/catalog keys.
     *
     * <p>The returned registry is used for both catalog signature verification and extracted bundle
     * verification. Returning an empty or stale registry makes signed catalog operations fail
     * closed.
     *
     * @return immutable trusted-key registry
     * @throws IOException if key material cannot be loaded from runtime configuration
     */
    TrustedAppKeys trustedKeys() throws IOException;
  }
}
