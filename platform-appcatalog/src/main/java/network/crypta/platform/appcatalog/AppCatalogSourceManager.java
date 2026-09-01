package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.List;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Implements configured-source lifecycle operations for {@link AppCatalogManager}.
 *
 * <p>This layer owns catalog enumeration, addition, removal, refresh, and bounded source inventory.
 * Legacy mode preserves its existing all-or-nothing verification behavior. Federation mode asks
 * {@link AppCatalogOperations} to isolate source-local trust or persistence failures so one
 * unavailable catalog does not disable unrelated active catalogs. Every mutation enters the shared
 * catalog mutation fence before it changes source-store state.
 *
 * <p>The class is package-scoped because callers use the inherited methods through the public
 * manager facade. It does not create a second catalog authority or expose stored sidecar bytes.
 * Reads return fresh verified projections rather than a long-lived catalog cache, while mutations
 * preserve the manager's lock order across network-independent trust and persistence checks.
 */
abstract class AppCatalogSourceManager extends AppCatalogManagerState {
  /**
   * Initializes source lifecycle handling over the shared manager state.
   *
   * @param sourceStore configured catalog source storage
   * @param trustedCatalogKeyProvider reloadable catalog-signing trust provider
   * @param bundleVerificationPolicy extracted app-bundle authorization policy
   * @param dependencies catalog pipeline collaborators
   * @param federatedTrustStore optional local catalog trust authority
   * @param pendingDiscoveryStore optional pending discovery store
   * @param discoveryIssuerKeyProvider optional discovery issuer trust provider
   */
  AppCatalogSourceManager(
      AppCatalogSourceStore sourceStore,
      AppCatalogManager.TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      AppCatalogManagerDependencies dependencies,
      FileFederatedCatalogTrustStore federatedTrustStore,
      FilePendingCatalogDiscoveryStore pendingDiscoveryStore,
      AppCatalogManager.TrustedKeyProvider discoveryIssuerKeyProvider) {
    super(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        dependencies,
        federatedTrustStore,
        pendingDiscoveryStore,
        discoveryIssuerKeyProvider);
  }

  /**
   * Lists configured catalogs after re-verifying their stored signed sidecars.
   *
   * <p>Federation mode omits source-local failures so an unauthorized or corrupt catalog does not
   * disable unrelated catalogs. Legacy mode preserves the existing all-or-nothing behavior.
   *
   * @return verified snapshots sorted by normalized catalog identity
   * @throws IOException if the source-store root cannot be enumerated
   */
  public synchronized List<AppCatalogSourceSnapshot> listCatalogs() throws IOException {
    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    if (federatedTrustStore != null) {
      return operations.listFederatedRoutineCatalogs(trustedKeys);
    }
    return sourceStore.list().stream()
        .map(stored -> operations.snapshot(stored, trustedKeys))
        .sorted(java.util.Comparator.comparing(AppCatalogSourceSnapshot::catalogId))
        .toList();
  }

  /**
   * Lists catalogs currently authorized for refresh, install, and update work.
   *
   * @return routine-authorized catalog snapshots in deterministic order
   * @throws IOException if the source-store root cannot be enumerated
   */
  public synchronized List<AppCatalogSourceSnapshot> listRoutineCatalogs() throws IOException {
    return listCatalogs();
  }

  /**
   * Lists persisted source identities without treating them as authenticated routine catalogs.
   *
   * @return normalized configured catalog IDs in deterministic order
   * @throws IOException if confined source metadata cannot be enumerated
   */
  public synchronized List<String> configuredCatalogIds() throws IOException {
    return sourceStore.configuredCatalogIds();
  }

  /**
   * Reads and verifies one configured catalog for bounded operator inspection.
   *
   * @param catalogId catalog identity to normalize and inspect
   * @return verified snapshot for the requested catalog only
   * @throws IOException if its source or trust state cannot be read
   */
  public synchronized AppCatalogSourceSnapshot catalog(String catalogId) throws IOException {
    return operations.catalogSnapshot(
        AppCatalogManager.normalizeCatalogIdForLookup(catalogId),
        trustedCatalogKeyProvider.trustedKeys());
  }

  /**
   * Adds a legacy source after fetching and authenticating its signed catalog.
   *
   * @param rawSource operator-supplied source path or URI
   * @return persisted verified source snapshot
   * @throws IOException if fetching, verification, or persistence fails
   */
  public AppCatalogSourceSnapshot addSource(String rawSource) throws IOException {
    return addSource(rawSource, null);
  }

  /**
   * Adds a source only when its authenticated identity matches the expected catalog.
   *
   * @param rawSource operator-supplied source path or URI
   * @param expectedCatalogId required signed catalog identity, or {@code null} in legacy mode
   * @return persisted verified source snapshot
   * @throws IOException if fetching, identity verification, or persistence fails
   */
  public AppCatalogSourceSnapshot addSource(String rawSource, String expectedCatalogId)
      throws IOException {
    return withCatalogMutationLock(() -> operations.addSource(rawSource, expectedCatalogId));
  }

  /**
   * Removes one configured source without uninstalling apps previously obtained from it.
   *
   * @param catalogId catalog source identity to remove
   * @throws IOException if the source is missing or cannot be deleted safely
   */
  public void remove(String catalogId) throws IOException {
    withCatalogMutationLock(
        () -> {
          sourceStore.remove(AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
          return null;
        });
  }

  /**
   * Refreshes one source through its primary endpoint and eligible mirrors.
   *
   * @param catalogId configured catalog identity
   * @return newly authenticated and persisted source snapshot
   * @throws IOException if no endpoint yields an acceptable revision
   */
  public AppCatalogSourceSnapshot refresh(String catalogId) throws IOException {
    return withCatalogMutationLock(() -> refresh(catalogId, false));
  }

  /**
   * Refreshes one source for urgent advisory propagation using normal verification gates.
   *
   * @param catalogId configured catalog identity
   * @return newly authenticated and persisted source snapshot
   * @throws IOException if no endpoint yields an acceptable revision
   */
  public AppCatalogSourceSnapshot emergencyRefresh(String catalogId) throws IOException {
    return withCatalogMutationLock(() -> refresh(catalogId, false));
  }

  /**
   * Refreshes one configured source without attempting mirror fallback.
   *
   * @param catalogId configured catalog identity
   * @return newly authenticated and persisted primary-source snapshot
   * @throws IOException if the primary source cannot be accepted
   */
  public AppCatalogSourceSnapshot refreshPrimaryOnly(String catalogId) throws IOException {
    return withCatalogMutationLock(() -> refresh(catalogId, true));
  }

  /**
   * Delegates one fenced refresh to the shared refresh coordinator.
   *
   * @param catalogId configured catalog identity
   * @param primaryOnly whether mirror fallback must remain disabled
   * @return newly authenticated and persisted source snapshot
   * @throws IOException if no permitted endpoint yields an acceptable revision
   */
  private AppCatalogSourceSnapshot refresh(String catalogId, boolean primaryOnly)
      throws IOException {
    return refreshCoordinator.refresh(catalogId, primaryOnly);
  }

  /**
   * Tests whether the current catalog-signing registry contains an active key identity.
   *
   * @param keyId exact public key identifier to inspect
   * @return {@code true} only when the key is active for verification
   * @throws IOException if catalog-signing trust cannot be loaded
   */
  public synchronized boolean hasTrustedCatalogKey(String keyId) throws IOException {
    return operations.hasTrustedCatalogKey(keyId);
  }
}
