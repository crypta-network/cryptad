package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.List;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Projects verified catalog contents and operator metadata through the manager facade.
 *
 * <p>This layer contains read and administration methods for mirrors, retained revisions, signing
 * key rotation, catalog entries, and signed security policy. Mutation methods retain the shared
 * write fence, while reads reuse the same verified {@link AppCatalogOperations} collaborator as
 * source lifecycle work. Federation security aggregation considers only catalogs that remain
 * authorized for active routine work.
 *
 * <p>Returned objects are bounded projections. This class does not expose source URIs beyond the
 * existing mirror model, raw signed catalog bodies, signature bytes, or private key material. The
 * layer owns no independent cache or lock: inherited state and the shared mutation fence keep its
 * view consistent with source additions, refreshes, trust transitions, and removals.
 */
abstract class AppCatalogOperationsManager extends AppCatalogSourceManager {
  /**
   * Initializes verified catalog projections over the shared source lifecycle state.
   *
   * @param sourceStore configured catalog source storage
   * @param trustedCatalogKeyProvider reloadable catalog-signing trust provider
   * @param bundleVerificationPolicy extracted app-bundle authorization policy
   * @param dependencies catalog pipeline collaborators
   * @param federatedTrustStore optional local catalog trust authority
   * @param pendingDiscoveryStore optional pending discovery store
   * @param discoveryIssuerKeyProvider optional discovery issuer trust provider
   */
  AppCatalogOperationsManager(
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
   * Lists the primary endpoint and configured mirrors for one catalog.
   *
   * @param catalogId configured catalog identity
   * @return bounded endpoint metadata in persisted order
   * @throws IOException if source metadata cannot be read safely
   */
  public synchronized List<AppCatalogMirror> listMirrors(String catalogId) throws IOException {
    return operations.listMirrors(catalogId);
  }

  /**
   * Computes authenticated endpoint health for one configured catalog.
   *
   * @param catalogId configured catalog identity
   * @return bounded primary and mirror health summaries
   * @throws IOException if catalog or endpoint state cannot be read
   */
  public synchronized List<AppCatalogMirrorHealth> sourceHealth(String catalogId)
      throws IOException {
    return operations.sourceHealth(catalogId);
  }

  /**
   * Adds one fallback endpoint under the catalog mutation fence.
   *
   * @param catalogId configured catalog identity
   * @param rawMirrorId operator-supplied mirror identity
   * @param rawSource operator-supplied mirror source URI
   * @param priority local mirror priority
   * @param enabled whether refresh may use the endpoint
   * @return persisted normalized mirror metadata
   * @throws IOException if metadata cannot be validated or persisted
   */
  public AppCatalogMirror addMirror(
      String catalogId, String rawMirrorId, String rawSource, int priority, boolean enabled)
      throws IOException {
    return withCatalogMutationLock(
        () -> operations.addMirror(catalogId, rawMirrorId, rawSource, priority, enabled));
  }

  /**
   * Updates mutable local metadata for one configured mirror.
   *
   * @param catalogId configured catalog identity
   * @param mirrorId configured mirror identity
   * @param rawSource replacement source URI, or {@code null} to retain it
   * @param priority replacement priority, or {@code null} to retain it
   * @param enabled replacement enabled state, or {@code null} to retain it
   * @return persisted normalized mirror metadata
   * @throws IOException if metadata cannot be validated or persisted
   */
  public AppCatalogMirror updateMirror(
      String catalogId, String mirrorId, String rawSource, Integer priority, Boolean enabled)
      throws IOException {
    return withCatalogMutationLock(
        () -> operations.updateMirror(catalogId, mirrorId, rawSource, priority, enabled));
  }

  /**
   * Removes one fallback endpoint without changing catalog trust.
   *
   * @param catalogId configured catalog identity
   * @param mirrorId configured mirror identity
   * @throws IOException if mirror metadata cannot be updated safely
   */
  public void removeMirror(String catalogId, String mirrorId) throws IOException {
    withCatalogMutationLock(
        () -> {
          operations.removeMirror(catalogId, mirrorId);
          return null;
        });
  }

  /**
   * Lists retained signed catalog revisions eligible for explicit rollback.
   *
   * @param catalogId configured catalog identity
   * @return bounded authenticated rollback candidates
   * @throws IOException if retained revision state cannot be inspected
   */
  public synchronized List<AppCatalogRollbackCandidate> rollbackCandidates(String catalogId)
      throws IOException {
    return operations.rollbackCandidates(catalogId);
  }

  /**
   * Reactivates one exact retained signed catalog revision.
   *
   * @param catalogId configured catalog identity
   * @param revisionDigest exact retained revision digest
   * @param reason bounded operator audit reason
   * @return verified snapshot of the reactivated revision
   * @throws IOException if historical authorization or persistence fails
   */
  public AppCatalogSourceSnapshot rollback(String catalogId, String revisionDigest, String reason)
      throws IOException {
    return withCatalogMutationLock(() -> operations.rollback(catalogId, revisionDigest, reason));
  }

  /**
   * Reports bounded signing-key rotation state for one catalog.
   *
   * @param catalogId configured catalog identity
   * @return authenticated key-rotation status without key bytes
   * @throws IOException if current or retained state cannot be verified
   */
  public synchronized AppCatalogKeyRotationStatus keyRotationStatus(String catalogId)
      throws IOException {
    return operations.keyRotationStatus(catalogId);
  }

  /**
   * Lists signed app entries from one verified configured catalog.
   *
   * @param catalogId configured catalog identity
   * @return entries in signed catalog order
   * @throws IOException if catalog state cannot be read or verified
   */
  public synchronized List<AppCatalogEntry> listApps(String catalogId) throws IOException {
    return operations.listApps(AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
  }

  /**
   * Lists app entries currently authorized for routine install and update selection.
   *
   * <p>Historical inspection may expose signed entries outside a federated binding's channel scope.
   * This projection instead requires current routine catalog authorization and omits those entries
   * without treating unrelated allowed entries as untrusted.
   *
   * @param catalogId configured catalog identity
   * @return entries authorized by the current catalog binding and its allowed channels
   * @throws IOException if catalog or trust state cannot be read or verified
   */
  public synchronized List<AppCatalogEntry> listRoutineApps(String catalogId) throws IOException {
    return operations.listRoutineApps(AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
  }

  /**
   * Returns the authenticated signed security policy for one catalog.
   *
   * @param catalogId configured catalog identity
   * @return bounded catalog security policy projection
   * @throws IOException if catalog state cannot be read or verified
   */
  public synchronized AppCatalogSecurityPolicy securityPolicy(String catalogId) throws IOException {
    return operations
        .readVerifiedCatalog(
            AppCatalogManager.normalizeCatalogIdForLookup(catalogId),
            trustedCatalogKeyProvider.trustedKeys())
        .securityPolicy();
  }

  /**
   * Selects one signed app entry from a verified catalog.
   *
   * @param catalogId configured catalog identity
   * @param appId normalized app namespace to select
   * @return exact authenticated catalog entry
   * @throws IOException if catalog state cannot be read or verified
   */
  public synchronized AppCatalogEntry getApp(String catalogId, String appId) throws IOException {
    return operations.getApp(AppCatalogManager.normalizeCatalogIdForLookup(catalogId), appId);
  }

  /**
   * Computes one catalog-local signed security decision for an app entry.
   *
   * @param catalogId configured catalog identity
   * @param appId normalized app namespace to evaluate
   * @return bounded authenticated security decision
   * @throws IOException if catalog state cannot be read or verified
   */
  public synchronized AppCatalogSecurityDecision securityDecision(String catalogId, String appId)
      throws IOException {
    return operations.securityDecision(
        AppCatalogManager.normalizeCatalogIdForLookup(catalogId), appId);
  }

  /**
   * Combines applicable signed security decisions for an installed app version.
   *
   * @param appId installed app namespace
   * @param version exact installed app version
   * @return strongest authenticated decision from eligible catalogs
   * @throws IOException if configured catalog state cannot be enumerated
   */
  public synchronized AppCatalogSecurityDecision installedSecurityDecision(
      String appId, String version) throws IOException {
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    List<AppCatalogSecurityDecision> decisions =
        federatedTrustStore == null
            ? sourceStore.list().stream()
                .map(stored -> operations.verifyStoredCatalog(stored, trustedKeys))
                .map(
                    catalog ->
                        catalog
                            .securityPolicy()
                            .decisionForInstalledVersion(normalizedAppId, version))
                .toList()
            : operations.installedFederatedSecurityDecisions(normalizedAppId, version, trustedKeys);
    return AppCatalogSecurityDecision.combine(decisions);
  }
}
