package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Coordinates catalog mutations with exact current and historical origin authorization.
 *
 * <p>This package-private component keeps the catalog manager focused on source and application
 * orchestration. It combines the origin-specific verification performed by {@link
 * AppCatalogOriginAuthority} with the read/write fence that prevents catalog mutations from
 * invalidating an authorization while AppHost commits a bundle change. Callers supply the catalog
 * manager monitor for each fenced operation, which preserves the established lock order: acquire
 * the federation fence first, then enter the manager monitor.
 *
 * <p>Mutation operations hold the exclusive fence until their source or trust-store work is
 * complete. Install and rollback authorization operations retain the shared fence in the returned
 * same-thread lease. Closing that lease allows pending trust transitions, refreshes, removals, and
 * rollbacks to proceed.
 */
final class AppCatalogAuthorizationCoordinator {
  /** Resolves exact current and retained catalog provenance. */
  private final AppCatalogOriginAuthority originAuthority;

  /** Prevents catalog mutations from invalidating an authorization retained through host commit. */
  private final CatalogMutationFence mutationFence = new CatalogMutationFence();

  /**
   * Creates one coordinator for a catalog source store and its current signing-key authority.
   *
   * @param sourceStore current and retained signed catalog persistence
   * @param trustedCatalogKeyProvider current catalog-signing key provider
   * @param federatedTrustStore optional local catalog trust-binding authority
   */
  AppCatalogAuthorizationCoordinator(
      AppCatalogSourceStore sourceStore,
      AppCatalogManager.TrustedKeyProvider trustedCatalogKeyProvider,
      FileFederatedCatalogTrustStore federatedTrustStore) {
    this.originAuthority =
        new AppCatalogOriginAuthority(
            Objects.requireNonNull(sourceStore, "sourceStore"),
            Objects.requireNonNull(trustedCatalogKeyProvider, "trustedCatalogKeyProvider"),
            federatedTrustStore);
  }

  /**
   * Authenticates the current stored revision and returns its exact origin context.
   *
   * @param normalizedCatalogId normalized catalog identity to authenticate
   * @return signer, revision, and local-policy provenance for the current source
   * @throws IOException if source, key, or local trust state cannot be read
   */
  AppCatalogOriginContext originContext(String normalizedCatalogId) throws IOException {
    return originAuthority.originContext(normalizedCatalogId);
  }

  /**
   * Builds an origin from a source already authenticated with the supplied key snapshot.
   *
   * @param stored exact stored source used for catalog verification
   * @param trustedKeys key snapshot used for the same catalog verification
   * @return exact legacy or federation-scoped catalog provenance
   * @throws IOException if local federation policy cannot be read
   */
  AppCatalogOriginContext originContext(StoredCatalogSource stored, TrustedAppKeys trustedKeys)
      throws IOException {
    return originAuthority.originContext(stored, trustedKeys);
  }

  /**
   * Reauthorizes an exact installed origin under current historical catalog policy.
   *
   * @param captured exact catalog authority retained with installed provenance
   * @param appId exact app namespace to restore
   * @param appVersion exact historical app version to restore
   * @param bundleSha256 exact retained bundle digest to restore
   * @return authenticated catalog entry matching every retained subject
   * @throws IOException if historical source or trust state cannot be read
   */
  AppCatalogEntry authorizeHistoricalAppOrigin(
      AppCatalogOriginContext captured, String appId, String appVersion, String bundleSha256)
      throws IOException {
    return originAuthority.authorizeHistoricalAppOrigin(captured, appId, appVersion, bundleSha256);
  }

  /**
   * Reauthorizes an exact historical origin and retains the read fence through host rollback.
   *
   * @param managerMonitor catalog manager monitor entered after the read fence
   * @param captured exact catalog authority retained with installed provenance
   * @param appId exact app namespace to restore
   * @param appVersion exact historical app version to restore
   * @param bundleSha256 exact retained bundle digest to restore
   * @return historical entry and same-thread authorization lease
   * @throws IOException if current historical policy no longer authorizes the origin
   */
  AppCatalogManager.HistoricalAppOriginAuthorization authorizeHistoricalAppOriginForRollback(
      Object managerMonitor,
      AppCatalogOriginContext captured,
      String appId,
      String appVersion,
      String bundleSha256)
      throws IOException {
    CatalogMutationFence.Authorized<AppCatalogEntry> authorized =
        mutationFence.authorizeRead(
            () ->
                synchronizedOperation(
                    managerMonitor,
                    () ->
                        originAuthority.authorizeHistoricalAppOrigin(
                            captured, appId, appVersion, bundleSha256)));
    return new AppCatalogManager.HistoricalAppOriginAuthorization(
        authorized.value(), authorized.authorization());
  }

  /**
   * Runs an exact current-plan check and retains its catalog authorization through host commit.
   *
   * @param managerMonitor catalog manager monitor entered after the read fence
   * @param operation current-plan verification performed under both locks
   * @return same-thread lease that releases the retained read fence
   * @throws IOException if the plan or current catalog policy cannot be verified
   */
  AppCatalogManager.CatalogTrustAuthorization retainAuthorization(
      Object managerMonitor, IoOperation<?> operation) throws IOException {
    return mutationFence
        .authorizeRead(() -> synchronizedOperation(managerMonitor, operation))
        .authorization();
  }

  /**
   * Runs one catalog or trust mutation under the exclusive fence and manager monitor.
   *
   * @param managerMonitor catalog manager monitor entered after the write fence
   * @param operation source or trust mutation to perform
   * @param <T> mutation result type
   * @return exact result produced by the mutation
   * @throws IOException if catalog persistence or verification fails
   */
  <T> T withMutationLock(Object managerMonitor, IoOperation<T> operation) throws IOException {
    return mutationFence.withWriteLock(
        () ->
            synchronizedOperation(managerMonitor, Objects.requireNonNull(operation, "operation")));
  }

  /**
   * Enters the supplied manager monitor after the caller owns the appropriate fence side.
   *
   * @param managerMonitor catalog manager monitor entered after the federation fence
   * @param operation catalog operation to execute while both locks remain held
   * @param <T> operation result type
   * @return exact result produced by the synchronized operation
   * @throws IOException if catalog persistence or verification fails
   */
  private static <T> T synchronizedOperation(Object managerMonitor, IoOperation<T> operation)
      throws IOException {
    synchronized (Objects.requireNonNull(managerMonitor, "managerMonitor")) {
      return Objects.requireNonNull(operation, "operation").run();
    }
  }

  /**
   * One catalog operation that may propagate a filesystem or trust-store failure.
   *
   * @param <T> operation result type
   */
  @FunctionalInterface
  interface IoOperation<T> {
    /**
     * Performs the operation while the coordinator owns the required fence and manager monitor.
     *
     * @return operation result transferred to the caller
     * @throws IOException if catalog persistence or verification fails
     */
    T run() throws IOException;
  }
}
