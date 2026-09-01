package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.Objects;

/**
 * Owns the shared collaborators and mutation fence used by the catalog manager layers.
 *
 * <p>The public {@link AppCatalogManager} facade delegates its source, install, and federation
 * responsibilities to package-scoped superclass layers. This base class centralizes their common
 * state so every inherited operation uses the same source store, trust providers, and authorization
 * coordinator. The coordinator always receives the concrete manager instance as its monitor; source
 * and trust mutations therefore retain the established lock order without exposing the
 * implementation layers as separate runtime services.
 *
 * <p>Instances are immutable after construction. The referenced stores and collaborators retain
 * their own documented persistence and synchronization behavior.
 */
abstract class AppCatalogManagerState {
  /** Persistent configured-source and retained-revision storage shared by every manager layer. */
  final AppCatalogSourceStore sourceStore;

  /** Reloadable catalog-signing trust provider used for each verification operation. */
  final AppCatalogManager.TrustedKeyProvider trustedCatalogKeyProvider;

  /** Bounded authenticated review log exposed through the public manager facade. */
  final AppReviewTransparencyLog reviewTransparencyLog;

  /** Verified catalog projection and operator metadata collaborator. */
  final AppCatalogOperations operations;

  /** Primary and mirror refresh workflow coordinator. */
  final AppCatalogRefreshCoordinator refreshCoordinator;

  /** Artifact download, extraction, and bundle verification coordinator. */
  final AppCatalogInstallPlanner installPlanner;

  /** Optional host-owned exact catalog trust authority for federation mode. */
  final FileFederatedCatalogTrustStore federatedTrustStore;

  /** Optional pending public discovery evidence store. */
  final FilePendingCatalogDiscoveryStore pendingDiscoveryStore;

  /** Optional reloadable key provider for discovery document issuers. */
  final AppCatalogManager.TrustedKeyProvider discoveryIssuerKeyProvider;

  /** Shared origin authority and read/write mutation fence. */
  final AppCatalogAuthorizationCoordinator authorizationCoordinator;

  /**
   * Assembles the collaborators shared by the specialized manager layers.
   *
   * <p>Nullable federation and discovery services select explicit compatibility modes. All core
   * source, key, bundle-policy, and pipeline dependencies are required. Construction performs no
   * network fetch or trust-store mutation.
   *
   * @param sourceStore configured-source and retained-revision storage
   * @param trustedCatalogKeyProvider reloadable catalog-signing trust provider
   * @param bundleVerificationPolicy extracted app-bundle authorization policy
   * @param dependencies transport, extraction, and transparency-log collaborators
   * @param federatedTrustStore optional local catalog trust authority
   * @param pendingDiscoveryStore optional pending discovery evidence store
   * @param discoveryIssuerKeyProvider optional discovery issuer trust provider
   */
  AppCatalogManagerState(
      AppCatalogSourceStore sourceStore,
      AppCatalogManager.TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      AppCatalogManagerDependencies dependencies,
      FileFederatedCatalogTrustStore federatedTrustStore,
      FilePendingCatalogDiscoveryStore pendingDiscoveryStore,
      AppCatalogManager.TrustedKeyProvider discoveryIssuerKeyProvider) {
    this.sourceStore = Objects.requireNonNull(sourceStore, "sourceStore");
    this.trustedCatalogKeyProvider =
        Objects.requireNonNull(trustedCatalogKeyProvider, "trustedCatalogKeyProvider");
    AppCatalogBundleVerificationPolicy checkedBundleVerificationPolicy =
        Objects.requireNonNull(bundleVerificationPolicy, "bundleVerificationPolicy");
    AppCatalogManagerDependencies checkedDependencies =
        Objects.requireNonNull(dependencies, "dependencies");
    this.reviewTransparencyLog = checkedDependencies.reviewTransparencyLog();
    this.federatedTrustStore = federatedTrustStore;
    this.pendingDiscoveryStore = pendingDiscoveryStore;
    this.discoveryIssuerKeyProvider = discoveryIssuerKeyProvider;
    this.authorizationCoordinator =
        new AppCatalogAuthorizationCoordinator(
            this.sourceStore, this.trustedCatalogKeyProvider, federatedTrustStore);
    this.operations =
        new AppCatalogOperations(
            this.sourceStore,
            this.trustedCatalogKeyProvider,
            checkedDependencies.fetcher(),
            federatedTrustStore);
    this.refreshCoordinator =
        new AppCatalogRefreshCoordinator(
            this.sourceStore,
            this.trustedCatalogKeyProvider,
            checkedDependencies.fetcher(),
            this.operations,
            federatedTrustStore);
    this.installPlanner =
        new AppCatalogInstallPlanner(
            this.sourceStore,
            checkedBundleVerificationPolicy,
            checkedDependencies.artifactDownloader(),
            checkedDependencies.bundleExtractor());
  }

  /**
   * Runs one source or trust mutation under the shared exclusive fence.
   *
   * @param mutation operation entered after the fence and manager monitor are acquired
   * @param <T> exact operation result type
   * @return value returned by the guarded operation
   * @throws IOException if the guarded operation cannot read or persist state
   */
  final <T> T withCatalogMutationLock(AppCatalogAuthorizationCoordinator.IoOperation<T> mutation)
      throws IOException {
    return authorizationCoordinator.withMutationLock(this, mutation);
  }
}
