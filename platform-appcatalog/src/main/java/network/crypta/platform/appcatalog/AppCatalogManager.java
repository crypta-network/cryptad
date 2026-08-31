package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Coordinates signed catalog sources, refreshes, artifact staging, and bundle verification.
 *
 * <p>The public facade preserves one entry point for runtime composition and Platform API callers.
 * Specialized package-scoped manager layers implement source lifecycle, verified catalog
 * projections, install and origin handling, and local federation administration. All layers share
 * one source store and one authorization coordinator, so inherited operations retain the original
 * synchronization monitor and catalog mutation fence.
 *
 * <p>The manager owns no global state. It reloads role-specific trusted keys for each operation,
 * verifies stored sidecars before selecting entries, and stops install/update preparation at {@link
 * AppCatalogInstallPlan}. AppHost remains responsible for the final coordinated bundle and
 * provenance mutation.
 */
public final class AppCatalogManager extends AppCatalogInstallManager {
  private static final String FEDERATED_TRUST_STORE_PARAMETER = "federatedTrustStore";

  /** Same-thread lease retaining exact catalog trust authorization through host mutation. */
  @FunctionalInterface
  public interface CatalogTrustAuthorization extends AutoCloseable {
    /** Releases the retained catalog trust decision. */
    @Override
    void close();
  }

  /** Exact catalog revision referenced by one host-owned current or rollback provenance slot. */
  public record OriginRevision(
      String catalogId,
      String catalogContentDigestSha256,
      String catalogSignerKeyId,
      String appId) {
    /** Normalizes the public identities used to resolve one retained signed revision. */
    public OriginRevision {
      catalogId = AppCatalog.normalizeCatalogId(catalogId);
      Objects.requireNonNull(catalogContentDigestSha256, "catalogContentDigestSha256");
      if (!AppCatalogRevisions.digestDirectoryName("sha256:" + catalogContentDigestSha256)
          .equals(catalogContentDigestSha256)) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE,
            "catalogContentDigestSha256 must be a lowercase sha256 digest");
      }
      catalogSignerKeyId =
          AppCatalogSidecars.requireNonBlankSingleLine(
              catalogSignerKeyId, "catalogSignerKeyId", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
      appId = AppCatalogEntry.normalizeAppId(appId);
    }
  }

  /** Exact historical catalog entry plus trust authorization retained through rollback commit. */
  public record HistoricalAppOriginAuthorization(
      AppCatalogEntry entry, CatalogTrustAuthorization authorization) {
    public HistoricalAppOriginAuthorization {
      Objects.requireNonNull(entry, "entry");
      Objects.requireNonNull(authorization, "authorization");
    }
  }

  /** Current non-authoritative status of one retained pending discovery recommendation. */
  public record PendingCatalogDiscoveryEvidence(
      PendingCatalogDiscoveryRecommendation recommendation,
      boolean descriptorActive,
      List<CatalogEndorsementVerification> endorsements) {
    /** Validates and defensively copies current local display evidence. */
    public PendingCatalogDiscoveryEvidence {
      Objects.requireNonNull(recommendation, "recommendation");
      endorsements = List.copyOf(Objects.requireNonNull(endorsements, "endorsements"));
    }
  }

  /**
   * Creates a manager whose catalog and app-bundle signatures use one compatibility registry.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app and catalog keys
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore, TrustedKeyProvider trustedKeyProvider) {
    this(sourceStore, trustedKeyProvider, trustedKeyProvider);
  }

  /**
   * Creates a manager with role-specific catalog and app-bundle trust providers.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedCatalogKeyProvider provider for trusted catalog-signing keys
   * @param trustedBundleKeyProvider provider for trusted app-bundle-signing keys
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      TrustedKeyProvider trustedBundleKeyProvider) {
    this(
        sourceStore,
        trustedCatalogKeyProvider,
        AppCatalogBundleVerificationPolicy.fromTrustedKeys(trustedBundleKeyProvider),
        AppCatalogManagerDependencies.defaults(sourceStore));
  }

  /**
   * Creates a manager with catalog authority trust and an explicit app-bundle policy.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedCatalogKeyProvider provider for catalog-signing trust
   * @param bundleVerificationPolicy app-publisher authorization for extracted bundles
   * @return manager using the explicit bundle policy
   */
  public static AppCatalogManager withBundleVerificationPolicy(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy) {
    return new AppCatalogManager(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        AppCatalogManagerDependencies.defaults(sourceStore));
  }

  /**
   * Creates a compatibility manager with Crypta content transport.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for trusted app and catalog keys
   * @param contentFetchPort runtime content fetch port for {@code crypta:} sources
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedKeyProvider,
      ContentFetchPort contentFetchPort) {
    this(sourceStore, trustedKeyProvider, trustedKeyProvider, contentFetchPort);
  }

  /**
   * Creates a manager with role-specific trust and Crypta content transport.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedCatalogKeyProvider provider for trusted catalog-signing keys
   * @param trustedBundleKeyProvider provider for trusted app-bundle-signing keys
   * @param contentFetchPort runtime content fetch port for {@code crypta:} sources
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      TrustedKeyProvider trustedBundleKeyProvider,
      ContentFetchPort contentFetchPort) {
    this(
        sourceStore,
        trustedCatalogKeyProvider,
        AppCatalogBundleVerificationPolicy.fromTrustedKeys(trustedBundleKeyProvider),
        AppCatalogManagerDependencies.withContentFetchPort(sourceStore, contentFetchPort));
  }

  /**
   * Creates a manager with explicit bundle authorization and Crypta content transport.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedCatalogKeyProvider provider for catalog-signing trust
   * @param bundleVerificationPolicy app-publisher authorization for extracted bundles
   * @param contentFetchPort runtime content transport for {@code crypta:} sources
   * @return manager using the explicit bundle policy and content transport
   */
  public static AppCatalogManager withBundleVerificationPolicy(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      ContentFetchPort contentFetchPort) {
    return new AppCatalogManager(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        AppCatalogManagerDependencies.withContentFetchPort(sourceStore, contentFetchPort));
  }

  /**
   * Creates a manager with explicit pipeline dependencies for controlled embeddings and tests.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for trusted app and catalog keys
   * @param dependencies fetch, download, extraction, and transparency-log dependencies
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedKeyProvider,
      AppCatalogManagerDependencies dependencies) {
    this(
        sourceStore,
        trustedKeyProvider,
        AppCatalogBundleVerificationPolicy.fromTrustedKeys(trustedKeyProvider),
        dependencies);
  }

  private AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      AppCatalogManagerDependencies dependencies) {
    this(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        dependencies,
        null,
        null,
        null);
  }

  private AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      AppCatalogManagerDependencies dependencies,
      FileFederatedCatalogTrustStore federatedTrustStore,
      FilePendingCatalogDiscoveryStore pendingDiscoveryStore,
      TrustedKeyProvider discoveryIssuerKeyProvider) {
    super(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        dependencies,
        federatedTrustStore,
        pendingDiscoveryStore,
        discoveryIssuerKeyProvider);
  }

  /** Creates a manager whose catalog operations require exact local catalog trust bindings. */
  public static AppCatalogManager withFederatedTrustPolicy(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      FileFederatedCatalogTrustStore federatedTrustStore) {
    return new AppCatalogManager(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        AppCatalogManagerDependencies.defaults(sourceStore),
        Objects.requireNonNull(federatedTrustStore, FEDERATED_TRUST_STORE_PARAMETER),
        null,
        null);
  }

  /**
   * Creates a federation-scoped manager with local pending-discovery persistence.
   *
   * @param sourceStore file-backed configured catalog source store
   * @param trustedCatalogKeyProvider provider for catalog-signing trust
   * @param bundleVerificationPolicy catalog/app-scoped bundle authorization
   * @param federatedTrustStore host-owned exact catalog trust bindings
   * @param pendingDiscoveryStore host-owned pending public discovery evidence
   * @param discoveryIssuerKeyProvider locally configured public discovery issuer keys
   * @return manager with federated routine work and pending discovery enabled
   */
  public static AppCatalogManager withFederatedTrustAndDiscoveryPolicy(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      FileFederatedCatalogTrustStore federatedTrustStore,
      FilePendingCatalogDiscoveryStore pendingDiscoveryStore,
      TrustedKeyProvider discoveryIssuerKeyProvider) {
    return new AppCatalogManager(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        AppCatalogManagerDependencies.defaults(sourceStore),
        Objects.requireNonNull(federatedTrustStore, FEDERATED_TRUST_STORE_PARAMETER),
        Objects.requireNonNull(pendingDiscoveryStore, "pendingDiscoveryStore"),
        Objects.requireNonNull(discoveryIssuerKeyProvider, "discoveryIssuerKeyProvider"));
  }

  /** Creates a federation-scoped manager with Crypta content transport. */
  public static AppCatalogManager withFederatedTrustPolicy(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      FileFederatedCatalogTrustStore federatedTrustStore,
      ContentFetchPort contentFetchPort) {
    return new AppCatalogManager(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        AppCatalogManagerDependencies.withContentFetchPort(sourceStore, contentFetchPort),
        Objects.requireNonNull(federatedTrustStore, FEDERATED_TRUST_STORE_PARAMETER),
        null,
        null);
  }

  /** Creates a federation/discovery manager with Crypta content transport. */
  public static AppCatalogManager withFederatedTrustAndDiscoveryPolicy(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedCatalogKeyProvider,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      FileFederatedCatalogTrustStore federatedTrustStore,
      FilePendingCatalogDiscoveryStore pendingDiscoveryStore,
      TrustedKeyProvider discoveryIssuerKeyProvider,
      ContentFetchPort contentFetchPort) {
    return new AppCatalogManager(
        sourceStore,
        trustedCatalogKeyProvider,
        bundleVerificationPolicy,
        AppCatalogManagerDependencies.withContentFetchPort(sourceStore, contentFetchPort),
        Objects.requireNonNull(federatedTrustStore, FEDERATED_TRUST_STORE_PARAMETER),
        Objects.requireNonNull(pendingDiscoveryStore, "pendingDiscoveryStore"),
        Objects.requireNonNull(discoveryIssuerKeyProvider, "discoveryIssuerKeyProvider"));
  }

  static String normalizeCatalogIdForLookup(String catalogId) {
    try {
      return AppCatalog.normalizeCatalogId(catalogId);
    } catch (AppCatalogException _) {
      throw new AppCatalogException(AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found.");
    }
  }

  /** Supplies the trusted keys used for one signing role. */
  @FunctionalInterface
  public interface TrustedKeyProvider {
    /**
     * Returns the current immutable trusted-key registry for the provider's assigned role.
     *
     * @return current trusted-key registry, which may be empty but never {@code null}
     * @throws IOException if key material cannot be loaded from runtime configuration
     */
    TrustedAppKeys trustedKeys() throws IOException;
  }
}
