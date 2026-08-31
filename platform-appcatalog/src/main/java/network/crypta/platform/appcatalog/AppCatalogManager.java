package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Coordinates signed catalog sources, refreshes, artifact staging, and bundle verification.
 *
 * <p>The manager owns no global state. Runtime composition supplies the file-backed store and
 * trusted-key providers, and API handlers call the manager for catalog operations. Install and
 * update flows stop at {@link AppCatalogInstallPlan}; callers still delegate final installation to
 * AppHost so existing staged-directory semantics and verification policies remain intact.
 *
 * <p>Public reads are synchronized because they share a source store and scratch root. Catalog and
 * trust mutations first acquire the federation write fence and then the manager monitor; retained
 * install and rollback authorizations acquire the read side in the same order. The manager re-reads
 * trusted keys for each operation through {@link TrustedKeyProvider}, which lets deployments rotate
 * catalog and app signing keys independently without recreating the manager. It verifies stored
 * sidecars before listing or selecting entries, and it never weakens the signed bundle verification
 * performed by {@code platform-appdist}.
 */
public final class AppCatalogManager {
  private static final String FEDERATED_TRUST_STORE_PARAMETER = "federatedTrustStore";

  private final AppCatalogSourceStore sourceStore;
  private final TrustedKeyProvider trustedCatalogKeyProvider;
  private final AppReviewTransparencyLog reviewTransparencyLog;
  private final AppCatalogOperations operations;
  private final AppCatalogRefreshCoordinator refreshCoordinator;
  private final AppCatalogInstallPlanner installPlanner;
  private final FileFederatedCatalogTrustStore federatedTrustStore;
  private final FilePendingCatalogDiscoveryStore pendingDiscoveryStore;
  private final TrustedKeyProvider discoveryIssuerKeyProvider;
  private final AppCatalogAuthorizationCoordinator authorizationCoordinator;

  /** Same-thread lease retaining exact catalog trust authorization through host mutation. */
  @FunctionalInterface
  public interface CatalogTrustAuthorization extends AutoCloseable {
    /** Releases the retained catalog trust decision. */
    @Override
    void close();
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
   * Creates a manager with default JDK fetch and download helpers.
   *
   * <p>This constructor is the normal runtime entry point. It uses the default no-redirect fetcher,
   * the default artifact downloader, and the standard ZIP extractor. The supplied store determines
   * both persistent catalog state and the scratch root used during install/update staging. Catalog
   * and bundle verification share the supplied provider for source compatibility; new runtime
   * wiring should use the role-specific overload.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore, TrustedKeyProvider trustedKeyProvider) {
    this(sourceStore, trustedKeyProvider, trustedKeyProvider);
  }

  /**
   * Creates a manager with role-specific catalog and app-bundle trust providers.
   *
   * <p>Catalog signatures are accepted only from {@code trustedCatalogKeyProvider}; extracted app
   * bundles are accepted only from {@code trustedBundleKeyProvider}. Both providers retain the
   * existing trusted-key registry format so runtime deployments can migrate configuration without
   * changing signature sidecars.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedCatalogKeyProvider provider for the current trusted catalog-signing keys
   * @param trustedBundleKeyProvider provider for the current trusted app-bundle-signing keys
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
   * <p>The named factory avoids making existing three-argument constructor calls with {@code null}
   * ambiguous with the content-transport overload. Protected runtimes use this entry point when
   * publisher authorization is narrower than a generic trusted-key registry. Catalog signatures
   * remain governed exclusively by {@code trustedCatalogKeyProvider}.
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
   * Creates a manager with a runtime content fetch port for {@code crypta:} catalog sources.
   *
   * <p>The supplied port is used only as bounded content transport. Catalog signatures and trusted
   * catalog keys remain the authentication boundary for fetched catalogs. Catalog and bundle
   * verification share the supplied provider for source compatibility; new runtime wiring should
   * use the role-specific overload.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
   * @param contentFetchPort runtime content fetch port for {@code crypta:} sources
   */
  public AppCatalogManager(
      AppCatalogSourceStore sourceStore,
      TrustedKeyProvider trustedKeyProvider,
      ContentFetchPort contentFetchPort) {
    this(sourceStore, trustedKeyProvider, trustedKeyProvider, contentFetchPort);
  }

  /**
   * Creates a manager with role-specific trust and a runtime content fetch port.
   *
   * <p>The supplied port is used only as bounded content transport. Catalog signatures are checked
   * with {@code trustedCatalogKeyProvider}, while extracted app bundles are checked with {@code
   * trustedBundleKeyProvider}.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedCatalogKeyProvider provider for the current trusted catalog-signing keys
   * @param trustedBundleKeyProvider provider for the current trusted app-bundle-signing keys
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
   * Creates a manager with explicit pipeline dependencies for tests and controlled embeddings.
   *
   * <p>Supplying a dependency bundle keeps network and filesystem edges deterministic while
   * preserving the production orchestration order. Catalog and bundle verification share the
   * supplied provider for source compatibility.
   *
   * @param sourceStore file-backed catalog source store
   * @param trustedKeyProvider provider for the current trusted app/catalog keys
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
   * <p>Discovery issuer keys authenticate public recommendation documents only. Import remains
   * pending and cannot add a catalog source or create a local trust binding.
   *
   * @param sourceStore file-backed configured catalog source store
   * @param trustedCatalogKeyProvider provider for catalog-signing trust
   * @param bundleVerificationPolicy catalog/app-scoped bundle authorization
   * @param federatedTrustStore host-owned exact catalog trust bindings
   * @param pendingDiscoveryStore host-owned pending public discovery evidence
   * @param discoveryIssuerKeyProvider locally configured public discovery issuer keys
   * @return manager with federated routine work and non-authoritative discovery import enabled
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

  /** Stores one explicit host-owned catalog trust binding. */
  public void putFederatedTrustBinding(FederatedCatalogTrustBinding binding) throws IOException {
    withCatalogMutationLock(
        () -> {
          requireFederatedTrustStore().put(binding);
          return null;
        });
  }

  /** Returns whether this manager has the host-owned federated catalog trust authority enabled. */
  public boolean federationEnabled() {
    return federatedTrustStore != null;
  }

  /** Returns whether bounded pending discovery import is configured for this manager. */
  public boolean catalogDiscoveryEnabled() {
    return pendingDiscoveryStore != null && discoveryIssuerKeyProvider != null;
  }

  /**
   * Authenticates and retains one recommendation as pending local evidence only.
   *
   * @param descriptorBytes exact signed descriptor bytes
   * @param endorsementBytes zero to eight exact direct-endorsement documents
   * @param now local verification instant
   * @return retained pending recommendation, which grants no trust and configures no source
   * @throws IOException if key loading or confined persistence fails
   */
  public synchronized PendingCatalogDiscoveryRecommendation importCatalogDiscovery(
      byte[] descriptorBytes, List<byte[]> endorsementBytes, Instant now) throws IOException {
    requireFederatedTrustStore();
    return requirePendingDiscoveryStore()
        .importRecommendation(
            descriptorBytes,
            endorsementBytes,
            requireDiscoveryIssuerKeyProvider().trustedKeys(),
            Objects.requireNonNull(now, "now"));
  }

  /** Lists bounded pending discovery evidence without exposing raw signed documents. */
  public synchronized List<PendingCatalogDiscoveryRecommendation> pendingCatalogDiscoveries()
      throws IOException {
    requireFederatedTrustStore();
    return requirePendingDiscoveryStore().list();
  }

  /**
   * Lists pending recommendations after re-evaluating current issuer lifecycle and freshness.
   *
   * <p>A revoked or expired issuer changes only the returned evidence status. It never creates or
   * removes catalog trust, alters another recommendation, or follows an endorsement chain.
   *
   * @param now current local verification instant
   * @return bounded pending records with current direct evidence status
   * @throws IOException if local key material or the pending store cannot be read
   */
  public synchronized List<PendingCatalogDiscoveryEvidence> currentPendingCatalogDiscoveries(
      Instant now) throws IOException {
    requireFederatedTrustStore();
    Instant checkedNow = Objects.requireNonNull(now, "now");
    TrustedAppKeys keys = requireDiscoveryIssuerKeyProvider().trustedKeys();
    List<PendingCatalogDiscoveryEvidence> evidence = new ArrayList<>();
    for (PendingCatalogDiscoveryRecommendation pending : requirePendingDiscoveryStore().list()) {
      evidence.add(
          new PendingCatalogDiscoveryEvidence(
              pending,
              descriptorIsActive(pending, keys, checkedNow),
              pending.currentEndorsementEvidence(keys, checkedNow)));
    }
    return List.copyOf(evidence);
  }

  private static boolean descriptorIsActive(
      PendingCatalogDiscoveryRecommendation pending, TrustedAppKeys keys, Instant now) {
    try {
      pending.reverifyDescriptor(keys, now);
      return true;
    } catch (AppCatalogException _) {
      return false;
    }
  }

  /** Discards one pending recommendation without changing catalog trust or configured sources. */
  public synchronized boolean discardPendingCatalogDiscovery(String descriptorId)
      throws IOException {
    requireFederatedTrustStore();
    return requirePendingDiscoveryStore().discard(descriptorId);
  }

  /** Lists local catalog trust bindings without exposing key bytes or source URIs. */
  public synchronized List<FederatedCatalogTrustBinding> federatedTrustBindings()
      throws IOException {
    return requireFederatedTrustStore().list();
  }

  /** Applies one explicit local lifecycle transition without changing signer or scope fields. */
  public FederatedCatalogTrustBinding transitionFederatedTrustBinding(
      String catalogId,
      FederatedCatalogTrustBinding.Status status,
      String reason,
      String operatorId,
      Instant changedAt)
      throws IOException {
    return withCatalogMutationLock(
        () -> {
          FileFederatedCatalogTrustStore store = requireFederatedTrustStore();
          String normalizedCatalogId = normalizeCatalogIdForLookup(catalogId);
          FederatedCatalogTrustBinding existing =
              store
                  .findByCatalogId(normalizedCatalogId)
                  .orElseThrow(
                      () ->
                          new AppCatalogException(
                              "catalog_trust_binding_not_found",
                              "No local trust binding exists for catalog " + normalizedCatalogId));
          FederatedCatalogTrustBinding updated =
              FederatedCatalogTrustBinding.create(
                  existing.bindingId(),
                  existing.catalogId(),
                  existing.signerFingerprints(),
                  Objects.requireNonNull(status, "status"),
                  existing.allowedChannels(),
                  existing.localPriority(),
                  existing.discoveryProvenanceDigest().orElse(null),
                  existing.reviewerPolicyDigest().orElse(null),
                  existing.publisherPolicyDigest().orElse(null),
                  existing.createdAt(),
                  Objects.requireNonNull(changedAt, "changedAt"),
                  reason,
                  operatorId);
          store.put(updated);
          return updated;
        });
  }

  /** Returns exact public authority identities for host-owned installation provenance. */
  public synchronized AppCatalogOriginContext originContext(String catalogId) throws IOException {
    return authorizationCoordinator.originContext(normalizeCatalogIdForLookup(catalogId));
  }

  private AppCatalogOriginContext originContext(
      StoredCatalogSource stored, TrustedAppKeys trustedKeys) throws IOException {
    return authorizationCoordinator.originContext(stored, trustedKeys);
  }

  /**
   * Reauthorizes one exact retained app origin under current historical catalog policy.
   *
   * <p>The lookup examines the current and retained signed revisions for the stored source, but it
   * accepts only the revision content, catalog signer, stable local binding identity, app version,
   * and bundle digest captured in the supplied origin. Current historical verification permits an
   * active or suspended binding and rejects pending, revoked, removed, unknown, or role-mismatched
   * authority. Publisher and reviewer policy remain caller-owned decisions because their key and
   * receipt registries are composed above the catalog manager.
   *
   * @param captured exact catalog authority retained with installed provenance
   * @param appId exact app namespace to restore
   * @param appVersion exact historical version to restore
   * @param bundleSha256 exact catalog bundle digest to restore
   * @return authenticated catalog entry matching every retained subject field
   * @throws IOException if the source or retained revision cannot be read safely
   */
  public synchronized AppCatalogEntry authorizeHistoricalAppOrigin(
      AppCatalogOriginContext captured, String appId, String appVersion, String bundleSha256)
      throws IOException {
    return authorizationCoordinator.authorizeHistoricalAppOrigin(
        captured, appId, appVersion, bundleSha256);
  }

  /**
   * Reauthorizes an exact historical app origin and retains catalog trust through host rollback.
   *
   * <p>The returned authorization must be closed by the same thread. Local binding and catalog
   * source mutations wait until the caller releases it after the AppHost rollback transaction has
   * committed or compensated.
   *
   * @param captured exact catalog authority retained with installed provenance
   * @param appId exact app namespace to restore
   * @param appVersion exact historical version to restore
   * @param bundleSha256 exact catalog bundle digest to restore
   * @return authenticated historical entry and retained catalog trust authorization
   * @throws IOException if current historical catalog policy does not authorize the origin
   */
  public HistoricalAppOriginAuthorization authorizeHistoricalAppOriginForRollback(
      AppCatalogOriginContext captured, String appId, String appVersion, String bundleSha256)
      throws IOException {
    return authorizationCoordinator.authorizeHistoricalAppOriginForRollback(
        this, captured, appId, appVersion, bundleSha256);
  }

  private FileFederatedCatalogTrustStore requireFederatedTrustStore() {
    if (federatedTrustStore == null) {
      throw new IllegalStateException("federated catalog trust is not configured");
    }
    return federatedTrustStore;
  }

  private FilePendingCatalogDiscoveryStore requirePendingDiscoveryStore() {
    if (pendingDiscoveryStore == null) {
      throw new IllegalStateException("pending catalog discovery is not configured");
    }
    return pendingDiscoveryStore;
  }

  private TrustedKeyProvider requireDiscoveryIssuerKeyProvider() {
    if (discoveryIssuerKeyProvider == null) {
      throw new IllegalStateException("catalog discovery issuer trust is not configured");
    }
    return discoveryIssuerKeyProvider;
  }

  /**
   * Returns the local review transparency log used by API gates.
   *
   * @return redacted review transparency log facade
   */
  public AppReviewTransparencyLog reviewTransparencyLog() {
    return reviewTransparencyLog;
  }

  /**
   * Lists all configured catalogs after re-verifying stored sidecars.
   *
   * <p>The returned snapshots are built from authenticated catalog bytes stored on disk. Legacy
   * mode preserves the existing all-or-nothing behavior when stored state cannot be authenticated.
   * Federation mode verifies each configured source independently and omits sources that are not
   * currently authorized, so a suspended, revoked, removed, corrupt, or stale catalog cannot
   * disable unrelated catalogs.
   *
   * @return source snapshots sorted by catalog id
   * @throws IOException if stored catalog state cannot be read
   */
  public synchronized List<AppCatalogSourceSnapshot> listCatalogs() throws IOException {
    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    if (federatedTrustStore != null) {
      return listFederatedRoutineCatalogs(trustedKeys);
    }
    return sourceStore.list().stream()
        .map(stored -> operations.snapshot(stored, trustedKeys))
        .sorted(java.util.Comparator.comparing(AppCatalogSourceSnapshot::catalogId))
        .toList();
  }

  /**
   * Lists catalogs authorized for new refresh, install, and update work.
   *
   * <p>Legacy mode retains the existing catalog listing. Federation mode independently checks each
   * configured source with routine (active-only) trust semantics, so one suspended, revoked,
   * removed, corrupt, or stale binding cannot authorize work or disable unrelated catalogs.
   *
   * @return independently verified active catalog snapshots sorted by catalog id
   * @throws IOException if the catalog store root itself cannot be enumerated
   */
  public synchronized List<AppCatalogSourceSnapshot> listRoutineCatalogs() throws IOException {
    return listCatalogs();
  }

  /**
   * Lists the normalized identities of all persisted catalog sources without authorizing them for
   * routine work.
   *
   * <p>This inventory intentionally includes sources whose local trust binding is stale, suspended,
   * revoked, or otherwise unavailable. Operator recovery surfaces use it to distinguish an unused
   * trust binding from a configured source that must be removed or re-admitted. Callers must not
   * interpret membership as catalog authenticity or authorization.
   *
   * @return configured catalog IDs sorted deterministically
   * @throws IOException if the source-store root cannot be enumerated safely
   */
  public synchronized List<String> configuredCatalogIds() throws IOException {
    return sourceStore.configuredCatalogIds();
  }

  private List<AppCatalogSourceSnapshot> listFederatedRoutineCatalogs(TrustedAppKeys trustedKeys)
      throws IOException {
    return operations.listFederatedRoutineCatalogs(trustedKeys);
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
    return operations.catalogSnapshot(
        normalizeCatalogIdForLookup(catalogId), trustedCatalogKeyProvider.trustedKeys());
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
  public AppCatalogSourceSnapshot addSource(String rawSource) throws IOException {
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
  public AppCatalogSourceSnapshot addSource(String rawSource, String expectedCatalogId)
      throws IOException {
    return withCatalogMutationLock(() -> operations.addSource(rawSource, expectedCatalogId));
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
  public void remove(String catalogId) throws IOException {
    withCatalogMutationLock(
        () -> {
          sourceStore.remove(normalizeCatalogIdForLookup(catalogId));
          return null;
        });
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
  public AppCatalogSourceSnapshot refresh(String catalogId) throws IOException {
    return withCatalogMutationLock(() -> refresh(catalogId, false));
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
  public AppCatalogSourceSnapshot emergencyRefresh(String catalogId) throws IOException {
    return withCatalogMutationLock(() -> refresh(catalogId, false));
  }

  /**
   * Refreshes only the primary endpoint, without mirror fallback.
   *
   * @param catalogId catalog id to refresh
   * @return updated source snapshot
   * @throws IOException if the primary source fails verification or persistence
   */
  public AppCatalogSourceSnapshot refreshPrimaryOnly(String catalogId) throws IOException {
    return withCatalogMutationLock(() -> refresh(catalogId, true));
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
  public AppCatalogMirror addMirror(
      String catalogId, String rawMirrorId, String rawSource, int priority, boolean enabled)
      throws IOException {
    return withCatalogMutationLock(
        () -> operations.addMirror(catalogId, rawMirrorId, rawSource, priority, enabled));
  }

  /** Updates local mirror metadata. */
  public AppCatalogMirror updateMirror(
      String catalogId, String mirrorId, String rawSource, Integer priority, Boolean enabled)
      throws IOException {
    return withCatalogMutationLock(
        () -> operations.updateMirror(catalogId, mirrorId, rawSource, priority, enabled));
  }

  /** Removes one mirror endpoint. */
  public void removeMirror(String catalogId, String mirrorId) throws IOException {
    withCatalogMutationLock(
        () -> {
          operations.removeMirror(catalogId, mirrorId);
          return null;
        });
  }

  /** Lists retained rollback candidates for one catalog. */
  public synchronized List<AppCatalogRollbackCandidate> rollbackCandidates(String catalogId)
      throws IOException {
    return operations.rollbackCandidates(catalogId);
  }

  /** Reactivates a retained verified catalog revision. */
  public AppCatalogSourceSnapshot rollback(String catalogId, String revisionDigest, String reason)
      throws IOException {
    return withCatalogMutationLock(() -> operations.rollback(catalogId, revisionDigest, reason));
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
    return operations.listApps(normalizeCatalogIdForLookup(catalogId));
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
    return operations
        .readVerifiedCatalog(
            normalizeCatalogIdForLookup(catalogId), trustedCatalogKeyProvider.trustedKeys())
        .securityPolicy();
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
    return operations.getApp(normalizeCatalogIdForLookup(catalogId), appId);
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
    return operations.securityDecision(normalizeCatalogIdForLookup(catalogId), appId);
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
            : installedFederatedSecurityDecisions(normalizedAppId, version, trustedKeys);
    return AppCatalogSecurityDecision.combine(decisions);
  }

  private List<AppCatalogSecurityDecision> installedFederatedSecurityDecisions(
      String appId, String version, TrustedAppKeys trustedKeys) throws IOException {
    return operations.installedFederatedSecurityDecisions(appId, version, trustedKeys);
  }

  /**
   * Downloads, extracts, and verifies one app bundle from a catalog.
   *
   * <p>The returned plan is the only output of the catalog install/update preparation path. The
   * method requires routine active-key verification of the retained catalog before selecting its
   * entry, downloads the declared artifact, checks size and SHA-256, extracts the ZIP safely,
   * verifies the extracted signed bundle, and confirms manifest id/version match the catalog.
   * Historical catalog trust remains available for inspection and explicit rollback, but cannot
   * authorize a new install or update plan. If any step fails, the per-operation scratch tree is
   * removed before the failure is rethrown.
   *
   * @param catalogId catalog id containing the app
   * @param appId catalog app id to prepare
   * @return temporary installation plan whose staged directory can be passed to AppHost
   * @throws IOException if catalog lookup, download, extraction, or bundle verification fails
   */
  public synchronized AppCatalogInstallPlan prepareInstallPlan(String catalogId, String appId)
      throws IOException {
    String normalizedCatalogId = normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    AppCatalogEntry entry = operations.getRoutineApp(stored, appId, trustedKeys);
    return installPlanner.prepareInstallPlan(
        normalizedCatalogId, entry, originContext(stored, trustedKeys));
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
    AppCatalogInstallPlan checkedPlan = Objects.requireNonNull(plan, "plan");
    AppCatalogOriginContext captured =
        checkedPlan
            .originContext()
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SOURCE,
                        "catalog install plan has no authenticated origin context"));
    AppCatalogOriginContext current = originContext(checkedPlan.catalogId());
    if (!captured.equals(current)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "catalog authority or revision changed after plan creation");
    }
    installPlanner.verifyInstallPlan(checkedPlan);
  }

  /**
   * Re-verifies an installation plan and retains its exact catalog trust decision through host
   * commit.
   *
   * <p>The returned lease must be closed by the same thread. Local catalog trust and source
   * mutations wait until it is closed, preventing suspension, revocation, removal, refresh,
   * rollback, or trust-root replacement from interleaving between the final plan check and the
   * coordinated AppHost mutation.
   *
   * @param plan retained installation plan selected for mutation
   * @return same-thread authorization lease
   * @throws IOException if the retained plan or current catalog trust is no longer valid
   */
  public CatalogTrustAuthorization authorizeInstallPlanForMutation(AppCatalogInstallPlan plan)
      throws IOException {
    return authorizationCoordinator.retainAuthorization(
        this,
        () -> {
          verifyInstallPlan(plan);
          retainInstallPlanRevision(plan);
          return plan;
        });
  }

  private void retainInstallPlanRevision(AppCatalogInstallPlan plan) throws IOException {
    if (plan.originContext().filter(AppCatalogOriginContext::federationScoped).isEmpty()) {
      return;
    }
    StoredCatalogSource stored = sourceStore.read(plan.catalogId());
    sourceStore.retainOriginRevision(
        plan.catalogId(),
        AppCatalogRevisions.catalogDigest(stored.fetchedCatalog()),
        plan.entry().appId());
  }

  private <T> T withCatalogMutationLock(AppCatalogAuthorizationCoordinator.IoOperation<T> mutation)
      throws IOException {
    return authorizationCoordinator.withMutationLock(this, mutation);
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
    return operations.hasTrustedCatalogKey(keyId);
  }

  static String normalizeCatalogIdForLookup(String catalogId) {
    try {
      return AppCatalog.normalizeCatalogId(catalogId);
    } catch (AppCatalogException _) {
      throw new AppCatalogException(AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog not found.");
    }
  }

  /**
   * Supplies the trusted keys used for one signing role.
   *
   * <p>Runtime wiring can reload key files on each operation by implementing this provider as a
   * small adapter over a role-specific trusted-key configuration. Implementations should be
   * side-effect-light because the manager calls them while holding its monitor.
   */
  @FunctionalInterface
  public interface TrustedKeyProvider {
    /**
     * Returns the current trusted keys for the provider's assigned role.
     *
     * <p>Returning an empty or stale registry makes operations for that role fail closed.
     *
     * @return immutable trusted-key registry
     * @throws IOException if key material cannot be loaded from runtime configuration
     */
    TrustedAppKeys trustedKeys() throws IOException;
  }
}
