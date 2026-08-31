package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Implements install, origin, local trust, and discovery operations for {@link AppCatalogManager}.
 *
 * <p>This layer binds a downloaded app bundle to the exact authenticated catalog revision that
 * selected it. Retained plans are reverified before staged code can run, and mutation authorization
 * holds the catalog read fence until the coordinated AppHost operation completes. Historical
 * rollback authorization uses the same fence with the bounded active-or-suspended trust semantics
 * defined by the origin authority.
 *
 * <p>Revision-pin methods operate on complete current-and-rollback provenance snapshots. Local
 * federation methods manage explicit trust bindings and pending discovery evidence under the same
 * mutation fence. Discovery remains non-authoritative: imports do not configure a source, install a
 * key, or activate trust.
 */
abstract class AppCatalogInstallManager extends AppCatalogOperationsManager {
  /**
   * Initializes install and federation handling over the shared verified catalog state.
   *
   * @param sourceStore configured catalog source storage
   * @param trustedCatalogKeyProvider reloadable catalog-signing trust provider
   * @param bundleVerificationPolicy extracted app-bundle authorization policy
   * @param dependencies catalog pipeline collaborators
   * @param federatedTrustStore optional local catalog trust authority
   * @param pendingDiscoveryStore optional pending discovery store
   * @param discoveryIssuerKeyProvider optional discovery issuer trust provider
   */
  AppCatalogInstallManager(
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
   * Returns exact authenticated catalog authority for host-owned install provenance.
   *
   * @param catalogId configured catalog identity
   * @return signer, revision, and local-policy origin context
   * @throws IOException if source or trust state cannot be read
   */
  public synchronized AppCatalogOriginContext originContext(String catalogId) throws IOException {
    return authorizationCoordinator.originContext(
        AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
  }

  /**
   * Builds an origin from a source already verified with the supplied key snapshot.
   *
   * @param stored exact stored source used for catalog verification
   * @param trustedKeys catalog-signing keys used for the same verification
   * @return exact legacy or federation-scoped catalog origin
   * @throws IOException if local federation policy cannot be read
   */
  private AppCatalogOriginContext originContext(
      StoredCatalogSource stored, TrustedAppKeys trustedKeys) throws IOException {
    return authorizationCoordinator.originContext(stored, trustedKeys);
  }

  /**
   * Reauthorizes one exact retained app origin under current historical catalog policy.
   *
   * @param captured exact catalog authority retained with installed provenance
   * @param appId exact app namespace to restore
   * @param appVersion exact historical version to restore
   * @param bundleSha256 exact catalog bundle digest to restore
   * @return authenticated entry matching every retained subject
   * @throws IOException if historical source or policy state cannot be verified
   */
  public synchronized AppCatalogEntry authorizeHistoricalAppOrigin(
      AppCatalogOriginContext captured, String appId, String appVersion, String bundleSha256)
      throws IOException {
    return authorizationCoordinator.authorizeHistoricalAppOrigin(
        captured, appId, appVersion, bundleSha256);
  }

  /**
   * Reauthorizes a historical origin and retains catalog trust through host rollback.
   *
   * @param captured exact catalog authority retained with installed provenance
   * @param appId exact app namespace to restore
   * @param appVersion exact historical version to restore
   * @param bundleSha256 exact catalog bundle digest to restore
   * @return authenticated entry and same-thread authorization lease
   * @throws IOException if current historical policy rejects the origin
   */
  public AppCatalogManager.HistoricalAppOriginAuthorization authorizeHistoricalAppOriginForRollback(
      AppCatalogOriginContext captured, String appId, String appVersion, String bundleSha256)
      throws IOException {
    return authorizationCoordinator.authorizeHistoricalAppOriginForRollback(
        this, captured, appId, appVersion, bundleSha256);
  }

  /**
   * Downloads, extracts, and verifies one app bundle selected from an active catalog.
   *
   * @param catalogId routine-authorized catalog identity
   * @param appId signed catalog app namespace
   * @return closeable plan containing the verified staged bundle and exact origin
   * @throws IOException if lookup, download, extraction, or verification fails
   */
  public synchronized AppCatalogInstallPlan prepareInstallPlan(String catalogId, String appId)
      throws IOException {
    String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    AppCatalogEntry entry = operations.getRoutineApp(stored, appId, trustedKeys);
    return installPlanner.prepareInstallPlan(
        normalizedCatalogId, entry, originContext(stored, trustedKeys));
  }

  /**
   * Re-verifies a retained plan and its exact current catalog authority.
   *
   * @param plan retained closeable install plan to verify
   * @throws IOException if staged bytes or catalog authority changed
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
   * Re-verifies a plan and retains its catalog trust decision through host commit.
   *
   * @param plan retained install plan selected for mutation
   * @return same-thread authorization lease that the caller must close
   * @throws IOException if current catalog state no longer authorizes the plan
   */
  public AppCatalogManager.CatalogTrustAuthorization authorizeInstallPlanForMutation(
      AppCatalogInstallPlan plan) throws IOException {
    return authorizationCoordinator.retainAuthorization(
        this,
        () -> {
          verifyInstallPlan(plan);
          return plan;
        });
  }

  /**
   * Reconciles durable revision pins with a complete AppHost provenance snapshot.
   *
   * @param retainedOrigins complete current-and-rollback origin references
   * @throws IOException if confined pin state cannot be updated safely
   */
  public synchronized void reconcileOriginRevisionPins(
      List<AppCatalogManager.OriginRevision> retainedOrigins) throws IOException {
    sourceStore.reconcileOriginRevisions(retainedOrigins);
  }

  /**
   * Retains every revision in a prospective AppHost provenance snapshot.
   *
   * @param retainedOrigins prospective current-and-rollback origin references
   * @throws IOException if any referenced revision cannot be retained
   */
  public synchronized void retainOriginRevisionPins(
      List<AppCatalogManager.OriginRevision> retainedOrigins) throws IOException {
    sourceStore.retainOriginRevisions(retainedOrigins);
  }

  /**
   * Stores one explicit host-owned catalog trust binding under the mutation fence.
   *
   * @param binding closed local trust binding to persist
   * @throws IOException if trust state cannot be validated or written atomically
   */
  public void putFederatedTrustBinding(FederatedCatalogTrustBinding binding) throws IOException {
    withCatalogMutationLock(
        () -> {
          requireFederatedTrustStore().put(binding);
          return null;
        });
  }

  /**
   * Reports whether exact host-owned catalog trust is configured.
   *
   * @return {@code true} when routine work requires federated bindings
   */
  public boolean federationEnabled() {
    return federatedTrustStore != null;
  }

  /**
   * Reports whether pending discovery persistence and issuer trust are configured.
   *
   * @return {@code true} when signed discovery documents can be imported locally
   */
  public boolean catalogDiscoveryEnabled() {
    return pendingDiscoveryStore != null && discoveryIssuerKeyProvider != null;
  }

  /**
   * Authenticates and retains one recommendation as pending local evidence only.
   *
   * @param descriptorBytes exact signed discovery descriptor bytes
   * @param endorsementBytes zero to eight direct signed endorsement documents
   * @param now local verification instant used for freshness checks
   * @return pending recommendation that grants no catalog trust
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

  /**
   * Lists retained pending recommendations without exposing raw signed documents.
   *
   * @return bounded pending discovery records in deterministic order
   * @throws IOException if pending evidence cannot be read safely
   */
  public synchronized List<PendingCatalogDiscoveryRecommendation> pendingCatalogDiscoveries()
      throws IOException {
    requireFederatedTrustStore();
    return requirePendingDiscoveryStore().list();
  }

  /**
   * Lists pending recommendations after current issuer and freshness evaluation.
   *
   * @param now local instant used for descriptor and endorsement freshness
   * @return current direct evidence status without transitive trust
   * @throws IOException if keys or pending evidence cannot be read
   */
  public synchronized List<AppCatalogManager.PendingCatalogDiscoveryEvidence>
      currentPendingCatalogDiscoveries(Instant now) throws IOException {
    requireFederatedTrustStore();
    Instant checkedNow = Objects.requireNonNull(now, "now");
    TrustedAppKeys keys = requireDiscoveryIssuerKeyProvider().trustedKeys();
    List<AppCatalogManager.PendingCatalogDiscoveryEvidence> evidence = new ArrayList<>();
    for (PendingCatalogDiscoveryRecommendation pending : requirePendingDiscoveryStore().list()) {
      evidence.add(
          new AppCatalogManager.PendingCatalogDiscoveryEvidence(
              pending,
              descriptorIsActive(pending, keys, checkedNow),
              pending.currentEndorsementEvidence(keys, checkedNow)));
    }
    return List.copyOf(evidence);
  }

  /**
   * Returns whether one pending descriptor remains authentic and fresh at the supplied instant.
   *
   * @param pending retained pending recommendation
   * @param keys current locally trusted discovery issuer keys
   * @param now local freshness evaluation instant
   * @return {@code true} only when descriptor re-verification succeeds
   */
  private static boolean descriptorIsActive(
      PendingCatalogDiscoveryRecommendation pending, TrustedAppKeys keys, Instant now) {
    try {
      pending.reverifyDescriptor(keys, now);
      return true;
    } catch (AppCatalogException _) {
      return false;
    }
  }

  /**
   * Discards one pending recommendation without changing trust or configured sources.
   *
   * @param descriptorId retained descriptor identity to discard
   * @return {@code true} when a pending record was removed
   * @throws IOException if confined pending state cannot be updated
   */
  public synchronized boolean discardPendingCatalogDiscovery(String descriptorId)
      throws IOException {
    requireFederatedTrustStore();
    return requirePendingDiscoveryStore().discard(descriptorId);
  }

  /**
   * Lists local catalog trust bindings without source URIs or key bytes.
   *
   * @return closed host-owned trust records in deterministic order
   * @throws IOException if local trust state cannot be read safely
   */
  public synchronized List<FederatedCatalogTrustBinding> federatedTrustBindings()
      throws IOException {
    return requireFederatedTrustStore().list();
  }

  /**
   * Applies an explicit lifecycle transition without changing signer or scope fields.
   *
   * @param catalogId catalog identity whose binding changes
   * @param status requested local lifecycle status
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identity
   * @param changedAt local transition instant
   * @return newly persisted binding state
   * @throws IOException if the binding is absent or the transition cannot persist
   */
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
          String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
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

  /**
   * Returns configured local trust storage or fails closed in compatibility mode.
   *
   * @return configured host-owned federated trust store
   */
  private FileFederatedCatalogTrustStore requireFederatedTrustStore() {
    if (federatedTrustStore == null) {
      throw new IllegalStateException("federated catalog trust is not configured");
    }
    return federatedTrustStore;
  }

  /**
   * Returns configured pending discovery storage or fails closed when unavailable.
   *
   * @return configured host-owned pending discovery store
   */
  private FilePendingCatalogDiscoveryStore requirePendingDiscoveryStore() {
    if (pendingDiscoveryStore == null) {
      throw new IllegalStateException("pending catalog discovery is not configured");
    }
    return pendingDiscoveryStore;
  }

  /**
   * Returns configured discovery issuer trust or fails closed when unavailable.
   *
   * @return configured reloadable discovery issuer key provider
   */
  private AppCatalogManager.TrustedKeyProvider requireDiscoveryIssuerKeyProvider() {
    if (discoveryIssuerKeyProvider == null) {
      throw new IllegalStateException("catalog discovery issuer trust is not configured");
    }
    return discoveryIssuerKeyProvider;
  }

  /**
   * Returns the redacted local review transparency log used by API gates.
   *
   * @return shared authenticated review transparency log facade
   */
  public AppReviewTransparencyLog reviewTransparencyLog() {
    return reviewTransparencyLog;
  }
}
