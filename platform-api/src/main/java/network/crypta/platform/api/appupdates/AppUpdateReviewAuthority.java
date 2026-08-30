package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogOriginContext;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appcatalog.TrustedReviewerKeysLoader;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.InstalledAppOrigin;

/**
 * Owns reviewer-key, receipt, scope, and transparency decisions for app-update operations.
 *
 * <p>The update lifecycle coordinates staging and host mutations, while this authority keeps the
 * reviewer implementation details together. It evaluates routine and historical reviewer scope,
 * retains the matching authorization through a host commit, and records only the existing path-free
 * review subject in the local transparency log.
 *
 * <p>Federation mode fails closed when no scoped policy is configured. Compatibility mode may use
 * the global reviewer registry, but that decision is not treated as federation-complete. The
 * mutable scoped-policy reference is configured during runtime composition; subsequent operations
 * evaluate current key and scope state rather than caching receipt authorization.
 */
final class AppUpdateReviewAuthority {
  /** JSON field containing the bounded reviewer decision status. */
  private static final String JSON_STATUS = "status";

  /** JSON field indicating whether an operator acknowledgement is required. */
  private static final String JSON_REQUIRES_ACKNOWLEDGEMENT = "requiresAcknowledgement";

  /** JSON field indicating whether reviewer policy blocks an update. */
  private static final String JSON_BLOCKS_UPDATE = "blocksUpdate";

  /** JSON field indicating whether reviewer policy blocks policy-driven apply. */
  private static final String JSON_BLOCKS_POLICY_APPLY = "blocksPolicyApply";

  /** Catalog manager that supplies federation state and the transparency log. */
  private final AppCatalogManager catalogManager;

  /** Local policy applied to signed review receipts. */
  private final AppReviewPolicy reviewPolicy;

  /** Provider for the current reviewer-key registry. */
  private final AppUpdateService.ReviewerKeysProvider reviewerKeysProvider;

  /** Optional catalog-scoped reviewer policy installed during runtime composition. */
  private CatalogScopedReviewerPolicy scopedReviewerPolicy;

  /**
   * Creates a reviewer authority over the current catalog and reviewer services.
   *
   * @param catalogManager manager providing federation state and transparency logging
   * @param reviewPolicy local review-receipt acceptance policy
   * @param reviewerKeysProvider provider for the current reviewer-key registry
   */
  AppUpdateReviewAuthority(
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      AppUpdateService.ReviewerKeysProvider reviewerKeysProvider) {
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.reviewPolicy = Objects.requireNonNull(reviewPolicy, "reviewPolicy");
    this.reviewerKeysProvider =
        Objects.requireNonNull(reviewerKeysProvider, "reviewerKeysProvider");
  }

  /**
   * Returns the production provider that loads reviewer keys from system configuration.
   *
   * @return reviewer-key provider backed by the system loader
   */
  static AppUpdateService.ReviewerKeysProvider systemReviewerKeysProvider() {
    return TrustedReviewerKeysLoader::loadFromSystem;
  }

  /**
   * Installs the catalog-scoped reviewer policy used by federation mode.
   *
   * @param scopedReviewerPolicy non-null local reviewer-scope policy
   */
  void setScopedReviewerPolicy(CatalogScopedReviewerPolicy scopedReviewerPolicy) {
    this.scopedReviewerPolicy =
        Objects.requireNonNull(scopedReviewerPolicy, "scopedReviewerPolicy");
  }

  /**
   * Returns the currently installed catalog-scoped reviewer policy.
   *
   * @return configured policy, or an empty value before federation wiring
   */
  Optional<CatalogScopedReviewerPolicy> scopedReviewerPolicy() {
    return Optional.ofNullable(scopedReviewerPolicy);
  }

  /**
   * Evaluates current review trust for an authenticated catalog entry.
   *
   * @param catalogId normalized source catalog identifier
   * @param entry authenticated entry containing review metadata and receipt
   * @return stable JSON-compatible review-trust decision
   */
  Map<String, Object> reviewTrust(String catalogId, AppCatalogEntry entry) {
    TrustedReviewerKeys keys = trustedReviewerKeysOrEmpty();
    CatalogScopedReviewerPolicy reviewerPolicy = scopedReviewerPolicy;
    if (reviewerPolicy == null) {
      if (catalogManager.federationEnabled()) {
        throw lifecycleFailure(
            503,
            "catalog_federation_unavailable",
            "Federated catalog reviewer policy is unavailable.");
      }
      return AppReviewReceiptVerifier.evaluate(entry, keys, reviewPolicy, Instant.now())
          .toJsonValue();
    }
    try {
      return scopedReviewTrust(
          reviewerPolicy.evaluate(catalogId, entry, keys, reviewPolicy, Instant.now()));
    } catch (IOException _) {
      throw lifecycleFailure(
          500, "catalog_reviewer_scope_failed", "Local catalog reviewer scope could not be read.");
    }
  }

  /**
   * Returns the stable catalog value for an unreviewed entry.
   *
   * @return closed unreviewed status string
   */
  String unreviewedStatus() {
    return AppCatalogReviewStatus.UNREVIEWED.catalogValue();
  }

  /**
   * Evaluates the configured policy for an entry with no review receipt.
   *
   * @return stable JSON-compatible missing-receipt decision
   */
  Map<String, Object> missingReviewTrust() {
    return AppReviewReceiptVerifier.evaluateMissingReceipt(
            AppCatalogReviewMetadata.EMPTY, TrustedReviewerKeys.empty(), reviewPolicy)
        .toJsonValue();
  }

  /**
   * Records the review gate for an operator-driven update phase.
   *
   * @param candidate exact candidate whose review trust was enforced
   * @param phase bounded lifecycle phase for the transparency event
   */
  void recordUpdateGate(AppUpdateCandidate candidate, String phase) {
    recordGate(AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE, candidate, phase);
  }

  /**
   * Records the review gate for a policy-driven apply phase.
   *
   * @param candidate exact candidate whose review trust was enforced
   * @param phase bounded lifecycle phase for the transparency event
   */
  void recordPolicyApplyGate(AppUpdateCandidate candidate, String phase) {
    recordGate(AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY, candidate, phase);
  }

  /**
   * Retains current reviewer authorization for a routine install or update.
   *
   * @param plan exact reverified catalog install plan
   * @param targetOrigin provenance that will accompany committed bytes
   * @param install whether the mutation creates a new installation
   * @return reviewer-scope lease retained through the AppHost commit
   * @throws IOException if reviewer keys or scoped policy cannot be read safely
   */
  AppHost.CatalogMutationAuthorizationLease retainRoutineAuthorization(
      AppCatalogInstallPlan plan, InstalledAppOrigin targetOrigin, boolean install)
      throws IOException {
    CatalogScopedReviewerPolicy reviewerPolicy = requireScopedReviewerPolicy();
    CatalogScopedReviewerPolicy.RoutineAuthorization authorization =
        reviewerPolicy.retainAuthorization(
            plan.catalogId(), plan.entry(), currentReviewerKeys(), reviewPolicy, Instant.now());
    boolean retained = false;
    try {
      CatalogScopedReviewerPolicy.Verification verification = authorization.verification();
      AppReviewTrustDecision decision = verification.reviewDecision();
      String receiptFingerprint =
          plan.entry().reviewReceipt().map(AppReviewReceipt::fingerprintSha256).orElse("");
      boolean blockedForMutation = install ? decision.blocksInstall() : decision.blocksUpdate();
      if (!verification.authorized()
          || !decision.trusted()
          || !decision.positive()
          || blockedForMutation
          || !receiptFingerprint.equals(targetOrigin.reviewReceiptFingerprintSha256())
          || plan.originContext()
              .map(AppCatalogOriginContext::reviewerPolicyDigestSha256)
              .filter(targetOrigin.reviewerPolicyDigestSha256()::equals)
              .isEmpty()) {
        throw lifecycleFailure(
            409,
            "catalog_reviewer_authorization_changed",
            "The exact catalog reviewer authorization changed before commit.");
      }
      retained = true;
      return authorization::close;
    } finally {
      if (!retained) {
        authorization.close();
      }
    }
  }

  /**
   * Retains current historical reviewer authorization for rollback.
   *
   * @param origin exact retained provenance being restored
   * @param entry retained catalog entry corresponding to the rollback bundle
   * @return historical reviewer-scope lease retained through commit
   * @throws IOException if reviewer keys or scoped policy cannot be read safely
   */
  AppHost.CatalogMutationAuthorizationLease retainHistoricalAuthorization(
      InstalledAppOrigin origin, AppCatalogEntry entry) throws IOException {
    CatalogScopedReviewerPolicy.HistoricalAuthorization authorization =
        requireScopedReviewerPolicy()
            .retainHistoricalAuthorization(
                origin.catalogId(), entry, currentReviewerKeys(), reviewPolicy, Instant.now());
    boolean retained = false;
    try {
      CatalogScopedReviewerPolicy.Verification verification = authorization.verification();
      String receiptFingerprint =
          entry.reviewReceipt().map(AppReviewReceipt::fingerprintSha256).orElse("");
      if (!verification.authorized()
          || !verification.reviewDecision().trusted()
          || !verification.reviewDecision().positive()
          || verification.reviewDecision().blocksInstall()
          || verification.reviewDecision().blocksUpdate()
          || !receiptFingerprint.equals(origin.reviewReceiptFingerprintSha256())) {
        throw new AppHostException.CatalogRollbackAuthorizationException();
      }
      retained = true;
      return authorization::close;
    } finally {
      if (!retained) {
        authorization.close();
      }
    }
  }

  /**
   * Converts a scoped verification to its bounded API representation.
   *
   * @param scoped current catalog-scoped reviewer verification
   * @return immutable JSON-compatible review decision
   */
  private static Map<String, Object> scopedReviewTrust(
      CatalogScopedReviewerPolicy.Verification scoped) {
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(scoped.reviewDecision().toJsonValue());
    json.put("federationScopeAuthorized", scoped.authorized());
    json.put("federationScopeStatus", scoped.status());
    json.put("reviewerScopeId", scoped.scopeId().isBlank() ? null : scoped.scopeId());
    json.put(
        "reviewerScopeDigestSha256",
        scoped.scopeDigestSha256().isBlank() ? null : scoped.scopeDigestSha256());
    json.put(
        "reviewerPolicySemanticDigestSha256",
        scoped.policySemanticDigestSha256().isBlank() ? null : scoped.policySemanticDigestSha256());
    if (!scoped.authorized()) {
      json.put(JSON_STATUS, scoped.status());
      json.put("trusted", false);
      json.put("positive", false);
      json.put(JSON_REQUIRES_ACKNOWLEDGEMENT, true);
      json.put(JSON_BLOCKS_UPDATE, true);
      json.put(JSON_BLOCKS_POLICY_APPLY, true);
    }
    return Collections.unmodifiableMap(json);
  }

  /**
   * Records one path-free review-trust transparency event.
   *
   * @param kind fixed transparency event kind
   * @param candidate exact candidate that reached the gate
   * @param phase bounded lifecycle phase identifier
   */
  private void recordGate(
      AppReviewTransparencyEventKind kind, AppUpdateCandidate candidate, String phase) {
    reviewTransparencyLog()
        .recordReviewTrustMap(
            kind,
            new AppReviewTransparencyLog.ReviewTrustMapSubject(
                candidate.appId(),
                candidate.targetVersion(),
                candidate.catalogId(),
                candidate.bundleSha256(),
                candidate.bundleSizeBytes()),
            candidate.reviewTrust(),
            List.of("phase=" + phase));
  }

  /**
   * Returns the configured transparency log or a disabled no-op implementation.
   *
   * @return non-null transparency log implementation
   */
  private AppReviewTransparencyLog reviewTransparencyLog() {
    AppReviewTransparencyLog log = catalogManager.reviewTransparencyLog();
    return log == null ? AppReviewTransparencyLog.disabled() : log;
  }

  /**
   * Requires the federation reviewer policy installed during runtime composition.
   *
   * @return configured non-null catalog-scoped reviewer policy
   */
  private CatalogScopedReviewerPolicy requireScopedReviewerPolicy() {
    return Objects.requireNonNull(
        scopedReviewerPolicy, "federated catalog reviewer policy is not configured");
  }

  /**
   * Loads the current reviewer registry, replacing a null provider result with an empty registry.
   *
   * @return current non-null reviewer-key registry
   * @throws IOException if configured reviewer-key material cannot be read
   */
  private TrustedReviewerKeys currentReviewerKeys() throws IOException {
    return Objects.requireNonNullElse(
        reviewerKeysProvider.trustedReviewerKeys(), TrustedReviewerKeys.empty());
  }

  /**
   * Loads reviewer keys for a summary and fails closed to an empty registry.
   *
   * @return current reviewer keys, or an empty registry on read failure
   */
  private TrustedReviewerKeys trustedReviewerKeysOrEmpty() {
    try {
      return reviewerKeysProvider.trustedReviewerKeys();
    } catch (AppCatalogException | IOException _) {
      return TrustedReviewerKeys.empty();
    }
  }

  /**
   * Creates a stable Platform API lifecycle failure.
   *
   * @param statusCode HTTP status associated with the failure
   * @param errorCode stable machine-readable lifecycle code
   * @param message bounded operator-facing explanation
   * @return constructed Platform API exception
   */
  private static PlatformApiException lifecycleFailure(
      int statusCode, String errorCode, String message) {
    return new PlatformApiException(statusCode, errorCode, message);
  }
}
