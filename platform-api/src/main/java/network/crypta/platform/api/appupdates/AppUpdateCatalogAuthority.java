package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Coordinates candidate evaluation with the independent reviewer authority.
 *
 * <p>This facade keeps catalog candidate construction and reviewer authorization behind one
 * lifecycle dependency. It delegates catalog scanning, version comparison, security summaries, and
 * retained-plan comparison to {@link AppUpdateCandidateEvaluator}. Review-receipt evaluation, gate
 * recording, and routine or historical reviewer leases remain with {@link
 * AppUpdateReviewAuthority}.
 *
 * <p>The split preserves role separation without requiring {@link AppUpdateService} to coordinate
 * the two helpers directly. A configured catalog-scoped reviewer policy is shared by candidate
 * summaries and final mutation authorization. The class holds no candidate cache; each operation
 * uses the caller's installed snapshot and current catalog state. Thread-safety therefore follows
 * the injected AppHost, catalog manager, and reviewer authority implementations.
 */
final class AppUpdateCatalogAuthority {
  /** Reviewer authority used for receipt decisions and retained authorization leases. */
  private final AppUpdateReviewAuthority reviewAuthority;

  /** Candidate evaluator that converts authenticated catalog entries to lifecycle results. */
  private final AppUpdateCandidateEvaluator candidateEvaluator;

  /**
   * Creates the combined catalog and reviewer authority.
   *
   * @param appHost host service used to inspect installed applications
   * @param catalogManager manager for authenticated catalog operations
   * @param reviewPolicy local review-receipt acceptance policy
   * @param reviewerKeysProvider provider for the current reviewer registry
   */
  AppUpdateCatalogAuthority(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      AppUpdateService.ReviewerKeysProvider reviewerKeysProvider) {
    reviewAuthority =
        new AppUpdateReviewAuthority(catalogManager, reviewPolicy, reviewerKeysProvider);
    candidateEvaluator = new AppUpdateCandidateEvaluator(appHost, catalogManager, reviewAuthority);
  }

  /**
   * Replaces the optional catalog-scoped reviewer policy.
   *
   * @param policy scoped reviewer policy, or {@code null} for legacy review behavior
   */
  void setScopedReviewerPolicy(CatalogScopedReviewerPolicy policy) {
    reviewAuthority.setScopedReviewerPolicy(policy);
  }

  /**
   * Returns the currently configured catalog-scoped reviewer policy.
   *
   * @return configured scoped policy, or an empty value in compatibility mode
   */
  Optional<CatalogScopedReviewerPolicy> scopedReviewerPolicy() {
    return reviewAuthority.scopedReviewerPolicy();
  }

  /**
   * Evaluates review trust for one authenticated catalog entry.
   *
   * @param catalogId normalized source catalog identifier
   * @param entry authenticated entry whose review receipt is evaluated
   * @return stable JSON-compatible review-trust summary
   */
  Map<String, Object> reviewTrust(String catalogId, AppCatalogEntry entry) {
    return reviewAuthority.reviewTrust(catalogId, entry);
  }

  /**
   * Records the reviewer gate for an operator-driven update phase.
   *
   * @param candidate candidate whose review status is enforced
   * @param phase bounded lifecycle phase recorded for diagnostics
   */
  void recordUpdateGate(AppUpdateCandidate candidate, String phase) {
    reviewAuthority.recordUpdateGate(candidate, phase);
  }

  /**
   * Records the reviewer gate for a policy-driven apply phase.
   *
   * @param candidate candidate whose review status is enforced
   * @param phase bounded lifecycle phase recorded for diagnostics
   */
  void recordPolicyApplyGate(AppUpdateCandidate candidate, String phase) {
    reviewAuthority.recordPolicyApplyGate(candidate, phase);
  }

  /**
   * Retains current reviewer authorization for a routine catalog mutation.
   *
   * @param plan exact retained catalog install plan
   * @param targetOrigin provenance that will accompany the committed bundle
   * @param install whether the mutation creates a new installation
   * @return lease that retains the current scoped reviewer authorization
   * @throws IOException if reviewer policy state cannot be read safely
   */
  AppHost.CatalogMutationAuthorizationLease retainRoutineAuthorization(
      AppCatalogInstallPlan plan, InstalledAppOrigin targetOrigin, boolean install)
      throws IOException {
    return reviewAuthority.retainRoutineAuthorization(plan, targetOrigin, install);
  }

  /**
   * Retains current historical reviewer authorization for rollback.
   *
   * @param origin exact retained provenance subject
   * @param entry retained catalog entry corresponding to the bundle
   * @return lease that retains historical reviewer authorization through commit
   * @throws IOException if reviewer policy state cannot be read safely
   */
  AppHost.CatalogMutationAuthorizationLease retainHistoricalAuthorization(
      InstalledAppOrigin origin, AppCatalogEntry entry) throws IOException {
    return reviewAuthority.retainHistoricalAuthorization(origin, entry);
  }

  /**
   * Lists ordinary update candidates from currently usable catalogs.
   *
   * @param appId exact application identifier to locate
   * @param installed current installed application snapshot
   * @param policy local update-selection policy
   * @param refresh whether sources should be refreshed before evaluation
   * @return immutable candidates from usable catalogs
   */
  List<AppUpdateCandidate> catalogCandidates(
      String appId, InstalledAppSnapshot installed, AppUpdatePolicy policy, boolean refresh) {
    return candidateEvaluator.catalogCandidates(appId, installed, policy, refresh);
  }

  /**
   * Lists complete catalog subjects for conflict classification.
   *
   * @param appId exact application identifier to locate
   * @param installed current installation, or {@code null} when absent
   * @return immutable conflict candidates from usable catalogs
   */
  List<AppUpdateCandidate> catalogConflictCandidates(String appId, InstalledAppSnapshot installed) {
    return candidateEvaluator.catalogConflictCandidates(appId, installed);
  }

  /**
   * Selects a candidate from one exact operator-selected catalog.
   *
   * @param appId exact application identifier to locate
   * @param installed current installed application snapshot
   * @param policy local update-selection policy
   * @param targetCatalogId normalized operator-selected catalog identifier
   * @return matching candidate, or {@code null} when it is unavailable
   */
  AppUpdateCandidate explicitCatalogCandidate(
      String appId,
      InstalledAppSnapshot installed,
      AppUpdatePolicy policy,
      String targetCatalogId) {
    return candidateEvaluator.explicitCatalogCandidate(appId, installed, policy, targetCatalogId);
  }

  /**
   * Builds one conflict subject from an authenticated catalog entry.
   *
   * @param catalogId normalized source catalog identifier
   * @param entry authenticated catalog entry to classify
   * @param installed current installation, or {@code null} when absent
   * @return complete conflict candidate for the supplied entry
   */
  AppUpdateCandidate conflictCandidate(
      String catalogId, AppCatalogEntry entry, InstalledAppSnapshot installed) {
    return candidateEvaluator.conflictCandidate(catalogId, entry, installed);
  }

  /**
   * Returns a catalog-local security-decision summary.
   *
   * @param catalogId normalized catalog identifier
   * @param appId exact application identifier to evaluate
   * @return stable JSON-compatible catalog security decision
   */
  Map<String, Object> catalogSecurityDecision(String catalogId, String appId) {
    return candidateEvaluator.catalogSecurityDecision(catalogId, appId);
  }

  /**
   * Returns the aggregate installed-version security-decision summary.
   *
   * @param appId exact application identifier to evaluate
   * @param version exact installed version to evaluate
   * @return stable JSON-compatible aggregate security decision
   */
  Map<String, Object> installedSecurityDecision(String appId, String version) {
    return candidateEvaluator.installedSecurityDecision(appId, version);
  }

  /**
   * Returns the combined security decision for one target entry.
   *
   * @param catalogId normalized source catalog identifier
   * @param entry authenticated target catalog entry
   * @return stable JSON-compatible combined security decision
   */
  Map<String, Object> targetSecurityDecision(String catalogId, AppCatalogEntry entry) {
    return candidateEvaluator.targetSecurityDecision(catalogId, entry);
  }

  /**
   * Builds the no-update candidate for an installed application.
   *
   * @param appId exact installed application identifier
   * @param installed current installed application snapshot
   * @return candidate that describes the unchanged installation
   */
  AppUpdateCandidate none(String appId, InstalledAppSnapshot installed) {
    return candidateEvaluator.none(appId, installed);
  }

  /**
   * Reports whether a retained plan differs from a presented candidate.
   *
   * @param candidate candidate previously presented by the lifecycle
   * @param installed current installed application snapshot
   * @param plan retained catalog plan being revalidated
   * @return {@code true} when a material candidate subject changed
   */
  boolean planDiffers(
      AppUpdateCandidate candidate, InstalledAppSnapshot installed, AppCatalogInstallPlan plan) {
    return candidateEvaluator.planDiffers(candidate, installed, plan);
  }
}
