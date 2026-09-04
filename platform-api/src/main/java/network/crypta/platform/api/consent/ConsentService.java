package network.crypta.platform.api.consent;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppDataMigrationPlan;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.appcatalog.AppCatalogEntry;

/**
 * Coordinates operator consent for material app-platform mutations.
 *
 * <p>The service builds redacted, JSON-compatible consent snapshots for app installs,
 * catalog-backed updates, app-update staging, app-service grant bundles, and app-data migration
 * review. Each snapshot is assigned a request id and a digest over the material review surface.
 * Later mutation routes use those values to prove that the operator approved the same catalog
 * entry, candidate bundle, review evidence, permission delta, advisory set, and migration plan they
 * are about to apply.
 *
 * <p>Stored requests and decisions are intentionally short-lived and process local. Approvals are
 * consumed when a protected mutation succeeds, expire after the consent TTL if unused, and are
 * written to the configured {@link ConsentAuditStore} with only redacted identifiers and reason
 * codes. Domain services remain responsible for their own state-machine checks; consent here only
 * decides whether an otherwise valid material action needs an operator decision.
 */
public final class ConsentService {
  private static final String PARAM_CONSENT_REQUEST_ID = "consentRequestId";
  private static final String PARAM_SNAPSHOT_DIGEST = "snapshotDigest";
  private static final String PARAM_CONSENT_SNAPSHOT_DIGEST = "consentSnapshotDigest";
  private static final String PARAM_REVIEW_ACKNOWLEDGED = "reviewAcknowledged";
  private static final String PARAM_SECURITY_ACKNOWLEDGED = "securityAcknowledged";
  private static final String PARAM_MIGRATION_ACKNOWLEDGED = "migrationAcknowledged";
  private static final String LOCAL_OPERATOR = "local_operator";
  private static final Duration STORED_CONSENT_TTL = Duration.ofMinutes(15);
  private static final int MAX_STORED_REQUESTS = 512;
  private static final int MAX_STORED_DECISIONS = 512;
  private static final String FIELD_APP_ID = "appId";
  private static final String FIELD_BLOCKS_INSTALL = "blocksInstall";
  private static final String FIELD_BLOCKS_UPDATE = "blocksUpdate";
  private static final String FIELD_CATALOG_ID = "catalogId";
  private static final String FIELD_CATALOG_SOURCE_ID = "catalogSourceId";
  private static final String FIELD_CHANNEL = "channel";
  private static final String FIELD_CONSUMER_APP_ID = "consumerAppId";
  private static final String FIELD_DATA_MIGRATION = "dataMigration";
  private static final String FIELD_DEPRECATION = "deprecation";
  private static final String FIELD_EXPERIMENTAL_CAPABILITIES_ACCEPTED =
      "experimentalCapabilitiesAccepted";
  private static final String FIELD_INSTALLED_VERSION = "installedVersion";
  private static final String FIELD_NAME = "name";
  private static final String FIELD_PERMISSION_DELTA = "permissionDelta";
  private static final String FIELD_POSITIVE = "positive";
  private static final String FIELD_REQUIRED = "required";
  private static final String FIELD_REQUIRES_ACKNOWLEDGEMENT = "requiresAcknowledgement";
  private static final String FIELD_REVIEWER_KEY_ID = "reviewerKeyId";
  private static final String FIELD_SECURITY_ADVISORIES = "securityAdvisories";
  private static final String FIELD_SECURITY_DECISION = "securityDecision";
  private static final String FIELD_STATUS = "status";
  private static final String FIELD_SUPPORT_STATUS = "supportStatus";
  private static final String FIELD_TARGET_STABILITY = "targetStability";
  private static final String FIELD_TARGET_VERSION = "targetVersion";
  private static final String FIELD_VERSION = "version";
  private static final String ERROR_CONSENT_BLOCKED = "consent_blocked";
  private static final String ERROR_STALE_CONSENT_SNAPSHOT = "stale_consent_snapshot";
  private static final String FINDING_BUNDLE_DIGEST = "bundle_digest";
  private static final String LABEL_BUNDLE_DIGEST = "Bundle digest";
  private static final String MESSAGE_CONSENT_BLOCKED =
      "This app-platform action is blocked by the current consent policy.";
  private static final String MESSAGE_STALE_CONSENT =
      "This approval is stale. Refresh the consent preview.";
  private static final String SECTION_IDENTITY = "identity";
  private static final String SUMMARY_NO_BUNDLE_DIGEST = "No bundle digest declared.";
  private static final String TITLE_UPDATE_CANDIDATE = "Update candidate";
  private static final String VALUE_ADDED = "added";
  private static final String VALUE_AVAILABLE = "available";
  private static final String VALUE_CANDIDATE = "candidate";
  private static final String VALUE_CHANGED = "changed";
  private static final String VALUE_NONE = "none";
  private static final String VALUE_STABLE = "stable";
  private static final String VALUE_SUPPORTED = "supported";
  private static final String VALUE_UNCHANGED = "unchanged";
  private static final String VALUE_UNKNOWN = "unknown";
  private static final String VALUE_UNSUPPORTED_BASELINE = "unsupported-baseline";

  private final AppCatalogsApiHandler catalogHandler;
  private final AppUpdateService updateService;
  private final AppServiceCoordinator appServiceCoordinator;
  private final ConsentAuditStore auditStore;
  private final Clock clock;
  private final AtomicLong requestSequence = new AtomicLong();
  private final AtomicLong decisionSequence = new AtomicLong();
  private final Map<String, ConsentRequest> requests = new LinkedHashMap<>();
  private final Map<String, ConsentDecision> decisionsByRequestId = new LinkedHashMap<>();

  /**
   * Creates a consent service backed by process-local audit storage and the system UTC clock.
   *
   * <p>This constructor is used by the default Platform API wiring when durable audit persistence
   * is not configured. Preview requests and approval decisions are still retained only in memory,
   * so a daemon restart clears pending approvals and forces the operator to refresh consent
   * snapshots.
   *
   * @param catalogHandler catalog handler used to summarize install and catalog-update candidates
   * @param updateService app-update service used to summarize read-only and prepared update
   *     candidates
   * @param appServiceCoordinator coordinator used to summarize app-service grant bundles
   */
  public ConsentService(
      AppCatalogsApiHandler catalogHandler,
      AppUpdateService updateService,
      AppServiceCoordinator appServiceCoordinator) {
    this(
        catalogHandler,
        updateService,
        appServiceCoordinator,
        new InMemoryConsentAuditStore(),
        Clock.systemUTC());
  }

  /**
   * Creates a consent service with explicit audit and clock dependencies.
   *
   * <p>Tests and alternate host embeddings use this constructor to provide deterministic time and a
   * durable or inspectable audit sink. The catalog, update, and app-service dependencies may be
   * absent in embeddings that expose only part of the app platform; routes that require a missing
   * dependency fail closed with a service-unavailable Platform API error.
   *
   * @param catalogHandler catalog handler used for install and catalog-update consent snapshots
   * @param updateService app-update service used for update consent snapshots
   * @param appServiceCoordinator coordinator used for app-service grant consent snapshots
   * @param auditStore store that receives redacted decision and expiry audit events
   * @param clock clock used for request ids, decision timestamps, and TTL pruning
   */
  public ConsentService(
      AppCatalogsApiHandler catalogHandler,
      AppUpdateService updateService,
      AppServiceCoordinator appServiceCoordinator,
      ConsentAuditStore auditStore,
      Clock clock) {
    this.catalogHandler = catalogHandler;
    this.updateService = updateService;
    this.appServiceCoordinator = appServiceCoordinator;
    this.auditStore = Objects.requireNonNull(auditStore, "auditStore");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Builds and registers an installation consent preview.
   *
   * <p>The preview describes the catalog entry's identity, bundle digest, channel/support metadata,
   * independent review evidence, security advisories, permissions, API stability, and declared data
   * policies. The returned map is safe to serialize directly as a Platform API JSON response.
   *
   * @param catalogId catalog that contains the candidate app entry
   * @param appId app id being installed
   * @return registered consent snapshot as a JSON-compatible map
   */
  public synchronized Map<String, Object> installPreview(String catalogId, String appId) {
    return register(buildInstallSnapshot(catalogId, appId)).snapshot().toJsonValue();
  }

  /**
   * Builds and registers an update consent preview using the prepared candidate path.
   *
   * <p>Prepared previews may refresh catalogs and ask the update service to prepare the
   * installation plan so app-data migration and backup requirements are included in the digest. Use
   * this path when an operator explicitly opens the review flow and expects the preview to match
   * the subsequent stage request.
   *
   * @param appId installed app id being updated
   * @param refreshCatalogs whether the update service should refresh catalogs before summarizing
   * @return registered consent snapshot as a JSON-compatible map
   */
  public synchronized Map<String, Object> updatePreview(String appId, boolean refreshCatalogs) {
    return register(buildUpdateSnapshot(appId, refreshCatalogs, true)).snapshot().toJsonValue();
  }

  /**
   * Builds and registers an update preview without catalog refresh or bundle preparation.
   *
   * <p>The read-only preview is used for status and discovery views where rendering consent
   * information must not download bundles, allocate staging resources, or invalidate existing
   * staged state. It can still report catalog, review, permission, security, and compatibility risk
   * that is already available from the detected candidate.
   *
   * @param appId installed app id whose current update candidate should be summarized
   * @return registered read-only consent snapshot as a JSON-compatible map
   */
  public synchronized Map<String, Object> updatePreviewReadOnly(String appId) {
    return register(buildUpdateSnapshot(appId, false, false)).snapshot().toJsonValue();
  }

  /**
   * Builds and registers a catalog-update consent preview.
   *
   * <p>This preview is for catalog-driven replacement of an installed app entry outside the update
   * scheduler path. It compares installed and candidate metadata, then records the same
   * digest-bound review surface used by installation consent before the catalog handler prepares
   * the final plan.
   *
   * @param catalogId catalog containing the replacement entry
   * @param appId installed app id being updated from the catalog
   * @return registered consent snapshot as a JSON-compatible map
   */
  public synchronized Map<String, Object> catalogUpdatePreview(String catalogId, String appId) {
    return register(buildCatalogUpdateSnapshot(catalogId, appId)).snapshot().toJsonValue();
  }

  /**
   * Builds and registers an app-service grant-bundle preview.
   *
   * <p>The preview summarizes the requesting app, dependency providers, requested scopes, expiry
   * metadata, and audit impact for a pending grant bundle. Approving this preview authorizes the
   * corresponding service-grant state transition only if the bundle still matches the digest.
   *
   * @param bundleId grant bundle id to review
   * @return registered consent snapshot as a JSON-compatible map
   */
  public synchronized Map<String, Object> serviceGrantPreview(String bundleId) {
    return register(buildServiceGrantSnapshot(bundleId)).snapshot().toJsonValue();
  }

  /**
   * Records an approval decision for a registered preview request.
   *
   * <p>The request id and supplied snapshot digest must identify a live preview. Blocking snapshots
   * cannot be approved, and stale digests are rejected so catalog or candidate changes force a
   * fresh review.
   *
   * @param queryParameters Platform API query parameters containing the consent request id and
   *     snapshot digest
   * @param principal authenticated actor recording the decision
   * @return recorded decision as a JSON-compatible map
   */
  public synchronized Map<String, Object> approve(
      Map<String, List<String>> queryParameters, PlatformApiPrincipal principal) {
    return decide(queryParameters, principal, ConsentDecisionStatus.APPROVED).toJsonValue();
  }

  /**
   * Records a rejection decision for a registered preview request.
   *
   * <p>Rejections are retained in the audit stream for operator traceability but do not authorize
   * any protected mutation. A later attempt to continue must create and approve a fresh preview.
   *
   * @param queryParameters Platform API query parameters containing the consent request id and
   *     snapshot digest
   * @param principal authenticated actor recording the decision
   * @return recorded decision as a JSON-compatible map
   */
  public synchronized Map<String, Object> reject(
      Map<String, List<String>> queryParameters, PlatformApiPrincipal principal) {
    return decide(queryParameters, principal, ConsentDecisionStatus.REJECTED).toJsonValue();
  }

  /**
   * Records a deferral decision for a registered preview request.
   *
   * <p>Deferral preserves the fact that the operator saw the preview without turning it into an
   * approval. It is useful for UI flows that need an explicit "not now" audit event.
   *
   * @param queryParameters Platform API query parameters containing the consent request id and
   *     snapshot digest
   * @param principal authenticated actor recording the decision
   * @return recorded decision as a JSON-compatible map
   */
  public synchronized Map<String, Object> defer(
      Map<String, List<String>> queryParameters, PlatformApiPrincipal principal) {
    return decide(queryParameters, principal, ConsentDecisionStatus.DEFERRED).toJsonValue();
  }

  /**
   * Lists redacted consent audit events.
   *
   * <p>The returned events contain decision ids, actors, app ids, action types, status values,
   * digests, timestamps, and blocking reason codes. They intentionally omit raw catalog JSON,
   * app-data paths, local file locations, service tokens, and other sensitive preview details.
   *
   * @param appId optional app id filter; {@code null} lists all retained events
   * @return audit events as JSON-compatible maps in store order
   */
  public synchronized List<Map<String, Object>> audit(String appId) {
    return auditStore.list(appId).stream().map(ConsentAuditEvent::toJsonValue).toList();
  }

  /**
   * Verifies the current installation preview if material consent is required.
   *
   * <p>When verification succeeds, legacy review/security acknowledgement parameters are added so
   * the existing catalog gate can continue to fail closed on hard blocks and prepared-plan drift.
   *
   * @param catalogId catalog containing the app entry about to be installed
   * @param appId app id about to be installed
   * @param queryParameters original mutation query parameters
   * @param principal authenticated caller attempting the mutation
   * @return query parameters augmented with legacy acknowledgement flags when consent was required
   */
  public synchronized Map<String, List<String>> requireApprovedInstallIfRequired(
      String catalogId,
      String appId,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    ConsentSnapshot current = buildInstallSnapshot(catalogId, appId);
    requireApprovedIfNeeded(current, queryParameters, principal, false);
    return current.requiresApproval() ? acknowledged(queryParameters) : queryParameters;
  }

  /**
   * Verifies that the prepared installation plan still matches the approved installation snapshot.
   *
   * <p>This second check runs after the catalog handler has materialized the installation plan,
   * catching bundle digest, review evidence, advisory, permission, or metadata drift between the
   * operator preview and the prepared app entry.
   *
   * @param catalogId catalog containing the prepared entry
   * @param entry prepared app catalog entry about to be committed
   * @param queryParameters original mutation query parameters
   * @param principal authenticated caller attempting the mutation
   */
  public synchronized void requireApprovedPreparedInstallIfRequired(
      String catalogId,
      AppCatalogEntry entry,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    ConsentSnapshot current = buildPreparedInstallSnapshot(catalogId, entry);
    requireApprovedIfNeeded(current, queryParameters, principal);
  }

  /**
   * Verifies update consent before an app update is staged.
   *
   * <p>The method first evaluates a read-only snapshot to avoid preparing update resources for
   * callers that have not supplied a valid approval. If material or prepared-only risk is possible,
   * it then requires a matching approval before building the prepared snapshot that includes
   * app-data migration and backup details. Successful material approvals are translated into the
   * legacy acknowledgement flags expected by the update service.
   *
   * @param appId installed app id being staged for update
   * @param queryParameters original mutation query parameters
   * @param principal authenticated caller attempting the mutation
   * @return query parameters with stale acknowledgement flags stripped or fresh acknowledgement
   *     flags added as appropriate
   */
  public synchronized Map<String, List<String>> requireApprovedUpdateIfRequired(
      String appId, Map<String, List<String>> queryParameters, PlatformApiPrincipal principal) {
    UpdateConsentSnapshot readOnlyResult = buildUpdateSnapshotWithCandidate(appId, false, false);
    if (isNonStageableUpdateCandidate(readOnlyResult.candidate())) {
      return withoutAcknowledgements(queryParameters);
    }
    ConsentSnapshot readOnly = readOnlyResult.snapshot();
    boolean approvalSupplied = hasConsentApprovalParameters(queryParameters);
    boolean preparedConsentRequired = preparedUpdateConsentRequired(readOnlyResult.candidate());
    if (!readOnly.requiresApproval() && !approvalSupplied && !preparedConsentRequired) {
      requireApprovedIfNeeded(readOnly, queryParameters, principal);
      return withoutAcknowledgements(queryParameters);
    }
    if (!readOnly.requiresApproval() && !approvalSupplied && !principal.isApp()) {
      ConsentSnapshot current = buildUpdateSnapshot(appId, false, true);
      requireApprovedIfNeeded(current, queryParameters, principal);
      return current.requiresApproval()
          ? acknowledged(queryParameters)
          : withoutAcknowledgements(queryParameters);
    }
    requireApprovedBeforePreparingUpdatePreview(readOnly, queryParameters, principal);
    ConsentSnapshot current = buildUpdateSnapshot(appId, false, true);
    requireApprovedIfNeeded(current, queryParameters, principal);
    return current.requiresApproval()
        ? acknowledged(queryParameters)
        : withoutAcknowledgements(queryParameters);
  }

  /**
   * Verifies catalog-update consent before a catalog-backed replacement starts.
   *
   * <p>The check preserves the catalog handler's own install/update state validation while ensuring
   * any material catalog, review, security, permission, or API-stability risk has a matching
   * operator approval for the current snapshot.
   *
   * @param catalogId catalog containing the replacement entry
   * @param appId installed app id being updated
   * @param queryParameters original mutation query parameters
   * @param principal authenticated caller attempting the mutation
   * @return query parameters augmented with legacy acknowledgement flags when consent was required
   */
  public synchronized Map<String, List<String>> requireApprovedCatalogUpdateIfRequired(
      String catalogId,
      String appId,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    ConsentSnapshot current = buildCatalogUpdateSnapshot(catalogId, appId);
    requireApprovedIfNeeded(current, queryParameters, principal, false);
    return current.requiresApproval() ? acknowledged(queryParameters) : queryParameters;
  }

  /**
   * Verifies that the prepared catalog-update plan still matches the approved snapshot.
   *
   * <p>The prepared check binds the final app entry to the same consent digest the operator
   * approved before the catalog handler commits the replacement.
   *
   * @param catalogId catalog containing the prepared replacement entry
   * @param entry prepared app catalog entry about to be committed
   * @param queryParameters original mutation query parameters
   * @param principal authenticated caller attempting the mutation
   */
  public synchronized void requireApprovedPreparedCatalogUpdateIfRequired(
      String catalogId,
      AppCatalogEntry entry,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    ConsentSnapshot current = buildPreparedCatalogUpdateSnapshot(catalogId, entry);
    requireApprovedIfNeeded(current, queryParameters, principal);
  }

  /**
   * Verifies app-service grant-bundle consent before approval or renewal.
   *
   * <p>The current bundle summary is hashed at verification time so dependency, scope, status, or
   * expiry changes after the preview invalidate the approval and force a fresh operator review.
   *
   * @param bundleId grant bundle id being approved or renewed
   * @param queryParameters original mutation query parameters
   * @param principal authenticated caller attempting the mutation
   */
  public synchronized void requireApprovedServiceGrantIfRequired(
      String bundleId, Map<String, List<String>> queryParameters, PlatformApiPrincipal principal) {
    ConsentSnapshot current = buildServiceGrantSnapshot(bundleId);
    requireApprovedIfNeeded(current, queryParameters, principal);
  }

  /**
   * Adds a redacted audit event for a direct service-grant rejection path.
   *
   * <p>Some service-grant state transitions can reject a bundle without first creating an explicit
   * consent decision through the consent routes. This method records an equivalent rejection event
   * using the current bundle snapshot so operator audit history remains complete.
   *
   * @param bundleId grant bundle id rejected by the app-service route
   * @param principal authenticated actor that rejected the bundle
   */
  public synchronized void recordServiceGrantRejection(
      String bundleId, PlatformApiPrincipal principal) {
    ConsentSnapshot snapshot = buildServiceGrantSnapshot(bundleId);
    ConsentDecision decision =
        new ConsentDecision(
            nextDecisionId(),
            snapshot.consentRequestId(),
            ConsentDecisionStatus.REJECTED,
            actor(principal),
            snapshot.snapshotDigest(),
            Instant.now(clock));
    auditStore.append(toAuditEvent(snapshot, decision));
  }

  private void requireApprovedIfNeeded(
      ConsentSnapshot current,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    requireApprovedIfNeeded(current, queryParameters, principal, true);
  }

  private void requireApprovedIfNeeded(
      ConsentSnapshot current,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal,
      boolean consumeDecision) {
    pruneStoredConsent(Instant.now(clock));
    if (!current.requiresApproval()) {
      consumeApprovedDecisionIfSupplied(queryParameters);
      return;
    }
    if (current.riskLevel() == ConsentRiskLevel.BLOCKING) {
      throw new PlatformApiException(409, ERROR_CONSENT_BLOCKED, MESSAGE_CONSENT_BLOCKED);
    }
    String requestId =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_CONSENT_REQUEST_ID);
    String suppliedDigest = snapshotDigestParameter(queryParameters);
    if (requestId == null || suppliedDigest == null) {
      throw new PlatformApiException(
          409,
          "consent_required",
          "This app-platform action requires an approved consent preview.");
    }
    ConsentDecision decision = decisionsByRequestId.get(requestId);
    if (decision == null || decision.status() != ConsentDecisionStatus.APPROVED) {
      throw new PlatformApiException(
          409, "consent_not_approved", "The consent request has not been approved.");
    }
    if (!suppliedDigest.equals(decision.snapshotDigest())
        || !suppliedDigest.equals(current.snapshotDigest())) {
      throw new PlatformApiException(409, ERROR_STALE_CONSENT_SNAPSHOT, MESSAGE_STALE_CONSENT);
    }
    if (!actor(principal).equals(decision.actor()) && principal.isApp()) {
      throw new PlatformApiException(
          403, "host_operator_required", "This consent decision requires a host/operator.");
    }
    if (consumeDecision) {
      consumeConsentRequest(requestId);
    }
  }

  private void requireApprovedBeforePreparingUpdatePreview(
      ConsentSnapshot readOnly,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    pruneStoredConsent(Instant.now(clock));
    if (readOnly.riskLevel() == ConsentRiskLevel.BLOCKING) {
      throw new PlatformApiException(409, ERROR_CONSENT_BLOCKED, MESSAGE_CONSENT_BLOCKED);
    }
    String requestId =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_CONSENT_REQUEST_ID);
    String suppliedDigest = snapshotDigestParameter(queryParameters);
    if (requestId == null || suppliedDigest == null) {
      throw new PlatformApiException(
          409,
          "consent_required",
          "This app-platform action requires an approved consent preview.");
    }
    ConsentDecision decision = decisionsByRequestId.get(requestId);
    if (decision == null || decision.status() != ConsentDecisionStatus.APPROVED) {
      throw new PlatformApiException(
          409, "consent_not_approved", "The consent request has not been approved.");
    }
    if (!suppliedDigest.equals(decision.snapshotDigest())) {
      throw new PlatformApiException(409, ERROR_STALE_CONSENT_SNAPSHOT, MESSAGE_STALE_CONSENT);
    }
    if (!actor(principal).equals(decision.actor()) && principal.isApp()) {
      throw new PlatformApiException(
          403, "host_operator_required", "This consent decision requires a host/operator.");
    }
  }

  private void consumeApprovedDecisionIfSupplied(Map<String, List<String>> queryParameters) {
    String requestId =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_CONSENT_REQUEST_ID);
    String suppliedDigest = snapshotDigestParameter(queryParameters);
    if (requestId == null || suppliedDigest == null) {
      return;
    }
    ConsentDecision decision = decisionsByRequestId.get(requestId);
    if (decision != null
        && decision.status() == ConsentDecisionStatus.APPROVED
        && suppliedDigest.equals(decision.snapshotDigest())) {
      consumeConsentRequest(requestId);
    }
  }

  private ConsentDecision decide(
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal,
      ConsentDecisionStatus status) {
    pruneStoredConsent(Instant.now(clock));
    String requestId =
        PlatformApiParameters.requireString(queryParameters, PARAM_CONSENT_REQUEST_ID);
    String suppliedDigest = snapshotDigestParameter(queryParameters);
    if (suppliedDigest == null) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Missing required query parameter 'snapshotDigest'.");
    }
    ConsentRequest request = requests.get(requestId);
    if (request == null) {
      throw new PlatformApiException(
          404, "consent_request_not_found", "Consent request not found.");
    }
    ConsentSnapshot snapshot = request.snapshot();
    if (!suppliedDigest.equals(snapshot.snapshotDigest())) {
      throw new PlatformApiException(409, ERROR_STALE_CONSENT_SNAPSHOT, MESSAGE_STALE_CONSENT);
    }
    if (status == ConsentDecisionStatus.APPROVED
        && snapshot.riskLevel() == ConsentRiskLevel.BLOCKING) {
      throw new PlatformApiException(409, ERROR_CONSENT_BLOCKED, MESSAGE_CONSENT_BLOCKED);
    }
    ConsentDecision decision =
        new ConsentDecision(
            nextDecisionId(),
            requestId,
            status,
            actor(principal),
            suppliedDigest,
            Instant.now(clock));
    auditStore.append(toAuditEvent(snapshot, decision));
    if (status == ConsentDecisionStatus.APPROVED) {
      decisionsByRequestId.put(requestId, decision);
    } else {
      consumeConsentRequest(requestId);
    }
    return decision;
  }

  private ConsentAuditEvent toAuditEvent(ConsentSnapshot snapshot, ConsentDecision decision) {
    return new ConsentAuditEvent(
        decision.decisionId(),
        decision.consentRequestId(),
        decision.actor(),
        snapshot.appId(),
        snapshot.action(),
        decision.status(),
        decision.decidedAt(),
        decision.snapshotDigest(),
        snapshot.blockingReasons());
  }

  private ConsentRequest register(ConsentSnapshot snapshot) {
    pruneStoredConsent(Instant.now(clock));
    ConsentRequest request =
        new ConsentRequest(snapshot.consentRequestId(), snapshot, snapshot.createdAt());
    requests.put(request.requestId(), request);
    pruneStoredConsent(Instant.now(clock));
    return request;
  }

  private void consumeConsentRequest(String requestId) {
    decisionsByRequestId.remove(requestId);
    requests.remove(requestId);
  }

  private void pruneStoredConsent(Instant now) {
    List<String> expiredDecisionIds =
        decisionsByRequestId.entrySet().stream()
            .filter(entry -> expired(entry.getValue().decidedAt(), now))
            .map(Map.Entry::getKey)
            .toList();
    expiredDecisionIds.forEach(requestId -> expireDecision(requestId, now));
    List<String> expiredRequestIds =
        requests.entrySet().stream()
            .filter(entry -> expired(entry.getValue().createdAt(), now))
            .filter(entry -> lacksFreshApprovedDecision(entry.getKey(), now))
            .map(Map.Entry::getKey)
            .toList();
    expiredRequestIds.forEach(requestId -> expireRequest(requestId, now));
    trimStoredConsent(now);
  }

  private void trimStoredConsent(Instant now) {
    while (decisionsByRequestId.size() > MAX_STORED_DECISIONS) {
      expireDecision(decisionsByRequestId.keySet().iterator().next(), now);
    }
    while (requests.size() > MAX_STORED_REQUESTS) {
      String requestId =
          requests.keySet().stream()
              .filter(candidate -> lacksFreshApprovedDecision(candidate, now))
              .findFirst()
              .orElse(null);
      if (requestId == null) {
        break;
      }
      expireRequest(requestId, now);
    }
  }

  private boolean lacksFreshApprovedDecision(String requestId, Instant now) {
    ConsentDecision decision = decisionsByRequestId.get(requestId);
    return decision == null
        || decision.status() != ConsentDecisionStatus.APPROVED
        || expired(decision.decidedAt(), now);
  }

  private void expireRequest(String requestId, Instant now) {
    ConsentDecision decision = decisionsByRequestId.remove(requestId);
    ConsentRequest request = requests.remove(requestId);
    appendExpiredApprovalAudit(request, decision, now);
  }

  private void expireDecision(String requestId, Instant now) {
    expireRequest(requestId, now);
  }

  private void appendExpiredApprovalAudit(
      ConsentRequest request, ConsentDecision decision, Instant now) {
    if (request == null
        || decision == null
        || decision.status() != ConsentDecisionStatus.APPROVED) {
      return;
    }
    ConsentDecision expiredDecision =
        new ConsentDecision(
            nextDecisionId(),
            decision.consentRequestId(),
            ConsentDecisionStatus.EXPIRED,
            decision.actor(),
            decision.snapshotDigest(),
            now);
    auditStore.append(toAuditEvent(request.snapshot(), expiredDecision));
  }

  private static boolean expired(Instant createdAt, Instant now) {
    return !createdAt.plus(STORED_CONSENT_TTL).isAfter(now);
  }

  private ConsentSnapshot buildInstallSnapshot(String catalogId, String appId) {
    requireCatalogHandler();
    Map<String, Object> app = catalogHandler.getApp(catalogId, appId);
    return buildInstallSnapshot(catalogId, app, nextRequestId());
  }

  private ConsentSnapshot buildPreparedInstallSnapshot(String catalogId, AppCatalogEntry entry) {
    requireCatalogHandler();
    Map<String, Object> app =
        catalogHandler.summarizePreparedPlanForConsent(catalogId, entry, false);
    return buildInstallSnapshot(catalogId, app, "prepared-install");
  }

  private ConsentSnapshot buildInstallSnapshot(
      String catalogId, Map<String, Object> app, String requestId) {
    List<ConsentSection> sections = new ArrayList<>();
    sections.add(installIdentitySection(catalogId, app));
    sections.add(catalogTrustSection(app));
    sections.add(reviewSection(app, true));
    sections.add(securitySection(app, true));
    sections.add(installPermissionsSection(app));
    sections.add(apiStabilitySection(app));
    sections.add(appDataAndBackupSection(app, Map.of()));
    sections.add(serviceGrantPlaceholderSection());
    ConsentRiskLevel risk = ConsentPolicy.riskLevel(sections);
    boolean requiresApproval = risk.requiresApproval();
    return snapshot(
        new SnapshotSpec(
            requestId,
            ConsentActionType.INSTALL_APP,
            new SnapshotCandidate(
                app,
                null,
                ConsentJson.string(app, FIELD_VERSION),
                bundleDigest(app),
                catalogId,
                catalogId),
            new SnapshotAssessment(risk, requiresApproval, requiresApproval, sections)));
  }

  private ConsentSnapshot buildUpdateSnapshot(
      String appId, boolean refreshCatalogs, boolean includePreparedMigrationPlan) {
    return buildUpdateSnapshotWithCandidate(appId, refreshCatalogs, includePreparedMigrationPlan)
        .snapshot();
  }

  private UpdateConsentSnapshot buildUpdateSnapshotWithCandidate(
      String appId, boolean refreshCatalogs, boolean includePreparedMigrationPlan) {
    requireUpdateService();
    Map<String, Object> summary =
        includePreparedMigrationPlan
            ? updateService.previewForConsent(appId, refreshCatalogs)
            : updateService.previewReadOnly(appId);
    Map<String, Object> candidate = ConsentJson.object(summary, VALUE_CANDIDATE);
    String requestId = nextRequestId();
    if (!isDetectedUpdateCandidate(candidate)) {
      return new UpdateConsentSnapshot(noUpdateSnapshot(requestId, appId), candidate);
    }
    List<ConsentSection> sections = new ArrayList<>();
    sections.add(updateIdentitySection(candidate));
    sections.add(permissionDeltaSection(candidate));
    sections.add(updateApiStabilitySection(candidate));
    sections.add(updateReviewSection(candidate));
    sections.add(updateCatalogSection(candidate));
    sections.add(updateSecuritySection(candidate));
    sections.add(updateMigrationSection(candidate));
    sections.add(updateBackupSection(candidate));
    sections.add(updateServiceGrantDeltaSection(candidate));
    ConsentRiskLevel risk = ConsentPolicy.riskLevel(sections);
    boolean requiresApproval = risk.requiresApproval();
    return new UpdateConsentSnapshot(
        new ConsentSnapshot(
            requestId,
            ConsentActionType.UPDATE_APP,
            ConsentJson.string(candidate, FIELD_APP_ID),
            null,
            ConsentJson.string(candidate, FIELD_INSTALLED_VERSION),
            ConsentJson.string(candidate, FIELD_TARGET_VERSION),
            null,
            bundleDigest(candidate),
            ConsentJson.string(candidate, FIELD_CATALOG_ID),
            ConsentJson.string(candidate, FIELD_CATALOG_SOURCE_ID),
            risk,
            requiresApproval,
            requiresApproval,
            ConsentPolicy.blockingReasons(sections),
            recommendedAction(risk, ConsentActionType.UPDATE_APP),
            sections,
            Instant.now(clock)),
        candidate);
  }

  private static boolean preparedUpdateConsentRequired(Map<String, Object> candidate) {
    if (isNonStageableUpdateCandidate(candidate)) {
      return false;
    }
    Map<String, Object> migration = ConsentJson.object(candidate, FIELD_DATA_MIGRATION);
    return AppDataMigrationPlan.STATUS_NOT_CHECKED.equals(
        ConsentJson.string(migration, FIELD_STATUS));
  }

  private ConsentSnapshot noUpdateSnapshot(String requestId, String appId) {
    List<ConsentSection> sections =
        List.of(
            section(
                VALUE_CANDIDATE,
                TITLE_UPDATE_CANDIDATE,
                finding(
                    "no_update_candidate",
                    "No update candidate",
                    "No catalog update candidate is currently available.",
                    VALUE_UNCHANGED,
                    ConsentRiskLevel.NONE)));
    return new ConsentSnapshot(
        requestId,
        ConsentActionType.UPDATE_APP,
        appId,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        ConsentRiskLevel.NONE,
        false,
        false,
        List.of(),
        "no_update_available",
        sections,
        Instant.now(clock));
  }

  private static boolean isDetectedUpdateCandidate(Map<String, Object> candidate) {
    String status = ConsentJson.string(candidate, FIELD_STATUS);
    return status != null && !VALUE_NONE.equals(status);
  }

  private static boolean isNonStageableUpdateCandidate(Map<String, Object> candidate) {
    return !VALUE_AVAILABLE.equals(ConsentJson.string(candidate, FIELD_STATUS));
  }

  private ConsentSnapshot buildCatalogUpdateSnapshot(String catalogId, String appId) {
    requireCatalogHandler();
    Map<String, Object> app = catalogHandler.getAppForCatalogUpdateConsent(catalogId, appId);
    return buildCatalogUpdateSnapshot(catalogId, app, nextRequestId());
  }

  private ConsentSnapshot buildPreparedCatalogUpdateSnapshot(
      String catalogId, AppCatalogEntry entry) {
    requireCatalogHandler();
    Map<String, Object> app =
        catalogHandler.summarizePreparedPlanForConsent(catalogId, entry, true);
    return buildCatalogUpdateSnapshot(catalogId, app, "prepared-catalog-update");
  }

  private ConsentSnapshot buildCatalogUpdateSnapshot(
      String catalogId, Map<String, Object> app, String requestId) {
    List<ConsentSection> sections = new ArrayList<>();
    sections.add(catalogUpdateIdentitySection(catalogId, app));
    sections.add(permissionDeltaFromDeltaMap(ConsentJson.object(app, FIELD_PERMISSION_DELTA)));
    sections.add(apiStabilitySection(app));
    sections.add(reviewSection(app, false));
    sections.add(catalogTrustSection(app));
    sections.add(securitySection(app, false));
    sections.add(appDataAndBackupSection(app, Map.of()));
    sections.add(serviceGrantPlaceholderSection());
    ConsentRiskLevel risk = ConsentPolicy.riskLevel(sections);
    boolean requiresApproval = risk.requiresApproval();
    return snapshot(
        new SnapshotSpec(
            requestId,
            ConsentActionType.UPDATE_APP,
            new SnapshotCandidate(
                app,
                ConsentJson.string(app, FIELD_INSTALLED_VERSION),
                ConsentJson.string(app, FIELD_VERSION),
                bundleDigest(app),
                catalogId,
                catalogId),
            new SnapshotAssessment(risk, requiresApproval, requiresApproval, sections)));
  }

  private ConsentSnapshot buildServiceGrantSnapshot(String bundleId) {
    requireServiceCoordinator();
    Map<String, Object> bundle =
        appServiceCoordinator.listBundles(PlatformApiPrincipal.hostOperator()).stream()
            .filter(item -> bundleId.equals(ConsentJson.string(item, "bundleId")))
            .findFirst()
            .orElseThrow(
                () ->
                    new PlatformApiException(
                        404,
                        "app_service_bundle_not_found",
                        "App-service grant bundle not found."));
    List<ConsentSection> sections = new ArrayList<>();
    sections.add(serviceGrantIdentitySection(bundle));
    sections.add(serviceGrantDependenciesSection(bundle));
    sections.add(serviceGrantAuditSection());
    ConsentRiskLevel risk = ConsentPolicy.riskLevel(sections);
    return new ConsentSnapshot(
        nextRequestId(),
        ConsentActionType.APP_SERVICE_GRANT,
        ConsentJson.string(bundle, FIELD_CONSUMER_APP_ID),
        null,
        null,
        null,
        null,
        bundleFingerprint(bundle),
        null,
        null,
        risk,
        risk.requiresApproval(),
        risk.requiresApproval(),
        ConsentPolicy.blockingReasons(sections),
        recommendedAction(risk, ConsentActionType.APP_SERVICE_GRANT),
        sections,
        Instant.now(clock));
  }

  private ConsentSection installIdentitySection(String catalogId, Map<String, Object> app) {
    return section(
        SECTION_IDENTITY,
        "App identity",
        finding(
            "app_identity",
            "App",
            "%s %s from catalog %s"
                .formatted(
                    safe(
                        ConsentJson.string(app, FIELD_NAME), ConsentJson.string(app, FIELD_APP_ID)),
                    safe(ConsentJson.string(app, FIELD_VERSION), "unknown version"),
                    catalogId),
            VALUE_CANDIDATE,
            ConsentRiskLevel.LOW),
        finding(
            FINDING_BUNDLE_DIGEST,
            LABEL_BUNDLE_DIGEST,
            safe(bundleDigest(app), SUMMARY_NO_BUNDLE_DIGEST),
            VALUE_CANDIDATE,
            bundleDigest(app) == null ? ConsentRiskLevel.MATERIAL : ConsentRiskLevel.LOW),
        finding(
            "catalog_channel",
            "Catalog channel",
            safe(ConsentJson.string(app, FIELD_CHANNEL), VALUE_STABLE),
            VALUE_CANDIDATE,
            channelRisk(ConsentJson.string(app, FIELD_CHANNEL))));
  }

  private ConsentSection catalogTrustSection(Map<String, Object> app) {
    Map<String, Object> maintenance = ConsentJson.object(app, "maintenance");
    Map<String, Object> deprecation = ConsentJson.object(app, FIELD_DEPRECATION);
    return section(
        "catalog-support",
        "Catalog and support",
        finding(
            "support_status",
            "Support status",
            safe(ConsentJson.string(app, FIELD_SUPPORT_STATUS), VALUE_SUPPORTED),
            VALUE_CANDIDATE,
            supportRisk(ConsentJson.string(app, FIELD_SUPPORT_STATUS))),
        finding(
            "maintenance_owner",
            "Maintenance owner",
            safe(ConsentJson.string(maintenance, "owner"), "Maintenance owner is not declared."),
            VALUE_CANDIDATE,
            ConsentJson.string(maintenance, "owner") == null
                ? ConsentRiskLevel.MATERIAL
                : ConsentRiskLevel.LOW),
        finding(
            "deprecation_status",
            "Deprecation",
            deprecationSummary(deprecation),
            VALUE_CANDIDATE,
            deprecationRisk(deprecation)));
  }

  private ConsentSection reviewSection(Map<String, Object> app, boolean install) {
    Map<String, Object> reviewTrust = ConsentJson.object(app, "reviewTrust");
    Map<String, Object> thirdPartyReview = ConsentJson.object(app, "thirdPartyReview");
    ConsentRiskLevel risk = reviewRisk(reviewTrust, install);
    return section(
        "review-trust",
        "Review and trust",
        finding(
            "review_trust_delta",
            "Review status",
            safe(ConsentJson.string(reviewTrust, FIELD_STATUS), "review metadata unavailable"),
            VALUE_CANDIDATE,
            risk),
        finding(
            "reviewer_key_status",
            "Reviewer key",
            safe(
                ConsentJson.string(thirdPartyReview, FIELD_REVIEWER_KEY_ID),
                "No reviewer key declared."),
            VALUE_CANDIDATE,
            ConsentJson.string(thirdPartyReview, FIELD_REVIEWER_KEY_ID) == null
                ? ConsentRiskLevel.MATERIAL
                : ConsentRiskLevel.LOW),
        finding(
            "review_receipt_fingerprint",
            "Review receipt",
            safe(
                ConsentJson.string(thirdPartyReview, "receiptFingerprintSha256"),
                "No independent review receipt fingerprint is available."),
            VALUE_CANDIDATE,
            ConsentJson.string(thirdPartyReview, "receiptFingerprintSha256") == null
                ? ConsentRiskLevel.MATERIAL
                : ConsentRiskLevel.LOW));
  }

  private ConsentSection securitySection(Map<String, Object> app, boolean install) {
    return securitySection(
        ConsentJson.object(app, FIELD_SECURITY_DECISION),
        ConsentJson.list(app, FIELD_SECURITY_ADVISORIES),
        install);
  }

  private ConsentSection securitySection(
      Map<String, Object> decision, List<Object> advisories, boolean install) {
    ConsentRiskLevel risk = securityRisk(decision, advisories, install);
    return section(
        "security",
        "Security advisory",
        finding(
            "security_advisory_delta",
            "Security decision",
            safe(ConsentJson.string(decision, FIELD_STATUS), "ok"),
            VALUE_CANDIDATE,
            risk),
        finding(
            "security_advisory_count",
            "Advisories",
            securityAdvisorySummary(advisories),
            advisories.isEmpty() ? VALUE_UNCHANGED : VALUE_ADDED,
            advisories.isEmpty() ? ConsentRiskLevel.NONE : ConsentRiskLevel.MATERIAL));
  }

  private ConsentSection installPermissionsSection(Map<String, Object> app) {
    List<Object> permissions = ConsentJson.list(app, "permissions");
    Map<String, Object> rationales = ConsentJson.object(app, "permissionRationales");
    ArrayList<ConsentFinding> findings = new ArrayList<>();
    if (permissions.isEmpty()) {
      findings.add(
          finding(
              "permissions_none",
              "Permissions",
              "No app permissions are declared.",
              VALUE_UNCHANGED,
              ConsentRiskLevel.NONE));
    }
    for (Object permission : permissions) {
      String text = String.valueOf(permission);
      findings.add(
          finding(
              "permission_required",
              text,
              safe(String.valueOf(rationales.getOrDefault(text, "")), "No rationale declared."),
              VALUE_ADDED,
              ConsentRiskLevel.MATERIAL));
    }
    return section("permissions", "Permissions", findings);
  }

  private ConsentSection apiStabilitySection(Map<String, Object> app) {
    Map<String, Object> api = ConsentJson.object(app, "apiCompatibility");
    return section("api-stability", "Platform API stability", apiStabilityFindings(api));
  }

  private ConsentSection appDataAndBackupSection(
      Map<String, Object> app, Map<String, Object> migration) {
    Map<String, Object> maintenance = ConsentJson.object(app, "maintenance");
    ArrayList<ConsentFinding> findings = new ArrayList<>();
    findings.add(
        finding(
            "app_data_schema_policy",
            "Schema policy",
            safe(ConsentJson.string(maintenance, "dataSchemaPolicy"), "No schema policy declared."),
            VALUE_CANDIDATE,
            ConsentRiskLevel.LOW));
    findings.add(
        finding(
            "backup_before_update",
            "Backup before update",
            safe(
                ConsentJson.string(maintenance, "backupRestore"), "Backup policy is not declared."),
            VALUE_CANDIDATE,
            ConsentJson.string(maintenance, "backupRestore") == null
                ? ConsentRiskLevel.MATERIAL
                : ConsentRiskLevel.LOW));
    if (!migration.isEmpty()) {
      findings.add(
          finding(
              "app_data_migration_plan",
              "Migration plan",
              migrationSummary(migration),
              VALUE_CANDIDATE,
              migrationRisk(migration)));
    }
    return section("app-data-migration", "App-data migration and backup", findings);
  }

  private ConsentSection serviceGrantPlaceholderSection() {
    return section(
        "app-service-grants",
        "App-service grants",
        finding(
            "app_service_dependencies",
            "Service dependencies",
            "No app-service grant bundle is pending in this preview.",
            VALUE_UNCHANGED,
            ConsentRiskLevel.NONE));
  }

  private ConsentSection updateIdentitySection(Map<String, Object> candidate) {
    return section(
        SECTION_IDENTITY,
        TITLE_UPDATE_CANDIDATE,
        finding(
            "version_change",
            "Version",
            "%s to %s"
                .formatted(
                    safe(ConsentJson.string(candidate, FIELD_INSTALLED_VERSION), VALUE_UNKNOWN),
                    safe(ConsentJson.string(candidate, FIELD_TARGET_VERSION), VALUE_UNKNOWN)),
            VALUE_CHANGED,
            ConsentRiskLevel.LOW),
        finding(
            FINDING_BUNDLE_DIGEST,
            LABEL_BUNDLE_DIGEST,
            safe(bundleDigest(candidate), SUMMARY_NO_BUNDLE_DIGEST),
            VALUE_CHANGED,
            bundleDigest(candidate) == null ? ConsentRiskLevel.MATERIAL : ConsentRiskLevel.LOW));
  }

  private ConsentSection catalogUpdateIdentitySection(String catalogId, Map<String, Object> app) {
    return section(
        SECTION_IDENTITY,
        TITLE_UPDATE_CANDIDATE,
        finding(
            "version_change",
            "Version",
            "%s to %s from catalog %s"
                .formatted(
                    safe(ConsentJson.string(app, FIELD_INSTALLED_VERSION), VALUE_UNKNOWN),
                    safe(ConsentJson.string(app, FIELD_VERSION), VALUE_UNKNOWN),
                    catalogId),
            VALUE_CHANGED,
            ConsentRiskLevel.LOW),
        finding(
            FINDING_BUNDLE_DIGEST,
            LABEL_BUNDLE_DIGEST,
            safe(bundleDigest(app), SUMMARY_NO_BUNDLE_DIGEST),
            VALUE_CHANGED,
            bundleDigest(app) == null ? ConsentRiskLevel.MATERIAL : ConsentRiskLevel.LOW));
  }

  private ConsentSection permissionDeltaSection(Map<String, Object> candidate) {
    return permissionDeltaFromDeltaMap(ConsentJson.object(candidate, FIELD_PERMISSION_DELTA));
  }

  private ConsentSection permissionDeltaFromDeltaMap(Map<String, Object> delta) {
    ArrayList<ConsentFinding> findings = new ArrayList<>();
    for (Object permission : ConsentJson.list(delta, VALUE_ADDED)) {
      findings.add(
          finding(
              "new_permission",
              String.valueOf(permission),
              "New permission requested by the update.",
              VALUE_ADDED,
              ConsentRiskLevel.MATERIAL));
    }
    for (Object permission : ConsentJson.list(delta, "removed")) {
      findings.add(
          finding(
              "removed_permission",
              String.valueOf(permission),
              "Permission removed by the update.",
              "removed",
              ConsentRiskLevel.LOW));
    }
    findings.add(
        finding(
            "permission_rationale_delta",
            "Permission rationales",
            "Rationale changes are reviewed with the candidate permission set.",
            VALUE_CHANGED,
            ConsentJson.list(delta, VALUE_ADDED).isEmpty()
                ? ConsentRiskLevel.LOW
                : ConsentRiskLevel.MATERIAL));
    return section("permission-delta", "Permission delta", findings);
  }

  private ConsentSection updateApiStabilitySection(Map<String, Object> candidate) {
    return section(
        "api-stability",
        "Platform API stability",
        apiStabilityFindings(ConsentJson.object(candidate, "apiCompatibility")));
  }

  private ConsentSection updateReviewSection(Map<String, Object> candidate) {
    Map<String, Object> reviewTrust = ConsentJson.object(candidate, "reviewTrust");
    ConsentRiskLevel risk = reviewRisk(reviewTrust, false);
    return section(
        "review-trust",
        "Review and trust",
        finding(
            "review_trust_delta",
            "Review trust",
            safe(ConsentJson.string(reviewTrust, FIELD_STATUS), "review metadata unavailable"),
            VALUE_CHANGED,
            risk),
        finding(
            "review_receipt_changed",
            "Review receipt",
            reviewTrustReceiptSummary(reviewTrust),
            VALUE_CHANGED,
            risk));
  }

  private ConsentSection updateCatalogSection(Map<String, Object> candidate) {
    return section(
        "catalog-support",
        "Catalog and support",
        finding(
            "catalog_channel_delta",
            "Channel",
            safe(ConsentJson.string(candidate, FIELD_CHANNEL), VALUE_STABLE),
            VALUE_CHANGED,
            channelRisk(ConsentJson.string(candidate, FIELD_CHANNEL))),
        finding(
            "support_status_delta",
            "Support status",
            safe(ConsentJson.string(candidate, FIELD_SUPPORT_STATUS), VALUE_SUPPORTED),
            VALUE_CHANGED,
            supportRisk(ConsentJson.string(candidate, FIELD_SUPPORT_STATUS))),
        finding(
            "deprecation_delta",
            "Deprecation",
            deprecationSummary(ConsentJson.object(candidate, FIELD_DEPRECATION)),
            VALUE_CHANGED,
            deprecationRisk(ConsentJson.object(candidate, FIELD_DEPRECATION))));
  }

  private ConsentSection updateSecuritySection(Map<String, Object> candidate) {
    return securitySection(
        ConsentJson.object(candidate, FIELD_SECURITY_DECISION),
        ConsentJson.list(candidate, FIELD_SECURITY_ADVISORIES),
        false);
  }

  private ConsentSection updateMigrationSection(Map<String, Object> candidate) {
    Map<String, Object> migration = ConsentJson.object(candidate, FIELD_DATA_MIGRATION);
    return section(
        "app-data-migration",
        "App-data migration",
        finding(
            "app_data_migration_plan",
            "Migration plan",
            migrationSummary(migration),
            VALUE_CHANGED,
            migrationRisk(migration)));
  }

  private ConsentSection updateBackupSection(Map<String, Object> candidate) {
    Map<String, Object> migration = ConsentJson.object(candidate, FIELD_DATA_MIGRATION);
    ConsentRiskLevel risk =
        migrationRisk(migration).requiresApproval()
            ? ConsentRiskLevel.MATERIAL
            : ConsentRiskLevel.LOW;
    return section(
        "backup-before-update",
        "Backup before update",
        finding(
            "backup_before_update",
            "Backup recommendation",
            Boolean.TRUE.equals(migration.get(FIELD_REQUIRED))
                ? "A migration is required; create or verify a backup before applying."
                : "No migration backup requirement is currently reported.",
            Boolean.TRUE.equals(migration.get(FIELD_REQUIRED)) ? "recommended" : VALUE_UNCHANGED,
            risk));
  }

  private ConsentSection updateServiceGrantDeltaSection(Map<String, Object> candidate) {
    Map<String, Object> delta = ConsentJson.object(candidate, FIELD_PERMISSION_DELTA);
    boolean servicePermissionAdded =
        ConsentJson.list(delta, VALUE_ADDED).stream()
            .map(String::valueOf)
            .anyMatch(permission -> permission.startsWith("app.services."));
    return section(
        "app-service-grants",
        "App-service grants",
        finding(
            "app_service_grant_delta",
            "Grant delta",
            servicePermissionAdded
                ? "The update adds app-service capability and may require grant-bundle review."
                : "No app-service grant-bundle delta is attached to this candidate.",
            servicePermissionAdded ? VALUE_ADDED : VALUE_UNCHANGED,
            servicePermissionAdded ? ConsentRiskLevel.MATERIAL : ConsentRiskLevel.NONE));
  }

  private ConsentSection serviceGrantIdentitySection(Map<String, Object> bundle) {
    return section(
        "service-grant",
        "App-service grant bundle",
        finding(
            "app_service_dependency_bundle",
            "Requesting app",
            "%s requested bundle %s"
                .formatted(
                    safe(ConsentJson.string(bundle, FIELD_CONSUMER_APP_ID), "unknown app"),
                    safe(
                        ConsentJson.string(bundle, "bundleAlias"),
                        ConsentJson.string(bundle, "bundleId"))),
            VALUE_CANDIDATE,
            ConsentRiskLevel.MATERIAL),
        finding(
            "grant_status",
            "Bundle status",
            safe(ConsentJson.string(bundle, FIELD_STATUS), "pending"),
            VALUE_CANDIDATE,
            "pending".equals(ConsentJson.string(bundle, FIELD_STATUS))
                ? ConsentRiskLevel.MATERIAL
                : ConsentRiskLevel.LOW));
  }

  private ConsentSection serviceGrantDependenciesSection(Map<String, Object> bundle) {
    ArrayList<ConsentFinding> findings = new ArrayList<>();
    for (Object item : ConsentJson.list(bundle, "dependencies")) {
      if (item instanceof Map<?, ?> raw) {
        @SuppressWarnings("unchecked")
        Map<String, Object> dependency = (Map<String, Object>) raw;
        findings.add(
            finding(
                "app_service_dependency",
                "%s / %s"
                    .formatted(
                        safe(ConsentJson.string(dependency, "providerAppId"), "provider"),
                        safe(ConsentJson.string(dependency, "serviceId"), "service")),
                serviceDependencySummary(dependency),
                dependencyRequirementText(ConsentJson.bool(dependency, FIELD_REQUIRED, false)),
                ConsentRiskLevel.MATERIAL));
      }
    }
    if (findings.isEmpty()) {
      findings.add(
          finding(
              "app_service_dependency_missing",
              "Dependencies",
              "No dependency records were available for this bundle.",
              VALUE_CANDIDATE,
              ConsentRiskLevel.MATERIAL));
    }
    return section("app-service-dependencies", "Service dependencies", findings);
  }

  private ConsentSection serviceGrantAuditSection() {
    return section(
        "audit",
        "Audit impact",
        finding(
            "app_service_audit_impact",
            "Audit",
            "Approving, rejecting, or renewing this bundle writes a consent audit record and an"
                + " app-service lifecycle record.",
            VALUE_CANDIDATE,
            ConsentRiskLevel.MATERIAL),
        finding(
            "app_service_revocation_behavior",
            "Revocation",
            "Revoking grants disables service invocation until a fresh operator approval exists.",
            VALUE_CANDIDATE,
            ConsentRiskLevel.LOW));
  }

  private List<ConsentFinding> apiStabilityFindings(Map<String, Object> api) {
    String stability = ConsentJson.string(api, FIELD_TARGET_STABILITY);
    boolean experimentalAccepted =
        ConsentJson.bool(api, FIELD_EXPERIMENTAL_CAPABILITIES_ACCEPTED, false);
    String status = ConsentJson.string(api, FIELD_STATUS);
    ArrayList<ConsentFinding> findings = new ArrayList<>();
    findings.add(
        finding(
            "platform_api_stability_change",
            "Target stability",
            safe(stability, "not declared"),
            VALUE_CANDIDATE,
            apiRisk(api)));
    findings.add(
        finding(
            "experimental_api_acceptance",
            "Experimental API acceptance",
            Boolean.toString(experimentalAccepted),
            VALUE_CANDIDATE,
            experimentalAccepted ? ConsentRiskLevel.MATERIAL : ConsentRiskLevel.LOW));
    findings.add(
        finding(
            "platform_api_compatibility",
            "Compatibility",
            safe(status, VALUE_UNKNOWN),
            VALUE_CANDIDATE,
            apiRisk(api)));
    return findings;
  }

  private ConsentSnapshot snapshot(SnapshotSpec spec) {
    SnapshotCandidate candidate = spec.candidate();
    SnapshotAssessment assessment = spec.assessment();
    return new ConsentSnapshot(
        spec.requestId(),
        spec.action(),
        ConsentJson.string(candidate.app(), FIELD_APP_ID),
        ConsentJson.string(candidate.app(), FIELD_NAME),
        candidate.installedVersion(),
        candidate.candidateVersion(),
        null,
        candidate.candidateDigest(),
        candidate.catalogId(),
        candidate.catalogSourceId(),
        assessment.risk(),
        assessment.requiresApproval(),
        assessment.blocksAutoUpdate(),
        ConsentPolicy.blockingReasons(assessment.sections()),
        recommendedAction(assessment.risk(), spec.action()),
        assessment.sections(),
        Instant.now(clock));
  }

  private record SnapshotSpec(
      String requestId,
      ConsentActionType action,
      SnapshotCandidate candidate,
      SnapshotAssessment assessment) {}

  private record SnapshotCandidate(
      Map<String, Object> app,
      String installedVersion,
      String candidateVersion,
      String candidateDigest,
      String catalogId,
      String catalogSourceId) {}

  private record SnapshotAssessment(
      ConsentRiskLevel risk,
      boolean requiresApproval,
      boolean blocksAutoUpdate,
      List<ConsentSection> sections) {}

  private static ConsentSection section(String id, String title, ConsentFinding... findings) {
    return section(id, title, List.of(findings));
  }

  private static ConsentSection section(String id, String title, List<ConsentFinding> findings) {
    ConsentRiskLevel risk = ConsentRiskLevel.NONE;
    for (ConsentFinding finding : findings) {
      risk = ConsentRiskLevel.max(risk, finding.riskLevel());
    }
    return new ConsentSection(id, title, risk, findings);
  }

  private static ConsentFinding finding(
      String code, String label, String summary, String change, ConsentRiskLevel risk) {
    return new ConsentFinding(code, label, summary, change, risk);
  }

  private static ConsentRiskLevel reviewRisk(Map<String, Object> reviewTrust, boolean install) {
    if (ConsentJson.bool(
        reviewTrust, install ? FIELD_BLOCKS_INSTALL : FIELD_BLOCKS_UPDATE, false)) {
      return ConsentRiskLevel.BLOCKING;
    }
    if (ConsentJson.bool(reviewTrust, FIELD_REQUIRES_ACKNOWLEDGEMENT, false)
        || !ConsentJson.bool(reviewTrust, FIELD_POSITIVE, false)) {
      return ConsentRiskLevel.MATERIAL;
    }
    return ConsentRiskLevel.LOW;
  }

  private static ConsentRiskLevel securityRisk(
      Map<String, Object> decision, List<Object> advisories, boolean install) {
    if (ConsentJson.bool(decision, install ? FIELD_BLOCKS_INSTALL : FIELD_BLOCKS_UPDATE, false)) {
      return ConsentRiskLevel.BLOCKING;
    }
    String status = ConsentJson.string(decision, FIELD_STATUS);
    if (ConsentJson.bool(decision, FIELD_REQUIRES_ACKNOWLEDGEMENT, false)
        || ConsentJson.bool(decision, "blocksAutomaticApply", false)
        || !advisories.isEmpty()
        || (status != null && !"ok".equals(status))) {
      return ConsentRiskLevel.MATERIAL;
    }
    return ConsentRiskLevel.LOW;
  }

  private static ConsentRiskLevel apiRisk(Map<String, Object> api) {
    String status = ConsentJson.string(api, FIELD_STATUS);
    String stability = ConsentJson.string(api, FIELD_TARGET_STABILITY);
    if ("below_minimum".equals(status)
        || "incompatible".equals(status)
        || VALUE_UNSUPPORTED_BASELINE.equals(status)) {
      return ConsentRiskLevel.BLOCKING;
    }
    if (status != null && !"compatible".equals(status) && !"satisfied".equals(status)) {
      return ConsentRiskLevel.MATERIAL;
    }
    if (!VALUE_STABLE.equals(stability)
        || ConsentJson.bool(api, FIELD_EXPERIMENTAL_CAPABILITIES_ACCEPTED, false)) {
      return ConsentRiskLevel.MATERIAL;
    }
    return ConsentRiskLevel.LOW;
  }

  private static ConsentRiskLevel channelRisk(String channel) {
    if (channel == null || VALUE_STABLE.equals(channel)) {
      return ConsentRiskLevel.LOW;
    }
    return ConsentRiskLevel.MATERIAL;
  }

  private static ConsentRiskLevel supportRisk(String supportStatus) {
    if (supportStatus == null || VALUE_SUPPORTED.equals(supportStatus)) {
      return ConsentRiskLevel.LOW;
    }
    return ConsentRiskLevel.MATERIAL;
  }

  private static ConsentRiskLevel deprecationRisk(Map<String, Object> deprecation) {
    String status = ConsentJson.string(deprecation, FIELD_STATUS);
    return status == null || VALUE_NONE.equals(status)
        ? ConsentRiskLevel.LOW
        : ConsentRiskLevel.MATERIAL;
  }

  private static ConsentRiskLevel migrationRisk(Map<String, Object> migration) {
    if (migration.isEmpty() || !ConsentJson.bool(migration, FIELD_REQUIRED, false)) {
      return ConsentRiskLevel.LOW;
    }
    if (migration.get("blockReason") != null) {
      return ConsentRiskLevel.BLOCKING;
    }
    return ConsentRiskLevel.MATERIAL;
  }

  private static String deprecationSummary(Map<String, Object> deprecation) {
    String status = safe(ConsentJson.string(deprecation, FIELD_STATUS), VALUE_NONE);
    String message = ConsentJson.string(deprecation, "message");
    String replacement = ConsentJson.string(deprecation, "replacementAppId");
    if (replacement != null) {
      return status + "; replacement app: " + replacement;
    }
    return message == null ? status : status + "; " + message;
  }

  private static String migrationSummary(Map<String, Object> migration) {
    if (migration.isEmpty() || !ConsentJson.bool(migration, FIELD_REQUIRED, false)) {
      return "No app-data migration is required.";
    }
    return "Schema "
        + safe(ConsentJson.scalarString(migration, "currentSchemaVersion"), VALUE_UNKNOWN)
        + " to "
        + safe(ConsentJson.scalarString(migration, "targetSchemaVersion"), VALUE_UNKNOWN)
        + "; dry run "
        + safe(ConsentJson.string(migration, "dryRunStatus"), "not checked")
        + "; rollback "
        + safe(ConsentJson.string(migration, "snapshotStatus"), "not created");
  }

  private static String securityAdvisorySummary(List<Object> advisories) {
    if (advisories.isEmpty()) {
      return "No catalog security advisories are attached.";
    }
    List<String> advisoryDetails =
        advisories.stream().map(ConsentJson::canonicalize).map(String::valueOf).sorted().toList();
    return advisories.size()
        + " catalog security advisory item(s) require review: "
        + advisoryDetails;
  }

  private static String reviewTrustReceiptSummary(Map<String, Object> reviewTrust) {
    ArrayList<String> fields = new ArrayList<>();
    addReviewTrustSummaryField(
        fields, FIELD_STATUS, ConsentJson.scalarString(reviewTrust, FIELD_STATUS));
    addReviewTrustSummaryField(fields, "trusted", ConsentJson.scalarString(reviewTrust, "trusted"));
    addReviewTrustSummaryField(
        fields, FIELD_POSITIVE, ConsentJson.scalarString(reviewTrust, FIELD_POSITIVE));
    addReviewTrustSummaryField(
        fields,
        FIELD_REQUIRES_ACKNOWLEDGEMENT,
        ConsentJson.scalarString(reviewTrust, FIELD_REQUIRES_ACKNOWLEDGEMENT));
    addReviewTrustSummaryField(
        fields, FIELD_BLOCKS_INSTALL, ConsentJson.scalarString(reviewTrust, FIELD_BLOCKS_INSTALL));
    addReviewTrustSummaryField(
        fields, FIELD_BLOCKS_UPDATE, ConsentJson.scalarString(reviewTrust, FIELD_BLOCKS_UPDATE));
    addReviewTrustSummaryField(
        fields, "blocksPolicyApply", ConsentJson.scalarString(reviewTrust, "blocksPolicyApply"));
    addReviewTrustSummaryField(
        fields, FIELD_REVIEWER_KEY_ID, ConsentJson.string(reviewTrust, FIELD_REVIEWER_KEY_ID));
    addReviewTrustSummaryField(
        fields, "reviewerDisplayName", ConsentJson.string(reviewTrust, "reviewerDisplayName"));
    addReviewTrustSummaryField(
        fields, "reviewerKeyStatus", ConsentJson.string(reviewTrust, "reviewerKeyStatus"));
    addReviewTrustSummaryField(fields, "policyId", ConsentJson.string(reviewTrust, "policyId"));
    addReviewTrustSummaryField(
        fields, "policyVersion", ConsentJson.string(reviewTrust, "policyVersion"));
    addReviewTrustSummaryField(
        fields, "policyVersionStatus", ConsentJson.string(reviewTrust, "policyVersionStatus"));
    addReviewTrustSummaryField(fields, "policyMode", ConsentJson.string(reviewTrust, "policyMode"));
    addReviewTrustSummaryField(fields, "reviewedAt", ConsentJson.string(reviewTrust, "reviewedAt"));
    addReviewTrustSummaryField(fields, "expiresAt", ConsentJson.string(reviewTrust, "expiresAt"));
    addReviewTrustSummaryField(
        fields, "evidenceSha256", ConsentJson.string(reviewTrust, "evidenceSha256"));
    addReviewTrustSummaryField(
        fields, "evidenceUri", ConsentJson.string(reviewTrust, "evidenceUri"));
    addReviewTrustSummaryField(fields, "warnings", reviewTrustWarnings(reviewTrust));
    return String.join("; ", fields);
  }

  private static void addReviewTrustSummaryField(
      List<String> fields, String fieldName, String value) {
    fields.add(fieldName + "=" + safe(value, "unavailable"));
  }

  private static String reviewTrustWarnings(Map<String, Object> reviewTrust) {
    List<Object> warnings = ConsentJson.list(reviewTrust, "warnings");
    return warnings.isEmpty() ? "[]" : String.valueOf(ConsentJson.canonicalize(warnings));
  }

  private static String serviceDependencySummary(Map<String, Object> dependency) {
    return "Capability "
        + safe(ConsentJson.string(dependency, "kind"), "service")
        + "; scopes "
        + ConsentJson.list(dependency, "scopes")
        + "; expiry "
        + safe(ConsentJson.string(dependency, "grantExpiresAfter"), "not declared")
        + "; revocation blocks matching service calls.";
  }

  private static String bundleDigest(Map<String, Object> source) {
    Map<String, Object> bundle = ConsentJson.object(source, "bundle");
    return ConsentJson.string(bundle, "sha256");
  }

  private static String bundleFingerprint(Map<String, Object> bundle) {
    return ConsentSnapshotDigest.digest(
        new ConsentSnapshot(
            "fingerprint",
            ConsentActionType.APP_SERVICE_GRANT,
            safe(ConsentJson.string(bundle, FIELD_CONSUMER_APP_ID), VALUE_UNKNOWN),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            ConsentRiskLevel.LOW,
            false,
            false,
            List.of(),
            "fingerprint",
            List.of(
                new ConsentSection(
                    "bundle",
                    "Bundle",
                    ConsentRiskLevel.LOW,
                    List.of(
                        finding(
                            "bundle_json",
                            "Bundle",
                            String.valueOf(ConsentJson.canonicalize(bundle)),
                            VALUE_CANDIDATE,
                            ConsentRiskLevel.LOW)))),
            Instant.EPOCH));
  }

  private static String recommendedAction(ConsentRiskLevel risk, ConsentActionType action) {
    if (risk == ConsentRiskLevel.BLOCKING) {
      return "do_not_continue";
    }
    if (risk.requiresApproval()) {
      return switch (action) {
        case UPDATE_APP -> "review_before_update";
        case APP_SERVICE_GRANT -> "review_before_service_grant";
        default -> "review_before_install";
      };
    }
    return "continue";
  }

  private static String actor(PlatformApiPrincipal principal) {
    if (principal == null || !principal.isApp()) {
      return LOCAL_OPERATOR;
    }
    return "app:" + principal.appId();
  }

  private static Map<String, List<String>> acknowledged(Map<String, List<String>> source) {
    LinkedHashMap<String, List<String>> copy = new LinkedHashMap<>(source);
    copy.put(PARAM_REVIEW_ACKNOWLEDGED, List.of(Boolean.TRUE.toString()));
    copy.put(PARAM_SECURITY_ACKNOWLEDGED, List.of(Boolean.TRUE.toString()));
    copy.put(PARAM_MIGRATION_ACKNOWLEDGED, List.of(Boolean.TRUE.toString()));
    return copy;
  }

  private static Map<String, List<String>> withoutAcknowledgements(
      Map<String, List<String>> source) {
    if (!source.containsKey(PARAM_REVIEW_ACKNOWLEDGED)
        && !source.containsKey(PARAM_SECURITY_ACKNOWLEDGED)
        && !source.containsKey(PARAM_MIGRATION_ACKNOWLEDGED)) {
      return source;
    }
    LinkedHashMap<String, List<String>> copy = new LinkedHashMap<>(source);
    copy.remove(PARAM_REVIEW_ACKNOWLEDGED);
    copy.remove(PARAM_SECURITY_ACKNOWLEDGED);
    copy.remove(PARAM_MIGRATION_ACKNOWLEDGED);
    return copy;
  }

  private static boolean hasConsentApprovalParameters(Map<String, List<String>> queryParameters) {
    return PlatformApiParameters.readOptionalString(queryParameters, PARAM_CONSENT_REQUEST_ID)
            != null
        && snapshotDigestParameter(queryParameters) != null;
  }

  private static String snapshotDigestParameter(Map<String, List<String>> queryParameters) {
    String digest =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_SNAPSHOT_DIGEST);
    if (digest != null) {
      return digest;
    }
    return PlatformApiParameters.readOptionalString(queryParameters, PARAM_CONSENT_SNAPSHOT_DIGEST);
  }

  private static String safe(String value, String fallback) {
    return value == null || value.isBlank() ? fallback : value;
  }

  private static String dependencyRequirementText(boolean required) {
    return required ? FIELD_REQUIRED : "optional";
  }

  private String nextRequestId() {
    return "consent-" + requestSequence.incrementAndGet();
  }

  private String nextDecisionId() {
    return "consent-decision-" + decisionSequence.incrementAndGet();
  }

  private void requireCatalogHandler() {
    if (catalogHandler == null) {
      throw new PlatformApiException(
          503, "app_catalogs_unavailable", "App catalogs are unavailable.");
    }
  }

  private void requireUpdateService() {
    if (updateService == null) {
      throw new PlatformApiException(
          503, "app_updates_unavailable", "App updates are unavailable.");
    }
  }

  private void requireServiceCoordinator() {
    if (appServiceCoordinator == null) {
      throw new PlatformApiException(
          503, "app_services_unavailable", "App-service coordinator is unavailable.");
    }
  }

  private record UpdateConsentSnapshot(ConsentSnapshot snapshot, Map<String, Object> candidate) {}
}
