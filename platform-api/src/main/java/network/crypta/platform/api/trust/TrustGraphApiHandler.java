package network.crypta.platform.api.trust;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.content.ContentApiHandler;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetDecision;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetLease;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetReservation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetScope;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.trustgraph.InMemoryTrustGraphStore;
import network.crypta.platform.trustgraph.TrustAnchor;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustGraphAuditEvent;
import network.crypta.platform.trustgraph.TrustGraphException;
import network.crypta.platform.trustgraph.TrustGraphImportPreview;
import network.crypta.platform.trustgraph.TrustGraphImportResult;
import network.crypta.platform.trustgraph.TrustGraphQuery;
import network.crypta.platform.trustgraph.TrustGraphScore;
import network.crypta.platform.trustgraph.TrustGraphScorer;
import network.crypta.platform.trustgraph.TrustGraphStore;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementFingerprint;
import network.crypta.platform.trustgraph.TrustStatementLifecycleRecord;
import network.crypta.platform.trustgraph.TrustStatementLifecycleStatus;
import network.crypta.platform.trustgraph.TrustStatementParser;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustStatementValidator;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Handles the local Trust Graph RC route family.
 *
 * <p>The handler stores only validated trust statement models, redacted source labels, and local
 * anchors. It never returns raw imported document bodies, signature values, request bodies, browser
 * session tokens, app process tokens, form passwords, private identity material, or local paths.
 *
 * <p>This class is intentionally transport-neutral. The parent Platform API router performs
 * authentication, capability checks, and audit emission; this handler focuses on decoded
 * parameters, trust-graph model validation, response shaping, and translating model failures into
 * stable client errors. The backing store is app-platform local trust state, not daemon-core
 * reputation, moderation, routing, or peer-selection state.
 */
public final class TrustGraphApiHandler {
  private static final String PARAM_CONTEXT = "context";
  private static final String PARAM_DOCUMENT = "document";
  private static final String PARAM_EXPECTED_DOCUMENT_FINGERPRINT = "expectedDocumentFingerprint";
  private static final String PARAM_INCLUDE_EVIDENCE = "includeEvidence";
  private static final String PARAM_ISSUER_FINGERPRINT = "issuerFingerprint";
  private static final String PARAM_LABEL = "label";
  private static final String PARAM_LIMIT = "limit";
  private static final String PARAM_MAX_BYTES = "maxBytes";
  private static final String PARAM_NOTE = "note";
  private static final String PARAM_REASON_CODE = "reasonCode";
  private static final String PARAM_REPLACEMENT_URI = "replacementUri";
  private static final String PARAM_SOURCE = "source";
  private static final String PARAM_SOURCE_LABEL = "sourceLabel";
  private static final String PARAM_SUBSCRIPTION_ID = "subscriptionId";
  private static final String PARAM_SOURCE_URI = "sourceUri";
  private static final String PARAM_SUBJECT_KIND = "subjectKind";
  private static final String PARAM_SUBJECT_URI = "subjectUri";
  private static final String PARAM_URI = "uri";
  private static final String AUDIT_EVENT_STATEMENT_IMPORT_PREVIEWED = "statement_import_previewed";
  private static final String AUDIT_EVENT_STATEMENT_IMPORT_PREVIEW_REJECTED =
      "statement_import_preview_rejected";
  private static final String AUDIT_EVENT_STATEMENT_IMPORT_REJECTED = "statement_import_rejected";
  private static final String AUDIT_STATUS_OK = "ok";
  private static final String CRYPTA_SCHEME_PREFIX = "crypta:";
  private static final String CHK_PREFIX = "CHK@";
  private static final String SSK_PREFIX = "SSK@";
  private static final String USK_PREFIX = "USK@";
  private static final String KSK_PREFIX = "KSK@";
  private static final String SOURCE_LOCAL_IMPORT = "local-import";
  private static final String SOURCE_LOCAL_PUBLISH = "local-publish";
  private static final String SOURCE_MANUAL = "manual";
  private static final int DEFAULT_AUDIT_LIMIT = 50;

  private final TrustGraphStore store;
  private final Clock clock;
  private final AppNetworkBudgetService networkBudgetService;

  /**
   * Creates a handler backed by a process-local in-memory store.
   *
   * <p>This constructor is used only by reduced embeddings and tests that omit the shared durable
   * trust graph service. Production HTTP runtime composition injects a file-backed store through
   * the router's shared app-platform services.
   */
  public TrustGraphApiHandler() {
    this(new InMemoryTrustGraphStore(), Clock.systemUTC());
  }

  /**
   * Creates a handler that reports the trust graph store as unavailable.
   *
   * <p>Runtime composition uses this when the durable local store cannot be opened during HTTP
   * shell startup. Keeping an explicit handler instead of falling back to a process-local store
   * preserves route-time 503 responses without silently discarding durable trust state.
   *
   * @return handler whose routes fail with {@code trust_graph_store_unavailable}
   */
  public static TrustGraphApiHandler unavailable() {
    return new TrustGraphApiHandler(new UnavailableTrustGraphStore(), Clock.systemUTC());
  }

  /**
   * Creates a handler backed by an explicit local store.
   *
   * @param store local trust graph store used for imports, anchors, and score queries
   * @param clock clock used for anchor timestamps and expiry-sensitive score calculations
   */
  public TrustGraphApiHandler(TrustGraphStore store, Clock clock) {
    this(store, clock, null);
  }

  /**
   * Creates a handler backed by an explicit local store and optional shared network budget.
   *
   * @param store local trust graph store used for imports, anchors, and score queries
   * @param clock clock used for anchor timestamps and expiry-sensitive score calculations
   * @param networkBudgetService optional shared app-network budget service
   */
  public TrustGraphApiHandler(
      TrustGraphStore store, Clock clock, AppNetworkBudgetService networkBudgetService) {
    this.store = java.util.Objects.requireNonNull(store, "store");
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
    this.networkBudgetService = networkBudgetService;
  }

  /**
   * Returns local RC status.
   *
   * <p>The status response describes the route family, durable-store mode, and current local counts
   * without exposing any imported statement body, signature value, private insert URI, or app
   * identity material.
   *
   * @return insertion-ordered JSON-compatible status fields for the local RC service
   */
  public Map<String, Object> status() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("available", true);
    json.put("service", "trust-graph-local-rc");
    json.put("mode", "local-rc");
    json.put("documentType", TrustDocumentTypes.TRUST_STATEMENT_V1);
    json.put("contentType", TrustDocumentTypes.TRUST_STATEMENT_CONTENT_TYPE);
    json.put("scope", scopeJson());
    json.put("durable", store.durable());
    json.put("storeType", store.storeType());
    json.put("statementCount", store.statementCount());
    json.put("anchorCount", store.anchors().size());
    json.put("auditCount", store.auditEvents(store.config().maxAuditEntries()).size());
    json.put("limits", limitsJson());
    json.put("scoring", "direct-local-anchors-confidence-weighted-average");
    json.put("statementLifecycle", statementLifecycleJson());
    json.put("anchorLifecycle", anchorLifecycleJson());
    json.put("completeWot", false);
    return json;
  }

  /**
   * Lists local trust anchors.
   *
   * <p>Anchors are local policy inputs only. Listing them does not imply that the issuer is trusted
   * by other apps, other nodes, or daemon networking components.
   *
   * @return redacted local anchor summaries in deterministic order
   */
  public List<Map<String, Object>> anchors() {
    return store.anchors().stream().map(TrustAnchor::toJson).toList();
  }

  /**
   * Adds or replaces one local trust anchor.
   *
   * @param queryParameters decoded form fields containing {@code issuerFingerprint} and optional
   *     display metadata
   * @return redacted anchor summary after local storage
   * @throws PlatformApiException when anchor fields violate trust graph bounds
   */
  @SuppressWarnings("unused")
  public Map<String, Object> addAnchor(Map<String, List<String>> queryParameters) {
    return addAnchor(queryParameters, null);
  }

  /**
   * Adds or replaces one local trust anchor and records a redacted audit event.
   *
   * @param queryParameters decoded form fields containing {@code issuerFingerprint} and optional
   *     display metadata
   * @param appId optional authenticated app id associated with the request
   * @return redacted anchor summary after local storage
   */
  public Map<String, Object> addAnchor(Map<String, List<String>> queryParameters, String appId) {
    try {
      String issuerFingerprint =
          PlatformApiParameters.requireString(queryParameters, PARAM_ISSUER_FINGERPRINT);
      String label = PlatformApiParameters.readOptionalString(queryParameters, PARAM_LABEL);
      String source = PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE);
      TrustAnchor anchor = new TrustAnchor(issuerFingerprint, label, source, clock.instant());
      TrustAnchor stored = store.addAnchor(anchor);
      appendAnchorAudit("anchor_added_or_replaced", appId, stored.issuerFingerprint());
      return stored.toJson();
    } catch (TrustGraphException exception) {
      appendRejectedAudit("anchor_rejected", appId, null, exception.errorCode());
      throw toPlatformException(exception);
    }
  }

  /**
   * Removes one local trust anchor.
   *
   * @param fingerprint issuer fingerprint path segment selected for local removal
   * @return mutation result showing the normalized fingerprint and whether an anchor was removed
   * @throws PlatformApiException when the supplied fingerprint violates model bounds
   */
  @SuppressWarnings("unused")
  public Map<String, Object> removeAnchor(String fingerprint) {
    return removeAnchor(fingerprint, null);
  }

  /**
   * Removes one local trust anchor and records a redacted audit event when an anchor existed.
   *
   * @param fingerprint issuer fingerprint path segment selected for local removal
   * @param appId optional authenticated app id associated with the request
   * @return mutation result showing the normalized fingerprint and whether an anchor was removed
   */
  public Map<String, Object> removeAnchor(String fingerprint, String appId) {
    try {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put(PARAM_ISSUER_FINGERPRINT, fingerprint);
      boolean removed = store.removeAnchor(fingerprint);
      json.put("removed", removed);
      if (removed) {
        appendAnchorAudit("anchor_removed", appId, fingerprint);
      }
      return json;
    } catch (TrustGraphException exception) {
      appendRejectedAudit("anchor_rejected", appId, null, exception.errorCode());
      throw toPlatformException(exception);
    }
  }

  /**
   * Marks one retained local anchor deprecated in local lifecycle policy.
   *
   * @param fingerprint issuer fingerprint path segment
   * @param queryParameters decoded mutation parameters with optional reason fields
   * @param appId optional app id associated with the request
   * @return updated local anchor summary
   */
  public Map<String, Object> deprecateAnchor(
      String fingerprint, Map<String, List<String>> queryParameters, String appId) {
    return updateAnchorLifecycle(
        fingerprint, TrustStatementLifecycleStatus.DEPRECATED, queryParameters, appId);
  }

  /**
   * Marks one retained local anchor revoked in local lifecycle policy.
   *
   * @param fingerprint issuer fingerprint path segment
   * @param queryParameters decoded mutation parameters with optional reason fields
   * @param appId optional app id associated with the request
   * @return updated local anchor summary
   */
  public Map<String, Object> revokeAnchor(
      String fingerprint, Map<String, List<String>> queryParameters, String appId) {
    return updateAnchorLifecycle(
        fingerprint, TrustStatementLifecycleStatus.REVOKED, queryParameters, appId);
  }

  /**
   * Restores one retained local anchor to active local lifecycle policy.
   *
   * @param fingerprint issuer fingerprint path segment
   * @param queryParameters decoded mutation parameters with optional reason fields
   * @param appId optional app id associated with the request
   * @return updated local anchor summary
   */
  public Map<String, Object> reactivateAnchor(
      String fingerprint, Map<String, List<String>> queryParameters, String appId) {
    return updateAnchorLifecycle(
        fingerprint, TrustStatementLifecycleStatus.ACTIVE, queryParameters, appId);
  }

  /**
   * Imports one trust statement from form parameters.
   *
   * <p>The handler parses the bounded JSON document, delegates signature verification and retention
   * policy to the store, and returns only a redacted import summary. Unverified statements remain
   * visible as evidence but cannot contribute to score results.
   *
   * @param queryParameters decoded form fields containing {@code document} and optional redacted
   *     source URI/label metadata
   * @return redacted import summary without raw document text or signature values
   * @throws PlatformApiException when the document or source metadata is invalid
   */
  @SuppressWarnings("unused")
  public Map<String, Object> importStatement(Map<String, List<String>> queryParameters) {
    return importStatement(queryParameters, null);
  }

  /**
   * Imports one trust statement from form parameters and records redacted audit metadata.
   *
   * @param queryParameters decoded form fields containing {@code document} and optional source
   *     metadata
   * @param appId optional authenticated app id associated with the request
   * @return redacted import summary without raw document text or signature values
   */
  public Map<String, Object> importStatement(
      Map<String, List<String>> queryParameters, String appId) {
    try {
      String documentJson = PlatformApiParameters.requireString(queryParameters, PARAM_DOCUMENT);
      try (var _ = acquireTrustGraphImportBudgetLease(appId)) {
        TrustStatementDocument document = TrustStatementParser.parse(documentJson);
        TrustGraphImportResult result =
            store.importStatement(
                document,
                importSource(queryParameters),
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_URI),
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_LABEL),
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_SUBSCRIPTION_ID));
        appendImportAudit("statement_imported", appId, result);
        return result.toJson();
      }
    } catch (TrustGraphException exception) {
      appendRejectedAudit(
          AUDIT_EVENT_STATEMENT_IMPORT_REJECTED,
          appId,
          PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_URI),
          exception.errorCode());
      throw toPlatformException(exception);
    } catch (PlatformApiException exception) {
      appendRejectedAudit(
          AUDIT_EVENT_STATEMENT_IMPORT_REJECTED,
          appId,
          PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_URI),
          exception.errorCode());
      throw exception;
    }
  }

  /**
   * Previews one bounded trust statement import without mutating local graph state.
   *
   * <p>The preview accepts either a pasted {@code document} or a bounded Crypta {@code uri}. URI
   * previews use the same content-fetch boundary and Trust Graph import budget as commits. The
   * fetched body must be a root {@code crypta.trust.statement.v1} document because the matching
   * commit route imports exactly that shape. Pasted previews reserve the same Trust Graph import
   * budget before parsing preview candidates and may summarize wrapper payloads without making
   * those wrappers valid URI import targets.
   *
   * @param queryParameters decoded fields containing either {@code document} or {@code uri}
   * @param contentFetchPort runtime content fetch port used for URI previews
   * @param appId optional authenticated app id associated with the request
   * @return redacted preview summary without raw candidate statement content
   */
  public Map<String, Object> previewImport(
      Map<String, List<String>> queryParameters, ContentFetchPort contentFetchPort, String appId) {
    String uri = PlatformApiParameters.readOptionalString(queryParameters, PARAM_URI);
    String sourceUri = PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_URI);
    String documentJson =
        optionalNonBlankString(
            PlatformApiParameters.readOptionalString(queryParameters, PARAM_DOCUMENT));
    try {
      if (documentJson == null && uri != null) {
        try (var importReservation = reserveTrustGraphImportBudget(appId)) {
          documentJson = fetchPreviewDocument(queryParameters, contentFetchPort, appId, uri);
          sourceUri = uri;
          verifyUriPreviewIsDirectStatement(documentJson);
          commitTrustGraphImportBudget(importReservation);
          Map<String, Object> preview =
              buildImportPreview(queryParameters, sourceUri, documentJson);
          appendPreviewAudit(appId, sourceUri, preview);
          return preview;
        }
      } else if (documentJson != null) {
        try (var importReservation = reserveTrustGraphImportBudget(appId)) {
          commitTrustGraphImportBudget(importReservation);
          Map<String, Object> preview =
              buildImportPreview(queryParameters, sourceUri, documentJson);
          appendPreviewAudit(appId, sourceUri, preview);
          return preview;
        }
      } else {
        throw new PlatformApiException(
            400, "invalid_query_parameter", "Import preview requires document or uri.");
      }
    } catch (TrustGraphException exception) {
      appendRejectedAudit(
          AUDIT_EVENT_STATEMENT_IMPORT_PREVIEW_REJECTED,
          appId,
          sourceUri == null ? uri : sourceUri,
          exception.errorCode());
      throw toPlatformException(exception);
    } catch (PlatformApiException exception) {
      appendRejectedAudit(
          AUDIT_EVENT_STATEMENT_IMPORT_PREVIEW_REJECTED,
          appId,
          sourceUri == null ? uri : sourceUri,
          exception.errorCode());
      throw exception;
    }
  }

  private Map<String, Object> buildImportPreview(
      Map<String, List<String>> queryParameters, String sourceUri, String documentJson) {
    return TrustGraphImportPreview.preview(
            documentJson,
            store,
            sourceUri,
            PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_LABEL),
            readMaxBytes(queryParameters),
            clock.instant())
        .toJson();
  }

  /**
   * Fetches one bounded Crypta content URI, parses it as a trust statement, and imports it.
   *
   * <p>The response is the same redacted import summary as {@link #importStatement(Map, String)}.
   * Raw fetched content and raw statement JSON are not returned to the caller.
   *
   * @param queryParameters decoded form fields containing {@code uri}
   * @param contentFetchPort runtime content fetch port
   * @param appId optional authenticated app id associated with the request
   * @return redacted import summary without raw fetched content
   */
  public Map<String, Object> importUri(
      Map<String, List<String>> queryParameters, ContentFetchPort contentFetchPort, String appId) {
    if (contentFetchPort == null) {
      throw new PlatformApiException(
          503, "content_fetch_failed", "Content fetch service is unavailable.");
    }
    String uri = PlatformApiParameters.requireString(queryParameters, PARAM_URI);
    int maxBytes = readMaxBytes(queryParameters);
    try {
      try (var importReservation = reserveTrustGraphImportBudget(appId)) {
        Map<String, Object> fetched =
            new ContentApiHandler(
                    contentFetchPort,
                    networkBudgetService,
                    AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI)
                .fetch(
                    Map.of(
                        PARAM_URI,
                        List.of(uri),
                        PARAM_MAX_BYTES,
                        List.of(Integer.toString(maxBytes)),
                        "format",
                        List.of("text"),
                        "purpose",
                        List.of("trust-graph-import")),
                    budgetAppId(appId));
        Object contentText = fetched.get("contentText");
        if (!(contentText instanceof String documentJson)) {
          throw new PlatformApiException(
              415, "unsupported_content_encoding", "Fetched trust statement is not valid UTF-8.");
        }
        if (documentJson.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
          throw new PlatformApiException(
              502,
              "content_fetch_too_large",
              "Fetched content exceeded the configured byte bound.");
        }
        commitTrustGraphImportBudget(importReservation);
        TrustStatementDocument document = TrustStatementParser.parse(documentJson);
        verifyExpectedDocumentFingerprint(
            PlatformApiParameters.readOptionalString(
                queryParameters, PARAM_EXPECTED_DOCUMENT_FINGERPRINT),
            document);
        TrustGraphImportResult result =
            store.importStatement(
                document,
                "content-fetch",
                uri,
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_LABEL),
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_SUBSCRIPTION_ID));
        appendImportAudit("statement_imported_from_uri", appId, result);
        return result.toJson();
      }
    } catch (TrustGraphException exception) {
      appendRejectedAudit(AUDIT_EVENT_STATEMENT_IMPORT_REJECTED, appId, uri, exception.errorCode());
      throw toPlatformException(exception);
    } catch (PlatformApiException exception) {
      appendRejectedAudit(AUDIT_EVENT_STATEMENT_IMPORT_REJECTED, appId, uri, exception.errorCode());
      throw exception;
    }
  }

  private String fetchPreviewDocument(
      Map<String, List<String>> queryParameters,
      ContentFetchPort contentFetchPort,
      String appId,
      String uri) {
    if (contentFetchPort == null) {
      throw new PlatformApiException(
          503, "content_fetch_failed", "Content fetch service is unavailable.");
    }
    int maxBytes = readMaxBytes(queryParameters);
    Map<String, Object> fetched =
        new ContentApiHandler(
                contentFetchPort,
                networkBudgetService,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI)
            .fetch(
                Map.of(
                    PARAM_URI,
                    List.of(uri),
                    PARAM_MAX_BYTES,
                    List.of(Integer.toString(maxBytes)),
                    "format",
                    List.of("text"),
                    "purpose",
                    List.of("trust-graph-import-preview")),
                budgetAppId(appId));
    Object contentText = fetched.get("contentText");
    if (!(contentText instanceof String documentJson)) {
      throw new PlatformApiException(
          415, "unsupported_content_encoding", "Fetched trust statement is not valid UTF-8.");
    }
    if (documentJson.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
      throw new PlatformApiException(
          502, "content_fetch_too_large", "Fetched content exceeded the configured byte bound.");
    }
    return documentJson;
  }

  private static void verifyUriPreviewIsDirectStatement(String documentJson) {
    TrustStatementParser.parse(documentJson);
  }

  private static void verifyExpectedDocumentFingerprint(
      String expectedDocumentFingerprint, TrustStatementDocument document) {
    if (expectedDocumentFingerprint == null || expectedDocumentFingerprint.isBlank()) {
      return;
    }
    String actualDocumentFingerprint = TrustStatementFingerprint.documentFingerprint(document);
    if (!expectedDocumentFingerprint.equals(actualDocumentFingerprint)) {
      throw new PlatformApiException(
          409,
          "trust_import_preview_stale",
          "Fetched trust statement no longer matches the import preview.");
    }
  }

  private AppNetworkBudgetReservation reserveTrustGraphImportBudget(String appId) {
    if (networkBudgetService == null) {
      return AppNetworkBudgetReservation.noop(
          budgetAppId(appId), AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT, clock.instant());
    }
    AppNetworkBudgetReservation reservation =
        networkBudgetService.reserve(
            budgetAppId(appId), AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    AppNetworkBudgetDecision decision = reservation.decision();
    if (!decision.allowed()) {
      throw new PlatformApiException(
          decision.statusCode(), decision.errorCode(), decision.message());
    }
    return reservation;
  }

  private static void commitTrustGraphImportBudget(AppNetworkBudgetReservation reservation) {
    AppNetworkBudgetDecision decision = reservation.commit();
    if (!decision.allowed()) {
      throw new PlatformApiException(
          decision.statusCode(), decision.errorCode(), decision.message());
    }
  }

  private AppNetworkBudgetLease acquireTrustGraphImportBudgetLease(String appId) {
    if (networkBudgetService == null) {
      return AppNetworkBudgetLease.noop();
    }
    AppNetworkBudgetDecision decision =
        networkBudgetService.acquire(
            budgetAppId(appId), AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    if (!decision.allowed()) {
      throw new PlatformApiException(
          decision.statusCode(), decision.errorCode(), decision.message());
    }
    return decision.lease();
  }

  private static String budgetAppId(String appId) {
    return appId == null || appId.isBlank() ? AppNetworkBudgetScope.HOST_OPERATOR : appId;
  }

  /**
   * Lists recent redacted trust graph audit events.
   *
   * @param queryParameters decoded query fields; optional {@code limit} caps the response
   * @return redacted audit summaries in newest-first order
   */
  public List<Map<String, Object>> audit(Map<String, List<String>> queryParameters) {
    int limit = readAuditLimit(queryParameters);
    return store.auditEvents(limit).stream().map(TrustGraphAuditEvent::toJson).toList();
  }

  /**
   * Lists distinct subjects with imported statements.
   *
   * @return unique subject summaries currently represented by retained imported statements
   */
  public List<Map<String, Object>> subjects() {
    return store.subjects().stream().map(TrustSubject::toJson).toList();
  }

  /**
   * Lists redacted trust statement summaries with optional filters.
   *
   * <p>When any subject filter is present, {@code subjectKind}, {@code subjectUri}, and {@code
   * context} must be supplied together. The summaries include public scores, timestamps, and
   * verification status, but not raw statement bodies or signature values.
   *
   * @param queryParameters decoded query fields for optional subject/context and issuer filtering
   * @return redacted statement summaries that match the supplied filters
   * @throws PlatformApiException when partial or unsupported filters are supplied
   */
  public List<Map<String, Object>> statements(Map<String, List<String>> queryParameters) {
    try {
      String issuerFingerprint =
          PlatformApiParameters.readOptionalString(queryParameters, PARAM_ISSUER_FINGERPRINT);
      TrustGraphQuery query = optionalQuery(queryParameters);
      return store.statements().stream()
          .filter(statement -> issuerMatches(statement.document().payload(), issuerFingerprint))
          .filter(statement -> query == null || query.matches(statement.document().payload()))
          .map(
              statement ->
                  statement.toSummaryJson(store.lifecycle(statement.documentFingerprint())))
          .toList();
    } catch (TrustGraphException exception) {
      throw toPlatformException(exception);
    }
  }

  /**
   * Returns one redacted statement summary by canonical document fingerprint.
   *
   * @param fingerprint document fingerprint path segment
   * @return redacted statement summary with lifecycle metadata
   * @throws PlatformApiException when the fingerprint is invalid or no retained statement matches
   */
  public Map<String, Object> statement(String fingerprint) {
    try {
      TrustGraphStore.StoredTrustStatement statement = store.statement(fingerprint);
      if (statement == null) {
        throw new TrustGraphException(
            "trust_statement_not_found", "Trust statement was not found.");
      }
      return statement.toSummaryJson(store.lifecycle(statement.documentFingerprint()));
    } catch (TrustGraphException exception) {
      throw toPlatformException(exception);
    }
  }

  /**
   * Marks one retained statement deprecated in local lifecycle policy.
   *
   * @param fingerprint document fingerprint path segment
   * @param queryParameters decoded mutation parameters with optional reason and note fields
   * @param appId optional app id associated with the request
   * @return stored local lifecycle summary
   */
  public Map<String, Object> deprecateStatement(
      String fingerprint, Map<String, List<String>> queryParameters, String appId) {
    return updateLifecycle(
        fingerprint, TrustStatementLifecycleStatus.DEPRECATED, queryParameters, appId);
  }

  /**
   * Marks one retained statement revoked in local lifecycle policy.
   *
   * @param fingerprint document fingerprint path segment
   * @param queryParameters decoded mutation parameters with optional reason and note fields
   * @param appId optional app id associated with the request
   * @return stored local lifecycle summary
   */
  public Map<String, Object> revokeStatement(
      String fingerprint, Map<String, List<String>> queryParameters, String appId) {
    return updateLifecycle(
        fingerprint, TrustStatementLifecycleStatus.REVOKED, queryParameters, appId);
  }

  /**
   * Restores one retained statement to active local lifecycle policy.
   *
   * @param fingerprint document fingerprint path segment
   * @param queryParameters decoded mutation parameters with optional reason and note fields
   * @param appId optional app id associated with the request
   * @return stored local lifecycle summary
   */
  public Map<String, Object> reactivateStatement(
      String fingerprint, Map<String, List<String>> queryParameters, String appId) {
    return updateLifecycle(
        fingerprint, TrustStatementLifecycleStatus.ACTIVE, queryParameters, appId);
  }

  /**
   * Scores one subject/context query.
   *
   * <p>The scorer is deterministic and direct-anchor only. It does not crawl, subscribe, moderate,
   * or apply global policy. Evidence rows are bounded and included only when requested.
   *
   * @param queryParameters decoded query fields containing subject kind, subject URI, context, and
   *     optional evidence flag
   * @return score summary with optional bounded evidence rows
   * @throws PlatformApiException when required query fields are missing or invalid
   */
  public Map<String, Object> score(Map<String, List<String>> queryParameters) {
    try {
      TrustGraphQuery query = requiredQuery(queryParameters);
      boolean includeEvidence =
          PlatformApiParameters.readBoolean(queryParameters, PARAM_INCLUDE_EVIDENCE, false);
      TrustGraphScore score = new TrustGraphScorer(store, clock).score(query);
      return score.toJson(includeEvidence);
    } catch (TrustGraphException exception) {
      throw toPlatformException(exception);
    }
  }

  private static boolean issuerMatches(TrustStatementPayload payload, String issuerFingerprint) {
    return issuerFingerprint == null
        || payload.issuer().publicKeyFingerprint().equals(issuerFingerprint.trim());
  }

  private static TrustGraphQuery optionalQuery(Map<String, List<String>> queryParameters) {
    String subjectKind =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_SUBJECT_KIND);
    String subjectUri =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_SUBJECT_URI);
    String context = PlatformApiParameters.readOptionalString(queryParameters, PARAM_CONTEXT);
    if (subjectKind == null && subjectUri == null && context == null) {
      return null;
    }
    if (subjectKind == null || subjectUri == null || context == null) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "subjectKind, subjectUri, and context must be supplied together.");
    }
    return new TrustGraphQuery(TrustSubjectKind.parse(subjectKind), subjectUri, context);
  }

  private static TrustGraphQuery requiredQuery(Map<String, List<String>> queryParameters) {
    return new TrustGraphQuery(
        TrustSubjectKind.parse(
            PlatformApiParameters.requireString(queryParameters, PARAM_SUBJECT_KIND)),
        PlatformApiParameters.requireString(queryParameters, PARAM_SUBJECT_URI),
        PlatformApiParameters.requireString(queryParameters, PARAM_CONTEXT));
  }

  private static PlatformApiException toPlatformException(TrustGraphException exception) {
    if ("trust_graph_store_unavailable".equals(exception.errorCode())) {
      return new PlatformApiException(503, exception.errorCode(), exception.getMessage());
    }
    if ("trust_statement_not_found".equals(exception.errorCode())) {
      return new PlatformApiException(404, exception.errorCode(), exception.getMessage());
    }
    if ("trust_anchor_not_found".equals(exception.errorCode())) {
      return new PlatformApiException(404, exception.errorCode(), exception.getMessage());
    }
    return new PlatformApiException(400, exception.errorCode(), exception.getMessage());
  }

  private Map<String, Object> limitsJson() {
    LinkedHashMap<String, Object> limits = LinkedHashMap.newLinkedHashMap(6);
    limits.put("maxEvidenceRows", TrustGraphScorer.MAX_EVIDENCE_ROWS);
    limits.put("maxStatements", store.config().maxStatements());
    limits.put("maxAnchors", store.config().maxAnchors());
    limits.put("maxAuditEntries", store.config().maxAuditEntries());
    limits.put("maxStoredDocumentBytes", store.config().maxStoredDocumentBytes());
    limits.put("maxLifecycleRecords", store.config().maxLifecycleRecords());
    return limits;
  }

  private static Map<String, Object> scopeJson() {
    LinkedHashMap<String, Object> scope = LinkedHashMap.newLinkedHashMap(7);
    scope.put("localAnchorsOnly", true);
    scope.put("importedStatementsOnly", true);
    scope.put("noCrawling", true);
    scope.put("noGlobalModeration", true);
    scope.put("noBlocking", true);
    scope.put("noRoutingDecisions", true);
    scope.put("noLegacyWoTCompatibility", true);
    return scope;
  }

  private static Map<String, Object> statementLifecycleJson() {
    LinkedHashMap<String, Object> lifecycle = LinkedHashMap.newLinkedHashMap(4);
    lifecycle.put("supportsLocalRevocation", true);
    lifecycle.put("supportsLocalDeprecation", true);
    lifecycle.put("revokedContributes", false);
    lifecycle.put("deprecatedContributes", false);
    return lifecycle;
  }

  private static Map<String, Object> anchorLifecycleJson() {
    LinkedHashMap<String, Object> lifecycle = LinkedHashMap.newLinkedHashMap(5);
    lifecycle.put("supportsLocalRevocation", true);
    lifecycle.put("supportsLocalDeprecation", true);
    lifecycle.put("supportsLocalReactivation", true);
    lifecycle.put("revokedContributes", false);
    lifecycle.put("deprecatedContributes", false);
    return lifecycle;
  }

  private int readMaxBytes(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.readOptionalString(queryParameters, PARAM_MAX_BYTES);
    if (raw == null || raw.isBlank()) {
      return Math.min(
          store.config().maxStoredDocumentBytes(), TrustStatementValidator.MAX_DOCUMENT_BYTES);
    }
    int value;
    try {
      value = Integer.parseInt(raw.trim());
    } catch (NumberFormatException _) {
      throw invalidPositiveInteger(PARAM_MAX_BYTES);
    }
    if (value <= 0) {
      throw invalidPositiveInteger(PARAM_MAX_BYTES);
    }
    int hardLimit =
        Math.min(
            store.config().maxStoredDocumentBytes(), TrustStatementValidator.MAX_DOCUMENT_BYTES);
    if (value > hardLimit) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "Query parameter 'maxBytes' exceeds the supported trust statement limit.");
    }
    return value;
  }

  private static String optionalNonBlankString(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private int readAuditLimit(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.readOptionalString(queryParameters, PARAM_LIMIT);
    if (raw == null || raw.isBlank()) {
      return DEFAULT_AUDIT_LIMIT;
    }
    int value;
    try {
      value = Integer.parseInt(raw.trim());
    } catch (NumberFormatException _) {
      throw invalidPositiveInteger(PARAM_LIMIT);
    }
    if (value <= 0) {
      throw invalidPositiveInteger(PARAM_LIMIT);
    }
    return Math.min(value, store.config().maxAuditEntries());
  }

  private static PlatformApiException invalidPositiveInteger(String name) {
    return new PlatformApiException(
        400,
        "invalid_query_parameter",
        "Query parameter '" + name + "' must be a positive integer.");
  }

  private static String importSource(Map<String, List<String>> queryParameters) {
    String source = PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE);
    if (source == null) {
      return SOURCE_LOCAL_IMPORT;
    }
    String normalized = source.trim();
    return switch (normalized) {
      case SOURCE_LOCAL_IMPORT, SOURCE_LOCAL_PUBLISH, SOURCE_MANUAL -> normalized;
      default -> SOURCE_LOCAL_IMPORT;
    };
  }

  private Map<String, Object> updateLifecycle(
      String fingerprint,
      TrustStatementLifecycleStatus status,
      Map<String, List<String>> queryParameters,
      String appId) {
    try {
      TrustStatementLifecycleRecord lifecycleRecord =
          store.updateLifecycle(
              fingerprint,
              status,
              PlatformApiParameters.readOptionalString(queryParameters, PARAM_REASON_CODE),
              PlatformApiParameters.readOptionalString(queryParameters, PARAM_NOTE),
              PlatformApiParameters.readOptionalString(queryParameters, PARAM_REPLACEMENT_URI),
              appId,
              appId == null ? "operator" : "app");
      appendLifecycleAudit("statement_lifecycle_" + status.jsonValue(), appId, lifecycleRecord);
      return lifecycleRecord.toJson();
    } catch (TrustGraphException exception) {
      appendRejectedAudit("statement_lifecycle_rejected", appId, null, exception.errorCode());
      throw toPlatformException(exception);
    }
  }

  private Map<String, Object> updateAnchorLifecycle(
      String fingerprint,
      TrustStatementLifecycleStatus status,
      Map<String, List<String>> queryParameters,
      String appId) {
    try {
      TrustAnchor anchor =
          store.updateAnchorLifecycle(
              fingerprint,
              status,
              PlatformApiParameters.readOptionalString(queryParameters, PARAM_REASON_CODE),
              appId,
              appId == null ? "operator" : "app");
      appendAnchorAudit(
          "anchor_lifecycle_" + status.jsonValue(), appId, anchor.issuerFingerprint());
      return anchor.toJson();
    } catch (TrustGraphException exception) {
      appendRejectedAudit("anchor_lifecycle_rejected", appId, null, exception.errorCode());
      throw toPlatformException(exception);
    }
  }

  private void appendAnchorAudit(String eventType, String appId, String issuerFingerprint) {
    store.appendAuditEvent(
        new TrustGraphAuditEvent(
            eventType,
            clock.instant(),
            appId,
            null,
            null,
            issuerFingerprint,
            null,
            null,
            null,
            SOURCE_MANUAL,
            null,
            null,
            null,
            AUDIT_STATUS_OK));
  }

  private void appendImportAudit(String eventType, String appId, TrustGraphImportResult result) {
    TrustStatementPayload payload = result.document().payload();
    store.appendAuditEvent(
        new TrustGraphAuditEvent(
            eventType,
            clock.instant(),
            appId,
            result.documentFingerprint(),
            result.payloadHash(),
            payload.issuer().publicKeyFingerprint(),
            payload.subject().kind().jsonValue(),
            hashText(payload.subject().uri()),
            redactedUriSummary(payload.subject().uri()),
            result.source(),
            result.sourceUriHash(),
            result.sourceUri(),
            result.signatureVerified(),
            AUDIT_STATUS_OK));
  }

  private void appendLifecycleAudit(
      String eventType, String appId, TrustStatementLifecycleRecord lifecycleRecord) {
    store.appendAuditEvent(
        new TrustGraphAuditEvent(
            eventType,
            clock.instant(),
            appId,
            lifecycleRecord.statementFingerprint(),
            null,
            null,
            null,
            null,
            null,
            lifecycleRecord.source(),
            null,
            null,
            null,
            lifecycleRecord.status().jsonValue()));
  }

  private void appendPreviewAudit(String appId, String sourceUri, Map<String, Object> preview) {
    store.appendAuditEvent(
        new TrustGraphAuditEvent(
            AUDIT_EVENT_STATEMENT_IMPORT_PREVIEWED,
            clock.instant(),
            appId,
            null,
            null,
            null,
            null,
            null,
            null,
            "preview",
            null,
            redactedRejectedUriSummary(sourceUri),
            null,
            previewStatus(preview)));
  }

  private static String previewStatus(Map<String, Object> preview) {
    Object conflictCount = preview.get("conflictCount");
    Object rejectedCount = preview.get("rejectedCount");
    Object materialRisk = preview.get("materialRisk");
    if (Boolean.TRUE.equals(materialRisk)) {
      return "manual-review";
    }
    if (conflictCount instanceof Number number && number.intValue() > 0) {
      return "conflict";
    }
    if (rejectedCount instanceof Number number && number.intValue() > 0) {
      return "rejected";
    }
    return AUDIT_STATUS_OK;
  }

  private void appendRejectedAudit(
      String eventType, String appId, String sourceUri, String statusCode) {
    store.appendAuditEvent(
        new TrustGraphAuditEvent(
            eventType,
            clock.instant(),
            appId,
            null,
            null,
            null,
            null,
            null,
            null,
            "rejected",
            null,
            redactedRejectedUriSummary(sourceUri),
            null,
            statusCode));
  }

  private static String hashText(String value) {
    return value == null
        ? null
        : network.crypta.platform.trustgraph.TrustStatementFingerprint.sha256Hex(
            value.getBytes(StandardCharsets.UTF_8));
  }

  private static String redactedUriSummary(String uri) {
    if (uri == null || uri.isBlank()) {
      return null;
    }
    String trimmed = uri.trim();
    String type = redactedUriSummaryType(trimmed);
    return type + ":sha256:" + hashText(trimmed).substring(0, 16);
  }

  private static String redactedRejectedUriSummary(String uri) {
    if (uri == null || uri.isBlank()) {
      return null;
    }
    String trimmed = uri.trim();
    String type = redactedRejectedUriSummaryType(trimmed);
    return type + ":redacted";
  }

  private static String redactedRejectedUriSummaryType(String trimmed) {
    if (containsUnsafeUriText(trimmed)) {
      return "uri";
    }
    String directType = knownContentKeyFamily(trimmed);
    if (directType != null) {
      return directType;
    }
    if (trimmed.regionMatches(true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      String runtime = trimmed.substring(CRYPTA_SCHEME_PREFIX.length());
      if (!containsUnsafeUriText(runtime)) {
        String nestedType = knownContentKeyFamily(runtime);
        if (nestedType != null) {
          return "crypta_" + nestedType;
        }
      }
    }
    return "uri";
  }

  private static String redactedUriSummaryType(String trimmed) {
    String directType = knownContentKeyFamily(trimmed);
    if (directType != null) {
      return directType;
    }
    if (trimmed.regionMatches(true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      String runtime = trimmed.substring(CRYPTA_SCHEME_PREFIX.length());
      String nestedType = knownContentKeyFamily(runtime);
      if (nestedType != null) {
        return "crypta_" + nestedType;
      }
    }
    return "uri";
  }

  private static String knownContentKeyFamily(String candidate) {
    String family = knownContentKeyFamily(candidate, CHK_PREFIX);
    if (family == null) {
      family = knownContentKeyFamily(candidate, SSK_PREFIX);
    }
    if (family == null) {
      family = knownContentKeyFamily(candidate, USK_PREFIX);
    }
    if (family == null) {
      family = knownContentKeyFamily(candidate, KSK_PREFIX);
    }
    return family;
  }

  private static String knownContentKeyFamily(String candidate, String prefix) {
    if (candidate.regionMatches(true, 0, prefix, 0, prefix.length())) {
      return prefix.substring(0, prefix.length() - 1);
    }
    return null;
  }

  private static boolean containsUnsafeUriText(String value) {
    return value.isEmpty()
        || value.indexOf('?') >= 0
        || value.indexOf('#') >= 0
        || value.indexOf('\\') >= 0
        || value.startsWith("/")
        || hasWhitespaceOrControl(value);
  }

  private static boolean hasWhitespaceOrControl(String value) {
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      if (Character.isWhitespace(ch) || Character.isISOControl(ch)) {
        return true;
      }
    }
    return false;
  }

  private static final class UnavailableTrustGraphStore implements TrustGraphStore {
    @Override
    public TrustGraphImportResult importStatement(
        TrustStatementDocument document, String source, String sourceUri, String sourceLabel) {
      throw unavailable();
    }

    @Override
    public TrustAnchor addAnchor(TrustAnchor anchor) {
      throw unavailable();
    }

    @Override
    public boolean removeAnchor(String issuerFingerprint) {
      throw unavailable();
    }

    @Override
    public List<TrustAnchor> anchors() {
      throw unavailable();
    }

    @Override
    public List<StoredTrustStatement> statements() {
      throw unavailable();
    }

    @Override
    public List<TrustSubject> subjects() {
      throw unavailable();
    }

    @Override
    public boolean isAnchor(String issuerFingerprint) {
      throw unavailable();
    }

    @Override
    public int statementCount() {
      throw unavailable();
    }

    @Override
    public boolean durable() {
      throw unavailable();
    }

    @Override
    public String storeType() {
      throw unavailable();
    }

    @Override
    public network.crypta.platform.trustgraph.TrustGraphStoreConfig config() {
      throw unavailable();
    }

    @Override
    public void appendAuditEvent(TrustGraphAuditEvent event) {
      throw unavailable();
    }

    @Override
    public List<TrustGraphAuditEvent> auditEvents(int limit) {
      throw unavailable();
    }

    private static TrustGraphException unavailable() {
      return new TrustGraphException(
          "trust_graph_store_unavailable", "Trust graph store is unavailable.");
    }
  }
}
