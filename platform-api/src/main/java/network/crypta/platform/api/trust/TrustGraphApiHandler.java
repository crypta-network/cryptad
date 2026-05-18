package network.crypta.platform.api.trust;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.trustgraph.InMemoryTrustGraphStore;
import network.crypta.platform.trustgraph.TrustAnchor;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustGraphException;
import network.crypta.platform.trustgraph.TrustGraphImportResult;
import network.crypta.platform.trustgraph.TrustGraphQuery;
import network.crypta.platform.trustgraph.TrustGraphScore;
import network.crypta.platform.trustgraph.TrustGraphScorer;
import network.crypta.platform.trustgraph.TrustGraphStore;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementParser;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;

/**
 * Handles the local Trust Graph Preview route family.
 *
 * <p>The handler stores only validated trust statement models, redacted source labels, and local
 * anchors. It never returns raw imported document bodies, signature values, request bodies, browser
 * session tokens, app process tokens, form passwords, private identity material, or local paths.
 *
 * <p>This class is intentionally transport-neutral. The parent Platform API router performs
 * authentication, capability checks, and audit emission; this handler focuses on decoded
 * parameters, trust-graph model validation, response shaping, and translating model failures into
 * stable client errors. The backing store is process-local for the preview and should be treated as
 * app-platform state, not as daemon-core reputation or moderation state.
 */
public final class TrustGraphApiHandler {
  private static final String PARAM_CONTEXT = "context";
  private static final String PARAM_DOCUMENT = "document";
  private static final String PARAM_INCLUDE_EVIDENCE = "includeEvidence";
  private static final String PARAM_ISSUER_FINGERPRINT = "issuerFingerprint";
  private static final String PARAM_LABEL = "label";
  private static final String PARAM_SOURCE = "source";
  private static final String PARAM_SOURCE_LABEL = "sourceLabel";
  private static final String PARAM_SOURCE_URI = "sourceUri";
  private static final String PARAM_SUBJECT_KIND = "subjectKind";
  private static final String PARAM_SUBJECT_URI = "subjectUri";

  private final TrustGraphStore store;
  private final Clock clock;

  /**
   * Creates a handler backed by a process-local in-memory store.
   *
   * <p>This constructor is used by the default Platform API router composition. The store is
   * bounded and non-durable, which matches the preview service: imports and anchors survive only as
   * long as the process-owned service instance remains live.
   */
  public TrustGraphApiHandler() {
    this(new InMemoryTrustGraphStore(), Clock.systemUTC());
  }

  /**
   * Creates a handler backed by an explicit local store.
   *
   * @param store local trust graph store used for imports, anchors, and score queries
   * @param clock clock used for anchor timestamps and expiry-sensitive score calculations
   */
  public TrustGraphApiHandler(TrustGraphStore store, Clock clock) {
    this.store = java.util.Objects.requireNonNull(store, "store");
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
  }

  /**
   * Returns local preview status.
   *
   * <p>The status response describes the route family and current in-memory counts without exposing
   * any imported statement body, signature value, or app identity material.
   *
   * @return insertion-ordered JSON-compatible status fields for the local preview service
   */
  public Map<String, Object> status() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("available", true);
    json.put("service", "trust-graph-preview");
    json.put("documentType", TrustDocumentTypes.TRUST_STATEMENT_V1);
    json.put("contentType", TrustDocumentTypes.TRUST_STATEMENT_CONTENT_TYPE);
    json.put("statementCount", store.statementCount());
    json.put("anchorCount", store.anchors().size());
    json.put("scoring", "direct-local-anchors-confidence-weighted-average");
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
  public Map<String, Object> addAnchor(Map<String, List<String>> queryParameters) {
    try {
      String issuerFingerprint =
          PlatformApiParameters.requireString(queryParameters, PARAM_ISSUER_FINGERPRINT);
      String label = PlatformApiParameters.readOptionalString(queryParameters, PARAM_LABEL);
      String source = PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE);
      TrustAnchor anchor = new TrustAnchor(issuerFingerprint, label, source, clock.instant());
      return store.addAnchor(anchor).toJson();
    } catch (TrustGraphException exception) {
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
  public Map<String, Object> removeAnchor(String fingerprint) {
    try {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put(PARAM_ISSUER_FINGERPRINT, fingerprint);
      json.put("removed", store.removeAnchor(fingerprint));
      return json;
    } catch (TrustGraphException exception) {
      throw toPlatformException(exception);
    }
  }

  /**
   * Imports one trust statement from form parameters.
   *
   * <p>The handler parses the bounded JSON document, delegates signature verification and retention
   * policy to the store, and returns only a redacted import summary. Unverified statements remain
   * visible as evidence but cannot contribute to score results.
   *
   * @param queryParameters decoded form fields containing {@code document} and optional source
   *     metadata
   * @return redacted import summary without raw document text or signature values
   * @throws PlatformApiException when the document or source metadata is invalid
   */
  public Map<String, Object> importStatement(Map<String, List<String>> queryParameters) {
    try {
      String documentJson = PlatformApiParameters.requireString(queryParameters, PARAM_DOCUMENT);
      TrustStatementDocument document = TrustStatementParser.parse(documentJson);
      TrustGraphImportResult result =
          store.importStatement(
              document,
              "local-import",
              PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_URI),
              PlatformApiParameters.readOptionalString(queryParameters, PARAM_SOURCE_LABEL));
      return result.toJson();
    } catch (TrustGraphException exception) {
      throw toPlatformException(exception);
    }
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
          .map(TrustGraphStore.StoredTrustStatement::toSummaryJson)
          .toList();
    } catch (TrustGraphException exception) {
      throw toPlatformException(exception);
    }
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
    return new PlatformApiException(400, exception.errorCode(), exception.getMessage());
  }
}
