package network.crypta.platform.trustgraph;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Redacted preview for a pending Trust Graph Local RC statement import.
 *
 * <p>The preview stage lets a first-party app or the local Trust Graph UI inspect import risk
 * before any statement mutates local graph state. It accepts the same public trust-statement
 * payloads used by the import route, compares each bounded candidate with the current store
 * snapshot, and returns only aggregate counts plus capped per-candidate summaries. That makes it
 * suitable for consent previews, operator confirmation screens, and support evidence that need to
 * show risk without becoming a raw-content archive.
 *
 * <p>The object is immutable after construction and does not retain the caller's raw document text.
 * It also does not change anchors, statement records, lifecycle records, audit history, app data,
 * or service grants. A later commit must submit the statement again through the normal import path,
 * where parsing, lifecycle checks, network budgets, and consent snapshot validation run again.
 * Keeping preview and commit separate is deliberate: previews are advisory local evidence, not a
 * global Web-of-Trust assertion or moderation decision.
 */
public final class TrustGraphImportPreview {
  /**
   * Maximum number of candidate statement values inspected from a single preview payload.
   *
   * <p>The cap prevents a preview-only call from becoming an unbounded parser or comparison scan.
   * Additional candidates are counted as rejected and summarized through the warning list instead
   * of being parsed, scored, or echoed back to the caller.
   */
  public static final int MAX_PREVIEW_STATEMENTS = 64;

  /**
   * Maximum number of per-candidate summaries included in the response.
   *
   * <p>The aggregate counters always account for the bounded candidate set, but detailed summaries
   * are kept short so UI panels, support bundles, and release evidence cannot become raw data
   * dumps. Each summary still carries enough redacted metadata for duplicate, issuer-conflict,
   * lifecycle, expiry, and signature-verification decisions.
   */
  public static final int MAX_CANDIDATE_SUMMARIES = 16;

  /*
   * Keep warnings short and deduplicated. They are operator-facing risk markers, not parser traces
   * or raw validation reports.
   */
  private static final int MAX_WARNINGS = 8;

  private final Map<String, Object> json;

  private TrustGraphImportPreview(Map<String, Object> json) {
    this.json = Collections.unmodifiableMap(new LinkedHashMap<>(json));
  }

  /**
   * Builds a redacted import preview for one JSON payload.
   *
   * <p>The payload may be a single {@code crypta.trust.statement.v1} document, an array of
   * statement documents, or an object with a {@code statements} array. Malformed candidates are
   * counted as rejected instead of being echoed. Store lookups use statement fingerprints and
   * issuer-subject keys only; raw statement text and signature values are discarded after parsing.
   * The returned preview is safe to serialize through the Platform API because it contains hashes,
   * lifecycle labels, bounded counts, and source summaries rather than raw fetched content.
   *
   * <p>A {@code null} {@code documentJson} value is treated as empty input and produces a rejected
   * candidate summary. {@code maxBytes} is clamped to at least one byte so callers cannot disable
   * byte enforcement accidentally. The method reads the supplied store but does not write audit
   * records, import statements, or lifecycle changes.
   *
   * @param documentJson candidate statement JSON supplied by paste or bounded content fetch
   * @param store local Trust Graph store used for duplicate and lifecycle comparisons
   * @param sourceUri optional import source URI, summarized by kind and hash only
   * @param sourceLabel optional caller display label, sanitized before inclusion
   * @param maxBytes maximum accepted UTF-8 bytes for the preview input
   * @param now clock value used for deterministic expiry checks
   * @return immutable preview object suitable for Platform API serialization
   * @throws NullPointerException when {@code store} or {@code now} is {@code null}
   */
  public static TrustGraphImportPreview preview(
      String documentJson,
      TrustGraphStore store,
      String sourceUri,
      String sourceLabel,
      int maxBytes,
      Instant now) {
    java.util.Objects.requireNonNull(store, "store");
    java.util.Objects.requireNonNull(now, "now");
    PreviewBuilder builder =
        new PreviewBuilder(documentJson, store, sourceUri, sourceLabel, maxBytes, now);
    return new TrustGraphImportPreview(builder.build());
  }

  /**
   * Returns the preview as a JSON-compatible map.
   *
   * <p>The map preserves insertion order so route responses, tests, and release-certification
   * evidence remain stable. Callers receive the same immutable snapshot on every invocation; the
   * returned value should be treated as read-only response data and not as a mutable builder.
   *
   * @return insertion-ordered summary map without raw candidate content or signature values
   */
  public Map<String, Object> toJson() {
    return json;
  }

  private static final class PreviewBuilder {
    private final String documentJson;
    private final TrustGraphStore store;
    private final String sourceUri;
    private final String sourceLabel;
    private final int maxBytes;
    private final Instant now;
    private final ArrayList<String> warnings = new ArrayList<>();
    private final ArrayList<Map<String, Object>> candidateSummaries = new ArrayList<>();
    private final HashMap<String, StatementProjection> byFingerprint = new HashMap<>();
    private final HashMap<String, ArrayList<StatementProjection>> byIssuerSubject = new HashMap<>();
    private int candidateStatementCount;
    private int acceptedCount;
    private int rejectedCount;
    private int duplicateCount;
    private int duplicateIssuerCount;
    private int conflictCount;
    private int revokedDeprecatedExpiredCount;

    private PreviewBuilder(
        String documentJson,
        TrustGraphStore store,
        String sourceUri,
        String sourceLabel,
        int maxBytes,
        Instant now) {
      this.documentJson = documentJson == null ? "" : documentJson;
      this.store = store;
      this.sourceUri = sourceUri;
      this.sourceLabel = sourceLabel;
      this.maxBytes = Math.max(1, maxBytes);
      this.now = now;
    }

    private Map<String, Object> build() {
      seedExistingStatements();
      if (documentJson.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
        rejectedCount = 1;
        addWarning("input-too-large");
        return responseJson();
      }
      List<Object> candidates = candidateValues();
      candidateStatementCount = candidates.size();
      if (candidates.size() > MAX_PREVIEW_STATEMENTS) {
        rejectedCount += candidates.size() - MAX_PREVIEW_STATEMENTS;
        addWarning("candidate-count-exceeds-preview-cap");
      }
      int inspected = Math.min(candidates.size(), MAX_PREVIEW_STATEMENTS);
      for (int index = 0; index < inspected; index++) {
        previewCandidate(candidates.get(index));
      }
      return responseJson();
    }

    private void seedExistingStatements() {
      for (TrustGraphStore.StoredTrustStatement statement : store.statements()) {
        TrustStatementPayload payload = statement.document().payload();
        TrustStatementLifecycleStatus lifecycle =
            store.lifecycle(statement.documentFingerprint()).status();
        StatementProjection projection =
            new StatementProjection(
                statement.documentFingerprint(), payload.score(), payload.confidence(), lifecycle);
        byFingerprint.put(statement.documentFingerprint(), projection);
        addIssuerSubjectProjection(issuerSubjectKey(payload), projection);
      }
    }

    private List<Object> candidateValues() {
      try {
        Object parsed = TrustJson.parse(documentJson);
        if (parsed instanceof Map<?, ?> root) {
          Object type = root.get("type");
          Object statements = root.get("statements");
          if (TrustDocumentTypes.TRUST_STATEMENT_V1.equals(type)) {
            return singleCandidate(parsed);
          }
          if (statements instanceof List<?> list) {
            return nullTolerantCopy(list);
          }
        }
        if (parsed instanceof List<?> list) {
          return nullTolerantCopy(list);
        }
        return singleCandidate(parsed);
      } catch (TrustGraphException exception) {
        rejectedCount = 1;
        addWarning(exception.errorCode());
        return List.of();
      }
    }

    private static List<Object> singleCandidate(Object value) {
      ArrayList<Object> values = new ArrayList<>(1);
      values.add(value);
      return values;
    }

    private static List<Object> nullTolerantCopy(List<?> values) {
      return new ArrayList<>(values);
    }

    private void previewCandidate(Object candidate) {
      try {
        TrustStatementDocument document = TrustStatementParser.parse(TrustJson.write(candidate));
        TrustStatementPayload payload = document.payload();
        String fingerprint = TrustStatementFingerprint.documentFingerprint(document);
        String issuerSubjectKey = issuerSubjectKey(payload);
        StatementProjection duplicate = byFingerprint.get(fingerprint);
        List<StatementProjection> issuerProjections = byIssuerSubject.get(issuerSubjectKey);
        if (issuerProjections == null) {
          issuerProjections = List.of();
        }
        TrustStatementLifecycleStatus lifecycle =
            duplicate == null ? TrustStatementLifecycleStatus.ACTIVE : duplicate.lifecycleStatus();
        boolean expired = payload.expiresAt() != null && !payload.expiresAt().isAfter(now);
        boolean duplicateFingerprint = duplicate != null;
        boolean duplicateIssuer = hasDifferentIssuerStatement(issuerProjections, fingerprint);
        boolean conflict = hasConflictingIssuerStatement(issuerProjections, fingerprint, payload);
        if (duplicateFingerprint) {
          duplicateCount++;
        } else {
          acceptedCount++;
        }
        if (duplicateIssuer) {
          duplicateIssuerCount++;
        }
        if (conflict) {
          conflictCount++;
        }
        if (expired || lifecycle != TrustStatementLifecycleStatus.ACTIVE) {
          revokedDeprecatedExpiredCount++;
        }
        if (!duplicateFingerprint) {
          StatementProjection projection =
              new StatementProjection(
                  fingerprint,
                  payload.score(),
                  payload.confidence(),
                  TrustStatementLifecycleStatus.ACTIVE);
          byFingerprint.put(fingerprint, projection);
          addIssuerSubjectProjection(issuerSubjectKey, projection);
        }
        appendCandidateSummary(
            document,
            fingerprint,
            duplicateFingerprint,
            duplicateIssuer,
            conflict,
            expired,
            lifecycle);
      } catch (TrustGraphException exception) {
        rejectedCount++;
        addWarning(exception.errorCode());
      }
    }

    private void addIssuerSubjectProjection(
        String issuerSubjectKey, StatementProjection projection) {
      byIssuerSubject.computeIfAbsent(issuerSubjectKey, _ -> new ArrayList<>()).add(projection);
    }

    private static boolean hasDifferentIssuerStatement(
        List<StatementProjection> issuerProjections, String fingerprint) {
      for (StatementProjection projection : issuerProjections) {
        if (!projection.documentFingerprint().equals(fingerprint)) {
          return true;
        }
      }
      return false;
    }

    private static boolean hasConflictingIssuerStatement(
        List<StatementProjection> issuerProjections,
        String fingerprint,
        TrustStatementPayload payload) {
      for (StatementProjection projection : issuerProjections) {
        if (!projection.documentFingerprint().equals(fingerprint)
            && projection.conflictsWith(payload)) {
          return true;
        }
      }
      return false;
    }

    private void appendCandidateSummary(
        TrustStatementDocument document,
        String fingerprint,
        boolean duplicateFingerprint,
        boolean duplicateIssuer,
        boolean conflict,
        boolean expired,
        TrustStatementLifecycleStatus lifecycle) {
      if (candidateSummaries.size() >= MAX_CANDIDATE_SUMMARIES) {
        return;
      }
      TrustStatementPayload payload = document.payload();
      LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(12);
      summary.put("documentFingerprint", fingerprint);
      summary.put("issuerFingerprint", payload.issuer().publicKeyFingerprint());
      summary.put("subjectKind", payload.subject().kind().jsonValue());
      summary.put("subjectUriHash", TrustGraphStoreSanitizer.hashText(payload.subject().uri()));
      summary.put("context", payload.context());
      summary.put("score", payload.score());
      summary.put("confidence", payload.confidence());
      summary.put("signatureVerified", TrustStatementVerifier.isSignatureVerified(document));
      summary.put("duplicate", duplicateFingerprint);
      summary.put("duplicateIssuer", duplicateIssuer);
      summary.put("conflictStatus", conflict ? "conflict" : "none");
      summary.put("lifecycleStatus", lifecycle.jsonValue());
      summary.put("expired", expired);
      candidateSummaries.add(summary);
    }

    private Map<String, Object> responseJson() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(20);
      json.put("sourceUriKind", safeSourceUriKind());
      json.put("sourceSummary", safeSourceSummary());
      json.put("sourceLabel", safeSourceLabel());
      json.put("candidateStatementCount", candidateStatementCount);
      json.put("acceptedCount", acceptedCount);
      json.put("rejectedCount", rejectedCount);
      json.put("duplicateCount", duplicateCount);
      json.put("duplicateIssuerCount", duplicateIssuerCount);
      json.put("conflictCount", conflictCount);
      json.put("revokedDeprecatedExpiredCount", revokedDeprecatedExpiredCount);
      json.put("approximateScoreImpact", scoreImpactSummary());
      json.put("materialRisk", materialRisk());
      json.put("rawContentDiscarded", true);
      json.put("candidateSummaries", List.copyOf(candidateSummaries));
      json.put("warnings", List.copyOf(warnings));
      json.put("limits", limitsJson());
      return json;
    }

    private boolean materialRisk() {
      return conflictCount > 0
          || (acceptedCount > 0
              && (rejectedCount > 0
                  || duplicateIssuerCount > 0
                  || revokedDeprecatedExpiredCount > 0));
    }

    private String scoreImpactSummary() {
      if (conflictCount > 0) {
        return "Manual review recommended; duplicate issuer conflicts may affect matching local"
            + " scores.";
      }
      if (acceptedCount == 0) {
        return duplicateCount > 0
            ? "No score change expected from duplicate-only preview."
            : "No score impact; no accepted statements.";
      }
      return "Potential score impact is limited to matching subjects from locally anchored"
          + " issuers.";
    }

    private Map<String, Object> limitsJson() {
      LinkedHashMap<String, Object> limits = LinkedHashMap.newLinkedHashMap(3);
      limits.put("maxBytes", maxBytes);
      limits.put("maxPreviewStatements", MAX_PREVIEW_STATEMENTS);
      limits.put("maxCandidateSummaries", MAX_CANDIDATE_SUMMARIES);
      return limits;
    }

    private String safeSourceUriKind() {
      try {
        return TrustGraphStoreSanitizer.sourceUriKind(sourceUri);
      } catch (TrustGraphException _) {
        addWarning("source-uri-redacted");
        return "unsupported";
      }
    }

    private String safeSourceSummary() {
      try {
        return TrustGraphStoreSanitizer.redactedUriSummary(sourceUri);
      } catch (TrustGraphException _) {
        addWarning("source-uri-redacted");
        return null;
      }
    }

    private String safeSourceLabel() {
      try {
        return TrustGraphStoreSanitizer.normalizeSourceLabel(sourceLabel);
      } catch (TrustGraphException _) {
        addWarning("source-label-redacted");
        return null;
      }
    }

    private void addWarning(String warning) {
      if (warning != null && warnings.size() < MAX_WARNINGS && !warnings.contains(warning)) {
        warnings.add(warning);
      }
    }

    private static String issuerSubjectKey(TrustStatementPayload payload) {
      return payload.issuer().publicKeyFingerprint()
          + "\n"
          + payload.subject().kind().jsonValue()
          + "\n"
          + payload.subject().uri()
          + "\n"
          + payload.context();
    }
  }

  private record StatementProjection(
      String documentFingerprint,
      int score,
      int confidence,
      TrustStatementLifecycleStatus lifecycleStatus) {
    private boolean conflictsWith(TrustStatementPayload payload) {
      return score != payload.score()
          || confidence != payload.confidence()
          || lifecycleStatus != TrustStatementLifecycleStatus.ACTIVE;
    }
  }
}
