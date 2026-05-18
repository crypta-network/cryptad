package network.crypta.platform.trustgraph;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Subject of a bounded trust statement.
 *
 * <p>The subject is intentionally simple: a kind plus a bounded URI or stable identifier string.
 * Scoring queries match the kind and URI exactly, and the optional fingerprint is displayed as
 * supporting metadata rather than used as a fallback match key. That keeps the preview algorithm
 * deterministic and avoids surprising cross-kind matches.
 *
 * @param kind subject kind
 * @param uri bounded URI or stable subject string
 * @param fingerprint optional stable subject fingerprint
 */
public record TrustSubject(TrustSubjectKind kind, String uri, String fingerprint) {
  /**
   * Creates a subject after applying trust statement bounds.
   *
   * <p>The constructor accepts the same set of subject strings used by the preview API and UI. It
   * rejects blank values, oversized fields, and control characters before the subject can be signed
   * or imported.
   */
  public TrustSubject {
    java.util.Objects.requireNonNull(kind, "kind");
    uri = TrustStatementValidator.requiredText("subject.uri", uri, 1024);
    fingerprint = TrustStatementValidator.optionalText("subject.fingerprint", fingerprint, 128);
  }

  /**
   * Returns this subject as an insertion-ordered JSON object.
   *
   * @return JSON-ready subject map in canonical payload field order
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("kind", kind.jsonValue());
    json.put("uri", uri);
    if (fingerprint != null) {
      json.put("fingerprint", fingerprint);
    }
    return json;
  }
}
