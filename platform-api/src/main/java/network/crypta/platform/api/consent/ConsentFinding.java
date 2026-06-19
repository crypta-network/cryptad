package network.crypta.platform.api.consent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One human-readable consent item inside a grouped consent section.
 *
 * <p>A finding is the smallest unit of review shown to an operator. It carries a stable reason code
 * for stale-consent and automation decisions, a short label for UI grouping, a redacted summary, an
 * optional change direction, and the risk level that contributes to section and snapshot severity.
 * Findings are immutable after construction and expose only JSON-compatible scalar fields.
 *
 * <p>The constructor trims stable identifiers and redacts the summary so previews and audit records
 * do not carry tokens, private insert URIs, or host-local paths. It does not localize labels or
 * summaries; callers should provide concise English text suitable for the local Web Shell and API
 * clients.
 *
 * @param code stable machine-readable reason code, such as {@code permission_required}
 * @param label short operator-facing label for the finding
 * @param summary redacted human-readable summary of the reviewed condition
 * @param change optional side of the comparison, such as {@code installed} or {@code candidate}
 * @param riskLevel severity contributed by this finding
 * @see ConsentSection
 */
public record ConsentFinding(
    String code, String label, String summary, String change, ConsentRiskLevel riskLevel) {
  /**
   * Creates a normalized finding.
   *
   * <p>Blank codes and labels are rejected because downstream clients use them as stable selectors.
   * The summary may be absent and is normalized to an empty redacted string. A blank change label
   * is normalized to {@code null} so JSON output can distinguish no comparison side from a
   * meaningful side value.
   *
   * @throws IllegalArgumentException when {@code code} or {@code label} is blank
   * @throws NullPointerException when {@code code}, {@code label}, or {@code riskLevel} is null
   */
  public ConsentFinding {
    code = requireText(code, "code");
    label = requireText(label, "label");
    summary = ConsentRedactor.redact(Objects.requireNonNullElse(summary, ""));
    change = change == null || change.isBlank() ? null : change.trim();
    Objects.requireNonNull(riskLevel, "riskLevel");
  }

  /**
   * Converts this finding to the public Platform API JSON shape.
   *
   * <p>The returned map preserves insertion order for deterministic snapshots and digest input. It
   * contains only redacted strings and stable tokens; callers can pass it directly to {@code
   * PlatformApiJsonWriter}.
   *
   * @return ordered JSON-compatible map for API responses and digest snapshots
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("code", code);
    json.put("label", label);
    json.put("summary", summary);
    json.put("change", change);
    json.put("riskLevel", riskLevel.jsonValue());
    return json;
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
