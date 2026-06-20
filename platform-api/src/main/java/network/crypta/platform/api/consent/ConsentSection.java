package network.crypta.platform.api.consent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Group of consent findings rendered as one operator-facing preview section.
 *
 * <p>Sections keep consent previews scannable. The service groups related findings into stable
 * buckets such as permissions, review trust, security, API stability, app-data migration, and
 * service dependencies. Each section carries its own rolled-up risk level so clients can highlight
 * high-risk groups without reimplementing policy logic.
 *
 * <p>Instances are immutable snapshots. The list of findings is copied at construction time, and
 * JSON output preserves deterministic field order for stable API responses and digest generation.
 * Section ids are stable machine-readable tokens; titles are short English labels for local UI
 * display.
 *
 * @param id stable section identifier used by clients and tests
 * @param title concise operator-facing section title
 * @param riskLevel maximum risk level contributed by the section's findings
 * @param items immutable ordered findings shown inside this section
 * @see ConsentFinding
 * @see ConsentSnapshot
 */
public record ConsentSection(
    String id, String title, ConsentRiskLevel riskLevel, List<ConsentFinding> items) {
  /**
   * Creates a normalized section.
   *
   * <p>The constructor trims and validates stable identifiers, requires an explicit risk level, and
   * copies the item list so later caller mutation cannot alter a stored preview or digest input.
   * Empty item lists are allowed for callers that need a present but informational section.
   *
   * @throws IllegalArgumentException when {@code id} or {@code title} is blank
   * @throws NullPointerException when {@code id}, {@code title}, {@code riskLevel}, or {@code
   *     items} is null
   */
  public ConsentSection {
    id = requireText(id, "id");
    title = requireText(title, "title");
    Objects.requireNonNull(riskLevel, "riskLevel");
    items = List.copyOf(Objects.requireNonNull(items, "items"));
  }

  /**
   * Converts this section to the public Platform API JSON shape.
   *
   * <p>The returned map preserves insertion order and contains a JSON-compatible copy of every
   * finding. It is safe to include in response bodies, audit previews, and canonical digest input.
   *
   * @return ordered JSON-compatible map for this consent section
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("id", id);
    json.put("title", title);
    json.put("riskLevel", riskLevel.jsonValue());
    json.put("items", items.stream().map(ConsentFinding::toJsonValue).toList());
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
