package network.crypta.platform.api.consent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Small helpers for reading and canonicalizing Platform API JSON-compatible maps.
 *
 * <p>Consent previews are assembled from several existing API summaries rather than from a single
 * strongly typed model. This helper centralizes the narrow, defensive reads needed for those maps:
 * non-blank strings, scalar values that should be displayed as text, booleans with defaults, nested
 * objects, and nested lists. Missing or wrongly typed values degrade to {@code null}, defaults, or
 * empty collections so preview generation can choose an explicit risk outcome.
 *
 * <p>The canonicalization path is used by {@link ConsentSnapshotDigest}. It sorts object keys
 * recursively, preserves list order, and redacts strings before digesting or writing audit-safe
 * summaries. That makes approvals stable across map insertion order while still preventing secrets
 * and local paths from entering the consent artifact.
 */
public final class ConsentJson {
  private ConsentJson() {}

  /**
   * Returns a non-blank string value from a JSON-compatible map.
   *
   * <p>This method intentionally accepts only Java {@link String} values. Use {@link
   * #scalarString(Map, String)} when numeric or boolean schema metadata should be displayed as text
   * in an operator preview.
   *
   * @param json JSON-compatible map to read
   * @param key map key to inspect
   * @return trimmed string-compatible value, or {@code null} when absent, blank, or not a string
   */
  public static String string(Map<String, Object> json, String key) {
    Object value = json.get(key);
    return value instanceof String text && !text.isBlank() ? text : null;
  }

  /**
   * Returns a string form of a scalar JSON-compatible value.
   *
   * <p>Migration schema versions and similar API summaries can arrive as numbers. This helper keeps
   * those values visible in consent text without accepting objects or arrays as accidental display
   * strings.
   *
   * @param json JSON-compatible map to read
   * @param key map key to inspect
   * @return non-blank string, number, or boolean rendered as text, or {@code null} otherwise
   */
  public static String scalarString(Map<String, Object> json, String key) {
    Object value = json.get(key);
    if (value instanceof String text) {
      return text.isBlank() ? null : text;
    }
    if (value instanceof Number || value instanceof Boolean) {
      return String.valueOf(value);
    }
    return null;
  }

  /**
   * Returns a boolean value from a JSON-compatible map.
   *
   * <p>Only Java {@link Boolean} values are accepted. String forms such as {@code "true"} are
   * ignored so callers do not accidentally treat malformed summaries as policy decisions.
   *
   * @param json JSON-compatible map to read
   * @param key map key to inspect
   * @param defaultValue value returned when the map has no boolean at the key
   * @return boolean stored in the map, or the supplied default
   */
  public static boolean bool(Map<String, Object> json, String key, boolean defaultValue) {
    Object value = json.get(key);
    return value instanceof Boolean bool ? bool : defaultValue;
  }

  /**
   * Returns a nested object from a JSON-compatible map.
   *
   * <p>The returned map is a view of the existing object when the value is a map. Missing or
   * mismatched values return an immutable empty map, which lets preview builders fail closed
   * without additional null checks.
   *
   * @param json JSON-compatible map to read
   * @param key map key to inspect
   * @return nested object map, or an empty map when no object is present
   */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> object(Map<String, Object> json, String key) {
    Object value = json.get(key);
    return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
  }

  /**
   * Returns a nested list from a JSON-compatible map.
   *
   * <p>The returned list is the existing JSON-compatible list when present. Missing, scalar, or
   * object values return an immutable empty list so callers can count findings or advisories
   * deterministically.
   *
   * @param json JSON-compatible map to read
   * @param key map key to inspect
   * @return nested list, or an empty list when no list is present
   */
  @SuppressWarnings("unchecked")
  public static List<Object> list(Map<String, Object> json, String key) {
    Object value = json.get(key);
    return value instanceof List<?> list ? (List<Object>) list : List.of();
  }

  /**
   * Returns a canonical JSON-compatible value with map keys sorted recursively.
   *
   * <p>Map keys that are not strings are ignored because Platform API JSON objects use string keys.
   * Iterable values are copied in iteration order, and strings are passed through {@link
   * ConsentRedactor} before they reach digest input or persisted audit output. Scalar numbers,
   * booleans, and {@code null} are returned unchanged.
   *
   * @param value JSON-compatible value to canonicalize
   * @return recursively sorted, copied, and redacted value suitable for deterministic JSON writing
   */
  public static Object canonicalize(Object value) {
    if (value instanceof Map<?, ?> source) {
      TreeMap<String, Object> sorted = new TreeMap<>();
      for (Map.Entry<?, ?> entry : source.entrySet()) {
        if (entry.getKey() instanceof String key) {
          sorted.put(key, canonicalize(entry.getValue()));
        }
      }
      LinkedHashMap<String, Object> copy = LinkedHashMap.newLinkedHashMap(sorted.size());
      copy.putAll(sorted);
      return copy;
    }
    if (value instanceof Iterable<?> source) {
      ArrayList<Object> copy = new ArrayList<>();
      for (Object item : source) {
        copy.add(canonicalize(item));
      }
      return List.copyOf(copy);
    }
    if (value instanceof String text) {
      return ConsentRedactor.redact(text);
    }
    return value;
  }
}
