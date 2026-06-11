package network.crypta.platform.webshell.bootstrap;

import java.util.LinkedHashMap;
import java.util.StringJoiner;

/**
 * JSON serializer for {@link WebShellBootstrap}.
 *
 * <p>The serializer stays dependency-light on purpose, so the shell can embed one stable JSON blob
 * into the page template without pulling in a general-purpose object mapper.
 */
public final class WebShellBootstrapJson {
  /** Prevents instantiation of this static helper. */
  private WebShellBootstrapJson() {}

  /**
   * Serializes the supplied bootstrap payload as stable JSON.
   *
   * @param bootstrap shell bootstrap model to serialize
   * @return JSON representation suitable for browser bootstrap
   */
  public static String serialize(WebShellBootstrap bootstrap) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("shellTitle", bootstrap.shellTitle());
    json.put("shellDescription", bootstrap.shellDescription());
    json.put("shellRoot", bootstrap.shellRoot());
    json.put("assetRoot", bootstrap.assetRoot());
    json.put("platformApiRoot", bootstrap.platformApiRoot());
    json.put("formPassword", bootstrap.formPassword());
    json.put("legacyRoot", bootstrap.legacyRoot());
    json.put("legacySecurityLevelsPath", bootstrap.legacySecurityLevelsPath());
    json.put("legacyDiagnosticPath", bootstrap.legacyDiagnosticPath());
    json.put(
        "legacyLinks",
        bootstrap.legacyLinks().stream().map(WebShellBootstrapJson::serializeLink).toList());
    return writeJson(json);
  }

  /**
   * Serializes one legacy deep-link descriptor into a small map-backed JSON object.
   *
   * @param link legacy deep link to serialize
   * @return ordered key-value view consumed by the generic JSON writer
   */
  private static java.util.Map<String, Object> serializeLink(WebShellBootstrap.LegacyLink link) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("path", link.path());
    json.put("label", link.label());
    return json;
  }

  /**
   * Writes one object graph as JSON text.
   *
   * @param value value tree to serialize
   * @return serialized JSON document
   */
  private static String writeJson(Object value) {
    StringBuilder out = new StringBuilder();
    appendJsonValue(out, value);
    return out.toString();
  }

  /**
   * Appends one JSON value using the serializer's supported runtime types.
   *
   * @param out destination builder that accumulates JSON text
   * @param value value to append, including maps, iterables, scalars, and {@code null}
   */
  private static void appendJsonValue(StringBuilder out, Object value) {
    if (value == null) {
      out.append("null");
      return;
    }
    if (value instanceof String text) {
      appendJsonString(out, text);
      return;
    }
    if (value instanceof Number || value instanceof Boolean) {
      out.append(value);
      return;
    }
    if (value instanceof java.util.Map<?, ?> map) {
      appendJsonObject(out, map);
      return;
    }
    if (value instanceof Iterable<?> iterable) {
      appendJsonArray(out, iterable);
      return;
    }
    appendJsonString(out, value.toString());
  }

  /**
   * Appends one JSON object from an ordered map.
   *
   * @param out destination builder that accumulates JSON text
   * @param map ordered key-value pairs to serialize as an object
   */
  private static void appendJsonObject(StringBuilder out, java.util.Map<?, ?> map) {
    out.append('{');
    StringJoiner joiner = new StringJoiner(",");
    map.forEach(
        (key, value) -> {
          StringBuilder entry = new StringBuilder();
          appendJsonString(entry, String.valueOf(key));
          entry.append(':');
          appendJsonValue(entry, value);
          joiner.add(entry.toString());
        });
    out.append(joiner);
    out.append('}');
  }

  /**
   * Appends one JSON array from an iterable sequence.
   *
   * @param out destination builder that accumulates JSON text
   * @param iterable ordered sequence to serialize as a JSON array
   */
  private static void appendJsonArray(StringBuilder out, Iterable<?> iterable) {
    out.append('[');
    StringJoiner joiner = new StringJoiner(",");
    for (Object item : iterable) {
      StringBuilder entry = new StringBuilder();
      appendJsonValue(entry, item);
      joiner.add(entry.toString());
    }
    out.append(joiner);
    out.append(']');
  }

  /**
   * Appends one JSON string with the shell's HTML-safe escaping rules.
   *
   * <p>In addition to standard JSON escapes, the serializer escapes HTML-sensitive characters and
   * line separators so the resulting string can be embedded safely into the rendered shell page.
   *
   * @param out destination builder that accumulates JSON text
   * @param value string value to escape and append
   */
  private static void appendJsonString(StringBuilder out, String value) {
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        case '<' -> out.append("\\u003c");
        case '>' -> out.append("\\u003e");
        case '&' -> out.append("\\u0026");
        case '\u2028' -> out.append("\\u2028");
        case '\u2029' -> out.append("\\u2029");
        default -> {
          if (ch < 0x20) {
            out.append("\\u");
            out.append(String.format("%04x", (int) ch));
          } else {
            out.append(ch);
          }
        }
      }
    }
    out.append('"');
  }
}
