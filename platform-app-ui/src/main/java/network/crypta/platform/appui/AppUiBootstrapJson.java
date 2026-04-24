package network.crypta.platform.appui;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;

/**
 * JSON serializer for {@link AppUiBootstrap}.
 *
 * <p>The app UI leaf keeps this serializer dependency-light so HTTP adapters can emit the small
 * dynamic bootstrap document without pulling browser UI routes into a general JSON framework. It is
 * intentionally shaped around one payload type, not around arbitrary API responses. That narrow
 * scope keeps first-party static UI bootstrap independent of later platform SDK work while still
 * producing stable output for tests and HTTP clients.
 *
 * <p>The serializer writes fields in insertion order and uses compact JSON without extra
 * whitespace. String escaping covers normal JSON control characters and additionally escapes {@code
 * <}, {@code >}, {@code &}, U+2028, and U+2029. Those extra escapes make the payload safer to
 * inspect or embed in browser-oriented tooling, even though the HTTP adapter serves it as {@code
 * application/json}. Instances are not created; callers use the static serializer method.
 *
 * @see AppUiBootstrap
 * @see AppUiBootstrapService
 */
public final class AppUiBootstrapJson {
  private AppUiBootstrapJson() {}

  /**
   * Serializes one app UI bootstrap payload as deterministic JSON.
   *
   * <p>The output schema is the browser contract for first-party static app UI bootstrap. It
   * contains route roots and the optional local-admin form password from {@link AppUiBootstrap}; it
   * does not synthesize or add AppHost launch credentials. A {@code null} form password is emitted
   * as the JSON literal {@code null}, which lets browser code distinguish a read-only bootstrap
   * context from an empty string.
   *
   * @param bootstrap bootstrap model whose fields should be written in a stable order
   * @return compact JSON text safe to serve as {@code application/json}
   * @throws NullPointerException if {@code bootstrap} is {@code null}
   */
  public static String serialize(AppUiBootstrap bootstrap) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("appId", bootstrap.appId());
    json.put("name", bootstrap.name());
    json.put("uiRoot", bootstrap.uiRoot());
    json.put("assetRoot", bootstrap.assetRoot());
    json.put("platformApiRoot", bootstrap.platformApiRoot());
    json.put("shellRoot", bootstrap.shellRoot());
    json.put("formPassword", bootstrap.formPassword());
    return writeJson(json);
  }

  private static String writeJson(Object value) {
    StringBuilder out = new StringBuilder();
    appendJsonValue(out, value);
    return out.toString();
  }

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
    if (value instanceof Map<?, ?> map) {
      appendJsonObject(out, map);
      return;
    }
    if (value instanceof Iterable<?> iterable) {
      appendJsonArray(out, iterable);
      return;
    }
    appendJsonString(out, value.toString());
  }

  private static void appendJsonObject(StringBuilder out, Map<?, ?> map) {
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

  private static void appendJsonString(StringBuilder out, String value) {
    out.append('"');
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
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
