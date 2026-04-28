package network.crypta.platform.appui;

import java.util.Map;

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
  private static final Map<Character, String> STRING_ESCAPES =
      Map.ofEntries(
          Map.entry('"', "\\\""),
          Map.entry('\\', "\\\\"),
          Map.entry('\b', "\\b"),
          Map.entry('\f', "\\f"),
          Map.entry('\n', "\\n"),
          Map.entry('\r', "\\r"),
          Map.entry('\t', "\\t"),
          Map.entry('<', "\\u003c"),
          Map.entry('>', "\\u003e"),
          Map.entry('&', "\\u0026"),
          Map.entry('\u2028', "\\u2028"),
          Map.entry('\u2029', "\\u2029"));

  private AppUiBootstrapJson() {}

  /**
   * Serializes one app UI bootstrap payload as deterministic JSON.
   *
   * <p>The output schema is the browser contract for first-party static app UI bootstrap. It
   * contains route roots and an opaque browser app session token from {@link AppUiBootstrap}; it
   * does not synthesize or add AppHost launch credentials or local-admin form passwords.
   *
   * @param bootstrap bootstrap model whose fields should be written in a stable order
   * @return compact JSON text safe to serve as {@code application/json}
   * @throws NullPointerException if {@code bootstrap} is {@code null}
   */
  public static String serialize(AppUiBootstrap bootstrap) {
    StringBuilder out = new StringBuilder(160);
    out.append('{');
    appendStringField(out, "appId", bootstrap.appId());
    appendStringField(out, "name", bootstrap.name());
    appendStringField(out, "uiRoot", bootstrap.uiRoot());
    appendStringField(out, "assetRoot", bootstrap.assetRoot());
    appendStringField(out, "platformApiRoot", bootstrap.platformApiRoot());
    appendStringField(out, "shellRoot", bootstrap.shellRoot());
    appendStringField(out, "browserSessionToken", bootstrap.browserSessionToken());
    appendStringField(
        out, "browserSessionExpiresAt", bootstrap.browserSessionExpiresAt().toString());
    return out.append('}').toString();
  }

  private static void appendStringField(StringBuilder out, String name, String value) {
    appendFieldName(out, name);
    appendJsonString(out, value);
  }

  private static void appendFieldName(StringBuilder out, String name) {
    if (out.length() > 1) {
      out.append(',');
    }
    appendJsonString(out, name);
    out.append(':');
  }

  private static void appendJsonString(StringBuilder out, String value) {
    out.append('"');
    for (int index = 0; index < value.length(); index++) {
      appendJsonCharacter(out, value.charAt(index));
    }
    out.append('"');
  }

  private static void appendJsonCharacter(StringBuilder out, char value) {
    String replacement = STRING_ESCAPES.get(value);
    if (replacement != null) {
      out.append(replacement);
      return;
    }
    if (value < 0x20) {
      out.append("\\u");
      out.append(String.format("%04x", (int) value));
    } else {
      out.append(value);
    }
  }
}
