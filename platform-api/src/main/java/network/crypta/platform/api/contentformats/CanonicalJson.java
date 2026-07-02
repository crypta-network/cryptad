package network.crypta.platform.api.contentformats;

import java.nio.charset.StandardCharsets;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Canonical JSON helper shared by content profile tests and app-vault request builders.
 *
 * <p>The helper delegates to the Platform API JSON writer, which preserves insertion order for
 * caller-supplied maps and emits compact JSON without insignificant whitespace. Use it when a
 * content profile needs stable bytes for hashing, signature payloads, or drift tests across Java
 * routes and SDK mirrors. The class is stateless and thread-safe; all determinism comes from the
 * supplied value graph.
 *
 * <p>Callers remain responsible for building maps in the profile-defined field order and for
 * validating unknown fields before serialization. This helper does not sort keys or enforce schema
 * membership because signed profiles need the exact field order selected by the profile-specific
 * builder.
 */
public final class CanonicalJson {
  private CanonicalJson() {}

  /**
   * Serializes a JSON-compatible value using the Platform API canonical writer.
   *
   * <p>The input should contain only values supported by {@link PlatformApiJsonWriter}, typically
   * maps, lists, strings, numbers, booleans, and {@code null}. Map iteration order becomes JSON
   * field order, so callers should use insertion-ordered maps when profile bytes must remain
   * stable.
   *
   * @param value JSON-compatible value graph assembled in profile field order
   * @return compact canonical JSON without insignificant whitespace
   */
  public static String write(Object value) {
    return PlatformApiJsonWriter.write(value);
  }

  /**
   * Serializes a JSON-compatible value to canonical UTF-8 bytes.
   *
   * <p>This is the byte-level form used by tests and builders when a content profile compares or
   * stores canonical payload bytes. The method uses UTF-8 unconditionally and performs no
   * additional normalization beyond the canonical JSON serialization performed by {@link
   * #write(Object)}.
   *
   * @param value JSON-compatible value graph assembled in profile field order
   * @return canonical UTF-8 bytes for the compact JSON representation
   */
  public static byte[] bytes(Object value) {
    return write(value).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Prefixes canonical JSON with a signing domain and newline.
   *
   * <p>Signed content profiles use this helper to make the signed bytes explicit: ASCII-compatible
   * domain text, one newline, then the compact canonical JSON payload. The signing domain must come
   * from the profile descriptor rather than from caller input so domain separation cannot drift
   * between builders and verifiers.
   *
   * @param signingDomain fixed profile signing domain or purpose from the registry
   * @param value JSON-compatible value graph assembled in profile field order
   * @return UTF-8 bytes of {@code signingDomain + "\n" + canonicalJson}
   */
  public static byte[] domainSeparatedBytes(String signingDomain, Object value) {
    return (signingDomain + "\n" + write(value)).getBytes(StandardCharsets.UTF_8);
  }
}
