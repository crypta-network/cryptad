package network.crypta.platform.api.contentformats;

import java.nio.charset.StandardCharsets;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Canonical JSON helper shared by content profile tests and app-vault request builders.
 *
 * <p>The helper delegates to the Platform API JSON writer, which preserves insertion order for
 * caller-supplied maps and emits compact JSON without insignificant whitespace. Callers remain
 * responsible for building maps in the profile-defined field order.
 */
public final class CanonicalJson {
  private CanonicalJson() {}

  /**
   * Serializes a JSON-compatible value using the Platform API canonical writer.
   *
   * @param value JSON-compatible value graph
   * @return compact canonical JSON
   */
  public static String write(Object value) {
    return PlatformApiJsonWriter.write(value);
  }

  /**
   * Serializes a JSON-compatible value to canonical UTF-8 bytes.
   *
   * @param value JSON-compatible value graph
   * @return canonical UTF-8 bytes
   */
  public static byte[] bytes(Object value) {
    return write(value).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Prefixes canonical JSON with a signing domain and newline.
   *
   * @param signingDomain fixed profile signing domain or purpose
   * @param value JSON-compatible value graph
   * @return UTF-8 bytes of {@code signingDomain + "\n" + canonicalJson}
   */
  public static byte[] domainSeparatedBytes(String signingDomain, Object value) {
    return (signingDomain + "\n" + write(value)).getBytes(StandardCharsets.UTF_8);
  }
}
