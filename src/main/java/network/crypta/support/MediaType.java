package network.crypta.support;

import java.net.MalformedURLException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Map;
import network.crypta.client.DefaultMIMETypes;

/**
 * Represents a media (MIME) type.
 *
 * <p>A media type consists of a top-level type, a subtype, and optional parameters. Examples
 * include {@code "audio/ogg"} and {@code "text/html; charset=utf-8"}.
 *
 * <p>Instances are immutable and therefore thread-safe. "Setter" methods such as {@link
 * #setType(String)} and {@link #setSubtype(String)} return new {@link MediaType} instances with the
 * requested part changed while copying all other parts. Parameter names are normalized to
 * lowercase, and values are trimmed; quoted values are unquoted during parsing.
 *
 * <p>Media types are defined by <a href="http://www.ietf.org/rfc/rfc2046.txt">RFC&nbsp;2046</a> and
 * related documents.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public final class MediaType {

  /** The top-level type. */
  private final String type;

  /** The subtype. */
  private final String subtype;

  /** The parameters. */
  private final LinkedHashMap<String, String> parameters = new LinkedHashMap<>();

  /**
   * Parses a media type string into a new instance.
   *
   * <p>Accepts inputs like {@code "text/html"} and {@code "text/html; charset=UTF-8; q=0.9"}. The
   * parser is strict about the basic structure:
   *
   * <ul>
   *   <li>Type/subtype must contain a {@code '/'} separator.
   *   <li>Semicolons separate parameters; each parameter must contain a single {@code '='}.
   *   <li>Parameter names are normalized to lowercase; quoted values are unquoted.
   * </ul>
   *
   * <p>On success, the resulting instance preserves parameter insertion order.
   *
   * @param mediaType media type string; must not be {@code null}
   * @throws NullPointerException if {@code mediaType} is {@code null}
   * @throws MalformedURLException if {@code mediaType} is not plausibly a MIME type, does not
   *     contain a slash, or a parameter lacks an equals sign
   */
  public MediaType(String mediaType) throws NullPointerException, MalformedURLException {
    if (mediaType == null) {
      throw new NullPointerException("contentType must not be null");
    }
    if (!DefaultMIMETypes.isPlausibleMIMEType(mediaType))
      throw new MalformedURLException("Doesn't look like a MIME type");
    // Basic structural parsing: split type/subtype first, then parameters.
    int slash = mediaType.indexOf('/');
    if (slash == -1) {
      throw new MalformedURLException("mediaType does not contain ‘/’!");
    }
    type = mediaType.substring(0, slash);
    int semicolon = mediaType.indexOf(';');
    if (semicolon == -1) {
      subtype = mediaType.substring(slash + 1);
      return;
    }
    subtype = mediaType.substring(slash + 1, semicolon).trim();
    String params = mediaType.substring(semicolon + 1);
    parseParameters(params);
  }

  private void parseParameters(String params) throws MalformedURLException {
    int paramStart = 0;
    while (paramStart < params.length()) {
      int paramEnd = params.indexOf(';', paramStart);
      if (paramEnd == -1) {
        paramEnd = params.length();
      }
      String parameter = params.substring(paramStart, paramEnd);
      if (parameter.trim().isEmpty()) {
        if (paramEnd == params.length()) {
          return;
        }
        throw new MalformedURLException("Illegal parameter: “%s”".formatted(parameter));
      }
      int equals = parameter.indexOf('=');
      if (equals == -1) {
        throw new MalformedURLException("Illegal parameter: “%s”".formatted(parameter));
      }
      // Normalize parameter names to lowercase and unquote quoted values.
      String name = parameter.substring(0, equals).trim().toLowerCase(Locale.ROOT);
      String value = parameter.substring(equals + 1).trim();
      if (value.startsWith("\"") && value.endsWith("\""))
        value = value.substring(1, value.length() - 1).trim();
      parameters.put(name, value);
      if (paramEnd == params.length()) {
        return;
      }
      paramStart = paramEnd + 1;
    }
  }

  /**
   * Constructs a new instance from explicit parts.
   *
   * <p>Parameter varargs are interpreted as key-value pairs in order: {@code key1, value1, key2,
   * value2, ...}. Parameter names are stored as-is and are not validated here.
   *
   * @param type top-level type (e.g., {@code "text"})
   * @param subtype subtype (e.g., {@code "html"})
   * @param parameters alternating parameter keys and values
   * @throws IllegalArgumentException if the number of {@code parameters} is odd
   */
  public MediaType(String type, String subtype, String... parameters)
      throws IllegalArgumentException {
    if ((parameters.length & 1) != 0) {
      throw new IllegalArgumentException("Invalid number of parameters given!");
    }
    this.type = type;
    this.subtype = subtype;
    for (int index = 0; index < parameters.length; index += 2) {
      this.parameters.put(parameters[index], parameters[index + 1]);
    }
  }

  /**
   * Constructs a new instance from explicit parts and a parameter map.
   *
   * <p>The provided map is defensively copied. Insertion order of the map is preserved in the
   * resulting instance if the map is an ordered implementation such as {@link LinkedHashMap}.
   * Parameter keys are copied as-is and not validated.
   *
   * @param type top-level type
   * @param subtype subtype
   * @param parameters parameter map to copy (may be empty but not {@code null})
   */
  public MediaType(String type, String subtype, Map<String, String> parameters) {
    this.type = type;
    this.subtype = subtype;
    this.parameters.putAll(parameters);
  }

  //
  // ACCESSORS
  //

  /**
   * Returns the top-level type.
   *
   * @return top-level type string (never {@code null})
   */
  public String getType() {
    return type;
  }

  /**
   * Returns a new instance with the given top-level type.
   *
   * <p>All other parts (subtype and parameters) are copied unchanged.
   *
   * @param type new top-level type
   * @return a new {@link MediaType} with {@code type} applied
   */
  public MediaType setType(String type) {
    return new MediaType(type, subtype, parameters);
  }

  /**
   * Returns the subtype.
   *
   * @return subtype string (never {@code null})
   */
  public String getSubtype() {
    return subtype;
  }

  /**
   * Returns a new instance with the given subtype.
   *
   * <p>All other parts (top-level type and parameters) are copied unchanged.
   *
   * @param subtype new subtype
   * @return a new {@link MediaType} with {@code subtype} applied
   */
  public MediaType setSubtype(String subtype) {
    return new MediaType(type, subtype, parameters);
  }

  /**
   * Returns the value of a parameter.
   *
   * <p>Lookup is case-insensitive because parameter names are normalized to lowercase for storage.
   *
   * @param name parameter name (case-insensitive)
   * @return parameter value, or {@code null} if not present
   */
  public String getParameter(String name) {
    return parameters.get(name.toLowerCase(Locale.ROOT));
  }

  /**
   * Returns a new instance with the parameter updated.
   *
   * <p>If {@code value} is {@code null}, the parameter is removed. The {@code name} is normalized
   * to lowercase for storage.
   *
   * @param name parameter name (case-insensitive)
   * @param value new value, or {@code null} to remove the parameter
   * @return a new {@link MediaType} reflecting the change
   */
  public MediaType setParameter(String name, String value) {
    MediaType newMediaType = new MediaType(type, subtype, parameters);
    if (value == null) newMediaType.parameters.remove(name.toLowerCase(Locale.ROOT));
    else newMediaType.parameters.put(name.toLowerCase(Locale.ROOT), value);
    return newMediaType;
  }

  /**
   * Returns a new instance with the parameter removed, if present.
   *
   * @param name parameter name (case-insensitive)
   * @return {@code this} if the parameter was absent; otherwise a new {@link MediaType}
   */
  public MediaType removeParameter(String name) {
    if (!parameters.containsKey(name.toLowerCase(Locale.ROOT))) {
      return this;
    }
    MediaType newMediaType = new MediaType(type, subtype, parameters);
    newMediaType.parameters.remove(name.toLowerCase(Locale.ROOT));
    return newMediaType;
  }

  //
  // OBJECT METHODS
  //

  /**
   * Returns the RFC-style string representation.
   *
   * <p>The format is {@code type/subtype} followed by semicolon-separated parameters in insertion
   * order. Parameter values are quoted. Parameters with {@code null} values are omitted.
   */
  @Override
  public String toString() {
    StringBuilder mediaType = new StringBuilder();
    mediaType.append(type).append('/').append(subtype);
    for (Entry<String, String> parameter : parameters.entrySet()) {
      if (parameter.getValue() == null) {
        continue;
      }
      mediaType
          .append("; ")
          .append(parameter.getKey())
          .append("=\"")
          .append(parameter.getValue())
          .append("\"");
    }
    return mediaType.toString();
  }

  /**
   * Best-effort extraction of the {@code charset} parameter from a media type string.
   *
   * <p>Returns {@code null} when the input is {@code null}, malformed, or when parsing triggers any
   * throwable (including {@link Error}) due to extreme or malicious inputs. This preserves the
   * historical "robust" contract: parse-time failures should not take down callers dealing with
   * untrusted headers.
   *
   * @param expectedMimeType content type string such as {@code "text/html; charset=UTF-8"}
   * @return the charset value if present; otherwise {@code null}
   */
  @SuppressWarnings("java:S1181") // Intentionally catch Throwable to uphold robustness contract.
  public static String getCharsetRobust(String expectedMimeType) {
    try {
      if (expectedMimeType == null) return null;
      MediaType type = new MediaType(expectedMimeType);
      return type.getParameter("charset");
    } catch (Throwable _) {
      // Could be malicious, hence "Robust".
      return null;
    }
  }

  /**
   * Returns the {@code charset} parameter or {@code "UTF-8"} when absent.
   *
   * <p>Falls back to {@code "UTF-8"} if the input is {@code null}, invalid, or lacks an explicit
   * charset parameter. This is a convenience wrapper around {@link #getCharsetRobust(String)}.
   *
   * @param expectedMimeType content type string to inspect
   * @return the parsed charset or {@code "UTF-8"} when unavailable
   */
  public static String getCharsetRobustOrUTF(String expectedMimeType) {
    String charset = getCharsetRobust(expectedMimeType);
    if (charset == null) return "UTF-8";
    return charset;
  }

  /**
   * Returns a defensive copy of the parameters map.
   *
   * <p>The returned map preserves the insertion order and may be modified by the caller without
   * affecting this instance.
   *
   * @return new {@link LinkedHashMap} containing all parameters
   */
  public Map<String, String> getParameters() {
    return new LinkedHashMap<>(parameters);
  }

  /**
   * Returns the base type without parameters.
   *
   * @return {@code type + "/" + subtype}
   */
  public String getPlainType() {
    return type + '/' + subtype;
  }
}
