package network.crypta.platform.api.json;

import java.util.Map;

/**
 * Minimal JSON writer used by the initial Platform API surface.
 *
 * <p>The writer supports the limited set of JSON value types required by Platform API v1: strings,
 * booleans, integers/longs, {@code null}, arrays, and nested objects. Callers are expected to
 * supply already-structured JDK values such as {@link Map}, {@link Iterable}, and scalar types.
 */
public final class PlatformApiJsonWriter {
  /** Prevents instantiation of this static helper type. */
  private PlatformApiJsonWriter() {}

  /**
   * Serializes the supplied JSON-compatible value into a UTF-16 Java string.
   *
   * @param value JSON-compatible root value
   * @return serialized JSON text
   * @throws IllegalArgumentException if the value graph contains an unsupported type
   */
  public static String write(Object value) {
    StringBuilder json = new StringBuilder();
    appendValue(value, json);
    return json.toString();
  }

  /**
   * Appends one JSON-compatible value to the output buffer.
   *
   * @param value JSON-compatible value to serialize
   * @param json destination buffer receiving serialized output
   * @throws IllegalArgumentException if {@code value} has an unsupported type
   */
  private static void appendValue(Object value, StringBuilder json) {
    switch (value) {
      case null -> {
        json.append("null");
        return;
      }
      case String stringValue -> {
        appendString(stringValue, json);
        return;
      }
      case Boolean booleanValue -> {
        json.append(booleanValue);
        return;
      }
      default -> {
        // no ops
      }
    }
    if (value instanceof Integer
        || value instanceof Long
        || value instanceof Short
        || value instanceof Byte) {
      json.append(value);
      return;
    }
    switch (value) {
      case Float floatValue -> {
        appendFloatingPoint(floatValue, json);
        return;
      }
      case Double doubleValue -> {
        appendFloatingPoint(doubleValue, json);
        return;
      }
      case Enum<?> enumValue -> {
        appendString(enumValue.name(), json);
        return;
      }
      case Map<?, ?> mapValue -> {
        appendObject(mapValue, json);
        return;
      }
      case Iterable<?> iterableValue -> {
        appendArray(iterableValue, json);
        return;
      }
      default -> {
        // no ops
      }
    }

    throw new IllegalArgumentException(
        "Unsupported Platform API JSON value type: " + value.getClass().getName());
  }

  /**
   * Appends one finite floating-point number to the output buffer.
   *
   * @param value floating-point value to serialize
   * @param json destination buffer receiving serialized output
   * @throws IllegalArgumentException if {@code value} is not finite
   */
  private static void appendFloatingPoint(double value, StringBuilder json) {
    if (!Double.isFinite(value)) {
      throw new IllegalArgumentException("Floating-point JSON values must be finite");
    }
    json.append(value);
  }

  /**
   * Appends one JSON object to the output buffer.
   *
   * @param value object values keyed by JSON field name
   * @param json destination buffer receiving serialized output
   * @throws IllegalArgumentException if any key is not a string
   */
  private static void appendObject(Map<?, ?> value, StringBuilder json) {
    json.append('{');
    boolean first = true;
    for (Map.Entry<?, ?> entry : value.entrySet()) {
      Object rawKey = entry.getKey();
      if (!(rawKey instanceof String key)) {
        throw new IllegalArgumentException("JSON object keys must be strings");
      }
      if (!first) {
        json.append(',');
      }
      appendString(key, json);
      json.append(':');
      appendValue(entry.getValue(), json);
      first = false;
    }
    json.append('}');
  }

  /**
   * Appends one JSON array to the output buffer.
   *
   * @param value iterable values to serialize in encounter order
   * @param json destination buffer receiving serialized output
   */
  private static void appendArray(Iterable<?> value, StringBuilder json) {
    json.append('[');
    boolean first = true;
    for (Object item : value) {
      if (!first) {
        json.append(',');
      }
      appendValue(item, json);
      first = false;
    }
    json.append(']');
  }

  /**
   * Appends one escaped JSON string literal to the output buffer.
   *
   * @param value string value to escape and quote
   * @param json destination buffer receiving serialized output
   */
  private static void appendString(String value, StringBuilder json) {
    json.append('"');
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> json.append("\\\"");
        case '\\' -> json.append("\\\\");
        case '\b' -> json.append("\\b");
        case '\f' -> json.append("\\f");
        case '\n' -> json.append("\\n");
        case '\r' -> json.append("\\r");
        case '\t' -> json.append("\\t");
        default -> {
          if (ch < 0x20) {
            json.append(String.format("\\u%04x", (int) ch));
          } else {
            json.append(ch);
          }
        }
      }
    }
    json.append('"');
  }
}
