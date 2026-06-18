package network.crypta.platform.appcatalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Minimal deterministic JSON reader and writer for app-submission metadata.
 *
 * <p>The submission package format needs stable JSON output without introducing another dependency
 * into the catalog module. This helper intentionally supports only the value types used by the
 * submission schema: objects, arrays, strings, booleans, {@code null}, and integer numbers. Object
 * iteration order is preserved on write and duplicate object keys are rejected on parse. That keeps
 * package metadata, pre-review reports, and review evidence reproducible across JVM runs.
 *
 * <p>This is not a general JSON API. It is package-private, fail-closed, and tied to the validation
 * rules in the surrounding submission classes. Callers still perform field-level validation after
 * parsing, such as bounded single-line text, SHA-256 normalization, enum parsing, and redaction
 * checks.
 */
final class AppSubmissionJson {
  private static final String FINDING_DETAILS_FIELD = "details";
  private static final String FINDING_DETAILS_NAME = "finding.details";
  private static final String REQUESTED_PERMISSIONS_FIELD = "requestedPermissions";
  private static final String SCHEMA_VERSION_FIELD = "schemaVersion";

  /** Prevents construction of this static helper class. */
  private AppSubmissionJson() {}

  /**
   * Writes a supported JSON value with deterministic object ordering.
   *
   * <p>The writer uses the iteration order supplied by maps and iterables. Callers that need stable
   * output should pass {@link LinkedHashMap} or already sorted maps. The returned document always
   * ends with a newline so file output and digest calculation use a consistent final byte.
   *
   * @param value supported JSON value to serialize
   * @return compact JSON document ending with one newline
   */
  static String write(Object value) {
    StringBuilder builder = new StringBuilder();
    appendValue(builder, value);
    builder.append('\n');
    return builder.toString();
  }

  /**
   * Parses a JSON object and rejects trailing data.
   *
   * <p>The parser returns insertion-ordered maps, validates string escapes, rejects duplicate
   * object keys, and accepts integer numbers only. The description is included in redacted error
   * messages so CLI and pre-review output can point to the malformed artifact without echoing raw
   * contents.
   *
   * @param json JSON text read from a submission artifact
   * @param description short artifact description used in validation errors
   * @return parsed top-level object preserving input key order
   */
  static Map<String, Object> parseObject(String json, String description) {
    Parser parser = new Parser(json, description);
    Object value = parser.parseValue();
    parser.skipWhitespace();
    if (!parser.finished()) {
      throw AppCatalogSidecars.invalidEntry(description + " contains trailing JSON data");
    }
    return requireObject(value, description);
  }

  /**
   * Requires a parsed value to be a JSON object.
   *
   * @param value parsed value to validate
   * @param fieldName field or artifact name used in validation errors
   * @return parsed object with string keys and JSON-compatible values
   */
  @SuppressWarnings("unchecked")
  static Map<String, Object> requireObject(Object value, String fieldName) {
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    throw AppCatalogSidecars.invalidEntry(fieldName + " must be a JSON object");
  }

  /**
   * Requires a named object member to be present as a string.
   *
   * @param object parsed object containing the member
   * @param key raw JSON key to read
   * @param fieldName schema field name used in validation errors
   * @return string member value for downstream schema validation
   */
  static String requireString(Map<String, Object> object, String key, String fieldName) {
    Object value = object.get(key);
    if (value instanceof String text) {
      return text;
    }
    throw AppCatalogSidecars.invalidEntry(fieldName + " must be a string");
  }

  /**
   * Reads an optional string member from a parsed object.
   *
   * @param object parsed object containing the optional member
   * @param key raw JSON key to read
   * @param fieldName schema field name used in validation errors
   * @return empty when the member is absent, otherwise the string value
   */
  static Optional<String> optionalString(Map<String, Object> object, String key, String fieldName) {
    Object value = object.get(key);
    if (value == null) {
      return Optional.empty();
    }
    if (value instanceof String text) {
      return Optional.of(text);
    }
    throw AppCatalogSidecars.invalidEntry(fieldName + " must be a string");
  }

  /**
   * Requires a named object member to be present as a boolean.
   *
   * @param object parsed object containing the member
   * @param key raw JSON key to read
   * @param fieldName schema field name used in validation errors
   * @return boolean member value
   */
  static boolean requireBoolean(Map<String, Object> object, String key, String fieldName) {
    Object value = object.get(key);
    if (value instanceof Boolean bool) {
      return bool;
    }
    throw AppCatalogSidecars.invalidEntry(fieldName + " must be a boolean");
  }

  /**
   * Requires the submission or report schema version to be present as a 32-bit integer.
   *
   * <p>JSON numbers are parsed as {@link Long} first so out-of-range schema values can be rejected
   * explicitly instead of truncating.
   *
   * @param object parsed object containing the schema version
   * @return schema version value within the Java {@code int} range
   */
  static int requireSchemaVersion(Map<String, Object> object) {
    Object value = object.get(SCHEMA_VERSION_FIELD);
    if (value instanceof Long number
        && number >= Integer.MIN_VALUE
        && number <= Integer.MAX_VALUE) {
      return number.intValue();
    }
    throw AppCatalogSidecars.invalidEntry(SCHEMA_VERSION_FIELD + " must be an integer");
  }

  /**
   * Requires requested permissions to be an array of strings.
   *
   * <p>The returned list is immutable. Element-level validation for permission-name syntax is left
   * to the submission metadata model.
   *
   * @param object parsed object containing requested permissions
   * @return immutable list of requested permission strings
   */
  static List<String> requireRequestedPermissions(Map<String, Object> object) {
    Object value = object.get(REQUESTED_PERMISSIONS_FIELD);
    if (!(value instanceof List<?> list)) {
      throw AppCatalogSidecars.invalidEntry(REQUESTED_PERMISSIONS_FIELD + " must be an array");
    }
    List<String> strings = new ArrayList<>();
    for (Object element : list) {
      if (!(element instanceof String text)) {
        throw AppCatalogSidecars.invalidEntry(
            REQUESTED_PERMISSIONS_FIELD + " must contain only strings");
      }
      strings.add(text);
    }
    return List.copyOf(strings);
  }

  /**
   * Reads the optional finding details object from a parsed finding.
   *
   * <p>Absent objects are represented as an immutable empty map so callers can iterate without
   * special null handling. Present values must be JSON objects.
   *
   * @param object parsed finding object containing optional details
   * @return parsed finding details object, or an empty map when absent
   */
  @SuppressWarnings("unchecked")
  static Map<String, Object> optionalFindingDetails(Map<String, Object> object) {
    Object value = object.get(FINDING_DETAILS_FIELD);
    if (value == null) {
      return Map.of();
    }
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    throw AppCatalogSidecars.invalidEntry(FINDING_DETAILS_NAME + " must be a JSON object");
  }

  /**
   * Appends a supported JSON value to the existing builder.
   *
   * @param builder destination receiving compact JSON text
   * @param value supported value or {@code null}
   */
  private static void appendValue(StringBuilder builder, Object value) {
    switch (value) {
      case null -> builder.append("null");
      case String text -> appendString(builder, text);
      case Boolean bool -> builder.append(bool.booleanValue());
      case Integer number -> builder.append(number.intValue());
      case Long number -> builder.append(number.longValue());
      case Map<?, ?> map -> appendObject(builder, map);
      case Iterable<?> iterable -> appendArray(builder, iterable);
      default -> throw new IllegalArgumentException("unsupported JSON value: " + value.getClass());
    }
  }

  /**
   * Appends a JSON object using the supplied map iteration order.
   *
   * @param builder destination receiving object text
   * @param map map whose keys are converted to strings
   */
  private static void appendObject(StringBuilder builder, Map<?, ?> map) {
    builder.append('{');
    boolean first = true;
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      appendString(builder, Objects.toString(entry.getKey()));
      builder.append(':');
      appendValue(builder, entry.getValue());
    }
    builder.append('}');
  }

  /**
   * Appends a JSON array using the supplied iterable order.
   *
   * @param builder destination receiving array text
   * @param values values to serialize as array elements
   */
  private static void appendArray(StringBuilder builder, Iterable<?> values) {
    builder.append('[');
    boolean first = true;
    for (Object value : values) {
      if (!first) {
        builder.append(',');
      }
      first = false;
      appendValue(builder, value);
    }
    builder.append(']');
  }

  /**
   * Appends a JSON string with required escaping for control characters.
   *
   * @param builder destination receiving string text
   * @param value string value to quote and escape
   */
  private static void appendString(StringBuilder builder, String value) {
    builder.append('"');
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      switch (ch) {
        case '"' -> builder.append("\\\"");
        case '\\' -> builder.append("\\\\");
        case '\b' -> builder.append("\\b");
        case '\f' -> builder.append("\\f");
        case '\n' -> builder.append("\\n");
        case '\r' -> builder.append("\\r");
        case '\t' -> builder.append("\\t");
        default -> {
          if (ch < 0x20) {
            builder.append(String.format("\\u%04x", (int) ch));
          } else {
            builder.append(ch);
          }
        }
      }
    }
    builder.append('"');
  }

  /**
   * Single-pass parser for the constrained submission JSON subset.
   *
   * <p>The parser keeps only the raw input, a short description for errors, and the current byte
   * index. It does not attempt recovery: malformed text produces an invalid catalog-entry exception
   * at the first detected boundary.
   */
  private static final class Parser {
    /** Raw JSON document being parsed. */
    private final String json;

    /** Redacted artifact description used in parse errors. */
    private final String description;

    /** Current character offset into {@link #json}. */
    private int index;

    /**
     * Creates a parser for one JSON document.
     *
     * @param json JSON text to parse
     * @param description short artifact description for validation errors
     */
    Parser(String json, String description) {
      this.json = Objects.requireNonNull(json, "json");
      this.description = Objects.requireNonNull(description, "description");
    }

    /**
     * Parses the next JSON value from the current offset.
     *
     * @return parsed Java representation for the next value
     */
    Object parseValue() {
      skipWhitespace();
      if (finished()) {
        throw AppCatalogSidecars.invalidEntry(description + " is empty");
      }
      char ch = json.charAt(index);
      return switch (ch) {
        case '{' -> parseObject();
        case '[' -> parseArray();
        case '"' -> parseString();
        case 't' -> parseLiteral("true", Boolean.TRUE);
        case 'f' -> parseLiteral("false", Boolean.FALSE);
        case 'n' -> parseLiteral("null", null);
        default -> {
          if (ch == '-' || Character.isDigit(ch)) {
            yield parseNumber();
          }
          throw AppCatalogSidecars.invalidEntry(description + " contains invalid JSON");
        }
      };
    }

    /** Skips JSON whitespace before parsing the next token. */
    void skipWhitespace() {
      while (!finished()) {
        char ch = json.charAt(index);
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
          return;
        }
        index++;
      }
    }

    /**
     * Returns whether the parser consumed the complete document.
     *
     * @return {@code true} when the current offset is at or past the end
     */
    boolean finished() {
      return index >= json.length();
    }

    /**
     * Parses an object and preserves key insertion order.
     *
     * @return parsed object with duplicate keys rejected
     */
    private Map<String, Object> parseObject() {
      index++;
      LinkedHashMap<String, Object> object = new LinkedHashMap<>();
      skipWhitespace();
      if (consume('}')) {
        return object;
      }
      while (true) {
        skipWhitespace();
        if (finished() || json.charAt(index) != '"') {
          throw AppCatalogSidecars.invalidEntry(description + " object key must be a string");
        }
        String key = parseString();
        if (object.containsKey(key)) {
          throw AppCatalogSidecars.invalidEntry(description + " contains duplicate key: " + key);
        }
        skipWhitespace();
        require(':');
        object.put(key, parseValue());
        skipWhitespace();
        if (consume('}')) {
          return object;
        }
        require(',');
      }
    }

    /**
     * Parses an array and returns an immutable element list.
     *
     * @return parsed array values in input order
     */
    private List<Object> parseArray() {
      index++;
      List<Object> values = new ArrayList<>();
      skipWhitespace();
      if (consume(']')) {
        return values;
      }
      while (true) {
        values.add(parseValue());
        skipWhitespace();
        if (consume(']')) {
          return List.copyOf(values);
        }
        require(',');
      }
    }

    /**
     * Parses a JSON string and resolves supported escapes.
     *
     * @return unescaped Java string value
     */
    private String parseString() {
      require('"');
      StringBuilder builder = new StringBuilder();
      while (!finished()) {
        char ch = json.charAt(index++);
        if (ch == '"') {
          return builder.toString();
        }
        if (ch != '\\') {
          if (ch < 0x20) {
            throw AppCatalogSidecars.invalidEntry(description + " contains a control character");
          }
          builder.append(ch);
          continue;
        }
        if (finished()) {
          throw AppCatalogSidecars.invalidEntry(description + " contains an invalid escape");
        }
        char escape = json.charAt(index++);
        switch (escape) {
          case '"', '\\', '/' -> builder.append(escape);
          case 'b' -> builder.append('\b');
          case 'f' -> builder.append('\f');
          case 'n' -> builder.append('\n');
          case 'r' -> builder.append('\r');
          case 't' -> builder.append('\t');
          case 'u' -> builder.append(parseUnicodeEscape());
          default ->
              throw AppCatalogSidecars.invalidEntry(description + " contains an invalid escape");
        }
      }
      throw AppCatalogSidecars.invalidEntry(description + " contains an unterminated string");
    }

    /**
     * Parses a four-digit Unicode escape from the current offset.
     *
     * @return decoded UTF-16 code unit
     */
    private char parseUnicodeEscape() {
      if (index + 4 > json.length()) {
        throw AppCatalogSidecars.invalidEntry(description + " contains an invalid unicode escape");
      }
      String hex = json.substring(index, index + 4);
      index += 4;
      try {
        return (char) Integer.parseInt(hex, 16);
      } catch (NumberFormatException exception) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            description + " contains an invalid unicode escape",
            exception);
      }
    }

    /**
     * Parses a fixed JSON literal.
     *
     * @param literal exact token expected at the current offset
     * @param value parsed value represented by the token
     * @return value supplied by the caller after the token is consumed
     */
    private Object parseLiteral(String literal, Object value) {
      if (!json.startsWith(literal, index)) {
        throw AppCatalogSidecars.invalidEntry(description + " contains an invalid literal");
      }
      index += literal.length();
      return value;
    }

    /**
     * Parses an integer JSON number as a {@link Long}.
     *
     * @return parsed integer number without fractional or exponent syntax
     */
    private Long parseNumber() {
      int start = index;
      if (json.charAt(index) == '-') {
        index++;
      }
      if (finished() || !Character.isDigit(json.charAt(index))) {
        throw AppCatalogSidecars.invalidEntry(description + " contains an invalid number");
      }
      while (!finished() && Character.isDigit(json.charAt(index))) {
        index++;
      }
      if (!finished()
          && (json.charAt(index) == '.'
              || json.charAt(index) == 'e'
              || json.charAt(index) == 'E')) {
        throw AppCatalogSidecars.invalidEntry(description + " accepts integer JSON numbers only");
      }
      try {
        return Long.parseLong(json.substring(start, index));
      } catch (NumberFormatException exception) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            description + " contains an out-of-range number",
            exception);
      }
    }

    /**
     * Consumes one expected character when present.
     *
     * @param expected character to match at the current offset
     * @return {@code true} when the character was present and consumed
     */
    private boolean consume(char expected) {
      if (!finished() && json.charAt(index) == expected) {
        index++;
        return true;
      }
      return false;
    }

    /**
     * Requires and consumes one expected character.
     *
     * @param expected character that must appear at the current offset
     */
    private void require(char expected) {
      if (finished() || json.charAt(index) != expected) {
        throw AppCatalogSidecars.invalidEntry(description + " expected '" + expected + "'");
      }
      index++;
    }
  }
}
