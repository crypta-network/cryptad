package network.crypta.platform.api.appdata;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;

/**
 * Small JSON parser used only for bounded app-data export imports.
 *
 * <p>The Platform API leaf intentionally avoids a general JSON dependency. This parser accepts the
 * JSON value types written by {@link network.crypta.platform.api.json.PlatformApiJsonWriter} and
 * used by app-data export payloads: objects, arrays, strings, booleans, {@code null}, and integral
 * numbers. It is not exposed as a general Platform API feature.
 *
 * <p>The grammar is deliberately stricter than arbitrary JSON because app-data imports need stable
 * failure behavior more than permissive parsing. Numbers are parsed as {@link Long} values and
 * fractional or exponent forms are rejected. Nesting is capped so malformed app-owned payloads
 * cannot force unbounded recursion. Any parse failure maps to the same sanitized Platform API error
 * code used by higher-level import validation.
 */
final class AppDataJsonParser {
  private static final int MAX_NESTING_DEPTH = 64;

  private final String text;
  private int index;

  private AppDataJsonParser(String text) {
    this.text = text;
  }

  /**
   * Parses a bounded app-data JSON value.
   *
   * <p>The returned object graph uses {@link Map}, {@link List}, {@link String}, {@link Boolean},
   * {@link Long}, and {@code null}. Callers remain responsible for validating the expected export
   * payload shape and applying app-data quota checks before any imported value is committed.
   *
   * @param text UTF-16 Java string containing UTF-8-decoded app-data JSON
   * @return parsed JSON value tree using platform-owned collection types
   * @throws PlatformApiException if the input is malformed or uses unsupported JSON number forms
   */
  static Object parse(String text) {
    return new AppDataJsonParser(text).parse();
  }

  private Object parse() {
    Object value = parseValue(0);
    skipWhitespace();
    if (index != text.length()) {
      throw error();
    }
    return value;
  }

  private Object parseValue(int depth) {
    skipWhitespace();
    if (index >= text.length()) {
      throw error();
    }
    return switch (text.charAt(index)) {
      case '{' -> parseObject(depth);
      case '[' -> parseArray(depth);
      case '"' -> parseString();
      case 't' -> parseLiteral("true", Boolean.TRUE);
      case 'f' -> parseLiteral("false", Boolean.FALSE);
      case 'n' -> parseLiteral("null", null);
      default -> parseNumber();
    };
  }

  private Map<String, Object> parseObject(int depth) {
    requireDepth(depth);
    expect('{');
    LinkedHashMap<String, Object> object = new LinkedHashMap<>();
    skipWhitespace();
    if (consume('}')) {
      return object;
    }
    do {
      skipWhitespace();
      String key = parseString();
      skipWhitespace();
      expect(':');
      object.put(key, parseValue(depth + 1));
      skipWhitespace();
    } while (consume(','));
    expect('}');
    return object;
  }

  private List<Object> parseArray(int depth) {
    requireDepth(depth);
    expect('[');
    ArrayList<Object> array = new ArrayList<>();
    skipWhitespace();
    if (consume(']')) {
      return List.copyOf(array);
    }
    do {
      array.add(parseValue(depth + 1));
      skipWhitespace();
    } while (consume(','));
    expect(']');
    return List.copyOf(array);
  }

  private void requireDepth(int depth) {
    if (depth >= MAX_NESTING_DEPTH) {
      throw error();
    }
  }

  private String parseString() {
    expect('"');
    StringBuilder value = new StringBuilder();
    while (index < text.length()) {
      char ch = text.charAt(index++);
      if (ch == '"') {
        return value.toString();
      }
      if (ch == '\\') {
        value.append(parseEscape());
      } else if (ch < 0x20) {
        throw error();
      } else {
        value.append(ch);
      }
    }
    throw error();
  }

  private char parseEscape() {
    if (index >= text.length()) {
      throw error();
    }
    char escaped = text.charAt(index++);
    return switch (escaped) {
      case '"', '\\', '/' -> escaped;
      case 'b' -> '\b';
      case 'f' -> '\f';
      case 'n' -> '\n';
      case 'r' -> '\r';
      case 't' -> '\t';
      case 'u' -> parseUnicodeEscape();
      default -> throw error();
    };
  }

  private char parseUnicodeEscape() {
    if (index + 4 > text.length()) {
      throw error();
    }
    int value = 0;
    for (int offset = 0; offset < 4; offset++) {
      int digit = Character.digit(text.charAt(index++), 16);
      if (digit < 0) {
        throw error();
      }
      value = (value << 4) | digit;
    }
    return (char) value;
  }

  private Object parseLiteral(String literal, Object value) {
    if (!text.startsWith(literal, index)) {
      throw error();
    }
    index += literal.length();
    return value;
  }

  private Long parseNumber() {
    int start = index;
    if (consume('-') && index >= text.length()) {
      throw error();
    }
    if (consume('0')) {
      if (index < text.length() && isDigit(text.charAt(index))) {
        throw error();
      }
    } else {
      parseDigits();
    }
    if (index < text.length()
        && (text.charAt(index) == '.' || text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
      throw error();
    }
    try {
      return Long.parseLong(text.substring(start, index));
    } catch (NumberFormatException _) {
      throw error();
    }
  }

  private void parseDigits() {
    if (index >= text.length() || !isDigit(text.charAt(index))) {
      throw error();
    }
    while (index < text.length() && isDigit(text.charAt(index))) {
      index++;
    }
  }

  private void skipWhitespace() {
    while (index < text.length()) {
      char ch = text.charAt(index);
      if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
        index++;
      } else {
        return;
      }
    }
  }

  private void expect(char expected) {
    if (!consume(expected)) {
      throw error();
    }
  }

  private boolean consume(char expected) {
    if (index < text.length() && text.charAt(index) == expected) {
      index++;
      return true;
    }
    return false;
  }

  private static boolean isDigit(char ch) {
    return ch >= '0' && ch <= '9';
  }

  private static PlatformApiException error() {
    return new PlatformApiException(
        400, "invalid_app_data_import", "Invalid app-data import payload.");
  }
}
