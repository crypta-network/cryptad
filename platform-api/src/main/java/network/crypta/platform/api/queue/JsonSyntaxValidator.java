package network.crypta.platform.api.queue;

/**
 * Tiny JSON syntax validator used for bounded app-generated documents.
 *
 * <p>The validator only answers whether a UTF-8 string is syntactically JSON. It does not expose
 * parsed values, so the app-document route can reject malformed JSON without adding a general JSON
 * dependency to the Platform API leaf.
 *
 * <p>The implementation is a small recursive-descent parser for the JSON grammar needed by the
 * app-document insert route. It validates complete documents, rejects trailing data, accepts only
 * JSON whitespace, enforces ASCII digits for numbers, and caps object/array nesting so untrusted
 * app-controlled input cannot overflow the JVM stack. It intentionally performs no semantic
 * interpretation: strings are not unescaped, numbers are not converted, and object keys are not
 * inspected. The caller should still enforce byte-size and UTF-8 constraints before invoking this
 * validator.
 *
 * <p>Instances are single-use and not thread-safe. The public entry point creates a fresh parser
 * for each document, so callers do not share parse state.
 */
final class JsonSyntaxValidator {
  /**
   * Maximum accepted object/array nesting depth.
   *
   * <p>The bound is high enough for small structured profile documents and low enough to keep the
   * recursive descent stack bounded for malicious app-supplied JSON.
   */
  private static final int MAX_NESTING_DEPTH = 64;

  /** Complete JSON text being validated. */
  private final String text;

  /** Current UTF-16 code-unit offset into {@link #text}. */
  private int index;

  /**
   * Creates one parser over a complete JSON document string.
   *
   * @param text UTF-16 Java string decoded from the caller's validated UTF-8 bytes
   */
  private JsonSyntaxValidator(String text) {
    this.text = text;
  }

  /**
   * Validates that the supplied text is one complete JSON document.
   *
   * <p>The method throws {@link IllegalArgumentException} for malformed input and otherwise returns
   * no value. It is deliberately narrow: callers use it only as a syntax gate before enqueueing
   * app-generated JSON bytes.
   *
   * @param text JSON document text decoded from app-supplied UTF-8 bytes
   * @throws IllegalArgumentException when the document is not syntactically valid JSON
   */
  static void validate(String text) {
    new JsonSyntaxValidator(text).parse();
  }

  /**
   * Parses a full document and rejects trailing non-whitespace input.
   *
   * @throws IllegalArgumentException when the first value is malformed or not the whole document
   */
  private void parse() {
    parseValue(0);
    skipWhitespace();
    if (index != text.length()) {
      throw error();
    }
  }

  /**
   * Parses one JSON value at the current offset.
   *
   * @param depth current object/array nesting depth before reading this value
   * @throws IllegalArgumentException when no valid JSON value begins at the current offset
   */
  private void parseValue(int depth) {
    skipWhitespace();
    if (index >= text.length()) {
      throw error();
    }
    switch (text.charAt(index)) {
      case '{' -> parseObject(depth);
      case '[' -> parseArray(depth);
      case '"' -> parseString();
      case 't' -> parseLiteral("true");
      case 'f' -> parseLiteral("false");
      case 'n' -> parseLiteral("null");
      default -> parseNumber();
    }
  }

  /**
   * Parses one JSON object.
   *
   * @param depth current nesting depth for the object being opened
   * @throws IllegalArgumentException when object syntax or nesting depth is invalid
   */
  private void parseObject(int depth) {
    requireDepth(depth);
    expect('{');
    skipWhitespace();
    if (consume('}')) {
      return;
    }
    do {
      skipWhitespace();
      parseString();
      skipWhitespace();
      expect(':');
      parseValue(depth + 1);
      skipWhitespace();
    } while (consume(','));
    expect('}');
  }

  /**
   * Parses one JSON array.
   *
   * @param depth current nesting depth for the array being opened
   * @throws IllegalArgumentException when array syntax or nesting depth is invalid
   */
  private void parseArray(int depth) {
    requireDepth(depth);
    expect('[');
    skipWhitespace();
    if (consume(']')) {
      return;
    }
    do {
      parseValue(depth + 1);
      skipWhitespace();
    } while (consume(','));
    expect(']');
  }

  /**
   * Enforces the configured recursive nesting bound.
   *
   * @param depth current object/array nesting depth before opening a container
   * @throws IllegalArgumentException when the next container would exceed the route limit
   */
  private void requireDepth(int depth) {
    if (depth >= MAX_NESTING_DEPTH) {
      throw error();
    }
  }

  /**
   * Parses one JSON string including escapes.
   *
   * <p>The method validates syntax only. It does not allocate or return the unescaped value because
   * the app-document route only needs to know that the original byte sequence is valid JSON.
   *
   * @throws IllegalArgumentException when the string is unterminated or contains raw controls
   */
  private void parseString() {
    expect('"');
    while (index < text.length()) {
      char ch = text.charAt(index++);
      if (ch == '"') {
        return;
      }
      if (ch == '\\') {
        parseEscape();
      } else if (ch < 0x20) {
        throw error();
      }
    }
    throw error();
  }

  /**
   * Parses one JSON string escape after a backslash.
   *
   * @throws IllegalArgumentException when the escape sequence is not permitted by JSON
   */
  private void parseEscape() {
    if (index >= text.length()) {
      throw error();
    }
    char escaped = text.charAt(index++);
    switch (escaped) {
      case '"', '\\', '/', 'b', 'f', 'n', 'r', 't' -> {
        // The single-character escape is valid and was consumed above.
      }
      case 'u' -> parseUnicodeEscape();
      default -> throw error();
    }
  }

  /**
   * Parses the four ASCII hexadecimal digits of a JSON Unicode escape.
   *
   * @throws IllegalArgumentException when fewer than four hex digits are available
   */
  private void parseUnicodeEscape() {
    if (index + 4 > text.length()) {
      throw error();
    }
    for (int offset = 0; offset < 4; offset++) {
      if (!isAsciiHexDigit(text.charAt(index++))) {
        throw error();
      }
    }
  }

  /**
   * Parses one fixed JSON literal.
   *
   * @param literal expected literal text such as {@code true}, {@code false}, or {@code null}
   * @throws IllegalArgumentException when the literal does not match at the current offset
   */
  private void parseLiteral(String literal) {
    if (!text.startsWith(literal, index)) {
      throw error();
    }
    index += literal.length();
  }

  /**
   * Parses one JSON number using ASCII digit rules.
   *
   * <p>JSON numbers do not accept locale-specific or Unicode digit classes. This method therefore
   * checks only {@code 0} through {@code 9}, rejects leading zeroes before another digit, and
   * requires at least one digit after decimal points and exponent markers.
   *
   * @throws IllegalArgumentException when the number grammar is not satisfied
   */
  private void parseNumber() {
    consumeOptionalMinus();
    parseIntegerPart();
    parseFractionPart();
    parseExponentPart();
  }

  /**
   * Consumes an optional leading minus sign.
   *
   * @throws IllegalArgumentException when the document ends immediately after the minus sign
   */
  private void consumeOptionalMinus() {
    if (!consume('-')) {
      return;
    }
    if (index >= text.length()) {
      throw error();
    }
  }

  /**
   * Parses the required integer portion of a JSON number.
   *
   * <p>The integer portion is either a single {@code 0} or a non-zero leading digit followed by
   * zero or more ASCII digits. A zero followed by another digit is rejected as a leading-zero
   * number.
   *
   * @throws IllegalArgumentException when no valid integer part is present
   */
  private void parseIntegerPart() {
    if (consume('0')) {
      rejectLeadingZero();
      return;
    }
    requireDigit();
    consumeAsciiDigits();
  }

  /**
   * Rejects an otherwise valid integer part that starts with {@code 0} and continues with a digit.
   *
   * @throws IllegalArgumentException when the current offset points at a second integer digit
   */
  private void rejectLeadingZero() {
    if (index < text.length() && isAsciiDigit(text.charAt(index))) {
      throw error();
    }
  }

  /**
   * Parses an optional fractional portion.
   *
   * @throws IllegalArgumentException when a decimal point is present without a following digit
   */
  private void parseFractionPart() {
    if (!consume('.')) {
      return;
    }
    requireDigit();
    consumeAsciiDigits();
  }

  /**
   * Parses an optional exponent portion.
   *
   * @throws IllegalArgumentException when an exponent marker is present without exponent digits
   */
  private void parseExponentPart() {
    if (!consumeExponentMarker()) {
      return;
    }
    consumeOptionalExponentSign();
    requireDigit();
    consumeAsciiDigits();
  }

  /**
   * Consumes an optional exponent marker.
   *
   * @return {@code true} when {@code e} or {@code E} was present
   */
  private boolean consumeExponentMarker() {
    if (index < text.length() && isExponentMarker(text.charAt(index))) {
      index++;
      return true;
    }
    return false;
  }

  /** Consumes an optional exponent sign after an exponent marker. */
  private void consumeOptionalExponentSign() {
    if (index < text.length() && isExponentSign(text.charAt(index))) {
      index++;
    }
  }

  /** Advances over zero or more ASCII digits. */
  private void consumeAsciiDigits() {
    while (index < text.length() && isAsciiDigit(text.charAt(index))) {
      index++;
    }
  }

  /**
   * Consumes one required ASCII digit.
   *
   * @throws IllegalArgumentException when the current offset is not an ASCII digit
   */
  private void requireDigit() {
    if (index >= text.length() || !isAsciiDigit(text.charAt(index))) {
      throw error();
    }
    index++;
  }

  /**
   * Tests whether a character is one of the JSON number digits.
   *
   * @param ch character to test without locale or Unicode digit expansion
   * @return {@code true} only for {@code '0'} through {@code '9'}
   */
  private static boolean isAsciiDigit(char ch) {
    return ch >= '0' && ch <= '9';
  }

  /**
   * Tests whether a character starts a JSON number exponent.
   *
   * @param ch character to test
   * @return {@code true} for {@code e} or {@code E}
   */
  private static boolean isExponentMarker(char ch) {
    return ch == 'e' || ch == 'E';
  }

  /**
   * Tests whether a character is a JSON exponent sign.
   *
   * @param ch character to test
   * @return {@code true} for {@code +} or {@code -}
   */
  private static boolean isExponentSign(char ch) {
    return ch == '+' || ch == '-';
  }

  /**
   * Tests whether a character is one of the JSON unicode-escape hex digits.
   *
   * @param ch character to test without accepting Unicode digit or letter classes
   * @return {@code true} only for ASCII {@code 0-9}, {@code A-F}, or {@code a-f}
   */
  private static boolean isAsciiHexDigit(char ch) {
    return isAsciiDigit(ch) || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
  }

  /**
   * Advances past JSON whitespace.
   *
   * <p>Only the four whitespace characters defined by JSON are skipped: space, line feed, carriage
   * return, and horizontal tab. Other Unicode whitespace remains significant and will fail if it is
   * not legal at the current grammar position.
   */
  private void skipWhitespace() {
    while (index < text.length()) {
      char ch = text.charAt(index);
      if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
        return;
      }
      index++;
    }
  }

  /**
   * Consumes one expected character when it is present.
   *
   * @param expected character to match at the current offset
   * @return {@code true} when the character was present and consumed
   */
  private boolean consume(char expected) {
    if (index < text.length() && text.charAt(index) == expected) {
      index++;
      return true;
    }
    return false;
  }

  /**
   * Consumes one required character.
   *
   * @param expected character that must appear at the current offset
   * @throws IllegalArgumentException when the expected character is absent
   */
  private void expect(char expected) {
    if (!consume(expected)) {
      throw error();
    }
  }

  /**
   * Creates the parser's stable syntax exception.
   *
   * @return exception containing the current parser offset for diagnostics
   */
  private IllegalArgumentException error() {
    return new IllegalArgumentException("Invalid JSON at offset " + index);
  }
}
