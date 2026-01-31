package network.crypta.support;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Utility methods for validating strings against platform and protocol constraints.
 *
 * <p>This class centralizes small, fast checks used throughout the codebase to decide whether a
 * string is acceptable for specific contexts such as filenames (Windows/macOS/Unix), user-visible
 * text (no line breaks or control characters), Internationalized Domain Names (no blacklisted
 * characters), and Unicode formatting safety (balanced directional formatting marks and
 * annotations). All methods are side‑effect free and run in time linear in the input length unless
 * otherwise noted.
 *
 * <p>Null arguments are not permitted. Passing {@code null} will result in a {@link
 * NullPointerException} from normal Java operations inside the methods.
 */
public final class StringValidityChecker {

  private StringValidityChecker() {
    throw new IllegalStateException("Utility class");
  }

  /* Characters blacklisted for IDN labels.
   * Source: http://kb.mozillazine.org/Network.IDN.blacklist_chars
   */
  private static final Set<Character> idnBlacklist = buildIdnBlacklist();

  private static Set<Character> buildIdnBlacklist() {
    final int[] codes = {
      0x0020, /* SPACE */
      0x00A0, /* NO-BREAK SPACE */
      0x00BC, /* VULGAR FRACTION ONE QUARTER */
      0x00BD, /* VULGAR FRACTION ONE HALF */
      0x01C3, /* LATIN LETTER RETROFLEX CLICK */
      0x0337, /* COMBINING SHORT SOLIDUS OVERLAY */
      0x0338, /* COMBINING LONG SOLIDUS OVERLAY */
      0x05C3, /* HEBREW PUNCTUATION SOF PASUQ */
      0x05F4, /* HEBREW PUNCTUATION GERSHAYIM */
      0x06D4, /* ARABIC FULL STOP */
      0x0702, /* SYRIAC SUBLINEAR FULL STOP */
      0x115F, /* HANGUL CHOSEONG FILLER */
      0x1160, /* HANGUL JUNGSEONG FILLER */
      0x2000, /* EN QUAD */
      0x2001, /* EM QUAD */
      0x2002, /* EN SPACE */
      0x2003, /* EM SPACE */
      0x2004, /* THREE-PER-EM SPACE */
      0x2005, /* FOUR-PER-EM SPACE */
      0x2006, /* SIX-PER-EM-SPACE */
      0x2007, /* FIGURE SPACE */
      0x2008, /* PUNCTUATION SPACE */
      0x2009, /* THIN SPACE */
      0x200A, /* HAIR SPACE */
      0x200B, /* ZERO WIDTH SPACE */
      0x2024, /* ONE DOT LEADER */
      0x2027, /* HYPHENATION POINT */
      0x2028, /* LINE SEPARATOR */
      0x2029, /* PARAGRAPH SEPARATOR */
      0x202F, /* NARROW NO-BREAK SPACE */
      0x2039, /* SINGLE LEFT-POINTING ANGLE QUOTATION MARK */
      0x203A, /* SINGLE RIGHT-POINTING ANGLE QUOTATION MARK */
      0x2044, /* FRACTION SLASH */
      0x205F, /* MEDIUM MATHEMATICAL SPACE */
      0x2154, /* VULGAR FRACTION TWO THIRDS */
      0x2155, /* VULGAR FRACTION ONE FIFTH */
      0x2156, /* VULGAR FRACTION TWO FIFTHS */
      0x2159, /* VULGAR FRACTION ONE SIXTH */
      0x215A, /* VULGAR FRACTION FIVE SIXTHS */
      0x215B, /* VULGAR FRACTION ONE EIGTH */
      0x215F, /* FRACTION NUMERATOR ONE */
      0x2215, /* DIVISION SLASH */
      0x23AE, /* INTEGRAL EXTENSION */
      0x29F6, /* SOLIDUS WITH OVERBAR */
      0x29F8, /* BIG SOLIDUS */
      0x2AFB, /* TRIPLE SOLIDUS BINARY RELATION */
      0x2AFD, /* DOUBLE SOLIDUS OPERATOR */
      0x2FF0, /* IDEOGRAPHIC DESCRIPTION CHARACTER LEFT TO RIGHT */
      0x2FF1, /* IDEOGRAPHIC DESCRIPTION CHARACTER ABOVE TO BELOW */
      0x2FF2, /* IDEOGRAPHIC DESCRIPTION CHARACTER LEFT TO MIDDLE AND RIGHT */
      0x2FF3, /* IDEOGRAPHIC DESCRIPTION CHARACTER ABOVE TO MIDDLE AND BELOW */
      0x2FF4, /* IDEOGRAPHIC DESCRIPTION CHARACTER FULL SURROUND */
      0x2FF5, /* IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM ABOVE */
      0x2FF6, /* IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM BELOW */
      0x2FF7, /* IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM LEFT */
      0x2FF8, /* IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM UPPER LEFT */
      0x2FF9, /* IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM UPPER RIGHT */
      0x2FFA, /* IDEOGRAPHIC DESCRIPTION CHARACTER SURROUND FROM LOWER LEFT */
      0x2FFB, /* IDEOGRAPHIC DESCRIPTION CHARACTER OVERLAID */
      0x3000, /* IDEOGRAPHIC SPACE */
      0x3002, /* IDEOGRAPHIC FULL STOP */
      0x3014, /* LEFT TORTOISE SHELL BRACKET */
      0x3015, /* RIGHT TORTOISE SHELL BRACKET */
      0x3033, /* VERTICAL KANA REPEAT MARK UPPER HALF */
      0x3164, /* HANGUL FILLER */
      0x321D, /* PARENTHESIZED KOREAN CHARACTER OJEON */
      0x321E, /* PARENTHESIZED KOREAN CHARACTER O HU */
      0x33AE, /* SQUARE RAD OVER S */
      0x33AF, /* SQUARE RAD OVER S SQUARED */
      0x33C6, /* SQUARE C OVER KG */
      0x33DF, /* SQUARE A OVER M */
      0xFE14, /* PRESENTATION FORM FOR VERTICAL SEMICOLON */
      0xFE15, /* PRESENTATION FORM FOR VERTICAL EXCLAMATION MARK */
      0xFE3F, /* PRESENTATION FORM FOR VERTICAL LEFT ANGLE BRACKET */
      0xFE5D, /* SMALL LEFT TORTOISE SHELL BRACKET */
      0xFE5E, /* SMALL RIGHT TORTOISE SHELL BRACKET */
      0xFEFF, /* ZERO-WIDTH NO-BREAK SPACE */
      0xFF0E, /* FULLWIDTH FULL STOP */
      0xFF0F, /* FULL WIDTH SOLIDUS */
      0xFF61, /* HALFWIDTH IDEOGRAPHIC FULL STOP */
      0xFFA0, /* HALFWIDTH HANGUL FILLER */
      0xFFF9, /* INTERLINEAR ANNOTATION ANCHOR */
      0xFFFA, /* INTERLINEAR ANNOTATION SEPARATOR */
      0xFFFB, /* INTERLINEAR ANNOTATION TERMINATOR */
      0xFFFC, /* OBJECT REPLACEMENT CHARACTER */
      0xFFFD /* REPLACEMENT CHARACTER */
    };

    HashSet<Character> set = new HashSet<>();
    for (int code : codes) {
      set.add((char) code);
    }
    return set;
  }

  /* Reserved printable characters for Windows filenames.
   * Source: https://en.wikipedia.org/w/index.php?title=Filename&oldid=344618757
   */
  private static final HashSet<Character> windowsReservedPrintableFilenameCharacters =
      new HashSet<>(Arrays.asList('/', '\\', '?', '*', ':', '|', '\"', '<', '>'));

  /* Reserved base names on Windows (case-insensitive).
   * Source: https://en.wikipedia.org/w/index.php?title=Filename&oldid=344618757
   */
  private static final HashSet<String> windowsReservedFilenames =
      new HashSet<>(
          Arrays.asList(
              "aux", "clock$", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
              "com9", "con", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
              "nul", "prn"));

  /* Reserved printable characters for macOS filenames.
   * Source: https://en.wikipedia.org/w/index.php?title=Filename&oldid=344618757
   */
  private static final HashSet<Character> macOSReservedPrintableFilenameCharacters =
      new HashSet<>(Arrays.asList(':', '/'));

  /**
   * Tests whether a character is a Windows-reserved printable filename character.
   *
   * <p>This does not test for control characters; those are forbidden on most operating systems and
   * are checked separately by {@link #containsNoControlCharacters(String)}.
   *
   * @param c character to test
   * @return {@code true} if {@code c} is reserved on Windows (e.g., {@code ':'}, {@code '\\'},
   *     {@code '/'})
   * @throws NullPointerException if {@code c} is {@code null}
   */
  public static boolean isWindowsReservedPrintableFilenameCharacter(Character c) {
    return windowsReservedPrintableFilenameCharacters.contains(c);
  }

  /**
   * Tests whether a filename matches a Windows-reserved base name.
   *
   * <p>The comparison is case-insensitive and only considers the portion of the name before the
   * first dot. For example, {@code "CON.txt"} and {@code "con.blah.txt"} are reserved.
   *
   * @param filename candidate filename (without path separators)
   * @return {@code true} if the base name is reserved on Windows (e.g., {@code CON}, {@code PRN},
   *     {@code NUL}, {@code AUX}, {@code COM1}–{@code COM9}, {@code LPT1}–{@code LPT9})
   * @throws NullPointerException if {@code filename} is {@code null}
   */
  public static boolean isWindowsReservedFilename(String filename) {
    filename = filename.toLowerCase(Locale.ROOT);
    // Only the segment before the first dot counts as the "base name" on Windows.
    // Example: "con.blah.txt" is treated as base name "con" and is therefore reserved.
    int nameEnd = filename.indexOf('.');
    if (nameEnd == -1) nameEnd = filename.length();

    return windowsReservedFilenames.contains(filename.substring(0, nameEnd));
  }

  /**
   * Tests whether a character is a macOS-reserved printable filename character.
   *
   * <p>This does not test for control characters; those are forbidden on most operating systems and
   * are checked separately by {@link #containsNoControlCharacters(String)}.
   *
   * @param c character to test
   * @return {@code true} if {@code c} is reserved on macOS (e.g., {@code ':'} or {@code '/'})
   * @throws NullPointerException if {@code c} is {@code null}
   */
  public static boolean isMacOSReservedPrintableFilenameCharacter(Character c) {
    return macOSReservedPrintableFilenameCharacters.contains(c);
  }

  /**
   * Tests whether a character is a Unix-reserved printable filename character.
   *
   * @param c character to test
   * @return {@code true} if {@code c} is {@code '/'} (the only portable reserved printable
   *     character on Unix-like systems)
   */
  public static boolean isUnixReservedPrintableFilenameCharacter(char c) {
    return c == '/';
  }

  /**
   * Checks that a string contains no characters blacklisted for IDN labels.
   *
   * <p>The blacklist comes from widely used browser/client policies and includes various spacing,
   * punctuation, and combining characters that are confusing or unsafe in hostnames.
   *
   * @param text string to check
   * @return {@code true} if {@code text} contains none of the blacklisted characters
   * @throws NullPointerException if {@code text} is {@code null}
   */
  public static boolean containsNoIDNBlacklistCharacters(String text) {
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (idnBlacklist.contains(c)) return false;
    }

    return true;
  }

  /**
   * Checks that a string contains no line breaks.
   *
   * <p>This rejects explicit {@code '\n'} and {@code '\r'} characters and also any characters in
   * the Unicode categories {@link Character#LINE_SEPARATOR} and {@link
   * Character#PARAGRAPH_SEPARATOR}.
   *
   * @param text string to check
   * @return {@code true} if {@code text} contains no line separators
   * @throws NullPointerException if {@code text} is {@code null}
   */
  public static boolean containsNoLinebreaks(String text) {
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (Character.getType(c) == Character.LINE_SEPARATOR
          || Character.getType(c) == Character.PARAGRAPH_SEPARATOR
          || c == '\n'
          || c == '\r') {
        return false;
      }
    }

    return true;
  }

  /**
   * Checks that a string contains only valid Unicode scalar values.
   *
   * <p>Specifically, this rejects all noncharacters (e.g., {@code U+FFFE}, {@code U+FFFF} and the
   * corresponding values in other planes) and any surrogate code units. The check operates on code
   * points and advances by {@link Character#charCount(int)}.
   *
   * @param text string to check
   * @return {@code true} if all code points are valid scalar values
   * @throws NullPointerException if {@code text} is {@code null}
   */
  public static boolean containsNoInvalidCharacters(String text) {
    int i = 0;
    while (i < text.length()) {
      int c = text.codePointAt(i);
      i += Character.charCount(c);

      if ((c & 0xFFFE) == 0xFFFE || Character.getType(c) == Character.SURROGATE) return false;
    }

    return true;
  }

  /**
   * Checks that a string contains no control characters.
   *
   * <p>This includes tab, line feed, carriage return, and any character whose Unicode category is
   * {@link Character#CONTROL}.
   *
   * @param text string to check
   * @return {@code true} if {@code text} contains no control characters
   * @throws NullPointerException if {@code text} is {@code null}
   */
  public static boolean containsNoControlCharacters(String text) {
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (Character.getType(c) == Character.CONTROL) return false;
    }

    return true;
  }

  /**
   * Checks that Unicode formatting marks are well-formed and not nested improperly.
   *
   * <p>Validates that directional formatting embeddings/overrides are balanced (increments for
   * {@code U+202A} LRE, {@code U+202B} RLE, {@code U+202D} LRO, {@code U+202E} RLO and decrements
   * for {@code U+202C} PDF) and that Interlinear Annotation characters form a valid sequence
   * without nesting ({@code U+FFF9} anchor → {@code U+FFFA} separator → {@code U+FFFB} terminator).
   * Isolates (LRI/RLI/FSI/PDI) are not handled by this method.
   *
   * @param text string to check
   * @return {@code true} if all applicable formatting controls are balanced and properly ordered
   * @throws NullPointerException if {@code text} is {@code null}
   */
  public static boolean containsNoInvalidFormatting(String text) {
    FormattingState state = new FormattingState();
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (!applyFormattingChar(state, c)) return false;
    }

    return state.isValidAtEnd();
  }

  private static int bidiDelta(char c) {
    return switch (c) {
      case 0x202A, // LEFT-TO-RIGHT EMBEDDING
          0x202B, // RIGHT-TO-LEFT EMBEDDING
          0x202D, // LEFT-TO-RIGHT OVERRIDE
          0x202E // RIGHT-TO-LEFT OVERRIDE
          ->
          1;
      case 0x202C -> -1; // POP DIRECTIONAL FORMATTING
      default -> 0;
    };
  }

  // Interlinear Annotation helpers are handled inside applyAnnotation().

  private static boolean applyFormattingChar(FormattingState s, char c) {
    int delta = bidiDelta(c);
    if (delta != 0) {
      return applyBidiDelta(s, delta);
    }
    return applyAnnotation(s, c);
  }

  private static boolean applyBidiDelta(FormattingState s, int delta) {
    s.dirCount += delta;
    // Invariant: directional depth must never go negative; PDF without a matching opener fails.
    return s.dirCount >= 0;
  }

  private static boolean applyAnnotation(FormattingState s, char c) {
    return switch (c) {
      case 0xFFF9 -> { // INTERLINEAR ANNOTATION ANCHOR
        if (s.inAnnotatedText || s.inAnnotation) {
          yield false;
        }
        s.inAnnotatedText = true;
        yield true;
      }
      case 0xFFFA -> { // INTERLINEAR ANNOTATION SEPARATOR
        if (!s.inAnnotatedText) {
          yield false;
        }
        s.inAnnotatedText = false;
        s.inAnnotation = true;
        yield true;
      }
      case 0xFFFB -> { // INTERLINEAR ANNOTATION TERMINATOR
        if (!s.inAnnotation) {
          yield false;
        }
        s.inAnnotation = false;
        yield true;
      }
      default -> true;
    };
  }

  private static final class FormattingState {
    int dirCount;
    boolean inAnnotatedText;
    boolean inAnnotation;

    boolean isValidAtEnd() {
      // All formatting must be fully closed by the end of the string.
      return dirCount == 0 && !inAnnotatedText && !inAnnotation;
    }
  }

  /**
   * Checks that a string contains only ASCII Latin letters and digits.
   *
   * @param text string to check
   * @return {@code true} if every character is in {@code 'A'..'Z'}, {@code 'a'..'z'}, or {@code
   *     '0'..'9'}
   * @throws NullPointerException if {@code text} is {@code null}
   */
  public static boolean isLatinLettersAndNumbersOnly(String text) {
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9')) {
        return false;
      }
    }

    return true;
  }
}
