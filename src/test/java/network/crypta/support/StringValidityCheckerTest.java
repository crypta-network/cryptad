package network.crypta.support;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S5778"})
class StringValidityCheckerTest {

  // ---------------------------
  // Windows printable characters
  // ---------------------------

  static Stream<Character> windowsReservedPrintableChars() {
    return Stream.of('/', '\\', '?', '*', ':', '|', '"', '<', '>');
  }

  @ParameterizedTest
  @MethodSource("windowsReservedPrintableChars")
  void isWindowsReservedPrintableFilenameCharacter_whenReservedChars_expectTrue(char c) {
    // Act & Assert
    assertTrue(StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c));
  }

  @ParameterizedTest
  @CsvSource({"a", "_", "-", "0", "Z"})
  void isWindowsReservedPrintableFilenameCharacter_whenSafeChars_expectFalse(char c) {
    assertFalse(StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c));
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void isWindowsReservedPrintableFilenameCharacter_whenNull_expectFalse() {
    // Arrange
    Character c = null;
    // Act & Assert
    assertFalse(StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c));
  }

  // ---------------------------
  // macOS printable characters
  // ---------------------------

  @ParameterizedTest
  @CsvSource({":", "/"})
  void isMacOSReservedPrintableFilenameCharacter_whenColonOrSlash_expectTrue(char c) {
    assertTrue(StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c));
  }

  @ParameterizedTest
  @CsvSource({"a", "_", "-", "0", "Z"})
  void isMacOSReservedPrintableFilenameCharacter_whenSafeChars_expectFalse(char c) {
    assertFalse(StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c));
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void isMacOSReservedPrintableFilenameCharacter_whenNull_expectFalse() {
    Character c = null;
    assertFalse(StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c));
  }

  // ---------------------------
  // Unix printable characters
  // ---------------------------

  @Test
  void isUnixReservedPrintableFilenameCharacter_whenSlash_expectTrue() {
    assertTrue(StringValidityChecker.isUnixReservedPrintableFilenameCharacter('/'));
  }

  @ParameterizedTest
  @CsvSource({"a", "_", "-", "0", "Z", "\\"})
  void isUnixReservedPrintableFilenameCharacter_whenOtherChars_expectFalse(char c) {
    assertFalse(StringValidityChecker.isUnixReservedPrintableFilenameCharacter(c));
  }

  // ---------------------------
  // Windows reserved filenames
  // ---------------------------

  static Stream<String> windowsReservedNamesTrue() {
    return Stream.of(
        "con",
        "CON",
        "con.txt",
        "Con.blah.txt",
        "lpt1",
        "LPT9",
        "com1",
        "COM9",
        "nul",
        "NUL",
        "prn",
        "clock$");
  }

  static Stream<String> windowsReservedNamesFalse() {
    return Stream.of("conx", "com10", ".con", "somefile", "lpt0", "auxiliary", "file.con");
  }

  @ParameterizedTest
  @MethodSource("windowsReservedNamesTrue")
  void isWindowsReservedFilename_whenReservedPatterns_expectTrue(String name) {
    assertTrue(StringValidityChecker.isWindowsReservedFilename(name));
  }

  @ParameterizedTest
  @MethodSource("windowsReservedNamesFalse")
  void isWindowsReservedFilename_whenNotReserved_expectFalse(String name) {
    assertFalse(StringValidityChecker.isWindowsReservedFilename(name));
  }

  @Test
  void isWindowsReservedFilename_whenNull_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
              StringValidityChecker.isWindowsReservedFilename(null));
        });
  }

  // ---------------------------
  // IDN blacklist
  // ---------------------------

  static Stream<Arguments> idnBlacklistedSamples() {
    return Stream.of(
        Arguments.of("a\u200Bz"), // ZERO WIDTH SPACE
        Arguments.of("x。y"), // IDEOGRAPHIC FULL STOP
        Arguments.of("p／q"), // FULLWIDTH SOLIDUS
        Arguments.of("m｡n") // HALFWIDTH IDEOGRAPHIC FULL STOP
        );
  }

  @Test
  void containsNoIDNBlacklistCharacters_whenNoBlacklisted_expectTrue() {
    assertTrue(StringValidityChecker.containsNoIDNBlacklistCharacters("Hello-World_123"));
    assertTrue(StringValidityChecker.containsNoIDNBlacklistCharacters(""));
  }

  @ParameterizedTest
  @MethodSource("idnBlacklistedSamples")
  void containsNoIDNBlacklistCharacters_whenBlacklistedPresent_expectFalse(String text) {
    assertFalse(StringValidityChecker.containsNoIDNBlacklistCharacters(text));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void containsNoIDNBlacklistCharacters_whenNull_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
              StringValidityChecker.containsNoIDNBlacklistCharacters(null));
        });
  }

  // ---------------------------
  // Linebreak detection
  // ---------------------------

  @Test
  void containsNoLinebreaks_whenPlainOrEmpty_expectTrue() {
    assertTrue(StringValidityChecker.containsNoLinebreaks("plain text"));
    assertTrue(StringValidityChecker.containsNoLinebreaks(""));
  }

  static Stream<String> linebreakSamples() {
    return Stream.of("line1\nline2", "carriage\rreturn", "A\u2028B", "C\u2029D");
  }

  @ParameterizedTest
  @MethodSource("linebreakSamples")
  void containsNoLinebreaks_whenLinebreakPresent_expectFalse(String text) {
    assertFalse(StringValidityChecker.containsNoLinebreaks(text));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void containsNoLinebreaks_whenNull_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
              StringValidityChecker.containsNoLinebreaks(null));
        });
  }

  // ---------------------------
  // Invalid Unicode code points
  // ---------------------------

  @Test
  void containsNoInvalidCharacters_whenEmojiAndAscii_expectTrue() {
    String emoji = new String(Character.toChars(0x1F600)); // GRINNING FACE
    assertTrue(StringValidityChecker.containsNoInvalidCharacters("Hi " + emoji + "!"));
    assertTrue(StringValidityChecker.containsNoInvalidCharacters(""));
  }

  static Stream<String> invalidCodePointSamples() {
    return Stream.of("bad\uFFFF", "bad\uFFFE", "bad\uD800");
  }

  @ParameterizedTest
  @MethodSource("invalidCodePointSamples")
  void containsNoInvalidCharacters_whenNonCharactersOrUnpairedSurrogate_expectFalse(String text) {
    assertFalse(StringValidityChecker.containsNoInvalidCharacters(text));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void containsNoInvalidCharacters_whenNull_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
              StringValidityChecker.containsNoInvalidCharacters(null));
        });
  }

  // ---------------------------
  // Control character detection
  // ---------------------------

  @Test
  void containsNoControlCharacters_whenPrintableOnly_expectTrue() {
    assertTrue(StringValidityChecker.containsNoControlCharacters("Printable 123 ABC xyz"));
    assertTrue(StringValidityChecker.containsNoControlCharacters(""));
  }

  static Stream<String> controlCharSamples() {
    return Stream.of("has\tTab", "has\nNewline", "bell\u0007");
  }

  @ParameterizedTest
  @MethodSource("controlCharSamples")
  void containsNoControlCharacters_whenControlPresent_expectFalse(String text) {
    assertFalse(StringValidityChecker.containsNoControlCharacters(text));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void containsNoControlCharacters_whenNull_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
              StringValidityChecker.containsNoControlCharacters(null));
        });
  }

  // ---------------------------
  // Formatting (directional/annotation) validation
  // ---------------------------

  @Test
  void containsNoInvalidFormatting_whenBalancedDirectional_expectTrue() {
    String s = "abc\u202Adef\u202Cghi"; // LRE ... PDF
    assertTrue(StringValidityChecker.containsNoInvalidFormatting(s));
  }

  @Test
  void containsNoInvalidFormatting_whenUnbalancedDirectionalMissingPop_expectFalse() {
    String s = "start\u202Aembedded"; // Missing POP (PDF)
    assertFalse(StringValidityChecker.containsNoInvalidFormatting(s));
  }

  @Test
  void containsNoInvalidFormatting_whenUnbalancedDirectionalExtraPop_expectFalse() {
    String s = "\u202Cpop-first"; // POP without a push
    assertFalse(StringValidityChecker.containsNoInvalidFormatting(s));
  }

  @Test
  void containsNoInvalidFormatting_whenValidAnnotationSequence_expectTrue() {
    String s = "\uFFF9base\uFFFAann\uFFFB"; // anchor, separator, terminator
    assertTrue(StringValidityChecker.containsNoInvalidFormatting(s));
  }

  static Stream<String> invalidAnnotationSamples() {
    return Stream.of(
        "\uFFF9a\uFFF9b", // nested anchor
        "\uFFFB", // terminator without annotation
        "\uFFF9a\uFFFAann" // missing terminator
        );
  }

  @ParameterizedTest
  @MethodSource("invalidAnnotationSamples")
  void containsNoInvalidFormatting_whenInvalidAnnotationOrderOrNesting_expectFalse(String text) {
    assertFalse(StringValidityChecker.containsNoInvalidFormatting(text));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void containsNoInvalidFormatting_whenNull_expectNPE() {
    assertThrows(
        NullPointerException.class, () -> StringValidityChecker.containsNoInvalidFormatting(null));
  }

  // ---------------------------
  // isLatinLettersAndNumbersOnly
  // ---------------------------

  @Test
  void isLatinLettersAndNumbersOnly_whenOnlyLettersNumbers_expectTrue() {
    assertTrue(StringValidityChecker.isLatinLettersAndNumbersOnly("abcXYZ123"));
    assertTrue(StringValidityChecker.isLatinLettersAndNumbersOnly(""));
  }

  static Stream<Arguments> notLatinLettersAndNumbers() {
    return Stream.of(
        Arguments.of("has space", false),
        Arguments.of("under_score", false),
        Arguments.of("dash-", false),
        Arguments.of("accenté", false),
        Arguments.of("symbols$", false));
  }

  @ParameterizedTest
  @MethodSource("notLatinLettersAndNumbers")
  @DisplayName("isLatinLettersAndNumbersOnly rejects non [a-zA-Z0-9] characters")
  void isLatinLettersAndNumbersOnly_whenContainsOtherChars_expectFalse(
      String text, boolean expected) {
    assertEquals(expected, StringValidityChecker.isLatinLettersAndNumbersOnly(text));
  }
}
