package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100") // test method naming style: method_whenCondition_expectOutcome
class ElementInfoTest {

  // isSpecificFontFamily / isSpecificVoiceFamily
  @ParameterizedTest
  @ValueSource(strings = {"Arial-Black_1.+,~", "simple", "", "A_b-1.2 +~"})
  void isSpecificFontFamily_whenAllowedCharacters_expectTrue(String font) {
    // Act & Assert
    assertTrue(ElementInfo.isSpecificFontFamily(font));
  }

  @Test
  void isSpecificFontFamily_whenContainsInvalidChars_expectFalse() {
    assertFalse(ElementInfo.isSpecificFontFamily("Arial/Black"));
    assertFalse(ElementInfo.isSpecificFontFamily("name;drop"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"male voice", "child", "Voice_1,+-.~", ""})
  void isSpecificVoiceFamily_whenAllowedCharacters_expectTrue(String voice) {
    assertTrue(ElementInfo.isSpecificVoiceFamily(voice));
  }

  @Test
  void isSpecificVoiceFamily_whenContainsInvalidChars_expectFalse() {
    assertFalse(ElementInfo.isSpecificVoiceFamily("voice/with/slash"));
  }

  // Generic families must be lower-case
  @ParameterizedTest
  @ValueSource(strings = {"serif", "sans-serif", "monospace", "emoji", "system-ui"})
  void isGenericFontFamily_whenKnownKeywords_expectTrue(String keyword) {
    assertTrue(ElementInfo.isGenericFontFamily(keyword));
  }

  @Test
  void isGenericFontFamily_whenUppercase_expectFalse() {
    assertFalse(ElementInfo.isGenericFontFamily("Serif"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"male", "female", "child"})
  void isGenericVoiceFamily_whenKnownKeywords_expectTrue(String keyword) {
    assertTrue(ElementInfo.isGenericVoiceFamily(keyword));
  }

  // Font family prefix/match lookup
  @Test
  void isWordPrefixOrMatchOfSpecificFontFamily_whenExactOrWordPrefix_expectExpected() {
    assertTrue(ElementInfo.isWordPrefixOrMatchOfSpecificFontFamily("arial")); // exact
    assertTrue(
        ElementInfo.isWordPrefixOrMatchOfSpecificFontFamily("lucida")); // prefix of "lucida ..."
    assertFalse(
        ElementInfo.isWordPrefixOrMatchOfSpecificFontFamily("luc")); // no space-delimited prefix
    assertFalse(ElementInfo.isWordPrefixOrMatchOfSpecificFontFamily("nonexistent"));
  }

  // Void elements
  @Test
  void isVoidElement_whenLowercaseVoid_expectTrue() {
    assertTrue(ElementInfo.isVoidElement("br"));
  }

  @Test
  void isVoidElement_whenUppercaseVoid_expectFalse() {
    assertFalse(ElementInfo.isVoidElement("BR")); // case-sensitive set
  }

  // Auto-close
  @Test
  void tryAutoClose_whenLi_expectTrue() {
    assertTrue(ElementInfo.tryAutoClose("li"));
  }

  @Test
  void tryAutoClose_whenOtherTag_expectFalse() {
    assertFalse(ElementInfo.tryAutoClose("div"));
  }

  // HTML tag validity (case-insensitive via toLowerCase())
  @Test
  void isValidHTMLTag_whenAllowedVoidUppercase_expectTrue() {
    assertTrue(ElementInfo.isValidHTMLTag("BR"));
  }

  @Test
  void isValidHTMLTag_whenUnknown_expectFalse() {
    assertFalse(ElementInfo.isValidHTMLTag("madeup"));
  }

  // HTML name validity
  @ParameterizedTest
  @ValueSource(strings = {"a", "a0", "a_b", "A:Z", "A-Z", "Name.12"})
  void isValidName_whenValidExamples_expectTrue(String name) {
    assertTrue(ElementInfo.isValidName(name));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "1abc", "-name", "name/", "a b"})
  void isValidName_whenInvalidExamples_expectFalse(String name) {
    assertFalse(ElementInfo.isValidName(name));
  }

  // CSS identifier validity
  @ParameterizedTest
  @ValueSource(strings = {"abc", "-a", "_a", "a1", "a-b_c", "éabc", "foo\\ bar"})
  void isValidIdentifier_whenValidExamples_expectTrue(String ident) {
    assertTrue(ElementInfo.isValidIdentifier(ident));
  }

  @Test
  void isValidIdentifier_whenEscapedNewline_expectTrue() {
    assertTrue(ElementInfo.isValidIdentifier("foo\\\nbar"));
    assertTrue(ElementInfo.isValidIdentifier("foo\\\r\nbar"));
    assertTrue(ElementInfo.isValidIdentifier("foo\\\fbar"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"1abc", "abc\n", "abc\r", "abc\f", "abc\\"})
  void isValidIdentifier_whenInvalidExamples_expectFalse(String ident) {
    assertFalse(ElementInfo.isValidIdentifier(ident));
  }

  // Pseudo-classes: banned detection
  @Test
  void isBannedPseudoClass_whenChainIncludesBanned_expectTrue() {
    assertTrue(ElementInfo.isBannedPseudoClass("hover:visited"));
    assertTrue(ElementInfo.isBannedPseudoClass("defined"));
  }

  @Test
  void isBannedPseudoClass_whenNoBanned_expectFalse() {
    assertFalse(ElementInfo.isBannedPseudoClass("hover"));
  }

  // Pseudo-classes: validity
  @Test
  void isValidPseudoClass_whenKnownCaseInsensitive_expectTrue() {
    assertTrue(ElementInfo.isValidPseudoClass("LINK"));
    assertTrue(ElementInfo.isValidPseudoClass("hover"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"lang(en)", "lang(\"en-US\")", "lang(en-US)"})
  void isValidPseudoClass_whenLangArgValid_expectTrue(String pc) {
    assertTrue(ElementInfo.isValidPseudoClass(pc));
  }

  @ParameterizedTest
  @ValueSource(strings = {"lang()", "lang(en,us)", "lang(../../)"})
  void isValidPseudoClass_whenLangArgInvalid_expectFalse(String pc) {
    assertFalse(ElementInfo.isValidPseudoClass(pc));
  }

  @Test
  void isValidPseudoClass_whenNthChildForms_expectTrue() {
    assertTrue(ElementInfo.isValidPseudoClass("nth-child(2n+1)"));
    assertTrue(ElementInfo.isValidPseudoClass("nth-last-child(even)"));
    assertTrue(ElementInfo.isValidPseudoClass("nth-of-type(3)"));
    assertTrue(ElementInfo.isValidPseudoClass("nth-last-of-type(-2n+4)"));
  }

  @Test
  void isValidPseudoClass_whenDirKeyword_expectTrue() {
    assertTrue(ElementInfo.isValidPseudoClass("dir(ltr)"));
    assertTrue(ElementInfo.isValidPseudoClass("dir(RTL)"));
  }

  // getPseudoClassArg
  @ParameterizedTest
  @CsvSource({"lang(\"en-US\"),lang,en-US", "lang(en),lang,en", "dir(ltr),dir,ltr"})
  void getPseudoClassArg_whenValidFormat_returnsArgument(
      String cname, String nameSansArg, String expected) {
    assertEquals(expected, ElementInfo.getPseudoClassArg(cname, nameSansArg));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "lang(en) extra|lang",
        " notlang(en) |lang",
        "lang(en|lang",
        "lang en)|lang",
        ":lang(en)|lang"
      },
      delimiter = '|')
  void getPseudoClassArg_whenInvalidFormat_returnsEmpty(String cname, String nameSansArg) {
    assertEquals("", ElementInfo.getPseudoClassArg(cname, nameSansArg));
  }

  // String validation (decoded/original)
  @Test
  void isValidString_whenUnescapedQuote_expectFalse() {
    assertFalse(ElementInfo.isValidString("it's bad"));
  }

  @Test
  void isValidString_whenUnescapedNewline_expectFalse() {
    assertFalse(ElementInfo.isValidString("hello\nworld"));
  }

  @Test
  void isValidString_whenEscapedNewline_expectTrue() {
    assertTrue(ElementInfo.isValidString("hello\\\nworld"));
  }

  @Test
  void isValidString_whenTrailingBackslash_expectFalse() {
    assertFalse(ElementInfo.isValidString("abc\\"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"'hello world'", "\"hello world\""})
  void isValidStringWithQuotes_whenProperQuotes_expectTrue(String s) {
    assertTrue(ElementInfo.isValidStringWithQuotes(s));
  }

  @Test
  void isValidStringWithQuotes_whenMismatchedQuotes_expectFalse() {
    assertFalse(ElementInfo.isValidStringWithQuotes("'hello\""));
  }

  @Test
  void isValidStringWithQuotes_whenInnerEscapedQuote_expectTrue() {
    assertTrue(ElementInfo.isValidStringWithQuotes("\"hel\\\"lo\""));
  }
}
