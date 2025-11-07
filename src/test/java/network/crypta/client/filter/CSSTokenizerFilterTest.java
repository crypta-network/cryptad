package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CSSTokenizerFilterTest {

  @Mock private FilterCallback callback;

  // ----------------------- removeOuterQuotes -----------------------

  @Test
  void removeOuterQuotes_whenQuotedSingle_expectInnerReturned() {
    String out = CSSTokenizerFilter.removeOuterQuotes("'abc'");
    assertEquals("abc", out);
  }

  @Test
  void removeOuterQuotes_whenQuotedDouble_expectInnerReturned() {
    String out = CSSTokenizerFilter.removeOuterQuotes("\"xyz\"");
    assertEquals("xyz", out);
  }

  @Test
  void removeOuterQuotes_whenUnquotedOrMismatched_expectOriginal() {
    assertEquals("abc", CSSTokenizerFilter.removeOuterQuotes("abc"));
    assertEquals("'abc", CSSTokenizerFilter.removeOuterQuotes("'abc"));
    assertEquals("a\"b", CSSTokenizerFilter.removeOuterQuotes("a\"b"));
  }

  // --------------------- HTMLelementVerifier ----------------------

  @Test
  void htmlElementVerifier_whenSimpleElement_expectSame() {
    String out = CSSTokenizerFilter.htmlElementVerifier("div", false);
    assertEquals("div", out);
  }

  @Test
  void htmlElementVerifier_whenClassOnly_expectSame() {
    String out = CSSTokenizerFilter.htmlElementVerifier(".item", false);
    assertEquals(".item", out);
  }

  @Test
  void htmlElementVerifier_whenIdSelectorOnly_expectSame() {
    String out = CSSTokenizerFilter.htmlElementVerifier("#logo", true);
    assertEquals("#logo", out);
  }

  @Test
  void htmlElementVerifier_whenElementAndId_withIdSelector_expectSame() {
    String out = CSSTokenizerFilter.htmlElementVerifier("div#logo", true);
    assertEquals("div#logo", out);
  }

  @Test
  void htmlElementVerifier_whenClassWithIdSelector_expectNull() {
    String out = CSSTokenizerFilter.htmlElementVerifier("div.main", true);
    assertNull(out);
  }

  @Test
  void htmlElementVerifier_whenInvalidElement_expectNull() {
    String out = CSSTokenizerFilter.htmlElementVerifier("nonexistenttag", false);
    assertNull(out);
  }

  @Test
  void htmlElementVerifier_whenBannedPseudoClass_expectEmptyString() {
    String out = CSSTokenizerFilter.htmlElementVerifier("a:visited", false);
    assertNotNull(out);
    assertEquals("", out);
  }

  @Test
  void htmlElementVerifier_whenAttributeSelection_expectRoundTrip() {
    String out = CSSTokenizerFilter.htmlElementVerifier("a[href=\"x\"]", false);
    assertEquals("a[href=\"x\"]", out);
  }

  // ----------------- recursiveSelectorVerifier --------------------

  @Test
  void recursiveSelectorVerifier_whenValidCombinator_expectConcatenated() {
    CSSTokenizerFilter f = new CSSTokenizerFilter();
    // Note: spaces around '>' are collapsed in the returned string
    String out = f.recursiveSelectorVerifier("div > .class");
    assertEquals("div>.class", out);
  }

  @Test
  void recursiveSelectorVerifier_whenMismatchedQuote_expectNull() {
    CSSTokenizerFilter f = new CSSTokenizerFilter();
    String out = f.recursiveSelectorVerifier("div[attr='x]");
    assertNull(out);
  }

  @Test
  void recursiveSelectorVerifier_whenUnquotedNewline_expectNull() {
    CSSTokenizerFilter f = new CSSTokenizerFilter();
    String out = f.recursiveSelectorVerifier("div\nspan");
    assertNull(out);
  }

  // ------------------------------ parse ---------------------------

  @Test
  void parse_whenCharsetSupported_setsDetectedAndWritesIt() throws Exception {
    String css = "@charset \"UTF-8\"; body { color: red; }";
    Reader r = new StringReader(css);
    StringWriter w = new StringWriter();
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(r, w, new NullFilterCallback(), "UTF-8", false, false);

    f.parse();

    assertEquals("UTF-8", f.detectedCharset());
    String out = w.toString();
    assertTrue(out.contains("@charset \"UTF-8\";"));
  }

  @Test
  void parse_whenStopAtDetectedCharset_true_doesNotWriteOutput() throws Exception {
    String css = "@charset \"UTF-8\"; body { color: red; }";
    Reader r = new StringReader(css);
    StringWriter w = new StringWriter();
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(r, w, new NullFilterCallback(), "UTF-8", true, false);

    f.parse();

    assertEquals("UTF-8", f.detectedCharset());
    assertEquals("", w.toString());
  }

  @Test
  void parse_whenCharsetMismatch_expectIOException() {
    String css = "@charset \"UTF-8\";";
    Reader r = new StringReader(css);
    Writer w = new StringWriter();
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(r, w, new NullFilterCallback(), "ISO-8859-1", false, false);

    assertThrows(IOException.class, f::parse);
  }

  @Test
  void parse_whenUnsupportedCharset_expectUnsupportedCharsetInFilterException() {
    String css = "@charset \"UTF-32-2143\"; body{color:black;}"; // charset known to be unsupported
    Reader r = new StringReader(css);
    Writer w = new StringWriter();
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(r, w, new NullFilterCallback(), "UTF-8", false, false);

    assertThrows(UnsupportedCharsetInFilterException.class, f::parse);
  }

  // --------------------------- isValidURI -------------------------

  @Test
  void isValidURI_whenCallbackReturnsSame_expectTrue() throws Exception {
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(
            new StringReader(""), new StringWriter(), callback, "UTF-8", false, false);
    when(callback.processURI("http://example.com", null)).thenReturn("http://example.com");
    assertTrue(f.isValidURI("http://example.com"));
  }

  @Test
  void isValidURI_whenCallbackReturnsDifferent_expectFalse() throws Exception {
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(
            new StringReader(""), new StringWriter(), callback, "UTF-8", false, false);
    when(callback.processURI("http://example.com", null))
        .thenReturn("http://safe.example/rewritten");
    assertFalse(f.isValidURI("http://example.com"));
  }

  @Test
  void isValidURI_whenCallbackThrows_expectFalse() throws Exception {
    CSSTokenizerFilter f =
        new CSSTokenizerFilter(
            new StringReader(""), new StringWriter(), callback, "UTF-8", false, false);
    when(callback.processURI("http://bad/uri", null)).thenThrow(new CommentException("bad"));
    assertFalse(f.isValidURI("http://bad/uri"));
  }

  // --------------- CSSPropertyVerifier simple helpers -------------

  @Test
  void isIntegerChecker_whenValidAndInvalid_expectCorrect() {
    assertTrue(CSSTokenizerFilter.CSSPropertyVerifier.isIntegerChecker("0"));
    assertTrue(CSSTokenizerFilter.CSSPropertyVerifier.isIntegerChecker("42"));
    assertFalse(CSSTokenizerFilter.CSSPropertyVerifier.isIntegerChecker("3.14"));
    assertFalse(CSSTokenizerFilter.CSSPropertyVerifier.isIntegerChecker("abc"));
  }

  @Test
  void isRealChecker_whenValidAndInvalid_expectCorrect() {
    assertTrue(CSSTokenizerFilter.CSSPropertyVerifier.isRealChecker("0"));
    assertTrue(CSSTokenizerFilter.CSSPropertyVerifier.isRealChecker("3.14"));
    assertFalse(CSSTokenizerFilter.CSSPropertyVerifier.isRealChecker("abc"));
  }

  @Test
  void CSSPropertyVerifier_isValidURI_whenCallbackBehaves_expectOutcomes() throws Exception {
    // Arrange a ParsedURL token
    CSSTokenizerFilter.ParsedURL url =
        new CSSTokenizerFilter.ParsedURL(
            "url(\"http://example.org\")", "http://example.org", false, '"');

    // Same value returned -> true
    when(callback.processURI("http://example.org", null)).thenReturn("http://example.org");
    assertTrue(CSSTokenizerFilter.CSSPropertyVerifier.isValidURI(url, callback));

    // Different sanitized value -> true and word updated
    url =
        new CSSTokenizerFilter.ParsedURL(
            "url(\"http://example.org\")", "http://example.org", false, '"');
    when(callback.processURI("http://example.org", null)).thenReturn("http://safe/rewritten");
    assertTrue(CSSTokenizerFilter.CSSPropertyVerifier.isValidURI(url, callback));

    // Callback returns null -> false
    url =
        new CSSTokenizerFilter.ParsedURL(
            "url(\"http://example.org\")", "http://example.org", false, '"');
    when(callback.processURI("http://example.org", null)).thenReturn(null);
    assertFalse(CSSTokenizerFilter.CSSPropertyVerifier.isValidURI(url, callback));

    // Callback throws -> false
    url =
        new CSSTokenizerFilter.ParsedURL(
            "url(\"http://example.org\")", "http://example.org", false, '"');
    when(callback.processURI("http://example.org", null))
        .thenThrow(new CommentException("invalid uri"));
    assertFalse(CSSTokenizerFilter.CSSPropertyVerifier.isValidURI(url, callback));
  }
}
