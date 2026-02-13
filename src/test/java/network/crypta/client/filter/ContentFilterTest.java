package network.crypta.client.filter;

import static network.crypta.l10n.BaseL10n.LANGUAGE.ENGLISH;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.clients.http.ExternalLinkToadlet;
import network.crypta.l10n.L10nTestUtils;
import network.crypta.support.Logging;
import network.crypta.support.TestProperty;
import network.crypta.support.io.ArrayBucket;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.event.Level;

/**
 * A simple meta-test to track regressions of the content-filter
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ContentFilterTest {
  static {
    GenericReadFilterCallback.setBaseL10n(L10nTestUtils.createTestL10n(ENGLISH));
  }

  private static final String HTML_OPEN = "<html>";
  private static final String HTML_CLOSE = "</html>";
  private static final String HEAD_OPEN = "<head>";
  private static final String HEAD_CLOSE = "</head>";
  private static final String TEXT_HTML = "text/html";
  private static final String DIV_BLOCK = "div { }";
  private static final String A_HREF_PREFIX = "<a href=\"";
  private static final String CSS_STYLE_SUFFIX = ") }</style>";
  private static final String WINDOWS_1252 = "windows-1252";

  public static String htmlFilter(String data)
      throws java.io.IOException, java.net.URISyntaxException {
    if (data.startsWith("<html")) {
      return htmlFilter(data, false);
    }
    if (data.startsWith("<?")) {
      return htmlFilter(data, false);
    }
    String s = htmlFilter(HTML_OPEN + data + HTML_CLOSE, false);
    assertTrue(s.startsWith(HTML_OPEN));
    s = s.substring(HTML_OPEN.length());
    assertTrue(s.endsWith(HTML_CLOSE), "s = \"" + s + "\"");
    s = s.substring(0, s.length() - HTML_CLOSE.length());
    return s;
  }

  public static String htmlFilter(String data, boolean alt)
      throws java.io.IOException, java.net.URISyntaxException {
    //noinspection UnnecessaryLocalVariable
    String typeName = TEXT_HTML;
    URI baseURI = new URI(alt ? ALT_BASE_URI : BASE_URI);
    byte[] dataToFilter = data.getBytes(StandardCharsets.UTF_8);
    try (AutoFreeArrayBucket input = new AutoFreeArrayBucket(dataToFilter);
        AutoFreeArrayBucket output = new AutoFreeArrayBucket()) {
      try (OutputStream outputStream = output.getOutputStream();
          InputStream inputStream = input.getInputStream()) {
        ContentFilterRequest request =
            new ContentFilterRequest(inputStream, outputStream, typeName, null, null, null);
        ContentFilterCallbacks callbacks = new ContentFilterCallbacks(baseURI, null, null, null);
        ContentFilter.filter(request, callbacks);
      }
      return output.toString();
    }
  }

  @Test
  void htmlFilter_relativizationAndExternalLinks_expectSanitized() throws Exception {
    enableVerboseLoggingIfRequested();

    // Relativization
    testOneHTMLFilter(INTERNAL_RELATIVE_LINK);
    assertEquals(INTERNAL_RELATIVE_LINK, htmlFilter(INTERNAL_RELATIVE_LINK, true));
    assertEquals(INTERNAL_RELATIVE_LINK1, htmlFilter(INTERNAL_RELATIVE_LINK1, true));
    assertEquals(INTERNAL_RELATIVE_LINK, htmlFilter(INTERNAL_ABSOLUTE_LINK));

    // External links are stripped/redirected
    assertTrue(htmlFilter(EXTERNAL_LINK_CHECK1).startsWith(EXTERNAL_LINK_OK));
    assertTrue(htmlFilter(EXTERNAL_LINK_CHECK2).contains(ExternalLinkToadlet.EXTERNAL_LINK_PATH));
    assertTrue(htmlFilter(EXTERNAL_LINK_CHECK3).startsWith(EXTERNAL_LINK_OK));
  }

  @Test
  void htmlFilter_anchorEdgeCases_expectSanitized() throws Exception {
    enableVerboseLoggingIfRequested();

    // bug #710
    testOneHTMLFilter(ANCHOR_TEST);
    testOneHTMLFilter(ANCHOR_TEST_EMPTY);
    testOneHTMLFilter(ANCHOR_TEST_SPECIAL);
    assertEquals(ANCHOR_TEST_SPECIAL2_RESULT, htmlFilter(ANCHOR_TEST_SPECIAL2));
  }

  @Test
  void htmlFilter_anchorRelativeAndMixed_expectSanitized() throws Exception {
    enableVerboseLoggingIfRequested();

    // bug #2496
    testOneHTMLFilter(ANCHOR_RELATIVE1);
    testOneHTMLFilter(ANCHOR_RELATIVE2);
    testOneHTMLFilter(ANCHOR_FALSE_POS1);
    testOneHTMLFilter(ANCHOR_FALSE_POS2);

    // Mix of #2496 + #2451
    assertEquals(ANCHOR_MIXED_RESULT, htmlFilter(ANCHOR_MIXED));
  }

  @Test
  void htmlFilter_encodingAndAccessPrevention_expectPolicyApplied() throws Exception {
    enableVerboseLoggingIfRequested();

    // bug #2451
    assertEquals(POUNT_CHARACTER_ENCODING_TEST_RESULT, htmlFilter(POUNT_CHARACTER_ENCODING_TEST));
    // bug #2297
    assertTrue(htmlFilter(PREVENT_FPROXY_ACCESS).contains(ExternalLinkToadlet.EXTERNAL_LINK_PATH));
    // bug #2921
    assertTrue(htmlFilter(PREVENT_EXTERNAL_ACCESS_CSS_SIMPLE).contains(DIV_BLOCK));
    assertTrue(htmlFilter(PREVENT_EXTERNAL_ACCESS_CSS_ESCAPE).contains(DIV_BLOCK));
    assertTrue(htmlFilter(PREVENT_EXTERNAL_ACCESS_CSS_CASE).contains(DIV_BLOCK));
  }

  @Test
  void htmlFilter_whitelistAndXhtmlAndCssNewlines_expectPreserved() throws Exception {
    enableVerboseLoggingIfRequested();

    testOneHTMLFilter(WHITELIST_STATIC_CONTENT);
    assertEquals(XHTML_VOIDELEMENTC, htmlFilter(XHTML_VOIDELEMENT));
    assertEquals(XHTML_INCOMPLETEDOCUMENTC, htmlFilter(XHTML_INCOMPLETEDOCUMENT));
    assertEquals(XHTML_IMPROPERNESTINGC, htmlFilter(XHTML_IMPROPERNESTING));
    assertEquals(CSS_STRING_NEWLINESC, htmlFilter(CSS_STRING_NEWLINES));
  }

  @ParameterizedTest
  @MethodSource("stylesheetCharsetCases")
  void htmlFilter_stylesheetCharset_expectSanitized(String input, String expected, boolean alt)
      throws Exception {
    enableVerboseLoggingIfRequested();
    assertEquals(expected, htmlFilter(input, alt));
  }

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments>
      stylesheetCharsetCases() {
    return java.util.stream.Stream.of(
        org.junit.jupiter.params.provider.Arguments.of(
            HTML_STYLESHEET_MAYBECHARSET, HTML_STYLESHEET_MAYBECHARSETC, true),
        org.junit.jupiter.params.provider.Arguments.of(
            HTML_STYLESHEET_CHARSET, HTML_STYLESHEET_CHARSETC, true),
        org.junit.jupiter.params.provider.Arguments.of(
            HTML_STYLESHEET_CHARSET_BAD, HTML_STYLESHEET_CHARSET_BADC, true),
        org.junit.jupiter.params.provider.Arguments.of(
            HTML_STYLESHEET_CHARSET_BAD1, HTML_STYLESHEET_CHARSET_BAD1C, true),
        org.junit.jupiter.params.provider.Arguments.of(
            HTML_STYLESHEET_WITH_MEDIA, HTML_STYLESHEET_WITH_MEDIAC, true));
  }

  @ParameterizedTest
  @MethodSource("frameSrcCharsetCases")
  void htmlFilter_frameSrcCharset_expectSanitized(String input, String expected, boolean alt)
      throws Exception {
    enableVerboseLoggingIfRequested();
    String filtered = htmlFilter(input, alt);
    assertNotNull(filtered);
    MatcherAssert.assertThat(filtered, Matchers.startsWith("<frame"));
    assertEquals(expected, filtered);
  }

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments>
      frameSrcCharsetCases() {
    return java.util.stream.Stream.of(
        org.junit.jupiter.params.provider.Arguments.of(FRAME_SRC_CHARSET, FRAME_SRC_CHARSETC, true),
        org.junit.jupiter.params.provider.Arguments.of(
            FRAME_SRC_CHARSET_BAD, FRAME_SRC_CHARSET_BADC, true),
        org.junit.jupiter.params.provider.Arguments.of(
            FRAME_SRC_CHARSET_BAD1, FRAME_SRC_CHARSET_BAD1C, true));
  }

  @Test
  void htmlFilter_cssSpecAndHtml5Tags_expectPreserved() throws Exception {
    enableVerboseLoggingIfRequested();

    testOneHTMLFilter(CSS_SPEC_EXAMPLE1);
    testOneHTMLFilter(SPAN_WITH_STYLE);
    testOneHTMLFilter(HTML_METER_PROGRESS_TAG);
    testOneHTMLFilter(HTML5_TAGS);
    testOneHTMLFilter(HTML5_BDI_RUBY);
  }

  @Test
  void htmlFilter_baseHref_valid_expectPreserved() throws Exception {
    enableVerboseLoggingIfRequested();
    testOneHTMLFilter(BASE_HREF);
  }

  @ParameterizedTest
  @MethodSource("badBaseHrefCases")
  void htmlFilter_baseHref_invalid_expectDeleted(String input) throws Exception {
    enableVerboseLoggingIfRequested();
    assertEquals(DELETED_BASE_HREF, htmlFilter(input));
  }

  static java.util.stream.Stream<String> badBaseHrefCases() {
    return java.util.stream.Stream.of(
        BAD_BASE_HREF, BAD_BASE_HREF2, BAD_BASE_HREF3, BAD_BASE_HREF4, BAD_BASE_HREF5);
  }

  @Test
  void htmlFilter_whenMediaTagPresent_expectM3UPlayerScriptAdded() throws Exception {
    // Arrange
    for (String content : HTML_MEDIA_TAG_COMBINATIONS) {
      String expected =
          HTML_START_TO_BODY + content + HTMLFilter.loadM3uPlayerScriptTagContent() + HTML_BODY_END;
      String unparsed = HTML_START_TO_BODY + content + HTML_BODY_END;
      // Act
      String filtered = htmlFilter(unparsed);
      // Assert
      assertEquals(expected, filtered);
      // ensure that that’s a script tag
      String expectedStart = HTML_START_TO_BODY + content + "<script";
      MatcherAssert.assertThat(filtered, Matchers.startsWith(expectedStart));
    }
  }

  @ParameterizedTest
  @MethodSource("metaRefreshEnabledCases")
  void headFilter_whenMetaRefresh_policyEnabled(String input, String expected) throws Exception {
    setMetaRefreshPolicy(5, 30);
    assertEquals(expected, headFilter(input));
  }

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments>
      metaRefreshEnabledCases() {
    return java.util.stream.Stream.of(
        org.junit.jupiter.params.provider.Arguments.of(META_TIME_ONLY, META_TIME_ONLY),
        org.junit.jupiter.params.provider.Arguments.of(META_TIME_ONLY_WRONG_CASE, META_TIME_ONLY),
        org.junit.jupiter.params.provider.Arguments.of(META_TIME_ONLY_TOO_SHORT, META_TIME_ONLY),
        org.junit.jupiter.params.provider.Arguments.of(META_TIME_ONLY_NEGATIVE, ""),
        org.junit.jupiter.params.provider.Arguments.of(
            META_TIME_ONLY_BADNUM1, META_TIME_ONLY_BADNUM_OUT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_TIME_ONLY_BADNUM2, META_TIME_ONLY_BADNUM_OUT),
        org.junit.jupiter.params.provider.Arguments.of(META_VALID_REDIRECT, META_VALID_REDIRECT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_VALID_REDIRECT_NOSPACE, META_VALID_REDIRECT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_BOGUS_REDIRECT1, META_BOGUS_REDIRECT1_OUT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_BOGUS_REDIRECT2, META_BOGUS_REDIRECT1_OUT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_BOGUS_REDIRECT3, META_BOGUS_REDIRECT3_OUT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_BOGUS_REDIRECT4, META_BOGUS_REDIRECT4_OUT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_BOGUS_REDIRECT5, META_BOGUS_REDIRECT1_OUT),
        org.junit.jupiter.params.provider.Arguments.of(
            META_BOGUS_REDIRECT6, META_BOGUS_REDIRECT_NO_URL));
  }

  @ParameterizedTest
  @MethodSource("metaRefreshDisabledCases")
  void headFilter_whenMetaRefresh_policyDisabled(String input) throws Exception {
    setMetaRefreshPolicy(-1, -1);
    assertEquals("", headFilter(input));
  }

  static java.util.stream.Stream<String> metaRefreshDisabledCases() {
    return java.util.stream.Stream.of(
        META_TIME_ONLY,
        META_TIME_ONLY_WRONG_CASE,
        META_TIME_ONLY_TOO_SHORT,
        META_TIME_ONLY_NEGATIVE,
        META_TIME_ONLY_BADNUM1,
        META_TIME_ONLY_BADNUM2,
        META_VALID_REDIRECT,
        META_VALID_REDIRECT_NOSPACE,
        META_BOGUS_REDIRECT1,
        META_BOGUS_REDIRECT2,
        META_BOGUS_REDIRECT3,
        META_BOGUS_REDIRECT4,
        META_BOGUS_REDIRECT5,
        META_BOGUS_REDIRECT6);
  }

  private static void setMetaRefreshPolicy(int samePageMin, int redirectMin) {
    HTMLFilter.setMetaRefreshSamePageMinInterval(samePageMin);
    HTMLFilter.setMetaRefreshRedirectMinInterval(redirectMin);
  }

  @Test
  void htmlFilter_whenHtml5MetaCharset_expectPreserved() throws Exception {
    // Arrange
    //noinspection UnnecessaryLocalVariable
    String inputUpper = META_CHARSET;
    //noinspection UnnecessaryLocalVariable
    String inputLower = META_CHARSET_LOWER;
    // Act
    String filteredUpper = htmlFilter(inputUpper);
    String filteredLower = htmlFilter(inputLower);
    // Assert
    assertEquals(META_CHARSET, filteredUpper);
    assertEquals(META_CHARSET_LOWER_RES, filteredLower);
  }

  @Test
  void filter_whenUtf16BomPrependedToUtf8Html_expectRejected() throws IOException {
    // Arrange (This is why we need to disallow characters before <html> !!)
    String s = "<html><body><a href=\"http://www.google.com/\">Blah</a>";
    //noinspection UnnecessaryLocalVariable
    String end = HTML_BODY_END;
    String alt =
        "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; "
            + "charset=UTF-16\"></head><body><a href=\"http://www.freenetproject"
            + ".org/\">Blah</a></body></html>";
    // Ensure an even-length boundary before appending the closing HTML so the following
    // UTF-16 segment starts on a 2-byte boundary in the mixed stream.
    s += " ";
    s = s + end;
    byte[] buf = s.getBytes(StandardCharsets.UTF_8);
    byte[] utf16bom = new byte[] {(byte) 0xFE, (byte) 0xFF};
    byte[] bufUTF16 = alt.getBytes(StandardCharsets.UTF_16);
    byte[] total = new byte[buf.length + utf16bom.length + bufUTF16.length];
    System.arraycopy(utf16bom, 0, total, 0, utf16bom.length);
    System.arraycopy(buf, 0, total, utf16bom.length, buf.length);
    System.arraycopy(bufUTF16, 0, total, utf16bom.length + buf.length, bufUTF16.length);
    HTMLFilter filter = new HTMLFilter();
    List<RuntimeException> failures = new ArrayList<>();
    try (FileOutputStream fos = new FileOutputStream("output.utf16")) {
      // Act
      try (AutoFreeArrayBucket in = new AutoFreeArrayBucket(total);
          AutoFreeArrayBucket out = new AutoFreeArrayBucket()) {
        filter.readFilter(in.getInputStream(), out.getOutputStream(), "UTF-16", null, null, null);
        fos.write(out.toByteArray());
      }
      failures.add(
          new RuntimeException(
              "Filter accepted dangerous UTF8 text with BOM as UTF16! (HTMLFilter)"));
    } catch (DataFilterException _) {
      // Assert (expected rejection)
      // no logging needed in tests
    }
    try (FileOutputStream fos = new FileOutputStream("output.filtered")) {
      // Act
      FilterStatus fo;
      try (AutoFreeArrayBucket in = new AutoFreeArrayBucket(total);
          AutoFreeArrayBucket out = new AutoFreeArrayBucket()) {
        fo =
            ContentFilter.filter(
                new ContentFilterRequest(
                    in.getInputStream(), out.getOutputStream(), TEXT_HTML, null, null, null));
        fos.write(out.toByteArray());
      }
      failures.add(
          new RuntimeException(
              "Filter accepted dangerous UTF8 text with BOM as UTF16! (ContentFilter) - Detected "
                  + "charset: "
                  + (fo == null ? "<null>" : fo.charset)));
    } catch (DataFilterException _) {
      // Assert (expected rejection)
      // no logging needed in tests
    }

    // Assert: no failure conditions should have been recorded. On failure, dump input for
    // debugging and include the first failure message.
    assertTrue(
        failures.isEmpty(),
        () -> {
          try (FileOutputStream fos = new FileOutputStream("unfiltered")) {
            fos.write(total);
          } catch (IOException _) {
            // best-effort debug write; ignore secondary I/O errors
          }
          RuntimeException first = failures.getFirst();
          String msg = "Expected BOM-prefixed mixed-encoding input to be rejected by both filters";
          return first == null ? msg : msg + ": " + first.getMessage();
        });
  }

  @Test
  void registeredMimeTypes_whenChecked_expectLowerCaseExtensions() {
    // Arrange
    // Act & Assert
    for (FilterMIMEType type : ContentFilter.mimeTypesByName.values()) {
      String ext = type.primaryExtension;
      if (ext != null) {
        assertEquals(ext, ext.toLowerCase(Locale.ROOT));
      }
      String[] exts = type.alternateExtensions;
      if (ext != null) {
        for (String s : exts) {
          assertEquals(s, s.toLowerCase(Locale.ROOT));
        }
      }
    }
  }

  @Test
  void htmlFilter_whenAriaRolePresent_expectPreserved() throws Exception {
    // Arrange
    //noinspection UnnecessaryLocalVariable
    String input = ARIA_ROLE_TEST;
    // Act
    String filtered = htmlFilter(input);
    // Assert
    assertEquals(ARIA_ROLE_TEST, filtered);
  }

  private static void testOneHTMLFilter(String html) throws Exception {
    assertEquals(html, htmlFilter(html));
  }

  private static void enableVerboseLoggingIfRequested() {
    if (TestProperty.VERBOSE) {
      Logging.bootstrap(Level.DEBUG, "network.crypta.client.filter.Generic:TRACE");
    }
  }

  private String headFilter(String data) throws Exception {
    String s = htmlFilter(HEAD_OPEN + data + HEAD_CLOSE);
    MatcherAssert.assertThat(s, startsWith(HEAD_OPEN));
    MatcherAssert.assertThat(s, endsWith(HEAD_CLOSE));

    s = s.substring(HEAD_OPEN.length());
    s = s.substring(0, s.length() - HEAD_CLOSE.length());
    return s;
  }

  private static final String BASE_URI_PROTOCOL = "http";
  private static final String BASE_URI_CONTENT = "localhost:8888";
  private static final String BASE_KEY =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,"
          + "AQACAAE/Ultimate-Freenet-Index/55/";
  private static final String BASE_URI = BASE_URI_PROTOCOL + "://" + BASE_URI_CONTENT + '/';
  private static final String INTERNAL_ABSOLUTE_LINK =
      A_HREF_PREFIX + BASE_URI + "KSK@gpl.txt\" />";
  // @see bug #2297
  private static final String PREVENT_FPROXY_ACCESS = A_HREF_PREFIX + BASE_URI + "\"/>";
  // @see bug #2921
  private static final String PREVENT_EXTERNAL_ACCESS_CSS_SIMPLE =
      "<style>div { background: url(" + BASE_URI + CSS_STYLE_SUFFIX;
  private static final String PREVENT_EXTERNAL_ACCESS_CSS_CASE =
      "<style>div { background: uRl(" + BASE_URI + CSS_STYLE_SUFFIX;
  private static final String PREVENT_EXTERNAL_ACCESS_CSS_ESCAPE =
      "<style>div { background: \\u\\r\\l(" + BASE_URI + CSS_STYLE_SUFFIX;
  private static final String ALT_BASE_URI =
      BASE_URI_PROTOCOL + "://" + BASE_URI_CONTENT + '/' + BASE_KEY;
  // yes, this is valid too
  private static final String EXTERNAL_LINK = "www.evilwebsite.gov";
  private static final String EXTERNAL_LINK_OK = "<a />";
  // check that external links are not allowed
  private static final String EXTERNAL_LINK_CHECK1 = A_HREF_PREFIX + EXTERNAL_LINK + "\"/>";
  private static final String EXTERNAL_LINK_CHECK2 =
      A_HREF_PREFIX + BASE_URI_PROTOCOL + "://" + EXTERNAL_LINK + "\"/>";
  private static final String EXTERNAL_LINK_CHECK3 =
      A_HREF_PREFIX + BASE_URI_CONTENT + "@http://" + EXTERNAL_LINK + "\"/>";
  private static final String INTERNAL_RELATIVE_LINK = A_HREF_PREFIX + "/KSK@gpl.txt\" />";
  private static final String INTERNAL_RELATIVE_LINK1 = A_HREF_PREFIX + "test.html\" />";
  // @see bug #710
  private static final String ANCHOR_TEST = A_HREF_PREFIX + "#test\" />";
  private static final String ANCHOR_TEST_EMPTY = A_HREF_PREFIX + "#\" />";
  private static final String ANCHOR_TEST_SPECIAL =
      A_HREF_PREFIX + "#!$()*+,;=:@ABC0123-._~xyz%3f\" />";
  // RFC3986 / RFC 2396
  private static final String ANCHOR_TEST_SPECIAL2 =
      A_HREF_PREFIX + "#!$&'()*+,;=:@ABC0123-._~xyz%3f\" />";
  private static final String ANCHOR_TEST_SPECIAL2_RESULT =
      A_HREF_PREFIX + "#!$&amp;&#39;()*+,;=:@ABC0123-._~xyz%3f\" />";
  // @see bug #2496
  private static final String ANCHOR_RELATIVE1 = A_HREF_PREFIX + "/KSK@test/test.html#C2\">";
  private static final String ANCHOR_RELATIVE2 = A_HREF_PREFIX + "/KSK@test/path/test.html#C2\">";
  private static final String ANCHOR_FALSE_POS1 = A_HREF_PREFIX + "/KSK@test/path/test.html#%23\">";
  // yes, this is valid
  private static final String ANCHOR_FALSE_POS2 = A_HREF_PREFIX + "/KSK@test/path/%23.html#2\">";
  // evil hack for #2496 + #2451, <SPACE><#> give <SPACE><%23>
  private static final String ANCHOR_MIXED = A_HREF_PREFIX + "/KSK@test/path/music #1.ogg\">";
  private static final String ANCHOR_MIXED_RESULT =
      A_HREF_PREFIX + "/KSK@test/path/music%20%231.ogg\">";
  // @see bug #2451
  private static final String POUNT_CHARACTER_ENCODING_TEST =
      A_HREF_PREFIX
          + "/CHK@DUiGC5D1ZsnFpH07WGkNVDujNlxhtgGxXBKrMT-9Rkw,~GrAWp02o9YylpxL1Fr4fPDozWmebhGv4qUoFlrxnY4,AAIC--8/Testing"
          + " - [blah] Apostrophe' - gratuitous 1 AND CAPITAL LETTERS!!!!.ogg\" />";
  private static final String POUNT_CHARACTER_ENCODING_TEST_RESULT =
      A_HREF_PREFIX
          + "/CHK@DUiGC5D1ZsnFpH07WGkNVDujNlxhtgGxXBKrMT-9Rkw,"
          + "~GrAWp02o9YylpxL1Fr4fPDozWmebhGv4qUoFlrxnY4,"
          + "AAIC--8/Testing%20-%20%5bblah%5d%20Apostrophe%27%20-%20gratuitous%201%20AND%20CAPITAL"
          + "%20LETTERS%21%21%21%21.ogg\" />";
  private static final String WHITELIST_STATIC_CONTENT =
      A_HREF_PREFIX + "/static/themes/clean/theme.css\" />";
  private static final String XHTML_VOIDELEMENT =
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"><br><hr></html>";
  private static final String XHTML_VOIDELEMENTC =
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"><br /><hr /></html>";
  private static final String XHTML_INCOMPLETEDOCUMENT =
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body> <h1> helloworld <h2> helloworld";
  private static final String XHTML_INCOMPLETEDOCUMENTC =
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body> <h1> helloworld <h2> "
          + "helloworld</h2></h1></body></html>";
  private static final String XHTML_IMPROPERNESTING =
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"><b><i>helloworld</b></i></html>";
  private static final String XHTML_IMPROPERNESTINGC =
      "<html xmlns=\"http://www.w3.org/1999/xhtml\"><b><i>helloworld</i></b></html>";
  private static final String CSS_STRING_NEWLINES =
      """
      <style>* { content: "this string does not terminate
      }
      body {
      background: url(http://www\
      .google.co.uk/intl/en_uk/images/logo.gif); }
      " }</style>\
      """;
  private static final String CSS_STRING_NEWLINESC = "<style>* {}\nbody { }\n</style>";
  private static final String HTML_STYLESHEET_MAYBECHARSET =
      "<link rel=\"stylesheet\" href=\"test.css\">";
  private static final String HTML_STYLESHEET_MAYBECHARSETC =
      "<link rel=\"stylesheet\" href=\"test.css?type=text/css&amp;maybecharset=iso-8859-1\" "
          + "type=\"text/css\">";
  private static final String HTML_STYLESHEET_CHARSET =
      "<link rel=\"stylesheet\" charset=\"utf-8\" href=\"test.css\">";
  private static final String HTML_STYLESHEET_CHARSETC =
      "<link rel=\"stylesheet\" charset=\"utf-8\""
          + " href=\"test.css?type=text/css%3b%20charset=utf-8\" type=\"text/css\">";
  private static final String HTML_STYLESHEET_CHARSET_BAD =
      "<link rel=\"stylesheet\" charset=\"utf-8&max-size=4194304\" href=\"test.css\">";
  private static final String HTML_STYLESHEET_CHARSET_BADC =
      "<link rel=\"stylesheet\" href=\"test.css?type=text/css&amp;maybecharset=iso-8859-1\" "
          + "type=\"text/css\">";
  private static final String HTML_STYLESHEET_CHARSET_BAD1 =
      "<link rel=\"stylesheet\" type=\"text/css; charset=utf-8&max-size=4194304\""
          + " href=\"test.css\">";
  private static final String HTML_STYLESHEET_CHARSET_BAD1C =
      "<link rel=\"stylesheet\" type=\"text/css\" href=\"test.css?type=text/css&amp;"
          + "maybecharset=iso-8859-1\">";
  private static final String HTML_STYLESHEET_WITH_MEDIA =
      "<LINK REL=\"stylesheet\" TYPE=\"text/css\"\nMEDIA=\"print, handheld\" HREF=\"foo.css\">";
  private static final String HTML_STYLESHEET_WITH_MEDIAC =
      "<LINK rel=\"stylesheet\" type=\"text/css\" media=\"print, handheld\" href=\"foo"
          + ".css?type=text/css&amp;maybecharset=iso-8859-1\">";
  private static final String FRAME_SRC_CHARSET =
      "<frame src=\"test.html?type=text/html; charset=UTF-8\">";
  private static final String FRAME_SRC_CHARSETC =
      "<frame src=\"test.html?type=text/html%3b%20charset=UTF-8\">";
  private static final String FRAME_SRC_CHARSET_BAD =
      "<frame src=\"test.html?type=text/html; charset=UTF-8&max-size=4194304\">";
  private static final String FRAME_SRC_CHARSET_BADC =
      "<frame src=\"test.html?type=text/html%3b%20charset=UTF-8\">";
  private static final String FRAME_SRC_CHARSET_BAD1 =
      "<frame src=\"test.html?type=text/html; charset=UTF-8%26max-size=4194304\">";
  // From CSS spec
  private static final String FRAME_SRC_CHARSET_BAD1C = "<frame src=\"test.html?type=text/html\">";
  private static final String SPAN_WITH_STYLE =
      "<span style=\"font-family: verdana, sans-serif; color: red;\">";
  private static final String HTML_METER_PROGRESS_TAG =
      "<meter min=\"0\" max=\"100\" low=\"20\" high=\"80\" optimum=\"80\" value=\"50\">alt "
          + "text</meter><progress max=\"100\" value=\"0\">alt text</progress>";
  private static final String HTML5_TAGS =
      "<main><article><details><summary><mark>TLDR</mark></summary><center>Too Long Di<wbr "
          + "/>dn&rsquo;t Read</center></details><section><figure><figcaption>Fig"
          + ".1</figcaption></figure></article></main>";
  private static final String HTML5_BDI_RUBY =
      "<small dir=\"auto\"><bdi>&#x0627;&#x06CC;&#x0631;&#x0627;&#x0646;</bdi>, <bdo><ruby>&#xBD81;"
          + "<rt>North</rt>&#xD55C;<rt>Korea</rt></ruby><rp>North Korea</rp></ruby></bdo></small>";
  private static final String BASE_HREF = "<base href=\"/" + BASE_KEY + "\">";
  private static final String BAD_BASE_HREF = "<base href=\"/\">";
  private static final String BAD_BASE_HREF2 = "<base href=\"//www.google.com\">";
  private static final String BAD_BASE_HREF3 = "<base>";
  private static final String BAD_BASE_HREF4 = "<base id=\"blah\">";
  private static final String BAD_BASE_HREF5 = "<base href=\"http://www.google.com/\">";
  private static final String DELETED_BASE_HREF = "<!-- deleted invalid base href -->";
  private static final String CSS_SPEC_EXAMPLE1 =
      """
      <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
      <HTML>
        <HEAD>
        <TITLE>Bach's home \
      page</TITLE>
        <STYLE type="text/css">
          body {
            font-family: "Gill Sans", \
      sans-serif;
            font-size: 12pt;
            margin: 3em;

          }
        </STYLE>
        </HEAD>
        \
      <BODY>
          <H1>Bach's home page</H1>
          <P>Johann Sebastian Bach was a prolific composer\
      .
        </BODY>
      </HTML>\
      """;
  private static final String HTML_START_TO_BODY = "<html><head></head><body>";
  private static final String HTML_BODY_END = "</body></html>";
  private static final String HTML_VIDEO_TAG = "<video></video>";
  private static final String HTML_AUDIO_TAG = "<audio></audio>";
  private static final List<String> HTML_MEDIA_TAG_COMBINATIONS =
      Arrays.asList(
          HTML_VIDEO_TAG,
          HTML_AUDIO_TAG,
          HTML_VIDEO_TAG + HTML_AUDIO_TAG,
          HTML_AUDIO_TAG + HTML_AUDIO_TAG);
  private static final String META_TIME_ONLY = "<meta http-equiv=\"refresh\" content=\"5\">";
  private static final String META_TIME_ONLY_WRONG_CASE =
      "<meta http-equiv=\"RefResH\" content=\"5\">";
  private static final String META_TIME_ONLY_TOO_SHORT =
      "<meta http-equiv=\"refresh\" content=\"0\">";
  private static final String META_TIME_ONLY_NEGATIVE =
      "<meta http-equiv=\"refresh\" content=\"-5\">";
  private static final String META_TIME_ONLY_BADNUM1 =
      "<meta http-equiv=\"refresh\" content=\"5.5\">";
  private static final String META_TIME_ONLY_BADNUM2 = "<meta http-equiv=\"refresh\" content=\"\">";
  private static final String META_TIME_ONLY_BADNUM_OUT =
      "<!-- doesn't parse as number in meta refresh -->";
  private static final String META_CHARSET = "<html><head><meta charset=\"UTF-8\" />";
  private static final String META_CHARSET_LOWER =
      """
      <!DOCTYPE html>
      <html lang="de">
      <head>
      <!-- 2022-12-08 Do 01:20 -->
      <meta charset="utf-8" />
      <title>Some Title</title>\
      """;
  private static final String META_CHARSET_LOWER_RES =
      """
      <!DOCTYPE html>
      <html lang="de">
      <head>
      <!--  2022-12-08 Do 01:20  -->
      <meta charset="utf-8" />
      <title>Some Title</title>\
      """;
  private static final String META_VALID_REDIRECT =
      "<meta http-equiv=\"refresh\" content=\"30; url=/KSK@gpl.txt\">";
  private static final String META_VALID_REDIRECT_NOSPACE =
      "<meta http-equiv=\"refresh\" content=\"30;url=/KSK@gpl.txt\">";
  private static final String META_BOGUS_REDIRECT1 =
      "<meta http-equiv=\"refresh\" content=\"30; url=/\">";
  private static final String META_BOGUS_REDIRECT2 =
      "<meta http-equiv=\"refresh\" content=\"30; url=/plugins\">";
  private static final String META_BOGUS_REDIRECT3 =
      "<meta http-equiv=\"refresh\" content=\"30; url=http://www.google.com\">";
  private static final String META_BOGUS_REDIRECT4 =
      "<meta http-equiv=\"refresh\" content=\"30; url=//www.google.com\">";
  private static final String META_BOGUS_REDIRECT5 =
      "<meta http-equiv=\"refresh\" content=\"30; url=\"/KSK@gpl.txt\"\">";
  private static final String META_BOGUS_REDIRECT6 =
      "<meta http-equiv=\"refresh\" content=\"30; /KSK@gpl.txt\">";
  private static final String META_BOGUS_REDIRECT1_OUT =
      "<!-- GenericReadFilterCallback.malformedRelativeURL-->";
  private static final String META_BOGUS_REDIRECT3_OUT =
      "<meta http-equiv=\"refresh\" content=\"30; url=/external-link/?_CHECKED_HTTP_=http://www"
          + ".google.com\">";
  private static final String META_BOGUS_REDIRECT4_OUT =
      "<!-- GenericReadFilterCallback.deletedURI-->";
  private static final String META_BOGUS_REDIRECT_NO_URL =
      "<!-- no url but doesn't parse as number in meta refresh -->";
  private static final String ARIA_ROLE_TEST = "<span role=\"caption\" />";

  /**
   * AutoCloseable wrapper for ArrayBucket so tests can use try-with-resources and still read
   * contents before resources are freed.
   */
  private static class AutoFreeArrayBucket extends ArrayBucket implements AutoCloseable {
    AutoFreeArrayBucket() {
      super();
    }

    AutoFreeArrayBucket(byte[] init) {
      super(init);
    }

    @Override
    public void close() {
      free();
    }
  }

  @Test
  void stripMIMEType_whenHasParams_expectTypeOnly() {
    // Arrange
    String withParams = "text/html; charset=UTF-8; boundary=abcd";
    String withSpaces = "text/html ; charset=UTF-8";

    // Act
    String stripped = ContentFilter.stripMIMEType(withParams);
    String strippedSpaces = ContentFilter.stripMIMEType(withSpaces);

    // Assert
    assertEquals(TEXT_HTML, stripped);
    assertEquals(TEXT_HTML, strippedSpaces);
  }

  @Test
  void stripMIMEType_whenNull_expectNull() {
    assertNull(ContentFilter.stripMIMEType(null));
  }

  @Test
  void getMIMEType_whenAlternateType_expectHandler() {
    // image/x-png is registered as an alternate for image/png
    FilterMIMEType mt = ContentFilter.getMIMEType("image/x-png");
    assertNotNull(mt);
    assertEquals("image/png", mt.primaryMimeType);
  }

  @Test
  void getMIMEType_whenNull_expectNull() {
    assertNull(ContentFilter.getMIMEType(null));
  }

  @ParameterizedTest
  @CsvSource({
    "http://example/test.m3u,audio/mpegurl",
    "http://example/test.m3u8,audio/mpegurl",
    "file:///tmp/x.flac,audio/flac",
    "http://example/t.oga,audio/ogg",
    "http://example/t.ogv,video/ogg",
    "http://example/t.ogg,application/ogg",
    "http://example/t.wav,audio/vnd.wave",
    "http://example/t.mp3,audio/mpeg",
    "http://example/noext,audio/mpeg"
  })
  void mimeTypeForSrc_whenExtension_expectMappedType(String uri, String expected) {
    assertEquals(expected, ContentFilter.mimeTypeForSrc(uri));
  }

  @Test
  void startsWith_whenMatchingAndNotMatching_expectCorrectResult() {
    byte[] data = new byte[] {1, 2, 3, 4};
    byte[] prefix = new byte[] {1, 2};
    byte[] longer = new byte[] {1, 2, 3, 4, 5};
    assertTrue(ContentFilter.startsWith(data, prefix, data.length));
    assertFalse(ContentFilter.startsWith(data, longer, data.length));
  }

  @Test
  void filter_whenSafeToReadCopiesAndKeepsCharsetParam() throws Exception {
    // Arrange
    String typeName = "text/plain; charset=ISO-8859-1";
    byte[] input = "hello world".getBytes(StandardCharsets.ISO_8859_1);
    ByteArrayInputStream in = new ByteArrayInputStream(input);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    FilterStatus status =
        ContentFilter.filter(
            new ContentFilterRequest(in, out, typeName, /*maybeCharset*/ null, null, null));

    // Assert
    assertArrayEquals(input, out.toByteArray());
    assertNotNull(status);
    assertEquals("ISO-8859-1", status.charset);
    assertEquals(typeName, status.mimeType);
  }

  @Test
  void filter_whenUnknownType_expectUnknownContentTypeException() {
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {1, 2, 3});
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertThrows(
        UnknownContentTypeException.class,
        () ->
            ContentFilter.filter(
                new ContentFilterRequest(
                    in, out, "application/x-unknown-type", /*maybeCharset*/ null, null, null)));
  }

  @Test
  void filter_whenKnownUnsafe_expectKnownUnsafeContentTypeException() {
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {1, 2, 3});
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertThrows(
        KnownUnsafeContentTypeException.class,
        () ->
            ContentFilter.filter(
                new ContentFilterRequest(
                    in, out, "application/pdf", /*maybeCharset*/ null, null, null)));
  }

  @Test
  void filter_withReadFilter_detectsCharsetViaExtractor_andCopiesBytes() throws Exception {
    // Arrange: mock CharsetExtractor to return default charset
    CharsetExtractor extractor = Mockito.mock(CharsetExtractor.class);
    Mockito.when(extractor.getCharsetBufferSize()).thenReturn(8);
    Mockito.when(extractor.getCharsetByBOM(Mockito.any(), Mockito.anyInt())).thenReturn(null);
    Mockito.when(extractor.getCharset(Mockito.any(), Mockito.anyInt(), Mockito.eq(WINDOWS_1252)))
        .thenReturn(WINDOWS_1252);
    // No further stubs needed: default charset returns immediately

    // Register a synthetic MIME type with a simple echo filter
    RecordingEchoFilter echo = new RecordingEchoFilter();
    FilterMIMEType mt =
        new FilterMIMEType(
            new FilterMIMETypeNames("application/x-unit-test", "ut", new String[0], new String[0]),
            new FilterMIMETypeSafety(/*safeToRead*/ false, /*safeToWrite*/ false, echo, "desc"),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(
                /*takesACharset*/ true, /*defaultCharset*/
                WINDOWS_1252,
                extractor,
                /*useMaybeCharset*/ false));
    ContentFilter.register(mt);

    String typeName = "application/x-unit-test; foo=bar; boundary=abc";
    byte[] payload = "abc123".getBytes(StandardCharsets.US_ASCII);
    ByteArrayInputStream in = new ByteArrayInputStream(payload);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    FilterStatus status =
        ContentFilter.filter(new ContentFilterRequest(in, out, typeName, null, null, null));

    // Assert: data copied and charset detected via extractor
    assertArrayEquals(payload, out.toByteArray());
    assertNotNull(status);
    assertEquals(WINDOWS_1252, status.charset);
    assertEquals(typeName, status.mimeType);

    // Ensure the extractor was consulted
    Mockito.verify(extractor, Mockito.atLeastOnce()).getCharsetBufferSize();
    Mockito.verify(extractor, Mockito.atLeastOnce())
        .getCharset(Mockito.any(), Mockito.anyInt(), Mockito.eq(WINDOWS_1252));

    // Ensure non-charset params were passed to the filter
    assertEquals("bar", echo.lastOtherParams.get("foo"));
    assertEquals("abc", echo.lastOtherParams.get("boundary"));
  }

  @Test
  void detectCharset_whenBomPresent_returnsExpectedNames() throws Exception {
    // UTF-8 BOM
    byte[] utf8 = new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 'x'};
    FilterMIMEType dummy =
        new FilterMIMEType(
            new FilterMIMETypeNames("text/x-dummy", "dum", new String[0], new String[0]),
            new FilterMIMETypeSafety(true, true, null, "desc"),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(true, null, null, false));
    assertEquals("UTF-8", ContentFilter.detectCharset(utf8, utf8.length, dummy, null));

    // UTF-16LE BOM
    byte[] utf16le = new byte[] {(byte) 0xFF, (byte) 0xFE, 'x', 0};
    assertEquals("UTF-16LE", ContentFilter.detectCharset(utf16le, utf16le.length, dummy, null));

    // UTF-32BE BOM (does not collide with UTF-16 prefix check)
    byte[] utf32be = new byte[] {0, 0, (byte) 0xFE, (byte) 0xFF, 0, 0, 0, 'x'};
    assertEquals("UTF-32BE", ContentFilter.detectCharset(utf32be, utf32be.length, dummy, null));

    // UTF-7 variant BOM
    byte[] utf7 = new byte[] {'+', '/', 'v', '8', 'a'}; // matches bom_utf7_1
    assertEquals("UTF-7", ContentFilter.detectCharset(utf7, utf7.length, dummy, null));
  }

  @Test
  void detectCharset_whenUnsupportedBom_expectException() {
    // UTF-32-2143 unsupported
    byte[] bad = new byte[] {0, 0, (byte) 0xFF, (byte) 0xFE, 'x'};
    FilterMIMEType dummy =
        new FilterMIMEType(
            new FilterMIMETypeNames("text/x-dummy", "dum", new String[0], new String[0]),
            new FilterMIMETypeSafety(true, true, null, "desc"),
            new FilterMIMETypeDangerousFlags(false, false, false, false, false, false),
            new FilterMIMETypeCharsetPolicy(true, null, null, false));
    assertThrows(
        UnsupportedCharsetInFilterException.class,
        () -> ContentFilter.detectCharset(bad, bad.length, dummy, null));
  }

  /** Simple echo filter that records last seen otherParams for assertions. */
  private static final class RecordingEchoFilter implements ContentDataFilter {
    HashMap<String, String> lastOtherParams = new HashMap<>();

    @Override
    public void readFilter(
        InputStream input,
        OutputStream output,
        String charset,
        java.util.Map<String, String> otherParams,
        String schemeHostAndPort,
        FilterCallback cb)
        throws IOException {
      // record params excluding charset (already parsed by ContentFilter)
      lastOtherParams.clear();
      if (otherParams != null) {
        lastOtherParams.putAll(otherParams);
      }
      // simple echo copy
      byte[] buf = input.readAllBytes();
      output.write(buf);
    }
  }
}
