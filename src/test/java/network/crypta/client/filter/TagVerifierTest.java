package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.util.LinkedHashMap;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.client.filter.HTMLFilter.TagVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TagVerifierTest {
  private static final String BASE_URI_PROTOCOL = "http";
  private static final String BASE_URI_CONTENT = "localhost:8888";
  private static final String BASE_KEY =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/Ultimate-Freenet-Index/55/";
  private static final String ALT_BASE_URI =
      BASE_URI_PROTOCOL + "://" + BASE_URI_CONTENT + '/' + BASE_KEY;

  String tagname;
  LinkedHashMap<String, String> attributes;
  ParsedTag htmlTag;
  TagVerifier verifier;
  HTMLFilter filter;
  HTMLFilter.HTMLParseContext pc;

  @BeforeEach
  void setUp() throws Exception {
    filter = new HTMLFilter();
    attributes = new LinkedHashMap<>();
    pc =
        filter
        .new HTMLParseContext(
            null,
            null,
            "utf-8",
            new GenericReadFilterCallback(new URI(ALT_BASE_URI), null, null, null),
            false);
  }

  @AfterEach
  void tearDown() {
    filter = null;
    attributes = null;
    pc = null;
    tagname = null;
    verifier = null;
    htmlTag = null;
  }

  @Test
  void sanitize_whenHtmlTagHasInvalidNamespace_removesNamespaceAttribute()
      throws DataFilterException {
    // Arrange
    tagname = "html";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("xmlns", "http://www.w3.org/1909/xhtml");
    attributes.put("version", "-//W3C//DTD HTML 4.01 Transitional//EN");
    htmlTag = new ParsedTag(tagname, attributes);
    final String expectedHtml = "<html version=\"-//W3C//DTD HTML 4.01 Transitional//EN\" />";

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expectedHtml, sanitized, "HTML tag containing an invalid xmlns");
  }

  @Test
  void sanitize_whenLinkTagHasStylesheetAttributes_returnsStylesheetLinkWithParams()
      throws DataFilterException {
    // Arrange
    tagname = "link";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("rel", "stylesheet");
    attributes.put("type", "text/css");
    attributes.put("target", "_blank");
    attributes.put("media", "print, handheld");
    attributes.put("href", "foo.css");
    htmlTag = new ParsedTag(tagname, attributes);
    final String expectedLink =
        "<link rel=\"stylesheet\" type=\"text/css\" target=\"_blank\" media=\"print, handheld\""
            + " href=\"foo.css?type=text/css&amp;maybecharset=utf-8\" />";

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expectedLink, sanitized, "Link tag importing CSS");
  }

  @Test
  void sanitize_whenMetaTagHasHtmlContentType_keepsTag() throws DataFilterException {
    // Arrange
    tagname = "meta";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("http-equiv", "Content-type");
    attributes.put("content", "text/html; charset=UTF-8");
    htmlTag = new ParsedTag(tagname, attributes);
    String expected = htmlTag.toString();

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expected, sanitized, "Meta tag describing HTML content-type");
  }

  @Test
  void sanitize_whenMetaTagHasXhtmlContentType_keepsTag() throws DataFilterException {
    // Arrange
    tagname = "meta";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("http-equiv", "Content-type");
    attributes.put("content", "application/xhtml+xml; charset=UTF-8");
    htmlTag = new ParsedTag(tagname, attributes);
    String expected = htmlTag.toString();

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expected, sanitized, "Meta tag describing XHTML content-type");
  }

  @Test
  void sanitize_whenMetaTagHasValidRobotsContent_keepsTag() throws DataFilterException {
    // Arrange
    tagname = "meta";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("name", "robots");
    attributes.put("content", "none, noindex, nofollow, noarchive, nosnippet, nocache");
    htmlTag = new ParsedTag(tagname, attributes);
    String expected = htmlTag.toString();

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expected, sanitized, "Meta tag controlling spiders - valid value");
  }

  @Test
  void sanitize_whenMetaTagHasInvalidRobotsContent_filtersInvalidTokens()
      throws DataFilterException {
    // Arrange
    tagname = "meta";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("name", "robots");
    attributes.put("content", "noindex,invalid");
    htmlTag = new ParsedTag(tagname, attributes);
    attributes.put("content", "noindex");
    ParsedTag filteredTag = new ParsedTag(tagname, attributes);
    String expected = filteredTag.toString();

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expected, sanitized, "Meta tag controlling spiders - invalid value");
  }

  @Test
  void sanitize_whenMetaTagHasUnknownContentType_throwsDataFilterException() {
    // Arrange
    tagname = "meta";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("http-equiv", "Content-type");
    attributes.put("content", "want/fishsticks; charset=UTF-8");
    htmlTag = new ParsedTag(tagname, attributes);

    // Act + Assert
    assertThrows(
        DataFilterException.class,
        () -> verifier.sanitize(htmlTag, pc),
        "Meta tag describing an unknown content-type: should throw an error");
  }

  @Test
  void sanitize_whenBodyTagHasEventHandlers_stripsEventHandlers() throws DataFilterException {
    // Arrange
    tagname = "body";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("bgcolor", "pink");
    attributes.put("onload", "evil_scripting_magic");
    htmlTag = new ParsedTag(tagname, attributes);
    final String expectedBody = "<body bgcolor=\"pink\" />";

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expectedBody, sanitized, "Body tag");
  }

  @Test
  void sanitize_whenFormTagHasLegacyCharset_replacesWithUtf8AndAddsEnctype()
      throws DataFilterException {
    // Arrange
    tagname = "form";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("method", "POST");
    attributes.put("accept-charset", "iso-8859-1");
    attributes.put("action", "/library/");
    htmlTag = new ParsedTag(tagname, attributes);
    final String expectedForm =
        "<form method=\"POST\" accept-charset=\"UTF-8\" action=\"/library/\""
            + " enctype=\"multipart/form-data\" />";

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expectedForm, sanitized, "Form tag");
  }

  @Test
  void sanitize_whenFormTagHasInvalidMethod_returnsNull() throws DataFilterException {
    // Arrange
    tagname = "form";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    attributes.put("method", "INVALID_METHOD");
    attributes.put("action", "/library/");
    htmlTag = new ParsedTag(tagname, attributes);

    // Act
    ParsedTag sanitized = verifier.sanitize(htmlTag, pc);

    // Assert
    assertNull(sanitized, "Form tag with an invalid method");
  }

  @Test
  void sanitize_whenInputTagMissingType_keepsTag() throws DataFilterException {
    // Arrange
    tagname = "input";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);
    htmlTag = new ParsedTag(tagname, attributes);
    String expected = htmlTag.toString();

    // Act
    String sanitized = verifier.sanitize(htmlTag, pc).toString();

    // Assert
    assertEquals(expected, sanitized, "Input tag without type");
  }

  @Test
  void sanitize_whenInputTagHasValidType_keepsTag() throws DataFilterException {
    // Arrange
    String[] types =
        new String[] {
          "TEXT",
          "password",
          "Checkbox",
          "radio",
          "SUBMIT",
          "rEsEt",
          // no ! file
          "hidden",
          "image",
          "button",
          "email",
          "number",
          "search",
          "tel",
          "url"
        };
    tagname = "input";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

    for (String t : types) {
      // Act
      attributes.put("type", t);
      htmlTag = new ParsedTag(tagname, attributes);
      String sanitized = verifier.sanitize(htmlTag, pc).toString();

      // Assert
      assertEquals(htmlTag.toString(), sanitized, "Input tag with a valid type");
    }
  }

  @Test
  void sanitize_whenInputTagHasInvalidType_returnsNull() throws DataFilterException {
    // Arrange
    String[] types =
        new String[] {
          "file", "FILE", "INVALID_TYPE",
        };

    tagname = "input";
    verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

    for (String t : types) {
      // Act
      attributes.put("type", t);
      htmlTag = new ParsedTag(tagname, attributes);
      ParsedTag sanitized = verifier.sanitize(htmlTag, pc);

      // Assert
      assertNull(sanitized, "Input tag with an invalid type");
    }
  }
}
