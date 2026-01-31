package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import network.crypta.support.MediaType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class DefaultMIMETypesTest {

  // ---------------------------
  // Plausibility (regex) checks
  // ---------------------------

  @Test
  void isPlausibleMIMEType_acceptsAllBuiltIns() {
    for (String mimeType : DefaultMIMETypes.getMIMETypes()) {
      assertTrue(DefaultMIMETypes.isPlausibleMIMEType(mimeType), "Failed: \"" + mimeType + "\"");
    }
  }

  @Test
  void isPlausibleMIMEType_acceptsParametersAndQuotedValues() {
    assertTrue(
        DefaultMIMETypes.isPlausibleMIMEType("text/xhtml+xml; charset=ISO-8859-1; blah=blah"));
    assertTrue(
        DefaultMIMETypes.isPlausibleMIMEType(
            "multipart/mixed; boundary=\"---this is a silly boundary---\""));
    assertTrue(DefaultMIMETypes.isPlausibleMIMEType("text/plain; charset=UTF-8;"));
  }

  @Test
  void isPlausibleMIMEType_rejectsMalformedInputs() {
    assertFalse(DefaultMIMETypes.isPlausibleMIMEType("textplain"));
    assertFalse(DefaultMIMETypes.isPlausibleMIMEType("text/plain;charset"));
    assertFalse(DefaultMIMETypes.isPlausibleMIMEType("text/")); // missing subtype
  }

  @Test
  void isPlausibleMIMEType_acceptsDirtyHackForInfocalypse() {
    assertTrue(DefaultMIMETypes.isPlausibleMIMEType("application/mercurial-bundle;123"));
    assertFalse(DefaultMIMETypes.isPlausibleMIMEType("application/mercurial-bundle;12ab"));
  }

  // ---------------------------
  // Name/number mapping
  // ---------------------------

  @Test
  void byName_whenKnownType_returnsNumber() {
    assertEquals(53, DefaultMIMETypes.byName("application/pdf"));
    assertEquals(533, DefaultMIMETypes.byName("text/html"));
  }

  @Test
  void byName_whenUnknownType_returnsMinusOne() {
    assertEquals(-1, DefaultMIMETypes.byName("application/x-abcxyz"));
  }

  @Test
  void byNumber_whenKnownNumber_returnsType() {
    assertEquals("application/pdf", DefaultMIMETypes.byNumber((short) 53));
    assertEquals("text/html", DefaultMIMETypes.byNumber((short) 533));
  }

  @Test
  void byNumber_whenOutOfRangeOrNegative_returnsNull() {
    assertNull(DefaultMIMETypes.byNumber((short) -5));
    assertNull(DefaultMIMETypes.byNumber((short) 2000));
  }

  // ---------------------------
  // Guess by filename/extension
  // ---------------------------

  @ParameterizedTest
  @CsvSource({
    "file.PDF, application/pdf",
    "photo.JPG, image/jpeg",
    "archive.zip, application/zip", // Prefer first registration over later duplicates
    "index.HTML, text/html"
  })
  void guessMIMEType_whenKnownExtension_expectMappedType(String name, String expected) {
    assertEquals(expected, DefaultMIMETypes.guessMIMEType(name, false));
  }

  @ParameterizedTest
  @CsvSource({
    "readme, application/octet-stream",
    "file., application/octet-stream",
    "x.unknown, application/octet-stream"
  })
  void guessMIMEType_whenUnknownOrMissingExtension_withDefault_returnsOctetStream(
      String name, String expected) {
    assertEquals(expected, DefaultMIMETypes.guessMIMEType(name, false));
    assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, expected);
  }

  @ParameterizedTest
  @CsvSource({"readme, ", "file., ", "x.unknown, "})
  void guessMIMEType_whenUnknownOrMissingExtension_noDefault_returnsNull(
      String name, String ignored) {
    assertNull(DefaultMIMETypes.guessMIMEType(name, true));
  }

  // ---------------------------
  // Extension lookup/validation
  // ---------------------------

  @Test
  void getExtension_whenKnownType_returnsPrimary() {
    assertEquals("pdf", DefaultMIMETypes.getExtension("application/pdf"));
    assertEquals("doc", DefaultMIMETypes.getExtension("application/msword")); // primary of doc|dot
    assertEquals("html", DefaultMIMETypes.getExtension("text/html"));
  }

  @Test
  void getExtension_whenUnknownType_returnsNull() {
    assertNull(DefaultMIMETypes.getExtension("application/x-abcxyz"));
  }

  @Test
  void isValidExt_whenExtensionBelongsToType_returnsTrue_caseInsensitive() {
    assertTrue(DefaultMIMETypes.isValidExt("application/msword", "DoT"));
    assertTrue(DefaultMIMETypes.isValidExt("application/pdf", "PDF"));
    assertTrue(DefaultMIMETypes.isValidExt("text/html", "sHtml")); // non-primary is still valid
  }

  @Test
  void isValidExt_whenExtensionDoesNotBelongToType_returnsFalse() {
    assertFalse(DefaultMIMETypes.isValidExt("application/pdf", "htm"));
    assertFalse(DefaultMIMETypes.isValidExt("application/x-abcxyz", "zzz"));
  }

  @Test
  void isValidExt_mediaTypeOverload_behavesSameAsStringVariant() throws MalformedURLException {
    MediaType htmlWithParams = new MediaType("text/html; charset=UTF-8");
    assertTrue(DefaultMIMETypes.isValidExt(htmlWithParams, "HTM"));
    assertFalse(DefaultMIMETypes.isValidExt(htmlWithParams, "pdf"));
  }

  // ---------------------------
  // Forcing filename extensions
  // ---------------------------

  @Test
  void forceExtension_whenNoExtension_appendsPrimary() {
    assertEquals("readme.pdf", DefaultMIMETypes.forceExtension("readme", "application/pdf"));
  }

  @Test
  void forceExtension_whenCorrectExtensionPresent_preservesFilename_caseInsensitive() {
    assertEquals("Thing.DOC", DefaultMIMETypes.forceExtension("Thing.DOC", "application/msword"));
  }

  @Test
  void forceExtension_whenWrongExtensionPresent_appendsPrimary() {
    assertEquals("note.txt.pdf", DefaultMIMETypes.forceExtension("note.txt", "application/pdf"));
  }

  @Test
  void forceExtension_whenUnknownOrNullType_appendsBin() {
    assertEquals("readme.bin", DefaultMIMETypes.forceExtension("readme", null));
    assertEquals("foo.txt.bin", DefaultMIMETypes.forceExtension("foo.txt", "application/x-abcxyz"));
  }
}
