package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link FilterMIMEType} focusing on constructor state, exception behavior, and the
 * localized messaging exposed via {@link KnownUnsafeContentTypeException}.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FilterMIMETypeTest {

  @Test
  void constructor_whenProvidedAllValues_expectFieldsRetained() {
    // Arrange
    String type = "application/x-test";
    String ext = "tst";
    String[] extraTypes = new String[] {"application/x-t", "application/t"};
    String[] extraExts = new String[] {"te1", "te2"};

    boolean safeToRead = false;
    boolean safeToWrite = true;

    // not used here

    boolean dangerousLinks = true;
    boolean dangerousInlines = false;
    boolean dangerousScripting = true;
    boolean dangerousReadMetadata = true;
    boolean dangerousWriteMetadata = false;
    boolean dangerousToWriteEvenWithFilter = false;

    String readDescription = "desc";
    boolean takesACharset = true;
    String defaultCharset = "UTF-8";
    // not used here
    boolean useMaybeCharset = true;

    // Act
    FilterMIMEType mt =
        new FilterMIMEType(
            type,
            ext,
            extraTypes,
            extraExts,
            safeToRead,
            safeToWrite,
            null,
            dangerousLinks,
            dangerousInlines,
            dangerousScripting,
            dangerousReadMetadata,
            dangerousWriteMetadata,
            dangerousToWriteEvenWithFilter,
            readDescription,
            takesACharset,
            defaultCharset,
            null,
            useMaybeCharset);

    // Assert
    assertEquals(type, mt.primaryMimeType);
    assertEquals(ext, mt.primaryExtension);
    assertEquals(extraTypes, mt.alternateMimeTypes);
    assertEquals(extraExts, mt.alternateExtensions);
    assertEquals(safeToRead, mt.safeToRead);
    assertEquals(safeToWrite, mt.safeToWrite);
    assertNull(mt.readFilter);
    assertEquals(dangerousLinks, mt.dangerousLinks);
    assertEquals(dangerousInlines, mt.dangerousInlines);
    assertEquals(dangerousScripting, mt.dangerousScripting);
    assertEquals(dangerousReadMetadata, mt.dangerousReadMetadata);
    assertEquals(dangerousWriteMetadata, mt.dangerousWriteMetadata);
    assertEquals(dangerousToWriteEvenWithFilter, mt.dangerousToWriteEvenWithFilter);
    assertEquals(readDescription, mt.readDescription);
    assertEquals(takesACharset, mt.takesACharset);
    assertEquals(defaultCharset, mt.defaultCharset);
    assertNull(mt.charsetExtractor);
    assertEquals(useMaybeCharset, mt.useMaybeCharset);
  }

  @Test
  void throwUnsafeContentTypeException_whenInvoked_expectKnownUnsafeWithTitlesAndCode() {
    // Arrange
    String mime = "text/html<svg>"; // include characters that require HTML escaping
    FilterMIMEType mt =
        new FilterMIMEType(
            mime, "html", null, null, false, false, null, false, false, true, false, false, false,
            "desc", true, "UTF-8", null, false);

    // Act + Assert
    KnownUnsafeContentTypeException ex =
        assertThrows(KnownUnsafeContentTypeException.class, mt::throwUnsafeContentTypeException);

    // The exception should carry this specific MIME type object (package-private field access)
    assertNotNull(ex);
    assertEquals(mt, ex.type);

    // Titles come from l10n with and without HTML encoding
    String expectedRawTitle =
        NodeL10n.getBase()
            .getString("KnownUnsafeContentTypeException.title", "type", mt.primaryMimeType);
    assertEquals(expectedRawTitle, ex.getRawTitle());

    String expectedHtmlTitle =
        NodeL10n.getBase()
            .getString(
                "KnownUnsafeContentTypeException.title",
                "type",
                HTMLEncoder.encode(mt.primaryMimeType));
    assertEquals(expectedHtmlTitle, ex.getHTMLEncodedTitle());

    // Error code is mapped for unsafe MIME
    assertEquals(FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME, ex.getFetchErrorCode());
  }

  @Test
  void details_whenNoDangerFlags_expectEmptyList() {
    // Arrange: all flags false
    FilterMIMEType mt =
        new FilterMIMEType(
            "application/x-none",
            "bin",
            null,
            null,
            false,
            false,
            null,
            false,
            false,
            false,
            false,
            false,
            false,
            "",
            false,
            null,
            null,
            false);

    // Act
    KnownUnsafeContentTypeException ex =
        assertThrows(KnownUnsafeContentTypeException.class, mt::throwUnsafeContentTypeException);
    List<String> details = ex.details();

    // Assert
    assertNotNull(details);
    assertTrue(details.isEmpty());
  }

  @Test
  void details_whenScriptingOnly_expectScriptsAndMetadataEntries() {
    // Arrange: scripting true, others false (reflects current implementation logic)
    FilterMIMEType mt =
        new FilterMIMEType(
            "application/x-scr",
            "scr",
            null,
            null,
            false,
            false,
            null,
            false,
            false,
            true,
            false,
            false,
            false,
            "",
            false,
            null,
            null,
            false);

    KnownUnsafeContentTypeException ex =
        assertThrows(KnownUnsafeContentTypeException.class, mt::throwUnsafeContentTypeException);
    List<String> details = ex.details();

    // Assert
    assertEquals(2, details.size());
    String scriptsLabel =
        NodeL10n.getBase().getString("KnownUnsafeContentTypeException.dangerousScriptsLabel");
    String metadataLabel =
        NodeL10n.getBase().getString("KnownUnsafeContentTypeException.dangerousMetadataLabel");
    assertTrue(details.get(0).startsWith(scriptsLabel));
    assertTrue(details.get(1).startsWith(metadataLabel));
  }

  @Test
  void details_whenInlinesAndLinks_expectTwoEntries() {
    // Arrange: inlines + links true
    FilterMIMEType mt =
        new FilterMIMEType(
            "application/x-img",
            "img",
            null,
            null,
            false,
            false,
            null,
            true,
            true,
            false,
            false,
            false,
            false,
            "",
            false,
            null,
            null,
            false);

    KnownUnsafeContentTypeException ex =
        assertThrows(KnownUnsafeContentTypeException.class, mt::throwUnsafeContentTypeException);
    List<String> details = ex.details();

    // Assert
    assertEquals(2, details.size());
    String inlinesLabel =
        NodeL10n.getBase().getString("KnownUnsafeContentTypeException.dangerousInlinesLabel");
    String linksLabel =
        NodeL10n.getBase().getString("KnownUnsafeContentTypeException.dangerousLinksLabel");
    assertTrue(details.get(0).startsWith(inlinesLabel) || details.get(1).startsWith(inlinesLabel));
    assertTrue(details.get(0).startsWith(linksLabel) || details.get(1).startsWith(linksLabel));
  }

  @Test
  void details_whenMetadataOnly_expectNoEntry() {
    // Arrange: metadata flags true but scripting false
    FilterMIMEType mt =
        new FilterMIMEType(
            "application/x-meta",
            "mta",
            null,
            null,
            false,
            false,
            null,
            false,
            false,
            false,
            true, // dangerousReadMetadata
            true, // dangerousWriteMetadata
            false,
            "",
            false,
            null,
            null,
            false);

    KnownUnsafeContentTypeException ex =
        assertThrows(KnownUnsafeContentTypeException.class, mt::throwUnsafeContentTypeException);
    List<String> details = ex.details();

    // Assert: current implementation does not add metadata-only details
    assertTrue(details.isEmpty());
  }
}
