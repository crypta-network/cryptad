package network.crypta.clients.fcp;

import network.crypta.client.DefaultMIMETypes;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.ManifestElement;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RedirectDirPutFileTest {

  private static final String IDENTIFIER = "redirect-test";
  private static final boolean GLOBAL = true;
  private static final String VALID_TARGET = "KSK@redirect-target";

  @Test
  void create_whenTargetUriMissing_expectMessageInvalidException() {
    SimpleFieldSet subset = new SimpleFieldSet(true);

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> RedirectDirPutFile.create("file.txt", "text/plain", subset, IDENTIFIER, GLOBAL));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    assertTrue(ex.global);
    assertTrue(ex.getMessage().contains("TargetURI missing"));
  }

  @Test
  void create_whenTargetUriInvalid_expectMessageInvalidException() {
    SimpleFieldSet subset = subsetWithTarget("not-a-valid-uri");

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> RedirectDirPutFile.create("file.txt", null, subset, IDENTIFIER, GLOBAL));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    assertTrue(ex.global);
    assertTrue(ex.getMessage().startsWith("Invalid TargetURI"));
  }

  @Test
  void create_whenContentTypeOverrideProvided_buildsRedirectManifestElement() throws Exception {
    String name = "docs/index.html";
    String overrideMime = "text/html";
    SimpleFieldSet subset = subsetWithTarget(VALID_TARGET);

    RedirectDirPutFile file =
        RedirectDirPutFile.create(name, overrideMime, subset, IDENTIFIER, false);

    assertEquals(name, file.getName());
    assertEquals(overrideMime, file.getMIMEType());
    assertNull(file.getData());

    ManifestElement element = file.getElement();
    assertEquals(name, element.getName());
    assertEquals(overrideMime, element.getMimeTypeOverride());
    assertNull(element.getData());
    assertEquals(-1L, element.getSize());
    assertEquals(new FreenetURI(VALID_TARGET), element.getTargetURI());
  }

  @Test
  void create_whenContentTypeMissing_guessesMimeFromName() throws Exception {
    String name = "images/photo.png";
    SimpleFieldSet subset = subsetWithTarget(VALID_TARGET);

    RedirectDirPutFile file = RedirectDirPutFile.create(name, null, subset, IDENTIFIER, false);

    String expectedMime = DefaultMIMETypes.guessMIMEType(name, true);
    assertEquals(expectedMime, file.getMIMEType());

    ManifestElement element = file.getElement();
    assertEquals(expectedMime, element.getMimeTypeOverride());
    assertEquals(new FreenetURI(VALID_TARGET), element.getTargetURI());
  }

  private static SimpleFieldSet subsetWithTarget(String target) {
    SimpleFieldSet subset = new SimpleFieldSet(true);
    subset.putSingle("TargetURI", target);
    return subset;
  }
}
