package network.crypta.client;

import java.util.Random;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class InsertUriChecksTest {

  @Test
  void checkInsertURI_whenMetaStringsPresent_throwsMetaStringsNotSupported() {
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(1)).pushMetaString("file");

    InsertException ex =
        assertThrows(InsertException.class, () -> InsertUriChecks.checkInsertURI(uri));
    assertEquals(InsertExceptionMode.META_STRINGS_NOT_SUPPORTED, ex.getMode());
    assertEquals(uri, ex.getUri());
  }

  @Test
  void checkInsertURI_whenMetaStringsAbsent_passes() {
    assertDoesNotThrow(() -> InsertUriChecks.checkInsertURI(FreenetURI.EMPTY_CHK_URI));
  }

  @Test
  void checkInsertURI_whenUriIsNull_throwsNullPointerException() {
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> InsertUriChecks.checkInsertURI(null));
  }
}
