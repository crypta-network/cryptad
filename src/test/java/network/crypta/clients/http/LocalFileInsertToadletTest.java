package network.crypta.clients.http;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import network.crypta.runtime.spi.TransferAccessPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LocalFileInsertToadletTest {

  private static final String VALID_KEY = "KSK@unit-test";

  @Mock private TransferAccessPort transferAccess;

  private LocalFileInsertToadlet toadlet;

  @BeforeEach
  void setUp() {
    lenient().doCallRealMethod().when(transferAccess).defaultUploadDir();
    toadlet = new LocalFileInsertToadlet(transferAccess);
  }

  @Test
  void path_whenCalled_returnsInsertBrowsePath() {
    String result = toadlet.path();

    assertEquals(LocalFileInsertToadlet.INSERT_BROWSE_PATH, result);
  }

  @Test
  void postTo_whenCalled_returnsUploadsPath() {
    String result = toadlet.postTo();

    assertEquals(LocalFileInsertToadlet.UPLOADS_PATH, result);
  }

  @Test
  void allowedDir_whenDelegatedToCore_returnsCoreDecision() {
    File path = new File("/tmp/allowed");
    when(transferAccess.allowUploadFrom(path)).thenReturn(true);

    boolean result = toadlet.allowedDir(path);

    assertTrue(result);
    verify(transferAccess).allowUploadFrom(path);
  }

  @Test
  void allowedDir_whenCoreDisallows_returnsFalse() {
    File path = new File("/tmp/disallowed");
    when(transferAccess.allowUploadFrom(path)).thenReturn(false);

    boolean result = toadlet.allowedDir(path);

    assertFalse(result);
    verify(transferAccess).allowUploadFrom(path);
  }

  @Test
  void startingDir_whenUploadsAllowedEverywhere_returnsUserHome() {
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[] {new File("all")});

    String result = toadlet.startingDir();

    assertEquals(System.getProperty("user.home"), result);
  }

  @Test
  void startingDir_whenExplicitUploadDirectoryConfigured_returnsFirstEntry() {
    File preferred = new File("/var/uploads");
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[] {preferred});

    String result = toadlet.startingDir();

    assertEquals(preferred.getAbsolutePath(), result);
  }

  @Test
  void persistenceFields_whenValidKeyAndFlagsPresent_returnsNormalizedMap() {
    Map<String, String> input = new HashMap<>();
    input.put("key", VALID_KEY);
    input.put("compress", "true");
    input.put("compatibilityMode", "legacy");
    input.put("overrideSplitfileKey", "override-key");

    Map<String, String> result = toadlet.persistenceFields(input);

    assertEquals(4, result.size());
    assertEquals("true", result.get("compress"));
    assertEquals("legacy", result.get("compatibilityMode"));
    assertEquals("override-key", result.get("overrideSplitfileKey"));
    assertEquals("freenet:" + VALID_KEY, result.get("key"));
  }

  @Test
  void persistenceFields_whenInvalidKey_omitsKeyField() {
    Map<String, String> input = new HashMap<>();
    input.put("key", "invalid");
    input.put("compress", "true");

    Map<String, String> result = toadlet.persistenceFields(input);

    assertEquals(1, result.size());
    assertEquals("true", result.get("compress"));
  }

  @Test
  void persistenceFields_whenCompressFalseAndNoExtras_returnsOnlyValidKey() {
    Map<String, String> input = new HashMap<>();
    input.put("key", VALID_KEY);
    input.put("compress", "false");

    Map<String, String> result = toadlet.persistenceFields(input);

    assertEquals(1, result.size());
    assertEquals("freenet:" + VALID_KEY, result.get("key"));
  }
}
