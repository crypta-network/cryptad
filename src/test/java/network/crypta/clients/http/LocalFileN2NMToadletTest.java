package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import network.crypta.runtime.spi.TransferAccessPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LocalFileN2NMToadletTest {

  @Mock private TransferAccessPort transferAccess;

  private LocalFileN2NMToadlet toadlet;

  @BeforeEach
  void setUp() {
    lenient().doCallRealMethod().when(transferAccess).defaultUploadDir();
    toadlet = new LocalFileN2NMToadlet(transferAccess);
  }

  @Test
  void path_whenCalled_returnsBrowsePath() {
    assertEquals(LocalFileN2NMToadlet.BROWSE_PATH, toadlet.path());
  }

  @Test
  void postTo_whenCalled_returnsSendPath() {
    assertEquals(LocalFileN2NMToadlet.POST_TARGET, toadlet.postTo());
  }

  @Test
  void allowedDir_whenDelegated_usesCoreCheck() {
    File sample = new File("some/path");
    when(transferAccess.allowUploadFrom(sample)).thenReturn(true);

    boolean result = toadlet.allowedDir(sample);

    assertTrue(result);
    verify(transferAccess).allowUploadFrom(sample);
  }

  @Test
  void startingDir_whenUploadsUnrestricted_returnsUserHome() {
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[] {new File("all")});

    String result = toadlet.startingDir();

    assertEquals(System.getProperty("user.home"), result);
  }

  @Test
  void startingDir_whenNoUploadDirsConfigured_returnsUserHome() {
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[0]);

    String result = toadlet.startingDir();

    assertEquals(System.getProperty("user.home"), result);
  }

  @Test
  void startingDir_whenExplicitUploadDirs_returnsFirstAbsolutePath(@TempDir Path tempDir)
      throws IOException {
    Path firstPath = Files.createDirectories(tempDir.resolve("first"));
    Path secondPath = Files.createDirectories(tempDir.resolve("second"));
    File first = firstPath.toFile();
    File second = secondPath.toFile();
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[] {first, second});

    String result = toadlet.startingDir();

    assertEquals(first.getAbsolutePath(), result);
  }

  @Test
  void persistenceFields_whenMessageAndNodeFlagsProvided_preservesMessageAndSetsFlags() {
    Map<String, String> input = new HashMap<>();
    input.put("message", "hello");
    input.put("node_123", "ignoredValue");
    input.put("node_abc", "0");
    input.put("other", "value");

    Map<String, String> result = toadlet.persistenceFields(input);

    assertEquals("hello", result.get("message"));
    assertEquals("1", result.get("node_123"));
    assertEquals("1", result.get("node_abc"));
    assertEquals(3, result.size());
  }

  @Test
  void persistenceFields_whenNoMessageAndNoNodeKeys_returnsEmptyMap() {
    Map<String, String> input = new HashMap<>();
    input.put("other", "value");
    input.put("message", null);

    Map<String, String> result = toadlet.persistenceFields(input);

    assertTrue(result.isEmpty());
  }
}
