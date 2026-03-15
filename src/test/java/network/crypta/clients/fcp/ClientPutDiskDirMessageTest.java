package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutDiskDirMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private RuntimePorts runtimePorts;
  @Mock private TransferAccessPort transferAccess;

  @Mock private InputStream inputStream;
  @Mock private BucketFactory bucketFactory;
  @Mock private FCPServer otherServer;
  @Mock private OutputStream outputStream;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    lenient().when(handler.getServer()).thenReturn(server);
    lenient().when(server.runtime()).thenReturn(runtimePorts);
    lenient().when(runtimePorts.transferAccess()).thenReturn(transferAccess);
    lenient().when(transferAccess.allowUploadFrom(any())).thenReturn(true);
  }

  @Test
  void constructor_whenFilenameMissing_expectException() {
    SimpleFieldSet fs = baseFieldSet();

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new ClientPutDiskDirMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
  }

  @Test
  void getName_whenCalled_returnsConstant() throws MessageInvalidException {
    ClientPutDiskDirMessage message = newMessage(tempDir);

    assertEquals(ClientPutDiskDirMessage.NAME, message.getName());
  }

  @Test
  void run_whenUploadNotAllowed_expectAccessDenied() throws Exception {
    when(transferAccess.allowUploadFrom(any())).thenReturn(false);
    ClientPutDiskDirMessage message = newMessage(tempDir);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    verify(handler, never()).startClientPutDir(any(), any(), anyBoolean());
  }

  @Test
  void run_whenDirectoryContainsFiles_passesManifestToHandler() throws Exception {
    Path file = Files.writeString(tempDir.resolve("index.html"), "<html>");
    Path nestedDir = Files.createDirectory(tempDir.resolve("assets"));
    Path nestedFile = Files.writeString(nestedDir.resolve("style.css"), "body");
    Path hiddenFile = Files.writeString(tempDir.resolve(".secret"), "hidden");
    if (!hiddenFile.toFile().isHidden()) {
      try {
        Files.setAttribute(hiddenFile, "dos:hidden", true);
      } catch (UnsupportedOperationException | IOException _) {
        // Platform does not expose DOS hidden attribute; fall back to runtime hidden semantics.
      }
    }

    ClientPutDiskDirMessage message = newMessage(tempDir);

    message.run(handler);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<HashMap<String, Object>> bucketsCaptor = ArgumentCaptor.forClass(HashMap.class);
    verify(handler).startClientPutDir(eq(message), bucketsCaptor.capture(), eq(true));
    HashMap<String, Object> buckets = bucketsCaptor.getValue();

    String hiddenFileName = hiddenFile.getFileName().toString();
    if (hiddenFile.toFile().isHidden()) {
      assertFalse(buckets.containsKey(hiddenFileName));
    } else {
      assertTrue(buckets.containsKey(hiddenFileName));
    }

    ManifestElement rootElement = (ManifestElement) buckets.get("index.html");
    assertEquals("index.html", rootElement.fullName);
    assertEquals(Files.size(file), rootElement.getSize());
    FileBucket bucket = (FileBucket) rootElement.getData();
    File bucketFile = bucket.getFile();
    assertNotNull(bucketFile);
    assertEquals(file.toFile().getAbsolutePath(), bucketFile.getAbsolutePath());

    @SuppressWarnings("unchecked")
    HashMap<String, Object> nested = (HashMap<String, Object>) buckets.get("assets");
    assertNotNull(nested);
    ManifestElement nestedElement = (ManifestElement) nested.get("style.css");
    assertEquals("assets/style.css", nestedElement.fullName);
    assertEquals(Files.size(nestedFile), nestedElement.getSize());
  }

  @Test
  void run_whenUnreadableFileAndNotAllowed_expectFileNotFound() throws Exception {
    Path unreadable = Files.createFile(tempDir.resolve("secret.txt"));
    File unreadableFile = unreadable.toFile();
    Assumptions.assumeTrue(unreadableFile.setReadable(false));
    Assumptions.assumeFalse(unreadableFile.canRead());
    try {
      ClientPutDiskDirMessage message = newMessage(tempDir);

      MessageInvalidException ex =
          assertThrows(MessageInvalidException.class, () -> message.run(handler));

      assertEquals(ProtocolErrorMessage.FILE_NOT_FOUND, ex.protocolCode);
    } finally {
      boolean restored = unreadableFile.setReadable(true);
      assertTrue(restored || unreadableFile.canRead(), "Failed to restore readability");
    }
  }

  @Test
  void run_whenUnreadableFileAllowed_skipsUnreadableEntry() throws Exception {
    Path unreadable = Files.createFile(tempDir.resolve("secret.txt"));
    File unreadableFile = unreadable.toFile();
    Assumptions.assumeTrue(unreadableFile.setReadable(false));
    Assumptions.assumeFalse(unreadableFile.canRead());
    try {
      ClientPutDiskDirMessage message = newMessage(tempDir, true, false);

      @SuppressWarnings("unchecked")
      ArgumentCaptor<HashMap<String, Object>> bucketsCaptor =
          ArgumentCaptor.forClass(HashMap.class);

      assertDoesNotThrow(() -> message.run(handler));
      verify(handler).startClientPutDir(eq(message), bucketsCaptor.capture(), eq(true));

      HashMap<String, Object> buckets = bucketsCaptor.getValue();
      assertFalse(buckets.containsKey("secret.txt"));
    } finally {
      boolean restored = unreadableFile.setReadable(true);
      assertTrue(restored || unreadableFile.canRead(), "Failed to restore readability");
    }
  }

  @Test
  void run_whenIncludeHiddenFilesTrue_includesHiddenEntries() throws Exception {
    Path hiddenFile = Files.writeString(tempDir.resolve(".secret.txt"), "hidden");

    ClientPutDiskDirMessage message = newMessage(tempDir, false, true);

    message.run(handler);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<HashMap<String, Object>> bucketsCaptor = ArgumentCaptor.forClass(HashMap.class);
    verify(handler).startClientPutDir(eq(message), bucketsCaptor.capture(), eq(true));
    HashMap<String, Object> buckets = bucketsCaptor.getValue();

    ManifestElement hiddenElement = (ManifestElement) buckets.get(".secret.txt");
    assertNotNull(hiddenElement);
    assertEquals(".secret.txt", hiddenElement.fullName);
    assertEquals(Files.size(hiddenFile), hiddenElement.getSize());
  }

  @Test
  void readFrom_whenInvoked_doesNothing() throws Exception {
    ClientPutDiskDirMessage message = newMessage(tempDir);

    assertDoesNotThrow(() -> message.readFrom(inputStream, bucketFactory, otherServer));
    assertEquals("test-id", message.getIdentifier());
  }

  @Test
  void writeData_whenInvoked_doesNothing() throws Exception {
    ClientPutDiskDirMessage message = newMessage(tempDir);

    assertDoesNotThrow(() -> message.writeData(outputStream));
    assertEquals("test-id", message.getIdentifier());
  }

  private SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "test-id");
    fs.putSingle("URI", "KSK@site");
    fs.putSingle("Persistence", "connection");
    return fs;
  }

  private ClientPutDiskDirMessage newMessage(Path dir) throws MessageInvalidException {
    return newMessage(dir, false, false);
  }

  private ClientPutDiskDirMessage newMessage(
      Path dir, boolean allowUnreadable, boolean includeHidden) throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("Filename", dir.toAbsolutePath().toString());
    if (allowUnreadable) {
      fs.put("AllowUnreadableFiles", true);
    }
    if (includeHidden) {
      fs.put("includeHiddenFiles", true);
    }
    return new ClientPutDiskDirMessage(fs);
  }
}
