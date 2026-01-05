package network.crypta.clients.fcp;

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

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
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

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutDiskDirMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private NodeClientCore core;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private InputStream inputStream;
  @Mock private BucketFactory bucketFactory;
  @Mock private FCPServer otherServer;
  @Mock private OutputStream outputStream;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    lenient().when(handler.getServer()).thenReturn(server);
    lenient().when(server.getCore()).thenReturn(core);
    lenient().when(core.allowUploadFrom(any())).thenReturn(true);
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
    when(core.allowUploadFrom(any())).thenReturn(false);
    ClientPutDiskDirMessage message = newMessage(tempDir);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    verify(handler, never()).startClientPutDir(any(), any(), anyBoolean());
  }

  @Test
  void run_whenDirectoryContainsFiles_passesManifestToHandler() throws Exception {
    Path file = Files.writeString(tempDir.resolve("index.html"), "<html>");
    Path nestedDir = Files.createDirectory(tempDir.resolve("assets"));
    Path nestedFile = Files.writeString(nestedDir.resolve("style.css"), "body");
    Files.writeString(tempDir.resolve(".secret"), "hidden");

    ClientPutDiskDirMessage message = newMessage(tempDir);

    message.run(handler, node);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<HashMap<String, Object>> bucketsCaptor = ArgumentCaptor.forClass(HashMap.class);
    verify(handler).startClientPutDir(eq(message), bucketsCaptor.capture(), eq(true));
    HashMap<String, Object> buckets = bucketsCaptor.getValue();

    assertFalse(buckets.containsKey(".secret"));

    ManifestElement rootElement = (ManifestElement) buckets.get("index.html");
    assertEquals("index.html", rootElement.fullName);
    assertEquals(Files.size(file), rootElement.getSize());
    FileBucket bucket = (FileBucket) rootElement.getData();
    assertEquals(file.toFile().getAbsolutePath(), bucket.getFile().getAbsolutePath());

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
          assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

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

      assertDoesNotThrow(() -> message.run(handler, node));
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

    message.run(handler, node);

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
