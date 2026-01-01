package network.crypta.clients.fcp;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutComplexDirMessageTest {

  private final BucketFactory tempBucketFactory = new ArrayBucketFactory();

  @Mock private PersistentTempBucketFactory persistentBucketFactory;
  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private Node node;
  @Mock private NodeClientCore core;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() throws IOException {
    lenient().when(node.getClientCore()).thenReturn(core);
    lenient().when(core.allowUploadFrom(any(File.class))).thenReturn(true);
    lenient()
        .when(persistentBucketFactory.makeBucket(anyLong()))
        .thenAnswer(_ -> new ArrayBucket());
  }

  @Test
  void constructor_whenFilesSectionMissing_expectMessageInvalidException() {
    SimpleFieldSet fs = baseFieldSet();

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> new ClientPutComplexDirMessage(fs, tempBucketFactory, persistentBucketFactory));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
  }

  @Test
  void dataLength_whenMultipleDirectFiles_expectSumOfBytes() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    addDirectFile(fs, 0, "alpha.txt", 5);
    addDirectFile(fs, 1, "bravo.txt", 3);

    ClientPutComplexDirMessage message =
        new ClientPutComplexDirMessage(fs, tempBucketFactory, persistentBucketFactory);

    assertEquals(8, message.dataLength());
  }

  @Test
  void constructor_whenPersistenceForever_expectPersistentBucketsUsed() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.putOverwrite("Persistence", "forever");
    addDirectFile(fs, 0, "payload.bin", 9);

    BucketFactory tempFactory = mock(BucketFactory.class);
    PersistentTempBucketFactory persistentFactory = mock(PersistentTempBucketFactory.class);
    when(persistentFactory.makeBucket(9L)).thenReturn(new ArrayBucket());

    new ClientPutComplexDirMessage(fs, tempFactory, persistentFactory);

    //noinspection EmptyTryBlock
    try (var _ = verify(persistentFactory).makeBucket(9L)) {
      // release the bucket immediately; only the side effect of verify() is needed
    }
    verifyNoInteractions(tempFactory);
  }

  @Test
  void readFrom_whenDirectFilesPresent_expectWriteDataOutputsSameBytes() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    addDirectFile(fs, 0, "alpha.txt", 4);
    addDirectFile(fs, 1, "bravo.txt", 6);
    ClientPutComplexDirMessage message =
        new ClientPutComplexDirMessage(fs, tempBucketFactory, persistentBucketFactory);

    byte[] payload = "abcdEFGHIJ".getBytes(UTF_8);
    message.readFrom(new ByteArrayInputStream(payload), tempBucketFactory, server);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    message.writeData(output);

    assertArrayEquals(payload, output.toByteArray());
  }

  @Test
  void run_whenDiskFileNotAllowed_expectAccessDenied() throws Exception {
    Path diskFile = Files.writeString(tempDir.resolve("disk.txt"), "denied");
    when(core.allowUploadFrom(diskFile.toFile())).thenReturn(false);
    SimpleFieldSet fs = baseFieldSet();
    addDiskFile(fs, 0, "disk.txt", diskFile);
    ClientPutComplexDirMessage message =
        new ClientPutComplexDirMessage(fs, tempBucketFactory, persistentBucketFactory);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    verify(handler, never()).startClientPutDir(any(), any(), anyBoolean());
  }

  @Test
  void run_whenFilesInSubdirectories_expectManifestTreeAndData() throws Exception {
    Path diskFile = Files.writeString(tempDir.resolve("disk.txt"), "disk-data");
    when(core.allowUploadFrom(diskFile.toFile())).thenReturn(true);
    byte[] directBytes = "hello".getBytes(UTF_8);
    SimpleFieldSet fs = baseFieldSet();
    addDirectFile(fs, 0, "docs/direct.txt", directBytes.length);
    addDiskFile(fs, 1, "docs/disk.txt", diskFile);
    ClientPutComplexDirMessage message =
        new ClientPutComplexDirMessage(fs, tempBucketFactory, persistentBucketFactory);

    message.readFrom(new ByteArrayInputStream(directBytes), tempBucketFactory, server);
    message.run(handler, node);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<HashMap<String, Object>> manifestCaptor = ArgumentCaptor.forClass(HashMap.class);
    verify(handler).startClientPutDir(eq(message), manifestCaptor.capture(), eq(false));

    HashMap<String, Object> manifest = manifestCaptor.getValue();
    @SuppressWarnings("unchecked")
    HashMap<String, Object> docs = (HashMap<String, Object>) manifest.get("docs");
    assertNotNull(docs);

    ManifestElement directElement = (ManifestElement) docs.get("direct.txt");
    assertNotNull(directElement);
    assertEquals(directBytes.length, directElement.getSize());
    assertArrayEquals(directBytes, readAllBytes(directElement.getData()));

    ManifestElement diskElement = (ManifestElement) docs.get("disk.txt");
    assertNotNull(diskElement);
    assertEquals(Files.size(diskFile), diskElement.getSize());
    assertEquals("disk-data", new String(readAllBytes(diskElement.getData()), UTF_8));
  }

  private static SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "test-id");
    fs.putSingle("URI", "KSK@site");
    fs.putSingle("Persistence", "connection");
    return fs;
  }

  private static void addDirectFile(SimpleFieldSet fs, int index, String name, long length) {
    String prefix = "Files." + index;
    fs.putSingle(prefix + ".Name", name);
    fs.putSingle(prefix + ".UploadFrom", "direct");
    fs.put(prefix + ".DataLength", length);
  }

  private static void addDiskFile(SimpleFieldSet fs, int index, String name, Path path) {
    String prefix = "Files." + index;
    fs.putSingle(prefix + ".Name", name);
    fs.putSingle(prefix + ".UploadFrom", "disk");
    fs.putSingle(prefix + ".Filename", path.toAbsolutePath().toString());
  }

  private static byte[] readAllBytes(RandomAccessBucket bucket) throws IOException {
    InputStream input = bucket.getInputStream();
    if (input == null) {
      return new byte[0];
    }
    try (input;
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      input.transferTo(output);
      return output.toByteArray();
    }
  }
}
