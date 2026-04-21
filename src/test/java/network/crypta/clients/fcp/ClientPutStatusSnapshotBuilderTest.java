package network.crypta.clients.fcp;

import java.io.File;
import java.lang.reflect.Field;
import java.time.Instant;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "java:S3011"})
class ClientPutStatusSnapshotBuilderTest {
  private static final String VALID_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";

  @TempDir private java.nio.file.Path tempDir;

  @Test
  void build_whenNoProgress_usesDefaultsAndMime() throws Exception {
    ClientPut request = new ClientPut();
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(bucket.size()).thenReturn(123L);
    ClientMetadata metadata = new ClientMetadata("text/plain");
    String filename = "data" + ".bin";
    File origFile = createFile(filename);
    DefaultFcpInsertContextHandle context = newContext();

    setField(request, "identifier", "id");
    setField(request, "uri", new FreenetURI(VALID_CHK));
    setField(request, "persistence", ClientRequest.Persistence.FOREVER);
    setField(request, "started", true);
    setField(request, "finished", false);
    setField(request, "succeeded", false);
    setField(request, "priorityClass", (short) 2);
    setField(request, "clientMetadata", metadata);
    setField(request, "data", bucket);
    setField(request, "uploadFrom", ClientPutBase.UploadFrom.DISK);
    setField(request, "origFilename", origFile);
    setField(request, "ctx", context);
    setField(request, "compressed", true);
    setField(request, "compressing", false);

    UploadFileRequestStatus status = ClientPutStatusSnapshotBuilder.build(request);

    assertEquals("id", status.getIdentifier());
    assertEquals(0, status.getTotalBlocks());
    assertEquals(0, status.getMinBlocks());
    assertEquals(0, status.getFetchedBlocks());
    assertEquals(0, status.getFailedBlocks());
    assertEquals(0, status.getFatalyFailedBlocks());
    assertFalse(status.isTotalFinalized());
    assertEquals(123L, status.getDataSize());
    assertEquals("text/plain", status.getMIMEType());
    assertNotNull(status.getOrigFilename());
    assertNotSame(origFile, status.getOrigFilename());
    assertEquals(origFile.getPath(), status.getOrigFilename().getPath());
    assertEquals(ClientPut.COMPRESS_STATE.WORKING, status.isCompressing());
  }

  @Test
  void build_whenProgressAndFailure_populatesStatusDetails() throws Exception {
    ClientPut request = new ClientPut();
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(bucket.size()).thenReturn(42L);
    DefaultFcpInsertContextHandle context = newContext();
    Instant success = Instant.ofEpochMilli(1000L);
    Instant failure = Instant.ofEpochMilli(2000L);
    SplitfileProgressCounts counts = new SplitfileProgressCounts(10, 3, 2, 1, 5, 0, true);
    SplitfileProgressTimestamps timestamps = new SplitfileProgressTimestamps(success, failure);
    SplitfileProgressEvent event = new SplitfileProgressEvent(counts, timestamps);
    SimpleProgressMessage progressMessage = new SimpleProgressMessage("id", false, event);
    InsertException exception =
        new InsertException(InsertExceptionMode.INTERNAL_ERROR, "oops", null);
    PutFailedMessage failureMessage = new PutFailedMessage(exception, "id", false);
    FreenetURI targetUri = new FreenetURI(VALID_CHK);
    FreenetURI finalUri = new FreenetURI(VALID_CHK);

    setField(request, "identifier", "id");
    setField(request, "uri", targetUri);
    setField(request, "persistence", ClientRequest.Persistence.CONNECTION);
    setField(request, "started", true);
    setField(request, "finished", true);
    setField(request, "succeeded", false);
    setField(request, "priorityClass", (short) 1);
    setField(request, "data", bucket);
    setField(request, "progressMessage", progressMessage);
    setField(request, "putFailedMessage", failureMessage);
    setField(request, "generatedURI", finalUri);
    setField(request, "ctx", context);
    setField(request, "compressed", true);
    setField(request, "compressing", true);

    UploadFileRequestStatus status = ClientPutStatusSnapshotBuilder.build(request);

    assertEquals(10, status.getTotalBlocks());
    assertEquals(5, status.getMinBlocks());
    assertEquals(3, status.getFetchedBlocks());
    assertEquals(2, status.getFailedBlocks());
    assertEquals(1, status.getFatalyFailedBlocks());
    assertTrue(status.isTotalFinalized());
    assertEquals(success, status.getLastSuccess());
    assertEquals(failure, status.getLastFailure());
    assertEquals(failureMessage.getShortFailedMessage(), status.getFailureReason(false));
    assertEquals(failureMessage.getLongFailedMessage(), status.getFailureReason(true));
    assertSame(finalUri, status.getFinalURI());
    assertEquals(targetUri, status.getTargetURI());
    assertEquals(42L, status.getDataSize());
    assertNull(status.getMIMEType());
    assertEquals(ClientPut.COMPRESS_STATE.COMPRESSING, status.isCompressing());
  }

  private File createFile(String name) throws Exception {
    File file = tempDir.resolve(name).toFile();
    assertTrue(file.createNewFile());
    return file;
  }

  private static void setField(Object target, String name, Object value) throws Exception {
    Field field = findField(target.getClass(), name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static DefaultFcpInsertContextHandle newContext() {
    return new DefaultFcpInsertContextHandle(
        new FcpInsertContextLimits(0, 0, 0),
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(false, false, false, 0, null, false, false, false),
            new FcpInsertTuningOptions(
                false, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
            null));
  }

  private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(name);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new NoSuchFieldException(name);
  }
}
