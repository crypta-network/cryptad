package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import java.time.Instant;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

@SuppressWarnings({"java:S100", "java:S3011"})
class ClientPutDirStatusSnapshotBuilderTest {

  @Test
  void build_whenProgressAndFailurePresent_returnsUploadDirRequestStatus() throws Exception {
    ClientPutDir request = new ClientPutDir();
    Instant success = Instant.ofEpochMilli(1000L);
    Instant failure = Instant.ofEpochMilli(2000L);
    SplitfileProgressCounts counts = new SplitfileProgressCounts(10, 3, 2, 1, 5, 0, true);
    SplitfileProgressTimestamps timestamps = new SplitfileProgressTimestamps(success, failure);
    SplitfileProgressEvent event = new SplitfileProgressEvent(counts, timestamps);
    SimpleProgressMessage progressMessage = new SimpleProgressMessage("id", false, event);
    InsertException exception =
        new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    PutFailedMessage failureMessage = new PutFailedMessage(exception, "id", false);
    FreenetURI finalUri = mock(FreenetURI.class);
    FreenetURI targetUri = mock(FreenetURI.class);

    setField(request, "identifier", "id");
    setField(request, "persistence", ClientRequest.Persistence.FOREVER);
    setField(request, "started", true);
    setField(request, "finished", true);
    setField(request, "succeeded", false);
    setField(request, "priorityClass", (short) 5);
    setField(request, "generatedURI", finalUri);
    setField(request, "uri", targetUri);
    setField(request, "totalSize", 2048L);
    setField(request, "numberOfFiles", 7);
    setField(request, "progressMessage", progressMessage);
    setField(request, "putFailedMessage", failureMessage);

    UploadDirRequestStatus status = ClientPutDirStatusSnapshotBuilder.build(request);

    assertInstanceOf(UploadDirRequestStatus.class, status);
    assertEquals(2048L, status.getTotalDataSize());
    assertEquals(7, status.getNumberOfFiles());
    assertEquals(finalUri, status.getFinalURI());
    assertEquals(targetUri, status.getTargetURI());
    assertEquals(10, status.getTotalBlocks());
    assertEquals(3, status.getFetchedBlocks());
    assertEquals(failureMessage.getLongFailedMessage(), status.getFailureReason(false));
    assertNull(status.getFailureReason(true));
  }

  private static void setField(Object target, String name, Object value) throws Exception {
    Field field = findField(target.getClass(), name);
    field.setAccessible(true);
    field.set(target, value);
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
