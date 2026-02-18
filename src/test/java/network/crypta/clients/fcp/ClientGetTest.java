package network.crypta.clients.fcp;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.time.Instant;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetTest {

  @Mock private FetchContext fetchContext;
  @Mock private Bucket directBucket;

  @Test
  void getBucket_whenReturnTypeDirect_returnsSameBucket() {
    ClientGet clientGet = newClientGet();
    setField(clientGet, "returnType", ReturnType.DIRECT);
    clientGet.state().setReturnBucketDirect(directBucket);

    Bucket bucket = clientGet.getBucket();

    assertSame(directBucket, bucket);
  }

  @Test
  void getBucket_whenReturnTypeDisk_createsBucketForTargetFile(@TempDir Path tempDir) {
    ClientGet clientGet = newClientGet();
    setField(clientGet, "returnType", ReturnType.DISK);
    File target = tempDir.resolve("download.bin").toFile();
    setField(clientGet, "targetFile", target);

    Bucket bucket = clientGet.getBucket();

    assertInstanceOf(FileBucket.class, bucket);
    FileBucket fileBucket = (FileBucket) bucket;
    assertEquals(target.getAbsoluteFile(), fileBucket.getFile());
  }

  @Test
  void getBucket_whenReturnTypeNone_returnsNull() {
    ClientGet clientGet = newClientGet();
    setField(clientGet, "returnType", ReturnType.NONE);

    assertNull(clientGet.getBucket());
  }

  @Test
  void progressAccessors_whenProgressPresent_returnEventValues() {
    ClientGet clientGet = newClientGet();
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(10, 7, 2, 1, 8, 5, true),
            new SplitfileProgressTimestamps(
                Instant.ofEpochMilli(1_000L), Instant.ofEpochMilli(2_000L)));
    SimpleProgressMessage progress = new SimpleProgressMessage("req", false, event);
    clientGet.state().setProgressPending(progress);

    assertEquals(0.7, clientGet.getSuccessFraction());
    assertEquals(10, clientGet.getTotalBlocks());
    assertEquals(8, clientGet.getMinBlocks());
    assertEquals(2, clientGet.getFailedBlocks());
    assertEquals(1, clientGet.getFatalyFailedBlocks());
    assertEquals(7, clientGet.getFetchedBlocks());
    assertTrue(clientGet.isTotalFinalized());
  }

  @Test
  void progressAccessors_whenProgressMissing_returnDefaultValues() {
    ClientGet clientGet = newClientGet();
    clientGet.state().setProgressPending(null);
    setField(clientGet, "finished", false);
    clientGet.state().setSucceeded(false);

    assertEquals(-1, clientGet.getSuccessFraction());
    assertEquals(1, clientGet.getTotalBlocks());
    assertEquals(1, clientGet.getMinBlocks());
    assertEquals(0, clientGet.getFailedBlocks());
    assertEquals(0, clientGet.getFatalyFailedBlocks());
    assertEquals(0, clientGet.getFetchedBlocks());
    assertFalse(clientGet.isTotalFinalized());
  }

  @Test
  void getFailureReason_whenLongDescriptionRequested_appendsExtraInfo() {
    ClientGet clientGet = newClientGet();
    FetchException exception =
        new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND, "explanation");
    GetFailedMessage message = new GetFailedMessage(exception, "req", false);
    clientGet.state().setFailedMessage(message);

    String result = clientGet.getFailureReason(true);

    assertEquals(message.getShortFailedMessage() + ": " + message.extraDescription, result);
  }

  @Test
  void getFailureReason_whenShortDescriptionRequested_ignoresExtraInfo() {
    ClientGet clientGet = newClientGet();
    FetchException exception = new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND, "details");
    GetFailedMessage message = new GetFailedMessage(exception, "req", false);
    clientGet.state().setFailedMessage(message);

    assertEquals(message.getShortFailedMessage(), clientGet.getFailureReason(false));
  }

  @Test
  void getFailureReason_whenNoFailureRecorded_returnsNull() {
    ClientGet clientGet = newClientGet();
    clientGet.state().setFailedMessage(null);

    assertNull(clientGet.getFailureReason(true));
  }

  @Test
  void getFailureReasonCode_whenFailurePresent_returnsMode() {
    ClientGet clientGet = newClientGet();
    FetchException exception = new FetchException(FetchExceptionMode.INTERNAL_ERROR, "boom");
    GetFailedMessage message = new GetFailedMessage(exception, "req", false);
    clientGet.state().setFailedMessage(message);

    assertEquals(FetchExceptionMode.INTERNAL_ERROR, clientGet.getFailureReasonCode());
  }

  @Test
  void hasPermRedirect_whenFailureContainsRedirect_returnsTrue() throws Exception {
    ClientGet clientGet = newClientGet();
    FreenetURI redirect = new FreenetURI("KSK@redirect");
    FetchException exception =
        new FetchException(FetchExceptionMode.PERMANENT_REDIRECT, "redirecting", redirect);
    GetFailedMessage message = new GetFailedMessage(exception, "req", false);
    clientGet.state().setFailedMessage(message);

    assertTrue(clientGet.hasPermRedirect());
  }

  @Test
  void hasPermRedirect_whenFailureMissing_returnsFalse() {
    ClientGet clientGet = newClientGet();
    clientGet.state().setFailedMessage(null);

    assertFalse(clientGet.hasPermRedirect());
  }

  @Test
  void compatibilityAccessors_whenAnalyserUpdated_reflectMergedState() {
    ClientGet clientGet = newClientGet();
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] key = new byte[] {1, 2, 3, 4};
    analyser.merge(CompatibilityMode.COMPAT_1250, CompatibilityMode.COMPAT_1468, key, false, false);
    clientGet.state().setCompatibilityAnalyser(analyser);

    assertArrayEquals(
        new CompatibilityMode[] {CompatibilityMode.COMPAT_1250, CompatibilityMode.COMPAT_1468},
        clientGet.getCompatibilityMode());
    assertFalse(clientGet.getDontCompress());
    assertArrayEquals(key, clientGet.getOverriddenSplitfileCryptoKey());
  }

  @Test
  void filterData_whenFetchContextDemandsFiltering_returnsTrue() {
    when(fetchContext.getFilterData()).thenReturn(true);
    ClientGet clientGet = newClientGet();

    assertTrue(clientGet.filterData());
  }

  @Test
  void getDataSize_whenLengthProvided_returnsValue() {
    ClientGet clientGet = newClientGet();
    clientGet.state().setFoundDataLength(42L);

    assertEquals(42L, clientGet.getDataSize());
  }

  @Test
  void getDataSize_whenLengthMissing_returnsNegativeOne() {
    ClientGet clientGet = newClientGet();
    clientGet.state().setFoundDataLength(0L);

    assertEquals(-1L, clientGet.getDataSize());
  }

  @Test
  void getMimeType_whenValueProvided_returnsIt() {
    ClientGet clientGet = newClientGet();
    clientGet.state().setFoundDataMimeType("text/plain");

    assertEquals("text/plain", clientGet.getMIMEType());
  }

  @Test
  void isDirect_whenConfiguredForDirect_returnsTrue() {
    ClientGet clientGet = newClientGet();
    setField(clientGet, "returnType", ReturnType.DIRECT);

    assertTrue(clientGet.isDirect());
    assertFalse(clientGet.isToDisk());
  }

  @Test
  void isToDisk_whenConfiguredForDisk_returnsTrue() {
    ClientGet clientGet = newClientGet();
    setField(clientGet, "returnType", ReturnType.DISK);

    assertTrue(clientGet.isToDisk());
    assertFalse(clientGet.isDirect());
  }

  private ClientGet newClientGet() {
    ClientGet clientGet = new ClientGet();
    clientGet.state().setCompatibilityAnalyser(new CompatibilityAnalyser());
    setField(clientGet, "fctx", fetchContext);
    return clientGet;
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = findField(target.getClass(), fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException("Unable to set field " + fieldName, e);
    }
  }

  private static Field findField(Class<?> type, String fieldName) {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new IllegalArgumentException("Field not found: " + fieldName);
  }
}
