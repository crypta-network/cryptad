package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetStateTest {

  @Test
  void constructor_whenRequestNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new ClientGetState(null));
  }

  @Test
  void constructor_whenCreated_initializesDefaultState() {
    ClientGet request = new ClientGet();
    ClientGetState state = new ClientGetState(request);

    assertFalse(state.hasSucceeded());
    assertEquals(-1L, state.getFoundDataLength());
    assertNull(state.getFoundDataMimeType());
    assertNull(state.getProgressPending());
    assertFalse(state.hasSentToNetwork());
    assertNull(state.getExpectedHashes());
    assertNull(state.getFailedMessage());
    assertNotNull(state.getCompatibilityAnalyser());
    assertArrayEquals(
        new InsertContext.CompatibilityMode[] {
          InsertContext.CompatibilityMode.COMPAT_UNKNOWN,
          InsertContext.CompatibilityMode.COMPAT_UNKNOWN
        },
        state.getCompatibilityMode());
    assertTrue(state.getDontCompress());
    assertNull(state.getOverriddenSplitfileCryptoKey());
    assertNull(state.getReturnBucketDirect());
  }

  @Test
  void scalarSetters_whenUpdated_reflectLatestValues() {
    ClientGetState state = new ClientGetState(new ClientGet());

    for (boolean expected : new boolean[] {true, false}) {
      state.setSucceeded(expected);
      assertEquals(expected, state.hasSucceeded());
    }
    state.setFoundDataLength(42L);
    state.setFoundDataMimeType("text/plain");

    assertEquals(42L, state.getFoundDataLength());
    assertEquals("text/plain", state.getFoundDataMimeType());
  }

  @Test
  void progressPending_whenSet_reflectsValue() {
    ClientGetState state = new ClientGetState(new ClientGet());
    SimpleProgressMessage progress = mock(SimpleProgressMessage.class);

    state.setProgressPending(progress);
    assertSame(progress, state.getProgressPending());
  }

  @Test
  void markSentToNetwork_whenInvoked_setsFlagTrue() {
    ClientGetState state = new ClientGetState(new ClientGet());

    state.markSentToNetwork();

    assertTrue(state.hasSentToNetwork());
  }

  @Test
  void expectedHashes_whenInitiallyAbsent_trySetStoresAndReturnsTrue() {
    ClientGetState state = new ClientGetState(new ClientGet());
    ExpectedHashes hashes = new ExpectedHashes(new HashResult[0], "req", false);

    assertTrue(state.trySetExpectedHashes(hashes));
    assertSame(hashes, state.getExpectedHashes());
  }

  @Test
  void expectedHashes_whenAlreadyPresent_trySetReturnsFalseAndKeepsOriginal() {
    ClientGetState state = new ClientGetState(new ClientGet());
    ExpectedHashes original = new ExpectedHashes(new HashResult[0], "req-original", false);
    ExpectedHashes replacement = new ExpectedHashes(new HashResult[0], "req-replacement", false);
    state.setExpectedHashes(original);

    assertFalse(state.trySetExpectedHashes(replacement));
    assertSame(original, state.getExpectedHashes());
  }

  @Test
  void expectedHashes_whenCleared_becomesNull() {
    ClientGetState state = new ClientGetState(new ClientGet());
    state.setExpectedHashes(new ExpectedHashes(new HashResult[0], "req", false));

    state.clearExpectedHashes();

    assertNull(state.getExpectedHashes());
  }

  @Test
  void failedMessage_whenSetAndReplaced_reflectsLatestMessage() throws Exception {
    ClientGetState state = new ClientGetState(new ClientGet());
    FetchException failure =
        new FetchException(
            FetchExceptionMode.PERMANENT_REDIRECT, "redirect", new FreenetURI("KSK@redirect"));
    GetFailedMessage message = new GetFailedMessage(failure, "req", false);
    GetFailedMessage replacement = new GetFailedMessage(failure, "req-replacement", false);

    state.setFailedMessage(message);
    assertSame(message, state.getFailedMessage());

    state.setFailedMessage(replacement);
    assertSame(replacement, state.getFailedMessage());
  }

  @Test
  void setCompatibilityAnalyser_whenCustomAnalyserProvided_reflectsMergedValues() {
    ClientGetState state = new ClientGetState(new ClientGet());
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] splitfileKey = new byte[] {1, 2, 3, 4};
    analyser.merge(
        InsertContext.CompatibilityMode.COMPAT_1250,
        InsertContext.CompatibilityMode.COMPAT_1468,
        splitfileKey,
        true,
        false);

    state.setCompatibilityAnalyser(analyser);

    assertSame(analyser, state.getCompatibilityAnalyser());
    assertArrayEquals(
        new InsertContext.CompatibilityMode[] {
          InsertContext.CompatibilityMode.COMPAT_1250, InsertContext.CompatibilityMode.COMPAT_1468
        },
        state.getCompatibilityMode());
    assertTrue(state.getDontCompress());
    assertArrayEquals(splitfileKey, state.getOverriddenSplitfileCryptoKey());
  }

  @Test
  void ensureCompatibilityMode_whenAnalyserMissing_createsNewInstance() {
    ClientGetState state = new ClientGetState(new ClientGet());
    state.setCompatibilityAnalyser(null);

    state.ensureCompatibilityMode();

    assertNotNull(state.getCompatibilityAnalyser());
  }

  @Test
  void ensureCompatibilityMode_whenAnalyserPresent_keepsSameInstance() {
    ClientGetState state = new ClientGetState(new ClientGet());
    CompatibilityAnalyser analyser = state.getCompatibilityAnalyser();

    state.ensureCompatibilityMode();

    assertSame(analyser, state.getCompatibilityAnalyser());
  }

  @Test
  void resetCompatibilityMode_whenInvoked_replacesAnalyserInstance() {
    ClientGetState state = new ClientGetState(new ClientGet());
    CompatibilityAnalyser before = state.getCompatibilityAnalyser();

    state.resetCompatibilityMode();

    assertNotNull(state.getCompatibilityAnalyser());
    assertNotSame(before, state.getCompatibilityAnalyser());
  }

  @Test
  void mergeCompatibilityMode_whenNoClientAndNoVerbosity_updatesAnalyserWithoutQueueing() {
    ClientGet request = spy(new ClientGet());
    ClientGetState state = new ClientGetState(request);
    byte[] splitfileKey = new byte[] {9, 8, 7};

    state.mergeCompatibilityMode(
        InsertContext.CompatibilityMode.COMPAT_1250,
        InsertContext.CompatibilityMode.COMPAT_1468,
        splitfileKey,
        false,
        false);

    assertArrayEquals(
        new InsertContext.CompatibilityMode[] {
          InsertContext.CompatibilityMode.COMPAT_1250, InsertContext.CompatibilityMode.COMPAT_1468
        },
        state.getCompatibilityMode());
    assertArrayEquals(splitfileKey, state.getOverriddenSplitfileCryptoKey());
    assertFalse(state.getDontCompress());
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  @Test
  void mergeCompatibilityMode_whenClientAndVerbosityPresent_updatesCacheAndQueuesMessage()
      throws Exception {
    ClientGet request = spy(new ClientGet());
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetState state = new ClientGetState(request);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setClientRequestField(request, "client", client);
    setClientRequestField(request, "identifier", "req-compat");
    setClientRequestField(request, "global", true);
    setClientRequestField(request, "verbosity", ClientGet.VERBOSITY_COMPATIBILITY_MODE);
    byte[] splitfileKey = new byte[] {3, 1, 4};

    state.mergeCompatibilityMode(
        InsertContext.CompatibilityMode.COMPAT_1250,
        InsertContext.CompatibilityMode.COMPAT_1468,
        splitfileKey,
        true,
        false);

    ArgumentCaptor<InsertContext.CompatibilityMode[]> modesCaptor =
        ArgumentCaptor.forClass(InsertContext.CompatibilityMode[].class);
    verify(cache)
        .updateDetectedCompatModes(
            eq("req-compat"), modesCaptor.capture(), eq(splitfileKey), eq(true));
    assertArrayEquals(
        new InsertContext.CompatibilityMode[] {
          InsertContext.CompatibilityMode.COMPAT_1250, InsertContext.CompatibilityMode.COMPAT_1468
        },
        modesCaptor.getValue());
    verify(request)
        .queueProgressMessageInner(
            any(network.crypta.clients.fcp.CompatibilityMode.class),
            eq(ClientGet.VERBOSITY_COMPATIBILITY_MODE));
  }

  @Test
  void mergeCompatibilityMode_whenClientCacheMissing_skipsCacheUpdateAndQueueWhenVerbosityOff()
      throws Exception {
    ClientGet request = spy(new ClientGet());
    ClientGetState state = new ClientGetState(request);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    when(client.getRequestStatusCache()).thenReturn(null);
    setClientRequestField(request, "client", client);
    setClientRequestField(request, "identifier", "req-no-cache");
    setClientRequestField(request, "verbosity", 0);

    state.mergeCompatibilityMode(
        InsertContext.CompatibilityMode.COMPAT_1250,
        InsertContext.CompatibilityMode.COMPAT_1468,
        new byte[] {5},
        false,
        false);

    verify(client).getRequestStatusCache();
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  @Test
  void returnBucketDirect_whenSetGetAndTake_clearsAfterTake() {
    ClientGetState state = new ClientGetState(new ClientGet());
    Bucket bucket = mock(Bucket.class);
    state.setReturnBucketDirect(bucket);

    assertSame(bucket, state.getReturnBucketDirect());
    assertSame(bucket, state.takeReturnBucketDirect());
    assertNull(state.getReturnBucketDirect());
    assertNull(state.takeReturnBucketDirect());
  }

  @SuppressWarnings({"java:S3011"})
  private static void setClientRequestField(ClientRequest target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }
}
