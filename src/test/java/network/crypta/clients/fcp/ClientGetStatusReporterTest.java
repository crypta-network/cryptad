package network.crypta.clients.fcp;

import java.io.File;
import java.lang.reflect.Field;
import java.time.Instant;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetStatusReporterTest {

  @Test
  void constructor_whenRequestNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new ClientGetStatusReporter(null));
  }

  @Test
  void getFailureReason_whenNoFailureRecorded_returnsNull() {
    ClientGet request = new ClientGet();
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertNull(reporter.getFailureReason(false));
    assertNull(reporter.getFailureReason(true));
  }

  @Test
  void getFailureReason_whenLongDescriptionAndExtraPresent_appendsExtraText() {
    ClientGet request = new ClientGet();
    FetchException failure = new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND, "details");
    GetFailedMessage message = new GetFailedMessage(failure, "req", false);
    request.state().setFailedMessage(message);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertEquals(message.getShortFailedMessage(), reporter.getFailureReason(false));
    assertEquals(
        message.getShortFailedMessage() + ": " + message.extraDescription,
        reporter.getFailureReason(true));
  }

  @Test
  void getFailureReason_whenLongDescriptionWithoutExtra_returnsShortSummaryOnly() {
    ClientGet request = new ClientGet();
    FetchException failure = new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND);
    GetFailedMessage message = new GetFailedMessage(failure, "req", false);
    request.state().setFailedMessage(message);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertEquals(message.getShortFailedMessage(), reporter.getFailureReason(true));
  }

  @Test
  void getFailureReasonCode_whenNoFailureRecorded_returnsNull() {
    ClientGet request = new ClientGet();
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertNull(reporter.getFailureReasonCode());
  }

  @Test
  void getFailureReasonCode_whenFailurePresent_returnsFailureMode() {
    ClientGet request = new ClientGet();
    FetchException failure = new FetchException(FetchExceptionMode.CONTENT_HASH_FAILED);
    request.state().setFailedMessage(new GetFailedMessage(failure, "req", false));
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertEquals(FetchExceptionMode.CONTENT_HASH_FAILED, reporter.getFailureReasonCode());
  }

  @Test
  void isTotalFinalized_whenFinishedAndSucceeded_returnsTrue() throws ReflectiveOperationException {
    ClientGet request = new ClientGet();
    setClientRequestField(request, "finished", true);
    request.state().setSucceeded(true);
    request.state().setProgressPending(null);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertTrue(reporter.isTotalFinalized());
  }

  @Test
  void isTotalFinalized_whenNoProgressAndNotSuccessful_returnsFalse()
      throws ReflectiveOperationException {
    ClientGet request = new ClientGet();
    setClientRequestField(request, "finished", false);
    request.state().setSucceeded(false);
    request.state().setProgressPending(null);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertFalse(reporter.isTotalFinalized());
  }

  @Test
  void isTotalFinalized_whenProgressPresent_usesProgressFlag() {
    ClientGet request = new ClientGet();
    SimpleProgressMessage progress = mock(SimpleProgressMessage.class);
    when(progress.isTotalFinalized()).thenReturn(true);
    request.state().setProgressPending(progress);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertTrue(reporter.isTotalFinalized());
  }

  @Test
  void progressAccessors_whenNoProgress_returnReporterDefaults() {
    ClientGet request = new ClientGet();
    request.state().setProgressPending(null);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertEquals(-1.0, reporter.getSuccessFraction());
    assertEquals(1.0, reporter.getTotalBlocks());
    assertEquals(1.0, reporter.getMinBlocks());
    assertEquals(0.0, reporter.getFailedBlocks());
    assertEquals(0.0, reporter.getFatalyFailedBlocks());
    assertEquals(0.0, reporter.getFetchedBlocks());
  }

  @Test
  void progressAccessors_whenProgressPresent_returnProgressValues() {
    ClientGet request = new ClientGet();
    SimpleProgressMessage progress = mock(SimpleProgressMessage.class);
    when(progress.getFraction()).thenReturn(0.75);
    when(progress.getTotalBlocks()).thenReturn(12.0);
    when(progress.getMinBlocks()).thenReturn(10.0);
    when(progress.getFailedBlocks()).thenReturn(1.0);
    when(progress.getFatalyFailedBlocks()).thenReturn(2.0);
    when(progress.getFetchedBlocks()).thenReturn(9.0);
    request.state().setProgressPending(progress);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    assertEquals(0.75, reporter.getSuccessFraction());
    assertEquals(12.0, reporter.getTotalBlocks());
    assertEquals(10.0, reporter.getMinBlocks());
    assertEquals(1.0, reporter.getFailedBlocks());
    assertEquals(2.0, reporter.getFatalyFailedBlocks());
    assertEquals(9.0, reporter.getFetchedBlocks());
  }

  @Test
  void getStatus_whenCalled_delegatesWithComposedSnapshotAndReturnsBuildResult() throws Exception {
    ClientGet request = new ClientGet();
    setClientRequestField(request, "identifier", "req-status");
    setClientRequestField(request, "started", true);
    setClientRequestField(request, "finished", false);
    setClientRequestField(request, "priorityClass", (short) 5);
    setClientRequestField(request, "uri", new FreenetURI("KSK@status"));
    ClientGetTestProfiles.setReturnType(request, ClientGet.ReturnType.DIRECT);
    ClientGetTestProfiles.setTargetFile(request, new File("download.bin"));
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    ClientGetTestProfiles.setFetchConfig(request, fetchConfig);

    Bucket bucket = mock(Bucket.class);
    request.state().setReturnBucketDirect(bucket);
    request.state().setFoundDataLength(123L);
    request.state().setFoundDataMimeType("text/plain");
    request.state().setSucceeded(false);
    byte[] splitfileKey = new byte[] {7, 8, 9, 10};
    FcpCompatibilityAnalysis analyser = new FcpCompatibilityAnalysis();
    analyser.merge(
        FcpCompatibilityMode.COMPAT_1250,
        FcpCompatibilityMode.COMPAT_1468,
        splitfileKey,
        false,
        false);
    request.state().setCompatibilityAnalyser(analyser);

    SimpleProgressMessage progress = mock(SimpleProgressMessage.class);
    when(progress.getTotalBlocks()).thenReturn(20.0);
    when(progress.getMinBlocks()).thenReturn(15.0);
    when(progress.getFetchedBlocks()).thenReturn(11.0);
    when(progress.getFailedBlocks()).thenReturn(2.0);
    when(progress.getFatalyFailedBlocks()).thenReturn(1.0);
    when(progress.getLatestSuccess()).thenReturn(Instant.ofEpochMilli(1_000L));
    when(progress.getLatestFailure()).thenReturn(Instant.ofEpochMilli(2_000L));
    when(progress.isTotalFinalized()).thenReturn(false);
    request.state().setProgressPending(progress);

    FetchException failure =
        new FetchException(FetchExceptionMode.CONTENT_VALIDATION_FAILED, "bad");
    GetFailedMessage message = new GetFailedMessage(failure, "req-status", false);
    request.state().setFailedMessage(message);

    RequestStatus expected = mock(RequestStatus.class);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    try (MockedStatic<ClientGetGetterFactory> mocked =
        org.mockito.Mockito.mockStatic(ClientGetGetterFactory.class)) {
      final ClientGetStatusSnapshot[] captured = new ClientGetStatusSnapshot[1];
      mocked
          .when(() -> ClientGetGetterFactory.buildStatus(any(ClientGetStatusSnapshot.class)))
          .thenAnswer(
              invocation -> {
                captured[0] = invocation.getArgument(0);
                return expected;
              });

      RequestStatus status = reporter.getStatus();

      assertSame(expected, status);
      ClientGetStatusSnapshot snapshot = captured[0];
      assertSame(progress, snapshot.progressPending());
      assertSame(message, snapshot.failedMessage());
      assertEquals("req-status", snapshot.identifier());
      assertTrue(snapshot.started());
      assertEquals("text/plain", snapshot.foundDataMimeType());
      assertEquals(123L, snapshot.foundDataLength());
      assertEquals("download.bin", snapshot.destinationFile().getPath());
      assertSame(bucket, snapshot.dataBucket());
      assertEquals(fetchConfig, snapshot.fetchConfig());
      assertArrayEquals(
          new FcpCompatibilityMode[] {
            FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468
          },
          snapshot.compatModes());
      assertArrayEquals(splitfileKey, snapshot.splitfileKey());
      assertEquals("KSK@status", snapshot.uri().toString());
      assertFalse(snapshot.dontCompress());
      RequestStatusSnapshot statusSnapshot = snapshot.statusSnapshot();
      assertEquals(20, statusSnapshot.total());
      assertEquals(11, statusSnapshot.fetched());
      assertEquals(2, statusSnapshot.failed());
      assertEquals(1, statusSnapshot.fatal());
      assertEquals(Instant.ofEpochMilli(1_000L), statusSnapshot.latestSuccess());
      assertEquals(Instant.ofEpochMilli(2_000L), statusSnapshot.latestFailure());
      assertFalse(statusSnapshot.totalFinalized());
    }
  }

  @Test
  void getStatus_whenFinishedAndSucceeded_forcesTotalFinalizedInStatusSnapshot() throws Exception {
    ClientGet request = new ClientGet();
    setClientRequestField(request, "identifier", "req-finished");
    setClientRequestField(request, "finished", true);
    setClientRequestField(request, "started", true);
    ClientGetTestProfiles.setReturnType(request, ClientGet.ReturnType.NONE);
    ClientGetTestProfiles.setFetchConfig(request, new ClientGetFetchConfig());
    request.state().setSucceeded(true);
    SimpleProgressMessage progress = mock(SimpleProgressMessage.class);
    when(progress.isTotalFinalized()).thenReturn(false);
    when(progress.getTotalBlocks()).thenReturn(2.0);
    when(progress.getMinBlocks()).thenReturn(2.0);
    when(progress.getFetchedBlocks()).thenReturn(2.0);
    when(progress.getFailedBlocks()).thenReturn(0.0);
    when(progress.getFatalyFailedBlocks()).thenReturn(0.0);
    when(progress.getLatestSuccess()).thenReturn(Instant.ofEpochMilli(500L));
    when(progress.getLatestFailure()).thenReturn(null);
    request.state().setProgressPending(progress);

    RequestStatus expected = mock(RequestStatus.class);
    ClientGetStatusReporter reporter = new ClientGetStatusReporter(request);

    try (MockedStatic<ClientGetGetterFactory> mocked =
        org.mockito.Mockito.mockStatic(ClientGetGetterFactory.class)) {
      final ClientGetStatusSnapshot[] captured = new ClientGetStatusSnapshot[1];
      mocked
          .when(() -> ClientGetGetterFactory.buildStatus(any(ClientGetStatusSnapshot.class)))
          .thenAnswer(
              invocation -> {
                captured[0] = invocation.getArgument(0);
                return expected;
              });

      assertSame(expected, reporter.getStatus());
      assertTrue(captured[0].statusSnapshot().totalFinalized());
    }
  }

  @SuppressWarnings({"java:S3011"})
  private static void setClientRequestField(ClientRequest target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }
}
