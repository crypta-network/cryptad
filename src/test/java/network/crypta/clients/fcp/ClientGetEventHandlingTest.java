package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Date;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.EnterFiniteCooldownEvent;
import network.crypta.client.events.ExpectedFileSizeEvent;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.ExpectedMIMEEvent;
import network.crypta.client.events.SendingToNetworkEvent;
import network.crypta.client.events.SplitfileCompatibilityModeEvent;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetEventHandlingTest {
  private static final String CLIENT_FIELD = "client";
  private static final String EXPECTED_MIME = "text/plain";
  private static final String IDENTIFIER = "id";
  private static final String ALT_IDENTIFIER = "other-id";

  @Test
  void constructor_whenRequestNull_expectNullPointerException() {
    // Arrange
    // Act & Assert
    assertThrows(NullPointerException.class, () -> new ClientGetEventHandling(null));
  }

  @Test
  void receive_whenSplitfileProgressEvent_expectRecordUpdateAndQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            IDENTIFIER,
            ClientGet.VERBOSITY_SPLITFILE_PROGRESS,
            false,
            ClientRequest.Persistence.CONNECTION);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    RequestStatusCache cache = Mockito.mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(request, ClientRequest.class, CLIENT_FIELD, client);
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    SplitfileProgressEvent event = newProgressEvent();

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(request).recordSplitfileProgress(any(SimpleProgressMessage.class));
    verify(cache).updateStatus(IDENTIFIER, event);
    verify(request)
        .queueProgressMessageInner(
            messageCaptor.capture(), eq(ClientGet.VERBOSITY_SPLITFILE_PROGRESS));
    assertInstanceOf(SimpleProgressMessage.class, messageCaptor.getValue());
  }

  @Test
  void receive_whenSplitfileProgressEventAndVerbosityDisabled_expectNoQueueButRecord() {
    // Arrange
    ClientGet request = newRequestWith(IDENTIFIER, 0, false, ClientRequest.Persistence.CONNECTION);
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    SplitfileProgressEvent event = newProgressEvent();

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    verify(request).recordSplitfileProgress(any(SimpleProgressMessage.class));
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  @Test
  void receive_whenSendingToNetworkEvent_expectMarkAndQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            IDENTIFIER,
            ClientGet.VERBOSITY_SENT_TO_NETWORK,
            false,
            ClientRequest.Persistence.CONNECTION);
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetEventHandling handler = new ClientGetEventHandling(request);

    // Act
    handler.receive(new SendingToNetworkEvent(), Mockito.mock(ClientContext.class));

    // Assert
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(request).markSentToNetwork();
    verify(request)
        .queueProgressMessageInner(
            messageCaptor.capture(), eq(ClientGet.VERBOSITY_SENT_TO_NETWORK));
    assertInstanceOf(SendingToNetworkMessage.class, messageCaptor.getValue());
  }

  @Test
  void receive_whenExpectedHashesEventAndTrySetFails_expectNoQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            IDENTIFIER,
            ClientGet.VERBOSITY_EXPECTED_HASHES,
            false,
            ClientRequest.Persistence.CONNECTION);
    Mockito.doReturn(false).when(request).trySetExpectedHashes(any(ExpectedHashes.class));
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    ExpectedHashesEvent event = new ExpectedHashesEvent(new HashResult[] {newSha256Hash()});

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    verify(request).trySetExpectedHashes(any(ExpectedHashes.class));
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  @Test
  void receive_whenExpectedHashesEventAndTrySetSucceeds_expectQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            IDENTIFIER,
            ClientGet.VERBOSITY_EXPECTED_HASHES,
            false,
            ClientRequest.Persistence.CONNECTION);
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    ExpectedHashesEvent event = new ExpectedHashesEvent(new HashResult[] {newSha256Hash()});

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(request)
        .queueProgressMessageInner(
            messageCaptor.capture(), eq(ClientGet.VERBOSITY_EXPECTED_HASHES));
    assertInstanceOf(ExpectedHashes.class, messageCaptor.getValue());
  }

  @Test
  void receive_whenExpectedMimeEvent_expectRecordCacheAndQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            IDENTIFIER,
            ClientGet.VERBOSITY_EXPECTED_TYPE,
            false,
            ClientRequest.Persistence.CONNECTION);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    RequestStatusCache cache = Mockito.mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(request, ClientRequest.class, CLIENT_FIELD, client);
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    ExpectedMIMEEvent event = new ExpectedMIMEEvent(EXPECTED_MIME);

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(request).recordExpectedMimeType(EXPECTED_MIME);
    verify(cache).updateExpectedMIME(IDENTIFIER, EXPECTED_MIME);
    verify(request)
        .queueProgressMessageInner(messageCaptor.capture(), eq(ClientGet.VERBOSITY_EXPECTED_TYPE));
    assertInstanceOf(ExpectedMIME.class, messageCaptor.getValue());
  }

  @Test
  void receive_whenExpectedFileSizeEvent_expectRecordCacheAndQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            IDENTIFIER,
            ClientGet.VERBOSITY_EXPECTED_SIZE,
            false,
            ClientRequest.Persistence.CONNECTION);
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    RequestStatusCache cache = Mockito.mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(request, ClientRequest.class, CLIENT_FIELD, client);
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    ExpectedFileSizeEvent event = new ExpectedFileSizeEvent(42L);

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(request).recordExpectedDataLength(42L);
    verify(cache).updateExpectedDataLength(IDENTIFIER, 42L);
    verify(request)
        .queueProgressMessageInner(messageCaptor.capture(), eq(ClientGet.VERBOSITY_EXPECTED_SIZE));
    assertInstanceOf(ExpectedDataLength.class, messageCaptor.getValue());
  }

  @Test
  void receive_whenEnterFiniteCooldownEvent_expectQueue() {
    // Arrange
    ClientGet request =
        newRequestWith(
            ALT_IDENTIFIER,
            ClientGet.VERBOSITY_ENTER_FINITE_COOLDOWN,
            true,
            ClientRequest.Persistence.CONNECTION);
    doNothing().when(request).queueProgressMessageInner(any(FCPMessage.class), anyInt());
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    EnterFiniteCooldownEvent event = new EnterFiniteCooldownEvent(1_000L);

    // Act
    handler.receive(event, Mockito.mock(ClientContext.class));

    // Assert
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(request)
        .queueProgressMessageInner(
            messageCaptor.capture(), eq(ClientGet.VERBOSITY_ENTER_FINITE_COOLDOWN));
    assertInstanceOf(EnterFiniteCooldown.class, messageCaptor.getValue());
  }

  @Test
  void receive_whenCompatibilityModeEventAndPersistenceForeverLoaded_expectQueuedJobInvokesMerge()
      throws PersistenceDisabledException {
    // Arrange
    ClientGet request = newRequestWith(IDENTIFIER, 0, false, ClientRequest.Persistence.FOREVER);
    doNothing()
        .when(request)
        .mergeCompatibilityMode(
            any(CompatibilityMode.class),
            any(CompatibilityMode.class),
            any(),
            anyBoolean(),
            anyBoolean());
    PersistentJobRunner jobRunner = Mockito.mock(PersistentJobRunner.class);
    when(jobRunner.hasLoaded()).thenReturn(true);
    doNothing().when(jobRunner).queue(any(PersistentJob.class), anyInt());
    ClientContext context = newContextWithJobRunner(jobRunner);
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    SplitfileCompatibilityModeEvent event =
        new SplitfileCompatibilityModeEvent(
            CompatibilityMode.COMPAT_1250,
            CompatibilityMode.COMPAT_1468,
            new byte[] {1, 2, 3},
            true,
            false);

    // Act
    handler.receive(event, context);

    // Assert
    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    ArgumentCaptor<byte[]> keyCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(jobRunner)
        .queue(jobCaptor.capture(), eq(NativeThread.PriorityLevel.HIGH_PRIORITY.value));
    jobCaptor.getValue().run(Mockito.mock(ClientContext.class));
    verify(request)
        .mergeCompatibilityMode(
            eq(CompatibilityMode.COMPAT_1250),
            eq(CompatibilityMode.COMPAT_1468),
            keyCaptor.capture(),
            eq(true),
            eq(false));
    assertArrayEquals(new byte[] {1, 2, 3}, keyCaptor.getValue());
  }

  @Test
  void receive_whenCompatibilityModeEventAndNotForever_expectDirectMerge()
      throws PersistenceDisabledException {
    // Arrange
    ClientGet request = newRequestWith(IDENTIFIER, 0, false, ClientRequest.Persistence.CONNECTION);
    doNothing()
        .when(request)
        .mergeCompatibilityMode(
            any(CompatibilityMode.class),
            any(CompatibilityMode.class),
            any(),
            anyBoolean(),
            anyBoolean());
    PersistentJobRunner jobRunner = Mockito.mock(PersistentJobRunner.class);
    ClientContext context = newContextWithJobRunner(jobRunner);
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    SplitfileCompatibilityModeEvent event =
        new SplitfileCompatibilityModeEvent(
            CompatibilityMode.COMPAT_1250,
            CompatibilityMode.COMPAT_1468,
            new byte[] {4, 5, 6},
            false,
            true);

    // Act
    handler.receive(event, context);

    // Assert
    ArgumentCaptor<byte[]> keyCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(request)
        .mergeCompatibilityMode(
            eq(CompatibilityMode.COMPAT_1250),
            eq(CompatibilityMode.COMPAT_1468),
            keyCaptor.capture(),
            eq(false),
            eq(true));
    assertArrayEquals(new byte[] {4, 5, 6}, keyCaptor.getValue());
    verify(jobRunner, never()).queue(any(PersistentJob.class), anyInt());
  }

  @Test
  void receive_whenCompatibilityModeQueueThrows_expectNoThrow() throws Exception {
    // Arrange
    ClientGet request = newRequestWith(IDENTIFIER, 0, false, ClientRequest.Persistence.FOREVER);
    PersistentJobRunner jobRunner = Mockito.mock(PersistentJobRunner.class);
    when(jobRunner.hasLoaded()).thenReturn(true);
    doThrow(new PersistenceDisabledException())
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());
    ClientContext context = newContextWithJobRunner(jobRunner);
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    SplitfileCompatibilityModeEvent event =
        new SplitfileCompatibilityModeEvent(
            CompatibilityMode.COMPAT_1250,
            CompatibilityMode.COMPAT_1468,
            new byte[] {7, 8, 9},
            true,
            true);

    // Act & Assert
    assertDoesNotThrow(() -> handler.receive(event, context));
  }

  @Test
  void receive_whenUnknownEvent_expectNoQueue() {
    // Arrange
    ClientGet request = newRequestWith(IDENTIFIER, 0, false, ClientRequest.Persistence.CONNECTION);
    ClientGetEventHandling handler = new ClientGetEventHandling(request);
    ClientEvent unknownEvent =
        new ClientEvent() {
          @Override
          public int getCode() {
            return 999;
          }

          @Override
          public String getDescription() {
            return "unknown";
          }
        };

    // Act
    handler.receive(unknownEvent, Mockito.mock(ClientContext.class));

    // Assert
    verify(request, never()).queueProgressMessageInner(any(FCPMessage.class), anyInt());
  }

  private static SplitfileProgressEvent newProgressEvent() {
    return new SplitfileProgressEvent(
        new SplitfileProgressCounts(10, 2, 1, 0, 10, 10, true),
        new SplitfileProgressTimestamps(new Date(0L), new Date(0L)));
  }

  private static HashResult newSha256Hash() {
    return new HashResult(HashType.SHA256, new byte[HashType.SHA256.hashLength]);
  }

  private static ClientGet newRequestWith(
      String identifier, int verbosity, boolean global, ClientRequest.Persistence persistence) {
    ClientGet request =
        Mockito.mock(
            ClientGet.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));
    setField(request, ClientRequest.class, "identifier", identifier);
    setField(request, ClientRequest.class, "verbosity", verbosity);
    setField(request, ClientRequest.class, "global", global);
    setField(request, ClientRequest.class, "persistence", persistence);
    return request;
  }

  private static ClientContext newContextWithJobRunner(PersistentJobRunner jobRunner) {
    ClientContext context =
        Mockito.mock(
            ClientContext.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));
    setField(context, ClientContext.class, "jobRunner", jobRunner);
    return context;
  }

  @SuppressWarnings("java:S3011")
  private static void setField(Object target, Class<?> owner, String fieldName, Object value) {
    try {
      Field field = owner.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to set field: " + fieldName, e);
    }
  }

  private static LinkageError linkageError(String message, ReflectiveOperationException e) {
    LinkageError error = new LinkageError(message);
    error.initCause(e);
    return error;
  }
}
