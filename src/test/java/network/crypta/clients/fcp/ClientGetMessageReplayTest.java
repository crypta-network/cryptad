package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetMessageReplayTest {

  @Test
  void sendPendingMessages_whenOnlyDataFalse_expectTagProgressAndMetadataMessages()
      throws Exception {
    // Arrange
    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    when(fetchContext.getMaxNonSplitfileRetries()).thenReturn(3);
    when(fetchContext.getMaxOutputLength()).thenReturn(1_000L);
    RequestClient requestClient = Mockito.mock(RequestClient.class);
    when(requestClient.realTimeFlag()).thenReturn(false);
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.getGlobalForeverClient();
    FreenetURI uri = new FreenetURI("SSK@");
    SplitfileProgressCounts counts = new SplitfileProgressCounts(10, 5, 1, 0, 5, 5, true);
    SplitfileProgressTimestamps timestamps = new SplitfileProgressTimestamps(Instant.EPOCH, null);
    SimpleProgressMessage progressMessage =
        new SimpleProgressMessage("req-1", true, new SplitfileProgressEvent(counts, timestamps));
    HashResult[] hashes = {new HashResult(HashType.SHA256, new byte[32])};
    ExpectedHashes expectedHashes = new ExpectedHashes(hashes, "req-1", true);
    ClientGet request =
        newRequest(
            uri,
            "req-1",
            true,
            Persistence.FOREVER,
            client,
            fetchContext,
            requestClient,
            ReturnType.DIRECT);
    request.state().setProgressPending(progressMessage);
    request.state().markSentToNetwork();
    setField(request, "finished", false);
    request.state().setCompatibilityAnalyser(new CompatibilityAnalyser());
    request.state().setExpectedHashes(expectedHashes);
    request.state().setFoundDataMimeType("text/plain");
    request.state().setFoundDataLength(64L);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);
    FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class);
    FCPConnectionOutputHandler outputHandler = new FCPConnectionOutputHandler(handler);
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);

    // Act
    replay.sendPendingMessages(outputHandler, "list-1", false, false);

    // Assert
    verify(handler, times(7)).send(captor.capture());
    List<String> names = captor.getAllValues().stream().map(FCPMessage::getName).toList();
    assertTrue(
        names.containsAll(
            List.of(
                "PersistentGet",
                "SimpleProgress",
                "SendingToNetwork",
                "CompatibilityMode",
                "ExpectedHashes",
                "ExpectedMIME",
                "ExpectedDataLength")));
    SimpleFieldSet fieldSet = captor.getAllValues().getFirst().getFieldSet();
    assertEquals("list-1", fieldSet.get("ListRequestIdentifier"));
  }

  @Test
  void sendPendingMessages_whenOnlyDataTrueAndNonDirect_expectProtocolErrorOnly() throws Exception {
    // Arrange
    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    RequestClient requestClient = Mockito.mock(RequestClient.class);
    PersistentRequestClient client =
        new PersistentRequestClient("client", null, false, null, Persistence.REBOOT, null);
    ClientGet request =
        newRequest(
            FreenetURI.EMPTY_CHK_URI,
            "req-2",
            false,
            Persistence.REBOOT,
            client,
            fetchContext,
            requestClient,
            ReturnType.NONE);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);
    FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class);
    FCPConnectionOutputHandler outputHandler = new FCPConnectionOutputHandler(handler);
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);

    // Act
    replay.sendPendingMessages(outputHandler, "list-2", false, true);

    // Assert
    verify(handler).send(captor.capture());
    assertEquals("ProtocolError", captor.getValue().getName());
  }

  @Test
  void queueProgressMessageInner_whenConnectionPersistence_expectSentToOriginHandler()
      throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    FCPConnectionHandler origHandler = Mockito.mock(FCPConnectionHandler.class);
    setField(request, "persistence", Persistence.CONNECTION);
    setField(request, "origHandler", origHandler);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);
    FCPMessage message = Mockito.mock(FCPMessage.class);

    // Act
    replay.queueProgressMessageInner(message, 0);

    // Assert
    verify(origHandler).send(message);
  }

  @Test
  void queueProgressMessageInner_whenPersistent_expectQueuedOnClient() throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    setField(request, "persistence", Persistence.REBOOT);
    setField(request, "client", client);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);
    FCPMessage message = Mockito.mock(FCPMessage.class);

    // Act
    replay.queueProgressMessageInner(message, 4);

    // Assert
    verify(client).queueClientRequestMessage(message, 4);
  }

  @Test
  void trySendDataFoundOrGetFailed_whenSucceededConnection_expectDataFoundSentToHandler()
      throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    FCPConnectionHandler origHandler = Mockito.mock(FCPConnectionHandler.class);
    setField(request, "identifier", "req-3");
    setField(request, "global", false);
    setField(request, "persistence", Persistence.CONNECTION);
    setField(request, "origHandler", origHandler);
    setField(request, "startupTime", 5L);
    setField(request, "completionTime", 12L);
    request.state().setFoundDataLength(99L);
    request.state().setFoundDataMimeType("text/plain");
    request.state().setSucceeded(true);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);

    // Act
    replay.trySendDataFoundOrGetFailed(null, "list-3");

    // Assert
    verify(origHandler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    assertEquals("DataFound", sent.getName());
    SimpleFieldSet fieldSet = sent.getFieldSet();
    assertEquals("req-3", fieldSet.get("Identifier"));
    assertEquals(99L, fieldSet.getLong("DataLength", -1L));
    assertEquals("text/plain", fieldSet.get("Metadata.ContentType"));
    assertEquals(12L, fieldSet.getLong("CompletionTime", -1L));
    assertEquals("list-3", fieldSet.get("ListRequestIdentifier"));
  }

  @Test
  void trySendDataFoundOrGetFailed_whenFailedPersistent_expectQueuedFailedMessage()
      throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    PersistentRequestClient client = Mockito.mock(PersistentRequestClient.class);
    FetchException failure = new FetchException(FetchExceptionMode.INTERNAL_ERROR);
    GetFailedMessage failedMessage = new GetFailedMessage(failure, "req-4", true);
    setField(request, "identifier", "req-4");
    setField(request, "global", true);
    setField(request, "persistence", Persistence.REBOOT);
    setField(request, "client", client);
    request.state().setSucceeded(false);
    request.state().setFailedMessage(failedMessage);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);

    // Act
    replay.trySendDataFoundOrGetFailed(null, "list-4");

    // Assert
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(client).queueClientRequestMessage(captor.capture(), eq(0));
    assertEquals("GetFailed", captor.getValue().getName());
    assertEquals("list-4", captor.getValue().getFieldSet().get("ListRequestIdentifier"));
  }

  @Test
  void trySendAllDataMessage_whenDirectAndHandlerProvided_expectAllDataSent() throws Exception {
    // Arrange
    ClientGet request = new ClientGet();
    Bucket bucket = Mockito.mock(Bucket.class);
    when(bucket.size()).thenReturn(55L);
    setField(request, "identifier", "req-5");
    setField(request, "global", false);
    setField(request, "startupTime", 1L);
    setField(request, "completionTime", 2L);
    request.state().setFoundDataMimeType("application/octet-stream");
    setField(request, "returnType", ReturnType.DIRECT);
    request.state().setReturnBucketDirect(bucket);
    setField(request, "persistence", Persistence.REBOOT);
    ClientGetMessageReplay replay = new ClientGetMessageReplay(request);
    FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class);
    FCPConnectionOutputHandler outputHandler = new FCPConnectionOutputHandler(handler);
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);

    // Act
    replay.trySendAllDataMessage(outputHandler, "list-5");

    // Assert
    verify(handler).send(captor.capture());
    assertEquals("AllData", captor.getValue().getName());
    assertEquals("list-5", captor.getValue().getFieldSet().get("ListRequestIdentifier"));
  }

  private static ClientGet newRequest(
      FreenetURI uri,
      String identifier,
      boolean global,
      Persistence persistence,
      PersistentRequestClient client,
      FetchContext fetchContext,
      RequestClient requestClient,
      ReturnType returnType)
      throws Exception {
    ClientGet request = new ClientGet();
    setField(request, "uri", uri);
    setField(request, "identifier", identifier);
    setField(request, "verbosity", 1);
    setField(request, "priorityClass", (short) 1);
    setField(request, "persistence", persistence);
    setField(request, "clientToken", "token");
    setField(request, "started", true);
    setField(request, "client", client);
    setField(request, "returnType", returnType);
    setField(request, "targetFile", new File("target.bin"));
    setField(request, "binaryBlob", false);
    setField(request, "fctx", fetchContext);
    setField(request, "lowLevelClient", requestClient);
    setField(request, "global", global);
    return request;
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = null;
    Class<?> type = target.getClass();
    while (type != null && field == null) {
      try {
        field = type.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        type = type.getSuperclass();
      }
    }
    if (field == null) {
      throw new NoSuchFieldException(fieldName);
    }
    field.setAccessible(true);
    field.set(target, value);
  }
}
