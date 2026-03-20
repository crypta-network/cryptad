package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ContainerInserter;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.ManifestElement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutDirTest {

  @Mock private PersistentRequestClient persistentRequestClient;

  @Test
  void register_whenPersistentAndTagsRequested_registersAndQueuesTagMessage() throws Exception {
    FCPMessage message = mock(FCPMessage.class);
    ClientPutDir putDir = newClientPutDirWithPersistentMessage(message);
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.FOREVER);
    setField(ClientRequest.class, putDir, "client", persistentRequestClient);

    putDir.register(false);

    verify(persistentRequestClient).register(putDir);
    verify(persistentRequestClient).queueClientRequestMessage(message, 0);
  }

  @Test
  void register_whenNoTagsRequested_doesNotQueuePersistentMessage() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.FOREVER);
    setField(ClientRequest.class, putDir, "client", persistentRequestClient);

    putDir.register(true);

    verify(persistentRequestClient).register(putDir);
    verify(persistentRequestClient, never())
        .queueClientRequestMessage(any(FCPMessage.class), anyInt());
  }

  @Test
  void freeData_whenManifestContainsNestedElements_freesAllEntries() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    ManifestElement fileElement = mock(ManifestElement.class);
    ManifestElement nestedElement = mock(ManifestElement.class);
    Map<String, Object> nested = new HashMap<>();
    nested.put("inner", nestedElement);
    Map<String, Object> manifest = new HashMap<>();
    manifest.put("file", fileElement);
    manifest.put("dir", nested);
    setField(ClientPutDir.class, putDir, "manifestElements", new HashMap<>(manifest));

    putDir.freeData();

    verify(fileElement).freeData();
    verify(nestedElement).freeData();
    assertNull(getManifestElements(putDir));
  }

  @Test
  void getStatus_whenProgressAvailable_returnsCombinedSnapshot() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    String identifier = "req-42";
    setField(ClientRequest.class, putDir, "identifier", identifier);
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.FOREVER);
    setField(ClientRequest.class, putDir, "started", true);
    setField(ClientRequest.class, putDir, "finished", true);
    setField(ClientPutBase.class, putDir, "succeeded", false);
    setField(ClientRequest.class, putDir, "priorityClass", (short) 5);
    FreenetURI finalUri = mock(FreenetURI.class);
    FreenetURI targetUri = mock(FreenetURI.class);
    setField(ClientPutBase.class, putDir, "generatedURI", finalUri);
    setField(ClientRequest.class, putDir, "uri", targetUri);
    setField(ClientPutBase.class, putDir, "publicURI", targetUri);
    setField(ClientPutDir.class, putDir, "totalSize", 2048L);
    setField(ClientPutDir.class, putDir, "numberOfFiles", 7);
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(50, 10, 4, 2, 20, 5, true),
            new SplitfileProgressTimestamps(
                Instant.ofEpochMilli(1000), Instant.ofEpochMilli(2000)));
    setField(
        ClientPutBase.class,
        putDir,
        "progressMessage",
        new SimpleProgressMessage(identifier, false, event));
    InsertException insertException =
        new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    PutFailedMessage failedMessage = new PutFailedMessage(insertException, identifier, false);
    setField(ClientPutBase.class, putDir, "putFailedMessage", failedMessage);

    RequestStatus status = putDir.getStatus();

    assertInstanceOf(UploadDirRequestStatus.class, status);
    UploadDirRequestStatus uploadStatus = (UploadDirRequestStatus) status;
    assertEquals(2048L, uploadStatus.getTotalDataSize());
    assertEquals(7, uploadStatus.getNumberOfFiles());
    assertEquals(finalUri, uploadStatus.getFinalURI());
    assertEquals(targetUri, uploadStatus.getTargetURI());
    assertEquals(50, uploadStatus.getTotalBlocks());
    assertEquals(10, uploadStatus.getFetchedBlocks());
    assertEquals(failedMessage.getLongFailedMessage(), uploadStatus.getFailureReason(false));
    assertNull(uploadStatus.getFailureReason(true));
  }

  @Test
  void start_whenPersistentRequestStarts_updatesCacheAndQueuesTag() throws Exception {
    ClientPutDir putDir = spy(newClientPutDir());
    ManifestPutter putter = mock(ManifestPutter.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    FCPMessage tagMessage = mock(FCPMessage.class);
    ClientContext context = mock(ClientContext.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    doReturn(tagMessage).when(putDir).persistentTagMessage();
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "identifier", "dir-start");
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.REBOOT);
    setField(ClientRequest.class, putDir, "client", client);

    putDir.start(context);

    verify(putter).start(context);
    verify(cache).updateStarted("dir-start", true);
    verify(client).queueClientRequestMessage(tagMessage, 0);
    assertTrue((boolean) getField(ClientRequest.class, putDir, "started"));
  }

  @Test
  void start_whenAlreadyStarted_doesNothing() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    ManifestPutter putter = mock(ManifestPutter.class);
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "started", true);

    putDir.start(mock(ClientContext.class));

    verify(putter, never()).start(any());
  }

  @Test
  void start_whenPutterThrowsInsertException_invokesOnFailure() throws Exception {
    ClientPutDir putDir = spy(newClientPutDir());
    ManifestPutter putter = mock(ManifestPutter.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    doThrow(failure).when(putter).start(any());
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.REBOOT);
    setField(ClientRequest.class, putDir, "client", persistentRequestClient);

    putDir.start(mock(ClientContext.class));

    verify(putDir).onFailure(failure, null);
  }

  @Test
  void innerResume_whenManifestPresent_delegatesToContainerInserter() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    Map<String, Object> manifest = new HashMap<>();
    setField(ClientPutDir.class, putDir, "manifestElements", manifest);
    ClientContext context = mock(ClientContext.class);

    try (MockedStatic<ContainerInserter> mocked = mockStatic(ContainerInserter.class)) {
      putDir.innerResume(context);
      mocked.verify(() -> ContainerInserter.resumeMetadata(manifest, context));
    }
  }

  @Test
  void canRestart_whenNotFinished_returnsFalse() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    setField(ClientRequest.class, putDir, "finished", false);

    assertFalse(putDir.canRestart());
  }

  @Test
  void canRestart_whenFinishedAndSucceeded_returnsFalse() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    setField(ClientRequest.class, putDir, "finished", true);
    setField(ClientPutBase.class, putDir, "succeeded", true);

    assertFalse(putDir.canRestart());
  }

  @Test
  void canRestart_whenFinishedAndFailed_returnsTrue() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    setField(ClientRequest.class, putDir, "finished", true);
    setField(ClientPutBase.class, putDir, "succeeded", false);

    assertTrue(putDir.canRestart());
  }

  @Test
  void getType_alwaysReturnsPutDir() {
    assertEquals(RequestType.PUTDIR, newClientPutDir().getType());
  }

  @Test
  void requestWasRemoved_whenForeverPersistence_clearsPutter() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    ManifestPutter putter = mock(ManifestPutter.class);
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.FOREVER);
    setField(ClientRequest.class, putDir, "client", persistentRequestClient);
    setField(ClientRequest.class, putDir, "finished", true);

    putDir.requestWasRemoved(mock(ClientContext.class));

    assertNull(getField(ClientPutDir.class, putDir, "putter"));
    verify(persistentRequestClient)
        .queueClientRequestMessage(any(PersistentRequestRemovedMessage.class), anyInt());
    verify(putter, never()).cancel(any());
  }

  @Test
  void fullyResumed_alwaysReturnsFalse() {
    assertFalse(newClientPutDir().fullyResumed());
  }

  private static ClientPutDir newClientPutDir() {
    return new ClientPutDir();
  }

  private static ClientPutDir newClientPutDirWithPersistentMessage(FCPMessage message) {
    ClientPutDir putDir = spy(newClientPutDir());
    doReturn(message).when(putDir).persistentTagMessage();
    return putDir;
  }

  private static void setField(Class<?> owner, Object target, String name, Object value)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static Object getManifestElements(ClientPutDir target)
      throws ReflectiveOperationException {
    return MANIFEST_ELEMENTS_FIELD.get(target);
  }

  private static Object getField(Class<?> owner, Object target, String name)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static final Field MANIFEST_ELEMENTS_FIELD;

  static {
    try {
      MANIFEST_ELEMENTS_FIELD = ClientPutDir.class.getDeclaredField("manifestElements");
      MANIFEST_ELEMENTS_FIELD.setAccessible(true);
    } catch (ReflectiveOperationException e) {
      throw new ExceptionInInitializerError(e);
    }
  }
}
