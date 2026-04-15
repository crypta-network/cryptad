package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.ManifestElement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

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
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
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
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "started", true);

    putDir.start(mock(ClientContext.class));

    verify(putter, never()).start(any());
  }

  @Test
  void start_whenPutterThrowsInsertException_invokesOnFailure() throws Exception {
    ClientPutDir putDir = spy(newClientPutDir());
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    doThrow(failure).when(putter).start(any());
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.REBOOT);
    setField(ClientRequest.class, putDir, "client", persistentRequestClient);

    putDir.start(mock(ClientContext.class));

    verify(putDir).onFailure(failure, (FcpInsertCallbackState) null);
  }

  @Test
  void innerResume_whenManifestPresent_delegatesToContainerInserter() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    Map<String, Object> manifest = new HashMap<>();
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    setField(ClientPutDir.class, putDir, "manifestElements", manifest);
    setField(ClientPutDir.class, putDir, "putter", putter);
    ClientContext context = mock(ClientContext.class);

    putDir.innerResume(context);

    verify(putter).resumeMetadata(manifest, context);
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
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    setField(ClientRequest.class, putDir, "finished", true);
    setField(ClientPutBase.class, putDir, "succeeded", false);
    setField(ClientPutDir.class, putDir, "putter", putter);
    when(putter.canRestart()).thenReturn(true);

    assertTrue(putDir.canRestart());
  }

  @Test
  void restart_whenPersistentRequestRestarts_requeuesTagAndUpdatesCache() throws Exception {
    ClientPutDir putDir = spy(newClientPutDir());
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    FCPMessage tagMessage = mock(FCPMessage.class);
    ClientContext context = mock(ClientContext.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    when(putter.canRestart()).thenReturn(true);
    when(putter.restart(context)).thenReturn(true);
    doReturn(tagMessage).when(putDir).persistentTagMessage();
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "identifier", "dir-restart");
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.REBOOT);
    setField(ClientRequest.class, putDir, "client", client);
    setField(ClientRequest.class, putDir, "finished", true);
    setField(ClientPutBase.class, putDir, "succeeded", false);
    setField(ClientPutBase.class, putDir, "generatedURI", mock(FreenetURI.class));

    boolean restarted = putDir.restart(context, false);

    assertTrue(restarted);
    assertNull(getField(ClientPutBase.class, putDir, "generatedURI"));
    assertTrue((boolean) getField(ClientRequest.class, putDir, "started"));
    InOrder order = inOrder(cache);
    order.verify(cache).updateStarted("dir-restart", false);
    order.verify(cache).updateStarted("dir-restart", true);
    verify(client).queueClientRequestMessage(tagMessage, 0);
  }

  @Test
  void getType_alwaysReturnsPutDir() {
    assertEquals(RequestType.PUTDIR, newClientPutDir().getType());
  }

  @Test
  void requestWasRemoved_whenForeverPersistence_clearsPutter() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    setField(ClientPutDir.class, putDir, "putter", putter);
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.FOREVER);
    setField(ClientRequest.class, putDir, "client", persistentRequestClient);
    setField(ClientRequest.class, putDir, "finished", true);

    putDir.requestWasRemoved(mock(ClientContext.class));

    assertNull(getField(ClientPutDir.class, putDir, "putter"));
    verify(persistentRequestClient)
        .queueClientRequestMessage(any(PersistentRequestRemovedMessage.class), anyInt());
    verifyNoInteractions(putter);
  }

  @Test
  void fullyResumed_alwaysReturnsFalse() {
    assertFalse(newClientPutDir().fullyResumed());
  }

  @Test
  void serializationFields_whenInspected_keepLegacyManifestPutterType() {
    ObjectStreamClass descriptor = ObjectStreamClass.lookup(ClientPutDir.class);

    assertEquals(
        "network.crypta.client.async.ManifestPutter",
        descriptor.getField("putter").getType().getName());
  }

  @Test
  void serialization_whenRoundTripped_restoresExecutionFromLegacyManifestPutter() throws Exception {
    ClientPutDir putDir = newClientPutDir();
    ManifestPutter legacyPutter = mock(ManifestPutter.class, withSettings().serializable());
    ClientPutDirExecution execution = mock(ClientPutDirExecution.class);
    when(execution.legacySerializableRequester()).thenReturn(legacyPutter);
    setField(ClientPutDir.class, putDir, "putter", execution);
    setField(ClientPutDir.class, putDir, "manifestElements", new HashMap<>());
    setField(ClientPutDir.class, putDir, "defaultName", "index.html");
    setField(ClientPutBase.class, putDir, "ctx", newSerializableInsertContextHandle());
    setField(ClientRequest.class, putDir, "identifier", "put-dir");
    setField(ClientRequest.class, putDir, "uri", new FreenetURI("CHK", "target"));
    setField(ClientRequest.class, putDir, "persistence", ClientRequest.Persistence.REBOOT);

    ClientPutDir restored = roundTrip(putDir);

    assertInstanceOf(ClientPutDirExecution.class, getField(ClientPutDir.class, restored, "putter"));
    assertInstanceOf(FcpInsertContextHandle.class, getField(ClientPutBase.class, restored, "ctx"));
    ClientPutDirExecution restoredExecution =
        (ClientPutDirExecution) getField(ClientPutDir.class, restored, "putter");
    assertInstanceOf(ManifestPutter.class, restoredExecution.legacySerializableRequester());
    assertInstanceOf(FcpRequesterHandle.class, restored.getClientRequest());
  }

  @Test
  void
      serialization_whenExecutionRequesterIsNotLegacyManifestPutter_throwsNotSerializableException()
          throws Exception {
    ClientPutDir putDir = newClientPutDir();
    ClientRequester requester = mock(ClientRequester.class, withSettings().serializable());
    ClientPutDirExecution execution = mock(ClientPutDirExecution.class);
    when(execution.legacySerializableRequester()).thenReturn(requester);
    setField(ClientPutDir.class, putDir, "putter", execution);

    assertThrows(NotSerializableException.class, () -> roundTrip(putDir));
  }

  @Test
  void executionSpecPriorityClass_whenRequestReprioritized_returnsCurrentPriority()
      throws Exception {
    ClientPutDir putDir = newClientPutDir();
    Map<String, Object> manifest = new HashMap<>();
    setField(ClientRequest.class, putDir, "priorityClass", (short) 6);
    setField(ClientPutDir.class, putDir, "manifestElements", manifest);
    ClientPutDirExecutionSpec spec =
        new ClientPutDirExecutionSpec(
            putDir,
            new ClientRequestParams(
                new FreenetURI("CHK", "target"),
                "put-dir",
                0,
                (short) 1,
                ClientRequest.Persistence.REBOOT,
                false,
                null,
                false),
            mock(FcpInsertContextHandle.class, withSettings().serializable()),
            "index.html",
            null);

    assertEquals(6, spec.priorityClass());
    assertSame(manifest, spec.manifestElements());
  }

  private static ClientPutDir newClientPutDir() {
    return new ClientPutDir();
  }

  private static FcpInsertContextHandle newSerializableInsertContextHandle() {
    return new DefaultFcpInsertContextHandle(
        new SimpleEventProducer(),
        new FcpInsertContextLimits(0, 1, 1),
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(false, false, false, 1, false, false, false),
            new FcpInsertTuningOptions(
                true, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
            null));
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

  private static ClientPutDir roundTrip(ClientPutDir value) throws Exception {
    byte[] serialized;
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
      objectOutput.writeObject(value);
      objectOutput.flush();
      serialized = output.toByteArray();
    }
    try (ObjectInputStream objectInput =
        new ObjectInputStream(new ByteArrayInputStream(serialized))) {
      return (ClientPutDir) objectInput.readObject();
    }
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
