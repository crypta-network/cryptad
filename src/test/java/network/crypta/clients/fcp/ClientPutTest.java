package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutTest {

  private ClientPut clientPut;
  private DefaultFcpInsertContextHandle insertContext;

  @BeforeEach
  void setUp() throws Exception {
    clientPut = new ClientPut();
    insertContext =
        new DefaultFcpInsertContextHandle(
            new SimpleEventProducer(),
            new FcpInsertContextLimits(0, 1, 1),
            new FcpInsertOptions(
                new FcpInsertBehaviorOptions(false, false, false, 1, null, false, false, false),
                new FcpInsertTuningOptions(
                    true, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
                null));
    setField(ClientPutBase.class, clientPut, "ctx", insertContext);
    setField(ClientPut.class, clientPut, "clientMetadata", new ClientMetadata("text/plain"));
    setField(ClientRequest.class, clientPut, "identifier", "test-id");
    setField(ClientRequest.class, clientPut, "persistence", Persistence.FOREVER);
  }

  @Test
  void getDataSize_whenBucketPresent_returnsUnderlyingSize() throws Exception {
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(bucket.size()).thenReturn(123L);
    setField(ClientPut.class, clientPut, "data", bucket);

    long result = clientPut.getDataSize();

    assertEquals(123L, result);
  }

  @Test
  void getDataSize_whenBucketMissing_returnsFinishedSize() throws Exception {
    setField(ClientPut.class, clientPut, "data", null);
    setField(ClientPut.class, clientPut, "finishedSize", 456L);

    long result = clientPut.getDataSize();

    assertEquals(456L, result);
  }

  @Test
  void getOrigFilename_whenUploadFromDisk_returnsOriginalFile() throws Exception {
    File file = new File("example.dat");
    setField(ClientPut.class, clientPut, "origFilename", file);
    setField(ClientPut.class, clientPut, "uploadFrom", ClientPutBase.UploadFrom.DISK);

    assertSame(file, clientPut.getOrigFilename());
  }

  @Test
  void getOrigFilename_whenUploadIsNotDisk_returnsNull() throws Exception {
    File file = new File("example.dat");
    setField(ClientPut.class, clientPut, "origFilename", file);
    setField(ClientPut.class, clientPut, "uploadFrom", ClientPutBase.UploadFrom.DIRECT);

    assertNull(clientPut.getOrigFilename());
  }

  @Test
  void getMIMEType_whenMetadataPresent_returnsValue() {
    assertEquals("text/plain", clientPut.getMIMEType());
  }

  @Test
  void isDirect_whenUploadFromDirect_returnsTrue() throws Exception {
    setField(ClientPut.class, clientPut, "uploadFrom", ClientPutBase.UploadFrom.DIRECT);

    assertTrue(clientPut.isDirect());
  }

  @Test
  void isCompressing_whenDontCompressConfigured_returnsWorking() {
    insertContext.setDontCompress(true);

    assertEquals(COMPRESS_STATE.WORKING, clientPut.isCompressing());
  }

  @Test
  void isCompressing_whenWaitingOnScheduler_returnsWaiting() throws Exception {
    insertContext.setDontCompress(false);
    setField(ClientPut.class, clientPut, "compressed", false);

    assertEquals(COMPRESS_STATE.WAITING, clientPut.isCompressing());
  }

  @Test
  void isCompressing_whenRestartedAndCompressing_returnsCompressing() throws Exception {
    insertContext.setDontCompress(false);
    setField(ClientPut.class, clientPut, "compressed", true);
    setField(ClientPut.class, clientPut, "compressing", true);

    assertEquals(COMPRESS_STATE.COMPRESSING, clientPut.isCompressing());
  }

  @Test
  void isCompressing_whenCompressionFinished_returnsWorking() {
    insertContext.setDontCompress(false);
    clientPut.onStopCompressing();

    assertEquals(COMPRESS_STATE.WORKING, clientPut.isCompressing());
  }

  @Test
  void onStartCompressing_whenClientHasCache_updatesCache() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientRequest.class, clientPut, "client", client);

    clientPut.onStartCompressing();

    verify(cache).updateCompressionStatus("test-id", COMPRESS_STATE.COMPRESSING);
  }

  @Test
  void onStopCompressing_whenClientHasCache_updatesCacheAndState() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientRequest.class, clientPut, "client", client);

    clientPut.onStopCompressing();

    verify(cache).updateCompressionStatus("test-id", COMPRESS_STATE.WORKING);
    assertEquals(COMPRESS_STATE.WORKING, clientPut.isCompressing());
  }

  @Test
  void freeData_whenBucketPresent_freesAndStoresSize() throws Exception {
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(bucket.size()).thenReturn(77L);
    setField(ClientPut.class, clientPut, "data", bucket);

    clientPut.freeData();

    verify(bucket).free();
    assertEquals(77L, (long) getField(ClientPut.class, clientPut, "finishedSize"));
    assertNull(getField(ClientPut.class, clientPut, "data"));
  }

  @Test
  void register_whenPersistentAndTagsRequested_registersAndQueuesTagMessage() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FCPMessage tagMessage = mock(FCPMessage.class);
    ClientPut put = spy(clientPut);
    setField(ClientRequest.class, put, "persistence", Persistence.FOREVER);
    setField(ClientRequest.class, put, "client", client);
    doReturn(tagMessage).when(put).persistentTagMessage();

    put.register(false);

    verify(client).register(put);
    verify(client).queueClientRequestMessage(tagMessage, 0);
  }

  @Test
  void start_whenPersistentRequestStarts_updatesCacheAndQueuesTag() throws Exception {
    ClientPutExecution putter = createExecution();
    ClientContext context = mock(ClientContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    FCPMessage tagMessage = mock(FCPMessage.class);
    ClientPut put = spy(clientPut);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientPut.class, put, "putter", putter);
    setField(ClientRequest.class, put, "identifier", "start-id");
    setField(ClientRequest.class, put, "persistence", Persistence.REBOOT);
    setField(ClientRequest.class, put, "client", client);
    doReturn(tagMessage).when(put).persistentTagMessage();

    put.start(context);

    verify(putter).start(context);
    verify(client).queueClientRequestMessage(tagMessage, 0);
    verify(cache).updateStarted("start-id", true);
    assertTrue((boolean) getField(ClientRequest.class, put, "started"));
  }

  @Test
  void start_whenPutterThrowsInsertException_invokesOnFailure() throws Exception {
    ClientPutExecution putter = createExecution();
    ClientContext context = mock(ClientContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    ClientPut put = spy(clientPut);
    setField(ClientPut.class, put, "putter", putter);
    setField(ClientRequest.class, put, "persistence", Persistence.REBOOT);
    setField(ClientRequest.class, put, "client", client);
    doThrow(failure).when(putter).start(context);

    put.start(context);

    verify(put).onFailure(failure, null);
  }

  @Test
  void innerResume_whenBucketPresent_delegatesToBucket() throws Exception {
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    setField(ClientPut.class, clientPut, "data", bucket);
    FcpRequestRuntimeContext context = mock(FcpRequestRuntimeContext.class);

    clientPut.innerResume(context);

    verify(bucket).onResume(context);
  }

  @Test
  void innerResume_whenPutterPresent_reappliesDiagnosticIdentifier() throws Exception {
    FcpRequesterHandle requester = mock(FcpRequesterHandle.class);
    ClientPutExecution putter = createExecution(requester);
    setField(ClientPut.class, clientPut, "putter", putter);
    FcpRequestRuntimeContext context = mock(FcpRequestRuntimeContext.class);

    clientPut.innerResume(context);

    verify(requester).setExternalRequestIdentifier("fcp:test-id");
  }

  @Test
  void innerResume_whenBucketThrows_propagatesException() throws Exception {
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    setField(ClientPut.class, clientPut, "data", bucket);
    FcpRequestRuntimeContext context = mock(FcpRequestRuntimeContext.class);
    ResumeFailedException failure = new ResumeFailedException("boom");
    doThrow(failure).when(bucket).onResume(context);

    assertThrows(ResumeFailedException.class, () -> clientPut.innerResume(context));
  }

  @Test
  void canRestart_whenNotFinished_returnsFalse() throws Exception {
    ClientPutExecution putter = createExecution();
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "finished", false);

    assertFalse(clientPut.canRestart());
    verify(putter, Mockito.never()).canRestart();
  }

  @Test
  void canRestart_whenSucceeded_returnsFalse() throws Exception {
    ClientPutExecution putter = createExecution();
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "finished", true);
    setField(ClientPutBase.class, clientPut, "succeeded", true);

    assertFalse(clientPut.canRestart());
    verify(putter, Mockito.never()).canRestart();
  }

  @Test
  void canRestart_whenDelegateAllows_returnsDelegateDecision() throws Exception {
    ClientPutExecution putter = createExecution();
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "finished", true);
    setField(ClientPutBase.class, clientPut, "succeeded", false);
    when(putter.canRestart()).thenReturn(true);

    assertTrue(clientPut.canRestart());
  }

  @Test
  void restart_whenDelegateSucceeds_updatesCacheAndState() throws Exception {
    ClientPutExecution putter = createExecution();
    ClientContext context = mock(ClientContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    when(putter.canRestart()).thenReturn(true);
    when(putter.restart(context)).thenReturn(true);
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "finished", true);
    setField(ClientPutBase.class, clientPut, "succeeded", false);
    setField(ClientPutBase.class, clientPut, "generatedURI", mock(FreenetURI.class));
    setField(ClientRequest.class, clientPut, "client", client);

    boolean restarted = clientPut.restart(context, false);

    assertTrue(restarted);
    assertNull(getField(ClientPutBase.class, clientPut, "generatedURI"));
    assertTrue((boolean) getField(ClientRequest.class, clientPut, "started"));
    InOrder order = inOrder(cache);
    order.verify(cache).updateStarted("test-id", false);
    order.verify(cache).updateStarted("test-id", true);
  }

  @Test
  void restart_whenDelegateThrowsInsertException_invokesOnFailure() throws Exception {
    ClientPutExecution putter = createExecution();
    ClientContext context = mock(ClientContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "finished", true);
    setField(ClientPutBase.class, clientPut, "succeeded", false);
    setField(ClientRequest.class, clientPut, "client", client);
    when(putter.canRestart()).thenReturn(true);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    when(putter.restart(context)).thenThrow(failure);
    ClientPut spyPut = spy(clientPut);

    boolean restarted = spyPut.restart(context, false);

    assertFalse(restarted);
    verify(spyPut).onFailure(failure, null);
  }

  @Test
  void setVarsRestart_whenClientHasCache_updatesCompressionStatus() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientRequest.class, clientPut, "client", client);

    clientPut.setVarsRestart();

    verify(cache).updateCompressionStatus("test-id", COMPRESS_STATE.WAITING);
    assertFalse((boolean) getField(ClientRequest.class, clientPut, "started"));
    assertNull(getField(ClientPutBase.class, clientPut, "putFailedMessage"));
    assertNull(getField(ClientPutBase.class, clientPut, "progressMessage"));
  }

  @Test
  void requestWasRemoved_whenForeverPersistence_clearsPutter() throws Exception {
    ClientPutExecution putter = createExecution();
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "persistence", Persistence.FOREVER);
    setField(ClientRequest.class, clientPut, "client", client);
    setField(ClientRequest.class, clientPut, "finished", true);

    clientPut.requestWasRemoved(mock(ClientContext.class));

    assertNull(getField(ClientPut.class, clientPut, "putter"));
    verify(client)
        .queueClientRequestMessage(Mockito.any(PersistentRequestRemovedMessage.class), eq(0));
    verifyNoInteractions(putter);
  }

  @Test
  void getClientRequest_whenPutterSet_returnsPutter() throws Exception {
    FcpRequesterHandle requester = mock(FcpRequesterHandle.class);
    ClientPutExecution putter = createExecution(requester);
    setField(ClientPut.class, clientPut, "putter", putter);

    assertSame(requester, clientPut.getClientRequest());
  }

  @Test
  void hasSucceeded_reflectsFlag() throws Exception {
    setField(ClientPutBase.class, clientPut, "succeeded", true);

    assertTrue(clientPut.hasSucceeded());
  }

  @Test
  void getFinalURI_returnsStoredValue() throws Exception {
    FreenetURI uri = mock(FreenetURI.class);
    setField(ClientPutBase.class, clientPut, "generatedURI", uri);

    assertSame(uri, clientPut.getFinalURI());
  }

  @Test
  void getType_alwaysReturnsPut() {
    assertEquals(RequestType.PUT, clientPut.getType());
  }

  @Test
  void fullyResumed_alwaysReturnsFalse() {
    assertFalse(clientPut.fullyResumed());
  }

  @Test
  void serializationFields_whenInspected_keepLegacyClientPutterType() {
    ObjectStreamClass descriptor = ObjectStreamClass.lookup(ClientPut.class);

    assertEquals(
        "network.crypta.client.async.ClientPutter",
        descriptor.getField("putter").getType().getName());
  }

  @Test
  void serialization_whenRoundTripped_restoresExecutionFromLegacyClientPutter() throws Exception {
    ClientPutter legacyPutter = mock(ClientPutter.class, withSettings().serializable());
    ClientPutExecution execution = createExecution(legacyPutter);
    setField(ClientPut.class, clientPut, "putter", execution);
    setField(ClientPut.class, clientPut, "uploadFrom", ClientPutBase.UploadFrom.DIRECT);

    ClientPut restored = roundTrip(clientPut);

    assertInstanceOf(ClientPutExecution.class, getField(ClientPut.class, restored, "putter"));
    assertInstanceOf(FcpInsertContextHandle.class, getField(ClientPutBase.class, restored, "ctx"));
    ClientPutExecution restoredExecution =
        (ClientPutExecution) getField(ClientPut.class, restored, "putter");
    assertInstanceOf(ClientPutter.class, restoredExecution.legacySerializableRequester());
    assertInstanceOf(FcpRequesterHandle.class, restored.getClientRequest());
  }

  @Test
  void serialization_whenExecutionRequesterIsNotLegacyClientPutter_throwsNotSerializableException()
      throws Exception {
    ClientRequester requester = mock(ClientRequester.class, withSettings().serializable());
    ClientPutExecution execution = createExecution(requester);
    setField(ClientPut.class, clientPut, "putter", execution);
    setField(ClientPut.class, clientPut, "uploadFrom", ClientPutBase.UploadFrom.DIRECT);

    assertThrows(NotSerializableException.class, () -> roundTrip(clientPut));
  }

  private static void setField(Class<?> owner, Object target, String name, Object value)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static Object getField(Class<?> owner, Object target, String name)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static ClientPutExecution createExecution() {
    return mock(ClientPutExecution.class);
  }

  private static ClientPutExecution createExecution(FcpRequesterHandle requester) {
    ClientPutExecution execution = mock(ClientPutExecution.class);
    when(execution.requester()).thenReturn(requester);
    return execution;
  }

  private static ClientPutExecution createExecution(ClientRequester requester) {
    ClientPutExecution execution = mock(ClientPutExecution.class);
    when(execution.legacySerializableRequester()).thenReturn(requester);
    return execution;
  }

  private static ClientPut roundTrip(ClientPut value) throws Exception {
    byte[] serialized;
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
      objectOutput.writeObject(value);
      objectOutput.flush();
      serialized = output.toByteArray();
    }
    try (ObjectInputStream objectInput =
        new ObjectInputStream(new ByteArrayInputStream(serialized))) {
      return (ClientPut) objectInput.readObject();
    }
  }
}
