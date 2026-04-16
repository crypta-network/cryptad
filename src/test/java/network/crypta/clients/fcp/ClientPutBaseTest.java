package network.crypta.clients.fcp;

import java.io.ObjectStreamClass;
import java.io.Serial;
import java.lang.reflect.Field;
import java.time.Instant;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.FinishedCompressionEvent;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.client.events.StartedCompressionEvent;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutBaseTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FcpInsertRuntimeSupport runtimeSupport;
  @Mock private ClientContext clientContext;
  @Mock private PersistentRequestClient persistentClient;
  @Mock private RequestStatusCache cache;
  @Mock private Bucket generatedMetadata;

  @Test
  void serializationFields_whenInspected_keepLegacyInsertContextType() {
    ObjectStreamClass descriptor = ObjectStreamClass.lookup(ClientPutBase.class);

    assertEquals(
        "network.crypta.client.InsertContext", descriptor.getField("ctx").getType().getName());
  }

  @Test
  void uploadFromGetByCode_whenValidCodeProvided_returnsMatchingEnum() {
    assertSame(ClientPutBase.UploadFrom.DIRECT, ClientPutBase.UploadFrom.getByCode(0));
    assertSame(ClientPutBase.UploadFrom.DISK, ClientPutBase.UploadFrom.getByCode(1));
    assertSame(ClientPutBase.UploadFrom.REDIRECT, ClientPutBase.UploadFrom.getByCode(2));
  }

  @Test
  void uploadFromGetByCode_whenCodeUnknown_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> ClientPutBase.UploadFrom.getByCode(99));
  }

  @Test
  void constructor_whenConnectionScoped_appliesInsertOptionsToRuntimeContext() {
    DefaultFcpInsertContextHandle insertContext = newInsertContextHandle();
    when(runtimeSupport.defaultPersistentInsertContextHandle()).thenReturn(insertContext);
    ClientRequestParams params = newRequestParams("conn-id", Persistence.CONNECTION);

    TestClientPutBase request =
        new TestClientPutBase(
            params, "bad[", newOptions(), handler, runtimeSupport, mock(FreenetURI.class));

    assertSame(insertContext, request.ctx);
    assertTrue(insertContext.getCHKOnly());
    assertTrue(insertContext.isDontCompress());
    assertEquals(5, insertContext.getMaxInsertRetries());
    assertTrue(insertContext.canWriteClientCache());
    assertEquals("GZIP", insertContext.getCompressorDescriptor());
    assertTrue(insertContext.localRequestOnly());
    assertTrue(insertContext.earlyEncode());
    assertTrue(insertContext.ignoreUSKDatehints());
  }

  @Test
  void constructor_whenPersistentScoped_appliesInsertOptionsToRuntimeContext() {
    DefaultFcpInsertContextHandle insertContext = newInsertContextHandle();
    when(runtimeSupport.defaultPersistentInsertContextHandle()).thenReturn(insertContext);
    ClientRequestParams params = newRequestParams("persistent-id", Persistence.REBOOT);
    PersistentRequestClient client =
        new PersistentRequestClient("client-a", null, false, null, Persistence.REBOOT, null);

    TestClientPutBase request =
        new TestClientPutBase(
            params, null, newOptions(), null, client, runtimeSupport, mock(FreenetURI.class));

    assertSame(insertContext, request.ctx);
    assertTrue(insertContext.getCHKOnly());
    assertEquals(FcpCompatibilityMode.latest(), insertContext.getCompatibilityMode());
    assertEquals(2, insertContext.getExtraInsertsSingleBlock());
    assertEquals(3, insertContext.getExtraInsertsSplitfileHeaderBlock());
  }

  @Test
  void onSuccess_whenConnectionScoped_freesDataSendsSuccessAndNotifiesClient() throws Exception {
    TestClientPutBase request = new TestClientPutBase();
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FcpInsertCallbackState state = mock(FcpInsertCallbackState.class);
    FreenetURI generatedUri = mock(FreenetURI.class);
    setField(ClientRequest.class, request, "identifier", "success-id");
    setField(ClientRequest.class, request, "persistence", Persistence.CONNECTION);
    setField(ClientRequest.class, request, "origHandler", handler);
    setField(ClientRequest.class, request, "client", client);
    setField(ClientPutBase.class, request, "generatedURI", generatedUri);

    request.onSuccess(state);

    assertTrue((boolean) getClientRequestField(request, "started"));
    assertTrue((boolean) getClientRequestField(request, "finished"));
    assertTrue(request.succeeded);
    assertEquals(1, request.freeDataCalls);
    verify(handler).finishedClientRequest(request);
    verify(handler).send(any(PutSuccessfulMessage.class));
    verify(client).notifySuccess(request);
  }

  @Test
  void onSuccess_whenGeneratedUriMissing_usesStateUriForPutSuccessfulAndStatus() throws Exception {
    TestClientPutBase request = new TestClientPutBase();
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FcpInsertCallbackState state = mock(FcpInsertCallbackState.class);
    FreenetURI generatedUri = new FreenetURI("KSK", "fallback-uri");
    setField(ClientRequest.class, request, "identifier", "fallback-id");
    setField(ClientRequest.class, request, "persistence", Persistence.CONNECTION);
    setField(ClientRequest.class, request, "origHandler", handler);
    setField(ClientRequest.class, request, "client", client);
    when(state.getURI()).thenReturn(generatedUri);

    request.onSuccess(state);

    ArgumentCaptor<PutSuccessfulMessage> successCaptor =
        ArgumentCaptor.forClass(PutSuccessfulMessage.class);
    verify(handler).send(successCaptor.capture());
    assertSame(generatedUri, request.getGeneratedURI());
    assertSame(generatedUri, successCaptor.getValue().uri);
    verify(client).notifySuccess(request);
  }

  @Test
  void onFailure_whenConnectionScoped_freesDataSendsFailureAndNotifiesClient() throws Exception {
    TestClientPutBase request = new TestClientPutBase();
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FcpInsertCallbackState state = mock(FcpInsertCallbackState.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    setField(ClientRequest.class, request, "identifier", "failure-id");
    setField(ClientRequest.class, request, "persistence", Persistence.CONNECTION);
    setField(ClientRequest.class, request, "origHandler", handler);
    setField(ClientRequest.class, request, "client", client);

    request.onFailure(failure, state);

    assertTrue((boolean) getClientRequestField(request, "started"));
    assertTrue((boolean) getClientRequestField(request, "finished"));
    assertEquals(1, request.freeDataCalls);
    assertInstanceOf(PutFailedMessage.class, request.getFailureMessage());
    verify(handler).finishedClientRequest(request);
    verify(handler).send(any(PutFailedMessage.class));
    verify(client).notifyFailure(request);
  }

  @Test
  void receive_whenVerboseEventsArrive_updatesProgressCacheAndCompressionHooks() throws Exception {
    TestClientPutBase request = new TestClientPutBase();
    when(persistentClient.getRequestStatusCache()).thenReturn(cache);
    setField(ClientRequest.class, request, "identifier", "event-id");
    setField(ClientRequest.class, request, "persistence", Persistence.REBOOT);
    setField(ClientRequest.class, request, "client", persistentClient);
    setField(ClientRequest.class, request, "verbosity", 1 | 8 | 512);

    SplitfileProgressEvent progressEvent =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(10, 4, 2, 1, 3, 1, true),
            new SplitfileProgressTimestamps(
                Instant.ofEpochMilli(1000), Instant.ofEpochMilli(2000)));
    ExpectedHashesEvent hashesEvent =
        new ExpectedHashesEvent(
            new HashResult[] {
              new HashResult(HashType.SHA256, new byte[HashType.SHA256.hashLength])
            });

    request.receive(progressEvent, clientContext);
    request.receive(new StartedCompressionEvent(COMPRESSOR_TYPE.GZIP), clientContext);
    request.receive(new FinishedCompressionEvent(1, 25L, 10L), clientContext);
    request.receive(hashesEvent, clientContext);

    verify(cache).updateStatus("event-id", progressEvent);
    verify(persistentClient, never()).notifySuccess(any());
    verify(persistentClient, never()).notifyFailure(any());
    verify(persistentClient, times(4)).queueClientRequestMessage(any(FCPMessage.class), anyInt());
    assertEquals(1, request.startCompressingCalls);
    assertEquals(1, request.stopCompressingCalls);
    assertInstanceOf(ExpectedHashes.class, request.getProgressMessageSnapshot());
  }

  @Test
  void requestWasRemoved_whenForeverPersistent_clearsTransientStateAndQueuesRemoval()
      throws Exception {
    TestClientPutBase request = new TestClientPutBase();
    FreenetURI generatedUri = mock(FreenetURI.class);
    PutFailedMessage failure =
        new PutFailedMessage(
            new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null),
            "remove-id",
            false);
    setField(ClientRequest.class, request, "identifier", "remove-id");
    setField(ClientRequest.class, request, "persistence", Persistence.FOREVER);
    setField(ClientRequest.class, request, "client", persistentClient);
    setField(ClientPutBase.class, request, "generatedURI", generatedUri);
    setField(ClientPutBase.class, request, "putFailedMessage", failure);
    setField(ClientPutBase.class, request, "progressMessage", new StaticFcpMessage("Progress"));
    setField(ClientPutBase.class, request, "generatedMetadata", generatedMetadata);
    setField(ClientRequest.class, request, "finished", true);

    request.requestWasRemoved(clientContext);

    verify(persistentClient)
        .queueClientRequestMessage(any(PersistentRequestRemovedMessage.class), eq(0));
    verify(generatedMetadata).free();
    assertEquals(1, request.freeDataCalls);
    assertNull(request.getFailureMessage());
    assertNull(request.getGeneratedURI());
    assertNull(request.getProgressMessageSnapshot());
  }

  private static ClientRequestParams newRequestParams(String identifier, Persistence persistence) {
    return new ClientRequestParams(
        mock(FreenetURI.class), identifier, 7, (short) 4, persistence, true, "token-1", false);
  }

  private static FcpInsertOptions newOptions() {
    return new FcpInsertOptions(
        new FcpInsertBehaviorOptions(true, true, true, 5, true, true, true),
        new FcpInsertTuningOptions(true, true, "GZIP", 2, 3, FcpCompatibilityMode.COMPAT_CURRENT),
        null);
  }

  private static DefaultFcpInsertContextHandle newInsertContextHandle() {
    return new DefaultFcpInsertContextHandle(
        new SimpleEventProducer(),
        new FcpInsertContextLimits(0, 1, 1),
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(false, false, false, 1, false, false, false),
            new FcpInsertTuningOptions(
                true, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
            null));
  }

  private static void setField(Class<?> owner, Object target, String name, Object value)
      throws ReflectiveOperationException {
    Field field = owner.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static Object getClientRequestField(Object target, String name)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static final class StaticFcpMessage extends FCPMessage {
    private final String name;

    private StaticFcpMessage(String name) {
      this.name = name;
    }

    @Override
    public SimpleFieldSet getFieldSet() {
      SimpleFieldSet fieldSet = new SimpleFieldSet(true);
      fieldSet.putSingle("Name", name);
      return fieldSet;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public void run(FCPConnectionHandler handler) {
      // No-op test message.
    }
  }

  private static final class TestClientPutBase extends ClientPutBase {
    @Serial private static final long serialVersionUID = 1L;

    private final transient FCPMessage tagMessage = new StaticFcpMessage("PersistentTag");
    private int freeDataCalls;
    private int startCompressingCalls;
    private int stopCompressingCalls;

    private TestClientPutBase(
        ClientRequestParams requestParams,
        String charset,
        FcpInsertOptions options,
        FCPConnectionHandler handler,
        FcpInsertRuntimeSupport runtimeSupport,
        FreenetURI publicURI) {
      super(requestParams, charset, options, handler, runtimeSupport, publicURI);
    }

    private TestClientPutBase(
        ClientRequestParams requestParams,
        String charset,
        FcpInsertOptions options,
        FCPConnectionHandler handler,
        PersistentRequestClient client,
        FcpInsertRuntimeSupport runtimeSupport,
        FreenetURI publicURI) {
      super(requestParams, charset, options, handler, client, runtimeSupport, publicURI);
    }

    private TestClientPutBase() {}

    @Override
    void register(boolean noTags) {
      // Registration is irrelevant for these base-class unit tests.
    }

    @Override
    protected FcpRequesterHandle getClientRequest() {
      return null;
    }

    @Override
    protected void freeData() {
      freeDataCalls++;
    }

    @Override
    public void start(PersistentRequestRuntimeContext context) {
      // The test double never schedules real network work.
    }

    @Override
    public boolean hasSucceeded() {
      return succeeded;
    }

    @Override
    public boolean canRestart() {
      return false;
    }

    @Override
    public boolean restart(PersistentRequestRuntimeContext context, boolean disableFilterData) {
      return false;
    }

    @Override
    RequestStatus getStatus() {
      return null;
    }

    @Override
    protected void innerResume(FcpRequestRuntimeContext context) {
      // No-op for test double.
    }

    @Override
    RequestType getType() {
      return RequestType.PUT;
    }

    @Override
    public boolean fullyResumed() {
      return true;
    }

    @Override
    protected void onStopCompressing() {
      stopCompressingCalls++;
    }

    @Override
    protected void onStartCompressing() {
      startCompressingCalls++;
    }

    @Override
    protected FCPMessage persistentTagMessage() {
      return tagMessage;
    }
  }
}
