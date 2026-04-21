package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.client.events.SimpleEventProducer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutLifecycleTest {

  private ClientPut clientPut;

  @BeforeEach
  void setUp() throws Exception {
    clientPut = new ClientPut();
    setField(
        ClientPutBase.class,
        clientPut,
        "ctx",
        new DefaultFcpInsertContextHandle(
            new SimpleEventProducer(),
            new FcpInsertContextLimits(0, 1, 1),
            new FcpInsertOptions(
                new FcpInsertBehaviorOptions(false, false, false, 1, null, false, false, false),
                new FcpInsertTuningOptions(
                    true, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
                null)));
    setField(ClientPut.class, clientPut, "clientMetadata", new ClientMetadata("text/plain"));
    setField(ClientRequest.class, clientPut, "identifier", "test-id");
    setField(ClientRequest.class, clientPut, "persistence", ClientRequest.Persistence.FOREVER);
  }

  @Test
  void register_whenPersistentAndTagsRequested_registersAndQueuesTagMessage() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FCPMessage tagMessage = mock(FCPMessage.class);
    ClientPut request = spy(clientPut);
    setField(ClientRequest.class, request, "client", client);
    doReturn(tagMessage).when(request).persistentTagMessage();

    new ClientPutLifecycle(request).register(false);

    verify(client).register(request);
    verify(client).queueClientRequestMessage(tagMessage, 0);
  }

  @Test
  void start_whenPersistentRequestStarts_updatesCacheAndQueuesTag() throws Exception {
    ClientPutExecution putter = mock(ClientPutExecution.class);
    PersistentRequestRuntimeContext context = mock(PersistentRequestRuntimeContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    FCPMessage tagMessage = mock(FCPMessage.class);
    ClientPut request = spy(clientPut);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientPut.class, request, "putter", putter);
    setField(ClientRequest.class, request, "identifier", "start-id");
    setField(ClientRequest.class, request, "persistence", ClientRequest.Persistence.REBOOT);
    setField(ClientRequest.class, request, "client", client);
    doReturn(tagMessage).when(request).persistentTagMessage();

    new ClientPutLifecycle(request).start(context);

    verify(putter).start(context);
    verify(client).queueClientRequestMessage(tagMessage, 0);
    verify(cache).updateStarted("start-id", true);
    assertTrue((boolean) getField(ClientRequest.class, request, "started"));
  }

  @Test
  void start_whenPutterThrowsInsertException_invokesOnFailure() throws Exception {
    ClientPutExecution putter = mock(ClientPutExecution.class);
    PersistentRequestRuntimeContext context = mock(PersistentRequestRuntimeContext.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    ClientPut request = spy(clientPut);
    setField(ClientPut.class, request, "putter", putter);
    doThrow(failure).when(putter).start(context);
    doNothing().when(request).onFailure(failure, null);

    new ClientPutLifecycle(request).start(context);

    verify(request).onFailure(failure, null);
  }

  @Test
  void restart_whenDelegateSucceeds_updatesCacheAndState() throws Exception {
    ClientPutExecution putter = mock(ClientPutExecution.class);
    PersistentRequestRuntimeContext context = mock(PersistentRequestRuntimeContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    when(putter.canRestart()).thenReturn(true);
    when(putter.restart(context)).thenReturn(true);
    setField(ClientPut.class, clientPut, "putter", putter);
    setField(ClientRequest.class, clientPut, "finished", true);
    setField(ClientPutBase.class, clientPut, "succeeded", false);
    setField(
        ClientPutBase.class, clientPut, "generatedURI", mock(network.crypta.keys.FreenetURI.class));
    setField(ClientRequest.class, clientPut, "client", client);

    boolean restarted = new ClientPutLifecycle(clientPut).restart(context);

    assertTrue(restarted);
    assertNull(getField(ClientPutBase.class, clientPut, "generatedURI"));
    assertTrue((boolean) getField(ClientRequest.class, clientPut, "started"));
    InOrder order = inOrder(cache);
    order.verify(cache).updateStarted("test-id", false);
    order.verify(cache).updateStarted("test-id", true);
  }

  @Test
  void restart_whenDelegateThrowsInsertException_invokesOnFailure() throws Exception {
    ClientPutExecution putter = mock(ClientPutExecution.class);
    PersistentRequestRuntimeContext context = mock(PersistentRequestRuntimeContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "boom", null);
    ClientPut request = spy(clientPut);
    setField(ClientPut.class, request, "putter", putter);
    setField(ClientRequest.class, request, "finished", true);
    setField(ClientPutBase.class, request, "succeeded", false);
    setField(ClientRequest.class, request, "client", client);
    when(putter.canRestart()).thenReturn(true);
    when(putter.restart(context)).thenThrow(failure);
    doNothing().when(request).onFailure(failure, null);

    boolean restarted = new ClientPutLifecycle(request).restart(context);

    assertFalse(restarted);
    verify(request).onFailure(failure, null);
  }

  @Test
  void onStartCompressing_whenClientHasCache_updatesCache() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientRequest.class, clientPut, "client", client);

    new ClientPutLifecycle(clientPut).onStartCompressing();

    verify(cache).updateCompressionStatus("test-id", ClientPut.COMPRESS_STATE.COMPRESSING);
  }

  @Test
  void onStopCompressing_whenClientHasCache_updatesCacheAndState() throws Exception {
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    setField(ClientRequest.class, clientPut, "client", client);

    new ClientPutLifecycle(clientPut).onStopCompressing();

    verify(cache).updateCompressionStatus("test-id", ClientPut.COMPRESS_STATE.WORKING);
    assertTrue((boolean) getField(ClientPut.class, clientPut, "compressed"));
  }

  @Test
  void requestWasRemoved_whenForeverPersistence_clearsPutter() throws Exception {
    ClientPutExecution putter = mock(ClientPutExecution.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    ClientPut request = spy(clientPut);
    setField(ClientPut.class, request, "putter", putter);
    setField(ClientRequest.class, request, "client", client);
    setField(ClientRequest.class, request, "finished", true);
    doNothing().when(request).requestWasRemovedBase(any());

    new ClientPutLifecycle(request).requestWasRemoved(mock(PersistentRequestRuntimeContext.class));

    assertNull(getField(ClientPut.class, request, "putter"));
    verify(request).requestWasRemovedBase(any());
    verifyNoInteractions(putter);
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
}
