package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentRequestClientTest {

  @Mock private FCPConnectionOutputHandler outputHandler;
  @Mock private ClientContext clientContext;

  @Test
  void constructor_whenNameNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () ->
            new PersistentRequestClient(
                null, mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null));
  }

  @Test
  void register_whenFinished_movesToCompletedAndQueuesPending()
      throws IdentifierCollisionException {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);
    TestClientRequest finishedRequest = new TestClientRequest(client, "id-finished", true);

    client.register(finishedRequest);

    int processed =
        client.queuePendingMessagesOnConnectionRestart(outputHandler, "list", 0, Integer.MAX_VALUE);

    assertEquals(1, processed);
    assertEquals(1, finishedRequest.pendingMessagesCalls);
  }

  @Test
  void queuePendingMessagesFromRunningRequests_honorsOffsetAndMax()
      throws IdentifierCollisionException {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);
    TestClientRequest first = new TestClientRequest(client, "first", false);
    TestClientRequest second = new TestClientRequest(client, "second", false);

    client.register(first);
    client.register(second);

    int processed =
        client.queuePendingMessagesFromRunningRequests(outputHandler, "list", 1, /* max= */ 1);

    assertEquals(2, processed);
    assertEquals(0, first.pendingMessagesCalls);
    assertEquals(1, second.pendingMessagesCalls);
  }

  @Test
  void finishedClientRequest_movesRequestFromRunningToCompleted()
      throws IdentifierCollisionException {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);
    TestClientRequest request = new TestClientRequest(client, "req", false);
    client.register(request);

    client.finishedClientRequest(request);
    int processed =
        client.queuePendingMessagesOnConnectionRestart(outputHandler, "list", 0, Integer.MAX_VALUE);

    assertEquals(1, processed);
    assertEquals(1, request.pendingMessagesCalls);
  }

  @Test
  void register_whenIdentifierCollision_throwsIdentifierCollisionException()
      throws IdentifierCollisionException {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);
    TestClientRequest first = new TestClientRequest(client, "dup", false);
    TestClientRequest second = new TestClientRequest(client, "dup", false);

    client.register(first);

    assertThrows(IdentifierCollisionException.class, () -> client.register(second));
  }

  @Test
  void removeByIdentifier_whenKillTrue_cancelsAndInvokesCallback()
      throws IdentifierCollisionException {
    RequestCompletionCallback callback = mock(RequestCompletionCallback.class);
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, callback, Persistence.REBOOT, null);
    TestClientRequest request = new TestClientRequest(client, "kill", false);
    client.register(request);

    boolean removed = client.removeByIdentifier("kill", true, null, clientContext);

    assertTrue(removed);
    assertEquals(1, request.cancelCalls);
    assertEquals(1, request.requestRemovedCalls);
    assertFalse(client.hasPersistentRequests());
    verify(callback).onRemove(request);
  }

  @Test
  void removeByIdentifier_whenKillFalse_doesNotCancel() throws IdentifierCollisionException {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);
    TestClientRequest request = new TestClientRequest(client, "keep", false);
    client.register(request);

    boolean removed = client.removeByIdentifier("keep", false, null, clientContext);

    assertTrue(removed);
    assertEquals(0, request.cancelCalls);
    assertEquals(1, request.requestRemovedCalls);
  }

  @Test
  void removeByIdentifier_whenUnknown_returnsFalse() {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);

    boolean removed = client.removeByIdentifier("missing", true, null, clientContext);

    assertFalse(removed);
  }

  @Test
  void notifySuccessAndFailure_forwardToCallbacks() {
    RequestCompletionCallback callback = mock(RequestCompletionCallback.class);
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), false, null, Persistence.REBOOT, null);
    client.addRequestCompletionCallback(callback);
    TestClientRequest request = new TestClientRequest(client, "req", false);

    client.notifySuccess(request);
    client.notifyFailure(request);

    verify(callback).notifySuccess(request);
    verify(callback).notifyFailure(request);
  }

  @Test
  void finishedClientRequest_whenFailedDownloadCompleted_cachesCanonicalLongFailureMessage()
      throws Exception {
    PersistentRequestClient client =
        new PersistentRequestClient(
            "client", mock(FCPConnectionHandler.class), true, null, Persistence.REBOOT, null);
    ClientGet download = newPersistentClientGet();
    client.register(download);
    GetFailedMessage failureMessage =
        new GetFailedMessage(
            new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND, "details"),
            "download-1",
            false);
    download.state().setFailedMessage(failureMessage);

    client.finishedClientRequest(download);

    RequestStatusCache cache = client.getRequestStatusCache();
    assertNotNull(cache);
    List<RequestStatus> statuses = new ArrayList<>();
    cache.addTo(statuses);
    DownloadRequestStatus status =
        assertInstanceOf(DownloadRequestStatus.class, statuses.getFirst());
    assertEquals(failureMessage.getShortFailedMessage(), status.getFailureReason(false));
    assertEquals(failureMessage.getLongFailedMessage(), status.getFailureReason(true));
  }

  private static final class TestClientRequest extends ClientRequest {
    int pendingMessagesCalls;
    int cancelCalls;
    int requestRemovedCalls;

    TestClientRequest(PersistentRequestClient client, String identifier, boolean finished) {
      super(
          prepareConstructorInit(
              new ClientRequestParams(
                  null, identifier, 0, (short) 1, client.persistence, false, null, false),
              null,
              client));
      this.finished = finished;
    }

    @Override
    public void onLostConnection(PersistentRequestRuntimeContext context) {
      // Deliberately no-op: test stub does not model connection loss behavior.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      pendingMessagesCalls++;
    }

    @Override
    void register(boolean noTags) {
      // Deliberately no-op: registration side effects not needed for stub.
    }

    @Override
    protected FcpRequesterHandle getClientRequest() {
      return null;
    }

    @Override
    protected void freeData() {
      // Deliberately no-op: stub does not allocate external resources.
    }

    @Override
    public double getSuccessFraction() {
      return 0;
    }

    @Override
    public double getTotalBlocks() {
      return 0;
    }

    @Override
    public double getMinBlocks() {
      return 0;
    }

    @Override
    public double getFetchedBlocks() {
      return 0;
    }

    @Override
    public double getFailedBlocks() {
      return 0;
    }

    @Override
    public double getFatalyFailedBlocks() {
      return 0;
    }

    @Override
    public String getFailureReason(boolean longDescription) {
      return "failure";
    }

    @Override
    public boolean isTotalFinalized() {
      return true;
    }

    @Override
    public void start(PersistentRequestRuntimeContext context) {
      // Deliberately no-op: start logic exercised via pending message counting only.
    }

    @Override
    public boolean hasSucceeded() {
      return true;
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
      return new TestRequestStatus(identifier, persistence);
    }

    @Override
    protected void innerResume(FcpRequestRuntimeContext context) {
      // Deliberately no-op: resumption mechanics not needed for these tests.
    }

    @Override
    RequestType getType() {
      return RequestType.GET;
    }

    @Override
    public boolean fullyResumed() {
      return true;
    }

    @Override
    public void cancel(PersistentRequestRuntimeContext context) {
      cancelCalls++;
    }

    @Override
    public void requestWasRemoved(PersistentRequestRuntimeContext context) {
      requestRemovedCalls++;
    }
  }

  private static ClientGet newPersistentClientGet() throws Exception {
    String identifier = "download-1";
    ClientGet request = new ClientGet();
    ClientGetTestProfiles.setFetchConfig(request, new ClientGetFetchConfig());
    ClientGetTestProfiles.setReturnType(request, ClientGet.ReturnType.NONE);
    setField(request, "identifier", identifier);
    setField(request, "persistence", Persistence.REBOOT);
    setField(request, "uri", new FreenetURI("KSK@" + identifier));
    return request;
  }

  private static void setField(Object target, String name, Object value)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static final class TestRequestStatus extends RequestStatus {

    private final String id;
    private final Persistence persistence;

    TestRequestStatus(String identifier, Persistence persistence) {
      super(
          new RequestStatusSnapshot(
              identifier,
              persistence,
              false,
              false,
              false,
              0,
              0,
              0,
              null,
              0,
              0,
              null,
              true,
              (short) 0));
      this.id = identifier;
      this.persistence = persistence;
    }

    @Override
    public FreenetURI getURI() {
      return null;
    }

    @Override
    public long getDataSize() {
      return 0;
    }

    @Override
    public String getFailureReason(boolean longDescription) {
      return "";
    }

    @Override
    public String getPreferredFilename() {
      return "";
    }

    @Override
    public RequestStatus copy() {
      return new TestRequestStatus(id, persistence);
    }
  }
}
