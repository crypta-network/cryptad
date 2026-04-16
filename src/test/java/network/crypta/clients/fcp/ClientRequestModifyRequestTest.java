package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ClientRequestModifyRequestTest {

  @Test
  void modifyRequest_whenPriorityAndTokenChange_updatesRequesterCacheAndQueuesMessage() {
    ClientContext context = mock(ClientContext.class);
    FcpServerRuntimeSupport runtimeSupport = mock(FcpServerRuntimeSupport.class);
    when(runtimeSupport.persistentRequestRuntimeContext()).thenReturn(context);
    FCPServer server = mock(FCPServer.class);
    when(server.serverRuntimeSupport()).thenReturn(runtimeSupport);
    FcpRequesterHandle requester = mock(FcpRequesterHandle.class);
    PersistentRequestClient client =
        spy(
            new PersistentRequestClient(
                "modify", null, true, null, ClientRequest.Persistence.REBOOT, null));
    DownloadRequestStatus status = newDownloadStatus();
    requireStatusCache(client).addDownload(status);
    TestClientRequest request =
        TestClientRequest.reboot("request-1", (short) 1, "token-a", client, requester);

    request.modifyRequest("token-b", (short) 4, server);

    verify(requester).setPriorityClass((short) 4, context);
    verify(client).queueClientRequestMessage(any(PersistentRequestModifiedMessage.class), eq(0));
    verify(runtimeSupport).setCheckpointASAP();
    assertEquals(4, request.priorityClass);
    assertEquals("token-b", request.clientToken);
    assertEquals(4, status.getPriority());

    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(client).queueClientRequestMessage(messageCaptor.capture(), eq(0));
    PersistentRequestModifiedMessage modified =
        assertInstanceOf(PersistentRequestModifiedMessage.class, messageCaptor.getValue());
    assertEquals("request-1", modified.getFieldSet().get("Identifier"));
    assertEquals("4", modified.getFieldSet().get("PriorityClass"));
    assertEquals("token-b", modified.getFieldSet().get("ClientToken"));
  }

  @Test
  void modifyRequest_whenNothingChanges_skipsCheckpointRequesterAndMessageQueue() {
    ClientContext context = mock(ClientContext.class);
    FcpServerRuntimeSupport runtimeSupport = mock(FcpServerRuntimeSupport.class);
    when(runtimeSupport.persistentRequestRuntimeContext()).thenReturn(context);
    FCPServer server = mock(FCPServer.class);
    when(server.serverRuntimeSupport()).thenReturn(runtimeSupport);
    FcpRequesterHandle requester = mock(FcpRequesterHandle.class);
    PersistentRequestClient client =
        spy(
            new PersistentRequestClient(
                "modify", null, true, null, ClientRequest.Persistence.REBOOT, null));
    TestClientRequest request =
        TestClientRequest.reboot("request-2", (short) 2, "same-token", client, requester);

    request.modifyRequest("same-token", (short) 2, server);

    verify(runtimeSupport, never()).setCheckpointASAP();
    verify(requester, never())
        .setPriorityClass(any(short.class), any(PersistentRequestRuntimeContext.class));
    verify(client, never()).queueClientRequestMessage(any(FCPMessage.class), eq(0));
  }

  private static RequestStatusCache requireStatusCache(PersistentRequestClient client) {
    RequestStatusCache cache = client.getRequestStatusCache();
    if (cache == null) {
      throw new AssertionError("Expected global client to expose a request status cache");
    }
    return cache;
  }

  private static DownloadRequestStatus newDownloadStatus() {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            "request-1",
            ClientRequest.Persistence.REBOOT,
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
            false,
            (short) 1);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(10, "text/plain", null, null, null, mock(Bucket.class), false);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(
            outcome, null, null, null, mock(FreenetURI.class), false, false);
    return new DownloadRequestStatus(statusSnapshot, details);
  }

  private static final class TestClientRequest extends ClientRequest {
    private final FcpRequesterHandle requester;

    private TestClientRequest(ConstructorInit init, FcpRequesterHandle requester) {
      super(init);
      this.requester = requester;
    }

    static TestClientRequest reboot(
        String identifier,
        short priorityClass,
        String clientToken,
        PersistentRequestClient client,
        FcpRequesterHandle requester) {
      return new TestClientRequest(
          prepareConstructorInit(
              new ClientRequestParams(
                  null, identifier, 0, priorityClass, Persistence.REBOOT, false, clientToken, true),
              null,
              client),
          requester);
    }

    @Override
    public void onLostConnection(PersistentRequestRuntimeContext context) {
      // No-op for focused modifyRequest() testing.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      // No-op for focused modifyRequest() testing.
    }

    @Override
    void register(boolean noTags) {
      // No-op for focused modifyRequest() testing.
    }

    @Override
    protected FcpRequesterHandle getClientRequest() {
      return requester;
    }

    @Override
    protected void freeData() {
      // No-op for focused modifyRequest() testing.
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
      // No-op for focused modifyRequest() testing.
    }

    @Override
    public boolean hasSucceeded() {
      return false;
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
      // No-op for focused modifyRequest() testing.
    }

    @Override
    RequestIdentifier.RequestType getType() {
      return RequestIdentifier.RequestType.GET;
    }

    @Override
    public boolean fullyResumed() {
      return true;
    }
  }
}
