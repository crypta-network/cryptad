package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

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
    TrackingJobRunner jobRunner = new TrackingJobRunner();
    ClientContext context = newContextWithJobRunner(jobRunner);
    FcpServerRuntimeSupport runtimeSupport = mock(FcpServerRuntimeSupport.class);
    when(runtimeSupport.clientContext()).thenReturn(context);
    FCPServer server = mock(FCPServer.class);
    when(server.serverRuntimeSupport()).thenReturn(runtimeSupport);
    ClientRequester requester = mock(ClientRequester.class);
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
    assertEquals(1, jobRunner.checkpointRequests);
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
    TrackingJobRunner jobRunner = new TrackingJobRunner();
    ClientContext context = newContextWithJobRunner(jobRunner);
    FcpServerRuntimeSupport runtimeSupport = mock(FcpServerRuntimeSupport.class);
    when(runtimeSupport.clientContext()).thenReturn(context);
    FCPServer server = mock(FCPServer.class);
    when(server.serverRuntimeSupport()).thenReturn(runtimeSupport);
    ClientRequester requester = mock(ClientRequester.class);
    PersistentRequestClient client =
        spy(
            new PersistentRequestClient(
                "modify", null, true, null, ClientRequest.Persistence.REBOOT, null));
    TestClientRequest request =
        TestClientRequest.reboot("request-2", (short) 2, "same-token", client, requester);

    request.modifyRequest("same-token", (short) 2, server);

    assertEquals(0, jobRunner.checkpointRequests);
    verify(requester, never()).setPriorityClass(any(short.class), any(ClientContext.class));
    verify(client, never()).queueClientRequestMessage(any(FCPMessage.class), eq(0));
  }

  @SuppressWarnings("java:S3011")
  private static ClientContext newContextWithJobRunner(PersistentJobRunner jobRunner) {
    ClientContext context =
        Mockito.mock(
            ClientContext.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));
    try {
      Field field = ClientContext.class.getDeclaredField("jobRunner");
      field.setAccessible(true);
      field.set(context, jobRunner);
      return context;
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set ClientContext.jobRunner", e);
    }
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

  private static final class TrackingJobRunner implements PersistentJobRunner {
    private int checkpointRequests;

    @Override
    public void queue(PersistentJob persistentJob, int threadPriority) {
      throw new UnsupportedOperationException("Not used by modifyRequest()");
    }

    @Override
    public void queueNormalOrDrop(PersistentJob persistentJob) {
      throw new UnsupportedOperationException("Not used by modifyRequest()");
    }

    @Override
    public void queueInternal(PersistentJob job, int threadPriority) {
      throw new UnsupportedOperationException("Not used by modifyRequest()");
    }

    @Override
    public void queueInternal(PersistentJob job) {
      throw new UnsupportedOperationException("Not used by modifyRequest()");
    }

    @Override
    public void setCheckpointASAP() {
      checkpointRequests++;
    }

    @Override
    public boolean hasLoaded() {
      return true;
    }

    @Override
    public CheckpointLock lock() {
      return (_, _) -> {};
    }

    @Override
    public boolean newSalt() {
      return false;
    }

    @Override
    public boolean shuttingDown() {
      return false;
    }
  }

  private static final class TestClientRequest extends ClientRequest {
    private final ClientRequester requester;

    private TestClientRequest(ConstructorInit init, ClientRequester requester) {
      super(init);
      this.requester = requester;
    }

    static TestClientRequest reboot(
        String identifier,
        short priorityClass,
        String clientToken,
        PersistentRequestClient client,
        ClientRequester requester) {
      return new TestClientRequest(
          prepareConstructorInit(
              new ClientRequestParams(
                  null, identifier, 0, priorityClass, Persistence.REBOOT, false, clientToken, true),
              null,
              client),
          requester);
    }

    @Override
    public void onLostConnection(ClientContext context) {
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
    protected ClientRequester getClientRequest() {
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
    public void start(ClientContext context) {
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
    public boolean restart(ClientContext context, boolean disableFilterData) {
      return false;
    }

    @Override
    RequestStatus getStatus() {
      return null;
    }

    @Override
    protected void innerResume(ClientContext context) {
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
