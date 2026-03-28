package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.persistence.PersistentRequestClientHandle;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentRequestRootTest {

  @Mock private FCPConnectionHandler handler;

  @Test
  void registerForeverClient_whenNew_createsAndStoresClient() {
    PersistentRequestRoot root = new PersistentRequestRoot();

    PersistentRequestClient client = root.registerForeverClient("clientA", handler);

    assertNotNull(client);
    assertFalse(client.isGlobalQueue);
    assertSame(client, root.getForeverClient("clientA", null));
    assertSame(handler, client.getConnection());
  }

  @Test
  void registerForeverClient_whenExisting_reusesInstanceAndUpdatesConnection() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient first = root.registerForeverClient("clientA", null);

    PersistentRequestClient result = root.registerForeverClient("clientA", handler);

    assertSame(first, result);
    assertSame(handler, first.getConnection());
  }

  @Test
  void getForeverClient_whenMissing_returnsNull() {
    PersistentRequestRoot root = new PersistentRequestRoot();

    PersistentRequestClient client = root.getForeverClient("missing", handler);

    assertNull(client);
  }

  @Test
  void maybeUnregisterClient_removesClientWithoutRequests() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.registerForeverClient("clientA", null);

    root.maybeUnregisterClient(client);

    assertNull(root.getForeverClient("clientA", null));
  }

  @Test
  void maybeUnregisterClient_keepsClientWithRequests() throws Exception {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.registerForeverClient("clientA", null);
    TestClientRequest request = new TestClientRequest(client, "id-1", false, false, true);
    client.register(request);

    root.maybeUnregisterClient(client);

    assertSame(client, root.getForeverClient("clientA", null));
  }

  @Test
  void getPersistentRequests_returnsRequestsFromGlobalAndClients() throws Exception {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.registerForeverClient("clientA", null);
    TestClientRequest globalReq =
        new TestClientRequest(root.getGlobalForeverClient(), "global-1", true, false, true);
    TestClientRequest clientReq = new TestClientRequest(client, "client-1", false, false, true);
    root.getGlobalForeverClient().register(globalReq);
    client.register(clientReq);

    ClientRequest[] requests = root.getPersistentRequests();

    assertArrayEquals(new ClientRequest[] {globalReq, clientReq}, requests);
  }

  @Test
  void hasRequest_returnsTrueForExistingRequests() throws Exception {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.registerForeverClient("clientA", null);
    TestClientRequest globalReq =
        new TestClientRequest(root.getGlobalForeverClient(), "global-1", true, false, true);
    TestClientRequest clientReq = new TestClientRequest(client, "client-1", false, false, true);
    root.getGlobalForeverClient().register(globalReq);
    client.register(clientReq);

    assertTrue(root.hasRequest(new RequestIdentifier(true, null, "global-1", RequestType.GET)));
    assertTrue(
        root.hasRequest(new RequestIdentifier(false, "clientA", "client-1", RequestType.GET)));
    assertFalse(
        root.hasRequest(new RequestIdentifier(false, "clientA", "missing", RequestType.GET)));
    assertFalse(
        root.hasRequest(new RequestIdentifier(false, "missing", "client-1", RequestType.GET)));
  }

  @Test
  void resume_nonGlobalClientRegistersRequest() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.registerForeverClient("clientA", null);
    TestClientRequest request = new TestClientRequest(client, "id-1", false, false, true);

    PersistentRequestClient resumed = root.resume(request, false, "clientA");

    assertSame(client, resumed);
    assertTrue(root.hasRequest(new RequestIdentifier(false, "clientA", "id-1", RequestType.GET)));
  }

  @Test
  void resume_globalQueuesRequestWithoutCreatingClient() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest request =
        new TestClientRequest(root.getGlobalForeverClient(), "id-1", true, true, true);

    PersistentRequestClientHandle resumed =
        root.resumePersistentRequest(request, true, "ignored-name");

    assertTrue(root.hasRequest(new RequestIdentifier(true, null, "id-1", RequestType.GET)));
    assertNull(root.getForeverClient("ignored-name", null));
    assertSame(root.getGlobalForeverClient(), resumed);
  }

  @Test
  void getOrCreateClientHandle_whenNamedClient_returnsPersistentClientHandle() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient expected = root.registerForeverClient("clientA", null);

    PersistentRequestClientHandle handle = root.getOrCreateClientHandle(false, "clientA");

    assertSame(expected, handle);
  }

  @Test
  void resumePersistentRequest_whenHandleIsNotClientRequest_rejectsHandle() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestHandle handle = org.mockito.Mockito.mock(PersistentRequestHandle.class);

    assertThrows(
        IllegalArgumentException.class,
        () -> root.resumePersistentRequest(handle, false, "clientA"));
  }

  @Test
  void requestConstructor_whenPersistentClientNull_rejectsImmediately() {
    assertThrows(
        IllegalStateException.class,
        () -> new TestClientRequest(null, "id-null", false, false, true));
  }

  @Test
  void requestConstructor_whenPersistentClientMismatched_rejectsImmediately() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.getGlobalForeverClient();
    ClientRequestParams params =
        new ClientRequestParams(
            null,
            "id-mismatch",
            0,
            (short) 0,
            ClientRequest.Persistence.REBOOT,
            false,
            null,
            false);

    assertThrows(
        IllegalStateException.class, () -> new TestClientRequest(params, false, true, client));
  }

  /**
   * Minimal concrete ClientRequest used to exercise PersistentRequestRoot behavior without touching
   * networked code.
   */
  private static final class TestClientRequest extends ClientRequest {
    private final boolean succeeded;

    TestClientRequest(
        PersistentRequestClient client,
        String identifier,
        boolean global,
        boolean finished,
        boolean succeeded) {
      this(
          new ClientRequestParams(
              null, identifier, 0, (short) 0, Persistence.FOREVER, false, null, global),
          finished,
          succeeded,
          client);
    }

    TestClientRequest(
        ClientRequestParams params,
        boolean finished,
        boolean succeeded,
        PersistentRequestClient client) {
      super(prepareConstructorInit(params, null, client));
      this.finished = finished;
      this.succeeded = succeeded;
    }

    @Override
    public void onLostConnection(ClientContext context) {
      // No-op: connection lifecycle is irrelevant for this stubbed request.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      // No-op: tests don't exercise message replay.
    }

    @Override
    void register(boolean noTags) {
      // No-op: registration is handled directly by PersistentRequestClient in tests.
    }

    @Override
    protected ClientRequester getClientRequest() {
      return null;
    }

    @Override
    protected void freeData() {
      // No-op: stub request doesn't allocate data buffers.
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
      return "";
    }

    @Override
    public boolean isTotalFinalized() {
      return true;
    }

    @Override
    public void start(ClientContext context) {
      // No-op: a start lifecycle isn't needed in these tests.
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
    public boolean restart(ClientContext context, boolean disableFilterData) {
      return false;
    }

    @Override
    RequestStatus getStatus() {
      return null;
    }

    @Override
    protected void innerResume(ClientContext context) {
      // No-op: resume side effects are unnecessary for the stub.
    }

    @Override
    RequestType getType() {
      return RequestType.GET;
    }

    @Override
    public boolean fullyResumed() {
      return true;
    }
  }
}
