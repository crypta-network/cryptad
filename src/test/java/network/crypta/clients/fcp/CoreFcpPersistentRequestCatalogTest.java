package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.clients.fcp.bridge.CoreFcpPersistentRequestCatalog;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CoreFcpPersistentRequestCatalogTest {

  @Test
  void getPersistentRequests_whenRootContainsRequests_expectReturnsSnapshot() {
    // Arrange
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient globalClient = root.getGlobalForeverClient();
    PersistentRequestClient namedClient = root.registerForeverClient("client-a", null);
    TestClientRequest globalRequest =
        new TestClientRequest(globalClient, "global-id", true, RequestIdentifier.RequestType.GET);
    TestClientRequest namedRequest =
        new TestClientRequest(namedClient, "client-id", false, RequestIdentifier.RequestType.PUT);
    globalClient.resume(globalRequest);
    namedClient.resume(namedRequest);
    CoreFcpPersistentRequestCatalog catalog = new CoreFcpPersistentRequestCatalog(root);

    // Act
    PersistentRequestHandle[] requests = catalog.getPersistentRequests();

    // Assert
    assertArrayEquals(new PersistentRequestHandle[] {globalRequest, namedRequest}, requests);
  }

  @Test
  void hasRequest_whenIdentifierMatchesExpectTrueEvenWhenTypeDiffers() {
    // Arrange
    PersistentRequestRoot root = new PersistentRequestRoot();
    PersistentRequestClient client = root.registerForeverClient("client-a", null);
    client.resume(
        new TestClientRequest(client, "shared-id", false, RequestIdentifier.RequestType.PUT));
    CoreFcpPersistentRequestCatalog catalog = new CoreFcpPersistentRequestCatalog(root);
    PersistentRequestIdentifier lookupIdentifier =
        new PersistentRequestIdentifier(
            false, "client-a", "shared-id", PersistentRequestIdentifier.RequestType.GET);

    // Act
    boolean present = catalog.hasRequest(lookupIdentifier);

    // Assert
    assertTrue(present);
  }

  @Test
  void hasRequest_whenIdentifierMissing_expectFalse() {
    // Arrange
    PersistentRequestRoot root = new PersistentRequestRoot();
    CoreFcpPersistentRequestCatalog catalog = new CoreFcpPersistentRequestCatalog(root);
    PersistentRequestIdentifier lookupIdentifier =
        new PersistentRequestIdentifier(
            false, "client-a", "missing-id", PersistentRequestIdentifier.RequestType.GET);

    // Act
    boolean present = catalog.hasRequest(lookupIdentifier);

    // Assert
    assertFalse(present);
  }

  private static final class TestClientRequest extends ClientRequest {
    private final RequestIdentifier.RequestType type;

    TestClientRequest(
        PersistentRequestClient client,
        String identifier,
        boolean global,
        RequestIdentifier.RequestType type) {
      super(
          prepareConstructorInit(
              new ClientRequestParams(
                  null, identifier, 0, (short) 0, Persistence.FOREVER, false, null, global),
              null,
              client));
      this.type = type;
    }

    @Override
    public void onLostConnection(ClientContext context) {
      // No-op: connection lifecycle is irrelevant for this adapter test.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      // No-op: message replay is outside this test's scope.
    }

    @Override
    void register(boolean noTags) {
      // No-op: the client registry is exercised directly in the test.
    }

    @Override
    protected ClientRequester getClientRequest() {
      return null;
    }

    @Override
    protected void freeData() {
      // No-op: the stub never allocates buffers.
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
      // No-op: startup mechanics are not part of catalog behavior.
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
      // No-op: runtime reattachment is not exercised here.
    }

    @Override
    RequestIdentifier.RequestType getType() {
      return type;
    }

    @Override
    public boolean fullyResumed() {
      return true;
    }
  }
}
