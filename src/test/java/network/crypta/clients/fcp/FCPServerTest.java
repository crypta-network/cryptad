package network.crypta.clients.fcp;

import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FCPServerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;

  private FCPServer newServer(boolean assumeDownloadAllowed, boolean assumeUploadAllowed) {
    FcpServerConfig config =
        new FcpServerConfig(
            "127.0.0.1",
            "127.0.0.1",
            "127.0.0.1",
            FCPServer.DEFAULT_FCP_PORT,
            true,
            assumeDownloadAllowed,
            assumeUploadAllowed,
            false,
            10);
    return new FCPServer(
        config, new FcpServerDependencies(node, core, new PersistentRequestRoot()));
  }

  @Test
  void registerRebootClient_whenNewName_createsClientWithConnection() {
    // Arrange
    FCPServer server = newServer(false, false);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);

    // Act
    PersistentRequestClient client = server.registerRebootClient("clientA", handler);

    // Assert
    assertSame(handler, client.getConnection());
  }

  @Test
  void registerRebootClient_whenDuplicateConnectionExists_killsOldConnectionAndReusesClient() {
    // Arrange
    FCPServer server = newServer(false, false);
    FCPConnectionHandler first = mock(FCPConnectionHandler.class);
    FCPConnectionHandler second = mock(FCPConnectionHandler.class);
    PersistentRequestClient initial = server.registerRebootClient("dup", first);

    // Act
    PersistentRequestClient returned = server.registerRebootClient("dup", second);

    // Assert
    assertSame(initial, returned);
    assertSame(second, returned.getConnection());
    verify(first).setKilledDupe();
    verify(first).send(isA(CloseConnectionDuplicateClientNameMessage.class));
    verify(first).close();
  }

  @Test
  void unregisterClient_whenRebootClient_removesMapping() {
    // Arrange
    FCPServer server = newServer(false, false);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    PersistentRequestClient first = server.registerRebootClient("clientA", handler);

    // Act
    server.unregisterClient(first);
    PersistentRequestClient second = server.registerRebootClient("clientA", handler);

    // Assert
    assertNotSame(first, second);
  }

  @Test
  void unregisterClient_whenForeverClient_delegatesToRoot() {
    // Arrange
    PersistentRequestRoot root = spy(new PersistentRequestRoot());
    FcpServerConfig config =
        new FcpServerConfig(
            "127.0.0.1",
            "127.0.0.1",
            "127.0.0.1",
            FCPServer.DEFAULT_FCP_PORT,
            true,
            false,
            false,
            false,
            10);
    FCPServer server = new FCPServer(config, new FcpServerDependencies(node, core, root));
    PersistentRequestClient forever = root.registerForeverClient("forever", null);

    // Act
    server.unregisterClient(forever);

    // Assert
    verify(root).maybeUnregisterClient(forever);
  }

  @Test
  void isDownloadDDAAlwaysAllowed_returnsConfiguredFlag() {
    // Arrange
    FCPServer server = newServer(true, false);

    // Act & Assert
    assertTrue(server.isDownloadDDAAlwaysAllowed());
    assertFalse(server.isUploadDDAAlwaysAllowed());
  }

  @Test
  void isUploadDDAAlwaysAllowed_returnsConfiguredFlag() {
    // Arrange
    FCPServer server = newServer(false, true);

    // Act & Assert
    assertFalse(server.isDownloadDDAAlwaysAllowed());
    assertTrue(server.isUploadDDAAlwaysAllowed());
  }

  @Test
  void getGlobalRequests_whenDatabaseDisabled_throwsPersistenceDisabledException() {
    // Arrange
    when(core.killedDatabase()).thenReturn(true);
    FCPServer server = newServer(false, false);

    // Act & Assert
    assertThrows(PersistenceDisabledException.class, server::getGlobalRequests);
  }

  @Test
  void getGlobalRequests_whenCacheHasEntries_returnsStatuses() throws Exception {
    // Arrange
    when(core.killedDatabase()).thenReturn(false);
    FCPServer server = newServer(false, false);
    PersistentRequestClient rebootClient = server.getGlobalRebootClient();
    FreenetURI uri = mock(FreenetURI.class);
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            "id-1",
            Persistence.REBOOT,
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
            (short) 0);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(10, "text/plain", null, null, null, mock(Bucket.class), false);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(outcome, null, null, null, uri, false, false);
    DownloadRequestStatus status = new DownloadRequestStatus(statusSnapshot, details);
    rebootClient.getRequestStatusCache().addDownload(status);

    // Act
    RequestStatus[] result = server.getGlobalRequests();

    // Assert
    assertEquals(1, result.length);
    assertEquals("id-1", result[0].getIdentifier());
  }

  @Test
  void lookupInstant_whenShadowBucketPresent_returnsCachedResult() {
    // Arrange
    FCPServer server = newServer(false, false);
    PersistentRequestClient foreverClient = server.getGlobalForeverClient();
    FreenetURI uri = mock(FreenetURI.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.size()).thenReturn(5L);
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            "cached",
            Persistence.FOREVER,
            false,
            false,
            true,
            0,
            0,
            0,
            null,
            0,
            0,
            null,
            true,
            (short) 0);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(5, "image/png", null, null, null, bucket, false);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(outcome, null, null, null, uri, false, false);
    DownloadRequestStatus status = new DownloadRequestStatus(statusSnapshot, details);
    foreverClient.getRequestStatusCache().addDownload(status);

    // Act
    CacheFetchResult result = server.lookupInstant(uri, false, false, null);

    // Assert
    assertNotNull(result);
    assertEquals("image/png", result.getMimeType());
    assertFalse(result.alreadyFiltered);
    try (Bucket resultBucket = result.asBucket()) {
      assertNotSame(bucket, resultBucket);
      assertEquals(5L, resultBucket.size());
    }
  }
}
