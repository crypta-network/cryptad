package network.crypta.clients.fcp;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.USKManager;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.endpoints.fcp.CoreFcpServerDependenciesFactory;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.mockito.ArgumentMatchers.isA;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FCPServerTest {

  @Mock private NodeClientCore core;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RuntimePorts coreRuntimePorts;
  @Mock private ExecutionPort executionPort;
  @Mock private TransferAccessPort serverTransferAccess;
  @Mock private TransferAccessPort coreTransferAccess;
  @Mock private ClientContext clientContext;
  @Mock private InsertContext insertContext;
  @Mock private USKManager uskManager;
  @Mock private TempBucketFactory tempBucketFactory;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private RandomSource randomSource;
  @Mock private HighLevelSimpleClient highLevelSimpleClient;

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
    return new FCPServer(config, newDependencies(new PersistentRequestRoot()));
  }

  private FcpServerDependencies newDependencies(PersistentRequestRoot root) {
    when(runtimePorts.execution()).thenReturn(executionPort);
    lenient().when(runtimePorts.transferAccess()).thenReturn(serverTransferAccess);
    lenient().when(core.getRuntimePorts()).thenReturn(coreRuntimePorts);
    lenient().when(coreRuntimePorts.transferAccess()).thenReturn(coreTransferAccess);
    lenient().when(core.getClientContext()).thenReturn(clientContext);
    lenient().when(clientContext.getDefaultPersistentInsertContext()).thenReturn(insertContext);
    lenient().when(core.getUskManager()).thenReturn(uskManager);
    lenient().when(core.getTempBucketFactory()).thenReturn(tempBucketFactory);
    lenient().when(core.getPersistentTempBucketFactory()).thenReturn(persistentTempBucketFactory);
    lenient().when(core.getRandom()).thenReturn(randomSource);
    return CoreFcpServerDependenciesFactory.create(core, runtimePorts, root);
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
    when(runtimePorts.execution()).thenReturn(executionPort);
    lenient().when(runtimePorts.transferAccess()).thenReturn(serverTransferAccess);
    lenient().when(core.getRuntimePorts()).thenReturn(coreRuntimePorts);
    lenient().when(coreRuntimePorts.transferAccess()).thenReturn(coreTransferAccess);
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
    FCPServer server = new FCPServer(config, newDependencies(root));
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
  void runtime_whenQueried_returnsConfiguredPorts() {
    FCPServer server = newServer(false, false);

    assertSame(runtimePorts, server.runtime());
  }

  @Test
  void serverRuntimeSupport_whenQueried_returnsConfiguredAdapter() {
    FCPServer server = newServer(false, false);
    FcpServerRuntimeSupport first = server.serverRuntimeSupport();

    FcpServerRuntimeSupport second = server.serverRuntimeSupport();

    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void serverRuntimeSupport_whenServicesQueried_delegatesToCore() {
    when(core.killedDatabase()).thenReturn(true);
    FCPServer server = newServer(false, false);
    byte[] bytes = new byte[4];

    FcpServerRuntimeSupport support = server.serverRuntimeSupport();

    assertSame(clientContext, support.clientContext());
    assertTrue(support.persistenceDisabled());
    assertSame(tempBucketFactory, support.tempBucketFactory());
    assertSame(persistentTempBucketFactory, support.persistentTempBucketFactory());
    support.fillSecureRandom(bytes);
    verify(randomSource).nextBytes(bytes);
  }

  @Test
  void messageRuntimeSupport_whenQueried_returnsConfiguredAdapter() {
    FCPServer server = newServer(false, false);
    FcpMessageRuntimeSupport first = server.messageRuntimeSupport();

    FcpMessageRuntimeSupport second = server.messageRuntimeSupport();

    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void messageRuntimeSupport_whenMakeClientInvoked_delegatesToCore() {
    when(core.makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true))
        .thenReturn(highLevelSimpleClient);
    FCPServer server = newServer(false, false);

    HighLevelSimpleClient actual =
        server
            .messageRuntimeSupport()
            .makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true);

    assertSame(highLevelSimpleClient, actual);
    verify(core).makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true);
  }

  @Test
  void fetchRuntimeSupport_whenQueried_returnsConfiguredAdapter() {
    // Arrange
    FCPServer server = newServer(false, false);
    FcpFetchRuntimeSupport first = server.fetchRuntimeSupport();

    // Act
    FcpFetchRuntimeSupport second = server.fetchRuntimeSupport();

    // Assert
    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void fetchRuntimeSupport_whenTransferAccessQueried_usesServerRuntimePorts() {
    // Arrange
    FCPServer server = newServer(false, false);

    // Act
    TransferAccessPort actual = server.fetchRuntimeSupport().transferAccess();

    // Assert
    assertSame(serverTransferAccess, actual);
    assertNotSame(coreTransferAccess, actual);
  }

  @Test
  void fetchRuntimeSupport_whenServerTransferPolicyChanges_readsLatestRuntimePort() {
    // Arrange
    FCPServer server = newServer(false, false);
    FcpFetchRuntimeSupport support = server.fetchRuntimeSupport();
    TransferAccessPort updatedServerTransferAccess = mock(TransferAccessPort.class);
    when(runtimePorts.transferAccess()).thenReturn(updatedServerTransferAccess);

    // Act
    TransferAccessPort actual = support.transferAccess();

    // Assert
    assertSame(updatedServerTransferAccess, actual);
    assertNotSame(serverTransferAccess, actual);
  }

  @Test
  void insertRuntimeSupport_whenQueried_returnsConfiguredAdapter() {
    FCPServer server = newServer(false, false);
    FcpInsertRuntimeSupport first = server.insertRuntimeSupport();

    FcpInsertRuntimeSupport second = server.insertRuntimeSupport();

    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void insertRuntimeSupport_whenTransferAccessQueried_usesCoreRuntimePorts() {
    FCPServer server = newServer(false, false);

    TransferAccessPort actual = server.insertRuntimeSupport().transferAccess();

    assertSame(coreTransferAccess, actual);
    assertNotSame(serverTransferAccess, actual);
  }

  @Test
  void insertRuntimeSupport_whenCoreTransferPolicyChanges_readsLatestCoreRuntimePort() {
    FCPServer server = newServer(false, false);
    FcpInsertRuntimeSupport support = server.insertRuntimeSupport();
    TransferAccessPort updatedCoreTransferAccess = mock(TransferAccessPort.class);
    when(coreRuntimePorts.transferAccess()).thenReturn(updatedCoreTransferAccess);

    TransferAccessPort actual = support.transferAccess();

    assertSame(updatedCoreTransferAccess, actual);
    assertNotSame(coreTransferAccess, actual);
  }

  @Test
  void insertRuntimeSupport_whenContextServicesQueried_delegatesToCore() {
    FCPServer server = newServer(false, false);
    FcpInsertRuntimeSupport support = server.insertRuntimeSupport();

    assertSame(clientContext, support.clientContext());
    assertSame(insertContext, support.defaultPersistentInsertContext());
    assertSame(uskManager, support.uskManager());
  }

  @Test
  void messageFetchRuntimeSupport_whenTransferAccessQueried_usesCoreRuntimePorts() {
    // Arrange
    FCPServer server = newServer(false, false);

    // Act
    TransferAccessPort actual = server.messageFetchRuntimeSupport().transferAccess();

    // Assert
    assertSame(coreTransferAccess, actual);
    assertNotSame(serverTransferAccess, actual);
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
    DownloadRequestStatus status =
        newDownloadStatus(
            "id-1", Persistence.REBOOT, false, 10, "text/plain", mock(Bucket.class), uri);
    requireStatusCache(rebootClient).addDownload(status);

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
    PersistentRequestClient foreverClient = requireClient(server.getGlobalForeverClient());
    FreenetURI uri = mock(FreenetURI.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.size()).thenReturn(5L);
    DownloadRequestStatus status =
        newDownloadStatus("cached", Persistence.FOREVER, true, 5, "image/png", bucket, uri);
    requireStatusCache(foreverClient).addDownload(status);

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

  private static RequestStatusCache requireStatusCache(PersistentRequestClient client) {
    RequestStatusCache cache = client.getRequestStatusCache();
    if (cache == null) {
      throw new AssertionError("Expected global client to expose a request status cache");
    }
    return cache;
  }

  private static PersistentRequestClient requireClient(PersistentRequestClient client) {
    if (client == null) {
      throw new AssertionError("Expected global forever client to be available");
    }
    return client;
  }

  private static DownloadRequestStatus newDownloadStatus(
      String identifier,
      Persistence persistence,
      boolean success,
      long dataSize,
      String mimeType,
      Bucket dataShadow,
      FreenetURI uri) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            identifier,
            persistence,
            false,
            false,
            success,
            0,
            0,
            0,
            null,
            0,
            0,
            null,
            success,
            (short) 0);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(dataSize, mimeType, null, null, null, dataShadow, false);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(outcome, null, null, null, uri, false, false);
    return new DownloadRequestStatus(statusSnapshot, details);
  }
}
