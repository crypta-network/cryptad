package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.Arrays;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetFactoryTest {

  @Mock private FcpFetchRuntimeSupport fetchRuntimeSupport;
  @Mock private ClientGetExecution execution;
  @Mock private FcpRequesterHandle requester;
  @Mock private TransferAccessPort transferAccess;

  @Test
  void fromGlobal_whenIdentifierAlreadyRegistered_throwsIdentifierCollisionException()
      throws Exception {
    PersistentRequestClient client = newPersistentClient(Persistence.REBOOT);
    client.register(new StubClientRequest(client, "dup-global"));

    ClientGetGlobalRequestConfig config =
        new ClientGetGlobalRequestConfig(
            false,
            false,
            false,
            0,
            0,
            1024,
            ReturnType.DIRECT,
            true,
            "dup-global",
            0,
            (short) 2,
            null,
            null,
            true,
            false,
            false);

    assertThrows(
        IdentifierCollisionException.class,
        () ->
            ClientGetFactory.fromGlobal(
                client, new FreenetURI("KSK@global-collision"), config, fetchRuntimeSupport));
  }

  @ParameterizedTest
  @CsvSource({"true,false", "false,true"})
  void fromGlobal_whenValidConfig_buildsRequestAndAppliesFetchConfig(
      boolean persistRebootOnly, boolean expectedForever) throws Exception {
    configureFetchRuntimeSupportDefaults();
    PersistentRequestClient client =
        newPersistentClient(persistRebootOnly ? Persistence.REBOOT : Persistence.FOREVER);
    FreenetURI uri = new FreenetURI("KSK@global-ok-" + persistRebootOnly);
    ClientGetGlobalRequestConfig config =
        new ClientGetGlobalRequestConfig(
            true,
            true,
            true,
            7,
            8,
            4096,
            ReturnType.DIRECT,
            persistRebootOnly,
            "global-id-" + persistRebootOnly,
            123,
            (short) 4,
            null,
            "UTF-8",
            false,
            true,
            false);

    ClientGet request = ClientGetFactory.fromGlobal(client, uri, config, fetchRuntimeSupport);

    checkGlobalRequestState(request, config, uri, expectedForever);
    ClientGetFetchConfig fetchConfig = fetchConfigFrom(request);
    checkGlobalFetchConfig(fetchConfig, config);
    checkFetchRuntimeSupportInteractions();
    checkExecutionSpecShape(
        executionSpecFromRuntimeSupport(),
        request,
        uri,
        config.prioClass(),
        fetchConfig,
        expectedForever);
  }

  @Test
  void fromGlobal_whenUsingLegacyPublicConfigAlias_buildsRequest() throws Exception {
    configureFetchRuntimeSupportDefaults();
    PersistentRequestClient client = newPersistentClient(Persistence.REBOOT);
    FreenetURI uri = new FreenetURI("KSK@legacy-global-config");
    ClientGet.GlobalRequestConfig config =
        new ClientGet.GlobalRequestConfig(
            false,
            true,
            false,
            4,
            5,
            2048,
            ReturnType.DIRECT,
            true,
            "legacy-global",
            7,
            (short) 3,
            null,
            "UTF-8",
            true,
            false,
            false);

    ClientGet request = ClientGetFactory.fromGlobal(client, uri, config, fetchRuntimeSupport);

    assertNotNull(request);
    assertEquals(config.identifier(), request.getIdentifier());
    assertSame(uri, request.getURI());
    verify(fetchRuntimeSupport).defaultPersistentFetchConfig();
    verify(fetchRuntimeSupport).transferAccess();
  }

  @Test
  void fromGlobal_whenDiskReturnDenied_throwsNotAllowedException(@TempDir Path tempDir)
      throws IOException {
    configureFetchRuntimeSupportDefaults();
    PersistentRequestClient client = newPersistentClient(Persistence.REBOOT);
    File target = tempDir.resolve("target.bin").toFile();
    when(transferAccess.allowDownloadTo(target)).thenReturn(false);
    ClientGetGlobalRequestConfig config =
        new ClientGetGlobalRequestConfig(
            false,
            false,
            false,
            1,
            1,
            512,
            ReturnType.DISK,
            true,
            "disk-id",
            0,
            (short) 2,
            target,
            null,
            true,
            false,
            false);

    assertThrows(
        NotAllowedException.class,
        () ->
            ClientGetFactory.fromGlobal(
                client, new FreenetURI("KSK@global-disk"), config, fetchRuntimeSupport));
  }

  @Test
  void fromMessage_whenConnectionIdentifierAlreadyUsed_throwsIdentifierCollisionException()
      throws Exception {
    try (FCPConnectionHandler handler = newConnectionHandler()) {
      handler.setKilledDupe();
      handler.requestsByIdentifier.put("dup-msg", mock(ClientRequest.class));
      ClientGetMessage message = new ClientGetMessage(baseMessageFieldSet("dup-msg"));

      assertThrows(
          IdentifierCollisionException.class,
          () -> ClientGetFactory.fromMessage(handler, message, fetchRuntimeSupport));
      handler.requestsByIdentifier.clear();
    }
  }

  @Test
  void fromMessage_whenValidConnectionMessage_buildsRequestAndAppliesFetchConfig()
      throws Exception {
    configureFetchRuntimeSupportDefaults();
    SimpleFieldSet fs = baseMessageFieldSet("message-ok");
    fs.putOverwrite("DSOnly", "true");
    fs.putOverwrite("IgnoreDS", "true");
    fs.putOverwrite("FilterData", "true");
    fs.putOverwrite("IgnoreUSKDatehints", "true");
    fs.putOverwrite("WriteToClientCache", "false");
    fs.putOverwrite("MaxRetries", "9");
    fs.putOverwrite("MaxSize", "2048");
    fs.putOverwrite("MaxTempSize", "1024");
    fs.putOverwrite("PriorityClass", "3");
    fs.putOverwrite("RealTimeFlag", "true");
    ClientGetMessage message = new ClientGetMessage(fs);

    ClientGet request = ClientGetFactory.fromMessage(null, message, fetchRuntimeSupport);

    checkMessageRequestState(request);
    ClientGetFetchConfig fetchConfig = fetchConfigFrom(request);
    checkMessageFetchConfig(fetchConfig);
    checkFetchRuntimeSupportInteractions();
    checkExecutionSpecShape(
        executionSpecFromRuntimeSupport(),
        request,
        request.getURI(),
        (short) 3,
        fetchConfig,
        false);
  }

  @Test
  void fromMessage_whenReturnTypeNone_marksExecutionSpecDiscardData() throws Exception {
    configureFetchRuntimeSupportDefaults();
    SimpleFieldSet fs = baseMessageFieldSet("message-none");
    fs.putOverwrite("ReturnType", ReturnType.NONE.name());
    ClientGetMessage message = new ClientGetMessage(fs);

    ClientGet request = ClientGetFactory.fromMessage(null, message, fetchRuntimeSupport);

    assertNotNull(request);
    assertFalse(request.isDirect());
    assertFalse(request.isToDisk());
    ArgumentCaptor<ClientGetExecutionSpec> executionSpecCaptor =
        ArgumentCaptor.forClass(ClientGetExecutionSpec.class);
    verify(fetchRuntimeSupport).createExecution(executionSpecCaptor.capture());
    ClientGetExecutionSpec executionSpec = executionSpecCaptor.getValue();
    assertTrue(executionSpec.discardData());
    assertNull(executionSpec.returnBucket());
    assertFalse(executionSpec.binaryBlob());
  }

  @Test
  void fromMessage_whenBinaryBlobBucketCreationFails_wrapsIntoMessageInvalidException()
      throws Exception {
    configureFetchRuntimeSupportDefaults();
    IOException ioFailure = new IOException("disk-full");
    when(fetchRuntimeSupport.createExecution(any(ClientGetExecutionSpec.class)))
        .thenThrow(ioFailure);

    SimpleFieldSet fs = baseMessageFieldSet("blob-io");
    fs.putOverwrite("BinaryBlob", "true");
    ClientGetMessage message = new ClientGetMessage(fs);

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientGetFactory.fromMessage(null, message, fetchRuntimeSupport));

    assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, exception.protocolCode);
    assertEquals("blob-io", exception.ident);
    assertFalse(exception.global);
    assertSame(ioFailure, exception.getCause());
    assertTrue(exception.getMessage().contains("Cannot create bucket for temporary storage"));
    verify(fetchRuntimeSupport).createExecution(any(ClientGetExecutionSpec.class));
  }

  private void configureFetchRuntimeSupportDefaults() throws IOException {
    when(fetchRuntimeSupport.defaultPersistentFetchConfig()).thenReturn(new ClientGetFetchConfig());
    when(fetchRuntimeSupport.transferAccess()).thenReturn(transferAccess);
    lenient()
        .doReturn(execution)
        .when(fetchRuntimeSupport)
        .createExecution(any(ClientGetExecutionSpec.class));
    lenient().when(execution.requester()).thenReturn(requester);
  }

  private FCPConnectionHandler newConnectionHandler() {
    FCPServer server = mock(FCPServer.class);
    FcpServerRuntimeSupport serverRuntimeSupport = mock(FcpServerRuntimeSupport.class);
    Socket socket = mock(Socket.class);
    RuntimePorts handlerRuntimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    when(server.serverRuntimeSupport()).thenReturn(serverRuntimeSupport);
    when(server.runtime()).thenReturn(handlerRuntimePorts);
    when(handlerRuntimePorts.randomness()).thenReturn(randomnessPort);
    doAnswer(
            invocation -> {
              byte[] target = invocation.getArgument(0);
              Arrays.fill(target, (byte) 1);
              return null;
            })
        .when(randomnessPort)
        .fillSecureRandom(any(byte[].class));
    return new FCPConnectionHandler(socket, server);
  }

  private void checkFetchRuntimeSupportInteractions() {
    verify(fetchRuntimeSupport).defaultPersistentFetchConfig();
    verify(fetchRuntimeSupport).transferAccess();
  }

  private ClientGetExecutionSpec executionSpecFromRuntimeSupport() throws IOException {
    ArgumentCaptor<ClientGetExecutionSpec> executionSpecCaptor =
        ArgumentCaptor.forClass(ClientGetExecutionSpec.class);
    verify(fetchRuntimeSupport).createExecution(executionSpecCaptor.capture());
    return executionSpecCaptor.getValue();
  }

  private static void checkGlobalRequestState(
      ClientGet request,
      ClientGetGlobalRequestConfig config,
      FreenetURI uri,
      boolean expectedForever) {
    assertNotNull(request);
    assertEquals(config.identifier(), request.getIdentifier());
    assertSame(uri, request.getURI());
    assertEquals(config.prioClass(), request.getPriority());
    assertTrue(request.isPersistent());
    assertEquals(expectedForever, request.isPersistentForever());
    assertTrue(request.isDirect());
    assertFalse(request.isToDisk());

    RequestClient lowLevelClient = request.getRequestClient();
    assertEquals(expectedForever, lowLevelClient.persistent());
    assertTrue(lowLevelClient.realTimeFlag());
  }

  private static void checkMessageRequestState(ClientGet request) {
    assertNotNull(request);
    assertEquals("message-ok", request.getIdentifier());
    assertEquals((short) 3, request.getPriority());
    assertTrue(request.isDirect());
    assertFalse(request.isToDisk());
    assertFalse(request.isPersistent());
    assertFalse(request.isPersistentForever());

    RequestClient lowLevelClient = request.getRequestClient();
    assertFalse(lowLevelClient.persistent());
    assertTrue(lowLevelClient.realTimeFlag());
  }

  private static ClientGetFetchConfig fetchConfigFrom(ClientGet request) {
    ClientGetFetchConfig fetchConfig = request.requestProfile().fetchConfig();
    assertNotNull(fetchConfig);
    return fetchConfig;
  }

  private static void checkGlobalFetchConfig(
      ClientGetFetchConfig fetchConfig, ClientGetGlobalRequestConfig config) {
    assertTrue(fetchConfig.getLocalRequestOnly());
    assertTrue(fetchConfig.getIgnoreStore());
    assertEquals(config.maxNonSplitfileRetries(), fetchConfig.getMaxNonSplitfileRetries());
    assertEquals(config.maxSplitfileRetries(), fetchConfig.getMaxSplitfileBlockRetries());
    assertTrue(fetchConfig.getFilterData());
    assertEquals(config.maxOutputLength(), fetchConfig.getMaxOutputLength());
    assertEquals(config.maxOutputLength(), fetchConfig.getMaxTempLength());
    assertFalse(fetchConfig.getCanWriteClientCache());
  }

  private static void checkMessageFetchConfig(ClientGetFetchConfig fetchConfig) {
    assertTrue(fetchConfig.getLocalRequestOnly());
    assertTrue(fetchConfig.getIgnoreStore());
    assertEquals(9, fetchConfig.getMaxNonSplitfileRetries());
    assertEquals(9, fetchConfig.getMaxSplitfileBlockRetries());
    assertEquals(2048L, fetchConfig.getMaxOutputLength());
    assertEquals(1024L, fetchConfig.getMaxTempLength());
    assertFalse(fetchConfig.getCanWriteClientCache());
    assertTrue(fetchConfig.getFilterData());
    assertTrue(fetchConfig.getIgnoreUSKDatehints());
  }

  private static void checkExecutionSpecShape(
      ClientGetExecutionSpec executionSpec,
      ClientGet request,
      FreenetURI uri,
      short priority,
      ClientGetFetchConfig fetchConfig,
      boolean persistenceForever) {
    assertSame(request, executionSpec.request());
    assertSame(uri, executionSpec.uri());
    assertEquals(priority, executionSpec.priorityClass());
    assertSame(fetchConfig, executionSpec.fetchConfig());
    assertNull(executionSpec.returnBucket());
    assertFalse(executionSpec.discardData());
    assertFalse(executionSpec.binaryBlob());
    assertEquals(persistenceForever, executionSpec.persistenceForever());
    assertNull(executionSpec.initialMetadata());
    assertNull(executionSpec.extensionCheck());
    assertNotNull(executionSpec.eventListener());
  }

  private static PersistentRequestClient newPersistentClient(Persistence persistence) {
    PersistentRequestRoot root =
        persistence == Persistence.FOREVER ? mock(PersistentRequestRoot.class) : null;
    return new PersistentRequestClient("client", null, false, null, persistence, root);
  }

  private static SimpleFieldSet baseMessageFieldSet(String identifier) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.putSingle("URI", "KSK@" + identifier + ".txt");
    fs.put("IgnoreDS", false);
    fs.put("DSOnly", false);
    fs.put("FilterData", false);
    fs.putSingle("Charset", "UTF-8");
    fs.put("Verbosity", 2);
    fs.putSingle("ReturnType", ReturnType.DIRECT.name());
    fs.put("MaxSize", 4096);
    fs.put("MaxTempSize", 8192);
    fs.put("MaxRetries", 2);
    fs.putSingle("PriorityClass", "2");
    fs.put("BinaryBlob", false);
    fs.putSingle("Persistence", Persistence.CONNECTION.name());
    fs.put("Global", false);
    fs.put("RealTimeFlag", false);
    return fs;
  }

  private static final class StubClientRequest extends ClientRequest {
    StubClientRequest(PersistentRequestClient client, String identifier) {
      super(
          prepareConstructorInit(
              new ClientRequestParams(
                  null, identifier, 0, (short) 1, client.persistence, false, null, false),
              null,
              client));
    }

    @Override
    public void onLostConnection(ClientContext context) {
      // No-op for this focused registration stub.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      // No replay behavior is needed for collision-only tests.
    }

    @Override
    void register(boolean noTags) {
      // The registration lifecycle is managed by the surrounding test setup.
    }

    @Override
    protected FcpRequesterHandle getClientRequest() {
      return null;
    }

    @Override
    protected void freeData() {
      // Stub does not allocate buckets or files.
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
      // Start semantics are irrelevant to identifier collision coverage.
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
      // Resume is intentionally unsupported for this lightweight test double.
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
