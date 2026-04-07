package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.lang.reflect.Field;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.persistence.PersistentRequestClientHandle;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.node.RequestClient;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ClientRequestTest {

  @Test
  void
      prepareConstructorInit_whenConnectionPersistenceWithoutHandler_expectFallbackRequestClient() {
    ClientRequestParams params =
        new ClientRequestParams(
            null,
            "connection-fallback",
            3,
            (short) 2,
            ClientRequest.Persistence.CONNECTION,
            true,
            "token",
            false);

    TestClientRequest request =
        new TestClientRequest(ClientRequest.prepareConstructorInit(params, null), null);

    assertFalse(request.isPersistent());
    assertFalse(request.isPersistentForever());
    assertNull(request.getClient());
    assertTrue(request.getRequestClient().realTimeFlag());
    assertFalse(request.getRequestClient().persistent());
    assertEquals("connection-fallback", request.getIdentifier());
  }

  @Test
  void prepareConstructorInit_whenConnectionPersistenceWithHandler_expectHandlerRequestClient() {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    RequestClient lowLevelClient = mock(RequestClient.class);
    when(handler.connectionRequestClient(true)).thenReturn(lowLevelClient);

    ClientRequestParams params =
        new ClientRequestParams(
            null,
            "connection-handler",
            5,
            (short) 1,
            ClientRequest.Persistence.CONNECTION,
            true,
            null,
            false);

    TestClientRequest request =
        new TestClientRequest(ClientRequest.prepareConstructorInit(params, handler, null), null);

    assertSame(lowLevelClient, request.getRequestClient());
    assertNull(request.getClient());
    verify(handler).connectionRequestClient(true);
  }

  @Test
  void
      prepareConstructorInit_whenGlobalForeverPersistent_expectMaxVerbosityAndPersistentIdentifiers() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest request =
        TestClientRequest.forever(
            "global-request",
            7,
            (short) 4,
            "token-a",
            true,
            true,
            root.getGlobalForeverClient(),
            null);

    RequestIdentifier identifier = request.getRequestIdentifier();
    PersistentRequestIdentifier persistentIdentifier = request.getPersistentRequestIdentifier();

    assertTrue(request.isPersistent());
    assertTrue(request.isPersistentForever());
    assertEquals(Integer.MAX_VALUE, request.verbosityValue());
    assertTrue(identifier.globalQueue);
    assertNull(identifier.clientName);
    assertEquals("global-request", identifier.identifier);
    assertEquals(RequestIdentifier.RequestType.GET, identifier.type);
    assertTrue(persistentIdentifier.isGlobalQueue());
    assertNull(persistentIdentifier.clientName());
    assertEquals("global-request", persistentIdentifier.identifier());
  }

  @Test
  void getRequestIdentifier_whenConnectionPersistence_expectIllegalStateException() {
    TestClientRequest request =
        new TestClientRequest(
            ClientRequest.prepareConstructorInit(
                new ClientRequestParams(
                    null,
                    "connection-id",
                    0,
                    (short) 1,
                    ClientRequest.Persistence.CONNECTION,
                    false,
                    null,
                    false),
                null),
            null);

    assertThrows(IllegalStateException.class, request::getRequestIdentifier);
  }

  @Test
  void applyDiagnosticIdentifier_whenRequesterPresent_expectPrefixedIdentifierAssigned() {
    ClientRequester requester = mock(ClientRequester.class);
    TestClientRequest request =
        new TestClientRequest(
            ClientRequest.prepareConstructorInit(
                new ClientRequestParams(
                    null,
                    "diag-id",
                    0,
                    (short) 1,
                    ClientRequest.Persistence.CONNECTION,
                    false,
                    null,
                    false),
                null),
            null);

    request.applyDiagnosticIdentifierTo(requester);

    assertEquals("fcp:diag-id", request.diagnosticIdentifierValue());
    verify(requester).setExternalRequestIdentifier("fcp:diag-id");
  }

  @Test
  void cancel_whenRequesterPresent_expectRequesterCancelledAndDataFreed() {
    ClientRequester requester = mock(ClientRequester.class);
    ClientContext context = mock(ClientContext.class);
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest request =
        TestClientRequest.forever(
            "cancel-id",
            0,
            (short) 1,
            null,
            false,
            false,
            root.registerForeverClient("cancel-client", null),
            requester);

    request.cancel(context);

    verify(requester).cancel(context);
    assertEquals(1, request.freeDataCalls());
  }

  @Test
  void onShutdown_whenRequesterPresent_expectDelegatesToRequester() {
    ClientRequester requester = mock(ClientRequester.class);
    ClientContext context = mock(ClientContext.class);
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest request =
        TestClientRequest.forever(
            "shutdown-id",
            0,
            (short) 1,
            null,
            false,
            false,
            root.registerForeverClient("shutdown-client", null),
            requester);

    request.onShutdown(context);

    verify(requester).onShutdown(context);
  }

  @Test
  void getClientDetail_whenPersistenceNotForever_expectNoOutput() throws IOException {
    TestClientRequest request =
        new TestClientRequest(
            ClientRequest.prepareConstructorInit(
                new ClientRequestParams(
                    null,
                    "non-persistent",
                    0,
                    (short) 1,
                    ClientRequest.Persistence.CONNECTION,
                    false,
                    null,
                    false),
                null),
            null);
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    request.getClientDetail(new DataOutputStream(buffer), mock(ChecksumChecker.class));

    assertEquals(0, buffer.size());
  }

  @Test
  void persistentDetailConstructor_whenRoundTripped_expectRestoresPersistentState()
      throws IOException, StorageFormatException {
    PersistentRequestRoot originalRoot = new PersistentRequestRoot();
    TestClientRequest original =
        TestClientRequest.forever(
            "roundtrip-id",
            9,
            (short) 4,
            "roundtrip-token",
            false,
            true,
            originalRoot.registerForeverClient("roundtrip-client", null),
            null);
    original.markFinished();

    PersistentRequestRoot resumedRoot = new PersistentRequestRoot();
    PersistentRequestClient resumedClient =
        resumedRoot.registerForeverClient("roundtrip-client", null);
    PersistentRequestCoordinator coordinator = mock(PersistentRequestCoordinator.class);
    when(coordinator.getOrCreateClientHandle(false, "roundtrip-client")).thenReturn(resumedClient);
    ClientContext context = newContextWithCoordinator(coordinator);

    TestClientRequest restored =
        new TestClientRequest(
            new DataInputStream(new ByteArrayInputStream(serializeClientDetail(original))),
            original.getRequestIdentifier(),
            context,
            null);

    assertEquals("roundtrip-id", restored.getIdentifier());
    assertEquals(4, restored.getPriority());
    assertEquals("roundtrip-token", restored.clientTokenValue());
    assertTrue(restored.hasFinished());
    assertSame(resumedClient, restored.getClient());
    assertSame(resumedClient.lowLevelClient(true), restored.getRequestClient());
    verify(coordinator).getOrCreateClientHandle(false, "roundtrip-client");
  }

  @Test
  void
      persistentDetailConstructor_whenCoordinatorReturnsIncompatibleHandle_expectIllegalStateException()
          throws IOException {
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest original =
        TestClientRequest.forever(
            "bad-handle-id",
            1,
            (short) 2,
            null,
            false,
            false,
            root.registerForeverClient("bad-handle-client", null),
            null);
    PersistentRequestCoordinator coordinator = mock(PersistentRequestCoordinator.class);
    when(coordinator.getOrCreateClientHandle(false, "bad-handle-client"))
        .thenReturn(new OpaqueHandle());
    ClientContext context = newContextWithCoordinator(coordinator);
    byte[] clientDetail = serializeClientDetail(original);
    RequestIdentifier requestIdentifier = original.getRequestIdentifier();
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(clientDetail));

    assertThrows(
        IllegalStateException.class,
        () -> new TestClientRequest(input, requestIdentifier, context, null));
  }

  @Test
  void persistentDetailConstructor_whenPriorityInvalid_expectStorageFormatException()
      throws IOException {
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest original =
        TestClientRequest.forever(
            "bad-priority-id",
            1,
            (short) 2,
            null,
            false,
            false,
            root.registerForeverClient("bad-priority-client", null),
            null);
    PersistentRequestCoordinator coordinator = mock(PersistentRequestCoordinator.class);
    when(coordinator.getOrCreateClientHandle(false, "bad-priority-client"))
        .thenReturn(root.registerForeverClient("bad-priority-client", null));
    ClientContext context = newContextWithCoordinator(coordinator);
    byte[] invalidDetail = rewritePriorityToInvalidValue(serializeClientDetail(original));
    RequestIdentifier requestIdentifier = original.getRequestIdentifier();
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(invalidDetail));

    assertThrows(
        StorageFormatException.class,
        () -> new TestClientRequest(input, requestIdentifier, context, null));
  }

  @Test
  void onResume_whenCoordinatorReturnsIncompatibleHandle_expectIllegalStateException() {
    PersistentRequestRoot root = new PersistentRequestRoot();
    TestClientRequest request =
        TestClientRequest.forever(
            "resume-bad-handle",
            0,
            (short) 1,
            null,
            false,
            false,
            root.registerForeverClient("resume-client", null),
            mock(ClientRequester.class));
    PersistentRequestCoordinator coordinator = mock(PersistentRequestCoordinator.class);
    when(coordinator.getOrCreateClientHandle(false, "resume-client"))
        .thenReturn(new OpaqueHandle());
    ClientContext context = newContextWithCoordinator(coordinator);

    assertThrows(IllegalStateException.class, () -> request.onResume(context));
  }

  @Test
  void onResume_whenRequesterPresent_expectInnerResumeRequesterAndCoordinator()
      throws ResumeFailedException {
    ClientRequester requester = mock(ClientRequester.class);
    PersistentRequestRoot originalRoot = new PersistentRequestRoot();
    TestClientRequest request =
        TestClientRequest.forever(
            "resume-ok",
            0,
            (short) 1,
            null,
            false,
            false,
            originalRoot.registerForeverClient("resume-client", null),
            requester);
    PersistentRequestRoot resumedRoot = new PersistentRequestRoot();
    PersistentRequestClient resumedClient =
        resumedRoot.registerForeverClient("resume-client", null);
    PersistentRequestCoordinator coordinator = mock(PersistentRequestCoordinator.class);
    when(coordinator.getOrCreateClientHandle(false, "resume-client")).thenReturn(resumedClient);
    when(coordinator.resumePersistentRequest(request, false, "resume-client"))
        .thenReturn(resumedClient);
    ClientContext context = newContextWithCoordinator(coordinator);

    request.onResume(context);

    InOrder inOrder = inOrder(coordinator, requester);
    inOrder.verify(coordinator).getOrCreateClientHandle(false, "resume-client");
    inOrder.verify(requester).onResume(context);
    inOrder.verify(coordinator).resumePersistentRequest(request, false, "resume-client");
    assertSame(context, request.innerResumeContext());
    assertSame(resumedClient, request.getClient());
    assertSame(resumedClient.lowLevelClient(false), request.getRequestClient());
  }

  private static byte[] serializeClientDetail(TestClientRequest request) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      request.getClientDetail(out, mock(ChecksumChecker.class));
    }
    return buffer.toByteArray();
  }

  private static byte[] rewritePriorityToInvalidValue(byte[] source) throws IOException {
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(source));
        ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(outputBuffer)) {
      output.writeLong(input.readLong());
      output.writeInt(input.readInt());
      RequestIdentifier identifier = new RequestIdentifier(input);
      identifier.writeTo(output);
      output.writeBoolean(input.readBoolean());
      output.writeInt(input.readInt());
      output.writeLong(input.readLong());
      output.writeShort((short) -1);
      boolean hasClientToken = input.readBoolean();
      output.writeBoolean(hasClientToken);
      if (hasClientToken) {
        output.writeUTF(input.readUTF());
      }
      output.writeBoolean(input.readBoolean());
      return outputBuffer.toByteArray();
    }
  }

  @SuppressWarnings("java:S3011")
  private static ClientContext newContextWithCoordinator(PersistentRequestCoordinator coordinator) {
    ClientContext context = mock(ClientContext.class);
    try {
      Field field = ClientContext.class.getDeclaredField("persistentRequestCoordinator");
      field.setAccessible(true);
      field.set(context, coordinator);
      return context;
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set ClientContext.persistentRequestCoordinator", e);
    }
  }

  private static final class OpaqueHandle implements PersistentRequestClientHandle {}

  private static final class TestClientRequest extends ClientRequest {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientRequester requester;
    private transient ClientContext innerResumeContext;
    private int freeDataCalls;

    private TestClientRequest(ConstructorInit init, ClientRequester requester) {
      super(init);
      this.requester = requester;
    }

    private TestClientRequest(
        DataInputStream input,
        RequestIdentifier requestIdentifier,
        ClientContext context,
        ClientRequester requester)
        throws IOException, StorageFormatException {
      super(input, requestIdentifier, context);
      this.requester = requester;
    }

    static TestClientRequest forever(
        String identifier,
        int verbosity,
        short priorityClass,
        String clientToken,
        boolean global,
        boolean realTime,
        PersistentRequestClient client,
        ClientRequester requester) {
      return new TestClientRequest(
          ClientRequest.prepareConstructorInit(
              new ClientRequestParams(
                  null,
                  identifier,
                  verbosity,
                  priorityClass,
                  Persistence.FOREVER,
                  realTime,
                  clientToken,
                  global),
              null,
              client),
          requester);
    }

    int verbosityValue() {
      return verbosity;
    }

    String clientTokenValue() {
      return clientToken;
    }

    int freeDataCalls() {
      return freeDataCalls;
    }

    ClientContext innerResumeContext() {
      return innerResumeContext;
    }

    String diagnosticIdentifierValue() {
      return diagnosticIdentifier();
    }

    void applyDiagnosticIdentifierTo(ClientRequester requester) {
      applyDiagnosticIdentifier(requester);
    }

    void markFinished() {
      finished = true;
    }

    @Override
    public void onLostConnection(ClientContext context) {
      // No-op for focused ClientRequest base-class tests.
    }

    @Override
    public void sendPendingMessages(
        FCPConnectionOutputHandler handler,
        String listRequestIdentifier,
        boolean includeData,
        boolean onlyData) {
      // No-op for focused ClientRequest base-class tests.
    }

    @Override
    void register(boolean noTags) {
      // Registration is outside this test's scope.
    }

    @Override
    protected ClientRequester getClientRequest() {
      return requester;
    }

    @Override
    protected void freeData() {
      freeDataCalls++;
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
      // Start behavior is outside this test's scope.
    }

    @Override
    public boolean hasSucceeded() {
      return false;
    }

    @Override
    public boolean canRestart() {
      return true;
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
      innerResumeContext = context;
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
