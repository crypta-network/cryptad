package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FcpServerPersistentOpsTest {

  @Mock private NodeClientCore core;

  @Mock private FCPServer server;

  @Test
  void load_whenInvoked_expectNoException() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());

    // Act & Assert
    assertDoesNotThrow(ops::load);
  }

  @Test
  void registerRebootClient_whenNewName_expectConnectionStored() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);

    // Act
    PersistentRequestClient client = ops.registerRebootClient("clientA", handler);

    // Assert
    assertSame(handler, client.getConnection());
  }

  @Test
  void registerRebootClient_whenDuplicate_expectOldConnectionClosed() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    FCPConnectionHandler first = mock(FCPConnectionHandler.class);
    FCPConnectionHandler second = mock(FCPConnectionHandler.class);
    PersistentRequestClient initial = ops.registerRebootClient("dup", first);

    // Act
    PersistentRequestClient returned = ops.registerRebootClient("dup", second);

    // Assert
    assertSame(initial, returned);
    assertSame(second, returned.getConnection());
    verify(first).setKilledDupe();
    verify(first).send(any(CloseConnectionDuplicateClientNameMessage.class));
    verify(first).close();
  }

  @Test
  void unregisterClient_whenRebootClient_expectMappingRemoved() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    PersistentRequestClient first = ops.registerRebootClient("clientA", handler);

    // Act
    ops.unregisterClient(first);
    PersistentRequestClient second = ops.registerRebootClient("clientA", handler);

    // Assert
    assertNotSame(first, second);
  }

  @Test
  void registerForeverClient_whenInvoked_expectDelegation() {
    // Arrange
    PersistentRequestRoot root = mock(PersistentRequestRoot.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FcpServerPersistentOps ops = newOps(root);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(root.registerForeverClient("forever", handler)).thenReturn(client);

    // Act
    PersistentRequestClient result = ops.registerForeverClient("forever", handler);

    // Assert
    assertSame(client, result);
    verify(root).registerForeverClient("forever", handler);
  }

  @Test
  void getForeverClient_whenInvoked_expectDelegation() {
    // Arrange
    PersistentRequestRoot root = mock(PersistentRequestRoot.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    FcpServerPersistentOps ops = newOps(root);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(root.getForeverClient("forever", handler)).thenReturn(client);

    // Act
    PersistentRequestClient result = ops.getForeverClient("forever", handler);

    // Assert
    assertSame(client, result);
    verify(root).getForeverClient("forever", handler);
  }

  @Test
  void unregisterClient_whenForeverClient_expectRootNotified() {
    // Arrange
    PersistentRequestRoot root = spy(new PersistentRequestRoot());
    FcpServerPersistentOps ops = newOps(root);
    PersistentRequestClient client =
        new PersistentRequestClient("forever", null, false, null, Persistence.FOREVER, root);

    // Act
    ops.unregisterClient(client);

    // Assert
    verify(root).maybeUnregisterClient(client);
  }

  @Test
  void getGlobalRequests_whenDatabaseKilled_expectPersistenceDisabledException() {
    // Arrange
    when(core.killedDatabase()).thenReturn(true);
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());

    // Act & Assert
    assertThrows(PersistenceDisabledException.class, ops::getGlobalRequests);
  }

  @Test
  void getGlobalRequests_whenCacheContainsEntry_expectStatusReturned() throws Exception {
    // Arrange
    when(core.killedDatabase()).thenReturn(false);
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = ops.getGlobalRebootClient();
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
    RequestStatus[] result = ops.getGlobalRequests();

    // Assert
    assertEquals(1, result.length);
    assertEquals("id-1", result[0].getIdentifier());
  }

  @Test
  void removeGlobalRequestBlocking_whenRebootRemoves_expectTrue() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientContext context = mock(ClientContext.class);
    when(core.getClientContext()).thenReturn(context);
    when(rebootClient.removeByIdentifier("id", true, server, context)).thenReturn(true);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    boolean result = ops.removeGlobalRequestBlocking("id");

    // Assert
    assertTrue(result);
    verify(rebootClient).removeByIdentifier("id", true, server, context);
  }

  @Test
  void removeGlobalRequestBlocking_whenRebootMissing_expectForeverRemoval() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    when(rebootClient.removeByIdentifier("id", true, server, context)).thenReturn(false);
    when(foreverClient.removeByIdentifier("id", true, server, context)).thenReturn(true);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    boolean result = ops.removeGlobalRequestBlocking("id");

    // Assert
    assertTrue(result);
    verify(foreverClient).removeByIdentifier("id", true, server, context);
  }

  @Test
  void removeAllGlobalRequestsBlocking_whenQueued_expectTrue() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    boolean result = ops.removeAllGlobalRequestsBlocking();

    // Assert
    assertTrue(result);
    verify(rebootClient).removeAll();
    verify(foreverClient).removeAll();
  }

  @Test
  void modifyGlobalRequestBlocking_whenRebootRequestPresent_expectModified() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    ClientRequest request = mock(ClientRequest.class);
    when(rebootClient.getRequest("id")).thenReturn(request);
    setField(ops, "globalRebootClient", rebootClient);

    // Act
    boolean result = ops.modifyGlobalRequestBlocking("id", "token", (short) 2);

    // Assert
    assertTrue(result);
    verify(request).modifyRequest("token", (short) 2, server);
  }

  @Test
  void modifyGlobalRequestBlocking_whenRebootMissing_expectForeverModified() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientRequest request = mock(ClientRequest.class);
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    when(rebootClient.getRequest("id")).thenReturn(null);
    when(foreverClient.getRequest("id")).thenReturn(request);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    boolean result = ops.modifyGlobalRequestBlocking("id", "token", (short) 2);

    // Assert
    assertTrue(result);
    verify(request).modifyRequest("token", (short) 2, server);
  }

  @Test
  void makePersistentGlobalRequestBlocking_whenJobSucceeds_expectNoException() throws Exception {
    // Arrange
    PersistentRequestRoot root = new PersistentRequestRoot();
    FcpServerPersistentOps ops = spy(newOps(root));
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    PersistentGlobalRequestParams params =
        new PersistentGlobalRequestParams(
            mock(FreenetURI.class), true, "text/plain", "reboot", "none", false, new File("/tmp"));
    doNothing().when(ops).makePersistentGlobalRequest(params);

    // Act & Assert
    assertDoesNotThrow(() -> ops.makePersistentGlobalRequestBlocking(params));
  }

  @Test
  void makePersistentGlobalRequestBlocking_whenJobThrowsIOException_expectPropagated()
      throws Exception {
    // Arrange
    PersistentRequestRoot root = new PersistentRequestRoot();
    FcpServerPersistentOps ops = spy(newOps(root));
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    PersistentGlobalRequestParams params =
        new PersistentGlobalRequestParams(
            mock(FreenetURI.class), false, "text/plain", "reboot", "none", false, new File("/tmp"));
    doThrow(new IOException("boom")).when(ops).makePersistentGlobalRequest(params);

    // Act & Assert
    assertThrows(IOException.class, () -> ops.makePersistentGlobalRequestBlocking(params));
  }

  @Test
  void makePersistentGlobalRequestBlocking_whenOverloadInvoked_expectParamsForwarded()
      throws Exception {
    // Arrange
    FcpServerPersistentOps ops = spy(newOps(new PersistentRequestRoot()));
    FreenetURI uri = mock(FreenetURI.class);
    AtomicReference<PersistentGlobalRequestParams> captured = new AtomicReference<>();
    doAnswer(
            invocation -> {
              captured.set(invocation.getArgument(0));
              return null;
            })
        .when(ops)
        .makePersistentGlobalRequestBlocking(any(PersistentGlobalRequestParams.class));

    // Act
    ops.makePersistentGlobalRequestBlocking(
        uri, true, "text/plain", "reboot", "none", true, new File("/tmp"));

    // Assert
    PersistentGlobalRequestParams params = captured.get();
    assertNotNull(params);
    assertSame(uri, params.fetchURI());
    assertEquals("text/plain", params.expectedMimeType());
    assertEquals("reboot", params.persistenceType());
    assertEquals("none", params.returnType());
  }

  @Test
  void makePersistentGlobalRequest_whenInvalidReturnType_expectIllegalArgumentException() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentGlobalRequestParams params =
        new PersistentGlobalRequestParams(
            mock(FreenetURI.class),
            false,
            "text/plain",
            "reboot",
            "bogus",
            false,
            new File("/tmp"));

    // Act & Assert
    assertThrows(IllegalArgumentException.class, () -> ops.makePersistentGlobalRequest(params));
  }

  @Test
  void makePersistentGlobalRequest_whenOverloadUsesDownloadsDir_expectForwarded() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = spy(newOps(new PersistentRequestRoot()));
    FreenetURI uri = mock(FreenetURI.class);
    File downloads = new File("/tmp/downloads");
    when(core.getDownloadsDir()).thenReturn(downloads);
    AtomicReference<PersistentGlobalRequestParams> captured = new AtomicReference<>();
    doAnswer(
            invocation -> {
              captured.set(invocation.getArgument(0));
              return null;
            })
        .when(ops)
        .makePersistentGlobalRequest(any(PersistentGlobalRequestParams.class));

    // Act
    ops.makePersistentGlobalRequest(uri, false, "text/plain", "reboot", "none", false);

    // Assert
    PersistentGlobalRequestParams params = captured.get();
    assertNotNull(params);
    assertSame(downloads, params.downloadsDir());
  }

  @Test
  void makePersistentGlobalRequest_whenOverloadWithDir_expectForwarded() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = spy(newOps(new PersistentRequestRoot()));
    FreenetURI uri = mock(FreenetURI.class);
    File downloads = new File("/tmp/custom");
    AtomicReference<PersistentGlobalRequestParams> captured = new AtomicReference<>();
    doAnswer(
            invocation -> {
              captured.set(invocation.getArgument(0));
              return null;
            })
        .when(ops)
        .makePersistentGlobalRequest(any(PersistentGlobalRequestParams.class));

    // Act
    ops.makePersistentGlobalRequest(uri, true, "text/plain", "reboot", "none", true, downloads);

    // Assert
    assertSame(downloads, captured.get().downloadsDir());
  }

  @Test
  void getGlobalForeverClient_whenInvoked_expectInstance() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());

    // Act
    PersistentRequestClient client = ops.getGlobalForeverClient();

    // Assert
    assertNotNull(client);
  }

  @Test
  void getGlobalRequest_whenRebootPresent_expectRebootRequestReturned() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientRequest request = mock(ClientRequest.class);
    when(rebootClient.getRequest("id")).thenReturn(request);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    ClientRequest result = ops.getGlobalRequest("id");

    // Assert
    assertSame(request, result);
    verify(foreverClient, times(0)).getRequest("id");
  }

  @Test
  void setCompletionCallback_whenInvoked_expectAddedToQueues() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    RequestCompletionCallback callback = mock(RequestCompletionCallback.class);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    ops.setCompletionCallback(callback);

    // Assert
    verify(rebootClient).addRequestCompletionCallback(callback);
    verify(foreverClient).addRequestCompletionCallback(callback);
  }

  @Test
  void startBlocking_whenRebootRequest_expectStartInvoked() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    ClientRequest request = mock(ClientRequest.class);
    ClientContext context = mock(ClientContext.class);
    when(core.getClientContext()).thenReturn(context);
    setClientRequestPersistence(request, Persistence.REBOOT);

    // Act
    ops.startBlocking(request);

    // Assert
    verify(request).start(any(ClientContext.class));
  }

  @Test
  void startBlocking_whenForeverRequest_expectQueuedAndStarted() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    ClientRequest request = mock(ClientRequest.class);
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    setClientRequestPersistence(request, Persistence.FOREVER);

    // Act
    ops.startBlocking(request);

    // Assert
    verify(request).register(false);
    verify(request).start(any(ClientContext.class));
  }

  @Test
  void restartBlocking_whenRebootRequest_expectRestarted() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    ClientRequest request = mock(ClientRequest.class);
    ClientContext context = mock(ClientContext.class);
    when(core.getClientContext()).thenReturn(context);
    when(rebootClient.getRequest("id")).thenReturn(request);
    setField(ops, "globalRebootClient", rebootClient);

    // Act
    boolean result = ops.restartBlocking("id", true);

    // Assert
    assertTrue(result);
    verify(request).restart(context, true);
  }

  @Test
  void restartBlocking_whenRebootMissing_expectForeverRestarted() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientRequest request = mock(ClientRequest.class);
    ClientContext context = clientContextWithJobRunner(new ImmediateJobRunner());
    when(core.getClientContext()).thenReturn(context);
    when(rebootClient.getRequest("id")).thenReturn(null);
    when(foreverClient.getRequest("id")).thenReturn(request);
    setField(ops, "globalRebootClient", rebootClient);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    boolean result = ops.restartBlocking("id", false);

    // Assert
    assertTrue(result);
    verify(request).restart(any(ClientContext.class), eq(false));
  }

  @Test
  void getCompletedRequestBlocking_whenRebootCompleted_expectFetchResult() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    ClientGet get = mock(ClientGet.class);
    Bucket bucket = mock(Bucket.class);
    when(get.getMIMEType()).thenReturn("text/plain");
    when(get.getBucket()).thenReturn(bucket);
    when(rebootClient.getCompletedRequest(any(FreenetURI.class))).thenReturn(get);
    setField(ops, "globalRebootClient", rebootClient);

    // Act
    FetchResult result = ops.getCompletedRequestBlocking(mock(FreenetURI.class));

    // Assert
    assertEquals("text/plain", result.getMimeType());
    assertNotNull(result.getMetadata());
  }

  @Test
  void lookupInstant_whenCompletedRequestNoCopy_expectCacheResult() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient rebootClient = mock(PersistentRequestClient.class);
    ClientGet get = mock(ClientGet.class);
    Bucket bucket = mock(Bucket.class);
    when(get.filterData()).thenReturn(true);
    when(get.getMIMEType()).thenReturn("text/plain");
    when(get.getBucket()).thenReturn(bucket);
    when(rebootClient.getCompletedRequest(any(FreenetURI.class))).thenReturn(get);
    setField(ops, "globalRebootClient", rebootClient);

    // Act
    CacheFetchResult result = ops.lookupInstant(mock(FreenetURI.class), false, false, null);

    // Assert
    assertNotNull(result);
    assertEquals("text/plain", result.getMimeType());
    assertTrue(result.alreadyFiltered);
  }

  @Test
  void lookup_whenCompletedRequestNoCopy_expectShadowBucketReturned() throws Exception {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());
    PersistentRequestClient foreverClient = mock(PersistentRequestClient.class);
    ClientGet get = mock(ClientGet.class);
    Bucket bucket = mock(Bucket.class);
    Bucket shadow = mock(Bucket.class);
    when(get.filterData()).thenReturn(false);
    when(get.getBucket()).thenReturn(bucket);
    when(get.getMIMEType()).thenReturn("text/plain");
    when(bucket.createShadow()).thenReturn(shadow);
    when(foreverClient.getCompletedRequest(any(FreenetURI.class))).thenReturn(get);
    setField(ops, "globalForeverClient", foreverClient);

    // Act
    CacheFetchResult result =
        ops.lookup(mock(FreenetURI.class), false, mock(ClientContext.class), false, null);

    // Assert
    assertNotNull(result);
    assertSame(shadow, result.asBucket());
    assertEquals("text/plain", result.getMimeType());
  }

  @Test
  void getGlobalRebootClient_whenInvoked_expectInstance() {
    // Arrange
    FcpServerPersistentOps ops = newOps(new PersistentRequestRoot());

    // Act
    PersistentRequestClient client = ops.getGlobalRebootClient();

    // Assert
    assertNotNull(client);
  }

  private FcpServerPersistentOps newOps(PersistentRequestRoot root) {
    return new FcpServerPersistentOps(server, core, root);
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private ClientContext clientContextWithJobRunner(PersistentJobRunner runner) throws Exception {
    ClientContext context = mock(ClientContext.class);
    Field field = ClientContext.class.getDeclaredField("jobRunner");
    field.setAccessible(true);
    field.set(context, runner);
    return context;
  }

  private void setClientRequestPersistence(ClientRequest request, Persistence persistence)
      throws Exception {
    Field field = ClientRequest.class.getDeclaredField("persistence");
    field.setAccessible(true);
    field.set(request, persistence);
  }

  private static final class ImmediateJobRunner implements PersistentJobRunner {
    @Override
    public void queue(PersistentJob persistentJob, int threadPriority) {
      persistentJob.run(mock(ClientContext.class));
    }

    @Override
    public void queueNormalOrDrop(PersistentJob persistentJob) {
      persistentJob.run(mock(ClientContext.class));
    }

    @Override
    public void queueInternal(PersistentJob job, int threadPriority) {
      job.run(mock(ClientContext.class));
    }

    @Override
    public void queueInternal(PersistentJob job) {
      job.run(mock(ClientContext.class));
    }

    @Override
    public void setCheckpointASAP() {
      // This test runner executes jobs synchronously and does not model checkpoints.
      throw new UnsupportedOperationException("Checkpoint scheduling is not supported in tests");
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
}
