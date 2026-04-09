package network.crypta.clients.fcp.bridge;

import java.io.File;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextResources;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.ClientPutDir;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestCompletionCallback;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.alerts.UserEvent;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyQueueCompletionPortTest {

  @Mock private NodeClientCore core;
  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private PriorityAwareExecutor executor;
  @Mock private ClientLayerPersister jobRunner;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcp;
  @Mock private UserAlertManager alerts;

  @TempDir Path tempDir;

  private ClientContext clientContext;
  private RequestCompletionCallback completionCallback;
  private LegacyQueueCompletionPort port;

  @BeforeEach
  void setUp() throws Exception {
    ProgramDirectory userDir = new ProgramDirectory();
    userDir.move(tempDir.toString());

    clientContext = createClientContext();
    when(core.getNode()).thenReturn(node);
    when(core.getClientContext()).thenReturn(clientContext);
    when(core.getEndpoints()).thenReturn(endpoints);
    when(core.getAlerts()).thenReturn(alerts);
    when(node.userDir()).thenReturn(userDir);
    when(node.getUserDir()).thenReturn(userDir.dir());
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcp));

    doAnswer(
            invocation -> {
              completionCallback = invocation.getArgument(0);
              return null;
            })
        .when(fcp)
        .setCompletionCallback(any(RequestCompletionCallback.class));
    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(clientContext);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());
    doAnswer(
            invocation -> {
              Runnable task = invocation.getArgument(0);
              task.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());

    port = new LegacyQueueCompletionPort(core);
  }

  @Test
  void ensureTrackingStarted_whenDownloadsRequested_registersCallbackAndQueuesRecoveryWork()
      throws Exception {
    port.ensureTrackingStarted(false);

    assertNotNull(completionCallback);
    verify(fcp).setCompletionCallback(completionCallback);
    verify(jobRunner).queue(any(PersistentJob.class), anyInt());
  }

  @Test
  void ensureTrackingStarted_whenCalledTwiceForSameSide_isIdempotent() throws Exception {
    port.ensureTrackingStarted(false);
    port.ensureTrackingStarted(false);

    verify(fcp).setCompletionCallback(any(RequestCompletionCallback.class));
    verify(jobRunner).queue(any(PersistentJob.class), anyInt());
  }

  @Test
  void ensureTrackingStarted_whenUploadsRequestedAfterDownloads_registersIndependentTracker()
      throws Exception {
    port.ensureTrackingStarted(false);
    RequestCompletionCallback downloadCallback = completionCallback;

    port.ensureTrackingStarted(true);

    assertNotNull(completionCallback);
    assertNotSame(downloadCallback, completionCallback);
    verify(fcp, times(2)).setCompletionCallback(any(RequestCompletionCallback.class));
    verify(jobRunner, times(2)).queue(any(PersistentJob.class), anyInt());
  }

  @Test
  void ensureTrackingStarted_whenPersistenceDisabledDuringLoad_ignoresException() throws Exception {
    doThrow(new PersistenceDisabledException())
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    assertDoesNotThrow(() -> port.ensureTrackingStarted(false));

    assertNotNull(completionCallback);
    verify(fcp).setCompletionCallback(any(RequestCompletionCallback.class));
    verify(jobRunner).queue(any(PersistentJob.class), anyInt());
  }

  @Test
  void ensureTrackingStarted_whenFcpServerUnavailable_throwsIllegalStateException() {
    when(endpoints.getFcpEndpoint()).thenReturn(null);

    IllegalStateException thrown =
        assertThrows(IllegalStateException.class, () -> port.ensureTrackingStarted(false));

    assertEquals("FCP server unavailable", thrown.getMessage());
  }

  @Test
  void notifySuccess_whenDownloadCompleted_writesIdentifierAndRegistersAlert() throws Exception {
    port.ensureTrackingStarted(false);
    clearInvocations(executor, alerts);

    ClientGet completedRequest = mockCompletedDownload("download-1", 123L);

    completionCallback.notifySuccess(completedRequest);

    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    assertTrue(completedList.exists());
    assertEquals("download-1\n", Files.readString(completedList.toPath()));

    ArgumentCaptor<UserEvent> alertCaptor = ArgumentCaptor.forClass(UserEvent.class);
    verify(alerts).register(alertCaptor.capture());
    assertTrue(alertCaptor.getValue().getClass().getSimpleName().contains("GetCompletedEvent"));
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void notifySuccess_whenDownloadNotFinished_persistsIdentifierWithoutRegisteringAlert()
      throws Exception {
    port.ensureTrackingStarted(false);
    clearInvocations(executor, alerts);

    ClientGet incompleteRequest = org.mockito.Mockito.mock(ClientGet.class);
    when(incompleteRequest.getIdentifier()).thenReturn("download-pending");
    when(incompleteRequest.hasFinished()).thenReturn(false);

    completionCallback.notifySuccess(incompleteRequest);

    assertEquals(
        "download-pending\n", Files.readString(tempDir.resolve("completed.list.downloads")));
    verifyNoInteractions(alerts);
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void notifySuccess_whenDirectionMismatch_ignoresRequest() throws Exception {
    port.ensureTrackingStarted(false);
    clearInvocations(executor, alerts);

    ClientPut uploadRequest = org.mockito.Mockito.mock(ClientPut.class);

    completionCallback.notifySuccess(uploadRequest);

    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    if (completedList.exists()) {
      assertEquals("", Files.readString(completedList.toPath()));
    }
    verifyNoInteractions(alerts);
    verify(executor, never()).execute(any(Runnable.class), anyString());
  }

  @Test
  void notifySuccess_whenUploadCompleted_writesIdentifierAndRegistersUploadAlert()
      throws Exception {
    port.ensureTrackingStarted(true);
    clearInvocations(executor, alerts);

    ClientPut completedRequest = org.mockito.Mockito.mock(ClientPut.class);
    when(completedRequest.getIdentifier()).thenReturn("upload-1");
    when(completedRequest.hasFinished()).thenReturn(true);
    when(completedRequest.getFinalURI()).thenReturn(sampleUri());
    when(completedRequest.getDataSize()).thenReturn(456L);

    completionCallback.notifySuccess(completedRequest);

    assertEquals("upload-1\n", Files.readString(tempDir.resolve("completed.list.uploads")));
    ArgumentCaptor<UserEvent> alertCaptor = ArgumentCaptor.forClass(UserEvent.class);
    verify(alerts).register(alertCaptor.capture());
    UserEvent alert = alertCaptor.getValue();
    assertEquals(UserEvent.Type.PUT_COMPLETED, alert.getEventType());
    assertTrue(alert.getTitle().contains(sampleUri().getPreferredFilename()));
    assertTrue(alert.getHTMLText().generate().contains(sampleUri().getPreferredFilename()));
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void notifySuccess_whenDirectoryUploadDismissed_clearsIdentifierAndInvalidatesAlert()
      throws Exception {
    port.ensureTrackingStarted(true);
    clearInvocations(executor, alerts);

    ClientPutDir completedRequest = org.mockito.Mockito.mock(ClientPutDir.class);
    when(completedRequest.getIdentifier()).thenReturn("site-1");
    when(completedRequest.hasFinished()).thenReturn(true);
    when(completedRequest.getFinalURI()).thenReturn(sampleUri());
    when(completedRequest.getTotalDataSize()).thenReturn(789L);
    when(completedRequest.getNumberOfFiles()).thenReturn(4);

    completionCallback.notifySuccess(completedRequest);

    ArgumentCaptor<UserEvent> alertCaptor = ArgumentCaptor.forClass(UserEvent.class);
    verify(alerts).register(alertCaptor.capture());
    UserEvent alert = alertCaptor.getValue();
    assertEquals(UserEvent.Type.PUT_DIR_COMPLETED, alert.getEventType());
    assertTrue(alert.getTitle().contains(sampleUri().getPreferredFilename()));

    clearInvocations(executor);
    alert.onDismiss();

    assertEquals("", Files.readString(tempDir.resolve("completed.list.uploads")));
    assertFalse(alert.isValid());
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void onRemove_whenEntryExists_clearsIdentifierAndPersistsChange() throws Exception {
    port.ensureTrackingStarted(false);

    ClientGet completedRequest = mockCompletedDownload("download-2", 500L);

    completionCallback.notifySuccess(completedRequest);
    clearInvocations(executor, alerts);

    completionCallback.onRemove(completedRequest);

    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    assertTrue(completedList.exists());
    assertEquals("", Files.readString(completedList.toPath()));
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void ensureTrackingStarted_whenPersistedIdentifiersReplayed_cleansStaleEntries()
      throws Exception {
    Files.writeString(
        tempDir.resolve("completed.list.downloads"),
        "download-keep\ndownload-stale\nupload-wrong-side\n");

    ClientGet replayedDownload = org.mockito.Mockito.mock(ClientGet.class);
    when(replayedDownload.getIdentifier()).thenReturn("download-keep");
    when(replayedDownload.hasFinished()).thenReturn(true);
    when(replayedDownload.getURI()).thenReturn(sampleUri());
    when(replayedDownload.getDataSize()).thenReturn(321L);

    ClientPut wrongSideUpload = org.mockito.Mockito.mock(ClientPut.class);
    when(wrongSideUpload.getIdentifier()).thenReturn("upload-wrong-side");

    when(fcp.getGlobalRequest("download-keep")).thenReturn(replayedDownload);
    when(fcp.getGlobalRequest("download-stale")).thenReturn(null);
    when(fcp.getGlobalRequest("upload-wrong-side")).thenReturn(wrongSideUpload);

    port.ensureTrackingStarted(false);

    assertEquals("download-keep\n", Files.readString(tempDir.resolve("completed.list.downloads")));
    verify(fcp).getGlobalRequest("download-keep");
    verify(fcp).getGlobalRequest("download-stale");
    verify(fcp).getGlobalRequest("upload-wrong-side");
    verify(alerts).register(any(UserEvent.class));
  }

  @Test
  void ensureTrackingStarted_whenLegacyCompletedListExists_migratesToSideSpecificFile()
      throws Exception {
    Files.writeString(tempDir.resolve("completed.list"), "download-legacy\n");
    ClientGet replayedDownload = mockCompletedDownload("download-legacy", 654L);
    when(fcp.getGlobalRequest("download-legacy")).thenReturn(replayedDownload);

    port.ensureTrackingStarted(false);

    assertEquals(
        "download-legacy\n", Files.readString(tempDir.resolve("completed.list.downloads")));
    verify(fcp).getGlobalRequest("download-legacy");
    verify(alerts).register(any(UserEvent.class));
  }

  @Test
  void ensureTrackingStarted_whenSideSpecificListExists_deletesLegacyCompletedList()
      throws Exception {
    Files.writeString(tempDir.resolve("completed.list.downloads"), "download-current\n");
    Files.writeString(tempDir.resolve("completed.list"), "download-legacy\n");
    ClientGet replayedDownload = mockCompletedDownload("download-current", 111L);
    when(fcp.getGlobalRequest("download-current")).thenReturn(replayedDownload);

    port.ensureTrackingStarted(false);

    assertFalse(Files.exists(tempDir.resolve("completed.list")));
    assertEquals(
        "download-current\n", Files.readString(tempDir.resolve("completed.list.downloads")));
  }

  private ClientGet mockCompletedDownload(String identifier, long size) {
    ClientGet completedRequest = org.mockito.Mockito.mock(ClientGet.class);
    when(completedRequest.getIdentifier()).thenReturn(identifier);
    when(completedRequest.hasFinished()).thenReturn(true);
    when(completedRequest.getURI()).thenReturn(sampleUri());
    when(completedRequest.getDataSize()).thenReturn(size);
    return completedRequest;
  }

  private ClientContext createClientContext() {
    ArchiveManager archiveManager = org.mockito.Mockito.mock(ArchiveManager.class);
    PersistentTempBucketFactory ptbf = org.mockito.Mockito.mock(PersistentTempBucketFactory.class);
    TempBucketFactory tbf = org.mockito.Mockito.mock(TempBucketFactory.class);
    PersistentFileTracker tracker = org.mockito.Mockito.mock(PersistentFileTracker.class);
    HealingQueue hq = org.mockito.Mockito.mock(HealingQueue.class);
    USKManager uskManager = org.mockito.Mockito.mock(USKManager.class);
    RandomSource strongRandom = org.mockito.Mockito.mock(RandomSource.class);
    Ticker ticker = org.mockito.Mockito.mock(Ticker.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner =
        org.mockito.Mockito.mock(MemoryLimitedJobRunner.class);
    FilenameGenerator fg = org.mockito.Mockito.mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory rafFactory =
        org.mockito.Mockito.mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRafFactory =
        org.mockito.Mockito.mock(LockableRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRafTransient =
        org.mockito.Mockito.mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRafPersistent =
        org.mockito.Mockito.mock(FileRandomAccessBufferFactory.class);
    RealCompressor rc = org.mockito.Mockito.mock(RealCompressor.class);
    DatastoreChecker checker = org.mockito.Mockito.mock(DatastoreChecker.class);
    PersistentRequestCoordinator persistentRoot =
        org.mockito.Mockito.mock(PersistentRequestCoordinator.class);
    MasterSecret masterSecret = org.mockito.Mockito.mock(MasterSecret.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        org.mockito.Mockito.mock(LinkFilterExceptionProvider.class);
    FetchContext fetchContext = org.mockito.Mockito.mock(FetchContext.class);
    InsertContext insertContext = org.mockito.Mockito.mock(InsertContext.class);
    Config config = org.mockito.Mockito.mock(Config.class);

    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            executor,
            memoryLimitedJobRunner,
            ticker,
            strongRandom,
            new Random(123),
            masterSecret),
        new ClientContextStorageFactories(
            ptbf, tbf, tracker, fg, fg, fileRafTransient, fileRafPersistent),
        new ClientContextRafFactories(rafFactory, persistentRafFactory),
        new ClientContextServices(
            new ClientContextResources(archiveManager, hq),
            uskManager,
            rc,
            checker,
            persistentRoot,
            linkFilterExceptionProvider),
        new ClientContextDefaults(fetchContext, insertContext, config));
  }

  private FreenetURI sampleUri() {
    try {
      return new FreenetURI(
          "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml");
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }
}
