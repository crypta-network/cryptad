package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.File;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.USKManager;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.clients.fcp.RequestCompletionCallback;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestStarterGroup;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.node.useralerts.UserEvent;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class QueueToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private FCPServer fcp;
  @Mock private UserAlertManager alerts;
  @Mock private PriorityAwareExecutor executor;
  @Mock private ClientLayerPersister jobRunner;
  private RequestCompletionCallback completionCallback;

  @TempDir Path tempDir;

  @Test
  void constructor_whenInstantiated_setsCompletionCallbackAndQueuesLoadJob() throws Exception {
    // Arrange
    QueueToadlet toadlet = createQueueToadlet(false);

    // Assert
    RequestCompletionCallback callback = getCompletionCallback();
    verify(fcp).setCompletionCallback(callback);
    verify(jobRunner, times(1)).queue(any(PersistentJob.class), anyInt());
    assertEquals(QueueToadlet.PATH_DOWNLOADS, toadlet.path());
  }

  @Test
  void path_whenUploadsFlagTrue_returnsUploadsPath() throws Exception {
    QueueToadlet toadlet = createQueueToadlet(true);

    assertEquals(QueueToadlet.PATH_UPLOADS, toadlet.path());
  }

  @Test
  void notifySuccess_whenDownloadCompleted_recordsIdentifierAndRegistersAlert() throws Exception {
    // Arrange
    createQueueToadlet(false);
    clearInvocations(executor, alerts, jobRunner);

    ClientGet request = mock(ClientGet.class);
    when(request.getIdentifier()).thenReturn("download-1");
    when(request.hasFinished()).thenReturn(true);
    when(request.getURI()).thenReturn(sampleUri());
    when(request.getDataSize()).thenReturn(123L);

    // Act
    getCompletionCallback().notifySuccess(request);

    // Assert
    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    assertTrue(completedList.exists());
    assertEquals("download-1\n", Files.readString(completedList.toPath()));

    ArgumentCaptor<UserEvent> alertCaptor = ArgumentCaptor.forClass(UserEvent.class);
    verify(alerts).register(alertCaptor.capture());
    assertTrue(alertCaptor.getValue().getClass().getSimpleName().contains("GetCompletedEvent"));
    verify(executor).execute(any(Runnable.class), anyString());
  }

  @Test
  void notifySuccess_whenDirectionMismatch_doesNothing() throws Exception {
    // Arrange
    createQueueToadlet(false);
    clearInvocations(executor, alerts);

    ClientPut uploadRequest = mock(ClientPut.class);

    // Act
    getCompletionCallback().notifySuccess(uploadRequest);

    // Assert
    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    if (completedList.exists()) {
      assertEquals(0, Files.size(completedList.toPath()));
    }
    verifyNoInteractions(alerts);
    verify(executor, times(0)).execute(any(Runnable.class), anyString());
  }

  @Test
  void onRemove_whenEntryExists_removesAndPersistsEmptyList() throws Exception {
    // Arrange
    createQueueToadlet(false);
    clearInvocations(executor, alerts, jobRunner);

    ClientGet request = mock(ClientGet.class);
    when(request.getIdentifier()).thenReturn("download-2");
    when(request.hasFinished()).thenReturn(true);
    when(request.getURI()).thenReturn(sampleUri());
    when(request.getDataSize()).thenReturn(500L);

    getCompletionCallback().notifySuccess(request);
    clearInvocations(executor, alerts);

    // Act
    getCompletionCallback().onRemove(request);

    // Assert
    File completedList = tempDir.resolve("completed.list.downloads").toFile();
    assertTrue(completedList.exists());
    assertEquals(0, Files.readAllBytes(completedList.toPath()).length);

    Map<?, ?> completedGets = getCompletedGets();
    assertFalse(completedGets.containsKey("download-2"));
    verify(executor).execute(any(Runnable.class), anyString());
  }

  private QueueToadlet createQueueToadlet(boolean uploads) throws Exception {
    ProgramDirectory userDir = new ProgramDirectory();
    userDir.move(tempDir.toString());

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.userDir()).thenReturn(userDir);
    when(node.getUserDir()).thenReturn(userDir.dir());

    RequestStarterGroup starters = mock(RequestStarterGroup.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getNode()).thenReturn(node);
    when(core.getAlerts()).thenReturn(alerts);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);

    ClientContext context = createClientContext();
    context.init(starters, alerts);
    when(core.getClientContext()).thenReturn(context);

    when(fcp.getGlobalRequest(anyString())).thenReturn(null);
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
              job.run(null);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());

    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));

    return new QueueToadlet(core, fcp, client, uploads);
  }

  private ClientContext createClientContext() {
    ArchiveManager archiveManager = mock(ArchiveManager.class);
    PersistentTempBucketFactory ptbf = mock(PersistentTempBucketFactory.class);
    TempBucketFactory tbf = mock(TempBucketFactory.class);
    PersistentFileTracker tracker = mock(PersistentFileTracker.class);
    HealingQueue hq = mock(HealingQueue.class);
    USKManager uskManager = mock(USKManager.class);
    RandomSource strongRandom = mock(RandomSource.class);
    Ticker ticker = mock(Ticker.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    FilenameGenerator fg = mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory rafFactory = mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRAFFactory =
        mock(LockableRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFTransient = mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFPersistent = mock(FileRandomAccessBufferFactory.class);
    RealCompressor rc = mock(RealCompressor.class);
    DatastoreChecker checker = mock(DatastoreChecker.class);
    PersistentRequestRoot persistentRoot = mock(PersistentRequestRoot.class);
    MasterSecret masterSecret = mock(MasterSecret.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        mock(LinkFilterExceptionProvider.class);
    FetchContext fetchContext = mock(FetchContext.class);
    InsertContext insertContext = mock(InsertContext.class);
    Config config = mock(Config.class);

    return new ClientContext(
        1L,
        jobRunner,
        executor,
        archiveManager,
        ptbf,
        tbf,
        tracker,
        hq,
        uskManager,
        strongRandom,
        new Random(123),
        ticker,
        memoryLimitedJobRunner,
        fg,
        fg,
        rafFactory,
        persistentRAFFactory,
        fileRAFTransient,
        fileRAFPersistent,
        rc,
        checker,
        persistentRoot,
        masterSecret,
        linkFilterExceptionProvider,
        fetchContext,
        insertContext,
        config);
  }

  private FreenetURI sampleUri() {
    try {
      return new FreenetURI(
          "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml");
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("unchecked")
  private Map<String, ?> getCompletedGets() throws NoSuchFieldException, IllegalAccessException {
    Object tracker = getCompletionTracker();
    var field = tracker.getClass().getDeclaredField("completedGets");
    field.setAccessible(true);
    return (Map<String, ?>) field.get(tracker);
  }

  private RequestCompletionCallback getCompletionCallback() {
    return (RequestCompletionCallback) getCompletionTracker();
  }

  private Object getCompletionTracker() {
    if (completionCallback == null) {
      throw new IllegalStateException("Completion callback was not captured.");
    }
    return completionCallback;
  }
}
