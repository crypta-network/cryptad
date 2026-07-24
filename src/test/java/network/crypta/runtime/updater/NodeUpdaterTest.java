package network.crypta.runtime.updater;

import java.io.File;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKFoundEditionPayload;
import network.crypta.client.async.USKFoundEditionProgress;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NodeUpdaterTest {

  private static final int CURRENT_VERSION = 1200;
  private static final int DEFAULT_SUBSCRIBE_SEED = 1325;
  private static final String BLOB_PREFIX = "core-info-";

  @TempDir Path tempDir;

  @Mock NodeUpdateManager manager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock NodeClientCore core;
  @Mock USKManager uskManager;
  @Mock HighLevelSimpleClient highLevelSimpleClient;
  @Mock ClientContext clientContext;
  @Mock Ticker ticker;

  private TestNodeUpdater updater;

  @BeforeEach
  void setUp() throws Exception {
    when(manager.getNode()).thenReturn(node);

    when(node.services().clientCore()).thenReturn(core);
    when(node.network().ticker()).thenReturn(ticker);

    when(core.makeClient(anyShort(), anyBoolean(), anyBoolean())).thenReturn(highLevelSimpleClient);
    when(highLevelSimpleClient.getFetchContext()).thenReturn(createFetchContext());

    updater = new TestNodeUpdater(defaultParams());
  }

  @Test
  void start_whenSubscribeSeedProvided_expectSubscribeFromSeedEdition() {
    // Arrange
    when(core.getUskManager()).thenReturn(uskManager);

    // Act
    updater.start();

    // Assert
    ArgumentCaptor<USK> capturedUsk = ArgumentCaptor.forClass(USK.class);
    verify(uskManager).subscribe(capturedUsk.capture(), same(updater), eq(true), same(updater));
    assertEquals(1325L, capturedUsk.getValue().suggestedEdition);
  }

  @Test
  void start_whenUpdaterWasStopped_expectNoDetachedSubscription() {
    // Arrange
    when(core.getUskManager()).thenReturn(uskManager);
    updater.preKill();
    updater.kill();

    // Act
    updater.start();

    // Assert
    verify(uskManager, never()).subscribe(any(), same(updater), eq(true), same(updater));
  }

  @Test
  void onChangeURI_whenSeedProvided_expectUpdaterUriAndSubscribeUseSeed() throws Exception {
    // Arrange
    when(core.getUskManager()).thenReturn(uskManager);
    FreenetURI newUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/600");

    // Act
    updater.onChangeURI(newUri, 1450);

    // Assert
    assertEquals(1450L, updater.getUpdateKey().getSuggestedEdition());
    assertEquals(CURRENT_VERSION, updater.getFetchedVersion());
    ArgumentCaptor<USK> capturedUsk = ArgumentCaptor.forClass(USK.class);
    verify(uskManager).subscribe(capturedUsk.capture(), same(updater), eq(true), same(updater));
    assertEquals(1450L, capturedUsk.getValue().suggestedEdition);
  }

  @Test
  void onSuccess_whenOldUriCallbackArrives_expectOnlyOldAttemptFileDeleted() throws Exception {
    // Arrange
    prepareFetchRuntime();
    ClientGetter oldGetter = startFetch(CURRENT_VERSION + 1, 1);
    Path oldTempBlob = findOnlyTempBlob();
    FreenetURI newUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/alternate-info/1");
    updater.onChangeURI(newUri, 1);
    Files.writeString(oldTempBlob, "late-old-fetch");
    ClientGetter replacementGetter = startFetch(CURRENT_VERSION + 2, 2);
    Path replacementTempBlob = findTempBlobOtherThan(oldTempBlob);
    FetchResult staleResult = mock(FetchResult.class);
    Bucket staleBucket = mock(Bucket.class);
    when(staleResult.asBucket()).thenReturn(staleBucket);

    // Act
    oldGetter.getClientCallback().onSuccess(staleResult, oldGetter);

    // Assert
    assertFalse(Files.exists(oldTempBlob));
    assertTrue(Files.exists(replacementTempBlob));
    assertNotEquals(oldGetter, replacementGetter);
    assertTrue(updater.isFetching());
    verify(staleBucket).close();
  }

  @Test
  void onFailure_whenOldUriCallbackArrives_expectReplacementAttemptUntouched() throws Exception {
    // Arrange
    prepareFetchRuntime();
    ClientGetter oldGetter = startFetch(CURRENT_VERSION + 1, 1);
    Path oldTempBlob = findOnlyTempBlob();
    FreenetURI newUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/alternate-info/1");
    updater.onChangeURI(newUri, 1);
    Files.writeString(oldTempBlob, "late-old-fetch");
    startFetch(CURRENT_VERSION + 2, 2);
    Path replacementTempBlob = findTempBlobOtherThan(oldTempBlob);

    // Act
    oldGetter
        .getClientCallback()
        .onFailure(new FetchException(FetchExceptionMode.CANCELLED, "old URI cancelled"));

    // Assert
    assertFalse(Files.exists(oldTempBlob));
    assertTrue(Files.exists(replacementTempBlob));
    assertTrue(updater.isFetching());
    verify(ticker, never()).queueTimedJob(any(Runnable.class), eq(0L));
  }

  @Test
  void kill_whenLateFailureRecreatesAttemptFile_expectOwnedFileDeletedWithoutRetry()
      throws Exception {
    // Arrange
    prepareFetchRuntime();
    ClientGetter stoppedGetter = startFetch(CURRENT_VERSION + 1, 1);
    Path stoppedTempBlob = findOnlyTempBlob();
    updater.kill();
    Files.writeString(stoppedTempBlob, "late-stopped-fetch");

    // Act
    stoppedGetter
        .getClientCallback()
        .onFailure(new FetchException(FetchExceptionMode.CANCELLED, "updater stopped"));

    // Assert
    assertFalse(Files.exists(stoppedTempBlob));
    assertFalse(updater.isFetching());
    verify(ticker, never()).queueTimedJob(any(Runnable.class), eq(0L));
  }

  @Test
  void onSuccess_whenFetchedUriProvided_expectRecordSuccessfulFetchWithProvidedUri()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());
    FreenetURI fetchedUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/1433");

    // Act
    updater.onSuccess(result, tempBlobFile, 1433, fetchedUri);

    // Assert
    verify(manager).recordSuccessfulCoreInfoFetch(fetchedUri, 1433);
    assertTrue(updater.getBlobFile(1433).exists());
  }

  @Test
  void onSuccess_whenFetchedUriIsNull_expectRecordSuccessfulFetchWithCurrentUpdateKey()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());

    // Act
    updater.onSuccess(result, tempBlobFile, 1434, null);

    // Assert
    ArgumentCaptor<FreenetURI> recordedUri = ArgumentCaptor.forClass(FreenetURI.class);
    verify(manager).recordSuccessfulCoreInfoFetch(recordedUri.capture(), eq(1434));
    assertEquals(
        updater.getUpdateKey().toString(false, false),
        recordedUri.getValue().toString(false, false));
    assertTrue(updater.getBlobFile(1434).exists());
  }

  @Test
  void onSuccess_whenPostProcessingRejectsEdition_expectEditionCanBeProcessedAgain()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    updater.acceptFetch = false;
    File first = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());
    File second = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());

    // Act
    updater.onSuccess(result, first, 1435, null);
    updater.onSuccess(result, second, 1435, null);

    // Assert
    assertEquals(2, updater.processCalls);
    verify(manager, never()).recordSuccessfulCoreInfoFetch(any(), eq(1435));
  }

  @Test
  void onSuccess_whenTransientPostProcessingFails_expectRetryScheduled() throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    updater.acceptFetch = false;
    updater.rejectedFetchRetryDelayMillis = 7500L;
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());

    // Act
    updater.onSuccess(result, tempBlobFile, 1436, null);

    // Assert
    verify(ticker).queueTimedJob(any(Runnable.class), eq(7500L));
    verify(manager, never()).recordSuccessfulCoreInfoFetch(any(), eq(1436));
  }

  @Test
  void onSuccess_whenUpdateScopeChangesDuringPostProcessing_expectOldEditionNotCommitted()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.getUskManager()).thenReturn(uskManager);
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());
    FreenetURI oldFetchUri = new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/1437");
    FreenetURI newUri = oldFetchUri.setDocName("alternate-info").setSuggestedEdition(1);
    updater.blockPostProcessing(1437);

    try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
      try {
        // Act
        Future<?> completion =
            executor.submit(() -> updater.onSuccess(result, tempBlobFile, 1437, oldFetchUri));
        assertTrue(updater.awaitPostProcessingStarted());
        updater.onChangeURI(newUri, 1);
        updater.continuePostProcessing();
        completion.get(5, TimeUnit.SECONDS);

        // Assert
        assertEquals(CURRENT_VERSION, updater.getFetchedVersion());
        verify(manager, never()).recordSuccessfulCoreInfoFetch(any(), eq(1437));
      } finally {
        updater.continuePostProcessing();
        executor.shutdownNow();
      }
    }
  }

  @Test
  void onSuccess_whenNewerAttemptCompletesFirst_expectOlderCompletionCannotRegressState()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.getClientContext()).thenReturn(clientContext);
    when(manager.isEnabled()).thenReturn(true);
    int olderEdition = CURRENT_VERSION + 1;
    int newerEdition = CURRENT_VERSION + 2;
    ClientGetter olderGetter = startFetch(olderEdition, 1);
    updater.blockPostProcessing(olderEdition);
    FetchResult olderResult = mock(FetchResult.class);
    when(olderResult.size()).thenReturn(1L);

    try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
      try {
        Future<?> olderCompletion =
            executor.submit(
                () -> olderGetter.getClientCallback().onSuccess(olderResult, olderGetter));
        assertTrue(updater.awaitPostProcessingStarted());
        ClientGetter newerGetter = startFetch(newerEdition, 2);
        FetchResult newerResult = mock(FetchResult.class);
        when(newerResult.size()).thenReturn(1L);

        // Act
        newerGetter.getClientCallback().onSuccess(newerResult, newerGetter);
        updater.continuePostProcessing();
        olderCompletion.get(5, TimeUnit.SECONDS);

        // Assert
        assertEquals(newerEdition, updater.getFetchedVersion());
        assertFalse(updater.isFetching());
        verify(manager).recordSuccessfulCoreInfoFetch(any(), eq(newerEdition));
        verify(manager, never()).recordSuccessfulCoreInfoFetch(any(), eq(olderEdition));
      } finally {
        updater.continuePostProcessing();
        executor.shutdownNow();
      }
    }
  }

  @Test
  void onSuccess_whenDigestChainedUpdaterHasMoreEditions_expectNextEditionScheduled()
      throws Exception {
    // Arrange
    when(core.getUskManager()).thenReturn(uskManager);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    updater.sequentialEditions = true;
    updater.nextDiscoveredEdition = CURRENT_VERSION + 1;
    updater.start();
    USK announcedKey =
        USK.create(
            new FreenetURI(
                "USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + (CURRENT_VERSION + 3)));
    updater.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(CURRENT_VERSION + 3L, announcedKey, false, (short) 0, null),
            null,
            new USKFoundEditionProgress(false, true)));
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);
    File tempBlobFile = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());

    // Act
    updater.onSuccess(result, tempBlobFile, CURRENT_VERSION + 1, null);

    // Assert
    verify(ticker).queueTimedJob(any(Runnable.class), eq(0L));
    assertEquals(CURRENT_VERSION + 2, updater.fetchingVersion());
  }

  @Test
  void onSuccess_whenNewerOrdinaryEditionArrivesDuringFetch_expectNewerEditionScheduled()
      throws Exception {
    // Arrange
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.getClientContext()).thenReturn(clientContext);
    when(manager.isEnabled()).thenReturn(true);
    ClientGetter firstGetter = startFetch(CURRENT_VERSION + 1, 1);
    updater.onFoundEdition(announcement(CURRENT_VERSION + 2));
    updater.maybeUpdate();
    FetchResult result = mock(FetchResult.class);
    when(result.size()).thenReturn(1L);

    // Act
    firstGetter.getClientCallback().onSuccess(result, firstGetter);

    // Assert
    ArgumentCaptor<Runnable> nextFetch = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker).queueTimedJob(nextFetch.capture(), eq(0L));
    nextFetch.getValue().run();
    verify(clientContext, times(2)).start(any(ClientGetter.class));
    assertEquals(CURRENT_VERSION + 2, updater.fetchingVersion());
  }

  @Test
  void onFailure_whenRecentlyFailed_expectDelayedRetry() {
    // Arrange
    FetchException recentlyFailed = new FetchException(FetchExceptionMode.RECENTLY_FAILED);

    // Act
    updater.onFailure(recentlyFailed);

    // Assert
    verify(ticker).queueTimedJob(any(Runnable.class), eq(1000L));
  }

  @Test
  void onFailure_whenSequentialIntermediateFailsFatally_expectLaterAnnouncementRearmsIt()
      throws Exception {
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.getClientContext()).thenReturn(clientContext);
    when(manager.isEnabled()).thenReturn(true);
    updater.sequentialEditions = true;
    updater.nextDiscoveredEdition = CURRENT_VERSION + 1;
    FetchResult accepted = mock(FetchResult.class);
    when(accepted.size()).thenReturn(1L);
    File acceptedTemp = File.createTempFile(BLOB_PREFIX, ".tmp", tempDir.toFile());
    updater.onSuccess(accepted, acceptedTemp, CURRENT_VERSION, null);
    USKFoundEdition announcement = announcement(CURRENT_VERSION + 2);
    updater.onFoundEdition(announcement);
    updater.maybeUpdate();

    updater.onFoundEdition(announcement);
    verify(clientContext).start(any(ClientGetter.class));
    verify(ticker).queueTimedJob(any(Runnable.class), eq(60_000L));
    updater.onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, "fatal"));
    verify(ticker, never()).queueTimedJob(any(Runnable.class), eq(0L));
    verify(ticker, never()).queueTimedJob(any(Runnable.class), eq(1000L));

    updater.onFoundEdition(announcement);
    updater.maybeUpdate();

    assertEquals(CURRENT_VERSION + 1, updater.fetchingVersion());
    verify(clientContext, times(2)).start(any(ClientGetter.class));
    verify(ticker, times(2)).queueTimedJob(any(Runnable.class), eq(60_000L));
  }

  @Test
  void onFailure_whenLatestEditionFailsFatally_expectSameAnnouncementDoesNotRetry()
      throws Exception {
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.getClientContext()).thenReturn(clientContext);
    when(manager.isEnabled()).thenReturn(true);
    USKFoundEdition announcement = announcement(CURRENT_VERSION + 2);
    updater.onFoundEdition(announcement);
    updater.maybeUpdate();

    updater.onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, "fatal"));
    updater.onFoundEdition(announcement);

    verify(clientContext).start(any(ClientGetter.class));
    verify(ticker).queueTimedJob(any(Runnable.class), eq(60_000L));
  }

  private static USKFoundEdition announcement(int edition) throws Exception {
    USK announcedKey =
        USK.create(new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + edition));
    return new USKFoundEdition(
        new USKFoundEditionPayload(edition, announcedKey, false, (short) 0, null),
        null,
        new USKFoundEditionProgress(false, true));
  }

  private void prepareFetchRuntime() {
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.getClientContext()).thenReturn(clientContext);
    when(core.getUskManager()).thenReturn(uskManager);
    when(manager.isEnabled()).thenReturn(true);
  }

  private ClientGetter startFetch(int edition, int expectedStartCount) throws Exception {
    updater.onFoundEdition(announcement(edition));
    updater.maybeUpdate();
    ArgumentCaptor<ClientGetter> getter = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext, times(expectedStartCount)).start(getter.capture());
    return getter.getAllValues().getLast();
  }

  private Path findOnlyTempBlob() throws Exception {
    try (var files = Files.list(tempDir)) {
      var matches = files.filter(NodeUpdaterTest::isTempBlob).toList();
      assertEquals(1, matches.size());
      return matches.getFirst();
    }
  }

  private Path findTempBlobOtherThan(Path excluded) throws Exception {
    try (var files = Files.list(tempDir)) {
      var matches =
          files.filter(NodeUpdaterTest::isTempBlob).filter(path -> !path.equals(excluded)).toList();
      assertEquals(1, matches.size());
      return matches.getFirst();
    }
  }

  private static boolean isTempBlob(Path path) {
    return path.getFileName().toString().endsWith(".fblob.tmp");
  }

  private NodeUpdaterParams defaultParams() throws MalformedURLException {
    return new NodeUpdaterParams(
        manager,
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + CURRENT_VERSION),
        CURRENT_VERSION,
        -1,
        Integer.MAX_VALUE,
        BLOB_PREFIX,
        DEFAULT_SUBSCRIBE_SEED);
  }

  private static @NotNull FetchContext createFetchContext() {
    SimpleEventProducer eventProducer = new SimpleEventProducer();
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(1, 1, 1, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 1, 1)
            .behavior(true, false, false)
            .clientOptions(eventProducer, false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  private static class TestNodeUpdater extends NodeUpdater {
    private boolean acceptFetch = true;
    private long rejectedFetchRetryDelayMillis = -1;
    private boolean sequentialEditions;
    private int nextDiscoveredEdition = Integer.MAX_VALUE;
    private int processCalls;
    private CountDownLatch processStarted;
    private CountDownLatch continueProcessing;
    private int blockedProcessingEdition = -1;

    private TestNodeUpdater(NodeUpdaterParams params) {
      super(params);
    }

    @Override
    public String artifactName() {
      return "core-info.json";
    }

    @Override
    protected void onStartFetching() {
      // No-op for testing.
    }

    @Override
    protected boolean processSuccess(int fetched, FetchResult result, File blobFile) {
      processCalls++;
      if (fetched == blockedProcessingEdition) {
        awaitPostProcessingRelease();
      }
      return acceptFetch;
    }

    private void blockPostProcessing(int fetchedEdition) {
      blockedProcessingEdition = fetchedEdition;
      processStarted = new CountDownLatch(1);
      continueProcessing = new CountDownLatch(1);
    }

    private boolean awaitPostProcessingStarted() throws InterruptedException {
      return processStarted.await(5, TimeUnit.SECONDS);
    }

    private void continuePostProcessing() {
      if (continueProcessing != null) {
        continueProcessing.countDown();
      }
    }

    private void awaitPostProcessingRelease() {
      if (processStarted == null || continueProcessing == null) {
        return;
      }
      processStarted.countDown();
      try {
        if (!continueProcessing.await(5, TimeUnit.SECONDS)) {
          throw new AssertionError("timed out waiting to continue post-processing");
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError("interrupted while waiting to continue post-processing", e);
      }
    }

    @Override
    protected long rejectedFetchRetryDelayMillis() {
      return rejectedFetchRetryDelayMillis;
    }

    @Override
    protected int selectDiscoveredEdition(int discoveredEdition) {
      return Math.min(discoveredEdition, nextDiscoveredEdition);
    }

    @Override
    protected boolean fetchIntermediateEditionsSequentially() {
      return sequentialEditions;
    }

    @Override
    protected void maybeParseManifest(FetchResult result, int build) {
      // No-op for testing.
    }
  }
}
