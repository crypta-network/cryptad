package network.crypta.clients.http.bridge.bookmark;

import java.io.IOException;
import java.nio.file.Path;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKFoundEditionPayload;
import network.crypta.client.async.USKFoundEditionProgress;
import network.crypta.client.async.USKManager;
import network.crypta.clients.http.bookmark.BookmarkRuntimeSupport;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestPriorityClasses;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class CoreBookmarkRuntimeSupportTest {

  @TempDir Path tempDir;

  @Test
  void bookmarkFiles_whenCalled_expectFilesResolvedFromUserDir() throws IOException {
    ProgramDirectory userDir = new ProgramDirectory();
    userDir.move(tempDir.toString());
    Node node = mock(Node.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(node.userDir()).thenReturn(userDir);
    when(core.getNode()).thenReturn(node);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);

    assertEquals(tempDir.resolve("bookmarks.dat").toFile(), runtime.bookmarksFile());
    assertEquals(tempDir.resolve("bookmarks.dat.bak").toFile(), runtime.backupBookmarksFile());
  }

  @Test
  void queueLazyStore_whenCalled_expectDelegatesToTicker() {
    Runnable job = mock(Runnable.class);
    Ticker ticker = mock(Ticker.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    Node node = mock(Node.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(network.ticker()).thenReturn(ticker);
    when(node.network()).thenReturn(network);
    when(core.getNode()).thenReturn(node);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);

    runtime.queueLazyStore(job, 123L);

    verify(ticker).queueTimedJob(job, 123L);
  }

  @Test
  void subscribeToUsk_whenCalled_expectDelegatesWithBackgroundFetchAndEphemeralClient() {
    USKManager uskManager = mock(USKManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    USK usk = mock(USK.class);
    BookmarkRuntimeSupport.BookmarkUpdateCallback callback =
        mock(BookmarkRuntimeSupport.BookmarkUpdateCallback.class);
    when(core.getUskManager()).thenReturn(uskManager);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);
    ArgumentCaptor<RequestClient> clientCaptor = ArgumentCaptor.forClass(RequestClient.class);
    ArgumentCaptor<network.crypta.client.async.USKCallback> callbackCaptor =
        ArgumentCaptor.forClass(network.crypta.client.async.USKCallback.class);

    runtime.subscribeToUsk(usk, callback);

    verify(uskManager)
        .subscribe(same(usk), callbackCaptor.capture(), eq(true), clientCaptor.capture());
    assertFalse(clientCaptor.getValue().persistent());
    assertFalse(clientCaptor.getValue().realTimeFlag());
  }

  @Test
  void unsubscribeFromUsk_whenCalled_expectDelegatesToUskManager() {
    USKManager uskManager = mock(USKManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    USK usk = mock(USK.class);
    BookmarkRuntimeSupport.BookmarkUpdateCallback callback =
        mock(BookmarkRuntimeSupport.BookmarkUpdateCallback.class);
    when(core.getUskManager()).thenReturn(uskManager);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);
    ArgumentCaptor<network.crypta.client.async.USKCallback> callbackCaptor =
        ArgumentCaptor.forClass(network.crypta.client.async.USKCallback.class);

    runtime.subscribeToUsk(usk, callback);

    runtime.unsubscribeFromUsk(usk, callback);

    verify(uskManager)
        .subscribe(same(usk), callbackCaptor.capture(), eq(true), any(RequestClient.class));
    verify(uskManager).unsubscribe(usk, callbackCaptor.getValue());
  }

  @Test
  void subscribeToUsk_whenRuntimeCallbackFires_adaptsEditionUpdateAndPriorities() {
    USKManager uskManager = mock(USKManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    USK usk = mock(USK.class);
    ClientContext clientContext = mock(ClientContext.class);
    BookmarkRuntimeSupport.BookmarkUpdateCallback callback =
        mock(BookmarkRuntimeSupport.BookmarkUpdateCallback.class);
    when(core.getUskManager()).thenReturn(uskManager);
    when(callback.getPollingPriorityNormal()).thenReturn((short) 2);
    when(callback.getPollingPriorityProgress()).thenReturn((short) 5);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);
    ArgumentCaptor<network.crypta.client.async.USKCallback> callbackCaptor =
        ArgumentCaptor.forClass(network.crypta.client.async.USKCallback.class);

    runtime.subscribeToUsk(usk, callback);

    verify(uskManager)
        .subscribe(same(usk), callbackCaptor.capture(), eq(true), any(RequestClient.class));
    USKFoundEdition foundEdition =
        new USKFoundEdition(
            new USKFoundEditionPayload(12L, usk, false, (short) 7, null),
            clientContext,
            new USKFoundEditionProgress(true, false));

    callbackCaptor.getValue().onFoundEdition(foundEdition);

    ArgumentCaptor<BookmarkRuntimeSupport.BookmarkEditionUpdate> updateCaptor =
        ArgumentCaptor.forClass(BookmarkRuntimeSupport.BookmarkEditionUpdate.class);
    verify(callback).onFoundEdition(updateCaptor.capture());
    assertSame(usk, updateCaptor.getValue().key());
    assertEquals(12L, updateCaptor.getValue().edition());
    assertTrue(updateCaptor.getValue().newKnownGood());
    assertEquals((short) 2, callbackCaptor.getValue().getPollingPriorityNormal());
    assertEquals((short) 5, callbackCaptor.getValue().getPollingPriorityProgress());
  }

  @Test
  void unsubscribeFromUsk_whenCallbackWasNeverSubscribed_doesNothing() {
    USKManager uskManager = mock(USKManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getUskManager()).thenReturn(uskManager);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);

    runtime.unsubscribeFromUsk(
        mock(USK.class), mock(BookmarkRuntimeSupport.BookmarkUpdateCallback.class));

    verifyNoMoreInteractions(uskManager);
  }

  @Test
  void prefetchUpdatedEdition_whenCalled_expectDelegatesToUpdatePriorityClient() {
    FreenetURI uri = mock(FreenetURI.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.makeClient(RequestPriorityClasses.UPDATE_PRIORITY_CLASS, false, false))
        .thenReturn(client);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);

    runtime.prefetchUpdatedEdition(uri, 456L);

    verify(core).makeClient(RequestPriorityClasses.UPDATE_PRIORITY_CLASS, false, false);
    verify(client)
        .prefetch(
            same(uri),
            eq(MINUTES.toMillis(60)),
            eq(456L),
            isNull(),
            eq(RequestPriorityClasses.UPDATE_PRIORITY_CLASS));
  }
}
