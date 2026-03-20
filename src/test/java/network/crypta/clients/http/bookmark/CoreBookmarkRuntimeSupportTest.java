package network.crypta.clients.http.bookmark;

import java.io.IOException;
import java.nio.file.Path;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKManager;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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
    USKCallback callback = mock(USKCallback.class);
    when(core.getUskManager()).thenReturn(uskManager);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);
    ArgumentCaptor<RequestClient> clientCaptor = ArgumentCaptor.forClass(RequestClient.class);

    runtime.subscribeToUsk(usk, callback);

    verify(uskManager).subscribe(same(usk), same(callback), eq(true), clientCaptor.capture());
    assertFalse(clientCaptor.getValue().persistent());
    assertFalse(clientCaptor.getValue().realTimeFlag());
  }

  @Test
  void unsubscribeFromUsk_whenCalled_expectDelegatesToUskManager() {
    USKManager uskManager = mock(USKManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    USK usk = mock(USK.class);
    USKCallback callback = mock(USKCallback.class);
    when(core.getUskManager()).thenReturn(uskManager);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);

    runtime.unsubscribeFromUsk(usk, callback);

    verify(uskManager).unsubscribe(usk, callback);
  }

  @Test
  void prefetchUpdatedEdition_whenCalled_expectDelegatesToUpdatePriorityClient() {
    FreenetURI uri = mock(FreenetURI.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.makeClient(RequestStarter.UPDATE_PRIORITY_CLASS, false, false)).thenReturn(client);
    CoreBookmarkRuntimeSupport runtime = new CoreBookmarkRuntimeSupport(core);

    runtime.prefetchUpdatedEdition(uri, 456L);

    verify(core).makeClient(RequestStarter.UPDATE_PRIORITY_CLASS, false, false);
    verify(client)
        .prefetch(
            same(uri),
            eq(MINUTES.toMillis(60)),
            eq(456L),
            isNull(),
            eq(RequestStarter.UPDATE_PRIORITY_CLASS));
  }
}
