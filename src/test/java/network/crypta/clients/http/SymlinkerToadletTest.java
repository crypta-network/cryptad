package network.crypta.clients.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.runtime.spi.ToadletSymlinkEntry;
import network.crypta.runtime.spi.ToadletSymlinkPort;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SymlinkerToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private ToadletSymlinkPort symlinkPort;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  @Test
  void handleMethodGET_whenAliasMatches_redirectsWithOriginalQueryAndFragment() throws Exception {
    when(symlinkPort.loadConfiguredSymlinks())
        .thenReturn(List.of(new ToadletSymlinkEntry("/cfg/", "/target/")));
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, symlinkPort);

    URI incoming = new URI("http://localhost/cfg/path?foo=bar#frag");

    RedirectException redirect =
        assertThrows(
            RedirectException.class, () -> toadlet.handleMethodGET(incoming, request, ctx));

    assertEquals("/target/path", redirect.getTarget().getPath());
    assertEquals("foo=bar", redirect.getTarget().getQuery());
    assertEquals("frag", redirect.getTarget().getFragment());
  }

  @Test
  void addLink_whenStoreTrue_persistsAndRedirects() {
    when(symlinkPort.loadConfiguredSymlinks()).thenReturn(List.of());
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, symlinkPort);

    boolean added = toadlet.addLink("/alias/", "/dest/", true);

    assertFalse(added);
    verify(symlinkPort)
        .persistConfiguredSymlinks(List.of(new ToadletSymlinkEntry("/alias/", "/dest/")));

    RedirectException redirect =
        assertThrows(
            RedirectException.class,
            () -> toadlet.handleMethodGET(new URI("http://x/alias/file"), request, ctx));

    assertEquals("/dest/file", redirect.getTarget().getPath());
  }

  @Test
  void addLink_whenConcurrentStoredUpdates_persistsSnapshotsInMutationOrder() throws Exception {
    BlockingToadletSymlinkPort blockingPort = new BlockingToadletSymlinkPort();
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, blockingPort);
    CountDownLatch secondStarted = new CountDownLatch(1);
    Thread firstUpdate = new Thread(() -> toadlet.addLink("/a/", "/dest-a/", true));
    Thread secondUpdate =
        new Thread(
            () -> {
              secondStarted.countDown();
              toadlet.addLink("/b/", "/dest-b/", true);
            });

    firstUpdate.start();
    assertTrue(blockingPort.awaitFirstPersistEntered());

    secondUpdate.start();
    assertTrue(secondStarted.await(1, TimeUnit.SECONDS));
    assertFalse(blockingPort.secondPersistStartedWithinShortWindow());

    blockingPort.releaseFirstPersist();

    firstUpdate.join(TimeUnit.SECONDS.toMillis(1));
    secondUpdate.join(TimeUnit.SECONDS.toMillis(1));

    assertFalse(firstUpdate.isAlive());
    assertFalse(secondUpdate.isAlive());
    assertEquals(
        List.of(
            List.of(new ToadletSymlinkEntry("/a/", "/dest-a/")),
            List.of(
                new ToadletSymlinkEntry("/a/", "/dest-a/"),
                new ToadletSymlinkEntry("/b/", "/dest-b/"))),
        blockingPort.persistedSnapshots());
  }

  @Test
  void removeLink_whenExistingAlias_returnsTrueAndPreventsRedirect() throws Exception {
    when(symlinkPort.loadConfiguredSymlinks()).thenReturn(List.of());
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, symlinkPort);

    toadlet.addLink("/remove/", "/kept/", false);

    boolean removed = toadlet.removeLink("/remove/", true);

    assertTrue(removed);
    verify(symlinkPort).persistConfiguredSymlinks(List.of());

    assertDoesNotThrow(
        () -> toadlet.handleMethodGET(new URI("http://localhost/remove/x"), request, ctx));

    verify(ctx)
        .sendReplyHeaders(
            org.mockito.ArgumentMatchers.eq(404),
            org.mockito.ArgumentMatchers.eq("Not found"),
            isNull(),
            org.mockito.ArgumentMatchers.eq("text/plain; charset=utf-8"),
            anyLong(),
            org.mockito.ArgumentMatchers.eq(true));
    verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodGET_whenNoMatchingAlias_sends404Response() throws Exception {
    when(symlinkPort.loadConfiguredSymlinks()).thenReturn(List.of());
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, symlinkPort);

    assertDoesNotThrow(
        () -> toadlet.handleMethodGET(new URI("http://localhost/unknown"), request, ctx));

    verify(ctx)
        .sendReplyHeaders(
            org.mockito.ArgumentMatchers.eq(404),
            org.mockito.ArgumentMatchers.eq("Not found"),
            isNull(),
            org.mockito.ArgumentMatchers.eq("text/plain; charset=utf-8"),
            anyLong(),
            org.mockito.ArgumentMatchers.eq(true));
    verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodGET_whenTargetContainsSpaces_redirectsWithEncodedPath() {
    when(symlinkPort.loadConfiguredSymlinks()).thenReturn(List.of());
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, symlinkPort);
    toadlet.addLink("/bad/", "/target with space/", false);

    RedirectException redirect =
        assertThrows(
            RedirectException.class,
            () -> toadlet.handleMethodGET(new URI("http://localhost/bad/here"), request, ctx));

    assertEquals("/target with space/here", redirect.getTarget().getPath());
    assertEquals("/target%20with%20space/here", redirect.getTarget().getRawPath());
  }

  private static final class BlockingToadletSymlinkPort implements ToadletSymlinkPort {
    private final CountDownLatch firstPersistEntered = new CountDownLatch(1);
    private final CountDownLatch allowFirstPersistToReturn = new CountDownLatch(1);
    private final CountDownLatch secondPersistEntered = new CountDownLatch(1);
    private final AtomicInteger persistCallCount = new AtomicInteger();
    private final CopyOnWriteArrayList<List<ToadletSymlinkEntry>> persistedSnapshots =
        new CopyOnWriteArrayList<>();

    @Override
    public List<ToadletSymlinkEntry> loadConfiguredSymlinks() {
      return List.of();
    }

    @Override
    public void persistConfiguredSymlinks(List<ToadletSymlinkEntry> entries) {
      persistedSnapshots.add(sortedEntries(entries));
      int callIndex = persistCallCount.incrementAndGet();
      if (callIndex == 1) {
        firstPersistEntered.countDown();
        awaitOrFail(allowFirstPersistToReturn);
        return;
      }
      if (callIndex == 2) {
        secondPersistEntered.countDown();
      }
    }

    boolean awaitFirstPersistEntered() throws InterruptedException {
      return firstPersistEntered.await(1, TimeUnit.SECONDS);
    }

    boolean secondPersistStartedWithinShortWindow() throws InterruptedException {
      return secondPersistEntered.await(200, TimeUnit.MILLISECONDS);
    }

    void releaseFirstPersist() {
      allowFirstPersistToReturn.countDown();
    }

    List<List<ToadletSymlinkEntry>> persistedSnapshots() {
      return List.copyOf(persistedSnapshots);
    }

    private static List<ToadletSymlinkEntry> sortedEntries(List<ToadletSymlinkEntry> entries) {
      ArrayList<ToadletSymlinkEntry> copy = new ArrayList<>(entries);
      copy.sort(Comparator.comparing(ToadletSymlinkEntry::alias));
      return List.copyOf(copy);
    }

    private static void awaitOrFail(CountDownLatch latch) {
      try {
        if (!latch.await(1, TimeUnit.SECONDS)) {
          fail("Timed out waiting for the blocked persist call to resume.");
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        fail(e);
      }
    }
  }
}
