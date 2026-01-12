package network.crypta.clients.http.updateableelements;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.Predicate;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.clients.http.FProxyFetchCriteria;
import network.crypta.clients.http.FProxyFetchInProgress;
import network.crypta.clients.http.FProxyFetchProgressCounts;
import network.crypta.clients.http.FProxyFetchResult;
import network.crypta.clients.http.FProxyFetchSnapshotInfo;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyFetchWaiter;
import network.crypta.clients.http.ToadletContainer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.complexhtmlnodes.SecondCounterNode;
import network.crypta.keys.FreenetURI;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Test method naming convention: method_whenCondition_expectOutcome
class ProgressInfoElementTest {

  @Mock private FProxyFetchTracker tracker;
  @Mock private FetchContext fetchContext;
  @Mock private ToadletContext toadletContext;
  @Mock private ToadletContainer toadletContainer;

  private static FreenetURI ksk(String name) {
    return new FreenetURI("KSK", name);
  }

  @Test
  @DisplayName("getId: encodes URI into stable Base64 wrapper")
  void getId_whenUriProvided_expectStableEncoding() {
    FreenetURI uri = ksk("doc");

    String id = ProgressInfoElement.getId(uri);

    assertEquals(Base64.encodeStandardUTF8(("progressinfo[URI:" + uri + "]")), id);
  }

  @Test
  @DisplayName("getUpdaterId: ignores requestId and derives from key")
  void getUpdaterId_whenCalled_expectDerivedFromKey() {
    FreenetURI uri = ksk("doc");
    stubUniqueId();
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, 123L, fetchContext)))
        .thenReturn(null);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, 123L, false, toadletContext, false);

    assertEquals(ProgressInfoElement.getId(uri), element.getUpdaterId("ignored-request-id"));
    assertEquals(ProgressInfoElement.getId(uri), element.getAttribute("id"));
  }

  @Test
  @DisplayName("getUpdaterType: always returns REPLACER_UPDATER")
  void getUpdaterType_whenCalled_expectReplacerUpdater() {
    FreenetURI uri = ksk("doc");
    stubUniqueId();
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, 1L, fetchContext)))
        .thenReturn(null);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, 1L, false, toadletContext, false);

    assertEquals(UpdaterConstants.REPLACER_UPDATER, element.getUpdaterType());
  }

  @Test
  @DisplayName("toString: includes key, maxSize, and derived updaterId")
  void toString_whenCalled_expectIncludesKeyMaxSizeAndUpdaterId() {
    FreenetURI uri = ksk("doc");
    long maxSize = 42L;
    stubUniqueId();
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(null);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, false, toadletContext, false);

    assertEquals(
        "ProgressInfoElement[key:"
            + uri
            + ",maxSize:"
            + maxSize
            + ",updaterId:"
            + ProgressInfoElement.getId(uri)
            + "]",
        element.toString());
  }

  @Test
  @DisplayName("updateState: no waiter -> renders 'No fetcher found'")
  void updateState_whenNoWaiter_expectNoFetcherFoundMessage() {
    FreenetURI uri = ksk("no-waiter");
    stubUniqueId();
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, 1024L, fetchContext)))
        .thenReturn(null);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, 1024L, false, toadletContext, false);

    assertTrue(element.generate().contains("No fetcher found"));
    verify(tracker).makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, 1024L, fetchContext));
    verify(tracker, never()).getFetchInProgress(new FProxyFetchCriteria(uri, 1024L, fetchContext));
  }

  @Test
  @DisplayName(
      "updateState: waiter result is null -> renders 'No fetcher found' and does not close")
  void updateState_whenWaiterReturnsNullResult_expectNoFetcherFoundAndNoClose() {
    FreenetURI uri = ksk("null-result");
    stubUniqueId();
    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, 1024L, fetchContext)))
        .thenReturn(waiter);
    when(waiter.getResult()).thenReturn(null);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, 1024L, false, toadletContext, false);

    assertTrue(element.generate().contains("No fetcher found"));
    verify(waiter).getResult();
    verify(tracker, never()).getFetchInProgress(new FProxyFetchCriteria(uri, 1024L, fetchContext));
  }

  @Test
  @DisplayName(
      "updateState: valid result + JS disabled -> renders link + elapsed/eta counters and closes"
          + " waiter/result")
  void updateState_whenValidResultAndJavascriptDisabled_expectMarkupAndClosesHandles() {
    FreenetURI uri = ksk("js-disabled");
    long maxSize = 2048L;
    stubUniqueId();
    stubContainerJavascriptEnabled(false);

    long now = System.currentTimeMillis();
    long timeStarted = now - 12_345L;
    long etaTotal = (now - timeStarted) + 60_000L;
    FProxyFetchResult result =
        newProgressResult(
            progressResultSpec()
                .mimeType("text/plain")
                .size(1024L)
                .timeStarted(timeStarted)
                .goneToNetwork(true)
                .finalizedBlocks(true)
                .eta(etaTotal));

    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(waiter);
    when(waiter.getResult()).thenReturn(result);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(progress);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, false, toadletContext, false);

    HTMLNode link = findFirstMatchingNode(element, node -> "a".equals(node.getName()));
    assertNotNull(link);
    assertEquals("/" + uri.toString(false, false), link.getAttribute("href"));
    assertTrue(element.generate().contains(uri.getPreferredFilename()));
    assertTrue(element.generate().contains("Size: " + SizeUtil.formatSize(1024L)));
    assertTrue(element.generate().contains("text/plain"));

    assertEquals(2L, countMatchingNodes(element, SecondCounterNode.class::isInstance));
    assertEquals(1L, countMatchingNodes(element, node -> "p".equals(node.getName())));

    verify(progress).close(waiter);
    verify(progress).close(result);
  }

  @Test
  @DisplayName("updateState: JS enabled -> includes json-only last-refresh counter")
  void updateState_whenJavascriptEnabled_expectJsonlyLastRefreshCounter() {
    FreenetURI uri = ksk("js-enabled");
    long maxSize = 4096L;
    stubUniqueId();
    stubContainerJavascriptEnabled(true);

    long now = System.currentTimeMillis();
    long timeStarted = now - 5_000L;
    FProxyFetchResult result =
        newProgressResult(
            progressResultSpec()
                .mimeType(null)
                .size(0L)
                .timeStarted(timeStarted)
                .goneToNetwork(false)
                .finalizedBlocks(true)
                .eta(-1L));

    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(waiter);
    when(waiter.getResult()).thenReturn(result);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(progress);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, false, toadletContext, false);

    HTMLNode jsonOnly =
        findFirstMatchingNode(
            element,
            node -> "span".equals(node.getName()) && "jsonly".equals(node.getAttribute("class")));
    assertNotNull(jsonOnly);
    assertEquals(2L, countMatchingNodes(element, SecondCounterNode.class::isInstance));
  }

  @Test
  @DisplayName("updateState: not-finalized blocks -> adds progressNotFinalized paragraph")
  void updateState_whenNotFinalizedBlocks_expectSecondParagraph() {
    FreenetURI uri = ksk("not-finalized");
    long maxSize = 123L;
    stubUniqueId();
    stubContainerJavascriptEnabled(false);

    long timeStarted = System.currentTimeMillis() - 1_000L;
    FProxyFetchResult result =
        newProgressResult(
            progressResultSpec()
                .mimeType(null)
                .size(0L)
                .timeStarted(timeStarted)
                .goneToNetwork(false)
                .finalizedBlocks(false)
                .eta(-1L));

    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(waiter);
    when(waiter.getResult()).thenReturn(result);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(progress);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, false, toadletContext, false);

    assertEquals(2L, countMatchingNodes(element, node -> "p".equals(node.getName())));
  }

  @Test
  @DisplayName("updateState: advanced mode -> includes block counters in the rendered markup")
  void updateState_whenAdvancedMode_expectIncludesBlockCounters() {
    FreenetURI uri = ksk("advanced");
    long maxSize = 999L;
    stubUniqueId();
    stubContainerJavascriptEnabled(false);

    long timeStarted = System.currentTimeMillis() - 10_000L;
    int fetched = 11;
    int required = 22;
    int total = 33;
    int failed = 44;
    int fatallyFailed = 55;
    FProxyFetchResult result =
        newProgressResult(
            progressResultSpec()
                .mimeType(null)
                .size(0L)
                .timeStarted(timeStarted)
                .goneToNetwork(false)
                .totalBlocks(total)
                .requiredBlocks(required)
                .fetchedBlocks(fetched)
                .failedBlocks(failed)
                .fatallyFailedBlocks(fatallyFailed)
                .finalizedBlocks(true)
                .eta(-1L));

    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(waiter);
    when(waiter.getResult()).thenReturn(result);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(progress);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, true, toadletContext, false);

    String html = element.generate();
    assertTrue(html.contains(Integer.toString(fetched)));
    assertTrue(html.contains(Integer.toString(required)));
    assertTrue(html.contains(Integer.toString(total)));
    assertTrue(html.contains(Integer.toString(failed)));
    assertTrue(html.contains(Integer.toString(fatallyFailed)));
  }

  @Test
  @DisplayName("dispose: progress present -> removes listener (even when not pushed)")
  void dispose_whenProgressExists_expectRemoveListenerCalled() {
    FreenetURI uri = ksk("dispose");
    long maxSize = 10L;
    stubUniqueId();
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(null);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(progress);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, false, toadletContext, false);
    element.dispose();

    verify(progress).removeListener(null);
  }

  @Test
  @DisplayName("dispose: no progress -> no listener removal attempted")
  void dispose_whenNoProgress_expectNoListenerRemovalAttempted() {
    FreenetURI uri = ksk("dispose-null");
    long maxSize = 10L;
    stubUniqueId();
    when(tracker.makeWaiterForFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(null);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext)))
        .thenReturn(null);

    ProgressInfoElement element =
        new ProgressInfoElement(tracker, uri, fetchContext, maxSize, false, toadletContext, false);
    element.dispose();

    verify(tracker).getFetchInProgress(new FProxyFetchCriteria(uri, maxSize, fetchContext));
  }

  private void stubUniqueId() {
    when(toadletContext.getUniqueId()).thenReturn("request-1");
  }

  private void stubContainerJavascriptEnabled(boolean enabled) {
    when(toadletContext.getContainer()).thenReturn(toadletContainer);
    when(toadletContainer.isFProxyJavascriptEnabled()).thenReturn(enabled);
  }

  private static HTMLNode findFirstMatchingNode(HTMLNode root, Predicate<HTMLNode> predicate) {
    Deque<HTMLNode> stack = new ArrayDeque<>();
    stack.push(root);
    while (!stack.isEmpty()) {
      HTMLNode current = stack.pop();
      if (predicate.test(current)) {
        return current;
      }
      for (int i = current.getChildren().size() - 1; i >= 0; i--) {
        stack.push(current.getChildren().get(i));
      }
    }
    return null;
  }

  private static long countMatchingNodes(HTMLNode root, Predicate<HTMLNode> predicate) {
    long count = 0L;
    Deque<HTMLNode> stack = new ArrayDeque<>();
    stack.push(root);
    while (!stack.isEmpty()) {
      HTMLNode current = stack.pop();
      if (predicate.test(current)) {
        count++;
      }
      for (int i = current.getChildren().size() - 1; i >= 0; i--) {
        stack.push(current.getChildren().get(i));
      }
    }
    return count;
  }

  private static ProgressResultSpec progressResultSpec() {
    return new ProgressResultSpec();
  }

  private static final Constructor<FProxyFetchResult> PROGRESS_RESULT_CTOR =
      progressResultConstructor();

  @SuppressWarnings("java:S3011") // Tests intentionally access package-private constructor
  private static Constructor<FProxyFetchResult> progressResultConstructor() {
    try {
      Constructor<FProxyFetchResult> ctor =
          FProxyFetchResult.class.getDeclaredConstructor(
              FProxyFetchInProgress.class,
              FProxyFetchSnapshotInfo.class,
              long.class,
              FProxyFetchProgressCounts.class,
              FetchException.class);
      ctor.setAccessible(true);
      return ctor;
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed to locate FProxyFetchResult constructor via reflection", e);
    }
  }

  private static final class ProgressResultSpec {
    private String mimeType;
    private long size;
    private long timeStarted;
    private boolean goneToNetwork;
    private int totalBlocks;
    private int requiredBlocks;
    private int fetchedBlocks;
    private int failedBlocks;
    private int fatallyFailedBlocks;
    private boolean finalizedBlocks;
    private FetchException failed;
    private long eta;
    private boolean hasWaited;

    ProgressResultSpec mimeType(String value) {
      this.mimeType = value;
      return this;
    }

    ProgressResultSpec size(long value) {
      this.size = value;
      return this;
    }

    ProgressResultSpec timeStarted(long value) {
      this.timeStarted = value;
      return this;
    }

    ProgressResultSpec goneToNetwork(boolean value) {
      this.goneToNetwork = value;
      return this;
    }

    ProgressResultSpec totalBlocks(int value) {
      this.totalBlocks = value;
      return this;
    }

    ProgressResultSpec requiredBlocks(int value) {
      this.requiredBlocks = value;
      return this;
    }

    ProgressResultSpec fetchedBlocks(int value) {
      this.fetchedBlocks = value;
      return this;
    }

    ProgressResultSpec failedBlocks(int value) {
      this.failedBlocks = value;
      return this;
    }

    ProgressResultSpec fatallyFailedBlocks(int value) {
      this.fatallyFailedBlocks = value;
      return this;
    }

    ProgressResultSpec finalizedBlocks(boolean value) {
      this.finalizedBlocks = value;
      return this;
    }

    @SuppressWarnings("unused")
    ProgressResultSpec failed(FetchException value) {
      this.failed = value;
      return this;
    }

    ProgressResultSpec eta(long value) {
      this.eta = value;
      return this;
    }

    @SuppressWarnings("unused")
    ProgressResultSpec hasWaited(boolean value) {
      this.hasWaited = value;
      return this;
    }
  }

  private static FProxyFetchResult newProgressResult(ProgressResultSpec spec) {
    try {
      return PROGRESS_RESULT_CTOR.newInstance(
          mock(FProxyFetchInProgress.class),
          new FProxyFetchSnapshotInfo(
              spec.mimeType, spec.timeStarted, spec.goneToNetwork, spec.eta, spec.hasWaited),
          spec.size,
          new FProxyFetchProgressCounts(
              spec.totalBlocks,
              spec.requiredBlocks,
              spec.fetchedBlocks,
              spec.failedBlocks,
              spec.fatallyFailedBlocks,
              spec.finalizedBlocks),
          spec.failed);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed to create FProxyFetchResult via reflection", e);
    }
  }
}
