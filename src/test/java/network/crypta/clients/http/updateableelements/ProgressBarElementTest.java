package network.crypta.clients.http.updateableelements;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.clients.http.FProxyFetchCriteria;
import network.crypta.clients.http.FProxyFetchInProgress;
import network.crypta.clients.http.FProxyFetchListener;
import network.crypta.clients.http.FProxyFetchProgressCounts;
import network.crypta.clients.http.FProxyFetchResult;
import network.crypta.clients.http.FProxyFetchSnapshotInfo;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyFetchWaiter;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ProgressBarElementTest {

  private static final String KEY_STRING = "KSK@unit-test";
  private static final String REQUEST_ID = "req-1";
  private static final String ATTR_CLASS = "class";

  private Locale previousDefaultLocale;

  @Mock private FProxyFetchTracker tracker;
  @Mock private FreenetURI key;
  @Mock private FetchContext fetchContext;
  @Mock private ToadletContext toadletContext;

  @BeforeEach
  void setUp() {
    previousDefaultLocale = Locale.getDefault();
    Locale.setDefault(Locale.US);
  }

  @AfterEach
  void tearDown() {
    Locale.setDefault(previousDefaultLocale);
  }

  @Test
  @DisplayName("getId: returns standard Base64 encoding of progressbar[URI:<uri>]")
  void getId_whenUriProvided_encodesExpectedPayload() {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);

    // Act
    String id = ProgressBarElement.getId(key);

    // Assert
    byte[] decoded = Base64.getDecoder().decode(id);
    assertEquals(
        "progressbar[URI:" + KEY_STRING + "]",
        new String(decoded, StandardCharsets.UTF_8),
        "Expected Base64 payload to match the documented id schema");
  }

  @Test
  void constructor_whenNotPushed_setsStableIdAndDoesNotRegisterPushOrListener() {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(null);

    // Act
    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, false);

    // Assert
    assertEquals(ProgressBarElement.getId(key), element.getAttribute("id"));
    verify(toadletContext, never()).getContainer();
  }

  @Test
  void updateState_whenNoFetchInProgress_rendersNoFetcherFoundAndDoesNotCloseAnything() {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(null);

    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, false);
    clearInvocations(tracker);

    // Act
    element.updateState(false);

    // Assert
    HTMLNode messageDiv = getSingleChild(element);
    assertEquals("div", messageDiv.getName());
    assertNull(
        messageDiv.getAttribute(ATTR_CLASS), "No class attribute should be set on message div");

    HTMLNode messageText = getSingleChild(messageDiv);
    assertEquals("#", messageText.getName());
    assertEquals("No fetcher found", messageText.getContent());
    verify(tracker).getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext));
  }

  @Test
  void updateState_whenWaiterResultIsNull_rendersNoFetcherFoundAndClosesWaiterOnly(
      @Mock FProxyFetchInProgress progress, @Mock FProxyFetchWaiter waiter) {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);

    AtomicReference<FProxyFetchInProgress> progressRef = new AtomicReference<>(null);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenAnswer(_ -> progressRef.get());

    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, false);

    progressRef.set(progress);
    when(progress.getWaiter()).thenReturn(waiter);
    when(waiter.getResult()).thenReturn(null);
    clearInvocations(progress, waiter);

    // Act
    element.updateState(false);

    // Assert
    HTMLNode messageDiv = getSingleChild(element);
    HTMLNode messageText = getSingleChild(messageDiv);
    assertEquals("No fetcher found", messageText.getContent());
    verify(progress).close(waiter);
    verify(progress, never()).close(any(FProxyFetchResult.class));
  }

  @Test
  void updateState_whenFetchIsFinished_setsFinishedContentAndClosesWaiterAndResult(
      @Mock FProxyFetchInProgress progress, @Mock FProxyFetchWaiter waiter)
      throws ReflectiveOperationException {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);

    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(progress);
    when(progress.getWaiter()).thenReturn(waiter);
    AtomicReference<FProxyFetchResult> resultRef = new AtomicReference<>();
    when(waiter.getResult()).thenAnswer(_ -> resultRef.get());

    resultRef.set(
        newFetchResultSnapshot(
            progress, /* requiredBlocks= */ 10, /* fetchedBlocks= */ 1, 0, 0, true, null));

    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, false);
    clearInvocations(progress, waiter);

    // Act
    FProxyFetchResult finishedResult =
        newFetchResultSnapshot(
            progress, /* requiredBlocks= */ 10, /* fetchedBlocks= */ 10, 0, 0, true, failure());
    resultRef.set(finishedResult);
    element.updateState(false);

    // Assert
    assertEquals(UpdaterConstants.FINISHED, element.getContent());
    assertTrue(element.getChildren().isEmpty(), "Finished element should not render any children");
    verify(progress).close(waiter);
    verify(progress).close(finishedResult);
  }

  @ParameterizedTest
  @CsvSource({
    // fetched, total, failed, fatal, finalized, expectFailedBar, expectFatalBar, expectedText
    "3, 10, 0, 0, true,  false, false, 30%",
    "3, 10, 1, 0, true,  true,  false, 30%",
    "3, 10, 1, 1, true,  true,  true,  30%",
    "3, 10, 0, 0, false, false, false, 3 (30%??)"
  })
  void updateState_whenInProgress_rendersProgressBarsAndPercentageText(
      int fetched,
      int total,
      int failed,
      int fatal,
      boolean finalized,
      boolean expectFailedBar,
      boolean expectFatalBar,
      String expectedText,
      @Mock FProxyFetchInProgress progress,
      @Mock FProxyFetchWaiter waiter)
      throws ReflectiveOperationException {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);

    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(progress);
    when(progress.getWaiter()).thenReturn(waiter);

    FProxyFetchResult result =
        newFetchResultSnapshot(
            progress, total, fetched, failed, fatal, finalized, /* failedException= */ null);
    when(waiter.getResult()).thenReturn(result);

    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, false);
    clearInvocations(progress, waiter);

    // Act
    element.updateState(false);

    // Assert
    HTMLNode progressBarContainer = getSingleChild(element);
    assertEquals("div", progressBarContainer.getName());
    assertEquals("progressbar", progressBarContainer.getAttribute(ATTR_CLASS));

    List<HTMLNode> barChildren = progressBarContainer.getChildren();
    assertFalse(barChildren.isEmpty(), "Expected progress bar container to have children");

    HTMLNode doneBar = barChildren.getFirst();
    assertEquals("div", doneBar.getName());
    assertEquals("progressbar-done", doneBar.getAttribute(ATTR_CLASS));
    assertEquals(
        "width: " + (int) (fetched / (double) total * 100) + "%;", doneBar.getAttribute("style"));

    assertEquals(expectFailedBar, hasChildWithClass(progressBarContainer, "progressbar-failed"));
    assertEquals(expectFatalBar, hasChildWithClass(progressBarContainer, "progressbar-failed2"));

    HTMLNode fractionDiv = getLastElementChild(progressBarContainer);
    assertEquals("div", fractionDiv.getName());
    assertEquals(
        finalized ? "progress_fraction_finalized" : "progress_fraction_not_finalized",
        fractionDiv.getAttribute(ATTR_CLASS));
    assertNotNull(fractionDiv.getAttribute("title"));
    assertTrue(
        fractionDiv.getAttribute("title").startsWith("(" + fetched + "/ " + total + "): "),
        "Expected title to include the (fetched/ total) prefix");

    HTMLNode fractionTextNode = getSingleChild(fractionDiv);
    assertEquals("#", fractionTextNode.getName());
    assertEquals(expectedText, fractionTextNode.getContent());

    verify(progress).close(waiter);
    verify(progress).close(result);
  }

  @Test
  void constructor_whenPushed_registersWithPushManagerAndFetchListener(
      @Mock SimpleToadletServer server,
      @Mock PushDataManager pushDataManager,
      @Mock FProxyFetchInProgress progress,
      @Mock FProxyFetchWaiter waiter)
      throws ReflectiveOperationException {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);
    when(toadletContext.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);

    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(progress);
    when(progress.getWaiter()).thenReturn(waiter);
    when(waiter.getResult())
        .thenReturn(
            newFetchResultSnapshot(
                progress, /* requiredBlocks= */ 10, /* fetchedBlocks= */ 0, 0, 0, true, null));

    // Act
    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, true);

    // Assert
    verify(pushDataManager).elementRendered(REQUEST_ID, element);
    ArgumentCaptor<FProxyFetchListener> listenerCaptor =
        ArgumentCaptor.forClass(FProxyFetchListener.class);
    verify(progress).addListener(listenerCaptor.capture());
    assertNotNull(listenerCaptor.getValue());
    assertInstanceOf(NotifierFetchListener.class, listenerCaptor.getValue());

    // Act
    element.dispose();

    // Assert
    verify(progress).removeListener(listenerCaptor.getValue());
  }

  @Test
  void getUpdaterId_whenRequestIdVaries_returnsSameValue() {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);

    // Act
    String idFromNull = ProgressBarElement.getId(key);
    String idFromOther =
        new ProgressBarElement(tracker, key, fetchContext, 1L, toadletContext, false)
            .getUpdaterId("x");

    // Assert
    assertEquals(idFromNull, idFromOther);
  }

  @Test
  void getUpdaterType_whenCalled_returnsProgressbarUpdaterConstant() {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(null);
    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, 123L, toadletContext, false);

    // Act
    String type = element.getUpdaterType();

    // Assert
    assertEquals(UpdaterConstants.PROGRESSBAR_UPDATER, type);
  }

  @Test
  void toString_whenCalled_includesKeyMaxSizeAndUpdaterId() {
    // Arrange
    when(key.toString()).thenReturn(KEY_STRING);
    when(toadletContext.getUniqueId()).thenReturn(REQUEST_ID);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, fetchContext)))
        .thenReturn(null);
    long maxSize = 123L;
    ProgressBarElement element =
        new ProgressBarElement(tracker, key, fetchContext, maxSize, toadletContext, false);

    // Act
    String result = element.toString();

    // Assert
    assertTrue(result.contains("ProgressBarElement[key:"));
    assertTrue(result.contains(KEY_STRING));
    assertTrue(result.contains("maxSize:" + maxSize));
    assertTrue(result.contains("updaterId:" + ProgressBarElement.getId(key)));
  }

  private static HTMLNode getSingleChild(HTMLNode parent) {
    List<HTMLNode> children = parent.getChildren();
    assertEquals(1, children.size(), "Expected exactly one child node");
    return children.getFirst();
  }

  private static HTMLNode getLastElementChild(HTMLNode parent) {
    List<HTMLNode> children = parent.getChildren();
    assertFalse(children.isEmpty(), "Expected at least one child");
    return children.getLast();
  }

  private static boolean hasChildWithClass(HTMLNode parent, String className) {
    for (HTMLNode child : parent.getChildren()) {
      if (className.equals(child.getAttribute(ATTR_CLASS))) {
        return true;
      }
    }
    return false;
  }

  private static FetchException failure() {
    return new FetchException(FetchException.FetchExceptionMode.INTERNAL_ERROR, "failure");
  }

  @SuppressWarnings("java:S3011")
  private static FProxyFetchResult newFetchResultSnapshot(
      FProxyFetchInProgress progress,
      int requiredBlocks,
      int fetchedBlocks,
      int failedBlocks,
      int fatallyFailedBlocks,
      boolean finalizedBlocks,
      FetchException failedException)
      throws ReflectiveOperationException {
    Constructor<FProxyFetchResult> ctor =
        FProxyFetchResult.class.getDeclaredConstructor(
            FProxyFetchInProgress.class,
            FProxyFetchSnapshotInfo.class,
            long.class,
            FProxyFetchProgressCounts.class,
            FetchException.class);
    ctor.setAccessible(true);
    return ctor.newInstance(
        progress,
        new FProxyFetchSnapshotInfo("text/plain", 0L, false, -1L, false),
        /* size= */ 0L,
        new FProxyFetchProgressCounts(
            /* totalBlocks= */ requiredBlocks,
            requiredBlocks,
            fetchedBlocks,
            failedBlocks,
            fatallyFailedBlocks,
            finalizedBlocks),
        failedException);
  }
}
