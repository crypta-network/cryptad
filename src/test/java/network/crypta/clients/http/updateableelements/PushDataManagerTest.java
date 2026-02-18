package network.crypta.clients.http.updateableelements;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PushDataManagerTest {
  private static final String CLEANER_TASK_NAME = "cleanerTask";
  private static final String ELEMENT_ID_1 = "element-1";
  private static final String MISSING_REQUEST_ID = "req-missing";
  private static final String REQUEST_1 = "req-1";
  private static final String ORIGIN_REQUEST_ID = "req-origin";
  private static final String POLLING_REQUEST_ID = "req-polling";

  @Test
  void elementRendered_whenFirstElementRendered_tracksRequestAndSchedulesCleanerOnce() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String requestA = "req-a";
    BaseUpdatableElement elementA = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(elementA.getUpdaterId(requestA)).thenReturn("element-a");

    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<Long> offsetCaptor = ArgumentCaptor.forClass(Long.class);

    // Act
    manager.elementRendered(requestA, elementA);

    // Assert
    Mockito.verify(ticker)
        .queueTimedJob(
            runnableCaptor.capture(),
            Mockito.eq(CLEANER_TASK_NAME),
            offsetCaptor.capture(),
            Mockito.eq(false),
            Mockito.eq(true));
    assertNotNull(runnableCaptor.getValue());
    assertEquals(expectedCleanerDelayMs(), offsetCaptor.getValue().longValue());

    assertTrue(manager.keepAliveReceived(requestA));
    BaseUpdatableElement rendered = manager.getRenderedElement(requestA, "element-a");
    assertSame(elementA, rendered);
    Mockito.verify(elementA).updateState(false);

    String requestB = "req-b";
    BaseUpdatableElement elementB = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(elementB.getUpdaterId(requestB)).thenReturn("element-b");

    manager.elementRendered(requestB, elementB);

    Mockito.verifyNoMoreInteractions(ticker);
  }

  @Test
  void updateElement_whenElementRenderedOnOnePage_addsUpdateEventToAllListsAndDedupes()
      throws Exception {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String originRequest = ORIGIN_REQUEST_ID;
    String pollingRequest = POLLING_REQUEST_ID;
    String elementId = ELEMENT_ID_1;

    BaseUpdatableElement elementOnOrigin = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(elementOnOrigin.getUpdaterId(originRequest)).thenReturn(elementId);

    BaseUpdatableElement elementOnPolling = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(elementOnPolling.getUpdaterId(pollingRequest)).thenReturn("other-element");

    manager.elementRendered(originRequest, elementOnOrigin);
    manager.elementRendered(pollingRequest, elementOnPolling);

    // Act
    manager.updateElement(elementId);
    manager.updateElement(elementId);
    assertTrue(manager.keepAliveReceived(originRequest));

    // Assert
    PushDataManager.UpdateEvent eventFromOrigin = manager.getNextNotification(originRequest);
    PushDataManager.UpdateEvent eventFromPolling = manager.getNextNotification(pollingRequest);
    assertNotNull(eventFromOrigin);
    assertNotNull(eventFromPolling);
    assertEquals(originRequest, eventFromOrigin.getRequestId());
    assertEquals(elementId, eventFromOrigin.getElementId());
    assertEquals(eventFromOrigin, eventFromPolling);
    assertEquals(eventFromOrigin.hashCode(), eventFromPolling.hashCode());
    assertEquals(
        "UpdateEvent[requestId=" + originRequest + ",elementId=" + elementId + "]",
        eventFromOrigin.toString());

    CountDownLatch done = new CountDownLatch(1);
    Holder<PushDataManager.UpdateEvent> secondPoll = new Holder<>();
    Thread waiter =
        new Thread(
            () -> {
              secondPoll.value = manager.getNextNotification(pollingRequest);
              done.countDown();
            });
    waiter.start();
    assertFalse(done.await(200, TimeUnit.MILLISECONDS));
    waiter.interrupt();
    joinOrThrow(waiter, TimeUnit.SECONDS.toMillis(5));
    assertNull(secondPoll.value);
  }

  @Test
  void getRenderedElement_whenElementExists_updatesStateAndReturnsElement() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String requestId = REQUEST_1;
    String elementId = ELEMENT_ID_1;
    BaseUpdatableElement element = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(element.getUpdaterId(requestId)).thenReturn(elementId);

    manager.elementRendered(requestId, element);

    // Act
    BaseUpdatableElement rendered = manager.getRenderedElement(requestId, elementId);

    // Assert
    assertSame(element, rendered);
    Mockito.verify(element).updateState(false);
  }

  @Test
  void getRenderedElement_whenRequestOrIdMissing_returnsNull() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    // Act + Assert
    assertNull(manager.getRenderedElement("missing-request", "missing-element"));

    String requestId = REQUEST_1;
    BaseUpdatableElement element = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(element.getUpdaterId(requestId)).thenReturn(ELEMENT_ID_1);
    manager.elementRendered(requestId, element);

    assertNull(manager.getRenderedElement(requestId, "other-element"));
  }

  @Test
  void keepAliveReceived_whenRequestUnknown_returnsFalse() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    // Act + Assert
    assertFalse(manager.keepAliveReceived(MISSING_REQUEST_ID));
  }

  @Test
  void getNextNotification_whenRequestNotRegistered_returnsNull() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    // Act + Assert
    assertNull(manager.getNextNotification(MISSING_REQUEST_ID));
  }

  @Test
  void getNextNotification_whenInterrupted_returnsNull() throws Exception {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String requestId = REQUEST_1;
    BaseUpdatableElement element = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(element.getUpdaterId(requestId)).thenReturn(ELEMENT_ID_1);
    manager.elementRendered(requestId, element);

    CountDownLatch started = new CountDownLatch(1);
    Holder<PushDataManager.UpdateEvent> result = new Holder<>();

    Thread thread =
        new Thread(
            () -> {
              started.countDown();
              result.value = manager.getNextNotification(requestId);
            });

    // Act
    thread.start();
    assertTrue(started.await(1, TimeUnit.SECONDS));
    thread.interrupt();
    joinOrThrow(thread, TimeUnit.SECONDS.toMillis(5));

    // Assert
    assertNull(result.value);
  }

  @Test
  void getNextNotification_whenOriginKeepaliveReceived_returnsNextEvent() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String originRequest = ORIGIN_REQUEST_ID;
    String pollingRequest = "req-poll";
    String elementId = ELEMENT_ID_1;

    BaseUpdatableElement originElement = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(originElement.getUpdaterId(originRequest)).thenReturn(elementId);
    manager.elementRendered(originRequest, originElement);

    BaseUpdatableElement pollingElement = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(pollingElement.getUpdaterId(pollingRequest)).thenReturn("polling-element");
    manager.elementRendered(pollingRequest, pollingElement);

    manager.updateElement(elementId);
    assertTrue(manager.keepAliveReceived(originRequest));

    // Act
    PushDataManager.UpdateEvent event = manager.getNextNotification(pollingRequest);

    // Assert
    assertNotNull(event);
    assertEquals(originRequest, event.getRequestId());
    assertEquals(elementId, event.getElementId());
  }

  @Test
  void failover_whenOriginalHasAwaitingNotifications_movesListAndReturnsTrue() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String originalRequest = "req-old";
    String newRequest = "req-new";
    String elementId = ELEMENT_ID_1;

    BaseUpdatableElement element = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(element.getUpdaterId(originalRequest)).thenReturn(elementId);
    manager.elementRendered(originalRequest, element);

    manager.updateElement(elementId);
    assertTrue(manager.keepAliveReceived(originalRequest));

    // Act
    assertTrue(manager.failover(originalRequest, newRequest));

    // Assert
    PushDataManager.UpdateEvent event = manager.getNextNotification(newRequest);
    assertNotNull(event);
    assertEquals(originalRequest, event.getRequestId());
    assertEquals(elementId, event.getElementId());
  }

  @Test
  void failover_whenOriginalMissing_returnsFalse() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    // Act + Assert
    assertFalse(manager.failover(MISSING_REQUEST_ID, "req-new"));
  }

  @Test
  void leaving_whenRequestRegistered_deletesRequestAndIsIdempotent() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String requestId = REQUEST_1;
    BaseUpdatableElement element = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(element.getUpdaterId(requestId)).thenReturn(ELEMENT_ID_1);
    manager.elementRendered(requestId, element);

    // Act + Assert
    assertTrue(manager.leaving(requestId));
    assertFalse(manager.leaving(requestId));
    assertFalse(manager.keepAliveReceived(requestId));
    Mockito.verify(element).dispose();
  }

  @Test
  void cleanerTask_whenKeepaliveMissing_deletesRequestAndStopsRescheduling() {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    PushDataManager manager = new PushDataManager(ticker);

    String requestId = REQUEST_1;
    BaseUpdatableElement element = Mockito.mock(BaseUpdatableElement.class);
    Mockito.when(element.getUpdaterId(requestId)).thenReturn(ELEMENT_ID_1);

    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    manager.elementRendered(requestId, element);

    Mockito.verify(ticker)
        .queueTimedJob(
            runnableCaptor.capture(),
            Mockito.eq(CLEANER_TASK_NAME),
            Mockito.anyLong(),
            Mockito.eq(false),
            Mockito.eq(true));

    Runnable cleanerTask = runnableCaptor.getValue();

    // Act
    cleanerTask.run();

    // Assert (first run resets keepalive and reschedules)
    Mockito.verify(ticker, Mockito.times(2))
        .queueTimedJob(
            Mockito.any(Runnable.class),
            Mockito.eq(CLEANER_TASK_NAME),
            Mockito.anyLong(),
            Mockito.eq(false),
            Mockito.eq(true));

    // Act
    cleanerTask.run();

    // Assert (second run deletes request and does not reschedule further)
    Mockito.verify(ticker, Mockito.times(2))
        .queueTimedJob(
            Mockito.any(Runnable.class),
            Mockito.eq(CLEANER_TASK_NAME),
            Mockito.anyLong(),
            Mockito.eq(false),
            Mockito.eq(true));
    Mockito.verify(element).dispose();
    assertFalse(manager.keepAliveReceived(requestId));
  }

  private static long expectedCleanerDelayMs() {
    return (long) (UpdaterConstants.KEEPALIVE_INTERVAL_SECONDS * 1000 * 2.1);
  }

  private static void joinOrThrow(Thread thread, long timeoutMillis) throws InterruptedException {
    thread.join(timeoutMillis);
    if (thread.isAlive()) {
      throw new AssertionError(
          "Thread did not finish within " + timeoutMillis + "ms (state=" + thread.getState() + ")");
    }
  }

  private static final class Holder<T> {
    private T value;
  }
}
