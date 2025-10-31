package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.client.async.ClientContext;
import network.crypta.support.math.RunningAverage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RequestStarterTest {

  @Mock private NodeClientCore core;
  @Mock private NodeStats nodeStats;
  @Mock private BaseRequestThrottle throttle;
  @Mock private RunningAverage avgOut;
  @Mock private RunningAverage avgIn;
  @Mock private RequestScheduler scheduler;
  @Mock private ClientContext clientContext;

  private RequestStarter newStarter(boolean isInsert, boolean realTime) {
    // Minimal wiring required by RequestStarter's constructor; scoped to callers to avoid
    // unnecessary stubbing on tests that don't construct a RequestStarter.
    when(core.getNodeStats()).thenReturn(nodeStats);
    RequestStarter starter =
        new RequestStarter(
            core, throttle, "starter", avgOut, avgIn, isInsert, /* isSSK= */ false, realTime);
    starter.setScheduler(scheduler);
    return starter;
  }

  @Test
  @DisplayName("exclude: returns MAX_VALUE when persistent request already running")
  void exclude_whenPersistentRequestRunning_returnsMaxValue() {
    RequestStarter starter = newStarter(false, false);
    // Item must be a SendableRequest to pass the initial cast in exclude()
    SendableRequest item = mock(SendableRequest.class);

    when(scheduler.isRunningOrQueuedPersistentRequest(item)).thenReturn(true);

    long when = starter.exclude(item, clientContext, 123L);
    assertEquals(Long.MAX_VALUE, when);
  }

  @Test
  @DisplayName("exclude: returns -1 for insert schedulers (no get wakeups)")
  void exclude_whenIsInsert_returnsMinusOne() {
    RequestStarter starter = newStarter(true, false);
    // For insert, the concrete type of item doesn't matter as long as it is a SendableRequest
    SendableRequest item = mock(SendableRequest.class);

    when(scheduler.isRunningOrQueuedPersistentRequest(item)).thenReturn(false);

    long when = starter.exclude(item, clientContext, 456L);
    assertEquals(-1L, when);
  }

  @Test
  @DisplayName("exclude: non-BaseSendableGet returns -1 (not schedulable as get)")
  void exclude_whenNotBaseSendableGet_returnsMinusOne() {
    RequestStarter starter = newStarter(false, false);
    SendableRequest notAGet = mock(SendableRequest.class); // implements RandomGrabArrayItem

    when(scheduler.isRunningOrQueuedPersistentRequest(notAGet)).thenReturn(false);

    long when = starter.exclude(notAGet, clientContext, 789L);
    assertEquals(-1L, when);
  }

  @Test
  @DisplayName("exclude: BaseSendableGet delegates to getWakeupTime")
  void exclude_whenBaseSendableGet_delegatesToGetWakeupTime() {
    RequestStarter starter = newStarter(false, true);
    BaseSendableGet get = mock(BaseSendableGet.class);

    when(scheduler.isRunningOrQueuedPersistentRequest(get)).thenReturn(false);
    // Deterministic wakeup timestamp
    long now = 1_000_000L;
    long expected = now + 1234L;
    when(get.getWakeupTime(clientContext, now)).thenReturn(expected);

    long when = starter.exclude(get, clientContext, now);
    assertEquals(expected, when);
  }

  @ParameterizedTest(name = "isValidPriorityClass({0}) => {1}")
  @CsvSource({"-1,false", "0,true", "3,true", "6,true", "7,false"})
  void isValidPriorityClass_boundaryAndRangeChecks(int value, boolean expected) {
    assertEquals(expected, RequestStarter.isValidPriorityClass(value));
  }

  @Test
  @DisplayName("toString includes name with real-time/bulk suffix")
  void toString_whenRealtimeAndBulk_expectSuffixes() {
    RequestStarter bulk = newStarter(false, false);
    RequestStarter realtime = newStarter(false, true);

    assertEquals("starter (bulk)", bulk.toString());
    assertEquals("starter (realtime)", realtime.toString());
  }

  @Test
  @DisplayName("wakeUp notifies threads waiting on the starter monitor")
  void wakeUp_notifiesWaitingThreads() throws InterruptedException {
    RequestStarter starter = newStarter(false, false);

    CountDownLatch enteredWait = new CountDownLatch(1);
    CountDownLatch finished = new CountDownLatch(1);
    AtomicLong elapsedMillis = new AtomicLong(-1);

    Thread t =
        new Thread(
            () -> {
              long start = System.nanoTime();
              synchronized (starter) {
                enteredWait.countDown();
                try {
                  starter.wait(5000L); // Will be interrupted by notifyAll()
                } catch (InterruptedException ignored) {
                  // not expected in this test
                }
              }
              long end = System.nanoTime();
              elapsedMillis.set(TimeUnit.NANOSECONDS.toMillis(end - start));
              finished.countDown();
            },
            "waiter");

    t.start();

    // Ensure the worker is waiting on the monitor before notifying
    assertTrue(enteredWait.await(1, TimeUnit.SECONDS));

    long beforeNotify = System.nanoTime();
    starter.wakeUp();

    assertTrue(finished.await(1, TimeUnit.SECONDS));
    long afterNotify = System.nanoTime();

    // The waiter should resume quickly after notifyAll(); allow a generous bound.
    long notifyWindowMs = TimeUnit.NANOSECONDS.toMillis(afterNotify - beforeNotify);
    assertTrue(
        elapsedMillis.get() <= 1000L + notifyWindowMs,
        "wait should finish promptly after wakeUp()");
  }
}
