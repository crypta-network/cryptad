package network.crypta.node;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.io.comm.AsyncMessageCallback;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WaitingMultiMessageCallbackTest {

  private Thread waiter;

  @AfterEach
  void cleanup() throws InterruptedException {
    if (waiter != null) {
      waiter.join(TimeUnit.SECONDS.toMillis(2));
      waiter = null;
    }
  }

  @Test
  void arm_whenNoMessages_finishAndSentAreTrue_andWaitForReturns() throws Exception {
    // Arrange
    RecordingWaitingCallback mcb = new RecordingWaitingCallback();

    // Act
    mcb.arm();
    mcb.waitFor();

    // Assert
    assertTrue(mcb.finishLatch.await(1, TimeUnit.SECONDS), "finish should have fired");
    assertTrue(mcb.sentLatch.await(1, TimeUnit.SECONDS), "sent should have fired");
    assertEquals(Boolean.TRUE, mcb.finishSuccess, "finish success should be true");
    assertEquals(Boolean.TRUE, mcb.sentSuccess, "sent success should be true");
    assertEquals(1, mcb.finishCalls.get(), "finish should be called once");
    assertEquals(1, mcb.sentCalls.get(), "sent should be called once");
  }

  @Test
  void waitFor_blocksUntilBothMessagesComplete_afterArm() throws Exception {
    // Arrange
    RecordingWaitingCallback mcb = new RecordingWaitingCallback();
    AsyncMessageCallback c1 = mcb.make();
    AsyncMessageCallback c2 = mcb.make();
    mcb.arm();

    CountDownLatch waiterDone = new CountDownLatch(1);
    waiter =
        new Thread(
            () -> {
              mcb.waitFor();
              waiterDone.countDown();
            },
            "waiter-after-arm");
    waiter.start();

    // Act: complete only one message first, finish must not fire yet
    c1.acknowledged();
    assertFalse(mcb.finishLatch.await(200, TimeUnit.MILLISECONDS), "finish must not fire yet");

    // Complete the second; now both callbacks should fire
    c2.fatalError();

    // Assert
    assertTrue(mcb.sentLatch.await(1, TimeUnit.SECONDS), "sent should have fired");
    assertTrue(mcb.finishLatch.await(1, TimeUnit.SECONDS), "finish should have fired");
    assertTrue(waiterDone.await(1, TimeUnit.SECONDS), "waiter should return after finish");

    assertEquals(Boolean.FALSE, mcb.finishSuccess, "finish success should aggregate failures");
    assertEquals(Boolean.FALSE, mcb.sentSuccess, "sent success should aggregate failures");
    assertEquals(1, mcb.finishCalls.get(), "finish should be called once");
    assertEquals(1, mcb.sentCalls.get(), "sent should be called once");
  }

  @Test
  void waitFor_unblocksWhenCompletedBeforeArm_thenArmTriggersCallbacks() throws Exception {
    // Arrange
    RecordingWaitingCallback mcb = new RecordingWaitingCallback();
    AsyncMessageCallback c1 = mcb.make();
    AsyncMessageCallback c2 = mcb.make();

    // Complete both BEFORE arming: one success, one failure
    c1.acknowledged();
    c2.disconnected();

    CountDownLatch waiterDone = new CountDownLatch(1);
    waiter =
        new Thread(
            () -> {
              mcb.waitFor();
              waiterDone.countDown();
            },
            "waiter-before-arm");
    waiter.start();

    // Act: arming now must trigger both group callbacks and unblock waiters
    mcb.arm();

    // Assert
    assertTrue(mcb.sentLatch.await(1, TimeUnit.SECONDS), "sent should have fired after arm()");
    assertTrue(mcb.finishLatch.await(1, TimeUnit.SECONDS), "finish should have fired after arm()");
    assertTrue(waiterDone.await(1, TimeUnit.SECONDS), "waiter should return after arm+finish");
    assertEquals(Boolean.FALSE, mcb.finishSuccess, "finish success should be false");
    assertEquals(Boolean.FALSE, mcb.sentSuccess, "sent success should be false");
  }

  @Test
  void duplicateSignals_areIgnored_andCallbacksFireOnce() throws Exception {
    // Arrange
    RecordingWaitingCallback mcb = new RecordingWaitingCallback();
    AsyncMessageCallback c = mcb.make();
    mcb.arm();

    // Act: duplicate 'sent' and 'acknowledged' should be ignored
    c.sent();
    c.sent();
    c.acknowledged();
    c.acknowledged();

    mcb.waitFor();

    // Assert
    assertTrue(mcb.sentLatch.await(1, TimeUnit.SECONDS));
    assertTrue(mcb.finishLatch.await(1, TimeUnit.SECONDS));
    assertEquals(1, mcb.sentCalls.get(), "sent should be called once");
    assertEquals(1, mcb.finishCalls.get(), "finish should be called once");
    assertEquals(Boolean.TRUE, mcb.finishSuccess);
    assertEquals(Boolean.TRUE, mcb.sentSuccess);
  }

  @Test
  void completionWithoutPriorSent_stillCountsTowardGroupSentAndFinish() throws Exception {
    // Arrange
    RecordingWaitingCallback mcb = new RecordingWaitingCallback();
    AsyncMessageCallback c1 = mcb.make();
    AsyncMessageCallback c2 = mcb.make();
    mcb.arm();

    // Act: one fails before any explicit 'sent', the other succeeds
    c1.fatalError();
    c2.acknowledged();

    // Assert
    mcb.waitFor();
    assertTrue(mcb.sentLatch.await(1, TimeUnit.SECONDS));
    assertTrue(mcb.finishLatch.await(1, TimeUnit.SECONDS));
    assertEquals(1, mcb.sentCalls.get());
    assertEquals(1, mcb.finishCalls.get());
    assertEquals(Boolean.FALSE, mcb.sentSuccess);
    assertEquals(Boolean.FALSE, mcb.finishSuccess);
  }

  @Test
  void waitFor_ignoresInterrupt_andContinuesWaitingUntilFinish() throws Exception {
    // Arrange
    RecordingWaitingCallback mcb = new RecordingWaitingCallback();
    AsyncMessageCallback c = mcb.make();
    mcb.arm();

    CountDownLatch waiterReady = new CountDownLatch(1);
    CountDownLatch waiterDone = new CountDownLatch(1);
    waiter =
        new Thread(
            () -> {
              // Signal that we're about to wait, then call waitFor which should ignore interrupts
              waiterReady.countDown();
              mcb.waitFor();
              waiterDone.countDown();
            },
            "waiter-interrupt");
    waiter.start();

    assertTrue(waiterReady.await(1, TimeUnit.SECONDS), "waiter should start");

    // Act: interrupt the waiter, then complete the message
    waiter.interrupt();
    c.acknowledged();

    // Assert
    assertTrue(mcb.finishLatch.await(1, TimeUnit.SECONDS));
    assertTrue(waiterDone.await(1, TimeUnit.SECONDS), "waiter should return after finish");
    assertEquals(Boolean.TRUE, mcb.finishSuccess);
  }

  /**
   * Package-private test helper that records callback invocations while preserving the production
   * semantics of {@link WaitingMultiMessageCallback} (notifying waiters on {@code finish}).
   */
  static class RecordingWaitingCallback extends WaitingMultiMessageCallback {
    final CountDownLatch finishLatch = new CountDownLatch(1);
    final CountDownLatch sentLatch = new CountDownLatch(1);
    final AtomicInteger finishCalls = new AtomicInteger();
    final AtomicInteger sentCalls = new AtomicInteger();
    volatile Boolean finishSuccess;
    volatile Boolean sentSuccess;

    @Override
    synchronized void finish(boolean success) {
      finishSuccess = success;
      finishCalls.incrementAndGet();
      super.finish(success); // keep notifyAll() behavior for waiters
      finishLatch.countDown();
    }

    @Override
    void sent(boolean success) {
      sentSuccess = success;
      sentCalls.incrementAndGet();
      sentLatch.countDown();
    }
  }
}
