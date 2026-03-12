package network.crypta.support;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class WrapperKeepaliveTest {

  private static final long AWAIT_TIMEOUT_MS = 2_000L;

  // Helper that waits until the thread is sleeping (TIMED_WAITING) or times out.
  private static boolean awaitTimedWaiting(Thread t) {
    final long deadline = System.nanoTime() + AWAIT_TIMEOUT_MS * 1_000_000L;
    while (System.nanoTime() < deadline) {
      if (t.getState() == Thread.State.TIMED_WAITING) {
        return true;
      }
      Thread.onSpinWait();
    }
    return t.getState() == Thread.State.TIMED_WAITING;
  }

  @Test
  @SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
  void run_whenClosedBeforeStart_exitsImmediately() throws Exception {
    // Arrange
    WrapperKeepalive keepalive = new WrapperKeepalive();
    // Act: closing before start should make the loop skip entirely
    keepalive.close();
    keepalive.start();

    // Assert: thread terminates promptly without needing an interrupt
    keepalive.join(500);
    assertFalse(keepalive.isAlive(), "Keepalive thread should exit immediately when pre-closed");
  }

  @Test
  @SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
  void run_whenSleepingThenClosedAndInterrupted_exitsPromptly() throws Exception {
    // Arrange
    WrapperKeepalive keepalive = new WrapperKeepalive();
    keepalive.start();

    // Wait until the thread is in TIMED_WAITING (sleeping). This avoids any timing flakiness
    // from racing the initial call to sleep.
    boolean inSleep = awaitTimedWaiting(keepalive);
    if (!inSleep) {
      fail("Keepalive thread did not reach sleep state in time");
    }

    // Act: request shutdown and interrupt to break the sleep immediately
    keepalive.close();
    keepalive.interrupt();

    // Assert: the thread should finish quickly after the interrupt because the loop condition
    // is false on the next iteration.
    keepalive.join(1_000);
    assertFalse(keepalive.isAlive(), "Keepalive thread should exit promptly after close+interrupt");
  }

  @Test
  @SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
  void run_whenInterruptedWithoutClose_continuesLoopUntilClosed() throws Exception {
    // Arrange
    WrapperKeepalive keepalive = new WrapperKeepalive();
    keepalive.start();

    // Ensure the thread is sleeping, then interrupt it to trigger the catch path.
    boolean inSleep = awaitTimedWaiting(keepalive);
    if (!inSleep) {
      fail("Keepalive thread did not reach sleep state in time");
    }

    // Act: interrupt without closing; the loop should continue running.
    keepalive.interrupt();

    // Wait for it to return to sleeping again, proving the loop continued past the catch block.
    boolean reenteredSleep = awaitTimedWaiting(keepalive);
    assertTrue(reenteredSleep, "Keepalive thread should continue looping after an interrupt");

    // Cleanup: now close and interrupt once more so the thread can exit immediately.
    keepalive.close();
    keepalive.interrupt();
    keepalive.join(1_000);
    assertFalse(keepalive.isAlive(), "Keepalive thread should terminate after final close");
  }
}
