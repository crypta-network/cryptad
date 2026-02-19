package network.crypta.support;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100") // test method naming style method_whenCondition_expectOutcome
class PooledExecutorTest {

  @Test
  @DisplayName("initial arrays are zeroed and sized to priority range")
  void introspection_initialState_expectZerosAndExpectedLength() {
    PooledExecutor exec = new PooledExecutor();

    int expectedLen = NativeThread.JAVA_PRIORITY_RANGE + 1; // indices map to priority-1
    int[] expectedZeros = new int[expectedLen];

    assertArrayEquals(expectedZeros, exec.runningThreads());
    assertArrayEquals(expectedZeros, exec.waitingThreads());
    assertEquals(0, exec.getWaitingThreadsCount());
  }

  @Test
  void execute_withDefaultPriority_expectRunsAndReportsRunningThread() {
    PooledExecutor exec = new PooledExecutor();

    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);

    Runnable job =
        () -> {
          started.countDown();
          try {
            // Block until the test allows the job to finish to keep the thread in RUNNING state.
            assertTrue(release.await(2, TimeUnit.SECONDS));
          } catch (InterruptedException e) {
            fail(e);
          }
        };

    exec.execute(job, "default-prio");

    assertTrue(uninterruptiblyAwait(started, 2), "job did not start in time");

    int idx = NativeThread.PriorityLevel.NORM_PRIORITY.value - 1;
    int[] running = exec.runningThreads();
    assertTrue(running[idx] >= 1, "expected at least one running thread at normal priority");
    assertEquals(0, exec.getWaitingThreadsCount(), "no threads should be waiting while job runs");

    release.countDown();
  }

  @Test
  void execute_whenInvalidPriority_expectIllegalArgumentException() {
    PooledExecutor exec = new PooledExecutor();

    PrioRunnable badLow =
        new PrioRunnable() {
          @Override
          public int getPriority() {
            return NativeThread.PriorityLevel.MIN_PRIORITY.value - 1; // invalid
          }

          @Override
          public void run() {
            // No-op: this task is never executed; we only trigger submission
            // to validate that invalid priorities cause IllegalArgumentException.
          }
        };

    PrioRunnable badHigh =
        new PrioRunnable() {
          @Override
          public int getPriority() {
            return NativeThread.PriorityLevel.MAX_PRIORITY.value + 1; // invalid
          }

          @Override
          public void run() {
            // No-op: this task is never executed; we only trigger submission
            // to validate that invalid priorities cause IllegalArgumentException.
          }
        };

    try {
      exec.execute(badLow, "badLow");
      fail("expected IllegalArgumentException for low priority");
    } catch (IllegalArgumentException _) {
      // ok
    }

    try {
      exec.execute(badHigh, "badHigh");
      fail("expected IllegalArgumentException for high priority");
    } catch (IllegalArgumentException _) {
      // ok
    }
  }

  @Test
  void execute_withTickerDelegation_conditionallyDelegatesBasedOnNativeSupport() {
    PooledExecutor exec = new PooledExecutor();
    Ticker ticker = mock(Ticker.class);
    exec.setTicker(ticker);

    CountDownLatch ran = new CountDownLatch(1);
    // Use above-normal priority to satisfy prio > currentThreadPriority condition.
    int high = NativeThread.PriorityLevel.HIGH_PRIORITY.value;
    PrioRunnable job =
        new PrioRunnable() {
          @Override
          public int getPriority() {
            return high;
          }

          @Override
          public void run() {
            ran.countDown();
          }
        };

    boolean expectDelegate = NativeThread.usingNativeCode();

    exec.execute(job, "delegation-check", false);

    if (expectDelegate) {
      // When native support is active, creation should be delegated to the ticker and the job
      // should not execute here.
      verify(ticker, times(1)).queueTimedJob(job, "delegation-check", 0, true, false);
      assertFalse(uninterruptiblyAwaitMillis(ran, 150), "job should not have executed here");
      assertArrayEquals(new int[NativeThread.JAVA_PRIORITY_RANGE + 1], exec.runningThreads());
      assertEquals(0, exec.getWaitingThreadsCount());
    } else {
      // Without native support, the executor creates a worker and runs the job immediately.
      verifyNoInteractions(ticker);
      assertTrue(uninterruptiblyAwait(ran, 2), "job did not execute when native unsupported");
    }
  }

  @Test
  void execute_whenFromTicker_true_doesNotDelegateAndRunsJob() {
    PooledExecutor exec = new PooledExecutor();
    Ticker ticker = mock(Ticker.class);
    exec.setTicker(ticker);

    CountDownLatch ran = new CountDownLatch(1);
    int high = NativeThread.PriorityLevel.HIGH_PRIORITY.value;
    PrioRunnable job =
        new PrioRunnable() {
          @Override
          public int getPriority() {
            return high;
          }

          @Override
          public void run() {
            ran.countDown();
          }
        };

    exec.execute(job, "from-ticker", true);

    assertTrue(uninterruptiblyAwait(ran, 2), "job did not execute when fromTicker=true");
    verifyNoInteractions(ticker);
  }

  @Test
  void execute_whenThreadIsWaiting_reusesSameWorkerThread() {
    PooledExecutor exec = new PooledExecutor();

    AtomicReference<String> name1 = new AtomicReference<>();
    AtomicReference<String> name2 = new AtomicReference<>();
    CountDownLatch ran1 = new CountDownLatch(1);
    CountDownLatch ran2 = new CountDownLatch(1);

    Runnable first =
        () -> {
          name1.set(Thread.currentThread().getName());
          ran1.countDown();
        };
    Runnable second =
        () -> {
          name2.set(Thread.currentThread().getName());
          ran2.countDown();
        };

    // Run the first job and wait until it completed.
    exec.execute(first, "first");
    assertTrue(uninterruptiblyAwait(ran1, 2), "first job did not run");

    // Wait until a worker has entered the waiting list before submitting the next job.
    assertTimeout(
        Duration.ofSeconds(2),
        () -> {
          while (exec.getWaitingThreadsCount() == 0) {
            // Busy-spin briefly; avoid sleep to keep tests deterministic and fast.
            Thread.onSpinWait();
          }
        });

    // Submit a second job and ensure it runs.
    exec.execute(second, "second");
    assertTrue(uninterruptiblyAwait(ran2, 2), "second job did not run");

    // Extract worker id suffix from thread names: label is "<job>(<id>)" set by PooledExecutor.
    String id1 = extractWorkerIdSuffix(name1.get());
    String id2 = extractWorkerIdSuffix(name2.get());
    assertEquals(id1, id2, "expected the same worker thread to be reused");
  }

  @Test
  void idleWorker_whenInterrupted_exitsInsteadOfSpinning_andNextJobUsesNewThread() {
    PooledExecutor exec = new PooledExecutor();

    AtomicReference<Thread> workerRef = new AtomicReference<>();
    AtomicReference<String> firstName = new AtomicReference<>();
    CountDownLatch ran1 = new CountDownLatch(1);

    Runnable first =
        () -> {
          Thread t = Thread.currentThread();
          workerRef.set(t);
          firstName.set(t.getName());
          ran1.countDown();
        };

    exec.execute(first, "first");
    assertTrue(uninterruptiblyAwait(ran1, 2), "first job did not run");

    // Wait for the worker to become idle/registered as waiting.
    assertTimeout(
        Duration.ofSeconds(2),
        () -> {
          while (exec.getWaitingThreadsCount() == 0) {
            Thread.onSpinWait();
          }
        });

    // Interrupt the idle worker and verify it retires (waiting count returns to 0).
    Thread w = workerRef.get();
    w.interrupt();

    assertTimeout(
        Duration.ofSeconds(2),
        () -> {
          while (exec.getWaitingThreadsCount() != 0) {
            Thread.onSpinWait();
          }
        });

    // Also confirm there are no running workers at the default priority once it retires.
    int idx = NativeThread.PriorityLevel.NORM_PRIORITY.value - 1;
    assertTimeout(
        Duration.ofSeconds(2),
        () -> {
          while (exec.runningThreads()[idx] != 0) {
            Thread.onSpinWait();
          }
        });

    // Submit a second job and ensure it runs on a different worker id.
    AtomicReference<String> secondName = new AtomicReference<>();
    CountDownLatch ran2 = new CountDownLatch(1);
    Runnable second =
        () -> {
          secondName.set(Thread.currentThread().getName());
          ran2.countDown();
        };
    exec.execute(second, "second");
    assertTrue(uninterruptiblyAwait(ran2, 2), "second job did not run");

    String id1 = extractWorkerIdSuffix(firstName.get());
    String id2 = extractWorkerIdSuffix(secondName.get());
    // If the interrupted worker retired, the thread id suffix must differ.
    Assertions.assertNotEquals(id1, id2, "expected a new worker thread after interrupt");
  }

  // --- Helpers ---

  private static boolean uninterruptiblyAwait(CountDownLatch latch, long seconds) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
    boolean done = false;
    while (!done && System.nanoTime() < deadline) {
      try {
        done = latch.await(5, TimeUnit.MILLISECONDS);
      } catch (InterruptedException _) {
        // retry until deadline
      }
    }
    return done;
  }

  private static boolean uninterruptiblyAwaitMillis(CountDownLatch latch, long millis) {
    long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
    boolean done = false;
    while (!done && System.nanoTime() < deadline) {
      try {
        done = latch.await(5, TimeUnit.MILLISECONDS);
      } catch (InterruptedException _) {
        // retry until deadline
      }
    }
    return done;
  }

  private static String extractWorkerIdSuffix(String threadName) {
    int open = threadName.lastIndexOf('(');
    int close = threadName.lastIndexOf(')');
    if (open == -1 || close == -1 || close <= open + 1) {
      fail("unexpected thread name format: " + threadName);
    }
    return threadName.substring(open + 1, close);
  }
}
