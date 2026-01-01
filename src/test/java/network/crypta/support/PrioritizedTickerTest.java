package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import network.crypta.node.FastRunnable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PrioritizedTickerTest {

  private WaitableExecutor realExec;

  private MyTicker ticker;

  private static class MyTicker extends PrioritizedTicker {

    private boolean sleeping;
    private final Object sleepSync = new Object();

    public MyTicker(PriorityAwareExecutor executor, int portNumber) {
      super(executor, portNumber);
    }

    @Override
    protected void sleep(long sleepTime) throws InterruptedException {
      if (sleepTime == MAX_SLEEP_TIME) {
        synchronized (sleepSync) {
          sleeping = true;
          sleepSync.notifyAll();
        }
      }
      super.sleep(sleepTime);
      if (sleepTime == MAX_SLEEP_TIME) {
        synchronized (sleepSync) {
          sleeping = false;
        }
      }
    }

    public void waitForSleeping() throws InterruptedException {
      synchronized (sleepSync) {
        while (!sleeping) {
          sleepSync.wait();
        }
      }
    }

    public void waitForIdle() throws InterruptedException {
      // Wait until all jobs have been removed from the queue.
      while (queuedJobsUniqueTimes() > 0) {
        waitForSleeping();
      }
      // Wait until the jobs have actually been started off thread or completed on thread.
      waitForSleeping();
    }
  }

  @BeforeEach
  void setUp() {
    realExec = new WaitableExecutor(new PooledExecutor());
    ticker = new MyTicker(realExec, 0);
    ticker.start();
  }

  private int runCount = 0;

  Runnable simpleRunnable =
      () -> {
        synchronized (PrioritizedTickerTest.this) {
          runCount++;
        }
      };

  Runnable simpleRunnable2 =
      () -> {
        synchronized (PrioritizedTickerTest.this) {
          runCount += 10;
        }
      };

  private enum BlockTickerJobState {
    WAITING,
    BLOCKING,
    FINISHED
  }

  /**
   * Allows us to block the Ticker. Because it's a FastRunnable it will be run directly on the
   * Ticker thread itself. But it's not actually fast - it waits!
   */
  private static class BlockTickerJob implements FastRunnable {

    private BlockTickerJobState state = BlockTickerJobState.WAITING;
    private boolean proceed = false;

    @Override
    public synchronized void run() {
      state = BlockTickerJobState.BLOCKING;
      notifyAll();
      while (!proceed) {
        try {
          wait();
        } catch (InterruptedException _) {
          // Ignore.
        }
      }
      state = BlockTickerJobState.FINISHED;
      notifyAll();
    }

    public synchronized void waitForBlocking() throws InterruptedException {
      while (state != BlockTickerJobState.BLOCKING) {
        wait();
      }
    }

    public synchronized void waitForFinished() throws InterruptedException {
      while (state != BlockTickerJobState.FINISHED) {
        wait();
      }
    }

    public synchronized void unblockAndWait() throws InterruptedException {
      waitForBlocking();
      proceed = true;
      notifyAll();
      waitForFinished();
    }
  }

  @Test
  void testSimple() throws InterruptedException {
    // Arrange
    synchronized (PrioritizedTickerTest.this) {
      runCount = 0;
    }

    // Act
    ticker.queueTimedJob(simpleRunnable, 0);
    ticker.waitForIdle();
    realExec.waitForIdle();

    // Assert
    synchronized (PrioritizedTickerTest.this) {
      assertEquals(1, runCount);
    }
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());

    // --- Scenario: queue while ticker thread is blocked ---
    // Arrange
    BlockTickerJob blocker = new BlockTickerJob();
    ticker.queueTimedJob(blocker, "Block the ticker", 0, true, false);
    blocker.waitForBlocking();

    // Act
    ticker.queueTimedJob(simpleRunnable, "test", 0, true, false);

    // Assert (still queued while blocked)
    assertEquals(1, ticker.queuedJobs());

    // Act (unblock and drain)
    blocker.unblockAndWait();
    ticker.waitForIdle();
    realExec.waitForIdle();

    // Assert
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());
    synchronized (PrioritizedTickerTest.this) {
      assertEquals(2, runCount);
    }
  }

  @Test
  void testRemove() throws InterruptedException {
    // Arrange
    synchronized (PrioritizedTickerTest.this) {
      runCount = 0;
    }
    BlockTickerJob blocker = new BlockTickerJob();
    ticker.queueTimedJob(blocker, "Block the ticker", 0, true, false);
    blocker.waitForBlocking();
    ticker.queueTimedJob(simpleRunnable, "test", 0, true, false);

    // Assert (pre-condition: queued once at a single time)
    assertEquals(1, ticker.queuedJobs());
    assertEquals(1, ticker.queuedJobsUniqueTimes());

    // Act
    ticker.removeQueuedJob(simpleRunnable);

    // Assert
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());
    synchronized (PrioritizedTickerTest.this) {
      assertEquals(0, runCount);
    }

    // Cleanup
    blocker.unblockAndWait();
  }

  @Test
  void testRemoveTwoInSameMillisecond() throws InterruptedException {
    // Arrange
    BlockTickerJob blocker = new BlockTickerJob();
    ticker.queueTimedJob(blocker, "Block the ticker", 0, true, false);
    blocker.waitForBlocking();
    long tRunAt = System.currentTimeMillis(); // ensure both jobs share the same timestamp
    ticker.queueTimedJobAbsolute(simpleRunnable, "test1", tRunAt, true, false);
    ticker.queueTimedJobAbsolute(simpleRunnable2, "test2", tRunAt, true, false);

    // Assert (pre-condition: both queued at one unique time)
    assertEquals(2, ticker.queuedJobs());
    assertEquals(1, ticker.queuedJobsUniqueTimes());

    // Act + Assert (remove first)
    ticker.removeQueuedJob(simpleRunnable);
    assertEquals(1, ticker.queuedJobs());
    assertEquals(1, ticker.queuedJobsUniqueTimes());

    // Act + Assert (idempotent remove of first)
    ticker.removeQueuedJob(simpleRunnable);
    assertEquals(1, ticker.queuedJobs());
    assertEquals(1, ticker.queuedJobsUniqueTimes());

    // Act + Assert (remove second)
    ticker.removeQueuedJob(simpleRunnable2);
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());

    // Act + Assert (idempotent remove of second)
    ticker.removeQueuedJob(simpleRunnable2);
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());

    // Cleanup
    blocker.unblockAndWait();
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());
    synchronized (PrioritizedTickerTest.this) {
      assertEquals(0, runCount);
    }
  }

  @Test
  void testDeduping() throws InterruptedException {
    // Arrange
    synchronized (PrioritizedTickerTest.this) {
      runCount = 0;
    }
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());

    // --- Scenario A: de-dupe with runOnTickerAnyway=true ---
    // Arrange
    BlockTickerJob blocker = new BlockTickerJob();
    ticker.queueTimedJob(blocker, "Block the ticker", 0, true, false);
    blocker.waitForBlocking();
    long runAt = System.currentTimeMillis();

    // Act (second later job ignored)
    ticker.queueTimedJobAbsolute(simpleRunnable, "De-dupe test", runAt, true, true);
    ticker.queueTimedJobAbsolute(simpleRunnable, "De-dupe test", runAt + 1, true, true);

    // Assert (only one queued time)
    assertEquals(1, ticker.queuedJobs());
    assertEquals(1, ticker.queuedJobsUniqueTimes());

    // Act (unblock and drain)
    blocker.unblockAndWait();
    ticker.waitForIdle();
    realExec.waitForIdle();

    // Assert
    synchronized (PrioritizedTickerTest.this) {
      assertEquals(1, runCount);
    }
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());

    // --- Scenario B: de-dupe with runOnTickerAnyway=false, earlier replaces later ---
    // Arrange
    blocker = new BlockTickerJob();
    ticker.queueTimedJob(blocker, "Block the ticker", 0, true, false);
    blocker.waitForBlocking();
    runAt = System.currentTimeMillis();

    // Act (later then earlier => earlier replaces)
    ticker.queueTimedJobAbsolute(simpleRunnable, "De-dupe test", runAt + 1, false, true);
    ticker.queueTimedJobAbsolute(simpleRunnable, "De-dupe test", runAt, false, true);

    // Assert (still one queued time)
    assertEquals(1, ticker.queuedJobs());
    assertEquals(1, ticker.queuedJobsUniqueTimes());

    // Act (unblock and drain)
    blocker.unblockAndWait();
    ticker.waitForIdle();
    realExec.waitForIdle();

    // Assert
    assertEquals(0, ticker.queuedJobs());
    assertEquals(0, ticker.queuedJobsUniqueTimes());
    synchronized (PrioritizedTickerTest.this) {
      assertEquals(2, runCount);
    }
  }

  // --- Additional deterministic tests using Mockito for direct/edge behaviors ---

  @Mock private PriorityAwareExecutor mockExec;

  @Test
  @DisplayName(
      "queueTimedJob: negative offset runs immediately via executor (no runOnTickerAnyway)")
  void queueTimedJob_whenNegativeOffset_expectDirectExecutorCall() {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 1234);
    Runnable r = () -> {};

    t.queueTimedJob(r, -5);

    verify(mockExec, times(1)).execute(r, "Scheduled job: " + r);
    assertEquals(0, t.queuedJobs());
    assertEquals(0, t.queuedJobsUniqueTimes());
  }

  @Test
  @DisplayName("queueTimedJob: zero offset with runOnTickerAnyway queues (no direct execute)")
  void queueTimedJob_whenZeroOffsetRunOnTickerAnyway_expectQueued() {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 42);
    Runnable r = () -> {};

    t.queueTimedJob(r, "test", 0, true, false);

    verify(mockExec, never()).execute(any(Runnable.class), any(String.class));
    assertEquals(1, t.queuedJobs());
    assertEquals(1, t.queuedJobsUniqueTimes());
  }

  @Test
  @DisplayName("queueTimedJobAbsolute: past time runs immediately via executor")
  void queueTimedJobAbsolute_whenTimeInPast_expectDirectExecutorCall() {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 2000);
    Runnable r = () -> {};
    long past = System.currentTimeMillis() - 10;

    t.queueTimedJobAbsolute(r, "abs", past, false, false);

    verify(mockExec, times(1)).execute(r, "abs");
    assertEquals(0, t.queuedJobs());
  }

  @Test
  @DisplayName("noDupes: later requeue ignored; earlier requeue replaces")
  void queueTimedJobAbsolute_whenNoDupes_respectsEarliest() throws Exception {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 8888);
    Runnable r = () -> {};
    long now = System.currentTimeMillis();

    // First: queue at now + 1s
    t.queueTimedJobAbsolute(r, "n1", now + 1_000, false, true);
    assertEquals(1, t.queuedJobs());

    // Second (later): ignored
    t.queueTimedJobAbsolute(r, "n2", now + 1_500, false, true);
    assertEquals(1, t.queuedJobs());
    assertEquals(1, t.queuedJobsUniqueTimes());

    // Third (earlier): replaces
    t.queueTimedJobAbsolute(r, "n3", now - 1, false, true);
    assertEquals(1, t.queuedJobs());
    assertEquals(1, t.queuedJobsUniqueTimes());

    // Drive execution: the 'earlier' one is due now and should run via executor with
    // fromTicker=true
    invokeRealRun(t);
    verify(mockExec, times(1)).execute(r, "n3", true);
    assertEquals(0, t.queuedJobs());
  }

  @Test
  @DisplayName("realRun: FastRunnable runs inline and does not hit executor")
  void realRun_whenFastRunnable_runsInline() throws Exception {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 7);
    final boolean[] ran = {false};
    FastRunnable fr = () -> ran[0] = true;

    t.queueTimedJob(fr, "fast", 0, true, false);
    invokeRealRun(t);

    assertTrue(ran[0]);
    verify(mockExec, never()).execute(eq(fr), any(String.class), anyBoolean());
    assertEquals(0, t.queuedJobs());
  }

  @Test
  @DisplayName("executeJobs: FastRunnable Error does not drop subsequent jobs")
  void executeJobs_whenFastRunnableThrowsError_restContinue() throws Exception {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 13);
    synchronized (PrioritizedTickerTest.this) {
      runCount = 0;
    }

    FastRunnable err =
        () -> {
          throw new AssertionError("boom");
        };
    FastRunnable ok =
        () -> {
          synchronized (PrioritizedTickerTest.this) {
            runCount += 5;
          }
        };

    long trun = System.currentTimeMillis();
    t.queueTimedJobAbsolute(err, "err-fast", trun, true, false);
    t.queueTimedJobAbsolute(ok, "ok-fast", trun, true, false);

    invokeRealRun(t);

    synchronized (PrioritizedTickerTest.this) {
      assertEquals(5, runCount);
    }
    assertEquals(0, t.queuedJobs());
    assertEquals(0, t.queuedJobsUniqueTimes());
  }

  @Test
  @DisplayName("realRun: executor failure re-queues job with delay")
  void realRun_whenExecutorThrows_requeuesJob() throws Exception {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 9);
    Runnable r = () -> {};

    // Arrange queued job
    t.queueTimedJob(r, "boom", 0, true, false);

    // Make executor throw on run from ticker path
    org.mockito.Mockito.doThrow(new RuntimeException("fail"))
        .when(mockExec)
        .execute(r, "boom", true);

    // Act
    invokeRealRun(t);

    // Assert: one attempt + queued again (visible as one pending job)
    verify(mockExec, times(1)).execute(r, "boom", true);
    assertEquals(1, t.queuedJobs());
    assertTrue(t.queuedJobsUniqueTimes() >= 1);
  }

  @Test
  @DisplayName("realRun: executor Error re-queues job with delay")
  void realRun_whenExecutorThrowsError_requeuesJob() throws Exception {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 10);
    Runnable r = () -> {};

    // Arrange queued job
    t.queueTimedJob(r, "err", 0, true, false);

    // Make executor throw an Error on run from ticker path
    org.mockito.Mockito.doThrow(new AssertionError("boom")).when(mockExec).execute(r, "err", true);

    // Act
    invokeRealRun(t);

    // Assert: one attempt + queued again (visible as one pending job)
    verify(mockExec, times(1)).execute(r, "err", true);
    assertEquals(1, t.queuedJobs());
    assertTrue(t.queuedJobsUniqueTimes() >= 1);
  }

  @Test
  @DisplayName("removeQueuedJob: not queued is a no-op; null throws")
  void removeQueuedJob_whenNotPresentOrNull_behavesAsDocumented() {
    PrioritizedTicker t = new PrioritizedTicker(mockExec, 11);
    Runnable r = () -> {};

    assertDoesNotThrow(() -> t.removeQueuedJob(r));
    assertEquals(0, t.queuedJobs());
    assertThrows(NullPointerException.class, () -> t.removeQueuedJob(null));
  }

  private static void invokeRealRun(PrioritizedTicker t) throws Exception {
    var m = PrioritizedTicker.class.getDeclaredMethod("realRun");
    m.setAccessible(true);
    m.invoke(t);
  }
}
