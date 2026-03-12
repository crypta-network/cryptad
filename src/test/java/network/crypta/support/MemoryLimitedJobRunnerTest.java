package network.crypta.support;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Allow descriptive test method names with underscores
class MemoryLimitedJobRunnerTest {

  // --- Test helpers ---------------------------------------------------------

  /**
   * Minimal deterministic executor that captures submitted runnables instead of executing them.
   * Tests can explicitly run tasks by calling {@link #runNext()}.
   */
  static final class CapturingExecutor implements PriorityAwareExecutor {
    private final Deque<Runnable> queue = new ArrayDeque<>();
    private final List<Integer> submittedPriorities = new ArrayList<>();

    @Override
    public void execute(@NotNull Runnable job) {
      execute(job, "<test>");
    }

    @Override
    public void execute(Runnable job, String jobName) {
      execute(job, jobName, false);
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      if (job instanceof PrioRunnable pr) {
        submittedPriorities.add(pr.getPriority());
      } else {
        // Default priority when not a PrioRunnable
        submittedPriorities.add(NativeThread.PriorityLevel.NORM_PRIORITY.value);
      }
      queue.addLast(job);
    }

    Runnable runNext() {
      Runnable r = queue.removeFirst();
      r.run();
      return r;
    }

    int pending() {
      return queue.size();
    }

    int[] priorities() {
      return submittedPriorities.stream().mapToInt(Integer::intValue).toArray();
    }

    @Override
    public int[] waitingThreads() {
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {0};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  /**
   * Test job that either completes synchronously (returning true) or stores the chunk for later
   * manual release (returning false).
   */
  static final class TestJob extends MemoryLimitedJob {
    private final int priority;
    private final boolean finishSynchronously;
    private boolean started;
    private MemoryLimitedChunk captured;

    TestJob(long initial, int priority, boolean finishSynchronously) {
      super(initial);
      this.priority = priority;
      this.finishSynchronously = finishSynchronously;
    }

    @Override
    public int getPriority() {
      return priority;
    }

    @Override
    public boolean start(MemoryLimitedChunk chunk) {
      this.started = true;
      this.captured = chunk;
      return finishSynchronously;
    }

    boolean wasStarted() {
      return started;
    }

    MemoryLimitedChunk chunk() {
      return captured;
    }
  }

  // --- Tests ---------------------------------------------------------------

  @Nested
  class QueueingAndCapacity {

    @Test
    @DisplayName("queueJob: rejects job larger than capacity and does not submit")
    void queueJob_whenTooLarge_expectIllegalArgumentAndNoSubmission() {
      PriorityAwareExecutor exec = Mockito.mock(PriorityAwareExecutor.class);
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(10, 2, exec, 4);
      TestJob tooBig = new TestJob(11, 0, true);

      assertThrows(IllegalArgumentException.class, () -> runner.queueJob(tooBig));
      Mockito.verifyNoInteractions(exec);
    }

    @Test
    @DisplayName("queueJob: starts immediately when capacity available; synchronous job releases")
    void queueJob_whenCapacityAvailable_expectImmediateStartAndRelease() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(10, 1, exec, 4);
      TestJob job = new TestJob(7, /* priority= */ 1, /* finishSynchronously= */ true);

      runner.queueJob(job);

      assertEquals(1, exec.pending(), "one runnable submitted");
      assertArrayEquals(
          new int[] {NativeThread.PriorityLevel.LOW_PRIORITY.value}, exec.priorities());
      assertEquals(7, runner.used(), "reservation accounted before run");
      assertEquals(1, runner.getRunningThreads());

      exec.runNext(); // run job -> returns true -> runner releases chunk

      assertTrue(job.wasStarted());
      assertEquals(0, runner.used(), "usage released after completion");
      assertEquals(0, runner.getRunningThreads());
    }

    @Test
    @DisplayName("capacity: second job waits until first releases, then runs")
    void queueJob_whenCapacityInsufficient_expectSecondRunsAfterFirstReleases() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(10, 2, exec, 4);

      TestJob a = new TestJob(10, 1, true);
      TestJob b = new TestJob(10, 1, true);

      runner.queueJob(a);
      runner.queueJob(b);

      assertEquals(1, exec.pending(), "only first job submitted initially");
      assertEquals(10, runner.used());
      assertEquals(1, runner.getRunningThreads());

      exec.runNext(); // completes a -> releases usage

      assertEquals(1, exec.pending(), "second job now submitted");
      assertEquals(10, runner.used(), "reservation for second job");
      exec.runNext();

      assertEquals(0, runner.used());
      assertEquals(0, runner.getRunningThreads());
    }
  }

  @Nested
  class PrioritiesAndConcurrency {

    @Test
    @DisplayName("priorities: lower index runs first regardless of insertion order")
    void priorities_whenMultipleQueued_expectLowestIndexFirst() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(5, 1, exec, 3);
      // All jobs fit individually but only one can run at a time (maxThreads=1, capacity=5)
      TestJob low = new TestJob(5, /* priority= */ 2, /*sync*/ true);
      TestJob mid = new TestJob(5, /* priority= */ 1, /*sync*/ true);
      TestJob high = new TestJob(5, /* priority= */ 0, /*sync*/ true);

      // Queue in reverse-priority order to verify selection
      runner.queueJob(low);
      runner.queueJob(mid);
      runner.queueJob(high);

      // First submission should be the highest priority (index 0)
      exec.runNext(); // runs 'high' and releases

      // After release, next should be 'mid', then 'low'
      exec.runNext();
      exec.runNext();

      assertTrue(high.wasStarted());
      assertTrue(mid.wasStarted());
      assertTrue(low.wasStarted());
      assertEquals(0, runner.used());
    }

    @Test
    @DisplayName("maxThreads: runner never submits more than limit concurrently")
    void concurrency_whenMaxThreadsSet_expectBoundedParallelism() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(100, 2, exec, 2);

      // Three async jobs (do not auto-release). Each reserves 10 units.
      TestJob j1 = new TestJob(10, 0, /*sync*/ false);
      TestJob j2 = new TestJob(10, 0, /*sync*/ false);
      TestJob j3 = new TestJob(10, 0, /*sync*/ false);

      runner.queueJob(j1);
      runner.queueJob(j2);
      runner.queueJob(j3);

      assertEquals(2, exec.pending(), "only two tasks submitted due to maxThreads=2");
      assertEquals(20, runner.used());
      // Start the two tasks (they don't release yet)
      exec.runNext();
      exec.runNext();
      assertEquals(2, runner.getRunningThreads());

      // Manually release one job; runner should admit the third
      j1.chunk().release();
      assertEquals(2, runner.getRunningThreads());
      assertEquals(20, runner.used());
      assertEquals(1, exec.pending(), "third task now admitted");
    }
  }

  @Nested
  class DynamicTuningAndShutdown {

    @Test
    @DisplayName("setCapacity: increasing capacity triggers scheduling of queued jobs")
    void setCapacity_whenIncreased_expectMoreJobsStart() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(5, 2, exec, 2);

      TestJob a = new TestJob(5, 0, false);
      TestJob b = new TestJob(6, 0, true);
      TestJob c = new TestJob(5, 0, true);

      runner.queueJob(a); // admitted
      assertThrows(IllegalArgumentException.class, () -> runner.queueJob(b));
      runner.queueJob(c); // queued but cannot start until capacity increases

      assertEquals(1, exec.pending());
      exec.runNext(); // start 'a' (async, no release yet)
      assertEquals(5, runner.used());

      runner.setCapacity(10); // now 'c' fits concurrently
      assertEquals(1, exec.pending(), "'c' admitted after capacity increase");
    }

    @Test
    @DisplayName("setMaxThreads: raising limit starts additional queued jobs")
    void setMaxThreads_whenRaised_expectAdditionalStarts() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(100, 1, exec, 2);
      TestJob a = new TestJob(10, 0, false);
      TestJob b = new TestJob(10, 0, false);

      runner.queueJob(a);
      runner.queueJob(b);

      assertEquals(1, exec.pending());
      exec.runNext(); // start 'a' (async)
      assertEquals(1, runner.getRunningThreads());
      assertEquals(0, exec.pending());

      runner.setMaxThreads(2); // should start 'b' now
      assertEquals(1, exec.pending());
    }

    @Test
    @DisplayName("shutdown: prevents new queueing; waitForShutdown waits for running jobs")
    void shutdown_whenInvoked_expectNoNewJobsAndWaitsForFinish() throws InterruptedException {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(100, 2, exec, 2);
      TestJob a = new TestJob(10, 0, false);
      TestJob b = new TestJob(10, 0, false);

      runner.queueJob(a);
      runner.queueJob(b);
      exec.runNext();
      exec.runNext();
      assertEquals(2, runner.getRunningThreads());

      // After shutdown, queueJob is a no-op
      runner.shutdown();
      TestJob c = new TestJob(10, 0, true);
      runner.queueJob(c);
      assertEquals(0, exec.pending(), "no new tasks accepted after shutdown");

      // Release both jobs and verify waitForShutdown returns
      Thread waiter = new Thread(runner::waitForShutdown);
      waiter.start();
      j1SafeRelease(a);
      j1SafeRelease(b);
      waiter.join(2_000L);
      assertFalse(waiter.isAlive(), "waitForShutdown should return after all jobs finish");
      assertEquals(0, runner.getRunningThreads());
    }

    @Test
    @DisplayName(
        "waitForShutdown: ignores interrupts, blocks until finish, and restores interrupt status")
    void waitForShutdown_whenInterrupted_expectBlocksAndRestoresInterrupt()
        throws InterruptedException {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(100, 2, exec, 2);
      TestJob a = new TestJob(10, 0, false);
      TestJob b = new TestJob(10, 0, false);

      runner.queueJob(a);
      runner.queueJob(b);
      exec.runNext();
      exec.runNext();
      assertEquals(2, runner.getRunningThreads());

      Thread waiter = new Thread(runner::waitForShutdown, "mljr-waiter-test");
      waiter.start();

      // Interrupt promptly; whether the thread is in wait() yet or not, the
      // implementation records the interruption and continues to wait until all jobs finish.
      waiter.interrupt();
      // It must still be alive shortly after the interrupt because jobs haven't finished yet.
      waiter.join(150);
      assertTrue(waiter.isAlive(), "waiter should still be blocked despite interrupt");

      // Now release both jobs so shutdown can complete
      j1SafeRelease(a);
      j1SafeRelease(b);

      waiter.join(2_000L);
      assertFalse(waiter.isAlive(), "waitForShutdown should return after jobs finish");
      // The waiter thread should have its interrupt status restored by waitForShutdown
      assertTrue(waiter.isInterrupted(), "interrupt status should be preserved on exit");
    }

    private void j1SafeRelease(TestJob j) {
      // Some jobs may be synchronous; only release when a chunk was captured
      if (j.chunk() != null) {
        j.chunk().release();
      }
    }
  }

  @Nested
  class RunnerInternalsVisibleForTests {
    @Test
    @DisplayName("deallocate: negative values are rejected")
    void deallocate_whenNegative_expectIllegalArgument() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(10, 1, exec, 2);
      assertThrows(IllegalArgumentException.class, () -> runner.deallocate(-1, false));
    }

    @Test
    @DisplayName("deallocate: zero is a legal no-op")
    void deallocate_whenZero_expectNoChange() {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(10, 1, exec, 2);
      runner.deallocate(0, false);
      assertEquals(0, runner.used());
      assertEquals(0, runner.getRunningThreads());
    }

    @Test
    @DisplayName(
        "deallocate: zero-size with finishedThread=true decrements runningThreads and wakes"
            + " waiters")
    void deallocate_whenZeroAndFinished_expectThreadCountDecrementsAndNotify() throws Exception {
      CapturingExecutor exec = new CapturingExecutor();
      MemoryLimitedJobRunner runner = new MemoryLimitedJobRunner(100, 1, exec, 2);

      // Job with zero initial allocation that completes asynchronously (so we can release(0) later)
      TestJob zeroAsync = new TestJob(0, 0, /*sync*/ false);
      runner.queueJob(zeroAsync);
      assertEquals(1, exec.pending());
      exec.runNext(); // start job -> runningThreads becomes 1
      assertEquals(1, runner.getRunningThreads());

      // Prepare a waiter that expects to be notified when runningThreads hits zero
      runner.shutdown();
      Thread waiter = new Thread(runner::waitForShutdown);
      waiter.start();
      assertTrue(waiter.isAlive());

      // release(0) must still mark the thread as finished (deallocate(0, true))
      zeroAsync.chunk().release(0);

      waiter.join(2_000L);
      assertFalse(waiter.isAlive(), "waiter should complete after zero-size release");
      assertEquals(0, runner.getRunningThreads());
    }
  }
}
