package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import network.crypta.node.NodeStats;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

// Mockito extension is not required; tests create mocks programmatically.
@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome style
class PrioritizedSerialExecutorTest {
  @BeforeEach
  void setUp() {
    realExec = new PooledExecutor();
    completedJobs = new ArrayList<>();
    completingJob = new SynchronousQueue<>();
    onThreadFlags = new LinkedBlockingQueue<>();
    awaitFlags = new LinkedBlockingQueue<>();
    exec =
        new PrioritizedSerialExecutor(NativeThread.PriorityLevel.MAX_PRIORITY.value, 10, 5, true);
  }

  @Test
  @DisplayName("execute_whenQueuedBeforeStart_doesNotRunUntilStart")
  void execute_whenQueuedBeforeStart_doesNotRunUntilStart() {
    // Arrange
    Q("J1", 0);
    Q("J2", 0);
    Q("J3", 0);
    Q("J4", 0);

    // Act (no start yet) — nothing to do

    // Assert
    assertTrue(completedJobs.isEmpty());
  }

  @Test
  @DisplayName("start_whenQueued_runsAllAtSamePriority")
  void start_whenQueued_runsAllAtSamePriority() throws InterruptedException {
    // Arrange
    Q("J1", 0);
    Q("J2", 0);
    Q("J3", 0);
    Q("J4", 0);

    // Act
    exec.start(realExec, "start-queued");
    waitFor(4);

    // Assert
    assertTrue(completedJobs.containsAll(Arrays.asList("J1", "J2", "J3", "J4")));
    assertFalse(exec.onThread());
    for (int i = 0; i < 4; i++) {
      Boolean b = onThreadFlags.poll(2, TimeUnit.SECONDS);
      assertEquals(Boolean.TRUE, b);
    }
  }

  @Test
  @DisplayName("execute_whenMixedPriorities_invertOrderTrue_respectsPriorityAndFifo")
  void execute_whenMixedPriorities_invertOrderTrue_respectsPriorityAndFifo()
      throws InterruptedException {
    // Arrange
    Q("JM", 9);
    Q("J8", 8);

    // Act
    exec.start(realExec, "prio-order");
    waitFor(1); // JM finishes first

    Q("J2", 2);
    Q("JN", 4);
    Q("JO", 2);
    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    QB(started, release); // ensure JP is running before adding JQ

    waitFor(2); // J8, JN

    // Wait until JP is definitely started so JQ will come after it
    assertTrue(started.await(1, TimeUnit.SECONDS));
    Q("JQ", 4);
    Q("JR", 0);

    // Allow JP to finish so JQ is selected next (higher priority than remaining jobs)
    release.countDown();

    waitFor(5); // JP, JQ, J2, JO, JR

    // Assert (single group: final execution order)
    List<String> expected = Arrays.asList("JM", "J8", "JN", "JP", "JQ", "J2", "JO", "JR");
    assertEquals(expected, completedJobs);
    for (int i = 0; i < 8; i++) {
      Boolean b = onThreadFlags.poll(2, TimeUnit.SECONDS);
      assertEquals(Boolean.TRUE, b);
    }
    // Await inside BlockingJ returned true
    Boolean awaited = awaitFlags.poll(2, TimeUnit.SECONDS);
    assertEquals(Boolean.TRUE, awaited);
  }

  private void Q(String j, int i) {
    exec.execute(new J(j, i), j);
  }

  private void waitFor(int count) throws InterruptedException {
    int completed = 0;
    while (completed < count) {
      String s = completingJob.poll(5, TimeUnit.SECONDS);
      if (s == null) {
        fail("Hang?");
      }

      completed++;
      completedJobs.add(s);
    }
    // no-op
  }

  private class J implements PrioRunnable {
    J(String name, int prio) {
      this.name = name;
      this.prio = prio;
    }

    @Override
    public int getPriority() {
      return prio;
    }

    @Override
    public void run() {
      try {
        onThreadFlags.put(exec.onThread());
        completingJob.put(name);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
    }

    private final int prio;
    private final String name;
  }

  // Queue a blocking job (fixed name/prio) that completes only when the provided latch is released.
  private void QB(CountDownLatch started, CountDownLatch release) {
    String name = "JP";
    int prio = 3;
    exec.execute(new BlockingJ(name, prio, started, release), name);
  }

  private class BlockingJ implements PrioRunnable {
    private final String name;
    private final int prio;
    private final CountDownLatch started;
    private final CountDownLatch release;

    BlockingJ(String name, int prio, CountDownLatch started, CountDownLatch release) {
      this.name = name;
      this.prio = prio;
      this.started = started;
      this.release = release;
    }

    @Override
    public int getPriority() {
      return prio;
    }

    @Override
    public void run() {
      try {
        onThreadFlags.put(exec.onThread());
        if (started != null) started.countDown();
        // Wait up to 1s for release to avoid hangs in case of failures.
        boolean ok = release.await(1, TimeUnit.SECONDS);
        awaitFlags.put(ok);
        completingJob.put(name);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private PriorityAwareExecutor realExec;
  private PrioritizedSerialExecutor exec;
  private SynchronousQueue<String> completingJob;
  private List<String> completedJobs;
  private LinkedBlockingQueue<Boolean> onThreadFlags;
  private LinkedBlockingQueue<Boolean> awaitFlags;

  // ---------------- Additional comprehensive tests ----------------

  @Test
  @DisplayName("start_whenQueueEmpty_doesNotSpawnUntilJobQueued")
  void start_whenQueueEmpty_doesNotSpawnUntilJobQueued() throws Exception {
    CountDownLatch ran = new CountDownLatch(1);
    List<Thread> started = Collections.synchronizedList(new ArrayList<>());
    PriorityAwareExecutor mockExec = mock(PriorityAwareExecutor.class);
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              String nm = inv.getArgument(1);
              Thread t = new Thread(r, nm);
              started.add(t);
              t.start();
              return null;
            })
        .when(mockExec)
        .execute(any(Runnable.class), any(String.class));

    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(
            NativeThread.PriorityLevel.NORM_PRIORITY.value,
            3,
            1,
            false,
            /*jobTimeout*/ 50,
            /*callback*/ null,
            /*stats*/ null);

    // No queued work yet — start should NOT run the runner.
    e.start(mockExec, "runner-empty");
    verify(mockExec, times(0)).execute(any(Runnable.class), any(String.class));

    // Now queue a job — this should trigger a single start and run the job.
    e.execute(ran::countDown, 1, "job1");

    assertTrue(ran.await(2, TimeUnit.SECONDS));
    verify(mockExec, times(1)).execute(any(Runnable.class), eq("runner-empty"));

    // Join the runner thread to avoid leaks.
    for (Thread t : started) {
      t.join(1000);
    }
  }

  @Test
  @DisplayName("executeNoDupes_whenSameInstanceQueuedTwice_expectSingleEntry")
  void executeNoDupes_whenSameInstanceQueuedTwice_expectSingleEntry() {
    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(
            NativeThread.PriorityLevel.NORM_PRIORITY.value, 3, 1, false, 100, null, null);

    Runnable r = () -> {};
    e.executeNoDupes(r, /*prio*/ 2, "r1");
    e.executeNoDupes(r, /*prio*/ 2, "r1-dup");

    assertEquals(1, e.getQueueSize(2));
    Runnable[][] snapshot = e.getQueuedJobsByPriority();
    assertEquals(r, snapshot[2][0]);
  }

  @Test
  @DisplayName("getQueuedJobsByPriority_whenMultipleQueued_expectFifoSnapshot")
  void getQueuedJobsByPriority_whenMultipleQueued_expectFifoSnapshot() {
    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(
            NativeThread.PriorityLevel.NORM_PRIORITY.value, 3, 1, false, 100, null, null);

    Runnable a = () -> {};
    Runnable b = () -> {};
    Runnable c = () -> {};

    e.execute(a, /*prio*/ 0, "a");
    e.execute(b, /*prio*/ 0, "b");
    e.execute(c, /*prio*/ 1, "c");

    Runnable[][] snapshot = e.getQueuedJobsByPriority();
    assertEquals(2, snapshot[0].length);
    assertEquals(a, snapshot[0][0]);
    assertEquals(b, snapshot[0][1]);
    assertEquals(1, snapshot[1].length);
    assertEquals(c, snapshot[1][0]);
  }

  @Test
  @DisplayName("execute_whenInvertOrderFalse_lowestPriorityIndexRunsFirst")
  void execute_whenInvertOrderFalse_lowestPriorityIndexRunsFirst() throws Exception {
    LinkedBlockingQueue<String> order = new LinkedBlockingQueue<>();
    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(
            /*runner prio*/ NativeThread.PriorityLevel.NORM_PRIORITY.value,
            /*internal*/ 3,
            /*default*/ 1,
            /*invertOrder*/ false,
            /*timeout*/ 100,
            /*callback*/ null,
            /*stats*/ null);

    e.execute(() -> order.add("p2"), /*prio*/ 2, "p2");
    e.execute(() -> order.add("p0"), /*prio*/ 0, "p0");

    e.start(new PooledExecutor(), "ordering");

    String first = order.poll(5, TimeUnit.SECONDS);
    String second = order.poll(5, TimeUnit.SECONDS);
    assertEquals("p0", first);
    assertEquals("p2", second);
  }

  @Test
  @DisplayName("runningAndWaitingThreads_whenJobActiveThenIdle_expectCounts")
  void runningAndWaitingThreads_whenJobActiveThenIdle_expectCounts() throws Exception {
    // Use runner priority within [0..9] to match internal indexing
    int runnerPrio = NativeThread.PriorityLevel.NORM_PRIORITY.value; // 5
    CountDownLatch jobStarted = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicBoolean jobAwaited = new AtomicBoolean(false);
    List<Thread> threads = new ArrayList<>();

    PriorityAwareExecutor mockExec = mock(PriorityAwareExecutor.class);
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              Thread t = new Thread(r, inv.getArgument(1));
              threads.add(t);
              t.start();
              return null;
            })
        .when(mockExec)
        .execute(any(Runnable.class), any(String.class));

    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(runnerPrio, 3, 1, false, /*timeout*/ 200, null, null);

    e.start(mockExec, "run-wait");

    e.execute(
        () -> {
          jobStarted.countDown();
          try {
            boolean ok = release.await(1, TimeUnit.SECONDS);
            jobAwaited.set(ok);
          } catch (InterruptedException _) {
            // Preserve interrupt status so the test runner can react if needed.
            Thread.currentThread().interrupt();
          }
        },
        1,
        "blockingJob");

    assertTrue(jobStarted.await(2, TimeUnit.SECONDS));

    int[] running = e.runningThreads();
    int[] waiting = e.waitingThreads();
    assertEquals(1, running[runnerPrio]);
    assertEquals(0, waiting[runnerPrio]);
    assertEquals(0, e.getWaitingThreadsCount());

    // Let the job finish; the runner should become briefly waiting until timeout triggers exit.
    release.countDown();

    long deadline = System.nanoTime() + Duration.ofSeconds(1).toNanos();
    boolean sawWaiting = false;
    while (System.nanoTime() < deadline) {
      int[] w = e.waitingThreads();
      if (w[runnerPrio] == 1) {
        sawWaiting = true;
        break;
      }
      LockSupport.parkNanos(1_000_000L);
    }
    assertTrue(sawWaiting);

    for (Thread t : threads) {
      t.join(1000);
    }
    assertTrue(jobAwaited.get());
  }

  @Test
  @DisplayName("statistics_whenJobRuns_reportsExecutionTimeWithJobString")
  void statistics_whenJobRuns_reportsExecutionTimeWithJobString() throws Exception {
    NodeStats stats = mock(NodeStats.class);
    AtomicBoolean ran = new AtomicBoolean(false);
    List<Thread> threads = new ArrayList<>();
    PriorityAwareExecutor mockExec = mock(PriorityAwareExecutor.class);
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              Thread t = new Thread(r, inv.getArgument(1));
              threads.add(t);
              t.start();
              return null;
            })
        .when(mockExec)
        .execute(any(Runnable.class), any(String.class));

    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(
            NativeThread.PriorityLevel.NORM_PRIORITY.value, 3, 1, false, 50, null, stats);

    Runnable r =
        new Runnable() {
          @Override
          public void run() {
            // No sleep: we only verify that the hook is called with some duration.
            ran.set(true);
          }

          @Override
          public String toString() {
            return "TestJob";
          }
        };

    e.start(mockExec, "stats");
    e.execute(r, 1, "j");

    long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
    while (!ran.get() && System.nanoTime() < deadline) {
      LockSupport.parkNanos(1_000_000L);
    }
    assertTrue(ran.get());

    verify(stats, times(1)).reportDatabaseJob(eq("TestJob"), anyLong());
    for (Thread t : threads) t.join(1000);
  }

  @Test
  @DisplayName("idleCallback_whenNoWork_enqueuesJobAndCalledOnce")
  void idleCallback_whenNoWork_enqueuesJobAndCalledOnce() throws Exception {
    LinkedBlockingQueue<String> order = new LinkedBlockingQueue<>();
    List<Thread> threads = new ArrayList<>();
    PriorityAwareExecutor mockExec = mock(PriorityAwareExecutor.class);
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              Thread t = new Thread(r, inv.getArgument(1));
              threads.add(t);
              t.start();
              return null;
            })
        .when(mockExec)
        .execute(any(Runnable.class), any(String.class));

    AtomicReference<PrioritizedSerialExecutor> ref = new AtomicReference<>();
    PrioritizedSerialExecutorIdleCallback cb =
        () -> ref.get().execute(() -> order.add("J2"), 1, "J2");

    PrioritizedSerialExecutor e =
        new PrioritizedSerialExecutor(
            NativeThread.PriorityLevel.NORM_PRIORITY.value, 3, 1, false, /*timeout*/ 30, cb, null);
    ref.set(e);

    e.start(mockExec, "idle");
    // Seed one job so the runner starts and then idles.
    e.execute(() -> order.add("J1"), 1, "J1");

    String a = order.poll(2, TimeUnit.SECONDS);
    String b = order.poll(2, TimeUnit.SECONDS);
    assertEquals("J1", a);
    assertEquals("J2", b);

    // Callback should be called only once per idle episode — indirectly verified by exactly two
    // jobs.
    for (Thread t : threads) t.join(1000);
  }
}
