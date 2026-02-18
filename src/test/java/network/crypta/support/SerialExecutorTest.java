package network.crypta.support;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100") // test method names follow method_whenCondition_expectOutcome style
class SerialExecutorTest {

  private static void runRunnerOnDaemonThread(PriorityAwareExecutor mockExec) {
    doAnswer(
            invocation -> {
              Runnable r = invocation.getArgument(0);
              String n = invocation.getArgument(1);
              Thread t = new Thread(r, "SerialExecutorTest-" + n);
              t.setDaemon(true); // Don't block JVM exit; SerialExecutor waits up to 5 minutes idle
              t.start();
              return null;
            })
        .when(mockExec)
        .execute(any(Runnable.class), anyString());
  }

  private static boolean await(BooleanSupplier condition, Duration timeout) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) return true;
      Thread.onSpinWait();
    }
    return false;
  }

  @Test
  void start_whenNoJobs_doesNotStartRunner() {
    // Arrange
    int prio = NativeThread.PriorityLevel.NORM_PRIORITY.value;
    SerialExecutor exec = new SerialExecutor(prio);
    PriorityAwareExecutor real = mock(PriorityAwareExecutor.class);

    // Act
    exec.start(real, "nojobs");

    // Assert
    verify(real, never()).execute(any(Runnable.class), anyString());
    assertEquals(0, exec.getWaitingThreadsCount());
    int[] running = exec.runningThreads();
    int[] waiting = exec.waitingThreads();
    assertEquals(NativeThread.JAVA_PRIORITY_RANGE + 1, running.length);
    assertEquals(NativeThread.JAVA_PRIORITY_RANGE + 1, waiting.length);
    for (int v : running) assertEquals(0, v);
    for (int v : waiting) assertEquals(0, v);
    assertFalse(exec.onThread());
  }

  @Test
  void execute_afterStart_runsJobsInOrder_andIntrospectionReflectsState() throws Exception {
    // Arrange
    int prio = NativeThread.PriorityLevel.NORM_PRIORITY.value;
    SerialExecutor exec = new SerialExecutor(prio);
    PriorityAwareExecutor real = mock(PriorityAwareExecutor.class);
    runRunnerOnDaemonThread(real);
    CountDownLatch job1Started = new CountDownLatch(1);
    CountDownLatch allowJob1Finish = new CountDownLatch(1);
    CountDownLatch job2Done = new CountDownLatch(1);
    AtomicInteger seq = new AtomicInteger();
    AtomicBoolean onThreadJob1 = new AtomicBoolean(false);
    AtomicBoolean onThreadJob2 = new AtomicBoolean(false);

    Runnable job1 =
        () -> {
          job1Started.countDown();
          onThreadJob1.set(exec.onThread());
          try {
            if (!allowJob1Finish.await(2, TimeUnit.SECONDS)) {
              // Timed out: allow test to proceed; runner will block on next poll
              return;
            }
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
          }
          seq.compareAndSet(0, 1);
        };
    Runnable job2 =
        () -> {
          onThreadJob2.set(exec.onThread());
          seq.compareAndSet(1, 2);
          job2Done.countDown();
        };

    exec.start(real, "runner");

    // Act
    exec.execute(job1, "job1");
    exec.execute(job2, "job2");

    assertTrue(job1Started.await(1, TimeUnit.SECONDS));

    // While job1 is running the executor should report one running thread at our priority
    int[] running = exec.runningThreads();
    assertEquals(1, running[prio]);
    assertEquals(0, exec.getWaitingThreadsCount());
    assertFalse(exec.onThread());

    // Let job1 complete; runner will immediately pick job2
    allowJob1Finish.countDown();
    assertTrue(job2Done.await(2, TimeUnit.SECONDS));

    // Assert: order and onThread semantics
    assertEquals(2, seq.get());
    assertTrue(onThreadJob1.get());
    assertTrue(onThreadJob2.get());

    // Runner is now idle and should be waiting; observe within a short time window
    assertTrue(
        await(() -> exec.getWaitingThreadsCount() == 1, Duration.ofSeconds(1)),
        "runner did not enter waiting state");
    int[] waiting = exec.waitingThreads();
    assertEquals(1, waiting[prio]);

    // The underlying executor was asked to start exactly once
    verify(real, times(1)).execute(any(Runnable.class), eq("runner"));
  }

  @Test
  void execute3Arg_whenCalled_runsJob() throws Exception {
    // Arrange
    int prio = NativeThread.PriorityLevel.NORM_PRIORITY.value;
    SerialExecutor exec = new SerialExecutor(prio);
    PriorityAwareExecutor real = mock(PriorityAwareExecutor.class);
    runRunnerOnDaemonThread(real);
    CountDownLatch ran = new CountDownLatch(1);

    exec.start(real, "three-arg");

    // Act
    exec.execute(ran::countDown, "via-3-arg", true);

    // Assert
    assertTrue(ran.await(1, TimeUnit.SECONDS));
    verify(real, times(1)).execute(any(Runnable.class), eq("three-arg"));
  }

  @Test
  void execute_whenRealExecutorNotStarted_jobsStayQueuedUntilStart() throws Exception {
    // Arrange
    SerialExecutor exec = new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
    CountDownLatch ran = new CountDownLatch(1);

    // Act: queue a job before start(); it must not run yet
    exec.execute(ran::countDown);

    // Assert: still not executed
    assertFalse(ran.await(100, TimeUnit.MILLISECONDS));

    // Now start with a mock that runs the runner
    PriorityAwareExecutor real = mock(PriorityAwareExecutor.class);
    runRunnerOnDaemonThread(real);
    exec.start(real, "late-start");

    assertTrue(ran.await(1, TimeUnit.SECONDS));
  }

  @Test
  void boundedQueue_whenOverflow_dropsExtraJobs() throws Exception {
    // Arrange
    int prio = NativeThread.PriorityLevel.NORM_PRIORITY.value;
    SerialExecutor exec = new SerialExecutor(prio, /*bound*/ 1);
    PriorityAwareExecutor real = mock(PriorityAwareExecutor.class);
    runRunnerOnDaemonThread(real);
    CountDownLatch job1Done = new CountDownLatch(1);
    CountDownLatch job2Done = new CountDownLatch(1);
    AtomicInteger ranCount = new AtomicInteger();

    Runnable job1 =
        () -> {
          ranCount.incrementAndGet();
          job1Done.countDown();
        };
    Runnable job2 =
        () -> {
          ranCount.incrementAndGet();
          job2Done.countDown();
        };

    // Fill to capacity before starting; the second offer() should be dropped silently
    exec.execute(job1, "first");
    exec.execute(job2, "second-overflow");

    // Act
    exec.start(real, "bounded");

    // Assert
    assertTrue(job1Done.await(1, TimeUnit.SECONDS));
    assertFalse(job2Done.await(200, TimeUnit.MILLISECONDS), "overflow job should not run");
    assertEquals(1, ranCount.get());
  }

  @Test
  void jobThrows_whenNextJobQueued_runnerKeepsProcessing() throws Exception {
    // Arrange
    int prio = NativeThread.PriorityLevel.NORM_PRIORITY.value;
    SerialExecutor exec = new SerialExecutor(prio);
    PriorityAwareExecutor real = mock(PriorityAwareExecutor.class);
    runRunnerOnDaemonThread(real);
    CountDownLatch secondRan = new CountDownLatch(1);

    exec.start(real, "errors");

    // Act: first job throws; second must still run
    exec.execute(
        () -> {
          throw new IllegalStateException("boom");
        },
        "boom");
    exec.execute(secondRan::countDown, "after-boom");

    // Assert
    assertTrue(secondRan.await(1, TimeUnit.SECONDS));
    int[] running = exec.runningThreads();
    assertNotNull(running);
  }
}
