package network.crypta.node.diagnostics.threads;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.node.NodeStats;
import network.crypta.support.PooledExecutor;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming style
class DefaultThreadDiagnosticsTest {

  @Mock private NodeStats nodeStats;
  @Mock private Ticker ticker;

  @Captor private ArgumentCaptor<Runnable> runnableCaptor;

  @BeforeAll
  static void enableThreadCpuTimeIfSupported() {
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (bean.isThreadCpuTimeSupported() && !bean.isThreadCpuTimeEnabled()) {
      try {
        bean.setThreadCpuTimeEnabled(true);
      } catch (UnsupportedOperationException _) {
        // If the platform forbids enabling, tests still run asserting non-negative deltas where
        // possible.
      }
    }
  }

  @Test
  void start_whenCalled_schedulesImmediateRunWithDefaultName() {
    // Arrange
    DefaultThreadDiagnostics diag = new DefaultThreadDiagnostics(nodeStats, ticker);

    // Act
    diag.start();

    // Assert
    verify(ticker, times(1))
        .queueTimedJob(
            runnableCaptor.capture(),
            org.mockito.ArgumentMatchers.eq("NodeDiagnostics: thread monitor"),
            org.mockito.ArgumentMatchers.eq(0L),
            org.mockito.ArgumentMatchers.eq(false),
            org.mockito.ArgumentMatchers.eq(true));
    assertSame(
        runnableCaptor.getValue(), diag, "Ticker should be scheduled with the same instance");
  }

  @Test
  void stop_whenCalled_removesQueuedJob() {
    // Arrange
    DefaultThreadDiagnostics diag = new DefaultThreadDiagnostics(nodeStats, ticker);

    // Act
    diag.stop();

    // Assert
    verify(ticker, times(1)).removeQueuedJob(diag);
  }

  @Test
  void run_whenThreadsPresent_buildsSnapshotAndReschedules() {
    // Arrange
    Thread testThread = new Thread(() -> {});
    testThread.setName("TestThread-A");
    // Priority may be constrained by the JVM/security manager; rely on default
    when(nodeStats.getThreads()).thenReturn(new Thread[] {testThread, null});

    final String customName = "MyDiag";
    final int intervalMs = 321;
    DefaultThreadDiagnostics diag =
        new DefaultThreadDiagnostics(nodeStats, ticker, customName, intervalMs);

    // Act
    diag.run();

    // Assert snapshot content
    NodeThreadSnapshot snap = diag.getThreadSnapshot();
    assertNotNull(snap, "Snapshot must not be null");
    assertEquals(intervalMs, snap.getInterval(), "Snapshot interval should match monitor interval");
    assertEquals(1, snap.getThreads().size(), "Exactly one thread should be reported");

    NodeThreadInfo info = snap.getThreads().getFirst();
    assertEquals(testThread.threadId(), info.getId(), "Thread id should match");
    assertEquals(
        testThread.threadId(), info.getJobId(), "Non-pooled threads map jobId to thread id");
    assertEquals(testThread.getName(), info.getName(), "Name should be captured");
    assertEquals(testThread.getPriority(), info.getPrio(), "Priority should match");
    assertEquals(testThread.getThreadGroup().getName(), info.getGroupName(), "Group should match");
    assertEquals(testThread.getState().toString(), info.getState(), "State should match");
    assertTrue(info.getCpuTime() >= -1, "CPU delta should be non-negative or -1 if unsupported");

    // Assert reschedule with the specified interval
    verify(ticker, times(1))
        .queueTimedJob(
            org.mockito.ArgumentMatchers.same(diag),
            org.mockito.ArgumentMatchers.eq(customName),
            org.mockito.ArgumentMatchers.eq((long) intervalMs),
            org.mockito.ArgumentMatchers.eq(false),
            org.mockito.ArgumentMatchers.eq(true));
  }

  @Test
  void run_whenIdlePooledThread_filtersOutJobIdZero() throws Exception {
    // Arrange: create a pooled worker and capture its MyThread instance
    PooledExecutor exec = new PooledExecutor();
    CountDownLatch ran = new CountDownLatch(1);
    AtomicReference<PooledExecutor.MyThread> workerRef = new AtomicReference<>();

    exec.execute(
        () -> {
          Thread t = Thread.currentThread();
          if (t instanceof PooledExecutor.MyThread mt) {
            workerRef.set(mt);
          }
          ran.countDown();
        },
        "capture-worker");

    assertTrue(ran.await(5, TimeUnit.SECONDS), "Worker job should complete");
    PooledExecutor.MyThread worker = workerRef.get();
    assertNotNull(worker, "Should capture pooled worker instance");

    // Wait until the worker is idle (jobId becomes 0)
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
    while (System.nanoTime() < deadline && worker.getJobId() != 0) {
      Thread.onSpinWait();
    }
    assertEquals(0, worker.getJobId(), "Worker jobId should be 0 when idle");

    // Stub NodeStats to include the idle pooled thread and a null terminator
    when(nodeStats.getThreads()).thenReturn(new Thread[] {worker, null});

    DefaultThreadDiagnostics diag = new DefaultThreadDiagnostics(nodeStats, ticker, "X", 100);

    // Act
    diag.run();

    // Assert: filtered out -> no entries
    NodeThreadSnapshot snap = diag.getThreadSnapshot();
    assertNotNull(snap);
    assertTrue(snap.getThreads().isEmpty(), "Idle pooled thread must be filtered out (jobId=0)");

    // Also ensure we rescheduled
    verify(ticker, times(1))
        .queueTimedJob(
            org.mockito.ArgumentMatchers.same(diag),
            org.mockito.ArgumentMatchers.eq("X"),
            org.mockito.ArgumentMatchers.eq(100L),
            org.mockito.ArgumentMatchers.eq(false),
            org.mockito.ArgumentMatchers.eq(true));

    // Cleanup: there's no explicit shutdown; worker exits on its own after idle timeout
  }
}
