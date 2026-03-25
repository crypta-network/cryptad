package network.crypta.runtime.diagnostics;

import network.crypta.node.NodeStats;
import network.crypta.runtime.diagnostics.threads.NodeThreadInfo;
import network.crypta.runtime.diagnostics.threads.NodeThreadSnapshot;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DefaultNodeDiagnosticsTest {

  @Mock private NodeStats nodeStats;
  @Mock private Ticker ticker;

  @Captor private ArgumentCaptor<Runnable> runnableCaptor;
  @Captor private ArgumentCaptor<String> nameCaptor;
  @Captor private ArgumentCaptor<Long> offsetCaptor;
  @Captor private ArgumentCaptor<Boolean> runOnTickerCaptor;
  @Captor private ArgumentCaptor<Boolean> noDupesCaptor;

  private DefaultNodeDiagnostics diagnostics;

  @BeforeEach
  void setup() {
    diagnostics = new DefaultNodeDiagnostics(nodeStats, ticker);
  }

  @Test
  @DisplayName("getThreadDiagnostics returns a stable instance")
  void getThreadDiagnostics_idempotent_returnsSameInstance() {
    // Arrange & Act
    ThreadDiagnostics d1 = diagnostics.getThreadDiagnostics();
    ThreadDiagnostics d2 = diagnostics.getThreadDiagnostics();

    // Assert
    assertNotNull(d1, "ThreadDiagnostics must not be null");
    assertSame(d1, d2, "Expected getThreadDiagnostics() to be idempotent");
  }

  @Test
  @DisplayName("start schedules initial sampling with expected ticker parameters")
  void start_schedulesInitialSamplingWithExpectedTickerParams() {
    // Arrange
    ThreadDiagnostics td = diagnostics.getThreadDiagnostics();

    // Act
    diagnostics.start();

    // Assert: verify that the ticker queued the sampler immediately (offset 0)
    verify(ticker)
        .queueTimedJob(
            runnableCaptor.capture(),
            nameCaptor.capture(),
            offsetCaptor.capture(),
            runOnTickerCaptor.capture(),
            noDupesCaptor.capture());

    Runnable queued = runnableCaptor.getValue();
    assertSame(td, queued, "Ticker must be queued with the same diagnostics runnable instance");
    assertEquals("NodeDiagnostics: thread monitor", nameCaptor.getValue());
    assertEquals(0L, offsetCaptor.getValue());
    assertEquals(Boolean.FALSE, runOnTickerCaptor.getValue());
    assertEquals(Boolean.TRUE, noDupesCaptor.getValue());
  }

  @Test
  @DisplayName("run after start updates snapshot and reschedules next interval; stop cancels it")
  void run_afterStart_updatesSnapshotAndReschedules_thenStopCancels() {
    // Arrange
    ThreadDiagnostics td = diagnostics.getThreadDiagnostics();
    Thread current = Thread.currentThread();
    when(nodeStats.getThreads()).thenReturn(new Thread[] {current, null});

    // Act: start to schedule first run (offset 0)
    diagnostics.start();

    // Capture the scheduled runnable
    verify(ticker)
        .queueTimedJob(
            runnableCaptor.capture(),
            nameCaptor.capture(),
            offsetCaptor.capture(),
            runOnTickerCaptor.capture(),
            noDupesCaptor.capture());
    Runnable scheduled = runnableCaptor.getValue();

    // Act: execute a sampling pass; this should update the snapshot and schedule the next run
    scheduled.run();

    // Assert: snapshot contains the current thread and uses the expected interval (1000ms)
    NodeThreadSnapshot snap = td.getThreadSnapshot();
    assertNotNull(snap, "Snapshot must not be null after a run");
    // DefaultThreadDiagnostics.DEFAULT_MONITOR_INTERVAL = 1000
    assertEquals(1000, snap.getInterval());

    // Only our current thread was provided by NodeStats.getThreads()
    assertEquals(1, snap.getThreads().size());
    NodeThreadInfo info = snap.getThreads().getFirst();
    assertEquals(current.threadId(), info.getId());
    assertEquals(
        current.threadId(), info.getJobId(), "Non-pooled threads should use threadId as jobId");
    assertEquals(current.getName(), info.getName());
    assertEquals(current.getPriority(), info.getPrio());
    assertEquals(current.getThreadGroup().getName(), info.getGroupName());
    assertEquals(current.getState().toString(), info.getState());

    // Verify rescheduling with the same runnable and a 1000ms offset
    verify(ticker, times(2))
        .queueTimedJob(
            runnableCaptor.capture(),
            nameCaptor.capture(),
            offsetCaptor.capture(),
            runOnTickerCaptor.capture(),
            noDupesCaptor.capture());

    // The second invocation captures the reschedule
    assertSame(
        scheduled,
        runnableCaptor.getValue(),
        "Reschedule must refer to the same runnable instance");
    assertEquals("NodeDiagnostics: thread monitor", nameCaptor.getValue());
    assertEquals(1000L, offsetCaptor.getValue());
    assertEquals(Boolean.FALSE, runOnTickerCaptor.getValue());
    assertEquals(Boolean.TRUE, noDupesCaptor.getValue());

    // Act: stop should cancel the same runnable instance
    diagnostics.stop();
    verify(ticker).removeQueuedJob(scheduled);

    verifyNoMoreInteractions(ticker);
  }
}
