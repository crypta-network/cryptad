package network.crypta.node.diagnostics.threads;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.node.NodeStats;
import network.crypta.node.diagnostics.ThreadDiagnostics;
import network.crypta.support.PooledExecutor;
import network.crypta.support.Ticker;

/**
 * Periodically samples JVM threads and produces lightweight diagnostics snapshots.
 *
 * <p>This implementation polls the JVM {@link ThreadMXBean} and internal executor metadata to
 * capture a point-in-time view of active threads. For worker threads managed by {@link
 * network.crypta.support.PooledExecutor.MyThread}, a stable <em>job id</em> is obtained so
 * successive samples can be correlated even when the underlying thread object is reused by the
 * pool. For non-pooled threads, the operating system thread id is used as the identifier.
 *
 * <p>The instance schedules itself at a fixed sampling interval using the provided {@link
 * network.crypta.support.Ticker}. Each execution computes per-thread CPU deltas since the previous
 * run and updates a {@link NodeThreadSnapshot} that can be retrieved at any time via {@link
 * #getThreadSnapshot()}. The snapshot is immutable from the caller’s perspective and is safe to
 * read concurrently.
 *
 * <ul>
 *   <li><strong>Responsibilities</strong>: schedule sampling, compute CPU deltas, expose snapshots.
 *   <li><strong>Thread-safety</strong>: reading the snapshot is lock-free; internal mutable state
 *       is confined to this sampler’s execution.
 *   <li><strong>Lifecycle</strong>: call {@link #start()} once to begin periodic sampling, and
 *       {@link #stop()} to cancel future runs.
 * </ul>
 */
public class DefaultThreadDiagnostics implements Runnable, ThreadDiagnostics {
  /**
   * Creates a diagnostics sampler with explicit scheduling name and interval.
   *
   * @param nodeStats the node statistics provider used to enumerate live JVM threads; never null
   *     and expected to return a stable snapshot for the duration of a single sampling pass
   * @param ticker the timing facility used to queue periodic executions; must invoke this runnable
   *     roughly every {@code monitorInterval} seconds and support cancellation
   * @param name the logical name under which the job is queued in the ticker so operators can
   *     identify it in logs or admin tooling
   * @param monitorInterval the sampling period in seconds; larger values reduce overhead but make
   *     computed CPU deltas less granular
   */
  public DefaultThreadDiagnostics(
      NodeStats nodeStats, Ticker ticker, String name, int monitorInterval) {
    this.nodeStats = nodeStats;
    this.ticker = ticker;
    this.name = name;
    this.monitorInterval = monitorInterval;
  }

  /**
   * Creates a diagnostics sampler that uses default naming and interval.
   *
   * <p>The job is queued under a default human-readable name and sampled every {@link
   * #DEFAULT_MONITOR_INTERVAL} milliseconds.
   *
   * @param nodeStats the node statistics provider used to enumerate live JVM threads; never null
   * @param ticker the timing facility used to schedule periodic executions; never null
   */
  public DefaultThreadDiagnostics(NodeStats nodeStats, Ticker ticker) {
    this(nodeStats, ticker, DEFAULT_MONITOR_THREAD_NAME, DEFAULT_MONITOR_INTERVAL);
  }

  /**
   * Returns the most recently computed snapshot of thread diagnostics.
   *
   * <p>The snapshot aggregates entries for the latest sampling interval and contains per-thread CPU
   * time deltas measured in nanoseconds along with descriptive fields such as name, priority, group
   * and state. The returned object is a stable view and does not change after this method returns.
   *
   * @return a new {@link NodeThreadSnapshot} instance representing the most recent sampling pass;
   *     may reference an empty list when sampling has not yet observed any eligible threads
   */
  @Override
  public NodeThreadSnapshot getThreadSnapshot() {
    return nodeThreadSnapshot.get();
  }

  /**
   * Starts periodic sampling by enqueueing the first run immediately.
   *
   * <p>This method is idempotent with respect to multiple invocations that occur before {@link
   * #stop()} is called; the ticker is asked to schedule this runnable, and subsequent runs will
   * re-queue themselves at the configured interval.
   */
  public void start() {
    scheduleNext(0);
  }

  /**
   * Cancels future sampling executions.
   *
   * <p>No in-flight run is interrupted. After this call returns, the ticker will no longer invoke
   * this runnable unless {@link #start()} is called again. The last computed snapshot remains
   * available via {@link #getThreadSnapshot()}.
   */
  public void stop() {
    ticker.removeQueuedJob(this);
  }

  /**
   * Performs a single sampling pass and updates the published snapshot.
   *
   * <p>This method fetches the current list of live threads from {@code nodeStats}, samples each
   * eligible thread to compute its recent CPU delta, and publishes a new {@link NodeThreadSnapshot}
   * to callers. It also purges bookkeeping for threads that have disappeared and finally schedules
   * the next execution based on the configured interval.
   */
  @Override
  public void run() {
    List<NodeThreadInfo> threads =
        Arrays.stream(nodeStats.getThreads())
            .filter(Objects::nonNull)
            .filter(thread -> thread.getThreadGroup() != null)
            .map(
                thread -> {
                  Sample s = sampleThread(thread);
                  if (s.jobId() == 0) return null; // skip workers with no job assigned yet
                  return new NodeThreadInfo(
                      thread.threadId(),
                      s.jobId(),
                      s.cpuDelta(),
                      s.name(),
                      thread.getPriority(),
                      thread.getThreadGroup().getName(),
                      thread.getState().toString());
                })
            .filter(Objects::nonNull)
            .toList();

    nodeThreadSnapshot.set(new NodeThreadSnapshot(threads, monitorInterval));

    purgeInactiveThreads(threads);
    scheduleNext();
  }

  /**
   * Schedule this class execution in seconds.
   *
   * @param interval Time internal in seconds.
   */
  private void scheduleNext(int interval) {
    ticker.queueTimedJob(this, name, interval, false, true);
  }

  private void scheduleNext() {
    scheduleNext(monitorInterval);
  }

  /**
   * Gets the job's ID from the thread (PooledExecutor.MyThread) or defaults to the thread's ID.
   *
   * @param thread the thread for which to resolve a stable job identifier; for pooled workers this
   *     is the current job id, otherwise the OS thread id
   * @return job id when the thread is a pooled worker with an assigned job; otherwise the thread id
   */
  private long getJobId(Thread thread) {
    long jobId = thread.threadId();
    if ((thread instanceof PooledExecutor.MyThread myThread)) {
      jobId = myThread.getJobId();
    }

    return jobId;
  }

  /**
   * Remove threads that aren't present in the last snapshot.
   *
   * @param threads List of active threads.
   */
  private void purgeInactiveThreads(List<NodeThreadInfo> threads) {
    List<Long> activeThreads =
        threads.stream()
            .map(NodeThreadInfo::getJobId) // job id might be the same as thread id
            .toList();

    threadSnapshot.keySet().removeIf(key -> !activeThreads.contains(key));
  }

  /**
   * Class holder for cpu and thread name at the moment of measurement. This is necessary as the
   * threads are pooled and may change name right after measurement.
   */
  private record ThreadSnapshot(long cpu, String name) {}

  /** Immutable sample of a single thread measurement. */
  private record Sample(long jobId, long cpuDelta, String name) {}

  /**
   * Takes an atomic sample of a thread's diagnostics, ensuring the job id and name are consistent.
   *
   * <p>For pooled workers this method queries {@link PooledExecutor.MyThread#diagSample()} to read
   * a coherent tuple of job id, thread name and CPU time. For other threads it falls back to the
   * JVM {@link ThreadMXBean} and the thread’s current name.
   */
  private Sample sampleThread(Thread thread) {
    long jobId;
    long current;
    String sampleName;
    if (thread instanceof PooledExecutor.MyThread my) {
      PooledExecutor.DiagSample ds = my.diagSample();
      sampleName = ds.name();
      current = ds.cpuTime();
      jobId = ds.jobId();
    } else {
      sampleName = thread.getName();
      current = threadMxBean.getThreadCpuTime(thread.threadId());
      jobId = getJobId(thread);
    }
    ThreadSnapshot prev = threadSnapshot.get(jobId);
    long delta = current - (prev != null ? prev.cpu() : 0);
    threadSnapshot.put(jobId, new ThreadSnapshot(current, sampleName));
    return new Sample(jobId, delta, sampleName);
  }

  /** Sleep interval to calculate % CPU used by each thread. */
  private static final int DEFAULT_MONITOR_INTERVAL = 1000;

  private static final String DEFAULT_MONITOR_THREAD_NAME = "NodeDiagnostics: thread monitor";
  private final String name;
  private final int monitorInterval;
  private final NodeStats nodeStats;
  private final Ticker ticker;

  /** Initialising with an empty NodeThreadSnapshot to avoid possible race conditions. */
  private final AtomicReference<NodeThreadSnapshot> nodeThreadSnapshot =
      new AtomicReference<>(new NodeThreadSnapshot(new ArrayList<>(), DEFAULT_MONITOR_INTERVAL));

  private final ThreadMXBean threadMxBean = ManagementFactory.getThreadMXBean();

  /** Map to track thread's CPU differences between intervals of time. */
  private final Map<Long, ThreadSnapshot> threadSnapshot = new HashMap<>();
}
