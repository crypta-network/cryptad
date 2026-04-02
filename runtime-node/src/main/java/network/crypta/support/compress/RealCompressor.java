package network.crypta.support.compress;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.fs.AppEnv;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executes {@link CompressJob} instances on background threads at low native priority.
 *
 * <p>Purpose: offload CPU-heavy compression from request orchestration, keeping the node responsive
 * while work proceeds asynchronously. Jobs are executed as {@link PrioRunnable}s so the {@link
 * NativeThread} scheduler can lower their native priority.
 *
 * <p>Error handling: if {@link CompressJob#tryCompress(ClientContext)} throws an {@link
 * InsertException}, the same instance is forwarded to {@link CompressJob#onFailure(InsertException,
 * network.crypta.client.async.ClientPutState, ClientContext)}. Any other failure (including {@link
 * Error}) is logged and wrapped in an {@link InsertExceptionMode#INTERNAL_ERROR} before being
 * passed to {@code onFailure} so callers are not left waiting.
 *
 * <p>Threading: this class internally owns a fixed-size {@link ExecutorService}. The {@link
 * ClientContext} reference is stored in an {@link java.util.concurrent.atomic.AtomicReference}; the
 * worker snapshots the current value at the start of each job. Ordering between distinct jobs is
 * not guaranteed.
 *
 * <p>Shutdown semantics: {@link #shutdown()} requests an orderly shutdown and does not wait for
 * termination; callers should await termination if needed.
 */
public class RealCompressor {
  private static final Logger LOG = LoggerFactory.getLogger(RealCompressor.class);

  private final ExecutorService executorService;
  private final AtomicReference<ClientContext> context = new AtomicReference<>();

  /**
   * Creates a compressor backed by a fixed-size worker pool.
   *
   * <p>The pool size is derived from {@link #getMaxRunningCompressionThreads()} and worker threads
   * are created by {@link CompressorThreadFactory} so they run at minimal native priority. Threads
   * are created lazily when the first job is submitted.
   */
  public RealCompressor() {
    this.executorService =
        Executors.newFixedThreadPool(
            getMaxRunningCompressionThreads(), new CompressorThreadFactory());
  }

  /**
   * Sets the {@link ClientContext} to be supplied to subsequently executed jobs.
   *
   * <p>Thread safety: the reference is updated atomically. Jobs snapshot the reference at start, so
   * changes made concurrently are not reflected mid-execution.
   *
   * @param context execution context; may be {@code null}
   */
  public void setClientContext(ClientContext context) {
    this.context.set(context);
  }

  /**
   * Enqueues the given job for asynchronous execution.
   *
   * <p>Errors are handled on the worker thread as described in the class documentation. Submission
   * retries on {@link RejectedExecutionException} until the executor is shut down. With the default
   * fixed thread pool, rejection typically occurs only during shutdown.
   *
   * @param j job to execute; must not be {@code null}
   */
  public void enqueueNewJob(final CompressJob j) {
    if (LOG.isDebugEnabled()) LOG.debug("Enqueueing compression job: {}", j);

    Future<String> task = null;
    while (!executorService.isShutdown() && task == null) {
      try {
        task = executorService.submit(createRunnable(j), "Compressor thread for " + j);
        if (LOG.isDebugEnabled()) LOG.debug("Compression job enqueued: {}", j);
      } catch (RejectedExecutionException e) {
        LOG.error("RejectedExecutionException for {}", j, e);
        task = null;
      }
    }
  }

  private PrioRunnable createRunnable(final CompressJob j) {
    return new PrioRunnable() {
      @Override
      public void run() {
        runJob(j);
      }

      @Override
      public int getPriority() {
        return NativeThread.PriorityLevel.MIN_PRIORITY.value;
      }
    };
  }

  /**
   * Executes a single job with outer error containment.
   *
   * <p>We intentionally catch {@link Throwable} to preserve historical semantics and ensure callers
   * receive {@code onFailure} notifications even on severe errors. See inline comments.
   */
  @SuppressWarnings("java:S1181") // Intentionally catch Throwable to preserve failure semantics
  private void runJob(CompressJob j) {
    try {
      doCompressHandling(j);
    } catch (Throwable t) { // NOSONAR: preserve legacy behavior; see method javadoc
      LOG.error("Caught {} in {}", t, this, t);
    }
  }

  /**
   * Runs the job and translates failures to {@code onFailure}.
   *
   * <p>We intentionally catch {@link Throwable} to convert all failures, including {@link Error},
   * into INTERNAL_ERROR notifications so the caller is not left waiting indefinitely.
   */
  @SuppressWarnings("java:S1181") // Intentionally catch Throwable to preserve failure semantics
  private void doCompressHandling(CompressJob j) {
    final ClientContext ctx = context.get();
    try {
      j.tryCompress(ctx);
    } catch (InsertException e) {
      j.onFailure(e, null, ctx);
    } catch (Throwable t) { // NOSONAR: convert all throwables to INTERNAL_ERROR
      LOG.error("Caught in OffThreadCompressor: {}", t, t);
      // Convert to INTERNAL_ERROR so job owners receive a terminal signal.
      j.onFailure(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null), null, ctx);
    }
  }

  /**
   * Determines the maximum number of concurrent compression threads.
   *
   * <p>Heuristic: on macOS or when native thread prioritization is unavailable, returns {@code 1}.
   * Otherwise, caps concurrency by the number of available processors and roughly one thread per
   * 128&nbsp;MiB of max heap.
   *
   * @return number of worker threads (at least {@code 1})
   */
  private static int getMaxRunningCompressionThreads() {
    int maxRunningThreads;

    AppEnv env = new AppEnv();
    if (env.isMac() || !NativeThread.usingNativeCode())
      // On macOS, niceness is weak; keep background load minimal. Also, when native prioritization
      // is unusable on non-Windows, prefer a single worker to avoid interference.
      maxRunningThreads = 1;
    else {
      // Other OSes typically honor niceness well; bound by CPUs and available memory.
      Runtime r = Runtime.getRuntime();
      // Note: availableProcessors() can vary on some virtualized environments.
      int max = r.availableProcessors();
      long maxMemory = r.maxMemory();
      if (maxMemory < 128 * 1024 * 1024) max = 1;
      else
        // one compressor thread per (128MB of ram + available core)
        max = Math.min(max, (int) Math.min(Integer.MAX_VALUE, maxMemory / (128 * 1024 * 1024)));
      maxRunningThreads = max;
    }
    LOG.debug("Maximum Compressor threads: {}", maxRunningThreads);
    return maxRunningThreads;
  }

  /**
   * Initiates an orderly shutdown of the worker pool.
   *
   * <p>Does not block. In-flight jobs continue unless rejected by concurrent shutdown. Callers that
   * require a graceful termination should await termination on the underlying executor.
   */
  public void shutdown() {
    // Intentionally does not await termination; callers manage lifecycle if needed.
    this.executorService.shutdown();
  }

  /**
   * Thread factory that creates {@link NativeThread}-backed workers at minimal priority.
   *
   * <p>Threads are named {@code "Compressor thread"} and report {@link
   * NativeThread.PriorityLevel#MIN_PRIORITY} via {@link PrioRunnable#getPriority()}.
   */
  public static class CompressorThreadFactory implements ThreadFactory {
    @Override
    public Thread newThread(@NotNull Runnable r) {
      return new NativeThread(
          r, "Compressor thread", NativeThread.PriorityLevel.MIN_PRIORITY.value, true);
    }
  }
}
