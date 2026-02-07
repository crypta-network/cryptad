package network.crypta.support.compress;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates a chain of decompression stages running on background threads.
 *
 * <p>Callers provide a {@link PipedInputStream} that yields the (possibly compressed) bytes and a
 * list of {@link Compressor} instances that can decompress them. When {@link #execute()} is
 * invoked, the manager wires each decompressor into a pipeline backed by {@link
 * PipedInputStream}/{@link PipedOutputStream} pairs and starts one thread per stage. The method
 * returns the final {@link PipedInputStream} from which callers can read the uncompressed bytes.
 *
 * <p>Threading and synchronization:
 *
 * <ul>
 *   <li>Public methods are {@code synchronized} to serialize state transitions and error delivery.
 *   <li>The last decompressor stage calls {@link #onFinish()} when it completes, which allows
 *       {@link #waitFinished()} to return. Any fatal error triggers {@link #onFailure(Throwable)}
 *       and wakes waiters.
 * </ul>
 *
 * <p>Error propagation:
 *
 * <ul>
 *   <li>{@link #execute()} and {@link #waitFinished()} throw {@link IOException} when a checked I/O
 *       failure occurs within the pipeline. Unchecked exceptions and {@link Error}s are rethrown
 *       unchanged.
 *   <li>{@link #getError()} exposes the first terminal failure, if any, without throwing.
 * </ul>
 *
 * <p>Ordering: decompressors are applied in reverse list order. The last element in the provided
 * list runs first; the first element runs last.
 *
 * <p>Usage contract: construct once per pipeline, call {@link #execute()} exactly once, consume the
 * returned stream, then call {@link #waitFinished()} to surface any late errors.
 *
 * @author sajack
 */
public class DecompressorThreadManager {
  private static final Logger LOG = LoggerFactory.getLogger(DecompressorThreadManager.class);

  final Queue<DecompressorThread> threads;
  PipedInputStream input;
  PipedOutputStream output = new PipedOutputStream();
  final long maxLen;
  private boolean finished = false;
  private Throwable error = null;

  /*
   * Rethrows {@link IOException} as-is and propagates unchecked failures without wrapping.
   * Any other checked exception type is wrapped into an {@link IOException}. This centralizes
   * the policy used by public methods so callers only need to handle IO-related failures.
   */
  private static void rethrowIoOrUnchecked(Throwable t) throws IOException {
    if (t instanceof IOException io) throw io;
    if (t instanceof RuntimeException re) throw re;
    if (t instanceof Error er) throw er;
    throw new IOException(t);
  }

  /**
   * Creates a new manager and prepares a decompression pipeline.
   *
   * <p>This constructor builds the chain by connecting a {@link PipedOutputStream} to a new {@link
   * PipedInputStream} for each decompressor stage. The chain is executed by {@link #execute()}.
   *
   * @param inputStream the head of the pipeline; bytes read from this stream are fed into the first
   *     decompressor
   * @param decompressors decompression stages to apply; the last element is applied first. The list
   *     is consumed from the end and therefore mutated; do not reuse it after the constructor
   *     returns.
   * @param maxLen upper bound on the number of uncompressed bytes expected; each stage receives
   *     {@code maxLen} and a best-effort output size estimate of {@code maxLen * 4}
   * @throws IOException if {@code inputStream} is {@code null} or a pipe cannot be created
   */
  public DecompressorThreadManager(
      PipedInputStream inputStream, List<? extends Compressor> decompressors, long maxLen)
      throws IOException {
    threads = new ArrayDeque<>(decompressors.size());
    this.maxLen = maxLen;
    if (inputStream == null) {
      IOException e = new IOException("Input stream may not be null");
      onFailure(e);
      throw e;
    }
    input = inputStream;
    while (!decompressors.isEmpty()) {
      Compressor compressor = decompressors.removeLast();
      if (LOG.isDebugEnabled()) LOG.debug("Decompressing with {}", compressor);
      // Wire current stage to previous output; each stage reads from the previous stage's pipe and
      // writes to a fresh pipe which becomes input for the next stage in the chain.
      DecompressorThread thread = new DecompressorThread(compressor, this, input, output, maxLen);
      threads.add(thread);
      input = new PipedInputStream(output);
      output = new PipedOutputStream();
    }
  }

  /**
   * Starts the decompression pipeline and returns the stream of uncompressed bytes.
   *
   * <p>For each configured stage, a thread is created and started. If the chain is empty, the
   * manager marks itself finished and returns the original input.
   *
   * @return the {@link PipedInputStream} from which uncompressed bytes are read
   * @throws IOException if a prior error was recorded, if creating the pipeline fails, or if a
   *     checked exception occurs during startup.
   */
  public synchronized PipedInputStream execute() throws IOException {
    if (error != null) rethrowIoOrUnchecked(error);
    if (threads.isEmpty()) {
      onFinish();
      return input;
    }
    try {
      int count = 0;
      while (!threads.isEmpty()) {
        Throwable currentError = getError();
        if (currentError != null) rethrowIoOrUnchecked(currentError);
        DecompressorThread threadRunnable = threads.remove();
        if (threads.isEmpty()) threadRunnable.setLast();
        Thread t = new Thread(threadRunnable, "DecompressorThread" + count);
        t.start();
        if (LOG.isDebugEnabled()) LOG.debug("Started decompressor thread {}", t);
        count++;
      }
      output.close();
    } catch (Exception e) {
      onFailure(e);
      rethrowIoOrUnchecked(e);
    } finally {
      IOUtils.closeQuietly(output);
    }
    return input;
  }

  /**
   * Records a terminal failure and wakes threads waiting for completion.
   *
   * @param t the error that caused termination; the first error wins and is exposed via {@link
   *     #getError()}
   */
  public synchronized void onFailure(Throwable t) {
    error = t;
    onFinish();
  }

  /** Marks the pipeline as finished and wakes any thread blocked in {@link #waitFinished()}. */
  public synchronized void onFinish() {
    finished = true;
    notifyAll();
  }

  /**
   * Blocks until all stages signal completion or a terminal error occurs.
   *
   * <p>Uses a bounded wait to avoid indefinite blocking under unexpected conditions. If the calling
   * thread is interrupted while waiting, the method restores the interrupt status and returns
   * early.
   *
   * @throws IOException if a checked I/O error caused the pipeline to fail. Unchecked failures are
   *     thrown on the worker thread; the first terminal error (checked or unchecked) is available
   *     via {@link #getError()}.
   */
  public synchronized void waitFinished() throws IOException {
    long start = System.currentTimeMillis();
    while (!finished) {
      try {
        // Intentionally use a bounded wait to avoid indefinite blocking in rare edge cases.
        // If a future change removes the timeout, ensure correctness under all failure modes.
        wait(MINUTES.toMillis(20));
        long time = System.currentTimeMillis() - start;
        if (time > MINUTES.toMillis(20) && LOG.isErrorEnabled()) {
          LOG.error("Still waiting for decompressor chain after {}", TimeUtil.formatTime(time));
        }
      } catch (InterruptedException _) {
        // Preserve interrupt status and exit loop. The final error propagation path below
        // remains reachable so callers still observe a stored failure if one occurred.
        Thread.currentThread().interrupt();
        break;
      }
    }
    if (error != null) rethrowIoOrUnchecked(error);
  }

  /**
   * Returns the first terminal failure that occurred during decompression, if any.
   *
   * <p>The returned value may be {@code null}. Callers that do not use {@link #waitFinished()} can
   * poll this method to detect failure.
   *
   * @return the first error raised by any stage, or {@code null} if none occurred
   */
  public synchronized Throwable getError() {
    return error;
  }

  /**
   * Runnable that applies a single {@link Compressor} to a stream.
   *
   * <p>Instances are created and managed by {@link DecompressorThreadManager}. When a stage is the
   * last in the chain it notifies the manager of completion.
   */
  static class DecompressorThread implements Runnable {

    /** The compressor whose decompress method will be invoked */
    final Compressor compressor;

    /** The stream compressed data will be read from */
    private final InputStream input;

    /** The stream decompressed data will be written */
    private final OutputStream output;

    /** An upper limit to how much data may be decompressed. This is passed to the decompressor */
    final long maxLen;

    /** The manager which created the thread */
    final DecompressorThreadManager manager;

    /** Whether this thread should signal the manager that decompression has finished */
    volatile boolean isLast = false;

    public DecompressorThread(
        Compressor compressor,
        DecompressorThreadManager manager,
        InputStream input,
        PipedOutputStream output,
        long maxLen) {
      this.compressor = compressor;
      this.input = input;
      this.output = output;
      this.maxLen = maxLen;
      this.manager = manager;
    }

    /** Runs the stage, reading from {@link #input} and writing to {@link #output}. */
    @Override
    public void run() {
      if (LOG.isDebugEnabled()) LOG.debug("Decompressing...");
      // Do not close the input stream from this side: when a stage fails early, closing the
      // upstream PipedInputStream would cause the writer's PipedOutputStream to throw
      // "Pipe closed" immediately. We close only our output to signal downstream termination.
      BufferedInputStream bufferedInput = new BufferedInputStream(input);
      try (BufferedOutputStream bufferedOutput = new BufferedOutputStream(output)) {
        /*
         * If another stage already failed, skip work and let the pipeline wind down. Otherwise,
         * invoke the compressor with the configured bounds. The estimated max output length is a
         * best-effort upper bound to help compressors guard against unbounded growth.
         */
        if (manager.getError() == null) {
          compressor.decompress(bufferedInput, bufferedOutput, maxLen, maxLen * 4);
          if (isLast) manager.onFinish();
        }
        if (LOG.isDebugEnabled()) LOG.debug("Finished decompressing...");
      } catch (Exception e) {
        manager.onFailure(e);
      }
    }

    /** Marks this stage as the last in the chain so it can notify the manager on completion. */
    public void setLast() {
      isLast = true;
    }
  }
}
