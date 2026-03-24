package network.crypta.support;

import java.io.IOException;
import java.util.concurrent.locks.LockSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Periodic keepalive thread for the Tanuki Java Service Wrapper.
 *
 * <p>Purpose: while a long-running, potentially blocking operation is in progress (for example,
 * disk preallocation), this thread periodically notifies the Wrapper that the application is still
 * starting by invoking {@link WrapperManager#signalStarting(int)} with a wait hint equal to the
 * keepalive interval plus a small margin. This prevents the Wrapper from timing out startup during
 * work that legitimately takes time.
 *
 * <p>Lifecycle: create an instance, call {@link #start()} before entering the blocking section, and
 * finally call {@link #close()} when the operation completes. This type implements {@link
 * AutoCloseable} so it can be used with try-with-resources; remember to call {@code start()} inside
 * the block:
 *
 * <pre>{@code
 * try (WrapperKeepalive wk = new WrapperKeepalive()) {
 *   wk.start();
 *   // perform long operation here
 * }
 * }</pre>
 *
 * <p>Threading: the instance owns its thread. {@link #close()} is thread-safe and may be invoked
 * from any thread. Closing requests termination; the loop exits after the current sleep interval or
 * sooner if the caller interrupts the thread. This class never interrupts itself.
 *
 * <p>Interrupts: if interrupted while sleeping, the thread logs at DEBUG level, clears the
 * interrupted status via {@link Thread#interrupted()}, and continues looping until closed.
 */
public class WrapperKeepalive extends Thread implements AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(WrapperKeepalive.class);
  private volatile boolean shutdown;
  private static final int INTERVAL = (int) MINUTES.toMillis(2);

  /**
   * Executes the keepalive loop.
   *
   * <p>Each iteration:
   *
   * <ol>
   *   <li>Calls {@link WrapperManager#signalStarting(int)} with a wait hint slightly larger than
   *       the sleep interval.
   *   <li>Sleeps for one interval using {@link LockSupport#parkNanos(long)} (no {@link
   *       InterruptedException}).
   *   <li>If interrupted, logs at DEBUG, clears the interrupted flag via {@link
   *       Thread#interrupted()}, and continues unless {@link #close()} has been called.
   * </ol>
   */
  @Override
  public void run() {
    while (!shutdown) {
      WrapperManager.signalStarting(INTERVAL + (int) SECONDS.toMillis(5));
      // Sleep without throwing InterruptedException; park returns early on interrupt.
      // The call to Thread.interrupted() below clears the flag.
      LockSupport.parkNanos(INTERVAL * 1_000_000L);
      if (Thread.interrupted()) {
        LOG.debug("Wrapper keepalive thread interrupted while sleeping; continuing until closed.");
        if (shutdown) break;
      }
    }
  }

  /**
   * Requests shutdown of this keepalive thread.
   *
   * <p>Sets an internal flag that causes {@link #run()} to exit on its next loop iteration. This
   * method does not interrupt the thread; callers may additionally invoke {@link #interrupt()} to
   * terminate the sleep promptly.
   *
   * <p>This method is idempotent and thread-safe.
   *
   * @throws IOException never thrown; present to satisfy {@link AutoCloseable}
   */
  @Override
  public void close() throws IOException {
    shutdown = true;
  }
}
