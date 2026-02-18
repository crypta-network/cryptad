package network.crypta.node;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Periodically persists throttle state provided by a {@link Persistable} to disk.
 *
 * <p>This helper writes the current throttling configuration to a temporary file and then moves it
 * to the target path. It schedules itself at a fixed interval and also registers a shutdown hook to
 * persist one last snapshot on JVM exit. Errors during persistence are logged; the next run is
 * still queued.
 *
 * <p>Threading: {@link #start()} is idempotent and synchronized on {@code this}. The periodic
 * execution is driven by a {@link Ticker} instance, which calls {@link #run()} on the daemon thread
 * it manages. Callers must initialize file paths before starting.
 */
class Persister implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(Persister.class);

  /** Interval between scheduled persistence attempts (milliseconds). */
  static final long PERIOD = MINUTES.toMillis(15);

  /**
   * Creates a persister with explicit file destinations.
   *
   * @param t source that can serialize throttle state to a {@link SimpleFieldSet}
   * @param persistTemp temporary file written first; moved to the target on success
   * @param persistTarget destination file that should replace any previous snapshot
   * @param ps scheduler used to queue periodic executions
   */
  Persister(Persistable t, File persistTemp, File persistTarget, Ticker ps) {
    this.persistable = t;
    this.persistTemp = persistTemp;
    this.persistTarget = persistTarget;
    this.ps = ps;
  }

  // Subclasses must initialize persistTemp and persistTarget before start().
  /**
   * Protected ctor for subclasses that provide file locations later.
   *
   * <p>Implementations must assign {@link #persistTemp} and {@link #persistTarget} before calling
   * {@link #start()}.
   *
   * @param t source that can serialize throttle state
   * @param ps scheduler used to queue periodic executions
   */
  protected Persister(Persistable t, Ticker ps) {
    this.persistable = t;
    this.ps = ps;
  }

  /** Source of throttle state to persist. */
  final Persistable persistable;

  private final Ticker ps;
  // Paths are package-private so subclasses in this package can set them before start().
  File persistTemp;
  File persistTarget;
  private boolean started;

  /**
   * Performs one persistence cycle and re-schedules the next run.
   *
   * <p>All throwables are caught and logged to keep the scheduling loop alive.
   *
   * @see #persistThrottle()
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    try {
      persistThrottle();
    } catch (Throwable e) {
      LOG.error("Caught in ThrottlePersister: {}", e, e);
      LOG.warn("Will restart ThrottlePersister...");
    }
    ps.queueTimedJob(this, PERIOD);
  }

  // Write to a temp file first, then move to the target to minimize partial writes being observed.
  private void persistThrottle() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Trying to persist throttles...");
    }

    // Ensure parent directories exist so persistence doesn't fail on missing temp/target paths.
    if (!ensureParentDirectory(persistTemp) || !ensureParentDirectory(persistTarget)) {
      return;
    }

    SimpleFieldSet fs = persistable.persistThrottlesToFieldSet();
    try (FileOutputStream fos = new FileOutputStream(persistTemp)) {
      fs.writeToBigBuffer(fos);
    } catch (FileNotFoundException e) {
      LOG.error("Could not store throttle data to disk: {}", e, e);
    } catch (IOException _) {
      try {
        java.nio.file.Files.delete(persistTemp.toPath());
      } catch (IOException ex) {
        LOG.debug("Failed to delete temp file after write failure: {}", persistTemp, ex);
      }
    }
    try {
      FileUtil.moveTo(persistTemp, persistTarget);
    } catch (Exception e) {
      LOG.error("Could not move temp file to target: {}", e, e);
    }
  }

  /** Creates the parent directory for a file if it does not already exist. */
  private boolean ensureParentDirectory(File file) {
    File parent = file.getAbsoluteFile().getParentFile();
    if (parent == null || parent.exists()) {
      return true;
    }
    if (parent.mkdirs()) {
      return true;
    }
    LOG.error("Could not create directory for throttle persistence: {}", parent);
    return false;
  }

  /**
   * Loads the last successfully persisted throttle state from disk.
   *
   * <p>Attempts to read {@link #persistTarget} first and falls back to {@link #persistTemp} when
   * the target is missing or unreadable. Failures are logged. When no snapshot exists, this method
   * returns {@code null}.
   *
   * @return a parsed {@link SimpleFieldSet}, or {@code null} if none is available
   */
  public SimpleFieldSet read() {
    SimpleFieldSet throttleFS = null;
    try {
      throttleFS = SimpleFieldSet.readFrom(persistTarget, false, true);
    } catch (IOException e) {
      try {
        throttleFS = SimpleFieldSet.readFrom(persistTemp, false, true);
      } catch (FileNotFoundException _) {
        // Expected when no snapshot has been written yet.
      } catch (IOException e1) {
        if (persistTarget.length() > 0 || persistTemp.length() > 0)
          LOG.error(
              "Could not read {} ({}) and could not read {} either ({})",
              persistTarget,
              e,
              persistTemp,
              e1,
              e1);
      }
    }
    return throttleFS;
  }

  /**
   * Starts periodic persistence and registers a shutdown write.
   *
   * <p>Subsequent calls are ignored after the first successful start. The first persistence happens
   * immediately in the calling thread; later runs are scheduled via the supplied {@link Ticker}.
   */
  public void start() {
    synchronized (this) {
      if (started) {
        LOG.warn("Already started: {}", this);
        return;
      }
      started = true;
    }
    SemiOrderedShutdownHook.get()
        .addEarlyJob(
            new Thread(
                () -> {
                  LOG.info("Writing {} on shutdown", persistTarget);
                  persistThrottle();
                }));
    run();
  }
}
