package network.crypta.config;

import java.io.File;
import java.io.IOException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * File-backed configuration that persists only after the node signals startup.
 *
 * <p>This specialization of {@link FilePersistentConfig} coordinates on-disk persistence with the
 * node lifecycle. Calls to {@link #store()} schedule a background task on a {@link Ticker}; that
 * task waits until {@link #setHasNodeStarted()} is invoked before writing. If the waiting thread is
 * interrupted prior to startup (for example during shutdown), the write is skipped and the internal
 * write-in-progress flag is cleared so later store requests can proceed once startup completes.
 *
 * <p>Thread-safety: external callers do not synchronize on this instance. The class serializes disk
 * writes under {@code storeSync} (inherited) and uses {@code synchronized(this)} only for the short
 * wait/notify section that gates startup.
 */
public class FreenetFilePersistentConfig extends FilePersistentConfig {
  private static final Logger LOG = LoggerFactory.getLogger(FreenetFilePersistentConfig.class);

  /**
   * Header written at the top of the serialized file. It warns users not to edit the configuration
   * while the node is running.
   */
  protected static final String DEFAULT_HEADER =
      "This file is overwritten whenever Crypta shuts down, so only edit it when the node is not"
          + " running.";

  // True while a persist task is queued/running; cleared after the task exits (success or abort).
  private volatile boolean isWritingConfig = false;
  // True after the node has signaled startup; allows the background task to proceed to persist.
  private volatile boolean hasNodeStarted = false;

  private Ticker ticker;

  /**
   * Background task scheduled by {@link #store()} to perform a deferred persist.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>Waits in 1s intervals for {@link #setHasNodeStarted()}.
   *   <li>If interrupted before startup, re-asserts the interrupt status, skips the write, and
   *       clears the write-in-progress flag.
   *   <li>After startup, calls {@link #innerStore()} and then clears the write-in-progress flag.
   * </ul>
   *
   * <p>This field is exposed for scheduling and tests; callers should not execute it directly
   * except through the configured {@link Ticker}.
   */
  public final Runnable thread =
      () -> {
        boolean interruptedDuringWait = false;
        synchronized (FreenetFilePersistentConfig.this) {
          while (!hasNodeStarted) {
            try {
              FreenetFilePersistentConfig.this.wait(1000);
            } catch (InterruptedException _) {
              // Worker threads may be interrupted during shutdown. Avoid persisting a partially
              // initialized configuration: record the interruption, re-assert the flag, and exit
              // the wait loop so the task can bail out below.
              Thread.currentThread().interrupt();
              interruptedDuringWait = true;
              break;
            }
          }
        }

        if (interruptedDuringWait || !hasNodeStarted) {
          // Bail out when startup never completed. Reset the write flag so future store() calls
          // can proceed once startup is signaled.
          synchronized (storeSync) {
            isWritingConfig = false;
          }
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Skipping config persist: {} (hasNodeStarted={})",
                (interruptedDuringWait ? "interrupted during wait" : "not started"),
                hasNodeStarted);
          }
          return;
        }

        try {
          innerStore();
        } catch (IOException e) {
          String err = "Cannot store config: " + e;
          LOG.error(err, e);
        }
        synchronized (storeSync) {
          isWritingConfig = false;
        }
      };

  /**
   * Creates a configuration backed by {@code filename} using the default header.
   *
   * @param set initial key/value set to seed the configuration; may be {@code null}
   * @param filename destination file to write on persist
   * @param tempFilename temporary file used for atomic writes
   * @throws IOException if existing files must be read and cannot be opened or parsed
   */
  public FreenetFilePersistentConfig(SimpleFieldSet set, File filename, File tempFilename)
      throws IOException {
    super(set, filename, tempFilename, DEFAULT_HEADER);
  }

  /**
   * Constructs an instance for {@code f}, deriving the temporary path by appending {@code ".tmp"}.
   * Loads existing configuration from {@code f} or its temp file when present.
   *
   * @param f target configuration file
   * @return a new instance backed by {@code f}
   * @throws IOException if a present file exists but cannot be read using relaxed parsing rules
   */
  @SuppressWarnings("unused")
  public static FreenetFilePersistentConfig constructFreenetFilePersistentConfig(File f)
      throws IOException {
    File tempFilename = new File(f.getPath() + ".tmp");
    return new FreenetFilePersistentConfig(load(f, tempFilename), f, tempFilename);
  }

  /**
   * Requests persistence of the current configuration.
   *
   * <p>If initialization has not yet completed, marks the write to run after {@link
   * #finishedInit()} and returns. Otherwise, when a {@link Ticker} is available and no write is in
   * progress, queues {@link #thread} on the ticker. The queued task blocks until the node signals
   * startup and then performs the write.
   */
  @Override
  public void store() {
    // Defer when initialization is not yet complete.
    synchronized (this) {
      if (!finishedInit) {
        writeOnFinished = true;
        return;
      }
    }
    synchronized (storeSync) {
      if (isWritingConfig || ticker == null) {
        LOG.info(
            "Already writing the config file to disk or the node object hasn't been set : refusing"
                + " to proceed");
        return;
      }
      isWritingConfig = true;

      ticker.queueTimedJob(thread, 0);
    }
  }

  /**
   * Completes initialization and installs the {@link Ticker} used to schedule deferred writes.
   *
   * <p>Calls {@link FilePersistentConfig#finishedInit()} to finalize base initialization. When a
   * write was requested earlier, the base implementation will trigger {@link #store()}, which uses
   * the provided {@code ticker}.
   *
   * @param ticker scheduler that executes the deferred write task; may be {@code null} to delay
   *     scheduling until a ticker is later provided
   */
  public void finishedInit(Ticker ticker) {
    this.ticker = ticker;
    super.finishedInit();
  }

  /**
   * Signals that the node has completed startup and that deferred writes may proceed.
   *
   * <p>Wakes threads waiting in {@link #thread}. A second call logs an error and still notifies
   * waiters.
   */
  public void setHasNodeStarted() {
    synchronized (this) {
      if (hasNodeStarted) LOG.error("It has already been called! that shouldn't happen!");
      this.hasNodeStarted = true;
      notifyAll();
    }
  }
}
