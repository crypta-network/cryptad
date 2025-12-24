package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JVM shutdown hook that executes registered jobs in two phases (early, then late).
 *
 * <p>On shutdown, this hook starts all early jobs concurrently and joins each with a fixed
 * per-thread timeout. It then starts late jobs and joins them with the same timeout. If an
 * interruption occurs while joining, it is remembered and the interrupted status is restored after
 * both join loops complete. This allows the remaining joins to proceed while still propagating the
 * interrupt to callers.
 *
 * <p>Thread safety: registration methods are synchronized. Snapshots of job lists are taken at
 * {@link #run()} time to avoid holding locks during joins. Callers should register jobs before
 * shutdown begins.
 *
 * <p>Usage: obtain the singleton via {@link #get()} and register unstarted threads with {@link
 * #addEarlyJob(Thread)} or {@link #addLateJob(Thread)}. The hook calls {@link Thread#start()}.
 */
@SuppressWarnings({"java:S6548", "java:S2142"})
public class SemiOrderedShutdownHook extends Thread {

  // Join timeout per thread in milliseconds.
  private static final long TIMEOUT = SECONDS.toMillis(100);
  private final ArrayList<Thread> earlyJobs;
  private final ArrayList<Thread> lateJobs;
  private static final Logger LOG = LoggerFactory.getLogger(SemiOrderedShutdownHook.class);

  public static final SemiOrderedShutdownHook singleton = new SemiOrderedShutdownHook();

  static {
    Runtime.getRuntime().addShutdownHook(singleton);
  }

  /**
   * Returns the process-wide singleton shutdown hook instance registered with the runtime.
   *
   * @return the singleton shutdown hook
   */
  public static SemiOrderedShutdownHook get() {
    return singleton;
  }

  private SemiOrderedShutdownHook() {
    earlyJobs = new ArrayList<>();
    lateJobs = new ArrayList<>();
  }

  /**
   * Registers a job to run in the early phase of shutdown.
   *
   * <p>The hook starts the thread and waits up to the per-thread timeout for completion.
   *
   * @param r unstarted thread to execute during the early phase
   */
  public synchronized void addEarlyJob(Thread r) {
    earlyJobs.add(r);
  }

  /**
   * Registers a job to run in the late phase of shutdown.
   *
   * <p>The hook starts the thread and waits up to the per-thread timeout for completion.
   *
   * @param r unstarted thread to execute during the late phase
   */
  public synchronized void addLateJob(Thread r) {
    lateJobs.add(r);
  }

  @Override
  public void run() {
    LOG.info("Shutdown hook starts; running early and late jobs.");
    // Start early jobs concurrently, then wait up to the per-thread timeout for each to finish.

    boolean wasInterrupted = false;

    Thread[] early = getEarlyJobs();

    // Start all early jobs.
    for (Thread r : early) {
      r.start();
    }
    // Join early jobs; remember interruptions but continue joining remaining threads.
    for (Thread r : early) {
      try {
        r.join(TIMEOUT);
      } catch (InterruptedException _) {
        // Remember interruption and continue joining remaining threads.
        wasInterrupted = true;
      }
    }

    Thread[] late = getLateJobs();

    // Then start late jobs concurrently and wait up to the per-thread timeout for each (the JVM
    // exits when this method returns).
    for (Thread r : late) {
      r.start();
    }
    // Join late jobs; remember interruptions but continue joining remaining threads.
    for (Thread r : late) {
      try {
        r.join(TIMEOUT);
      } catch (InterruptedException _) {
        // Remember interruption and continue joining remaining threads.
        wasInterrupted = true;
      }
    }

    if (wasInterrupted) {
      // Restore the interrupted status after all joins so callers can observe it
      // without causing subsequent joins in this method to fail immediately.
      Thread.currentThread().interrupt();
    }
  }

  // Return a snapshot to avoid holding the monitor while joining.
  private synchronized Thread[] getEarlyJobs() {
    return earlyJobs.toArray(new Thread[0]);
  }

  // Return a snapshot to avoid holding the monitor while joining.
  private synchronized Thread[] getLateJobs() {
    return lateJobs.toArray(new Thread[0]);
  }
}
