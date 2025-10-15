package network.crypta.support;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import network.crypta.node.NodeStats;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PrioritizedSerialExecutor implements PriorityAwareExecutor {
  private static final Logger LOG = LoggerFactory.getLogger(PrioritizedSerialExecutor.class);

  static {
  }

  private final List<ArrayDeque<Runnable>> jobs;
  private final int priority;
  private final int defaultPriority;
  private boolean waiting;
  private final boolean invertOrder;

  private String name;
  private PriorityAwareExecutor realExecutor;
  private boolean running;
  private final ExecutorIdleCallback callback;

  private static final long DEFAULT_JOB_TIMEOUT = MINUTES.toMillis(5);
  private final long jobTimeout;

  private final Runner runner = new Runner();

  private final NodeStats statistics;

  class Runner implements PrioRunnable {

    Thread current;

    @Override
    public int getPriority() {
      return priority;
    }

    @Override
    public void run() {
      synchronized (jobs) {
        if (current != null) {
          if (current.isAlive()) {
            LOG.warn("Already running a thread for {} !!", this);
            return;
          }
        }
        current = Thread.currentThread();
      }
      try {
        boolean calledIdleCallback = false;
        while (true) {
          Runnable job = null;
          synchronized (jobs) {
            job = checkQueue();
            if (job == null) {
              waiting = true;
              try {
                // NB: notify only on adding work or this quits early.
                jobs.wait(jobTimeout);
              } catch (InterruptedException e) {
                // Ignore
              }
              waiting = false;
              job = checkQueue();
              if (job == null) {
                if (calledIdleCallback || callback == null) {
                  running = false;
                  current = null;
                  return;
                }
              }
            }
          }
          if (job == null) {
            try {
              callback.onIdle();
            } catch (Throwable t) {
              LOG.error("Idle callback failed: " + t, t);
            }
            calledIdleCallback = true;
            continue;
          }
          calledIdleCallback = false;
          try {
            if (LOG.isDebugEnabled()) LOG.debug("Running job " + job);
            long start = System.currentTimeMillis();
            job.run();
            long end = System.currentTimeMillis();
            if (LOG.isDebugEnabled()) {
              LOG.debug("Job " + job + " took " + (end - start) + "ms");
            }

            if (statistics != null) {
              statistics.reportDatabaseJob(job.toString(), end - start);
            }
          } catch (Throwable t) {
            LOG.error("Caught " + t, t);
            LOG.error("While running " + job + " on " + this);
          }
        }
      } finally {
        synchronized (jobs) {
          current = null;
          running = false;
        }
      }
    }

    private Runnable checkQueue() {
      if (!invertOrder) {
        for (int i = 0; i < jobs.size(); i++) {
          if (!jobs.get(i).isEmpty()) {
            if (LOG.isDebugEnabled()) LOG.debug("Chosen job at priority " + i);
            return jobs.get(i).removeFirst();
          }
        }
      } else {
        for (int i = jobs.size() - 1; i >= 0; i--) {
          if (!jobs.get(i).isEmpty()) {
            if (LOG.isDebugEnabled()) LOG.debug("Chosen job at priority " + i);
            return jobs.get(i).removeFirst();
          }
        }
      }
      return null;
    }
  }

  /**
   * @param priority
   * @param internalPriorityCount
   * @param defaultPriority
   * @param invertOrder Set if the priorities are thread priorities. Unset if they are request
   *     priorities. D'oh!
   */
  public PrioritizedSerialExecutor(
      int priority,
      int internalPriorityCount,
      int defaultPriority,
      boolean invertOrder,
      long jobTimeout,
      ExecutorIdleCallback callback,
      NodeStats statistics) {
    this.jobs = new ArrayList<>(internalPriorityCount);
    for (int i = 0; i < internalPriorityCount; i++) {
      this.jobs.add(new ArrayDeque<>());
    }
    this.priority = priority;
    this.defaultPriority = defaultPriority;
    this.invertOrder = invertOrder;
    this.jobTimeout = jobTimeout;
    this.callback = callback;
    this.statistics = statistics;
  }

  public PrioritizedSerialExecutor(
      int priority, int internalPriorityCount, int defaultPriority, boolean invertOrder) {
    this(
        priority,
        internalPriorityCount,
        defaultPriority,
        invertOrder,
        DEFAULT_JOB_TIMEOUT,
        null,
        null);
  }

  public void start(PriorityAwareExecutor realExecutor, String name) {
    this.realExecutor = realExecutor;
    this.name = name;
    synchronized (jobs) {
      boolean empty = true;
      for (ArrayDeque<Runnable> l : jobs) {
        if (!l.isEmpty()) {
          empty = false;
          break;
        }
      }
      if (!empty) reallyStart();
    }
  }

  private void reallyStart() {
    synchronized (jobs) {
      if (running) {
        LOG.warn("Not reallyStart()ing: ALREADY RUNNING");
        return;
      }
      running = true;
      if (LOG.isDebugEnabled()) LOG.debug("Starting thread... {} : {}", name, runner);
      realExecutor.execute(runner, name);
    }
  }

  @Override
  public void execute(Runnable job) {
    execute(job, "<noname>");
  }

  @Override
  public void execute(Runnable job, String jobName) {
    int prio = defaultPriority;
    if (job instanceof PrioRunnable runnable) prio = runnable.getPriority();
    execute(job, prio, jobName);
  }

  public void execute(Runnable job, int prio, String jobName) {
    synchronized (jobs) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Queueing "
                + jobName
                + " : "
                + job
                + " priority "
                + prio
                + ", executor state: running="
                + running
                + " waiting="
                + waiting);
      jobs.get(prio).addLast(job);
      jobs.notifyAll();
      if (!running && realExecutor != null) {
        reallyStart();
      }
    }
  }

  public void executeNoDupes(Runnable job, int prio, String jobName) {
    synchronized (jobs) {
      if (jobs.get(prio).contains(job)) {
        if (LOG.isDebugEnabled()) LOG.debug("Not queueing job: Job already queued: " + job);
        return;
      }

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Queueing "
                + jobName
                + " : "
                + job
                + " priority "
                + prio
                + ", executor state: running="
                + running
                + " waiting="
                + waiting);

      jobs.get(prio).addLast(job);
      jobs.notifyAll();
      if (!running && realExecutor != null) {
        reallyStart();
      }
    }
  }

  @Override
  public void execute(Runnable job, String jobName, boolean fromTicker) {
    execute(job, jobName);
  }

  @Override
  public int[] runningThreads() {
    int[] retval = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];
    if (running) retval[priority] = 1;
    return retval;
  }

  @Override
  public int[] waitingThreads() {
    int[] retval = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];
    synchronized (jobs) {
      if (waiting) retval[priority] = 1;
    }
    return retval;
  }

  public boolean onThread() {
    Thread running = Thread.currentThread();
    synchronized (jobs) {
      if (runner == null) return false;
      return runner.current == running;
    }
  }

  public int[] getQueuedJobsCountByPriority() {
    int[] retval = new int[jobs.size()];
    synchronized (jobs) {
      for (int i = 0; i < retval.length; i++) retval[i] = jobs.get(i).size();
    }
    return retval;
  }

  public Runnable[][] getQueuedJobsByPriority() {
    final Runnable[][] ret = new Runnable[jobs.size()][];

    synchronized (jobs) {
      for (int i = 0; i < jobs.size(); ++i) {
        ret[i] = jobs.get(i).toArray(new Runnable[0]);
      }
    }

    return ret;
  }

  public int getQueueSize(int priority) {
    synchronized (jobs) {
      return jobs.get(priority).size();
    }
  }

  @Override
  public int getWaitingThreadsCount() {
    synchronized (jobs) {
      return (waiting ? 1 : 0);
    }
  }

  public boolean anyQueued() {
    synchronized (jobs) {
      for (int i = 0; i < jobs.size(); i++) if (!jobs.get(i).isEmpty()) return true;
    }
    return false;
  }
}
