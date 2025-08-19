package network.crypta.client.async;

import static org.junit.Assert.*;

import network.crypta.support.CheatingTicker;
import network.crypta.support.Executor;
import network.crypta.support.PooledExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.WaitableExecutor;
import network.crypta.support.io.NativeThread;
import org.junit.Test;

public class PersistentJobRunnerImplTest {

  public PersistentJobRunnerImplTest() {
    jobRunner = new JobRunner(exec, ticker, 1000);
    context =
        new ClientContext(
            0, null, exec, null, null, null, null, null, null, null, null, ticker, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null);
    jobRunner.start(context);
    jobRunner.onStarted(false);
    exec.waitForIdle();
    jobRunner.grabHasCheckpointed();
  }

  @Test
  public void testWaitForCheckpoint() throws PersistenceDisabledException {
    jobRunner.onLoading();
    WakeableJob w = new WakeableJob();
    jobRunner.queue(w, NativeThread.PriorityLevel.NORM_PRIORITY.value);
    w.waitForStarted();
    WaitAndCheckpoint checkpointer = new WaitAndCheckpoint(jobRunner);
    new Thread(checkpointer).start();
    checkpointer.waitForStarted();
    w.wakeUp();
    checkpointer.waitForFinished();
    assertTrue(w.finished());
  }

  @Test
  public void testDisabledCheckpointing() throws PersistenceDisabledException {
    jobRunner.setCheckpointASAP();
    exec.waitForIdle();
    assertFalse(jobRunner.mustCheckpoint()); // Has checkpointed, now false.
    jobRunner.disableWrite();
    assertFalse(jobRunner.mustCheckpoint());
    jobRunner.setCheckpointASAP();
    assertFalse(jobRunner.mustCheckpoint());

    // Run a job which will request a checkpoint.
    jobRunner.queue(context -> true, NativeThread.PriorityLevel.NORM_PRIORITY.value);

    // Wait for the job to complete.
    exec.waitForIdle();
    assertFalse(jobRunner.mustCheckpoint());
  }

  private static class WakeableJob implements PersistentJob {
    @Override
    public boolean run(ClientContext context) {
      synchronized (this) {
        started = true;
        notifyAll();
        while (!wake) {
          try {
            wait();
          } catch (InterruptedException e) {
            // Ignore.
          }
        }
        finished = true;
        notifyAll();
      }
      return false;
    }

    public synchronized void wakeUp() {
      wake = true;
      notifyAll();
    }

    public synchronized boolean started() {
      return started;
    }

    public synchronized boolean finished() {
      return finished;
    }

    public synchronized void waitForStarted() {
      while (!started) {
        try {
          wait();
        } catch (InterruptedException e) {
          // Ignore.
        }
      }
    }

    private boolean wake;
    private boolean started;
    private boolean finished;
  }

  private static class JobRunner extends PersistentJobRunnerImpl {

    public JobRunner(Executor executor, Ticker ticker, long interval) {
      super(executor, ticker, interval);
      // TODO Auto-generated constructor stub
    }

    @Override
    public boolean newSalt() {
      // Ignore.
      return false;
    }

    public synchronized boolean grabHasCheckpointed() {
      boolean ret = hasCheckpointed;
      hasCheckpointed = false;
      return ret;
    }

    @Override
    protected synchronized void innerCheckpoint(boolean shutdown) {
      hasCheckpointed = true;
      notifyAll();
    }

    private boolean hasCheckpointed;
  }

  private static class WaitAndCheckpoint implements Runnable {

    public WaitAndCheckpoint(JobRunner jobRunner2) {
      jobRunner = jobRunner2;
    }

    @Override
    public void run() {
      synchronized (this) {
        started = true;
        notifyAll();
      }
      try {
        jobRunner.waitAndCheckpoint();
      } catch (PersistenceDisabledException e) {
        throw new IllegalStateException(
            JobRunner.class.getSimpleName() + " has failed with unexpected exception", e);
      }
      assertTrue(jobRunner.grabHasCheckpointed());
      synchronized (this) {
        finished = true;
        notifyAll();
      }
    }

    public synchronized void waitForFinished() {
      while (!finished) {
        try {
          wait();
        } catch (InterruptedException e) {
          // Ignore.
        }
      }
    }

    public synchronized void waitForStarted() {
      while (!started) {
        try {
          wait();
        } catch (InterruptedException e) {
          // Ignore.
        }
      }
    }

    private final JobRunner jobRunner;
    private boolean started;
    private boolean finished;
  }

  final WaitableExecutor exec = new WaitableExecutor(new PooledExecutor());
  final Ticker ticker = new CheatingTicker(exec);
  final JobRunner jobRunner;
  final ClientContext context;
}
