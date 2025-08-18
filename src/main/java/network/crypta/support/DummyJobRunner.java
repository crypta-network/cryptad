package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;

/** A PersistentJobRunner that isn't persistent. Convenient for transient requests, code doesn't
 * need messy if(persistent) everywhere. */
public class DummyJobRunner implements PersistentJobRunner {
    
    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(DummyJobRunner.class);
    }
    
    final Executor executor;
    final ClientContext context;

    public DummyJobRunner(Executor executor, ClientContext context) {
        this.executor = executor;
        this.context = context;
    }

    @Override
    public void queue(final PersistentJob job, final int priority) {
        if(logMINOR) Logger.minor(this, "Running job off thread: "+job);
        executor.execute(new PrioRunnable() {

            @Override
            public void run() {
                if(logMINOR) Logger.minor(this, "Starting job "+job);
                job.run(context);
            }

            @Override
            public int getPriority() {
                return priority;
            }
            
        });
    }

    @Override
    public void queueNormalOrDrop(PersistentJob job) {
        queue(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
    }

    @Override
    public void setCheckpointASAP() {
        // Ignore.
    }

    @Override
    public boolean hasLoaded() {
        return true;
    }

    @Override
    public void queueInternal(PersistentJob job, int threadPriority) {
        queue(job, threadPriority);
    }

    @Override
    public void queueInternal(PersistentJob job) {
        queueInternal(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
    }

    @Override
    public CheckpointLock lock() {
        return new CheckpointLock() {

            @Override
            public void unlock(boolean forceWrite, int threadPriority) {
                // Do nothing.
            }
            
        };
    }

    @Override
    public boolean newSalt() {
        return false;
    }

    @Override
    public boolean shuttingDown() {
        return false;
    }

}
