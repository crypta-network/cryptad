package network.crypta.support;

/**
** Note that unlike {@link java.util.concurrent.Executor}, none of these run
** methods throw {@link java.util.concurrent.RejectedExecutionException}.
*/
public interface Executor extends java.util.concurrent.Executor {

	/** Execute a job. */
	@Override
    void execute(Runnable job);
	void execute(Runnable job, String jobName);
	void execute(Runnable job, String jobName, boolean fromTicker);

	/** Count the number of threads waiting for work at each priority level */
    int[] waitingThreads();
	/** Count the number of threads running at each priority level */
    int[] runningThreads();

	/** Fast method returning how many threads are waiting */
    int getWaitingThreadsCount();
}
