package network.crypta.support;

public interface ExecutorIdleCallback {
	
	/** Called when the executor is idle for some period. On a single-thread executor,
	 * this will be called on the thread which runs the jobs, but after that the thread
	 * may change. */
    void onIdle();

}
