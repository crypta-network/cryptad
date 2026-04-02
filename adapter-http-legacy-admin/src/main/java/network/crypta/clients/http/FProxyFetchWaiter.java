package network.crypta.clients.http;

/**
 * Coordinates synchronous access to an {@link FProxyFetchInProgress} while the HTTP fetch
 * transitions between datastore lookup and network retrieval stages.
 *
 * <p>The waiter is constructed per in-progress fetch and exposes a small blocking API used by
 * callers that need either immediate results or a bounded wait. The class tracks three pieces of
 * state ({@code finished}, {@code hasWaited}, and {@code awoken}) that reflect whether a fetch
 * completed, a caller already waited once, or an external thread signaled progress (for example, to
 * show a progress bar). These flags are used to avoid redundant waits and to provide the correct
 * {@code waited} hint back to {@link FProxyFetchInProgress#innerGetResult(boolean)}.
 *
 * <p>Instances are not thread-safe for concurrent callers; callers coordinate through the intrinsic
 * monitor so that only one thread executes wait logic at a time. However, other threads may invoke
 * {@link #wakeUp(boolean)} to interrupt the current wait when progress or completion occurs.
 *
 * <ul>
 *   <li>Blocking callers use {@link #getResult(boolean)} with {@code true} to wait indefinitely
 *       until {@link #wakeUp(boolean)} signals completion.
 *   <li>Non-blocking callers use {@link #getResult(boolean)} with {@code false} to wait up to five
 *       seconds or return earlier when awoken.
 *   <li>{@link #getResultFast()} returns immediately without waiting and is suitable for polling or
 *       diagnostic use.
 * </ul>
 *
 * @see FProxyFetchInProgress
 */
public class FProxyFetchWaiter {

  /**
   * Creates a waiter bound to the supplied in-progress fetch.
   *
   * <p>The constructor captures whether the fetch is already marked finished and whether a previous
   * wait occurred, preserving state if the {@link FProxyFetchInProgress} is reused. The reference
   * is stored as provided; callers must ensure it is non-null and remains valid for the duration of
   * the waiter. No synchronization occurs during construction.
   *
   * @param progress2 the active fetch to coordinate; must not be {@code null} and must remain
   *     usable until the waiter is closed.
   */
  public FProxyFetchWaiter(FProxyFetchInProgress progress2) {
    this.progress = progress2;
    if (progress.finished()) finished = true;
    hasWaited = progress.hasWaited();
  }

  final FProxyFetchInProgress progress;

  private boolean hasWaited;
  private boolean finished;
  private boolean awoken;

  /**
   * Returns the result, waiting up to the default timeout before falling back to non-blocking
   * retrieval.
   *
   * <p>This is a convenience wrapper around {@link #getResult(boolean)} with {@code waitForever}
   * set to {@code false}. Callers receive either a completed fetch or the most recent partial
   * result after a single timed wait cycle.
   *
   * @return the fetch result, including partial progress if the timed wait expires.
   */
  public FProxyFetchResult getResult() {
    return getResult(false);
  }

  /**
   * Obtains the fetch result, optionally blocking until completion.
   *
   * <p>When {@code waitForever} is {@code true}, the calling thread waits indefinitely until {@link
   * #wakeUp(boolean)} is invoked with {@code true}. When {@code waitForever} is {@code false}, the
   * caller waits at most five seconds unless awoken earlier, after which it proceeds with the most
   * recent progress snapshot. The method communicates whether a wait occurred to {@link
   * FProxyFetchInProgress#innerGetResult(boolean)} so downstream consumers can decide whether to
   * show progress UI or immediately return cached results.
   *
   * <p>This method is synchronized to ensure a consistent view of the waiter state. It does not
   * clear the {@code finished} flag once set.
   *
   * @param waitForever {@code true} to wait until {@link #wakeUp(boolean)} signals completion;
   *     {@code false} to wait up to five seconds or return sooner when awoken.
   * @return the final or interim fetch result; the caller must not modify the returned object.
   */
  public FProxyFetchResult getResult(boolean waitForever) {
    boolean waited;
    synchronized (this) {
      if (waitForever) waitUntilFinished();
      else waitWithTimeout();
      waited = hasWaited;
    }
    progress.setHasWaited();
    return progress.innerGetResult(waited);
  }

  /**
   * Returns the result without performing any wait.
   *
   * <p>This accessor bypasses all waiting semantics and immediately delegates to {@link
   * FProxyFetchInProgress#innerGetResult(boolean)} with {@code waited=false}. Use it for status
   * probes or logging when the caller controls timing externally and accepts that the returned
   * result may still reflect an in-progress fetch. No additional synchronization is applied beyond
   * what the underlying progress object provides.
   *
   * @return the latest fetch result snapshot; may represent partial or completed data.
   */
  public FProxyFetchResult getResultFast() {
    return progress.innerGetResult(false);
  }

  /**
   * Returns the underlying progress tracker backing this waiter.
   *
   * <p>The returned {@link FProxyFetchInProgress} enables callers to inspect detailed fetch state,
   * attach observers, or perform cleanup outside the waiter. The reference remains stable for the
   * lifetime of this waiter, though the tracked state can mutate as the fetch advances. Callers
   * should synchronize externally if they need a consistent view across multiple reads.
   *
   * @return the shared {@link FProxyFetchInProgress} instance for this fetch.
   */
  public FProxyFetchInProgress getProgress() {
    return progress;
  }

  /**
   * Releases resources held by the waiter and informs the underlying progress tracker.
   *
   * <p>This is a lightweight delegating close; callers should invoke it when the fetch lifecycle is
   * complete so any observer bookkeeping in {@link FProxyFetchInProgress#close(FProxyFetchWaiter)}
   * can run.
   */
  public void close() {
    progress.close(this);
  }

  /**
   * Signals the waiter that the fetch has progressed or finished, waking any waiting caller.
   *
   * <p>When {@code fin} is {@code true}, the waiter permanently marks the fetch as finished and
   * notifies all waiting threads. When {@code fin} is {@code false}, it sets the {@code awoken}
   * flag to indicate a non-terminal progress event such as leaving the datastore stage. Callers are
   * expected to invoke this from worker threads as milestones are reached.
   *
   * @param fin {@code true} to mark the fetch finished; {@code false} to signal intermediate
   *     progress.
   */
  public synchronized void wakeUp(boolean fin) {
    if (fin) this.finished = true;
    else this.awoken = true;
    notifyAll();
  }

  /**
   * Indicates whether this waiter has completed at least one wait cycle.
   *
   * <p>The flag transitions to {@code true} after a timed wait or an indefinite wait completes and
   * remains set for the lifetime of the waiter. It does not reset when the fetch finishes or when
   * additional wake-ups occur. Callers can use this to decide whether to display progress UI or to
   * avoid reusing the initial wait budget on subsequent calls.
   *
   * @return {@code true} once a wait has occurred; {@code false} if no waiting has been performed.
   */
  public boolean hasWaited() {
    return hasWaited;
  }

  @SuppressWarnings("java:S2142")
  private synchronized void waitUntilFinished() {
    // Loop to handle spurious wakeups; wakeUp(true) sets finished and notifies.
    while (!finished) {
      try {
        wait();
        hasWaited = true;
      } catch (InterruptedException _) {
        // Ignore interrupts to honour the blocking contract; caller expects to wait
        // until the fetch completes via wakeUp(true).
      }
    }
  }

  private synchronized void waitWithTimeout() {
    /* Wait for 5 seconds or until something happens. The
     * most common something other than finishing is a callback
     * because the request has finished checking the datastore
     * and has been sent to the network, in which case we want
     * to show the progress bar. */
    if (finished || hasWaited || awoken) return;

    long deadline = System.currentTimeMillis() + 5000L;
    boolean waited = false;
    while (!finished && !awoken) {
      long remaining = deadline - System.currentTimeMillis();
      if (remaining <= 0) break;
      try {
        waited = true;
        wait(remaining);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return;
      }
    }
    if (waited) hasWaited = true;
  }
}
