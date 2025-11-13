package network.crypta.client;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.node.RequestClient;

/**
 * Blocking adapter for asynchronous fetch callbacks.
 *
 * <p>{@code FetchWaiter} bridges the asynchronous {@link ClientGetCallback} contract to a simple
 * blocking call that returns a {@link FetchResult} or throws a {@link FetchException}. It is useful
 * when higher-level APIs or integration tests prefer a synchronous style and do not want to manage
 * callback lifecycles or thread hand‑off explicitly. A typical usage pattern is to construct a
 * waiter, initiate a request that targets the waiter as its callback, and then call {@link
 * #waitForCompletion()} to obtain the outcome.
 *
 * <p>The instance holds the first terminal outcome it receives: either {@link
 * #onSuccess(FetchResult, ClientGetter)} or {@link #onFailure(FetchException, ClientGetter)}.
 * Subsequent terminal signals are ignored to preserve the single-result invariant. Callers waiting
 * in {@link #waitForCompletion()} block until the outcome is available or the current thread is
 * interrupted. If interrupted, the method preserves the interrupt status and reports cancellation
 * via a {@link FetchException} with mode {@code CANCELLED}.
 *
 * <p>Thread-safety: all state access is synchronized on {@code this}. Multiple threads may wait for
 * completion concurrently; exactly one terminal outcome is observed. The class performs no I/O and
 * does not spawn threads. It relies on upstream components to deliver callbacks on the appropriate
 * scheduler thread.
 *
 * <ul>
 *   <li>Converts async fetch callbacks into a blocking wait-for-result call.
 *   <li>Preserves thread interrupt status and surfaces cancellation as {@link FetchException}.
 *   <li>Ensures at-most-once delivery of a terminal outcome for each instance.
 * </ul>
 *
 * @see ClientGetCallback
 * @see ClientGetter
 * @see FetchResult
 * @see FetchException
 * @see RequestClient
 */
public class FetchWaiter implements ClientGetCallback {

  private FetchResult result;
  private FetchException error;
  private boolean finished;
  private final RequestClient client;

  /**
   * Creates a new waiter bound to a request client identity.
   *
   * <p>The provided {@link RequestClient} is returned from {@link #getRequestClient()} so the
   * scheduler can attribute work correctly. The value must be a stable identity appropriate for the
   * surrounding client code; this class does not copy or modify it.
   *
   * @param client Non-null request client used for scheduling and attribution; must represent a
   *     stable identity for the lifetime of the associated request.
   */
  public FetchWaiter(RequestClient client) {
    this.client = client;
  }

  /**
   * Records a successful terminal outcome and wakes any waiting threads.
   *
   * <p>If a terminal outcome has already been recorded, the call is ignored. The provided result is
   * stored as-is and later returned by {@link #waitForCompletion()}.
   *
   * @param result Non-null {@link FetchResult} describing the fetched payload and metadata.
   * @param state The originating {@link ClientGetter} that initiated the request; may be used by
   *     callers for correlation but is not stored by this class.
   */
  @Override
  public synchronized void onSuccess(FetchResult result, ClientGetter state) {
    if (finished) return;
    this.result = result;
    finished = true;
    notifyAll();
  }

  /**
   * Records a failed terminal outcome and wakes any waiting threads.
   *
   * <p>If a terminal outcome has already been recorded, the call is ignored. The provided exception
   * is stored as-is and later rethrown by {@link #waitForCompletion()}.
   *
   * @param e Non-null {@link FetchException} describing why the fetch failed or was canceled.
   * @param state The originating {@link ClientGetter} for correlation; not stored by this class.
   */
  @Override
  public synchronized void onFailure(FetchException e, ClientGetter state) {
    if (finished) return;
    this.error = e;
    finished = true;
    notifyAll();
  }

  /**
   * Blocks until a terminal outcome is available and returns the result or throws the failure.
   *
   * <p>This method waits until either {@link #onSuccess(FetchResult, ClientGetter)} or {@link
   * #onFailure(FetchException, ClientGetter)} has been invoked. If the current thread is
   * interrupted while waiting, the interrupt flag is restored and a {@link FetchException} with
   * mode {@code CANCELLED} is thrown to signal cancellation to the caller. The method is safe to
   * call from multiple threads; once completed, all callers observe the same terminal outcome.
   *
   * <pre>{@code
   * // Example: simple synchronous fetch pattern
   * FetchWaiter waiter = new FetchWaiter(client);
   * // ... initiate a request that targets 'waiter' as its callback ...
   * FetchResult out = waiter.waitForCompletion();
   * }</pre>
   *
   * @return The non-null {@link FetchResult} produced by a successful fetch; identical to the value
   *     provided to {@link #onSuccess(FetchResult, ClientGetter)}.
   * @throws FetchException If the fetch fails, is canceled, or the waiting thread is interrupted;
   *     the instance explains the failure mode and may wrap an underlying cause.
   */
  public synchronized FetchResult waitForCompletion() throws FetchException {
    while (!finished) {
      try {
        wait();
      } catch (InterruptedException e) {
        // Preserve interrupt status and signal cancellation to callers.
        Thread.currentThread().interrupt();
        throw new FetchException(
            FetchException.FetchExceptionMode.CANCELLED, "Interrupted while waiting", e);
      }
    }

    if (error != null) throw error;
    return result;
  }

  /**
   * Unsupported for this transient, non-persistent helper.
   *
   * <p>{@code FetchWaiter} is intended for one-shot, non-persistent requests in synchronous call
   * paths. It does not participate in persistence or recovery and therefore does not implement
   * resume semantics.
   *
   * @param context Non-null execution context provided by the node when resuming; ignored.
   * @throws UnsupportedOperationException Always thrown because this helper is not persistent.
   */
  @Override
  public void onResume(ClientContext context) {
    throw new UnsupportedOperationException();
    // Not persistent.
  }

  /**
   * Returns the scheduling identity associated with this waiter.
   *
   * <p>The identity is the same instance supplied to the constructor and is used by schedulers to
   * attribute and group work. This method is thread-safe and returns without blocking.
   *
   * @return Non-null {@link RequestClient} describing persistence and real-time attributes for
   *     scheduling purposes.
   */
  @Override
  public RequestClient getRequestClient() {
    return client;
  }
}
