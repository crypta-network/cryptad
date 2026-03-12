package network.crypta.client.async;

/**
 * Callback interface used by asynchronous USK fetchers to report progress around the transition
 * from local datastore checks to network activity, and to signal the end of a polling round.
 *
 * <p>Implementations receive notifications at key points in the USK polling lifecycle so that user
 * interfaces, logging systems, or orchestration code can provide feedback without participating in
 * the protocol itself. Typical call patterns are: the client checks the datastore; when it decides
 * to contact peers, {@link #onSendingToNetwork(ClientContext)} is invoked; once all polling
 * requests cool down and probe attempts complete, {@link #onRoundFinished(ClientContext)} is
 * called. Implementations should return quickly and avoid blocking network or scheduler threads.
 *
 * <p>Concurrency: callbacks may be invoked on internal worker threads. No ordering beyond what is
 * stated here is guaranteed, and a callback can be invoked multiple times over the lifetime of a
 * long-running request. Implementations should be thread-safe if shared across requests and must
 * tolerate long gaps between notifications.
 *
 * <ul>
 *   <li>Never perform blocking I/O inside a callback.
 *   <li>Prefer idempotent updates; the same notification might occur more than once.
 *   <li>Assume {@code ClientContext} is non-null and scoped to the current request.
 * </ul>
 *
 * @see USKCallback
 */
public interface USKProgressCallback extends USKCallback {

  /**
   * Notifies that the client has finished the local datastore phase and intends to send network
   * requests for the current USK polling cycle. There may be a noticeable delay before the first
   * packet actually leaves the node, for example while scheduling aligns or rate limits apply.
   *
   * <p>Use this signal to update progress indicators or logs that distinguish between local lookup
   * and network activity. Implementations should return promptly; heavy work here can delay the
   * beginning of the network phase and negatively impact latency.
   *
   * @param context execution context for the request; never {@code null}; provides access to
   *     request-scoped services and identifiers suitable for logging and lightweight progress
   *     updates
   */
  void onSendingToNetwork(ClientContext context);

  /**
   * Notifies that a polling round concluded after the datastore checks, cooldown of active polling
   * requests, and completion of any random future-edition probes. At this point the scheduler may
   * decide to begin a new round or stop depending on policy and observed results.
   *
   * <p>Use this signal to finalize per-round metrics, refresh UI state, or emit summary logs. The
   * method should perform only quick bookkeeping; avoid long-running operations that could stall
   * subsequent scheduling decisions.
   *
   * @param context execution context for the request; never {@code null}; holds stable identifiers
   *     and lightweight helpers intended for diagnostics and progress reporting within the current
   *     polling round
   */
  void onRoundFinished(ClientContext context);
}
