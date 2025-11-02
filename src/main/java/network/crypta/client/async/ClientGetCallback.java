package network.crypta.client.async;

import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;

/**
 * Callback contract for client fetch operations.
 *
 * <p>Implementations receive success and failure notifications for fetch requests initiated through
 * the client layer. When a request is persistent, callbacks run on the database thread so that
 * state can be updated consistently with persistence. For transient requests, the callback executes
 * on the thread that completed the work (in that case, the surrounding container may be {@code
 * null}). Typical usage is for a higher‑level client component to implement this interface together
 * with {@link ClientBaseCallback} so it can resume state after restarts and report results back to
 * the application boundary.
 *
 * <p>Callbacks should remain lightweight. If substantial processing is required—such as indexing,
 * parsing, or downstream requests—schedule the work onto the {@code Ticker} or the main executor
 * available from {@link ClientContext} to avoid blocking internal scheduler threads.
 * Implementations must be robust to being called at most once per request for each terminal outcome
 * and should perform any necessary cleanup of resources they own.
 *
 * <ul>
 *   <li>Delivers a terminal success with a {@link FetchResult} describing the retrieved data.
 *   <li>Delivers a terminal failure with a {@link FetchException} describing what went wrong.
 *   <li>Advises clients to offload heavy work to appropriate executors to keep callbacks fast.
 * </ul>
 *
 * @see ClientBaseCallback
 * @see ClientContext
 */
public interface ClientGetCallback extends ClientBaseCallback {
  /**
   * Signals that the fetch completed successfully.
   *
   * <p>The provided {@link FetchResult} carries the fetched payload and associated metadata. This
   * is a terminal event for the request. If processing the content is expected to be expensive,
   * schedule the work on the {@code Ticker} or the main executor from {@link ClientContext} rather
   * than blocking the scheduler thread that delivers this callback. Implementations should treat
   * the result as read‑only and promptly hand it off to downstream components.
   *
   * @param result Non-null {@link FetchResult} describing the fetched content and any related
   *     metadata; ownership is not transferred and callers should avoid mutating internal buffers.
   * @param state The original {@link ClientGetter} that initiated the fetch; may be used to inspect
   *     request parameters or correlate logging and application-level state.
   */
  void onSuccess(FetchResult result, ClientGetter state);

  /**
   * Signals that the fetch failed or was canceled.
   *
   * <p>This is a terminal event for the request. The {@link FetchException} conveys details about
   * the failure and may include nested causes or categorized error information. Implementations may
   * choose to retry according to their own policy by scheduling follow‑up work on the {@code
   * Ticker} or the main executor from {@link ClientContext}. Avoid heavy work on the callback
   * thread to keep the system responsive.
   *
   * @param e The {@link FetchException} describing why the fetch did not complete successfully; it
   *     may include causes and structured error codes for diagnostics and policy decisions.
   * @param state The original {@link ClientGetter} that initiated the fetch; useful for correlating
   *     application state, logging, and potential retry logic.
   */
  void onFailure(FetchException e, ClientGetter state);
}
