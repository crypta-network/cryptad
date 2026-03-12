package network.crypta.client.async;

import network.crypta.keys.ClientSSKBlock;

/**
 * Callback interface for receiving USK check results and state transitions.
 *
 * <p>Implementations of this interface are supplied to components that probe Updateable Subspace
 * Keys (USKs) and report outcomes asynchronously. A single instance may observe several short‑lived
 * probes over time, each producing exactly one terminal outcome (success, data not found, author
 * error, network error, or cancellation). Implementations should therefore be lightweight and avoid
 * long blocking operations; dispatch heavy processing to separate executors when appropriate.
 *
 * <p>Threading and lifecycle: callbacks are typically invoked on internal scheduler or worker
 * threads that also execute other client requests. Handlers must return promptly to avoid starving
 * unrelated work. A checker may first signal a finite cooldown before delivering a terminal
 * outcome; callers can use this to update progress indicators or backoff logic. Unless explicitly
 * documented by the caller, callback invocations are not retried and may arrive at most once per
 * checker for each terminal category.
 *
 * <ul>
 *   <li>Success: {@link #onSuccess(ClientSSKBlock, ClientContext)} with the retrieved block.
 *   <li>Data not found: {@link #onDNF(ClientContext)} for a negative probe.
 *   <li>Author error: {@link #onFatalAuthorError(ClientContext)} when content is invalid by origin.
 *   <li>Network error: {@link #onNetworkError(ClientContext)} for transport/remote failures.
 *   <li>Cancelled: {@link #onCancelled(ClientContext)} when the probe does not complete.
 *   <li>Cooldown: {@link #onEnterFiniteCooldown(ClientContext)} before a bounded retry pause.
 * </ul>
 */
interface USKCheckerCallback {

  /**
   * Reports that no data was found at the checked USK slot.
   *
   * <p>This terminal notification indicates that the probe completed successfully but the target
   * slot did not contain retrievable content. Implementations may choose to schedule a later probe
   * for a higher slot/index or record the absence for monitoring. This result is distinct from
   * network failures and author errors, which are reported through dedicated callbacks.
   *
   * @param context the execution context for the request providing configuration and services; may
   *     be used to schedule follow‑up work or record diagnostics, never {@code null}
   */
  void onDNF(ClientContext context);

  /**
   * Reports that content for the requested USK slot was successfully retrieved.
   *
   * <p>The provided block represents the decoded client view of the retrieved SSK content. The
   * implementation should treat the block as read‑only and avoid retaining unbounded references if
   * the callback fan‑out is asynchronous. Callers commonly persist or index the content and may
   * immediately schedule a probe for the next expected slot.
   *
   * <pre>{@code
   * // Example: simple handoff
   * void onSuccess(ClientSSKBlock block, ClientContext ctx) {
   *   indexer.accept(block);
   * }
   * }</pre>
   *
   * @param block the retrieved client SSK block for the slot; treated as immutable by callers and
   *     not modified by the framework; never {@code null}
   * @param context the execution context associated with the probe; useful for scheduling or
   *     diagnostics; never {@code null}
   */
  void onSuccess(ClientSSKBlock block, ClientContext context);

  /**
   * Reports an unrecoverable error attributed to the content origin or author.
   *
   * <p>Examples include malformed payloads, signature failures, or other conditions that make the
   * content invalid irrespective of transport. Implementations should not immediately retry the
   * same slot; instead, record the failure and consider alerting the user or operator depending on
   * the application’s policy.
   *
   * @param context the execution context for the probe at the time of the failure; supplied for
   *     logging, metrics, or follow‑up actions; never {@code null}
   */
  void onFatalAuthorError(ClientContext context);

  /**
   * Reports a failure attributed to the network, local node, or contacted peers.
   *
   * <p>This category covers transport errors, timeouts, or infrastructure issues that prevented the
   * probe from reaching a definitive conclusion. Implementations may choose to retry later with the
   * same parameters or escalate to higher‑level recovery logic.
   *
   * @param context the execution context providing access to schedulers and logging facilities; may
   *     guide deferred retries or status updates; never {@code null}
   */
  void onNetworkError(ClientContext context);

  /**
   * Reports that the request was cancelled before it completed.
   *
   * <p>Cancellation may be user‑initiated, caused by shutdown, or a result of higher‑level
   * orchestration de‑duplicating overlapping probes. Implementations should treat this as a
   * terminal outcome for the checker instance and avoid assuming that another callback will follow.
   *
   * @param context the execution context present at the time of cancellation; can be used to
   *     release resources or update progress; never {@code null}
   */
  void onCancelled(ClientContext context);

  /**
   * Returns the relative priority used to schedule the probe.
   *
   * <p>Higher values typically result in earlier execution under the active scheduler, subject to
   * system policy and fairness. The accepted range and exact interpretation are defined by the
   * caller; implementations should return a stable value per callback instance.
   *
   * @return a small integral priority value interpreted by the scheduler; higher numbers usually
   *     indicate greater urgency, but the precise semantics are caller‑defined
   */
  short getPriority();

  /**
   * Signals that the checker is entering a finite cooldown before retrying.
   *
   * <p>The cooldown duration is determined by the caller; this notification allows implementations
   * to update user‑visible status or adjust backoff accounting. A later callback will report the
   * terminal outcome of the probe once the retry completes or is abandoned.
   *
   * @param context the execution context in effect when cooldown begins; available for logging or
   *     scheduling auxiliary work; never {@code null}
   */
  void onEnterFiniteCooldown(ClientContext context);
}
