package network.crypta.client.async;

import java.io.Serial;
import network.crypta.client.FetchContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.SendableRequestItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks a single USK slot and reports the outcome to a caller-supplied callback.
 *
 * <p>This helper performs a short‑lived, one‑off probe of a specific Updateable Subspace Key (USK)
 * slot. It is designed to be created by higher‑level orchestration (for example, a {@code
 * USKFetcher}) to determine whether content is available at a given index, and to surface
 * actionable results to the caller via {@link USKCheckerCallback}. The instance does not own any
 * persistent state; it relies on the underlying single‑file fetch logic in the superclass and
 * forwards results to the provided callback.
 *
 * <p>Behaviorally, the checker tracks basic failure classifications across retry attempts. Data not
 * found conditions are accounted to a local counter and influence whether the final callback is
 * reported as “data not found” versus a broader network failure once retries are exhausted. Certain
 * error codes (for example, decode failures) are treated as fatal and are surfaced immediately. The
 * checker itself is not thread‑safe beyond the guarantees of the surrounding request machinery; it
 * should be used in the same scheduling context as the request that spawned it.
 *
 * <ul>
 *   <li>Single purpose: probe one USK slot and notify via callback.
 *   <li>Ephemeral: no persistence; lifecycle is bound to the probe.
 *   <li>Retries: limited; classification distinguishes DNF from transport errors.
 * </ul>
 */
class USKChecker extends BaseSingleFileFetcher {
  /** Serial version for the transient helper; included for stream compatibility if needed. */
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Class logger used only for diagnostic output. Messages include the key and instance identity to
   * aid tracing when multiple slot probes run concurrently under a coordinator.
   */
  private static final Logger LOG = LoggerFactory.getLogger(USKChecker.class);

  /**
   * Callback invoked on success, cancellation, finite cooldown entry, and classified failure. The
   * callback is provided by the orchestrating component and must remain valid for the lifetime of
   * this checker instance.
   */
  final transient USKCheckerCallback cb;

  /**
   * Count of data‑not‑found style outcomes observed across retries. A positive value biases the
   * final failure classification toward {@code onDNF} when retries are exhausted.
   */
  private int dnfs;

  /**
   * Creates a new checker bound to the given key and callback.
   *
   * <p>The checker issues a single‑slot fetch using the inherited single‑file request machinery.
   * Retry behavior and scheduling characteristics are derived from the provided parameters and
   * context. Results are always emitted through {@link #cb} and never retained internally.
   *
   * @param cb the recipient for success notifications, cooldown entry, and classified failures;
   *     receives all terminal outcomes for this probe and determines priority
   * @param key the USK‑derived key identifying the exact slot to check; used to construct the
   *     underlying request and for diagnostic messages
   * @param maxRetries maximum number of retry attempts permitted for transient conditions; values
   *     at or below zero effectively disable retry and lead to immediate classification
   * @param ctx the fetch context carrying tunables such as timeouts, caching policy, and
   *     verification; forwarded to the underlying request layer unchanged
   * @param parent the logical requester used for accounting and association with the spawning
   *     client operation; not used for user‑visible state
   * @param realTimeFlag when {@code true}, the request uses real‑time scheduling hints appropriate
   *     for interactive or low‑latency operations; otherwise default background policies apply
   */
  USKChecker(
      USKCheckerCallback cb,
      ClientKey key,
      int maxRetries,
      FetchContext ctx,
      ClientRequester parent,
      boolean realTimeFlag) {
    super(key, maxRetries, ctx, parent, false, realTimeFlag);
    this.cb = cb;
    if (LOG.isDebugEnabled()) LOG.debug("Created USKChecker for {} : {}", key, this);
  }

  /**
   * Handles a successful fetch and forwards it to the callback.
   *
   * <p>The retrieved block is expected to represent a USK slot and is down‑cast to a {@link
   * network.crypta.keys.ClientSSKBlock} prior to delegation. Any values such as {@code token} and
   * {@code fromStore} are accepted as part of the framework contract; this implementation does not
   * use them and reports success solely through the callback.
   *
   * @param block the fetched key block containing the slot content; treated as an SSK block and
   *     forwarded to the callback without mutation
   * @param fromStore whether the result came from a local store cache; not used for decision-making
   *     in this implementation
   * @param token an opaque token associated with the request item; ignored here but may be provided
   *     by the scheduler
   * @param context execution context for the client request; forwarded to the callback unchanged
   */
  @Override
  public void onSuccess(
      ClientKeyBlock block, boolean fromStore, Object token, ClientContext context) {
    // No need to check from here since USKFetcher will be told anyway.
    cb.onSuccess((ClientSSKBlock) block, context);
  }

  /**
   * Handles a failed fetch, applying retry policy and failure classification.
   *
   * <p>Failure codes are mapped to retryability. Data‑not‑found style errors increment a local
   * counter. If a retry is permitted, control is delegated to {@code retry(context)} and the method
   * returns immediately. When retries are exhausted, the checker unregisters from further callbacks
   * and emits one of: {@code onCancelled}, {@code onFatalAuthorError}, {@code onDNF}, or {@code
   * onNetworkError}, depending on the final error code and whether any DNF was observed.
   *
   * @param e the low‑level failure including a stable numeric code used for policy decisions; never
   *     modified
   * @param token the request item associated with the failure; not inspected by this implementation
   * @param context execution context for the client request; used for retry bookkeeping and passed
   *     through to callbacks
   */
  @Override
  public void onFailure(LowLevelGetException e, SendableRequestItem token, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("onFailure: {} for {}", e, this);
    // Firstly, can we retry?
    boolean canRetry;
    switch (e.code) {
      case LowLevelGetException.CANCELLED, LowLevelGetException.DECODE_FAILED ->
          // Cannot retry
          canRetry = false;
      case LowLevelGetException.DATA_NOT_FOUND,
          LowLevelGetException.DATA_NOT_FOUND_IN_STORE,
          LowLevelGetException.RECENTLY_FAILED -> {
        dnfs++;
        canRetry = true;
      }
      case LowLevelGetException.INTERNAL_ERROR,
          LowLevelGetException.REJECTED_OVERLOAD,
          LowLevelGetException.ROUTE_NOT_FOUND,
          LowLevelGetException.TRANSFER_FAILED,
          LowLevelGetException.VERIFY_FAILED ->
          // Can retry
          canRetry = true;
      default -> {
        LOG.error("Unknown low-level fetch error code: {}", e.code);
        canRetry = true;
      }
    }

    if (canRetry && retry(context)) return;

    // Ran out of retries.
    unregisterAll(context);
    if (e.code == LowLevelGetException.CANCELLED) {
      cb.onCancelled(context);
      return;
    }
    if (e.code == LowLevelGetException.DECODE_FAILED) {
      cb.onFatalAuthorError(context);
      return;
    }
    // Rest are non-fatal. If we have DNFs, DNF, else network error.
    if (dnfs > 0) cb.onDNF(context);
    else cb.onNetworkError(context);
  }

  /**
   * Returns a concise diagnostic string including the key and callback.
   *
   * @return a human‑readable identifier of the form {@code "USKChecker for <uri> for <callback>"}
   *     suitable for logs and debugging; content is intended for diagnostics only
   */
  @Override
  public String toString() {
    return "USKChecker for " + key.getURI() + " for " + cb;
  }

  /**
   * Reports the priority class to use for the request.
   *
   * <p>This delegates to the callback so the orchestrating component can control scheduling
   * behavior across related probes.
   *
   * @return a priority class value as defined by the surrounding fetch framework; the value is not
   *     validated here and is forwarded as‑is from the callback
   */
  @Override
  public short getPriorityClass() {
    return cb.getPriority();
  }

  /**
   * Notifies the callback that the request entered a finite cooldown period.
   *
   * <p>The cooldown reflects backoff applied by the underlying request machinery after a transient
   * condition. The checker does not modify or track the duration; it forwards the event so callers
   * can observe progress or update UI.
   *
   * @param context execution context for the client request associated with this cooldown
   */
  @Override
  protected void onEnterFiniteCooldown(ClientContext context) {
    cb.onEnterFiniteCooldown(context);
  }

  /**
   * Handles the case where the block was not found in any local store after retries.
   *
   * <p>The checker unregisters for further callbacks and classifies the terminal state as data not
   * found. No additional retries are attempted from this point.
   *
   * @param context execution context for the client request at the time of classification
   */
  @Override
  protected void notFoundInStore(ClientContext context) {
    // Ran out of retries.
    unregisterAll(context);
    // Rest are non-fatal. If we have DNFs, DNF, else network error.
    cb.onDNF(context);
  }

  /**
   * Treats a decode error as a terminal failure and reuses the failure path.
   *
   * <p>For consistency with other failure handling, this constructs a {@link LowLevelGetException}
   * with the {@code DECODE_FAILED} code and forwards it to {@link #onFailure(LowLevelGetException,
   * SendableRequestItem, ClientContext)}.
   *
   * @param token the request item whose decode failed; not inspected by this implementation
   * @param context execution context for the client request; forwarded unchanged
   */
  @Override
  protected void onBlockDecodeError(SendableRequestItem token, ClientContext context) {
    onFailure(new LowLevelGetException(LowLevelGetException.DECODE_FAILED), token, context);
  }

  /**
   * Returns the current client get state for inspection by callers.
   *
   * <p>This checker does not expose internal state and therefore returns {@code null}. Callers
   * should rely on callbacks for progress and terminal notifications instead of polling.
   *
   * @return always {@code null}; this checker does not maintain a retrievable get state
   */
  @Override
  protected ClientGetState getClientGetState() {
    return null;
  }
}
