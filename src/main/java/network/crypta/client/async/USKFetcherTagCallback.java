package network.crypta.client.async;

/**
 * Callback extension that receives the concrete {@link USKFetcherTag} instance associated with a
 * USK fetch. Implementations typically store the tag for later correlation, transitions, or UI
 * updates and then handle terminal events via the inherited {@link USKFetcherCallback} methods.
 *
 * <p>The framework calls {@link #setTag(USKFetcherTag, ClientContext)} before delivering terminal
 * events such as {@code onFoundEdition}, {@code onFailure}, or {@code onCancelled}. For persistent
 * requests, this method may be invoked after a restart when callbacks are replayed on the
 * persistent job runner. Implementations should therefore treat it as idempotent and thread‑safe.
 * The provided {@link ClientContext} reflects the execution environment where subsequent callback
 * methods will run.
 *
 * <p>Typical responsibilities include:
 *
 * <ul>
 *   <li>Capturing the tag to enable handoff or transition to another state machine.
 *   <li>Associating the tag with UI elements or request tracking structures.
 *   <li>Reading immutable properties (token, persistence) needed to process results.
 * </ul>
 *
 * @see USKFetcherTag
 * @see USKFetcherCallback
 * @see ClientContext
 */
public interface USKFetcherTagCallback extends USKFetcherCallback {

  /**
   * Supplies the runtime tag instance and execution context prior to delivering terminal events.
   * Implementations usually cache the tag for later correlation or transitions. The call may occur
   * more than once across the lifecycle (e.g., after restart), and should be written to be
   * thread‑safe and idempotent. Avoid blocking; heavy work should be deferred to subsequent event
   * handlers running on the provided context.
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * class MyCb implements USKFetcherTagCallback {
   *   private USKFetcherTag tag;
   *   public void setTag(USKFetcherTag t, ClientContext ctx) { this.tag = t; }
   * }
   * }</pre>
   *
   * @param tag The concrete {@link USKFetcherTag} associated with this callback; expected non‑null
   *     and stable for the duration of the current fetch attempt.
   * @param context The client execution context where callbacks execute; use only for lightweight
   *     coordination and do not retain beyond the immediate callback unless documented.
   */
  void setTag(USKFetcherTag tag, ClientContext context);
}
