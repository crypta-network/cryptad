package network.crypta.clients.http.updateableelements;

import network.crypta.clients.http.FProxyFetchListener;

/**
 * Bridges FProxy fetch callbacks to the {@link PushDataManager} so UI-updatable elements stay in
 * sync with background downloads. A single instance is typically scoped to one {@link
 * BaseUpdateableElement} and passed to the HTTP client when initiating a fetch. The listener
 * remains lightweight: it delegates immediately without keeping additional state and therefore
 * imposes minimal overhead on the networking thread. Callers rely on it to propagate progress
 * notifications to the push layer, which then schedules UI refreshes or diff pushes as needed.
 *
 * <p><strong>Lifecycle and thread safety:</strong> the listener is usually invoked from the thread
 * that processes HTTP fetch events. It does not mutate shared state on its own; correctness depends
 * on {@link PushDataManager} being safe for concurrent invocation. Instances are immutable after
 * construction, making them safe to reuse for repeated fetch attempts associated with the same
 * element.
 *
 * <p><strong>Typical usage:</strong>
 *
 * <ul>
 *   <li>Create the listener alongside the element being updated.
 *   <li>Provide it to the HTTP fetch call so {@link #onEvent()} executes when progress occurs.
 *   <li>Allow the push manager to compute the updater ID and propagate changes to subscribers.
 * </ul>
 */
public class NotifierFetchListener implements FProxyFetchListener {

  private final PushDataManager pushManager;

  private final BaseUpdateableElement element;

  /**
   * Creates a listener that forwards fetch notifications for a specific element to the provided
   * push manager.
   *
   * @param pushManager receiver that coordinates downstream UI or client updates; must accept calls
   *     from the fetch processing thread without additional synchronization.
   * @param element updatable element whose identifier is resolved and refreshed when events are
   *     reported; must not be {@code null} for correct updater resolution.
   */
  public NotifierFetchListener(PushDataManager pushManager, BaseUpdateableElement element) {
    this.pushManager = pushManager;
    this.element = element;
  }

  /**
   * Reacts to a fetch progress signal by notifying the push manager that the associated element
   * should be refreshed. The method is intentionally minimal and idempotent: successive calls for
   * the same element lead to repeated refresh attempts without accumulating state. Callers should
   * ensure the underlying element can be resolved via {@link BaseUpdateableElement#getUpdaterId}
   * even when invoked from background threads, and that {@link PushDataManager#updateElement}
   * handles redundant refresh requests gracefully. No exceptions are thrown; failures, if any, are
   * expected to be handled downstream by the push manager.
   */
  @Override
  public void onEvent() {
    pushManager.updateElement(element.getUpdaterId(null));
  }

  /**
   * Returns a diagnostic representation containing the configured push manager and element. The
   * string is intended for logs or debugging output rather than end-user display and reflects the
   * immutability of this listener instance. Implementations relying on this value should not parse
   * it for machine logic because the format may change between versions while remaining human- *
   * readable.
   *
   * @return textual form describing the push manager and element references held by this listener.
   */
  @Override
  public String toString() {
    return "NotifierFetchListener[pushManager:" + pushManager + ",element;" + element + "]";
  }
}
