package network.crypta.clients.http;

/**
 * Shared-shell view of one pending push/update notification.
 *
 * <p>An event tells the legacy push client which server-side page/request and which tracked element
 * need to be refreshed next. The polling endpoint returns these notifications after the push
 * manager observes a state change and decides that a client should ask for updated markup. The
 * event is intentionally small because the actual HTML payload is fetched separately through the
 * element lookup path.
 *
 * <p>Implementations typically behave like immutable value objects. Callers should treat the
 * request identifier and element identifier together as the routing key for the next refresh step,
 * not as independent data points with separate lifecycles.
 */
public interface PushUpdateEvent {

  /**
   * Returns the request/page identifier that should apply the update.
   *
   * <p>This identifies the tracked page or request whose rendered state should be consulted for the
   * next refresh. In the legacy system, the polling request that receives the event can differ from
   * the page/request that originally rendered the changed element.
   *
   * @return target request or page identifier that should apply the update
   */
  String getRequestId();

  /**
   * Returns the updater element identifier that changed.
   *
   * <p>Callers use this identifier together with {@link #getRequestId()} to resolve the matching
   * {@link PushUpdatableElement} and fetch the latest serialized child markup for the browser-side
   * updater.
   *
   * @return updater element identifier for the changed element
   */
  String getElementId();
}
