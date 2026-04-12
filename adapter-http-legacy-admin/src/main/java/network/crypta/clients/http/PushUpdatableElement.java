package network.crypta.clients.http;

/**
 * Shared-shell view of an element that can be re-rendered through the legacy push/update flow.
 *
 * <p>An implementation represents one server-side DOM fragment that can be rendered during the
 * initial page response and later refreshed in place after the server detects a state change. The
 * shared shell only needs a small contract for that lifecycle: refresh the element's internal
 * state, identify it with a stable updater id and updater type, serialize its children, and clean
 * up any resources when the request leaves the push system.
 *
 * <p>The interface deliberately avoids browse-owned base classes, so schedulers, toadlets, and
 * request services can work against a neutral type. Implementations remain mutable request-scoped
 * objects. Callers should assume they are tied to a single render/update lifecycle rather than
 * reusable across unrelated requests.
 */
public interface PushUpdatableElement {

  /**
   * Refreshes the element state before it is read or re-rendered.
   *
   * <p>Implementations should rebuild or recalculate any transient state needed for rendering so
   * that a subsequent call to {@link #generateChildren()} reflects the current server-side view.
   * The {@code initial} flag distinguishes the first render from later push-driven refreshes when
   * an implementation needs slightly different setup behavior.
   *
   * @param initial {@code true} when invoked for the initial render of the element instance, or
   *     {@code false} for a later refresh
   */
  void updateState(boolean initial);

  /**
   * Returns the stable updater id used for server-side lookup and DOM targeting.
   *
   * <p>The returned identifier is used as the key that links server-side element tracking to the
   * browser-side updater logic. Implementations should produce a value that remains stable for the
   * lifetime of the element within the supplied request or page.
   *
   * @param requestId request or page identifier used to scope the updater id
   * @return stable updater identifier for this element within the supplied request
   */
  String getUpdaterId(String requestId);

  /**
   * Returns the client-side updater type identifier for this element.
   *
   * <p>This value tells the browser-side update code which updater implementation should interpret
   * the serialized payload for this element. Implementations should return the same logical type
   * for every refresh of the same element kind.
   *
   * @return updater type identifier understood by the client-side update code
   */
  String getUpdaterType();

  /**
   * Generates the serialized child markup for the current element state.
   *
   * <p>Callers use this after {@link #updateState(boolean)} to build the payload returned by the
   * push endpoints. The result should represent the current child markup for the element, ready to
   * send back to the browser without additional element-specific transformation.
   *
   * @return serialized child markup for the element's current state
   */
  String generateChildren();

  /**
   * Releases resources held by this element.
   *
   * <p>This is the teardown hook for request completion and push cleanup. Implementations should
   * detach listeners, cancel auxiliary work, and drop references that should not survive after the
   * element is no longer tracked.
   */
  void dispose();
}
