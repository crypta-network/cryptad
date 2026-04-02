package network.crypta.clients.http.updateableelements;

import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.support.HTMLNode;

/**
 * Base class for HTTP elements that participate in the server-side update/push mechanism.
 *
 * <p>A {@code BaseUpdatableElement} is an {@link HTMLNode} that is tied to a single {@link
 * ToadletContext} and can be rendered once, then updated in place. Subclasses implement {@link
 * #updateState(boolean)} to (re)build this node's children from current state. During {@link
 * #init(boolean)}, the element is assigned a stable {@code id} attribute via {@link
 * #getUpdaterId(String)} and the initial state is rendered.
 *
 * <p>When constructed for a "pushed" response, {@link #init(boolean)} registers the element with
 * the {@link SimpleToadletServer} push manager so that later server-side events can be delivered to
 * the browser-side updater identified by {@link #getUpdaterType()}. Instances are mutable and not
 * inherently thread-safe; callers should treat them as request/UI objects and update them from the
 * same context that performs rendering.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Deriving a stable updater id for the element's {@code id} attribute.
 *   <li>Building and rebuilding the DOM subtree represented by this node.
 *   <li>Participating in the push registration lifecycle when enabled.
 * </ul>
 *
 * @see SimpleToadletServer
 */
public abstract class BaseUpdatableElement extends HTMLNode {

  /**
   * Request context associated with this element's current render/update cycle.
   *
   * <p>This context provides the request unique id (used to derive the element {@code id}) and
   * access to the container/server for optional push registration. It is set by the constructors
   * and is expected to remain unchanged for the lifetime of the element instance.
   */
  protected ToadletContext ctx;

  /**
   * Creates an updatable element with no additional HTML attributes.
   *
   * <p>This is a convenience constructor that delegates to {@link #BaseUpdatableElement(String,
   * String[], String[], ToadletContext)} with empty attribute arrays. Subclasses must still invoke
   * {@link #init(boolean)} during construction to assign an {@code id} and render initial children.
   *
   * @param name the HTML tag name passed to the {@link HTMLNode} superclass constructor
   * @param ctx the request context used to derive ids and access the server container
   */
  protected BaseUpdatableElement(String name, ToadletContext ctx) {
    this(name, new String[] {}, new String[] {}, ctx);
  }

  /**
   * Creates an updatable element with a single attribute key/value pair.
   *
   * <p>This overload is useful for elements that need exactly one attribute at construction time,
   * in addition to the {@code id} attribute set during {@link #init(boolean)}. The attribute name
   * and value are forwarded to the superclass unchanged; any validation or escaping behavior is
   * defined by {@link HTMLNode}.
   *
   * @param name the HTML tag name passed to the {@link HTMLNode} superclass constructor
   * @param attributeName the attribute name forwarded to {@link HTMLNode} without modification
   * @param attributeValue the attribute value forwarded to {@link HTMLNode} without modification
   * @param ctx the request context used to derive ids and access the server container
   */
  protected BaseUpdatableElement(
      String name, String attributeName, String attributeValue, ToadletContext ctx) {
    this(name, new String[] {attributeName}, new String[] {attributeValue}, ctx);
  }

  /**
   * Creates an updatable element with the provided attribute arrays.
   *
   * <p>This is the primary constructor used by the convenience overloads. It forwards {@code name},
   * {@code attributeNames}, and {@code attributeValues} to {@link HTMLNode} and stores the {@link
   * ToadletContext} for later initialization and push registration.
   *
   * <p>The {@link HTMLNode} superclass defines any requirements on the attribute arrays (for
   * example, whether lengths must match) and whether they are defensively copied.
   *
   * @param name the HTML tag name passed to the {@link HTMLNode} superclass constructor
   * @param attributeNames attribute names forwarded to {@link HTMLNode}, in declaration order
   * @param attributeValues attribute values forwarded to {@link HTMLNode}, in declaration order
   * @param ctx the request context used to derive ids and access the server container
   */
  protected BaseUpdatableElement(
      String name, String[] attributeNames, String[] attributeValues, ToadletContext ctx) {
    super(name, attributeNames, attributeValues);
    this.ctx = ctx;
  }

  /**
   * Initializes this element for rendering and (optionally) push-based updates.
   *
   * <p>Subclasses must call this method during construction, once the instance is ready to build
   * its initial DOM structure. Initialization assigns a stable {@code id} attribute using {@link
   * #getUpdaterId(String)} and invokes {@link #updateState(boolean)} with {@code initial=true}, so
   * the node's children match the current state.
   *
   * <p>When {@code pushed} is {@code true}, the element is registered with the current request's
   * push manager so that later updates can be routed back to this instance.
   *
   * @param pushed {@code true} to register the element with the push manager after rendering
   */
  protected void init(boolean pushed) {
    // We set the id to easily find the element
    addAttribute("id", getUpdaterId(ctx.getUniqueId()));
    // Updates the state, so the resulting page will have the actual state and content
    updateState(true);
    // Notifies the manager that the element has been rendered
    if (pushed)
      ((SimpleToadletServer) ctx.getContainer())
          .getPushDataManager()
          .elementRendered(ctx.getUniqueId(), this);
  }

  /**
   * Rebuilds this element's children to reflect the current server-side state.
   *
   * <p>Implementations should treat this as a full refresh of the DOM subtree rooted at this node:
   * remove any existing children and recreate them from current state. The method is invoked during
   * initial rendering (from {@link #init(boolean)}) and may be invoked again by the update/push
   * pipeline when the element needs to change in place.
   *
   * <p>Implementations should produce a consistent subtree on every call, even if the underlying
   * state has not changed.
   *
   * @param initial {@code true} when called for the first render of this instance
   */
  public abstract void updateState(boolean initial);

  /**
   * Returns the stable DOM id used to locate this element for client-side updates.
   *
   * <p>The returned value is written to the {@code id} attribute during {@link #init(boolean)} and
   * is used as a key in internal structures for pushed elements. It may incorporate {@code
   * requestId} to avoid collisions between concurrent renders, but it should remain stable across
   * internal navigation (for example, redirects) where the same logical element continues to be
   * updated.
   *
   * @param requestId identifier for the current HTTP request, typically from {@link ToadletContext}
   * @return a stable and deterministic DOM id string for this element instance
   */
  public abstract String getUpdaterId(String requestId);

  /**
   * Returns the client-side updater type identifier for this element.
   *
   * <p>The returned string is used by the browser-side update framework to select an updater
   * implementation that knows how to apply changes for this element. The exact set of supported
   * identifiers is defined by the HTTP UI layer.
   *
   * @return an updater type identifier string understood by the client-side update framework
   */
  public abstract String getUpdaterType();

  /**
   * Releases resources associated with this element and stops further updates.
   *
   * <p>This is invoked when the element is no longer needed (for example, when a page is torn down
   * or when the push framework discards it). Implementations should detach listeners, cancel
   * scheduled work, and drop references that would otherwise keep request-scoped objects alive.
   */
  public abstract void dispose();
}
