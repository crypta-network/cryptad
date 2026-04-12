package network.crypta.clients.http.updateableelements;

import network.crypta.clients.http.PushUpdatableElement;
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
public abstract class BaseUpdatableElement extends HTMLNode implements PushUpdatableElement {

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
}
