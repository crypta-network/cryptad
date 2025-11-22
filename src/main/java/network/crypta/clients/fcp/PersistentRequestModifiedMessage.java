package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Server-to-client notification describing that a persistent FCP request has been altered on the
 * node. The message mirrors the {@code ModifyPersistentRequest} command and echoes back the updated
 * identifier, scope, priority class, and optional client token so a client can reconcile its local
 * bookkeeping with the node's authoritative state.
 *
 * <p>Instances are immutable and constructed on the server when a previously registered request is
 * reprioritized or relabeled. Clients typically receive this message as part of their long-lived
 * connection, use the {@code Identifier} field to locate the affected request, and then refresh any
 * progress tracking or retry scheduling based on the new priority and scope. The {@code global}
 * flag indicates whether the change applies to the node-wide queue, while the optional client token
 * allows multi-tenant clients to disambiguate overlapping identifiers.
 *
 * <p>Although lightweight, the message carries enough context to drive UI updates and queue
 * management without issuing follow-up queries. Because it is generated on the server side, no
 * client code should attempt to instantiate or submit it as part of a request pipeline. Message
 * objects are thread-safe for concurrent read access after creation.
 *
 * <ul>
 *   <li>Responsibilities: serialize the modified request metadata to an {@link SimpleFieldSet}.
 *   <li>Notable behavior: rejects client-originated handling paths via {@link #run}.
 * </ul>
 *
 * @see ModifyPersistentRequest
 * @see FCPConnectionHandler
 */
public class PersistentRequestModifiedMessage extends FCPMessage {

  private final String ident;
  private final boolean global;

  private final short priorityClass;
  private final String clientToken;

  /**
   * Creates a notification that updates the priority of a persistent request without supplying a
   * client token.
   *
   * <p>Use this constructor when the server needs to publish a priority change and the original
   * requester did not include or require a {@code ClientToken}. A negative priority class is not
   * permitted here; callers should pass the new non-negative class that will be propagated to
   * downstream consumers.
   *
   * @param identifier unique request identifier previously registered by the client; must not be
   *     {@code null}.
   * @param global whether the modification targets the global queue ({@code true}) or a local
   *     request subset ({@code false}); informs client-side routing decisions.
   * @param priorityClass new non-negative priority class assigned by the node; higher values denote
   *     lower priority according to FCP semantics.
   */
  public PersistentRequestModifiedMessage(String identifier, boolean global, short priorityClass) {
    this(identifier, global, priorityClass, null); // clientToken not set
  }

  /**
   * Creates a notification that preserves the caller-supplied client token but leaves the priority
   * class unspecified.
   *
   * <p>This form is used when the modification concerns metadata other than the priority class, or
   * when the server cannot determine an adjusted class. The token lets multi-tenant clients map the
   * update to an application-level request without inspecting the global queue state.
   *
   * @param identifier unique request identifier previously registered by the client; must not be
   *     {@code null}.
   * @param global whether the modification applies across the node or is scoped to the client
   *     session; {@code true} signals a global effect.
   * @param clientToken optional caller-defined correlation token echoed back unmodified; may be
   *     {@code null} when no token was supplied.
   */
  public PersistentRequestModifiedMessage(String identifier, boolean global, String clientToken) {
    this(identifier, global, (short) (-1), clientToken); // priorityClass not set
  }

  /**
   * Creates a fully specified modification notification with both priority class and client token
   * populated.
   *
   * <p>Use this constructor when the node needs to convey the complete set of request attributes.
   * The combination of identifier and client token lets clients reconcile updates in environments
   * where identifiers can collide across tenants. Passing a negative priority class signals that no
   * change to priority should be inferred by recipients.
   *
   * @param identifier unique request identifier previously registered by the client; must not be
   *     {@code null}.
   * @param global whether the modification affects the global request pool ({@code true}) or is
   *     confined to the originating client ({@code false}).
   * @param priorityClass non-negative priority class to assign; use a negative value to indicate
   *     the priority is unchanged or unknown.
   * @param clientToken optional correlation token provided by the original client; may be {@code
   *     null} if none was supplied.
   */
  public PersistentRequestModifiedMessage(
      String identifier, boolean global, short priorityClass, String clientToken) {
    this.ident = identifier;
    this.global = global;
    this.priorityClass = priorityClass;
    this.clientToken = clientToken;
  }

  /**
   * Serializes this message into the wire-format {@link SimpleFieldSet} expected by the FCP client.
   *
   * <p>The returned field set always includes the {@code Identifier} and {@code Global} entries. If
   * a non-negative priority class is present it is emitted as {@code PriorityClass}; likewise, a
   * non-null client token is emitted as {@code ClientToken}. Callers should treat the resulting
   * field set as immutable once returned.
   *
   * @return field set containing the identifier, scope flag, and any optional attributes required
   *     to represent the modification on the wire.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    final SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", ident);
    fs.put("Global", global);
    if (priorityClass >= 0) fs.put("PriorityClass", priorityClass);
    if (clientToken != null) fs.putSingle("ClientToken", clientToken);
    return fs;
  }

  /**
   * Reports the FCP message name associated with this type.
   *
   * <p>The name is stable across protocol versions and is used both during serialization and by
   * dispatch code inside {@link FCPConnectionHandler}. Consumers should not cache alternative
   * aliases; use this method to ensure parity with wire tokens when building routing tables.
   *
   * @return constant string {@code "PersistentRequestModified"} suitable for wire encoding and
   *     handler lookup.
   */
  @Override
  public String getName() {
    return "PersistentRequestModified";
  }

  /**
   * Rejects client-side handling because this message is intended only for server-to-client
   * delivery.
   *
   * <p>If invoked on the server in response to a client submission, this method consistently raises
   * {@link MessageInvalidException} to signal protocol misuse. It does not attempt recovery or
   * logging because the responsibility lies with higher protocol layers to enforce directionality.
   *
   * @param handler connection handler that attempted to route the message; never modified.
   * @param node node instance processing the inbound message; unused because execution aborts.
   * @throws MessageInvalidException always thrown to indicate that clients must not send this
   *     message type to the server.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentRequestModified goes from server to client not the other way around",
        ident,
        global);
  }
}
