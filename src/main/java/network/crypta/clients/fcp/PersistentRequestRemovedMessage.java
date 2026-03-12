package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Server-to-client notification confirming that a persistent request has been removed.
 *
 * <p>This message is emitted by the node after it processes a {@code RemovePersistentRequest}
 * command and succeeds in removing the referenced request from the persistence store. It carries
 * only the client-provided identifier and the scope flag so that a receiving FCP client can match
 * the acknowledgement to its original request tracking. Instances are immutable and therefore safe
 * to share across threads once constructed; typical usage constructs the message on the server side
 * and hands it directly to the connection handler for transmission without further mutation.
 *
 * <p>Persistent removal is an asynchronous workflow: the client asks the node to clear a queued or
 * running persistent fetch/insert, and the node reports back when it has removed the record. The
 * {@code global} field indicates whether the deletion targeted the global persistent store
 * (survives restarts) or a session-scoped entry, allowing clients to update their own caches
 * consistently. The message itself is side effect free on receipt; it is purely a confirmation
 * payload and will be rejected if sent in the wrong direction.
 *
 * <ul>
 *   <li>Confirms removal of a persistent request identified by a client token.
 *   <li>Distinguishes between global and session-scoped persistence via the {@code global} flag.
 *   <li>Intended for server-to-client flow; inbound use is treated as a protocol error.
 * </ul>
 *
 * @see RemovePersistentRequest
 */
public class PersistentRequestRemovedMessage extends FCPMessage {

  private final String ident;
  private final boolean global;

  /**
   * Creates a confirmation message for a removed persistent request.
   *
   * <p>The constructor captures only immutable metadata required by the client to correlate the
   * acknowledgement with its original removal instruction. Callers should supply the exact
   * identifier previously used when submitting the request; no normalization is performed. The
   * {@code global} flag mirrors the scope used during removal so clients can distinguish between
   * per-session and node-wide persistent queues. Instances are light-weight and can be constructed
   * on demand for immediate dispatch.
   *
   * @param identifier unique token provided by the client when the request was created; must not be
   *     {@code null}.
   * @param global {@code true} when the removal applied to the node-wide persistent store rather
   *     than only the session-scoped queue.
   */
  public PersistentRequestRemovedMessage(String identifier, boolean global) {
    this.ident = identifier;
    this.global = global;
  }

  /**
   * Serializes this message into the FCP field set for transmission.
   *
   * <p>The resulting field set contains the original client-supplied {@code Identifier} so the
   * recipient can correlate the acknowledgement, plus the {@code Global} boolean mirroring the
   * removal scope. The method allocates a fresh {@link SimpleFieldSet} on each call and does not
   * retain references to external data. Callers are expected to treat the returned instance as
   * mutable only until it is written to the wire; subsequent modifications do not affect this
   * message object.
   *
   * @return a new {@link SimpleFieldSet} with {@code Identifier} and {@code Global} entries encoded
   *     exactly as stored in this message.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", ident);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Returns the FCP message name identifying this acknowledgement type.
   *
   * <p>The name is a fixed protocol token used by clients to dispatch handler logic upon receipt.
   * It is stable across versions and does not depend on instance state, so callers may cache the
   * result safely. Invocations are side effect free and constant time.
   *
   * @return the literal string {@code "PersistentRequestRemoved"} representing this message type.
   */
  @Override
  public String getName() {
    return "PersistentRequestRemoved";
  }

  /**
   * Rejects client-side attempts to process this server-originated message.
   *
   * <p>In the FCP protocol this message travels from the node to the client only. If a client
   * erroneously sends it back to the node, the handler calls this method and an exception is raised
   * to signal a protocol violation. No state is mutated and the failure surfaces as a structured
   * {@link MessageInvalidException}. Callers should not invoke this method during normal outbound
   * handling; it exists solely to satisfy the {@link FCPMessage} contract for inbound dispatch.
   *
   * @param handler connection handler that attempted to route the message; never modified by this
   *     method.
   * @param node node instance receiving the message; included for interface parity and not used
   *     here.
   * @throws MessageInvalidException always thrown to indicate that this message is invalid when
   *     sent toward the node.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentRequestRemoved goes from server to client not the other way around",
        ident,
        global);
  }
}
