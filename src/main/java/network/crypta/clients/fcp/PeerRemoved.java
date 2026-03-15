package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Notifies an FCP client that a peer was removed from the node's peer list.
 *
 * <p>The server emits this message when it drops a previously known peer, allowing clients that
 * cache peer metadata to evict stale entries and stop scheduling activity for that peer. The
 * message carries the remote peer's identity, the locally assigned node identifier, and the
 * optional client-supplied identifier used to correlate asynchronous events. Instances are
 * immutable after creation and are intended to be serialized directly to the FCP wire format via
 * {@link #getFieldSet()}.
 *
 * <p>Typical consumers enqueue the message for delivery to a connected client session, and do not
 * reuse or modify it across threads. The class itself is thread-safe because it exposes only final
 * state, but concurrent dispatchers should still avoid sharing mutable transport buffers. As part
 * of the server-to-client event stream it obeys the FCP rule that clients never send this message
 * back to the server; attempts to do so are rejected by {@link #run(FCPConnectionHandler)}.
 *
 * <ul>
 *   <li>Represents a peer removal event originating from the server.
 *   <li>Encapsulates identity, node identifier, and an optional correlation token.
 *   <li>Serializable through {@link SimpleFieldSet} for FCP transport.
 * </ul>
 *
 * @see FCPMessage
 * @see SimpleFieldSet
 */
public class PeerRemoved extends FCPMessage {

  static final String NAME = "PeerRemoved";
  final String identity;
  final String nodeIdentifier;
  final String messageIdentifier;

  /**
   * Creates a removal notification with the identifiers needed by downstream FCP clients.
   *
   * <p>The constructor captures the remote peer's long-term {@code identity}, the local {@code
   * nodeIdentifier} used within this node's peer registry, and an optional {@code identifier}
   * chosen by the client when it subscribed to peer events. All arguments are stored verbatim and
   * are not validated here; callers should pass canonical values. The resulting instance is
   * immutable and can be safely shared for read-only use across components that emit FCP messages.
   *
   * @param identity canonical identity string for the removed peer; never {@code null}
   * @param identifier optional client correlation token; may be {@code null} when unspecified
   */
  public PeerRemoved(String identity, String nodeIdentifier, String identifier) {
    this.identity = identity;
    this.nodeIdentifier = nodeIdentifier;
    this.messageIdentifier = identifier;
  }

  /**
   * Builds the FCP field set representing this removal event for wire transmission.
   *
   * <p>The returned {@link SimpleFieldSet} includes the mandatory {@code Identity} and {@code
   * NodeIdentifier} entries. When a client-supplied message identifier is present it is emitted as
   * {@code Identifier}; otherwise that field is omitted. The field set is created fresh on each
   * call and is safe for the caller to mutate or serialize without affecting this instance.
   *
   * @return new field set containing identity, node identifier, and optional correlation token
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identity", identity);
    fs.putSingle("NodeIdentifier", nodeIdentifier);
    if (messageIdentifier != null) fs.putSingle("Identifier", messageIdentifier);
    return fs;
  }

  /**
   * Returns the protocol-level name that identifies this FCP message type.
   *
   * <p>The name is a stable constant used by encoders and decoders to route messages through the
   * correct handlers. It does not vary with instance state and is always {@code "PeerRemoved"}.
   *
   * @return constant string {@code "PeerRemoved"} identifying the message on the wire
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects client attempts to send this server-only event back to the node.
   *
   * <p>Because {@code PeerRemoved} is defined as a server-to-client notification, any invocation of
   * this method from a client handler results in a {@link MessageInvalidException} that maps to the
   * {@link ProtocolErrorMessage#INVALID_MESSAGE} error. The exception includes the original message
   * identifier, when provided, so clients can correlate the rejection. The method performs no other
   * side effects and is intentionally non-idempotent only in that it always throws.
   *
   * @param handler connection handler that attempted to process the message; never {@code null}
   * @throws MessageInvalidException always thrown to signal that the direction is unsupported
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PeerRemoved goes from server to client not the other way around",
        messageIdentifier,
        false);
  }
}
