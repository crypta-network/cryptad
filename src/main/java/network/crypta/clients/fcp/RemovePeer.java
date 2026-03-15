package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.RemovedPeerSnapshot;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;

/**
 * Handles the FCP {@code RemovePeer} command by orchestrating the removal of a peer that is
 * currently known to the node and reporting the outcome back to the client session.
 *
 * <p>The handler extracts the peer identifier, validates full-access privileges, resolves the peer
 * in the routing table, and either removes the connection with a {@link PeerRemoved} acknowledgment
 * or reports an {@link UnknownNodeIdentifierMessage}. It preserves the caller-provided message
 * identifier so asynchronous replies can be correlated and avoids touching the node when required
 * fields are missing.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Enforcing that only fully privileged clients may remove peers.
 *   <li>Resolving and validating the requested peer before any destructive action.
 *   <li>Emitting protocol-level acknowledgments that reflect success or descriptive failure.
 * </ul>
 *
 * <p>Instances are short-lived and not thread-safe; a single {@link #run(FCPConnectionHandler)}
 * invocation should be used per incoming request on the handler thread. The original {@link
 * SimpleFieldSet} is retained by reference, so callers should not reuse it concurrently.
 *
 * @see PeerRemoved
 * @see UnknownNodeIdentifierMessage
 * @see Node
 */
public class RemovePeer extends FCPMessage {

  static final String NAME = "RemovePeer";

  final SimpleFieldSet fs;
  final String messageIdentifier;

  /**
   * Creates a handler for an incoming {@code RemovePeer} request and captures the message
   * identifier used for correlating responses.
   *
   * <p>The constructor reads the {@code Identifier} field from the supplied {@link SimpleFieldSet}
   * to keep it available for later replies and removes it from the mutable field set to avoid
   * accidental forwarding. The remaining fields, including {@code NodeIdentifier}, are processed
   * during {@link #run(FCPConnectionHandler)}. Reference retains the supplied field set, so callers
   * should not modify it after construction if consistent behavior is required.
   *
   * @param fs inbound protocol fields for this request; must contain {@code Identifier} and is
   *     expected to contain {@code NodeIdentifier} when {@link #run(FCPConnectionHandler)} is
   *     invoked; must be non-null and remain stable for the lifetime of this instance.
   */
  public RemovePeer(SimpleFieldSet fs) {
    this.fs = fs;
    messageIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  /**
   * Returns an empty field set because this message type does not send a body back to the client
   * during dispatch.
   *
   * <p>The returned instance is freshly allocated and marked as case-insensitive, matching the
   * expectations of other FCP message builders. Callers can treat it as immutable for sending but
   * should avoid caching it across messages because it carries no payload.
   *
   * @return new {@link SimpleFieldSet} with no entries, suitable for immediate transmission.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Reports the protocol-level name for this FCP message.
   *
   * <p>The name is a constant string defined by the FCP specification and is used by connection
   * handlers to route messages to the correct implementation. It does not vary per instance and can
   * be compared using reference equality in performance-sensitive paths if desired.
   *
   * @return the literal {@code "RemovePeer"} identifier used by the protocol.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the removal request against the provided node, validating access and sending the
   * appropriate protocol response.
   *
   * <p>The handler must have full access; otherwise a {@link MessageInvalidException} with an
   * {@link ProtocolErrorMessage#ACCESS_DENIED} error is thrown. When the {@code NodeIdentifier}
   * field is missing, the method signals a {@link ProtocolErrorMessage#MISSING_FIELD} error. If a
   * matching peer exists, it is detached through the runtime peer-management SPI and a {@link
   * PeerRemoved} acknowledgment is sent. Unknown peer identifiers yield an {@link
   * UnknownNodeIdentifierMessage}. No state beyond the current invocation is retained, and the
   * method is not idempotent if the peer list changes between calls.
   *
   * <pre>{@code
   * // Example: remove a peer by its node identifier
   * var message = new RemovePeer(fields);
   * message.run(handler);
   * }</pre>
   *
   * @param handler connection handler responsible for sending responses; must provide full-access
   *     privileges for the operation to proceed and must not be null.
   * @throws MessageInvalidException when access is denied or required, fields are absent, halting
   *     further processing and surfacing a protocol-level error to the caller.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          NAME + " requires full access",
          messageIdentifier,
          false);
    }
    String nodeIdentifier = fs.get("NodeIdentifier");
    if (nodeIdentifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Error: NodeIdentifier field missing",
          messageIdentifier,
          false);
    }
    try {
      RemovedPeerSnapshot removedPeer = handler.getServer().runtime().peer().remove(nodeIdentifier);
      handler.send(
          new PeerRemoved(removedPeer.identity(), removedPeer.nodeIdentifier(), messageIdentifier));
    } catch (UnknownPeerException _) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, messageIdentifier);
      handler.send(msg);
    }
  }
}
