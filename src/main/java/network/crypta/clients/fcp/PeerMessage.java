package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the server-to-client {@code Peer} FCP message built from a {@link PeerNode} snapshot.
 * The message bundles identity information with optional metadata and volatile sections so clients
 * can render a peer list or perform diagnostics without extra node round-trips.
 *
 * <p>This type is lightweight and immutable; each instance captures the peer's exported fields at
 * the time the request is assembled. Callers choose whether to include metadata (calculated with
 * the current wall-clock timestamp) and volatile attributes. The {@link #run(FCPConnectionHandler,
 * Node)} method is unsupported on the client path and always rejects attempts to send this message
 * to the server.
 *
 * <ul>
 *   <li>Exports core peer state, plus optional metadata and volatile snapshots.
 *   <li>Encodes an optional message identifier so clients can correlate responses.
 *   <li>Designed for one-way delivery from server to client; not executed inbound.
 * </ul>
 *
 * <p>Instances are not thread-safe for mutation, but the exported {@link SimpleFieldSet} is
 * detached from the source peer so callers may reuse it across threads once created.
 *
 * @see PeerNode
 * @see SimpleFieldSet
 */
public class PeerMessage extends FCPMessage {
  static final String NAME = "Peer";

  final PeerNode pn;
  final boolean withMetadata;
  final boolean withVolatile;
  final String messageIdentifier;

  /**
   * Creates a {@code PeerMessage} that exports the provided peer snapshot with optional metadata
   * and volatile sections for downstream FCP clients.
   *
   * <p>The constructor does not perform deep copies; it defers to the {@link PeerNode} export
   * helpers when {@link #getFieldSet()} is invoked. Callers should therefore construct this message
   * close to dispatch time to keep the snapshot representative of the current node state. Supplying
   * both optional flags allows the receiver to render a complete view, while disabling them can
   * reduce payload size for bandwidth-sensitive environments.
   *
   * <pre>{@code
   * var message = new PeerMessage(peerNode, true, false, "ui-refresh-42");
   * sendToClient(message);
   * }</pre>
   *
   * @param pn peer node to serialize; must not be {@code null} when used
   * @param withMetadata include metadata snapshot using the current wall-clock timestamp
   * @param withVolatile include transient volatile attributes such as dynamic statistics
   * @param messageIdentifier optional caller-supplied token to correlate downstream responses
   */
  public PeerMessage(
      PeerNode pn, boolean withMetadata, boolean withVolatile, String messageIdentifier) {
    this.pn = pn;
    this.withMetadata = withMetadata;
    this.withVolatile = withVolatile;
    this.messageIdentifier = messageIdentifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} payload representing the peer state for FCP transmission.
   *
   * <p>The returned structure always includes the base peer fields exported by {@link
   * PeerNode#exportFieldSet()}. When {@code withMetadata} is enabled, it appends the current
   * metadata snapshot using the time of invocation to compute age-sensitive fields. When {@code
   * withVolatile} is enabled, it includes volatile statistics if present. Empty sections are
   * omitted to keep the message compact. If a non-null identifier was provided at construction, the
   * method also adds it under the {@code Identifier} key so clients can match responses.
   *
   * @return a mutable field set containing base peer data plus any requested optional sections
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = pn.exportFieldSet();
    if (withMetadata) {
      SimpleFieldSet meta = pn.exportMetadataFieldSet(System.currentTimeMillis());
      if (!meta.isEmpty()) {
        fs.put("metadata", meta);
      }
    }
    if (withVolatile) {
      SimpleFieldSet vol = pn.exportVolatileFieldSet();
      if (!vol.isEmpty()) {
        fs.put("volatile", vol);
      }
    }
    if (messageIdentifier != null) fs.putSingle("Identifier", messageIdentifier);
    return fs;
  }

  /**
   * Returns the fixed FCP message name used on the wire for peer descriptions.
   *
   * <p>The name is stable and shared across all instances so routing and parsing logic in FCP
   * handlers can match incoming messages efficiently. Because it returns a constant, this method is
   * effectively free of side effects and can be invoked frequently by higher-level dispatchers
   * without additional allocations.
   *
   * @return the literal {@code "Peer"} message identifier expected by FCP clients
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Always rejects attempts to process a {@code Peer} message from client to server.
   *
   * <p>Peer messages are intended solely for server-to-client delivery; invoking this method on an
   * inbound path signals a protocol violation. The method therefore throws a {@link
   * MessageInvalidException} with the {@link ProtocolErrorMessage#INVALID_MESSAGE} code to ensure
   * the caller receives a clear, predictable failure. No state changes occur before the exception
   * is raised, and the operation is idempotent because it never mutates either the handler or the
   * node.
   *
   * @param handler connection handler that attempted to execute the message; not mutated here
   * @param node node instance associated with the connection; unused because execution is rejected
   * @throws MessageInvalidException always thrown to indicate the direction is unsupported
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "Peer goes from server to client not the other way around",
        null,
        false);
  }
}
