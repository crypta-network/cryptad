package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the server-to-client completion notice for a peer-bound send operation.
 *
 * <p>Instances of this message are produced by {@link SendPeerMessage} once the node has attempted
 * to deliver data or a control update to a darknet peer. They mirror the caller-supplied identifier
 * and include the integer status code returned by the peer-facing logic so clients can correlate
 * asynchronous outcomes, even when multiple sends are queued over the same FCP connection. The
 * class is immutable, carries no side effects, and is intended to be serialized immediately after
 * construction rather than retained long term. Because it is purely a response envelope, invoking
 * {@link #run(FCPConnectionHandler, Node)} is invalid and will always raise a protocol error to
 * guard against direction mistakes.
 *
 * <ul>
 *   <li>Echoes the client-provided identifier for correlation with outstanding requests.
 *   <li>Conveys the numeric status emitted by peer-specific send handlers.
 *   <li>Enforces server-to-client direction by rejecting handler execution attempts.
 * </ul>
 *
 * @see SendPeerMessage
 * @see FCPMessage
 */
public class SentPeerMessage extends FCPMessage {

  /**
   * Canonical FCP message name used during serialization, logging, and dispatch routing for
   * SentPeer notifications sent from the node to the client. The value is stable across releases so
   * downstream handlers can match responses without inspecting payload fields.
   */
  public static final String NAME = "SentPeer";

  /**
   * Optional client correlation token supplied by the original send request; may be {@code null}
   * when the caller did not provide an identifier but is otherwise echoed unchanged.
   */
  public final String clientIdentifier;

  /**
   * Status code reported by the peer-facing send logic; consumers interpret the numeric range
   * according to the originating {@link SendPeerMessage} subclass.
   */
  public final int nodeStatus;

  /**
   * Creates an immutable notification carrying the original client identifier and resulting peer
   * status code.
   *
   * <p>The constructor performs no validation or I/O; it simply stores the supplied values so they
   * can be serialized back to the requesting client. Callers may pass {@code null} identifiers when
   * correlation is unnecessary, and they may forward any integer status value, including sentinel
   * negatives, without reinterpretation. Instances are lightweight and thread-safe for concurrent
   * reads, but they are expected to be short-lived and emitted immediately after a peer send
   * completes.
   *
   * @param identifier client-provided token used to match responses to requests; may be {@code
   *     null} when the client omitted the field in its send command.
   * @param nodeStatus integer status reported by peer-handling logic; range and meaning are defined
   *     by the originating send command implementation.
   */
  public SentPeerMessage(String identifier, int nodeStatus) {
    this.clientIdentifier = identifier;
    this.nodeStatus = nodeStatus;
  }

  /**
   * Serializes the message into a mutable {@link SimpleFieldSet} for transmission to the client.
   *
   * <p>The field set always contains {@code Identifier} and {@code NodeStatus} entries mirroring
   * the values supplied at construction time. Callers may append additional keys if transport
   * framing requires them, but this method does not alter or filter the stored fields. The returned
   * instance is independent of any internal state, allowing safe reuse across encoding steps.
   *
   * @return new field set containing identifier and node status values ready for FCP encoding.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", clientIdentifier);
    fs.put("NodeStatus", nodeStatus);
    // Textual description of the node status is handled by consuming clients if needed.
    return fs;
  }

  /**
   * Returns the canonical FCP message name for this response type.
   *
   * <p>The value is stable and shared across all instances so connection handlers can route or
   * serialize messages without inspecting their contents. Because the direction is strictly
   * server-to-client, callers typically invoke this when constructing outgoing frames rather than
   * during inbound parsing.
   *
   * @return constant string {@code "SentPeer"} identifying the message on the wire.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects attempts to process the message as an inbound client command.
   *
   * <p>SentPeer is defined as a server-originated notification. If a client tries to submit it, the
   * method throws a {@link MessageInvalidException} with a protocol error code to signal incorrect
   * direction. No state is mutated and no network I/O occurs beyond the exception-handling pathway.
   *
   * @param handler active connection handler that attempted to dispatch the message; never used for
   *     successful execution because the message should not arrive from a client.
   * @param node local node instance supplied by the dispatcher; unused because execution always
   *     aborts before any node interaction.
   * @throws MessageInvalidException always thrown to indicate the message cannot be sent by a
   *     client under the FCP protocol rules.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        getName() + " goes from server to client not the other way around",
        clientIdentifier,
        false);
  }
}
