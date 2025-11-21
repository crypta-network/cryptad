package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;

/**
 * Client-to-node FCP message that requests detailed information about a specific peer maintained by
 * the destination node.
 *
 * <p>This lightweight wrapper is used when a client needs the status of a single peer—for example
 * to display link health or drive automated peer-admission decisions. It stores the caller-provided
 * request identifier and the field set that supplies {@code NodeIdentifier} during execution. When
 * run, the message enforces full-access permissions, validates the identifier, and emits either a
 * populated {@link PeerMessage} or an {@link UnknownNodeIdentifierMessage} error. Instances hold no
 * mutable state beyond the supplied {@link SimpleFieldSet}, allowing them to be passed across
 * threads provided that field set is not mutated concurrently.
 *
 * <ul>
 *   <li>Requires authenticated clients to have full FCP access before proceeding.
 *   <li>Performs strict {@code NodeIdentifier} validation before touching network state.
 *   <li>Emits structured protocol errors rather than silent failures for missing or unknown peers.
 * </ul>
 *
 * @see PeerMessage
 * @see UnknownNodeIdentifierMessage
 */
public class ListPeerMessage extends FCPMessage {

  static final String NAME = "ListPeer";

  final SimpleFieldSet fs;
  final String requestIdentifier;

  /**
   * Builds the message from an incoming field set, capturing the request identifier and removing it
   * from the payload.
   *
   * <p>The supplied {@link SimpleFieldSet} must include an {@code Identifier} entry used for
   * correlating responses; it is extracted and deleted immediately to avoid forwarding client
   * metadata unnecessarily. Callers may populate additional fields such as {@code NodeIdentifier}
   * before invoking {@link #run(FCPConnectionHandler, Node)}. The constructor keeps a direct
   * reference to the field set, so external mutations after construction will be visible during
   * execution.
   *
   * @param fs mutable field set containing request metadata; must include {@code Identifier} and
   *     should eventually include {@code NodeIdentifier}; must not be {@code null}.
   */
  public ListPeerMessage(SimpleFieldSet fs) {
    this.fs = fs;
    this.requestIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  /**
   * Provides the outgoing field set for serialization.
   *
   * <p>This implementation returns a new, empty {@link SimpleFieldSet} because all request data is
   * consumed during {@link #run(FCPConnectionHandler, Node)}. Callers may mutate the returned set
   * without affecting the original message.
   *
   * @return a freshly created, empty {@link SimpleFieldSet} instance.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Reports the protocol-level name used when this message travels over FCP.
   *
   * <p>The value is constant and shared by all instances; it is relied on by dispatchers to route
   * incoming traffic and by logs or metrics to tag peer-list requests consistently.
   *
   * @return the literal message name {@code "ListPeer"}.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Validates permissions and peer identity, then responds with details or a suitable error.
   *
   * <p>The handler must expose full-access credentials; otherwise a {@link MessageInvalidException}
   * with {@link ProtocolErrorMessage#ACCESS_DENIED} is thrown. A {@code NodeIdentifier} field is
   * required and validated. Missing values cause a missing-field error; unknown peers produce an
   * {@link UnknownNodeIdentifierMessage}. When the peer exists, a {@link PeerMessage} describing it
   * is sent. The method is synchronous and read-only; it does not retry, cache results, or alter
   * node state.
   *
   * @param handler connection handler that validates permissions and dispatches replies; must not
   *     be {@code null}.
   * @param node target node queried for peer information; must not be {@code null}.
   * @throws MessageInvalidException when access is denied or required fields are absent.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ListPeer requires full access",
          requestIdentifier,
          false);
    }
    String nodeIdentifier = fs.get("NodeIdentifier");
    if (nodeIdentifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Error: NodeIdentifier field missing",
          requestIdentifier,
          false);
    }
    PeerNode pn = node.getPeerNode(nodeIdentifier);
    if (pn == null) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, requestIdentifier);
      handler.send(msg);
      return;
    }
    handler.send(new PeerMessage(pn, true, true, requestIdentifier));
  }
}
