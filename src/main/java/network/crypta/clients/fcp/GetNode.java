package network.crypta.clients.fcp;

import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.support.SimpleFieldSet;

/**
 * FCP message that requests node metadata to send back to a privileged client connection.
 *
 * <p>This message acts as a thin wrapper around {@link NodeData}, capturing caller preferences
 * about which portions of the node description should be exposed. Typical flows construct the
 * {@code GetNode} from an inbound {@link SimpleFieldSet}, validate access, and then let the
 * connection handler serialize the resulting {@code NodeData}. Instances are short-lived and carry
 * only immutable flags, so multiple threads can safely reuse them once created. The request only
 * succeeds for callers with full access, ensuring that private or volatile state is not leaked to
 * limited-control peers. Consumers should prefer this operation when they need a snapshot of
 * current node capabilities or contact references without performing additional network I/O.
 *
 * <ul>
 *   <li>Honors optional flags to include opennet references, private state, and volatile details.
 *   <li>Copies a caller-supplied identifier so clients can correlate responses.
 *   <li>Does not mutate the source field set beyond removing the identifier key.
 * </ul>
 */
public class GetNode extends FCPMessage {

  final boolean giveOpennetRef;
  final boolean withPrivate;
  final boolean withVolatile;
  static final String NAME = "GetNode";
  final String requestIdentifier;

  /**
   * Creates a {@code GetNode} message by extracting request flags from the supplied field set.
   *
   * <p>The constructor reads the caller's desired visibility settings, records the optional request
   * identifier, and removes that identifier from the source {@link SimpleFieldSet} to prevent
   * duplicate propagation. The resulting instance is immutable, making it safe to hand off to
   * message handlers without further synchronization. Callers are expected to supply a field set
   * constructed from FCP input; missing flags fall back to {@code false}, keeping the response
   * minimal unless extra details are explicitly requested.
   *
   * @param fs field set carrying GiveOpennetRef/WithPrivate/WithVolatile flags and optional
   *     identifier.
   */
  public GetNode(SimpleFieldSet fs) {
    giveOpennetRef = fs.getBoolean("GiveOpennetRef", false);
    withPrivate = fs.getBoolean("WithPrivate", false);
    withVolatile = fs.getBoolean("WithVolatile", false);
    requestIdentifier = fs.get(FCPMessage.IDENTIFIER);
    fs.removeValue(FCPMessage.IDENTIFIER);
  }

  /**
   * Produces the outbound field set that echoes the request identifier when available.
   *
   * <p>The generated {@link SimpleFieldSet} intentionally omits the visibility flags because they
   * are consumed server side and only the identifier is required to correlate responses. The field
   * set is newly allocated for each call to avoid sharing mutable state across message processors.
   *
   * @return immutable-style field set containing only the identifier key when present; otherwise an
   *     empty set.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (requestIdentifier != null) fs.putSingle(FCPMessage.IDENTIFIER, requestIdentifier);
    return fs;
  }

  /**
   * Returns the protocol-visible name of this FCP message.
   *
   * <p>The name is constant and aligns with the value the peer expects when dispatching message
   * handlers, allowing callers to log or route the request predictably. Because the value is shared
   * by both client and server components, downstream code can key metrics, debugging logs, or
   * feature gates off this identifier without recalculating or duplicating literals. The monotonic
   * string also aids backwards compatibility by keeping the wire token stable even when internal
   * implementation details evolve.
   *
   * @return fixed {@code "GetNode"} token that identifies the message type on the wire.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the request by validating access and sending node details back to the client.
   *
   * <p>The handler must already be associated with a fully authorized connection; otherwise a
   * {@link ProtocolErrorMessage#ACCESS_DENIED} failure is raised. On success, it requests the
   * selected node-reference snapshot from the runtime SPI and emits a {@link NodeData} response
   * populated according to the stored flags, ensuring the caller receives only the amount of
   * information it asked for. The method performs no retries or partial responses; any failure
   * propagates via the thrown exception.
   *
   * @param handler connection handler performing access checks and delivering responses; must be
   *     authenticated.
   * @throws MessageInvalidException if the client lacks full access or the request violates
   *     protocol constraints.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "GetNode requires full access",
          requestIdentifier,
          false);
    }
    handler.send(
        new NodeData(
            handler.getServer().runtime().nodeInfo().exportReference(referenceView(), withVolatile),
            requestIdentifier));
  }

  private NodeReferenceView referenceView() {
    if (giveOpennetRef) {
      return withPrivate ? NodeReferenceView.OPENNET_PRIVATE : NodeReferenceView.OPENNET_PUBLIC;
    }
    return withPrivate ? NodeReferenceView.DARKNET_PRIVATE : NodeReferenceView.DARKNET_PUBLIC;
  }
}
