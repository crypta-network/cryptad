package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the {@code ListPeers} FCP command sent from a client to the node to get the current
 * set of known peers.
 *
 * <p>This message is read-only and simply instructs the node to list its peers without changing
 * state. Instances are immutable once created; the flags provided by the client are stored in final
 * fields and reused when generating individual peer responses. Typical callers create one instance
 * per request, hand it to the {@link FCPConnectionHandler}, and rely on the handler to stream
 * {@link PeerMessage} objects back to the client followed by {@link EndListPeersMessage} as a
 * terminator.
 *
 * <p>Use this command when a UI or monitoring tool needs a snapshot of active peers along with
 * optional metadata or volatile runtime statistics. The message runs within the handler's thread
 * and assumes the handler has full access; access checks occur before any network I/O to avoid
 * exposing partial data. Because processing only iterates over the current peer array and sends
 * each entry, runtime scales linearly with peer count.
 *
 * <ul>
 *   <li>Includes metadata when {@code WithMetadata=true} in the source field set.
 *   <li>Includes volatile runtime counters when {@code WithVolatile=true} is present.
 *   <li>Always appends a terminal {@code EndListPeers} message to mark completion.
 * </ul>
 */
public class ListPeersMessage extends FCPMessage {

  final boolean withMetadata;
  final boolean withVolatile;
  final String requestIdentifier;
  static final String NAME = "ListPeers";

  /**
   * Builds a message instance from the inbound {@link SimpleFieldSet} supplied by the FCP client.
   *
   * <p>The field set is expected to contain boolean flags named {@code WithMetadata} and {@code
   * WithVolatile}; missing entries default to {@code false}. The constructor also captures the
   * caller-provided {@code Identifier} so downstream responses can be correlated by the client
   * connection. The identifier is removed from the field set to avoid forwarding it back in peer
   * responses.
   *
   * @param fs field collection originating from the client request; must not be {@code null} and
   *     may include {@code WithMetadata}, {@code WithVolatile}, and {@code Identifier} entries.
   */
  public ListPeersMessage(SimpleFieldSet fs) {
    withMetadata = fs.getBoolean("WithMetadata", false);
    withVolatile = fs.getBoolean("WithVolatile", false);
    this.requestIdentifier = fs.get(FCPMessage.IDENTIFIER);
    fs.removeValue(FCPMessage.IDENTIFIER);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command does not require a request body, so it returns an empty, ordered {@link
   * SimpleFieldSet}. Callers should not mutate the returned instance.
   *
   * @return fresh field set containing only a root node, suitable for immediate serialization.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The literal name {@code ListPeers} is stable and defined by the FCP protocol. Clients send
   * this value in the {@code MessageName} field to request peer enumeration.
   *
   * @return static protocol string {@code ListPeers} used to dispatch this message type.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the request by streaming peer details to the connected client.
   *
   * <p>The handler must have full access; otherwise a {@link ProtocolErrorMessage#ACCESS_DENIED}
   * response is sent via {@link MessageInvalidException}. When authorized, the method iterates the
   * node's current peer list, emits a {@link PeerMessage} for each peer with the selected metadata
   * flags, and finally emits {@link EndListPeersMessage} to signal completion. Execution occurs on
   * the handler's thread, so callers should avoid invoking it from long-running blocking contexts
   * to keep connection responsiveness predictable.
   *
   * @param handler connection handler responsible for sending responses; must already be
   *     authenticated for full access.
   * @param node node instance supplied by the legacy FCP dispatch signature; unused because peer
   *     enumeration is delegated through the runtime SPI
   * @throws MessageInvalidException when the handler lacks required access rights or when message
   *     validation fails before any peer data is returned.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ListPeers requires full access",
          requestIdentifier,
          false);
    }
    for (PeerSnapshot snapshot :
        handler.getServer().runtime().peer().list(withMetadata, withVolatile)) {
      handler.send(new PeerMessage(snapshot, requestIdentifier));
    }

    handler.send(new EndListPeersMessage(requestIdentifier));
  }
}
