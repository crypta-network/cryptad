package network.crypta.clients.fcp;

import java.util.Map;
import java.util.Objects;
import network.crypta.node.Node;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.support.SimpleFieldSet;

/**
 * Packages node reference data for transmission from the server to an FCP client.
 *
 * <p>This message carries a detached {@link NodeReferenceSnapshot} produced by the runtime SPI.
 * Callers choose the requested reference view before constructing the message, and serialization is
 * deferred until {@link #getFieldSet()} rebuilds a fresh {@link SimpleFieldSet}. The message is
 * intentionally one-directional: it is created by the server side when answering discovery or
 * status requests and must not be sent from clients.
 *
 * <ul>
 *   <li>Rebuilds the historical node-reference tree from an immutable runtime snapshot.
 *   <li>Echoes an optional identifier to correlate responses with client requests.
 * </ul>
 */
public class NodeData extends FCPMessage {

  static final String NAME = "NodeData";

  final NodeReferenceSnapshot snapshot;
  final String requestIdentifier;

  /**
   * Creates an immutable message wrapper around a detached node-reference snapshot.
   *
   * <p>The constructor stores only the immutable snapshot and optional request identifier; it does
   * not perform additional runtime lookups. Actual serialization happens when {@link
   * #getFieldSet()} is called, allowing callers to defer wire reconstruction until just before a
   * response is written. Providing a {@code null} identifier omits the {@code Identifier} field and
   * yields an anonymous response.
   *
   * <pre>{@code
   * NodeData payload =
   *     new NodeData(
   *         new NodeReferenceSnapshot(new NodeFieldSet(Map.of("identity", "alpha"), Map.of())),
   *         "req-42");
   * SimpleFieldSet fs = payload.getFieldSet();
   * }</pre>
   *
   * @param snapshot runtime-exported node-reference snapshot to serialize
   * @param requestIdentifier optional identifier echoed in the {@code Identifier} field; nullable.
   */
  public NodeData(NodeReferenceSnapshot snapshot, String requestIdentifier) {
    this.snapshot = Objects.requireNonNull(snapshot);
    this.requestIdentifier = requestIdentifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} containing the requested node reference details.
   *
   * <p>This method rebuilds the historical node-reference tree from the stored snapshot and writes
   * the optional identifier under the {@code Identifier} key so clients can correlate responses.
   * The returned field set is newly allocated for each call; callers may modify it without
   * affecting the stored snapshot or future serializations.
   *
   * @return SimpleFieldSet containing the selected node reference data; never null.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = toSimpleFieldSet(snapshot.root());
    if (requestIdentifier != null) {
      fs.putSingle("Identifier", requestIdentifier);
    }
    return fs;
  }

  private static SimpleFieldSet toSimpleFieldSet(NodeFieldSet source) {
    SimpleFieldSet target = new SimpleFieldSet(true);
    for (Map.Entry<String, String> entry : source.directValues().entrySet()) {
      target.putSingle(entry.getKey(), entry.getValue());
    }
    for (Map.Entry<String, NodeFieldSet> entry : source.directSubsets().entrySet()) {
      target.tput(entry.getKey(), toSimpleFieldSet(entry.getValue()));
    }
    return target;
  }

  /**
   * Provides the FCP message name associated with this payload.
   *
   * <p>The name is constant and used by framing logic when sending the message over the wire. It is
   * independent of the export flags, ensuring consistent dispatch handling on the client side.
   *
   * @return Constant message name {@code NodeData} used in outbound FCP frames.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects client-originated execution because {@code NodeData} is server-to-client only.
   *
   * <p>Any attempt to process this message on the server side results in an explicit {@link
   * MessageInvalidException}. This guards against misuse of the class for inbound traffic and
   * preserves the directional contract of the FCP exchange. Callers should never invoke this method
   * directly; it exists solely to satisfy the {@link FCPMessage} interface and enforce protocol
   * correctness.
   *
   * @param handler connection handler that attempted to route the message; ignored after failure.
   * @param node node instance associated with the connection; not used because execution is
   *     blocked.
   * @throws MessageInvalidException whenever invoked because clients must not send {@code
   *     NodeData}.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "NodeData goes from server to client not the other way around",
        requestIdentifier,
        false);
  }
}
