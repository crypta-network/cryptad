package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Packages node reference data for transmission from the server to an FCP client.
 *
 * <p>This message captures a snapshot of the current node identity and connectivity information
 * produced by the supplied {@link Node}. Callers choose whether to emit opennet or darknet
 * references, whether to include private details intended only for trusted peers, and whether to
 * append transient volatile metadata. Instances are immutable after construction; serialization is
 * deferred until {@link #getFieldSet()} is invoked, so the referenced {@code Node} should remain
 * stable while export occurs. The message is intentionally one-directional: it is created by the
 * server side when answering discovery or status requests and must not be sent from clients.
 * Concurrency expectations match the node: callers should invoke export methods within the node's
 * usual synchronization regime to avoid racing configuration updates.
 *
 * <ul>
 *   <li>Selects opennet or darknet representations based on {@code giveOpennetRef}.
 *   <li>Optionally includes private and volatile subsets for richer diagnostics.
 *   <li>Echoes an optional identifier to correlate responses with client requests.
 * </ul>
 */
public class NodeData extends FCPMessage {

  static final String NAME = "NodeData";

  final Node node;
  final boolean giveOpennetRef;
  final boolean withPrivate;
  final boolean withVolatile;
  final String requestIdentifier;

  /**
   * Creates an immutable message wrapper around the node's reference exports.
   *
   * <p>The constructor only stores references and flags; it does not perform expensive exports.
   * Actual serialization happens when {@link #getFieldSet()} is called, allowing callers to defer
   * work until just before a response is written. No validation is performed here, so callers must
   * ensure the {@link Node} has up-to-date reference data and that privacy flags reflect the
   * intended audience. Providing a {@code null} identifier omits the {@code Identifier} field and
   * yields an anonymous response. Instances are safe to reuse across requests as long as the
   * underlying node state remains consistent with the chosen visibility settings.
   *
   * <pre>{@code
   * NodeData payload = new NodeData(node, true, true, false, "req-42");
   * SimpleFieldSet fs = payload.getFieldSet();
   * }</pre>
   *
   * @param node Node providing reference data to serialize; must not be null.
   * @param giveOpennetRef true to export opennet reference, false for darknet details instead.
   * @param withPrivate true to include private elements intended for trusted peers only.
   * @param withVolatile true to append transient volatile metadata when available from the node.
   * @param requestIdentifier optional identifier echoed in the {@code Identifier} field; nullable.
   */
  public NodeData(
      Node node,
      boolean giveOpennetRef,
      boolean withPrivate,
      boolean withVolatile,
      String requestIdentifier) {
    this.node = node;
    this.giveOpennetRef = giveOpennetRef;
    this.withPrivate = withPrivate;
    this.withVolatile = withVolatile;
    this.requestIdentifier = requestIdentifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} containing the requested node reference details.
   *
   * <p>This method invokes the appropriate export routine on the backing {@link Node}, choosing
   * between opennet and darknet forms and adding private content when requested. When {@code
   * withVolatile} is set, it merges the node's volatile field set under the {@code volatile} key if
   * present. If a {@code requestIdentifier} was provided at construction time, it is written under
   * the {@code Identifier} key so clients can correlate responses. The returned field set is newly
   * allocated by the node export routines; callers may modify it without affecting shared state.
   *
   * @return SimpleFieldSet containing the selected node reference data; never null.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs;
    if (giveOpennetRef) {
      if (withPrivate) {
        fs = node.exportOpennetPrivateFieldSet();
      } else {
        fs = node.exportOpennetPublicFieldSet();
      }
    } else {
      if (withPrivate) {
        fs = node.exportDarknetPrivateFieldSet();
      } else {
        fs = node.exportDarknetPublicFieldSet();
      }
    }
    if (withVolatile) {
      SimpleFieldSet vol = node.exportVolatileFieldSet();
      if (!vol.isEmpty()) {
        fs.put("volatile", vol);
      }
    }
    if (requestIdentifier != null) {
      fs.putSingle("Identifier", requestIdentifier);
    }
    return fs;
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
