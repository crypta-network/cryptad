package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message sent from the node to an FCP client when a previously loaded plugin is removed.
 *
 * <p>The payload carries the client-provided identifier and the human-readable plugin name so the
 * client can correlate the event with earlier management requests or UI state. Instances are
 * created on the server side only; if a client attempts to emit this message it is rejected as an
 * invalid request. This class does not mutate after construction, making it safe to share across
 * threads that stream FCP responses or audit network traffic.
 *
 * <p>Typical consumers subscribe to removal events while maintaining a synchronized plugin list in
 * the UI or persistence layer. After receiving the message, clients should drop any cached
 * capabilities for the named plugin and update in-progress workflows that relied on it. The message
 * is small and allocates only the two string fields it exposes, so multiple instances can be
 * buffered without noticeable overhead during bursts of plugin churn.
 *
 * <ul>
 *   <li>Direction: server to client only; outbound client use is rejected.
 *   <li>Thread-safety: immutable after construction; safe for concurrent dispatch.
 *   <li>Correlates: identifier echoes client request tokens; pluginName matches plugin manifest.
 * </ul>
 *
 * @see FCPMessage
 */
public class PluginRemovedMessage extends FCPMessage {

  static final String NAME = "PluginRemoved";

  private final String identifierValue;

  private final String plugname;

  PluginRemovedMessage(String plugname2, String identifier2) {
    this.identifierValue = identifier2;
    this.plugname = plugname2;
  }

  /**
   * Builds the serialized representation of this message for transmission over the FCP wire format.
   * It returns a new {@link SimpleFieldSet} containing the caller-provided identifier under the
   * {@code Identifier} key and the human-readable plugin name under {@code PluginName}. The
   * resulting structure is independent of the original instance and can be queued or reused by the
   * transport layer without additional synchronization. Neither field is optional; callers should
   * ensure meaningful values were provided at construction time before invoking this method.
   *
   * @return a {@link SimpleFieldSet} with single-valued Identifier and PluginName entries ready for
   *     sending
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Identifier", identifierValue);
    sfs.putSingle("PluginName", plugname);
    return sfs;
  }

  /**
   * Returns the canonical FCP name for this message type, which remains constant across protocol
   * versions and is used by both the server dispatcher and clients to route handling logic. The
   * value is stable and can be logged or compared without additional normalization. Because the
   * name never changes for the lifetime of the object, repeated invocations are safe and allocate
   * no new state.
   *
   * @return the literal message name {@code PluginRemoved} used on the FCP wire protocol
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects inbound handling because {@code PluginRemoved} is strictly a server-to-client
   * notification. Any attempt by a client to send this message back to the server is converted into
   * a {@link MessageInvalidException} with the {@link ProtocolErrorMessage#INVALID_MESSAGE} code so
   * callers receive consistent protocol-level feedback. The method does not inspect the connection
   * or node state; it unconditionally signals the error to prevent accidental misuse and maintain
   * the one-way contract of plugin removal notifications.
   *
   * @param handler the connection handler that attempted to process the incoming message; never
   *     modified but included for protocol parity
   * @param node the running node instance associated with the handler; ignored because processing
   *     is unsupported in this direction
   * @throws MessageInvalidException always thrown to indicate the message is invalid from client to
   *     server
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        null,
        false);
  }
}
