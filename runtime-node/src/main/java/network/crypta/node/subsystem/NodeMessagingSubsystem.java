package network.crypta.node.subsystem;

import java.util.HashMap;
import java.util.Map;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeToNodeMessageListener;
import network.crypta.node.PeerNode;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates node-to-node messaging and routes FProxy text messages to the correct handlers.
 *
 * <p>This subsystem is a small routing layer that accepts decoded transport messages, extracts
 * message type metadata, and forwards the payload to either a registered {@link
 * NodeToNodeMessageListener} or an appropriate {@link DarknetPeerNode} handler. Callers typically
 * register listeners during node initialization, then invoke one of the {@code
 * receivedNodeToNodeMessage} entry points whenever a message arrives from the transport. For
 * text-based node-to-node messages, callers pass a parsed {@link SimpleFieldSet} into {@link
 * #handleNodeToNodeTextMessageSimpleFieldSet(SimpleFieldSet, DarknetPeerNode, int)}.
 *
 * <p>Thread safety is provided by synchronizing access to the listener registry. Message dispatch
 * itself is synchronous and does not mutate shared state beyond the listener lookup. The subsystem
 * does not own the lifetime of any buffers or field sets; callers retain ownership and must ensure
 * they remain valid for the duration of the call.
 *
 * <ul>
 *   <li>Maintains a type-to-listener registry for binary node-to-node messages.
 *   <li>Unpacks transport-level message wrappers into type and payload components.
 *   <li>Routes FProxy text messages based on type fields in {@link SimpleFieldSet}.
 * </ul>
 *
 * @see NodeToNodeMessageListener
 * @see DarknetPeerNode
 */
public final class NodeMessagingSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeMessagingSubsystem.class);

  private final Map<Integer, NodeToNodeMessageListener> n2nmListeners = new HashMap<>();

  /**
   * Creates a new messaging subsystem with an empty listener registry.
   *
   * <p>The subsystem has no mutable initialization state beyond the internal registry, so the
   * constructor performs no I/O and cannot fail. Callers are expected to register listeners before
   * dispatching any messages; otherwise, unknown message types are logged and discarded.
   */
  public NodeMessagingSubsystem() {
    // Intentionally empty: the subsystem has no initialization state.
  }

  /**
   * Registers or replaces the listener for a specific node-to-node message type.
   *
   * <p>This method is synchronized to protect the registry from concurrent updates. If a listener
   * is already registered for the given {@code type}, it is replaced without notification. The
   * registry is used only for binary node-to-node messages; text-based messages are routed through
   * {@link #handleNodeToNodeTextMessageSimpleFieldSet(SimpleFieldSet, DarknetPeerNode, int)}.
   *
   * <p>Callers should register listeners during node startup and avoid passing {@code null}
   * listeners, since a {@code null} entry will lead to a {@link NullPointerException} during
   * dispatch.
   *
   * @param type the numeric message type identifier used to select a listener.
   * @param listener the handler that processes payloads for the specified type.
   */
  public synchronized void registerNodeToNodeMessageListener(
      int type, NodeToNodeMessageListener listener) {
    n2nmListeners.put(type, listener);
  }

  /**
   * Handles a received node-to-node message provided by the transport layer.
   *
   * <p>This method extracts the type and payload buffer from the {@link Message} using the expected
   * {@link DMT} field keys, then delegates to the lower-level dispatcher. It does not modify the
   * message object and performs no validation beyond the field lookups, so callers should ensure
   * that the message contains the required fields.
   *
   * @param m the decoded message wrapper, including type and payload objects.
   * @param src the peer that sent the message.
   */
  public void receivedNodeToNodeMessage(Message m, PeerNode src) {
    int type = (Integer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_TYPE);
    ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
    receivedNodeToNodeMessage(src, type, messageData, false);
  }

  /**
   * Dispatches a binary node-to-node message to the registered listener for its type.
   *
   * <p>The listener registry is consulted under synchronization, but the listener callback runs
   * outside the synchronized block to avoid holding the registry lock during user code. If no
   * listener is registered for the provided {@code type}, the message is logged and discarded. The
   * {@code partingMessage} flag is used only for logging context and does not change dispatch
   * behavior.
   *
   * <p>This method is synchronous and does not retain references to the supplied buffer. Callers
   * should ensure {@code messageData} remains valid for the duration of the call.
   *
   * @param src the peer that sent the message and owns the connection state.
   * @param type the numeric message type identifier used to select a listener.
   * @param messageData the payload buffer containing the encoded message bytes.
   * @param partingMessage whether the message is associated with a peer parting sequence.
   */
  public void receivedNodeToNodeMessage(
      PeerNode src, int type, ShortBuffer messageData, boolean partingMessage) {
    boolean fromDarknet = src instanceof DarknetPeerNode;

    NodeToNodeMessageListener listener;
    synchronized (this) {
      listener = n2nmListeners.get(type);
    }

    if (listener == null) {
      LOG.error(
          "Unknown n2nm ID (parting={}): {} - discarding packet length {}",
          partingMessage,
          type,
          messageData.getLength());
      return;
    }

    listener.handleMessage(messageData.getData(), fromDarknet, src, type);
  }

  /**
   * Handles a node-to-node text message formatted as a {@link SimpleFieldSet}.
   *
   * <p>The method reads the overall message type from {@link Node#N2N_TYPE_KEY}, removes that key
   * from the field set, and routes the remainder to a type-specific handler. Only the FProxy
   * message family is recognized here; unknown types are logged and ignored. The field set is not
   * copied and must remain valid for the duration of the call.
   *
   * <p>Parsing is strict: missing or malformed fields will raise {@link FSParseException}. Callers
   * should treat this as a malformed peer message rather than a local configuration error.
   *
   * @param fs the parsed field set payload; caller retains ownership.
   * @param source the darknet peer that sent the message and will receive callbacks.
   * @param fileNumber extra-peer-data file index used to reference persisted metadata.
   * @throws FSParseException if required fields are absent or not parseable.
   */
  public void handleNodeToNodeTextMessageSimpleFieldSet(
      SimpleFieldSet fs, DarknetPeerNode source, int fileNumber) throws FSParseException {
    if (LOG.isDebugEnabled()) LOG.debug("Got node to node message: \n{}", fs);
    int overallType = fs.getInt(Node.N2N_TYPE_KEY);
    fs.removeValue(Node.N2N_TYPE_KEY);
    if (overallType == Node.N2N_MESSAGE_TYPE_FPROXY) {
      handleFproxyNodeToNodeTextMessageSimpleFieldSet(fs, source, fileNumber);
    } else {
      LOG.error(
          "Received unknown node to node message type '{}' from {}", overallType, source.getPeer());
    }
  }

  private void handleFproxyNodeToNodeTextMessageSimpleFieldSet(
      SimpleFieldSet fs, DarknetPeerNode source, int fileNumber) throws FSParseException {
    int type = fs.getInt("type");
    switch (type) {
      case Node.N2N_TEXT_MESSAGE_TYPE_USERALERT -> source.handleFproxyN2NTM(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER -> source.handleFproxyFileOffer(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED ->
          source.handleFproxyFileOfferAccepted(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED ->
          source.handleFproxyFileOfferRejected(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK -> source.handleFproxyBookmarkFeed(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD -> source.handleFproxyDownloadFeed(fs, fileNumber);
      default ->
          LOG.error(
              "Received unknown fproxy node to node message sub-type '{}' from {}",
              type,
              source.getPeer());
    }
  }
}
