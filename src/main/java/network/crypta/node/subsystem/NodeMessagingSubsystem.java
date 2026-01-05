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

/** Node-to-node messaging and FProxy message routing subsystem. */
public final class NodeMessagingSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeMessagingSubsystem.class);

  private final Node node;
  private final Map<Integer, NodeToNodeMessageListener> n2nmListeners = new HashMap<>();

  public NodeMessagingSubsystem(Node node) {
    this.node = node;
  }

  public synchronized void registerNodeToNodeMessageListener(
      int type, NodeToNodeMessageListener listener) {
    n2nmListeners.put(type, listener);
  }

  /**
   * Handles a received node-to-node message provided by the transport layer.
   *
   * @param m the decoded message wrapper, including type and payload objects.
   * @param src the peer that sent the message.
   */
  public void receivedNodeToNodeMessage(Message m, PeerNode src) {
    int type = (Integer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_TYPE);
    ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
    receivedNodeToNodeMessage(src, type, messageData, false);
  }

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
   * @param fs the parsed field set payload; ownership is not transferred.
   * @param source the darknet peer that sent the message.
   * @param fileNumber extra-peer-data file index used to reference persisted metadata.
   * @throws FSParseException if the field set does not conform to the expected schema.
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
