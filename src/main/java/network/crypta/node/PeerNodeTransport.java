package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.SocketHandler;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Transport/messaging helpers for {@link PeerNode}. */
final class PeerNodeTransport implements PeerTransport {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeTransport.class);
  private static final String STR_ERROR = "error";
  private static final String STR_FOR = " for ";

  private final PeerNode peer;
  private final PacketThrottle lastThrottle = new PacketThrottle(Node.PACKET_SIZE);
  private long resendBytesSent;
  private final ByteCounter resendByteCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Ignore
        }

        @Override
        public void sentBytes(int x) {
          synchronized (peer) {
            resendBytesSent += x;
          }
          peer.node.getNodeStats().resendByteCounter.sentBytes(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  PeerNodeTransport(PeerNode peer) {
    this.peer = peer;
  }

  @Override
  public MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr)
      throws NotConnectedException {
    if (ctr == null)
      LOG.error(
          "ByteCounter null, so bandwidth usage cannot be logged. Refusing to send.",
          new Exception("debug"));
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Sending async: {} : {} on {}" + STR_FOR + "{} priority {}",
          msg,
          cb,
          peer,
          peer.node.getDarknetPortNumber(),
          msg.getPriority());
    if (!peer.isConnected()) {
      if (cb != null) cb.disconnected();
      throw new NotConnectedException();
    }
    if (msg.getSource() != null) {
      LOG.error(
          "Messages should NOT be relayed as-is, they should always be re-created to clear any"
              + " sub-messages etc, see comments in Message.java!: {}",
          msg,
          new Exception(STR_ERROR));
    }
    peer.incrementSentMessageType(msg.getSpec().getName());
    MessageItem item =
        new MessageItem(msg, cb == null ? null : new AsyncMessageCallback[] {cb}, ctr);
    long now = System.currentTimeMillis();
    peer.reportBackoffStatus(now);
    int maxSize = peer.getMaxPacketSize();
    int x = peer.getMessageQueue().queueAndEstimateSize(item, maxSize);
    if (x > maxSize || !peer.node.isEnablePacketCoalescing()) {
      // If there is a packet's worth to send, wake up the packetsender.
      peer.wakeUpSender();
    }
    // Otherwise we do not need to wake up the PacketSender
    // It will wake up before the maximum coalescing delay (100ms) because
    // it wakes up every 100ms *anyway*.
    return item;
  }

  @Override
  public void sendSync(Message req, ByteCounter ctr, boolean realTime)
      throws NotConnectedException, SyncSendWaitedTooLongException {
    SyncMessageCallback cb = new SyncMessageCallback();
    MessageItem item = sendAsync(req, cb, ctr);
    cb.waitForSend(MINUTES.toMillis(1));
    if (!cb.done) {
      LOG.warn(
          "Waited too long for a blocking send for {} to {}",
          req,
          peer.selfPeerNode(),
          new Exception(STR_ERROR));
      peer.localRejectedOverload("SendSyncTimeout", realTime);
      // Try to unqueue it, since it presumably won't be of any use now.
      if (!peer.getMessageQueue().removeMessage(item)) {
        cb.waitForSend(SECONDS.toMillis(10));
        if (!cb.done) {
          LOG.error(
              "Waited too long for blocking send and then could not unqueue for {} to {}",
              req,
              peer.selfPeerNode(),
              new Exception(STR_ERROR));
          // Can't cancel yet can't send, something seriously wrong.
          // Treat as fatal timeout as probably their fault.
          // Note: We have already waited more than the no-messages timeout; do not wait again.
          peer.fatalTimeout();
          // Then throw the error.
        } else {
          return;
        }
      }
      throw new SyncSendWaitedTooLongException();
    }
  }

  @Override
  public boolean ping(int pingID) throws NotConnectedException {
    Message ping = DMT.createFNPPing(pingID);
    peer.node.getUSM().send(peer, ping, peer.node.getDispatcher().pingCounter);
    Message msg;
    try {
      msg =
          peer.node
              .getUSM()
              .waitFor(
                  MessageFilter.create()
                      .setTimeout(2000)
                      .setType(DMT.FNPPong)
                      .setField(DMT.PING_SEQNO, pingID),
                  null);
    } catch (DisconnectedException _) {
      throw new NotConnectedException("Disconnected while waiting for pong");
    }
    return msg != null;
  }

  @Override
  public PacketThrottle getThrottle() {
    return lastThrottle;
  }

  @Override
  public SocketHandler getSocketHandler() {
    return peer.getOutgoingMangler().getSocketHandler();
  }

  @Override
  public void handleMessage(Message m) {
    peer.node.getUSM().checkFilters(m, peer.crypto.getSocket());
  }

  @Override
  public DecodingMessageGroup startProcessingDecryptedMessages(int size) {
    return new DecodingMessageGroupImpl(size);
  }

  void sendInitialMessages() {
    Message locMsg =
        DMT.createFNPLocChangeNotificationNew(
            peer.node.getLocationManager().getLocation(),
            peer.node.getPeers().getPeerLocationDoubles(true));
    Message ipMsg = DMT.createFNPDetectedIPAddress(peer.getPeer());
    Message timeMsg = DMT.createFNPTime(System.currentTimeMillis());
    Message dRoutingMsg = DMT.createRoutingStatus(!peer.disableRoutingHasBeenSetLocally);
    Message uptimeMsg =
        DMT.createFNPUptime((byte) (int) (100 * peer.node.getUptimeEstimator().getUptime()));

    try {
      if (peer.isRealConnection())
        sendAsync(locMsg, null, peer.node.getNodeStats().initialMessagesCtr);
      sendAsync(ipMsg, null, peer.node.getNodeStats().initialMessagesCtr);
      sendAsync(timeMsg, null, peer.node.getNodeStats().initialMessagesCtr);
      sendAsync(dRoutingMsg, null, peer.node.getNodeStats().initialMessagesCtr);
      sendAsync(uptimeMsg, null, peer.node.getNodeStats().initialMessagesCtr);
    } catch (NotConnectedException e) {
      LOG.error(
          "Completed handshake with {} but disconnected ({}:{}!!!: {}",
          peer.getPeer(),
          peer.isConnected(),
          peer.getCurrentKeyTracker(),
          e,
          e);
    }

    peer.sendConnectedDiffNoderef();
  }

  void sendIPAddressMessage() {
    Message ipMsg = DMT.createFNPDetectedIPAddress(peer.getPeer());
    try {
      sendAsync(ipMsg, null, peer.node.getNodeStats().changedIPCtr);
    } catch (NotConnectedException e) {
      LOG.info("Sending IP change message to {} but disconnected: {}", peer, e, e);
    }
  }

  void sendNodeToNodeMessage(
      SimpleFieldSet fs,
      int n2nType,
      boolean includeSentTime,
      long now,
      boolean queueOnNotConnected) {
    fs.putOverwrite("n2nType", Integer.toString(n2nType));
    if (includeSentTime) {
      fs.put("sentTime", now);
    }
    Message n2nm =
        DMT.createNodeToNodeMessage(n2nType, fs.toString().getBytes(StandardCharsets.UTF_8));
    UnqueueMessageOnAckCallback cb = null;
    if (peer.isDarknet() && queueOnNotConnected) {
      int fileNumber = peer.queueN2NM(fs);
      cb = new UnqueueMessageOnAckCallback((DarknetPeerNode) peer, fileNumber);
    }
    try {
      sendAsync(n2nm, cb, peer.node.getNodeStats().nodeToNodeCounter);
    } catch (NotConnectedException _) {
      if (includeSentTime) {
        fs.removeValue("sentTime");
      }
    }
  }

  void resendBytes(int length) {
    resendByteCounter.sentBytes(length);
  }

  long getResendBytesSent() {
    return resendBytesSent;
  }

  private class SyncMessageCallback implements AsyncMessageCallback {

    private boolean done = false;
    private boolean disconnected = false;
    private boolean sent = false;

    public synchronized void waitForSend(long maxWaitInterval) throws NotConnectedException {
      long now = System.currentTimeMillis();
      long end = now + maxWaitInterval;
      while ((now = System.currentTimeMillis()) < end) {
        if (done) {
          if (disconnected) throw new NotConnectedException();
          return;
        }
        int waitTime = (int) (Math.min(end - now, Integer.MAX_VALUE));
        try {
          wait(waitTime);
        } catch (InterruptedException _) {
          // Re-interrupt current thread and stop waiting
          Thread.currentThread().interrupt();
          return;
        }
      }
    }

    @Override
    public void acknowledged() {
      synchronized (this) {
        if (!done) {
          if (!sent) {
            // Can happen due to lag.
            LOG.info(
                "Acknowledged but not sent?! on {}" + STR_FOR + "{} - lag ???",
                this,
                peer.selfPeerNode());
          }
        } else return;
        done = true;
        notifyAll();
      }
    }

    @Override
    public void disconnected() {
      synchronized (this) {
        done = true;
        disconnected = true;
        notifyAll();
      }
    }

    @Override
    public void fatalError() {
      synchronized (this) {
        done = true;
        notifyAll();
      }
    }

    @Override
    public void sent() {
      // It might have been lost, we wait until it is acked.
      synchronized (this) {
        sent = true;
      }
    }
  }

  private final class DecodingMessageGroupImpl implements DecodingMessageGroup {

    private final ArrayList<Message> messages;
    private final ArrayList<Message> messagesWantSomething;

    private DecodingMessageGroupImpl(int size) {
      messages = new ArrayList<>(size);
      messagesWantSomething = new ArrayList<>(size);
    }

    @Override
    public void processDecryptedMessage(byte[] data, int offset, int length, int overhead) {
      Message m = peer.node.getUSM().decodeSingleMessage(data, offset, length, peer, overhead);
      if (m == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Message not decoded from {} ({})", peer, peer.getBuildNumber());
        return;
      }
      if (DMT.isPeerLoadStatusMessage(m)) {
        handleMessage(m);
        return;
      }
      if (DMT.isLoadLimitedRequest(m)) {
        messagesWantSomething.add(m);
      } else {
        messages.add(m);
      }
    }

    @Override
    public void complete() {
      for (Message msg : messages) {
        handleMessage(msg);
      }
      for (Message msg : messagesWantSomething) {
        handleMessage(msg);
      }
    }
  }
}
