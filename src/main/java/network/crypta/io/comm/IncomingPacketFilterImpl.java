package network.crypta.io.comm;

import java.util.concurrent.atomic.AtomicLong;
import network.crypta.crypt.EntropySource;
import network.crypta.node.FNPPacketMangler;
import network.crypta.node.Node;
import network.crypta.node.NodeCrypto;
import network.crypta.node.PeerNode;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

public class IncomingPacketFilterImpl implements IncomingPacketFilter {

  private static volatile boolean logMINOR;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, IncomingPacketFilterImpl.class);
          }
        });
  }

  private final FNPPacketMangler mangler;
  private final NodeCrypto crypto;
  private final Node node;
  private final EntropySource fnpTimingSource;

  public IncomingPacketFilterImpl(FNPPacketMangler mangler, Node node, NodeCrypto crypto) {
    this.mangler = mangler;
    this.node = node;
    this.crypto = crypto;
    fnpTimingSource = new EntropySource();
  }

  @Override
  public boolean isDisconnected(PeerContext context) {
    if (context == null) return false;
    return !context.isConnected();
  }

  private static final AtomicLong successfullyDecodedPackets = new AtomicLong();
  private static final AtomicLong failedDecodePackets = new AtomicLong();

  public static long[] getDecodedPackets() {
    if (!logMINOR) return null;
    long decoded = successfullyDecodedPackets.get();
    long failed = failedDecodePackets.get();
    return new long[] {decoded, decoded + failed};
  }

  @Override
  public DECODED process(byte[] buf, int offset, int length, Peer peer, long now) {
    if (logMINOR) Logger.minor(this, "Packet length " + length + " from " + peer);
    node.getRandom().acceptTimerEntropy(fnpTimingSource, 0.25);
    PeerNode opn = node.getPeers().getByPeer(peer, mangler);

    if (opn != null) {
      if (opn.handleReceivedPacket(buf, offset, length, now, peer)) {
        if (logMINOR) successfullyDecodedPackets.incrementAndGet();
        return DECODED.DECODED;
      }
    } else {
      Logger.normal(this, "Got packet from unknown address");
    }
    DECODED decoded = mangler.process(buf, offset, length, peer, opn, now);
    if (decoded == DECODED.DECODED) {
      if (logMINOR) successfullyDecodedPackets.incrementAndGet();
    } else if (decoded == DECODED.NOT_DECODED) {

      for (PeerNode pn : crypto.getPeerNodes()) {
        if (pn == opn) continue;
        if (pn.handleReceivedPacket(buf, offset, length, now, peer)) {
          if (logMINOR) successfullyDecodedPackets.incrementAndGet();
          return DECODED.DECODED;
        }
      }

      if (logMINOR) failedDecodePackets.incrementAndGet();
    }
    return decoded;
  }
}
