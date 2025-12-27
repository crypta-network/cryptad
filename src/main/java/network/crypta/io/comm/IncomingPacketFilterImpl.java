package network.crypta.io.comm;

import java.util.concurrent.atomic.AtomicLong;
import network.crypta.crypt.EntropySource;
import network.crypta.node.FNPPacketMangler;
import network.crypta.node.Node;
import network.crypta.node.NodeCrypto;
import network.crypta.node.PeerNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters and decodes incoming FNP packets.
 *
 * <p>This class coordinates with {@link FNPPacketMangler} and {@link NodeCrypto} to decide whether
 * a packet can be decoded and which {@link PeerNode} owns it. If the owning peer cannot decode the
 * packet, the filter attempts a best-effort fallback with other known peers. Minimal, debug-enabled
 * counters record successes and failures for diagnostics.
 *
 * <p><strong>Thread-safety:</strong> Instances are stateless with respect to packet processing. The
 * decoding counters are stored in static {@link java.util.concurrent.atomic.AtomicLong} fields and
 * are safe for concurrent updates. Counters are process-wide and monotonic for the lifetime of the
 * JVM.
 *
 * <p><strong>Statistics:</strong> Counters are incremented only when the logger for this class is
 * in debug mode. Callers should use {@link #getDecodedPackets()} and treat a {@code null} result as
 * “statistics disabled”.
 */
public class IncomingPacketFilterImpl implements IncomingPacketFilter {
  private static final Logger LOG = LoggerFactory.getLogger(IncomingPacketFilterImpl.class);

  private final FNPPacketMangler mangler;
  private final NodeCrypto crypto;
  private final Node node;
  private final EntropySource fnpTimingSource;

  /**
   * Creates a new filter wired to the node's packet-processing components.
   *
   * @param mangler helper that performs low-level decoding when the owning peer cannot handle the
   *     packet
   * @param node the local node providing peer coordination and randomness
   * @param crypto access to known peers for fallback decoding
   */
  public IncomingPacketFilterImpl(FNPPacketMangler mangler, Node node, NodeCrypto crypto) {
    this.mangler = mangler;
    this.node = node;
    this.crypto = crypto;
    fnpTimingSource = new EntropySource();
  }

  /**
   * Returns whether the peer associated with the provided context is disconnected.
   *
   * <p>A {@code null} context returns {@code false}. This allows inexpensive guards without extra
   * null checks at call sites.
   *
   * @param context tracks the peer's connection state; may be {@code null}
   * @return {@code true} when the peer is known and not connected; otherwise {@code false}
   */
  @Override
  public boolean isDisconnected(PeerContext context) {
    if (context == null) return false;
    return !context.isConnected();
  }

  // Debug-only packet counters. These remain zero and are never read when debug logging is off.
  private static final AtomicLong successfullyDecodedPackets = new AtomicLong();
  private static final AtomicLong failedDecodePackets = new AtomicLong();

  /**
   * Returns a snapshot of packet-decoding statistics or {@code null} when statistics are disabled.
   *
   * <p>When debug logging is off for this class, the method returns {@code null} and callers are
   * expected to suppress any packet-statistics UI. When debug logging is on, the returned array has
   * length 2 with the following layout:
   *
   * <ul>
   *   <li>index 0 — number of successfully decoded packets
   *   <li>index 1 — total observed packets considered by the counters (decoded + failed)
   * </ul>
   *
   * <p>The counts are monotonic during the lifetime of the JVM and are not persisted.
   *
   * @return {@code long[2]} with {decoded, total} when enabled; otherwise {@code null}
   */
  @SuppressWarnings("java:S1168")
  public static long[] getDecodedPackets() {
    if (!LOG.isDebugEnabled()) {
      // When debugging is disabled, stats collection is off; signal caller to hide UI section.
      return null;
    }
    long decoded = successfullyDecodedPackets.get();
    long failed = failedDecodePackets.get();
    return new long[] {decoded, decoded + failed};
  }

  /**
   * Attempts to decode and route an incoming packet.
   *
   * <p>The method consults the owning {@link PeerNode} when available. If the owning peer cannot
   * decode the packet, {@link FNPPacketMangler} is invoked. As a last resort, other known peers are
   * probed to handle the packet.
   *
   * <p>Side effects:
   *
   * <ul>
   *   <li>Accepts a small amount of arrival-time entropy into the node RNG.
   *   <li>Updates debug-only counters when debug logging is enabled.
   *   <li>Emits debug logs for basic packet properties.
   * </ul>
   *
   * @param buf packet data; must contain at least {@code length} bytes from {@code offset}
   * @param offset start offset into {@code buf}
   * @param length number of bytes to read from {@code buf}
   * @param peer source address of the packet
   * @param now wall-clock time in milliseconds for freshness/timeout logic
   * @return a {@link DECODED} value indicating the outcome
   */
  @Override
  public DECODED process(byte[] buf, int offset, int length, Peer peer, long now) {
    debugLogPacket(length, peer);
    // Mix a small amount of arrival-time entropy into the node RNG. The bias preserves legacy
    // behavior and balances entropy quality with performance.
    node.getRandom().acceptTimerEntropy(fnpTimingSource, 0.25);
    PeerNode opn = node.getPeers().roster().getByPeer(peer, mangler);

    if (opn == null) {
      LOG.info("Got packet from unknown address");
    } else if (opn.handleReceivedPacket(buf, offset, length, now, peer)) {
      incrementDecoded();
      return DECODED.DECODED;
    }

    DECODED decoded = mangler.process(buf, offset, length, peer, opn);
    if (decoded == DECODED.DECODED) {
      incrementDecoded();
      return DECODED.DECODED;
    }
    if (decoded == DECODED.NOT_DECODED) {
      // Probe other known peers (excluding the owning peer) as a last resort. This is O(n) in the
      // number of peers but triggers only for undecoded packets.
      if (tryFallbackPeers(buf, offset, length, peer, now, opn)) {
        incrementDecoded();
        return DECODED.DECODED;
      }
      incrementFailed();
    }
    return decoded;
  }

  // Emit a concise debug line for packet properties when debug is enabled.
  private void debugLogPacket(int length, Peer peer) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Packet length {} from {}", length, peer);
    }
  }

  // Debug-only counters avoid overhead in production; no-op when debug is off.
  private void incrementDecoded() {
    if (LOG.isDebugEnabled()) {
      successfullyDecodedPackets.incrementAndGet();
    }
  }

  // Debug-only counters avoid overhead in production; no-op when debug is off.
  private void incrementFailed() {
    if (LOG.isDebugEnabled()) {
      failedDecodePackets.incrementAndGet();
    }
  }

  /**
   * Attempts to decode the packet using other known peers when the owning peer could not decode it.
   * The owning peer (if any) is excluded. Returns on first success.
   */
  private boolean tryFallbackPeers(
      byte[] buf, int offset, int length, Peer peer, long now, PeerNode opn) {
    for (PeerNode pn : crypto.getPeerNodes()) {
      if (pn == opn) {
        continue;
      }
      if (pn.handleReceivedPacket(buf, offset, length, now, peer)) {
        return true;
      }
    }
    return false;
  }
}
