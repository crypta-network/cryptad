package network.crypta.io.xfer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Congestion window and pacing helper for packet transfers.
 *
 * <p>This class implements a lightweight, TCP-inspired congestion controller using slow start and
 * additive-increase/multiplicative-decrease (AIMD). The window is modeled in "packets" (it may be
 * fractional), and callers use {@link #getWindowSize()} and {@link #getDelay()} to pace outbound
 * transmissions. RTT is provided externally via {@link #setRoundTripTime(long)}.
 *
 * <p>Thread-safety: all public methods are {@code synchronized}; instances are safe for use by a
 * single sending path with multiple helper threads.
 *
 * <p>Units and invariants:
 *
 * <ul>
 *   <li>Window size is in logical packets and never fewer than 1.0.
 *   <li>Round-trip time (RTT) is in milliseconds.
 *   <li>{@link #getDelay()} returns a pacing delay in milliseconds; it is lower-bounded by {@link
 *       #MIN_DELAY} to avoid zero/unstable delays.
 *   <li>{@link #getBandwidth()} estimates throughput in {@code packetSize} units per second (e.g.,
 *       bytes/second when {@code packetSize} is bytes).
 * </ul>
 */
public class PacketThrottle {
  private static final Logger LOG = LoggerFactory.getLogger(PacketThrottle.class);

  /**
   * AIMD multiplicative decrease factor applied per lost packet. A loss of {@code n} packets scales
   * the window by {@code PACKET_DROP_DECREASE_MULTIPLE^n}.
   */
  protected static final double PACKET_DROP_DECREASE_MULTIPLE = 0.875;

  /**
   * Additive increase term used during congestion avoidance (non–slow start). The window increases
   * by {@code PACKET_TRANSMIT_INCREMENT / windowSize} per acknowledged packet.
   */
  protected static final double PACKET_TRANSMIT_INCREMENT =
      (4 * (1 - (PACKET_DROP_DECREASE_MULTIPLE * PACKET_DROP_DECREASE_MULTIPLE))) / 3;

  /** Divisor that controls slow-start growth; larger values grow more gently. */
  protected static final double SLOW_START_DIVISOR = 3.0;

  /** Minimum pacing delay (milliseconds) returned by {@link #getDelay()}. */
  protected static final long MIN_DELAY = 1;

  /** Legacy source-control identifier; not used for logic. */
  public static final String VERSION =
      "$Id: PacketThrottle.java,v 1.3 2005/08/25 17:28:19 amphibian Exp $";

  private long roundTripTime = 500;
  private long totalPackets;
  private long droppedPackets;

  /**
   * Congestion window, measured in packets. It never drops below 1.0, so at least one packet can be
   * sent, and divisions by window size remain well-defined.
   */
  private float windowSize = 2;

  private final int packetSize;
  private boolean slowStart = true;

  /**
   * Creates a throttle for a fixed logical packet size.
   *
   * @param packetSize Size of one transmission unit used for rate estimation. When expressed in
   *     bytes, {@link #getBandwidth()} reports bytes per second.
   */
  public PacketThrottle(int packetSize) {
    this.packetSize = packetSize;
  }

  /**
   * Sets the estimated round-trip time.
   *
   * @param rtt Round-trip time in milliseconds. Values less than 10 ms are clamped to 10 ms.
   */
  public synchronized void setRoundTripTime(long rtt) {
    roundTripTime = Math.max(rtt, 10);
    if (LOG.isDebugEnabled()) LOG.debug("Set round trip time to {} on {}", rtt, this);
  }

  /**
   * Applies multiplicative decrease in response to packet loss and exits slow start.
   *
   * @param numPackets Number of packets lost; must be positive.
   * @throws IllegalArgumentException if {@code numPackets <= 0}.
   */
  public synchronized void notifyOfPacketsLost(int numPackets) {
    if (numPackets <= 0) {
      throw new IllegalArgumentException("Reported loss is zero or negative");
    }
    droppedPackets += numPackets;
    totalPackets += numPackets;
    windowSize *= (float) Math.pow(PACKET_DROP_DECREASE_MULTIPLE, numPackets);
    if (windowSize < 1.0F) {
      windowSize = 1.0F;
    }
    slowStart = false;
    if (LOG.isDebugEnabled()) {
      LOG.debug("notifyOfPacketsLost(): {}", this);
    }
  }

  /**
   * Notifies the throttle that a packet was acknowledged and increases the window.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If in slow start, grow by {@code windowSize / SLOW_START_DIVISOR} per ACK.
   *   <li>Otherwise, grow additively by {@code PACKET_TRANSMIT_INCREMENT / windowSize} per ACK.
   *   <li>The window is bounded above by {@code maxWindowSize}.
   * </ul>
   *
   * @param maxWindowSize Upper bound for the window, typically ≥ the largest in-flight window
   *     observed so far. Prevents uncontrolled growth beyond what has actually worked on the link.
   */
  public synchronized void notifyOfPacketAcknowledged(double maxWindowSize) {
    totalPackets++;
    // Track the previous integer window to wake waiters only when we cross a whole-packet boundary.
    int windowSizeInt = (int) getWindowSize();

    if (slowStart) {
      if (LOG.isDebugEnabled()) LOG.debug("Still in slow start");
      windowSize += windowSize / (float) SLOW_START_DIVISOR;
      // Avoid craziness if there is a lag in detecting packet loss.
      if (windowSize > maxWindowSize) slowStart = false;
      // Ensure window >= 1.0 so we can send at least one packet and keep divisions defined.
      if (windowSize < 1.0F) windowSize = 1.0F;
    } else {
      windowSize += (float) (PACKET_TRANSMIT_INCREMENT / windowSize);
    }
    // Bound to the largest observed in-flight window.
    if (windowSize > maxWindowSize) windowSize = (float) maxWindowSize;
    // Wake waiting senders if the integer window increased.
    if (windowSize > (windowSizeInt + 1)) notifyAll();
    if (LOG.isDebugEnabled()) LOG.debug("notifyOfPacketAcked(): {}", this);
  }

  /**
   * Returns the pacing delay derived from the current RTT and window.
   *
   * @return Delay in milliseconds; always {@code >= MIN_DELAY}.
   */
  public synchronized long getDelay() {
    return Math.max(MIN_DELAY, (long) (roundTripTime / windowSize));
  }

  /**
   * Returns a human-readable snapshot of the throttle state. The format is intended for logs and
   * may change without notice; do not parse.
   */
  @Override
  public synchronized String toString() {
    return getBandwidth()
        + " k/sec, (w: "
        + windowSize
        + ", r:"
        + roundTripTime
        + ", d:"
        + ((float) droppedPackets / (float) totalPackets)
        + ") total="
        + totalPackets
        + " : "
        + super.toString();
  }

  /**
   * Returns the configured round-trip time.
   *
   * @return RTT in milliseconds.
   */
  public synchronized long getRoundTripTime() {
    return roundTripTime;
  }

  /**
   * Returns the current (clamped) congestion window.
   *
   * @return Window size in logical packets; never less than {@code 1.0}.
   */
  public synchronized double getWindowSize() {
    return Math.max(1.0, windowSize);
  }

  /**
   * Returns estimated throughput based on the current delay.
   *
   * <p>The result is expressed in {@code packetSize} units per second (e.g., bytes/second when
   * {@code packetSize} is bytes). Because {@link #getDelay()} is lower-bounded by {@link
   * #MIN_DELAY} the estimate is implicitly capped.
   *
   * @return Estimated rate in {@code packetSize}/second.
   */
  public synchronized double getBandwidth() {
    // 1000 ms per second; compute packetSize units per second based on delay.
    return packetSize * 1000.0 / getDelay();
  }

  /**
   * Lifecycle hook invoked when the associated connection may have disconnected.
   *
   * <p>The throttle no longer blocks on its own monitor, so this hook intentionally performs no
   * signaling.
   */
  public void maybeDisconnected() {
    // No-op: PacketThrottle currently has no internal waiters.
  }
}
