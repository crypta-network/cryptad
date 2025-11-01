package network.crypta.node;

import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages a congestion-style throttle window for request scheduling.
 *
 * <p>The manager tracks a simulated window size that increases when a request completes and
 * decreases when work is rejected due to overload. The effective capacity is the simulated window
 * multiplied by the number of currently eligible peers (non-backed-off), which depends on the
 * {@code realTime} flag passed to {@link #currentValue(boolean)}.
 *
 * <p>Thread-safety: mutating and most read operations are synchronized. The methods {@link
 * #exportFieldSet(boolean)} and {@link #realCurrentValue()} are not synchronized and may return a
 * non-atomic snapshot relative to concurrent updates.
 */
public class ThrottleWindowManager {
  private static final Logger LOG = LoggerFactory.getLogger(ThrottleWindowManager.class);

  // On overload, scale the window down by this factor (< 1.0).
  static final float PACKET_DROP_DECREASE_MULTIPLE = 0.97f;
  // On success, increase the window by a small amount inversely proportional to its size.
  static final float PACKET_TRANSMIT_INCREMENT =
      (4 * (1 - (PACKET_DROP_DECREASE_MULTIPLE * PACKET_DROP_DECREASE_MULTIPLE))) / 3;

  private long totalPackets = 0;
  private long droppedPackets = 0;
  private double simulatedWindowSize;

  private final Node node;

  /**
   * Creates a new manager with an initial window and optional persisted counters.
   *
   * @param def default simulated window size when no value exists in {@code fs}
   * @param fs optional state to restore; reads keys {@code TotalPackets}, {@code DroppedPackets},
   *     and {@code SimulatedWindowSize}
   * @param node backing node used to query peer state; must not be {@code null}
   */
  public ThrottleWindowManager(double def, SimpleFieldSet fs, Node node) {
    this.node = node;
    if (fs != null) {
      totalPackets = fs.getInt("TotalPackets", 0);
      droppedPackets = fs.getInt("DroppedPackets", 0);
      simulatedWindowSize = fs.getDouble("SimulatedWindowSize", def);
    } else {
      simulatedWindowSize = def;
    }
  }

  /**
   * Returns the current capacity scaled by eligible peers.
   *
   * <p>Enforces a minimum simulated window of {@code 1.0}. The value is then multiplied by the
   * number of non-backed-off peers as reported by {@code node.getPeers().countNonBackedOffPeers}.
   *
   * @param realTime when {@code true}, counts peers based on real-time eligibility; otherwise uses
   *     non-real-time criteria
   * @return the effective capacity as a {@code double}
   */
  public synchronized double currentValue(boolean realTime) {
    if (simulatedWindowSize < 1.0) {
      simulatedWindowSize = 1.0F;
    }
    return simulatedWindowSize * Math.max(1, node.getPeers().countNonBackedOffPeers(realTime));
  }

  /**
   * Registers an overload rejection and decreases the window accordingly.
   *
   * <p>Increments both the dropped and total counters, and scales the window down by {@link
   * #PACKET_DROP_DECREASE_MULTIPLE}.
   */
  public synchronized void rejectedOverload() {
    droppedPackets++;
    totalPackets++;
    simulatedWindowSize *= PACKET_DROP_DECREASE_MULTIPLE;
    if (LOG.isDebugEnabled()) LOG.debug("Overload rejection recorded (state={})", this);
  }

  /**
   * Registers a completed request and increases the window.
   *
   * <p>Increments the total counter and adjusts the window by {@code PACKET_TRANSMIT_INCREMENT /
   * simulatedWindowSize}.
   */
  public synchronized void requestCompleted() {
    totalPackets++;
    simulatedWindowSize += (PACKET_TRANSMIT_INCREMENT / simulatedWindowSize);
    if (LOG.isDebugEnabled()) LOG.debug("Request completes (state={})", this);
  }

  @Override
  public synchronized String toString() {
    return super.toString()
        + " w: "
        + simulatedWindowSize
        + ", d:"
        + ((float) droppedPackets / (float) totalPackets)
        + '='
        + droppedPackets
        + '/'
        + totalPackets;
  }

  /**
   * Exports the current state as a {@link SimpleFieldSet}.
   *
   * <p>The field set contains {@code Type}, {@code TotalPackets}, {@code DroppedPackets}, and
   * {@code SimulatedWindowSize}. This method is not synchronized and may return a non-atomic
   * snapshot when updates occur concurrently.
   *
   * @param shortLived whether the returned field set is short-lived
   * @return a new field set representing the current state
   */
  public SimpleFieldSet exportFieldSet(boolean shortLived) {
    SimpleFieldSet fs = new SimpleFieldSet(shortLived);
    fs.putSingle("Type", "ThrottleWindowManager");
    fs.put("TotalPackets", totalPackets);
    fs.put("DroppedPackets", droppedPackets);
    fs.put("SimulatedWindowSize", simulatedWindowSize);
    return fs;
  }

  /**
   * Returns the current simulated window size without peer scaling.
   *
   * @return the baseline window as a {@code double}
   */
  public double realCurrentValue() {
    return simulatedWindowSize;
  }
}
