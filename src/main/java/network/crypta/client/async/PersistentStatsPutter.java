package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.node.Node;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.UptimeContainer;

/**
 * Maintains incremental, persistable statistics for bandwidth and uptime.
 *
 * <p>This helper accumulates deltas from a running {@link network.crypta.node.Node} so that
 * coarse-grained client statistics survive across process restarts. The instance keeps the last
 * observed absolute counters from the node and converts subsequent absolute readings into
 * increments, updating two lightweight containers: a {@link
 * network.crypta.support.BandwidthStatsContainer} and an {@link
 * network.crypta.support.UptimeContainer}. Typical usage is to:
 *
 * <ul>
 *   <li>Load a previously persisted instance (if any) and {@linkplain
 *       #addFrom(PersistentStatsPutter) merge} it into a fresh instance at startup.
 *   <li>Periodically call {@link #updateData(network.crypta.node.Node)} with the live node to fold
 *       in recent activity.
 *   <li>Persist the returned data structures between runs to resume accumulation later.
 * </ul>
 *
 * <p>Thread-safety: this type is not synchronized. Callers should confine an instance to a single
 * thread or provide external synchronization if accessed concurrently. The returned container
 * objects are mutable and owned by this putter; treat them as a live view of the running totals.
 *
 * @author Artefact2
 * @see network.crypta.support.BandwidthStatsContainer
 * @see network.crypta.support.UptimeContainer
 */
public class PersistentStatsPutter implements Serializable {
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Last absolute number of bytes the node reported as sent (outbound). Used as the baseline for
   * converting absolute counters into per-run increments. Initialized to {@code 0} until the first
   * {@link #updateData(network.crypta.node.Node)} call captures a baseline.
   */
  private long latestNodeBytesOut = 0;

  /**
   * Last absolute number of bytes the node reported as received (inbound). Functions as a baseline
   * for computing deltas on subsequent updates. Starts at {@code 0} for the first update cycle.
   */
  private long latestNodeBytesIn = 0;

  /**
   * Last absolute uptime value reported by the node, in milliseconds. The difference between the
   * current uptime and this stored value is accumulated into {@link #latestUptime}. The field is
   * {@code 0} until the first update captures a baseline.
   */
  private long latestUptimeVal = 0;

  /**
   * Accumulated bandwidth statistics for this process lifetime plus any merged persisted state. The
   * container’s {@code totalBytesIn}/{@code totalBytesOut} grow monotonically as new deltas are
   * applied. Its {@code creationTime} is refreshed on each update to reflect the moment of the
   * latest fold-in.
   */
  private final BandwidthStatsContainer latestBW = new BandwidthStatsContainer();

  /**
   * Accumulated uptime statistics for this process lifetime plus any merged persisted state. The
   * container records the running total of uptime and its own {@code creationTime} for auditing.
   */
  private final UptimeContainer latestUptime = new UptimeContainer();

  /**
   * Creates a new putter with zeroed baselines and empty statistics containers.
   *
   * <p>The first {@link #updateData(network.crypta.node.Node)} call captures the node’s absolute
   * counters as a baseline and converts subsequent readings into deltas. To resume accumulation
   * from a previous run, call {@link #addFrom(PersistentStatsPutter)} with the deserialized prior
   * state immediately after construction.
   */
  public PersistentStatsPutter() {
    // Intentionally empty: baselines and containers are initialized at declaration
    // a no-arg constructor is required for deserialization and test scaffolding.
  }

  /**
   * Returns the live, accumulated bandwidth statistics container.
   *
   * <p>The returned instance is owned by this putter and is updated in place whenever {@link
   * #updateData(network.crypta.node.Node)} is invoked or when {@link
   * #addFrom(PersistentStatsPutter)} merges data. Callers should treat it as a mutable view and
   * avoid storing external copies if concurrent updates may occur. The totals represent the
   * cumulative bytes in/out for this run, plus any previously persisted values that were folded in.
   *
   * @return a mutable {@link network.crypta.support.BandwidthStatsContainer} reflecting cumulative
   *     in/out bytes; ownership remains with this putter and values change after subsequent
   *     updates.
   */
  public BandwidthStatsContainer getLatestBWData() {
    return this.latestBW;
  }

  /**
   * Returns the live, accumulated uptime statistics container.
   *
   * <p>The container’s total uptime is incremented by the delta between successive absolute uptime
   * readings supplied to {@link #updateData(network.crypta.node.Node)}. The container is mutable
   * and is refreshed in place; callers must not assume immutability or snapshot semantics.
   *
   * @return a mutable {@link network.crypta.support.UptimeContainer} reflecting cumulative uptime;
   *     ownership remains with this putter and values change after subsequent updates.
   */
  public UptimeContainer getLatestUptimeData() {
    return this.latestUptime;
  }

  /**
   * Folds the node’s current absolute counters into this putter as deltas.
   *
   * <p>This method reads the node’s total bytes out/in and uptime and converts them into increments
   * relative to the last call, updating the internal containers and refreshing their creation time
   * to the current wall clock. On the first call, the baselines are zero so the containers increase
   * by the node’s absolute values; subsequent calls apply only the difference since the previous
   * invocation. This method is idempotent only when the node’s counters remain unchanged between
   * invocations.
   *
   * @param n the live {@link network.crypta.node.Node} to sample; must be non-null and expected to
   *     expose monotonically increasing absolute counters for IO and uptime.
   */
  public void updateData(Node n) {
    // Update our values
    // 0 : total bytes out, 1 : total bytes in
    final long[] nodeBW = n.getCollector().getTotalIO();
    this.latestBW.setTotalBytesOut(
        this.latestBW.getTotalBytesOut() + nodeBW[0] - this.latestNodeBytesOut);
    this.latestBW.setTotalBytesIn(
        this.latestBW.getTotalBytesIn() + nodeBW[1] - this.latestNodeBytesIn);
    this.latestBW.setCreationTime(System.currentTimeMillis());
    this.latestNodeBytesOut = nodeBW[0];
    this.latestNodeBytesIn = nodeBW[1];

    final long uptime = n.getUptime();
    this.latestUptime.setTotalUptime(
        this.latestUptime.getTotalUptime() + uptime - this.latestUptimeVal);
    this.latestUptime.setCreationTime(System.currentTimeMillis());
    this.latestUptimeVal = uptime;
  }

  /**
   * Merges statistics from an existing putter into this instance.
   *
   * <p>Use this to resume accumulation across restarts by loading a previously persisted putter and
   * merging its containers into the fresh instance created for the new process. The merge is
   * additive: totals from the given {@code stored} instance are added to the current containers; no
   * baselines are modified. This operation does not modify the input instance.
   *
   * @param stored a previously recorded {@link PersistentStatsPutter} whose bandwidth and uptime
   *     containers will be added into this putter; must be non-null.
   */
  public void addFrom(PersistentStatsPutter stored) {
    this.latestBW.addFrom(stored.latestBW);
    this.latestUptime.addFrom(stored.latestUptime);
  }
}
