package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;

/**
 * View of a peer's advertised load metrics used for fairness and liability checks.
 *
 * <p>This type represents a point-in-time snapshot of counters and bandwidth thresholds that a peer
 * reports to its neighbors. Callers typically construct it from an incoming {@link Message} and
 * then consult the fields when deciding whether to accept or defer additional requests. Values are
 * copied out of the message and are not recomputed, so the instance is immutable and thread-safe
 * for concurrent reads. The snapshot intentionally exposes raw counters rather than derived rates,
 * leaving aggregation and policy decisions to higher-level components.
 *
 * <p>It does not retain any mutable state from the sender, and it does not attempt to update itself
 * after construction. The only interpretation applied is to map byte/short encodings to unsigned
 * integer ranges, keeping the numeric meaning consistent across message formats.
 *
 * <ul>
 *   <li>Captures expected transfer counts for CHK and SSK operations.
 *   <li>Exposes per-peer and overall bandwidth limits for both directions.
 *   <li>Provides derived caps for concurrent outbound transfers.
 * </ul>
 *
 * @see Message
 * @see PeerNode
 * @see RunningRequestsSnapshot
 */
public final class PeerLoadStats {

  /**
   * Peer that advertised this snapshot, used as a stable identity handle.
   *
   * <p>The reference is not copied or wrapped; it is the exact {@link PeerNode} supplied at
   * construction time. The snapshot never mutates the peer, and callers should treat it as a
   * read-only identifier for logging or lookups.
   */
  public final PeerNode peer;

  /**
   * Expected outbound CHK transfers attributable to this peer.
   *
   * <p>This count excludes transfers initiated by the local node itself; it represents the peer's
   * reported view of its own traffic. The value is a transfer count, not bytes, and is decoded from
   * the message format as an unsigned quantity when needed.
   */
  public final int expectedTransfersOutCHK;

  /**
   * Expected inbound CHK transfers attributable to this peer.
   *
   * <p>The value is a count of transfers rather than a byte estimate. It is read directly from the
   * peer's message and may be in the unsigned range when the peer uses byte or short encodings.
   */
  public final int expectedTransfersInCHK;

  /**
   * Expected outbound SSK transfers attributable to this peer.
   *
   * <p>The count is reported by the peer and excludes local-only traffic. The value is stored as an
   * integer after mapping any byte or short encodings into their unsigned ranges.
   */
  public final int expectedTransfersOutSSK;

  /**
   * Expected inbound SSK transfers attributable to this peer.
   *
   * <p>This is a transfer count (not a size), derived directly from the message fields. For
   * byte/short message variants it is converted to an unsigned integer range to preserve meaning.
   */
  public final int expectedTransfersInSSK;

  /**
   * Lower bound for output bandwidth available to the peer, in bytes per second.
   *
   * <p>The value is an advertised threshold used when deciding whether additional outbound work is
   * fair. It is copied as-is from the message and is not derived from local measurements.
   */
  public final double outputBandwidthLowerLimit;

  /**
   * Upper bound for output bandwidth available to the peer, in bytes per second.
   *
   * <p>This limit represents the peer's declared ceiling for outbound throughput. It is used in
   * fairness checks and is read directly from the peer's message without local adjustment.
   */
  public final double outputBandwidthUpperLimit;

  /**
   * Per-peer output bandwidth limit applied to this connection, in bytes per second.
   *
   * <p>The value reflects a peer-specific cap rather than a network-wide ceiling. It is typically
   * compared against this peer's contribution when making accept/reject decisions.
   */
  public final double outputBandwidthPeerLimit;

  /**
   * Lower bound for input bandwidth available to the peer, in bytes per second.
   *
   * <p>This threshold describes the peer's declared inbound capacity floor. It is used for
   * balancing inbound work and is taken directly from the received message.
   */
  public final double inputBandwidthLowerLimit;

  /**
   * Upper bound for input bandwidth available to the peer, in bytes per second.
   *
   * <p>The value is a peer-reported ceiling for inbound throughput. It is not normalized by the
   * local node and serves as a raw signal for fairness calculations.
   */
  public final double inputBandwidthUpperLimit;

  /**
   * Per-peer input bandwidth limit applied to this connection, in bytes per second.
   *
   * <p>This is a peer-specific cap used when evaluating inbound requests from the peer. The value
   * is copied verbatim from the message and is not derived locally.
   */
  public final double inputBandwidthPeerLimit;

  /**
   * Total number of requests reported by the peer, or {@code -1} when absent.
   *
   * <p>Some message variants do not carry a total request count; in those cases this field is set
   * to {@code -1} as a sentinel. Callers should treat negative values as "not provided."
   */
  public final int totalRequests;

  /**
   * Average transfers per insert reported by the peer, as a transfer count.
   *
   * <p>This value is used as a heuristic for estimating transfer liabilities. It is stored as an
   * integer count rather than a byte estimate and is copied from the incoming message.
   */
  public final int averageTransfersOutPerInsert;

  /**
   * Flag indicating whether the reported counters describe real-time traffic.
   *
   * <p>When {@code true}, the snapshot corresponds to real-time traffic classification; when {@code
   * false}, it corresponds to bulk traffic. The value is taken directly from the message.
   */
  public final boolean realTime;

  /**
   * Maximum outbound transfers allowed by congestion control.
   *
   * <p>This is the hard cap the peer reports for concurrent outbound transfers. It is a transfer
   * count, not bytes, and is derived directly from the message without adjustment.
   */
  public final int maxTransfersOut;

  /**
   * Maximum outbound transfers allowed for this peer regardless of overall load.
   *
   * <p>This peer-specific cap applies when aggregate transfers are above the lower overall limit.
   * It represents a transfer count rather than bytes and is used to decide whether this peer can
   * still be accepted when the network is congested.
   */
  public final int maxTransfersOutPeerLimit;

  /**
   * Lower overall outbound transfer threshold that shifts acceptance to per-peer checks.
   *
   * <p>When aggregate outbound transfers exceed this value, acceptance decisions depend on whether
   * this peer remains under {@link #maxTransfersOutPeerLimit}. The value is a raw transfer count
   * copied directly from the peer's message.
   */
  public final int maxTransfersOutLowerLimit;

  /**
   * Maximum outbound transfers allowed in total before rejecting all new work.
   *
   * <p>This upper bound is the strictest aggregate limit the peer reports. When the total transfer
   * count exceeds this value, no additional outbound transfers should be accepted regardless of
   * per-peer usage.
   */
  public final int maxTransfersOutUpperLimit;

  /**
   * Determine structural equality for peer load snapshots.
   *
   * <p>The comparison checks peer identity via {@link PeerNode#equals(Object)} and then compares
   * all numeric fields for exact equality, including bandwidth limits and transfer caps. This
   * method is deterministic, has no side effects, and treats {@code null} as unequal. Because peer
   * identity is compared, two snapshots with equal field values but different peers are treated as
   * unequal.
   *
   * @param o candidate object to compare against this snapshot; may be {@code null}
   * @return {@code true} when all fields and peer identity are equal, {@code false} otherwise
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof PeerLoadStats s)) return false;
    if (!peer.equals(s.peer)) return false;
    if (s.expectedTransfersOutCHK != expectedTransfersOutCHK) return false;
    if (s.expectedTransfersInCHK != expectedTransfersInCHK) return false;
    if (s.expectedTransfersOutSSK != expectedTransfersOutSSK) return false;
    if (s.expectedTransfersInSSK != expectedTransfersInSSK) return false;
    if (s.totalRequests != totalRequests) return false;
    if (s.averageTransfersOutPerInsert != averageTransfersOutPerInsert) return false;
    if (s.outputBandwidthLowerLimit != outputBandwidthLowerLimit) return false;
    if (s.outputBandwidthUpperLimit != outputBandwidthUpperLimit) return false;
    if (s.outputBandwidthPeerLimit != outputBandwidthPeerLimit) return false;
    if (s.inputBandwidthLowerLimit != inputBandwidthLowerLimit) return false;
    if (s.inputBandwidthUpperLimit != inputBandwidthUpperLimit) return false;
    if (s.inputBandwidthPeerLimit != inputBandwidthPeerLimit) return false;
    if (s.maxTransfersOut != maxTransfersOut) return false;
    if (s.maxTransfersOutPeerLimit != maxTransfersOutPeerLimit) return false;
    if (s.maxTransfersOutLowerLimit != maxTransfersOutLowerLimit) return false;
    return s.maxTransfersOutUpperLimit == maxTransfersOutUpperLimit;
  }

  /**
   * Return a hash code derived from the peer identity.
   *
   * <p>The hash code is computed solely from {@link #peer}, matching the equality contract that
   * compares peer identity via {@link PeerNode#equals(Object)}. This keeps the hash stable for the
   * lifetime of the snapshot and avoids incorporating mutable state. Callers should not assume that
   * different snapshots with equal field values but distinct peers will share a hash code.
   *
   * @return hash code based on the {@link #peer} identity
   */
  @Override
  public int hashCode() {
    return peer.hashCode();
  }

  /**
   * Produce a human-readable summary of the peer's load snapshot.
   *
   * <p>The string includes bandwidth limits, expected transfers, and outbound transfer caps in a
   * fixed format suitable for diagnostics and logging. The method performs no allocation beyond
   * string concatenation and does not consult external state. It reflects the exact values stored
   * in this snapshot, so the result is deterministic for a given instance.
   *
   * @return formatted string containing limits, counts, and transfer caps for this peer
   */
  @Override
  public String toString() {
    return peer.toString()
        + ":output:{lower="
        + outputBandwidthLowerLimit
        + ",upper="
        + outputBandwidthUpperLimit
        + ",this="
        + outputBandwidthPeerLimit
        + "},input:lower="
        + inputBandwidthLowerLimit
        + ",upper="
        + inputBandwidthUpperLimit
        + ",peer="
        + inputBandwidthPeerLimit
        + "},requests:"
        + "in:"
        + expectedTransfersInCHK
        + "chk/"
        + expectedTransfersInSSK
        + "ssk:out:"
        + expectedTransfersOutCHK
        + "chk/"
        + expectedTransfersOutSSK
        + "ssk transfers="
        + maxTransfersOut
        + "/"
        + maxTransfersOutPeerLimit
        + "/"
        + maxTransfersOutLowerLimit
        + "/"
        + maxTransfersOutUpperLimit;
  }

  /**
   * Create a snapshot from the peer's load status message.
   *
   * <p>The constructor reads the message fields defined by {@link DMT#FNPPeerLoadStatusInt}, {@link
   * DMT#FNPPeerLoadStatusShort}, or {@link DMT#FNPPeerLoadStatusByte}. Byte and short encodings are
   * interpreted as unsigned values to preserve their intended ranges. All fields are copied into
   * final members, so the resulting instance is immutable and safe to share across threads. The
   * {@code totalRequests} field is set to {@code -1} because peer status messages do not carry a
   * total count.
   *
   * <p>This constructor is not idempotent in terms of the message contents; each call captures a
   * new snapshot. It performs no validation beyond ensuring the message type is supported.
   *
   * @param source peer that supplied the message; must be non-null and stable for peer-identity
   *     checks
   * @param m message holding the peer's load statistics; must match a supported peer-load spec
   * @throws IllegalArgumentException if the message spec is not a supported peer-load variant
   */
  public PeerLoadStats(PeerNode source, Message m) {
    peer = source;
    MessageType spec = m.getSpec();
    if (DMT.FNPPeerLoadStatusInt.equals(spec)) {
      expectedTransfersInCHK = m.getInt(DMT.OTHER_TRANSFERS_IN_CHK);
      expectedTransfersInSSK = m.getInt(DMT.OTHER_TRANSFERS_IN_SSK);
      expectedTransfersOutCHK = m.getInt(DMT.OTHER_TRANSFERS_OUT_CHK);
      expectedTransfersOutSSK = m.getInt(DMT.OTHER_TRANSFERS_OUT_SSK);
      averageTransfersOutPerInsert = m.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT);
      maxTransfersOut = m.getInt(DMT.MAX_TRANSFERS_OUT);
      maxTransfersOutUpperLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT);
      maxTransfersOutLowerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT);
      maxTransfersOutPeerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT);
    } else if (DMT.FNPPeerLoadStatusShort.equals(spec)) {
      expectedTransfersInCHK = m.getShort(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFFFF;
      expectedTransfersInSSK = m.getShort(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFFFF;
      expectedTransfersOutCHK = m.getShort(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFFFF;
      expectedTransfersOutSSK = m.getShort(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFFFF;
      averageTransfersOutPerInsert = m.getShort(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFFFF;
      maxTransfersOut = m.getShort(DMT.MAX_TRANSFERS_OUT) & 0xFFFF;
      maxTransfersOutUpperLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFFFF;
      maxTransfersOutLowerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFFFF;
      maxTransfersOutPeerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFFFF;
    } else if (DMT.FNPPeerLoadStatusByte.equals(spec)) {
      expectedTransfersInCHK = m.getByte(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFF;
      expectedTransfersInSSK = m.getByte(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFF;
      expectedTransfersOutCHK = m.getByte(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFF;
      expectedTransfersOutSSK = m.getByte(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFF;
      averageTransfersOutPerInsert = m.getByte(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFF;
      maxTransfersOut = m.getByte(DMT.MAX_TRANSFERS_OUT) & 0xFF;
      maxTransfersOutUpperLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFF;
      maxTransfersOutLowerLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFF;
      maxTransfersOutPeerLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFF;
    } else throw new IllegalArgumentException();
    outputBandwidthLowerLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT);
    outputBandwidthUpperLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT);
    outputBandwidthPeerLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT);
    inputBandwidthLowerLimit = m.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT);
    inputBandwidthUpperLimit = m.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT);
    inputBandwidthPeerLimit = m.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT);
    totalRequests = -1;
    realTime = m.getBoolean(DMT.REAL_TIME_FLAG);
  }

  RunningRequestsSnapshot getOtherRunningRequests() {
    return new RunningRequestsSnapshot(this);
  }

  /**
   * Return the per-peer bandwidth limit for the requested direction.
   *
   * <p>The method selects between the input and output peer limits stored on this snapshot. It
   * performs no normalization and does not consult any external state, so the return value is
   * deterministic and constant for the lifetime of the instance. Use this when comparing a peer's
   * individual contribution against its own cap rather than global thresholds.
   *
   * @param input {@code true} to return the inbound peer limit, {@code false} for outbound
   * @return the peer-specific bandwidth limit in bytes per second for the chosen direction
   */
  public double peerLimit(boolean input) {
    if (input) return inputBandwidthPeerLimit;
    else return outputBandwidthPeerLimit;
  }

  /**
   * Return the lower overall bandwidth limit for the requested direction.
   *
   * <p>This accessor selects the lower bound advertised by the peer for inbound or outbound
   * throughput. The value is not clamped or validated locally; it is returned exactly as stored in
   * the snapshot. Callers typically use this threshold when deciding whether to admit additional
   * work under aggregate load conditions.
   *
   * @param input {@code true} to return the inbound lower limit, {@code false} for outbound
   * @return the lower bandwidth threshold in bytes per second for the chosen direction
   */
  public double lowerLimit(boolean input) {
    if (input) return inputBandwidthLowerLimit;
    else return outputBandwidthLowerLimit;
  }
}
