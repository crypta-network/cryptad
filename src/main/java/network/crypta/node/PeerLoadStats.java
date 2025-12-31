package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;

/**
 * View of a peer's advertised load metrics used for fairness and liability checks.
 *
 * <p>Holds expected in/out transfers, per-peer and overall bandwidth limits, and derived caps for
 * concurrent transfers. Instances are immutable snapshots parsed from a {@link Message}.
 */
public class PeerLoadStats {

  public final PeerNode peer;

  /** These do not include those from the peer */
  public final int expectedTransfersOutCHK;

  public final int expectedTransfersInCHK;
  public final int expectedTransfersOutSSK;
  public final int expectedTransfersInSSK;
  public final double outputBandwidthLowerLimit;
  public final double outputBandwidthUpperLimit;
  public final double outputBandwidthPeerLimit;
  public final double inputBandwidthLowerLimit;
  public final double inputBandwidthUpperLimit;
  public final double inputBandwidthPeerLimit;
  public final int totalRequests;
  public final int averageTransfersOutPerInsert;
  public final boolean realTime;

  /** Maximum transfers out - hard limit based on congestion control. */
  public final int maxTransfersOut;

  /**
   * Maximum transfers out - per-peer limit. If total is over the lower limit, we will be accepted
   * as long as we are below this limit.
   */
  public final int maxTransfersOutPeerLimit;

  /**
   * Maximum transfers out - lower overall limit. If total is over this limit, we will be accepted
   * as long as the per-peer usage is above the peer limit.
   */
  public final int maxTransfersOutLowerLimit;

  /** Maximum transfers out - upper overall limit. Nothing is accepted above this limit. */
  public final int maxTransfersOutUpperLimit;

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof PeerLoadStats s)) return false;
    if (s.peer != peer) return false;
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

  @Override
  public int hashCode() {
    return peer.hashCode();
  }

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

  public PeerLoadStats(PeerNode source, Message m) {
    peer = source;
    if (m.getSpec() == DMT.FNPPeerLoadStatusInt) {
      expectedTransfersInCHK = m.getInt(DMT.OTHER_TRANSFERS_IN_CHK);
      expectedTransfersInSSK = m.getInt(DMT.OTHER_TRANSFERS_IN_SSK);
      expectedTransfersOutCHK = m.getInt(DMT.OTHER_TRANSFERS_OUT_CHK);
      expectedTransfersOutSSK = m.getInt(DMT.OTHER_TRANSFERS_OUT_SSK);
      averageTransfersOutPerInsert = m.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT);
      maxTransfersOut = m.getInt(DMT.MAX_TRANSFERS_OUT);
      maxTransfersOutUpperLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT);
      maxTransfersOutLowerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT);
      maxTransfersOutPeerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT);
    } else if (m.getSpec() == DMT.FNPPeerLoadStatusShort) {
      expectedTransfersInCHK = m.getShort(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFFFF;
      expectedTransfersInSSK = m.getShort(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFFFF;
      expectedTransfersOutCHK = m.getShort(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFFFF;
      expectedTransfersOutSSK = m.getShort(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFFFF;
      averageTransfersOutPerInsert = m.getShort(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFFFF;
      maxTransfersOut = m.getShort(DMT.MAX_TRANSFERS_OUT) & 0xFFFF;
      maxTransfersOutUpperLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFFFF;
      maxTransfersOutLowerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFFFF;
      maxTransfersOutPeerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFFFF;
    } else if (m.getSpec() == DMT.FNPPeerLoadStatusByte) {
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

  public double peerLimit(boolean input) {
    if (input) return inputBandwidthPeerLimit;
    else return outputBandwidthPeerLimit;
  }

  public double lowerLimit(boolean input) {
    if (input) return inputBandwidthLowerLimit;
    else return outputBandwidthLowerLimit;
  }
}
