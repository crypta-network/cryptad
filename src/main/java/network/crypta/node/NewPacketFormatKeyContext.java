package network.crypta.node;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.node.NewPacketFormat.SentPacket;
import network.crypta.support.SentTimeCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Context for sequence numbers and acknowledgments for a single session key.
 *
 * <p>Each {@code SessionKey} maintains its own sequence number space. Sequence numbers are used as
 * part of packet encryption, so they must be unique per key. This class tracks which sequence
 * number to allocate next, which outgoing packets are in flight and awaiting acknowledgment, and
 * which incoming sequence numbers have been observed so that acks can be generated.
 *
 * <p>Thread safety: methods synchronize on internal locks for sequence number allocation and for
 * the ack/sent-packet maps ({@code sequenceNumberLock}, {@code acks}, and {@code sentPackets}).
 * Instances may be shared across threads as long as callers respect these synchronization points.
 *
 * <p>Time units are milliseconds unless stated otherwise.
 *
 * @author toad
 */
public class NewPacketFormatKeyContext {
  private static final Logger LOG = LoggerFactory.getLogger(NewPacketFormatKeyContext.class);

  int firstSeqNumUsed = -1;
  int nextSeqNum;
  int highestReceivedSeqNum;

  byte[][] seqNumWatchList = null;

  /** Index of the packet with the lowest sequence number. */
  int watchListPointer = 0;

  int watchListOffset;

  private final TreeMap<Integer, Long> acks = new TreeMap<>();
  private final HashMap<Integer, SentPacket> sentPackets = new HashMap<>();

  /**
   * Capacity of the cache of sent-times for packets later deemed lost. Retaining recent sent-times
   * allows computing an accurate RTT if an ack arrives after the packet was considered lost.
   */
  private static final int MAX_LOST_SENT_TIMES = 128;

  /** We add all lost packets sequence numbers and the corresponding sent time to this cache. */
  private final SentTimeCache lostSentTimes = new SentTimeCache(MAX_LOST_SENT_TIMES);

  private final Object sequenceNumberLock = new Object();

  private static final int REKEY_THRESHOLD = 100;

  /** All acks must be sent within 200 ms. */
  static final int MAX_ACK_DELAY = 200;

  /**
   * Minimum RTT for purposes of calculating whether to retransmit. Must be greater than
   * MAX_ACK_DELAY
   */
  private static final int MIN_RTT_FOR_RETRANSMIT = 250;

  private int maxSeenInFlight;

  NewPacketFormatKeyContext(int ourFirstSeqNum, int theirFirstSeqNum) {
    ourFirstSeqNum &= 0x7FFFFFFF;
    theirFirstSeqNum &= 0x7FFFFFFF;

    this.nextSeqNum = ourFirstSeqNum;
    this.watchListOffset = theirFirstSeqNum;

    this.highestReceivedSeqNum = theirFirstSeqNum - 1;
    if (this.highestReceivedSeqNum == -1) this.highestReceivedSeqNum = Integer.MAX_VALUE;
  }

  /**
   * Returns whether a new sequence number can be allocated without rekeying.
   *
   * @return {@code true} if {@link #allocateSequenceNumber(BasePeerNode)} would return a valid
   *     sequence number; {@code false} if allocation would wrap to the first used number and a
   *     rekey is required.
   */
  boolean canAllocateSeqNum() {
    synchronized (sequenceNumberLock) {
      return nextSeqNum != firstSeqNumUsed;
    }
  }

  /**
   * Allocates the next sequence number for an outgoing packet.
   *
   * <p>When the sequence number would wrap to {@code firstSeqNumUsed}, the method requests rekeying
   * on the provided peer and returns {@code -1}.
   *
   * @param pn the peer used to trigger rekeying when needed; must not be {@code null} when rekeying
   *     is possible.
   * @return the allocated sequence number, or {@code -1} if allocation is blocked pending rekey.
   */
  int allocateSequenceNumber(BasePeerNode pn) {
    synchronized (sequenceNumberLock) {
      if (firstSeqNumUsed == -1) {
        firstSeqNumUsed = nextSeqNum;
        if (LOG.isDebugEnabled())
          LOG.debug("First sequence number for {} is {}", this, firstSeqNumUsed);
      } else {
        if (nextSeqNum == firstSeqNumUsed) {
          LOG.error("Sequence number allocation blocked; rekey pending");
          pn.startRekeying();
          return -1;
        }

        if (shouldStartRekeying(firstSeqNumUsed, nextSeqNum)) {
          pn.startRekeying();
        }
      }
      int seqNum = nextSeqNum++;
      if (nextSeqNum < 0) {
        nextSeqNum = 0;
      }
      return seqNum;
    }
  }

  private static boolean shouldStartRekeying(int firstUsed, int next) {
    if (firstUsed > next) {
      return firstUsed - next < REKEY_THRESHOLD;
    }
    return (NewPacketFormat.NUM_SEQNUMS - next) + firstUsed < REKEY_THRESHOLD;
  }

  /**
   * Processes an acknowledgment for one of our outgoing packets.
   *
   * <p>The method computes an RTT sample, updates the peer's throttle and ping statistics, and
   * removes the corresponding in-flight entry. If the ack refers to a packet already marked as
   * lost, a saved sent-time is used to compute RTT when available. Duplicate acks are ignored.
   *
   * @param ack the acknowledged sequence number.
   * @param pn the peer associated with the packet; may be {@code null} when peer state is not
   *     available.
   * @param key the session key used to finalize the ack handling.
   */
  public void ack(int ack, BasePeerNode pn, SessionKey key) {
    long rtt;
    int maxSize;
    boolean validAck = false;
    long ackReceived = System.currentTimeMillis();
    if (LOG.isTraceEnabled()) LOG.trace("Ack received for packet {} from {}", ack, pn);
    SentPacket sent;
    synchronized (sentPackets) {
      sent = sentPackets.remove(ack);
      maxSize = (maxSeenInFlight * 2) + 10;
    }
    if (sent != null) {
      rtt = sent.acked(key);
      validAck = true;
    } else {
      if (LOG.isTraceEnabled()) LOG.trace("Packet {} already acknowledged or marked lost", ack);
      long packetSent = lostSentTimes.queryAndRemove(ack);
      if (packetSent < 0) {
        if (LOG.isTraceEnabled()) LOG.trace("Missing sent time for {}; duplicate ack likely", ack);
        return;
      }
      rtt = ackReceived - packetSent;
    }

    if (pn == null) return;
    int rt = (int) Math.min(rtt, Integer.MAX_VALUE);
    pn.reportPing(rt);
    if (validAck) pn.receivedAck(ackReceived);
    PacketThrottle throttle = pn.transport().getThrottle();
    if (throttle == null) return;
    throttle.setRoundTripTime(rt);
    if (validAck) throttle.notifyOfPacketAcknowledged(maxSize);
  }

  /**
   * Queues an acknowledgment for transmission.
   *
   * @param seqno the sequence number to acknowledge.
   * @return {@code -1} if the ack is already queued; otherwise the total count of queued acks.
   */
  public int queueAck(int seqno) {
    synchronized (acks) {
      if (!acks.containsKey(seqno)) {
        acks.put(seqno, System.currentTimeMillis());
        return acks.size();
      } else return -1;
    }
  }

  /**
   * Records that a packet with the given sequence number and length was sent.
   *
   * @param sequenceNumber the packet sequence number.
   * @param length the number of bytes sent.
   */
  public void sent(int sequenceNumber, int length) {
    synchronized (sentPackets) {
      SentPacket sentPacket = sentPackets.get(sequenceNumber);
      if (sentPacket != null) sentPacket.sent(length);
    }
  }

  class AddedAcks {
    /** Are there any urgent acks? */
    final boolean anyUrgentAcks;

    private final Map<Integer, Long> moved;

    public AddedAcks(boolean mustSend, Map<Integer, Long> moved) {
      this.anyUrgentAcks = mustSend;
      this.moved = moved;
    }

    public void abort() {
      synchronized (acks) {
        acks.putAll(moved);
      }
    }
  }

  /**
   * Adds as many queued acks as fit into the given packet.
   *
   * @return a handle for restoring moved acks on abort, or {@code null} if none were added. The
   *     handle indicates whether any acks are urgent and should force a send.
   */
  AddedAcks addAcks(NPFPacket packet, int maxPacketSize, long now) {
    boolean mustSend = false;
    Map<Integer, Long> moved = null;
    int numAcks = 0;
    synchronized (acks) {
      Iterator<Map.Entry<Integer, Long>> it = acks.entrySet().iterator();
      while (it.hasNext() && packet.getLength() < maxPacketSize) {
        Map.Entry<Integer, Long> entry = it.next();
        int ack = entry.getKey();
        // All acks must be sent within MAX_ACK_DELAY (200 ms).
        if (LOG.isTraceEnabled()) LOG.trace("Attempting to add ack {} to packet", ack);
        if (!packet.addAck(ack, maxPacketSize)) {
          if (LOG.isTraceEnabled()) LOG.trace("Cannot add ack {} to packet", ack);
          break;
        }
        if (entry.getValue() + MAX_ACK_DELAY < now) mustSend = true;
        if (moved == null) {
          // Use a temporary map to stage moved acks so they can be restored on abort.
          // Overhead is small because it only holds the acks added to this packet.
          moved = new HashMap<>();
        }
        moved.put(ack, entry.getValue());
        ++numAcks;
        it.remove();
      }
    }
    if (numAcks == 0) return null;
    return new AddedAcks(mustSend, moved);
  }

  public int countSentPackets() {
    synchronized (sentPackets) {
      return sentPackets.size();
    }
  }

  void sent(SentPacket sentPacket, int seqNum, int length) {
    sentPacket.sent(length);
    synchronized (sentPackets) {
      sentPackets.put(seqNum, sentPacket);
      int inFlight = sentPackets.size();
      if (inFlight > maxSeenInFlight) {
        maxSeenInFlight = inFlight;
        if (LOG.isTraceEnabled()) {
          LOG.trace("Max in-flight packets updated to {} for {}", maxSeenInFlight, this);
        }
      }
    }
  }

  /**
   * Computes the next time to check for lost packets.
   *
   * @param averageRTT the peer's average RTT in milliseconds.
   * @return an absolute timestamp (ms since epoch) when the next loss check should occur, or {@link
   *     Long#MAX_VALUE} if there are no in-flight packets.
   */
  public long timeCheckForLostPackets(double averageRTT) {
    long timeCheck = Long.MAX_VALUE;
    // Because MIN_RTT_FOR_RETRANSMIT > MAX_ACK_DELAY and averageRTT includes the ack delay,
    // there is no need to add the ack delay here.
    double avgRtt = Math.max(MIN_RTT_FOR_RETRANSMIT, averageRTT);
    long maxDelay = (long) (avgRtt + MAX_ACK_DELAY * 1.1);
    synchronized (sentPackets) {
      for (SentPacket s : sentPackets.values()) {
        long t = s.getSentTime() + maxDelay;
        if (t < timeCheck) {
          timeCheck = t;
        }
      }
    }
    return timeCheck;
  }

  /**
   * Marks overdue in-flight packets as lost and updates backoff.
   *
   * @param averageRTT the peer's average RTT in milliseconds.
   * @param curTime the current time in milliseconds.
   * @param pn the peer whose throttle/backoff should be updated; may be {@code null}.
   */
  public void checkForLostPackets(double averageRTT, long curTime, BasePeerNode pn) {
    // Mark overdue packets as lost.
    int bigLostCount = 0;
    int count = 0;

    // Because MIN_RTT_FOR_RETRANSMIT > MAX_ACK_DELAY and averageRTT includes the ack delay,
    // there is no need to add the ack delay here.
    double avgRtt = Math.max(MIN_RTT_FOR_RETRANSMIT, averageRTT);
    long maxDelay = (long) (avgRtt + MAX_ACK_DELAY * 1.1);
    long threshold = curTime - maxDelay;

    synchronized (sentPackets) {
      Iterator<Map.Entry<Integer, SentPacket>> it = sentPackets.entrySet().iterator();
      while (it.hasNext()) {
        Map.Entry<Integer, SentPacket> e = it.next();
        SentPacket s = e.getValue();
        if (s.getSentTime() < threshold) {
          markPacketAsLost(e, s, curTime, threshold);
          it.remove();
          bigLostCount++;
        } else {
          count++;
        }
      }
    }
    if (count > 0 && LOG.isDebugEnabled())
      LOG.debug("In-flight packets={}, retransmit threshold={} ms", count, maxDelay);
    if (bigLostCount != 0 && pn != null) {
      PacketThrottle throttle = pn.transport().getThrottle();
      if (throttle != null) {
        throttle.notifyOfPacketsLost(bigLostCount);
      }
      pn.backoffOnResend();
    }
  }

  private void markPacketAsLost(
      Map.Entry<Integer, SentPacket> entry, SentPacket packet, long curTime, long threshold) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Mark packet {} as lost; delay {} ms, threshold {} ms",
          entry.getKey(),
          curTime - packet.getSentTime(),
          threshold);
    }
    if (!packet.messages.isEmpty()) {
      lostSentTimes.report(entry.getKey(), packet.getSentTime());
    }
    packet.lost();
  }

  /**
   * Computes the next deadline to flush queued acks.
   *
   * @return an absolute timestamp (ms since epoch) for the earliest ack deadline, or {@link
   *     Long#MAX_VALUE} if there are no queued acks.
   */
  public long timeCheckForAcks() {
    long ret = Long.MAX_VALUE;
    synchronized (acks) {
      for (Long l : acks.values()) {
        long timeout = l + MAX_ACK_DELAY;
        if (ret > timeout) ret = timeout;
      }
    }
    return ret;
  }

  /** Treats all in-flight packets as lost and clears state on disconnect. */
  public void disconnected() {
    synchronized (sentPackets) {
      for (SentPacket s : sentPackets.values()) {
        s.lost();
      }
      sentPackets.clear();
    }
  }
}
