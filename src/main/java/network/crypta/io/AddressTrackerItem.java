package network.crypta.io;

import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks message activity to and from a single logical address and derives recent inactivity gaps.
 *
 * <p>The concrete address (for example, an IP:port, an IP only, or another scheme) is owned by a
 * subclass; this type focuses purely on timing and counters:
 *
 * <ul>
 *   <li>First/last send and receive times (milliseconds since epoch).
 *   <li>Total send/receive counters.
 *   <li>A fixed-size ring of the most recent inactivity gaps (see {@link #getGaps()}).
 * </ul>
 *
 * <p>Concurrency: mutating and accessor methods on the evolving state are synchronized unless
 * stated otherwise. {@link #longestGap(long, long)} is intentionally unsynchronized and returns a
 * best-effort value suitable for diagnostics and UI.
 */
public class AddressTrackerItem {
  private static final Logger LOG = LoggerFactory.getLogger(AddressTrackerItem.class);

  private static final AtomicLongFieldUpdater<AddressTrackerItem> PACKETS_SENT_UPDATER =
      AtomicLongFieldUpdater.newUpdater(AddressTrackerItem.class, "packetsSent");

  private static final AtomicLongFieldUpdater<AddressTrackerItem> PACKETS_RECEIVED_UPDATER =
      AtomicLongFieldUpdater.newUpdater(AddressTrackerItem.class, "packetsReceived");

  /**
   * Time of the first observed receive from this address, in milliseconds since epoch, or {@code
   * -1} if none.
   */
  private volatile long timeFirstReceivedPacket;

  /**
   * Time of the first observed send to this address, in milliseconds since epoch, or {@code -1} if
   * none.
   */
  private volatile long timeFirstSentPacket;

  /**
   * The earliest time (strict upper bound) at which we know no packet was received. Typically, the
   * socket startup time may advance if caches are flushed.
   */
  private final long timeDefinitelyNoPacketsReceived;

  /**
   * The earliest time (strict upper bound) at which we know no packet was sent. Typically, the node
   * startup time; may advance if caches are flushed.
   */
  private final long timeDefinitelyNoPacketsSent;

  /** Time of the most recent receiving, in milliseconds since epoch, or {@code -1} if none. */
  private volatile long timeLastReceivedPacket;

  /** Time of the most recent sending, in milliseconds since epoch, or {@code -1} if none. */
  private volatile long timeLastSentPacket;

  /** Total number of packets sent to this address. */
  private volatile long packetsSent;

  /** Total number of packets received from this address. */
  private volatile long packetsReceived;

  /** Number of recent gaps to retain and expose via {@link #getGaps()}. */
  public static final int TRACK_GAPS = 5;

  private final long[] gapLengths;
  private final long[] gapLengthRecvTimes;

  /** Minimum inactivity length (ms) required to record a gap. */
  private static final long GAP_THRESHOLD = AddressTracker.MAYBE_TUNNEL_LENGTH;

  /**
   * When true, the interval start considers the last receiving as well as the last sending. This
   * yields conservative (longer) gaps when back-to-back receives occur without intervening sending.
   */
  static final boolean INCLUDE_RECEIVED_PACKETS = true;

  private static final class ParsedState {
    private long timeFirstReceivedPacket;
    private long timeFirstSentPacket;
    private long timeDefinitelyNoPacketsSent;
    private long timeDefinitelyNoPacketsReceived;
    private long timeLastReceivedPacket;
    private long timeLastSentPacket;
    private long packetsSent;
    private long packetsReceived;
    private long[] gapLengths;
    private long[] gapLengthRecvTimes;
  }

  /**
   * Creates an empty tracker with known upper bounds for the "no packets yet" window.
   *
   * @param timeDefinitelyNoPacketsReceived the earliest time at which receiving is known to have
   *     been impossible (e.g., socket startup), in milliseconds since epoch
   * @param timeDefinitelyNoPacketsSent the earliest time at which sending is known to have been
   *     impossible (e.g., node startup), in milliseconds since epoch
   */
  public AddressTrackerItem(
      long timeDefinitelyNoPacketsReceived, long timeDefinitelyNoPacketsSent) {
    timeFirstReceivedPacket = -1;
    timeFirstSentPacket = -1;
    timeLastReceivedPacket = -1;
    timeLastSentPacket = -1;
    packetsSent = 0;
    packetsReceived = 0;
    this.timeDefinitelyNoPacketsReceived = timeDefinitelyNoPacketsReceived;
    this.timeDefinitelyNoPacketsSent = timeDefinitelyNoPacketsSent;
    gapLengths = new long[TRACK_GAPS];
    gapLengthRecvTimes = new long[TRACK_GAPS];
  }

  private AddressTrackerItem(ParsedState parsed) {
    timeFirstReceivedPacket = parsed.timeFirstReceivedPacket;
    timeFirstSentPacket = parsed.timeFirstSentPacket;
    timeDefinitelyNoPacketsSent = parsed.timeDefinitelyNoPacketsSent;
    timeDefinitelyNoPacketsReceived = parsed.timeDefinitelyNoPacketsReceived;
    timeLastReceivedPacket = parsed.timeLastReceivedPacket;
    timeLastSentPacket = parsed.timeLastSentPacket;
    packetsSent = parsed.packetsSent;
    packetsReceived = parsed.packetsReceived;
    gapLengths = parsed.gapLengths;
    gapLengthRecvTimes = parsed.gapLengthRecvTimes;
  }

  /**
   * Reconstructs a tracker from a serialized {@link SimpleFieldSet}.
   *
   * <p>Expected keys: {@code TimeFirstReceivedPacket}, {@code TimeFirstSentPacket}, {@code
   * TimeDefinitelyNoPacketsSent}, {@code TimeDefinitelyNoPacketsReceived}, {@code
   * TimeLastReceivedPacket}, {@code TimeLastSentPacket}, {@code PacketsSent}, {@code
   * PacketsReceived}, and a {@code Gaps} subset containing {@code 0..(TRACK_GAPS-1)} with {@code
   * Length} and {@code Received}.
   *
   * @param fs field set produced by {@link #toFieldSet()}
   * @throws FSParseException if required keys are missing or values cannot be parsed
   */
  public AddressTrackerItem(SimpleFieldSet fs) throws FSParseException {
    this(parseState(fs));
  }

  private static ParsedState parseState(SimpleFieldSet fs) throws FSParseException {
    ParsedState parsed = new ParsedState();
    parsed.timeFirstReceivedPacket = fs.getLong("TimeFirstReceivedPacket");
    parsed.timeFirstSentPacket = fs.getLong("TimeFirstSentPacket");
    parsed.timeDefinitelyNoPacketsSent = fs.getLong("TimeDefinitelyNoPacketsSent");
    parsed.timeDefinitelyNoPacketsReceived = fs.getLong("TimeDefinitelyNoPacketsReceived");
    parsed.timeLastReceivedPacket = fs.getLong("TimeLastReceivedPacket");
    parsed.timeLastSentPacket = fs.getLong("TimeLastSentPacket");
    parsed.packetsSent = fs.getLong("PacketsSent");
    parsed.packetsReceived = fs.getLong("PacketsReceived");
    SimpleFieldSet gaps = fs.getSubset("Gaps");
    parsed.gapLengths = new long[TRACK_GAPS];
    parsed.gapLengthRecvTimes = new long[TRACK_GAPS];
    for (int i = 0; i < TRACK_GAPS; i++) {
      SimpleFieldSet gap = gaps.subset(Integer.toString(i));
      if (gap == null) {
        LOG.info("No more gaps at i={} - TRACK_GAPS changed??", i);
        break;
      }
      parsed.gapLengths[i] = gap.getLong("Length");
      parsed.gapLengthRecvTimes[i] = gap.getLong("Received");
    }
    return parsed;
  }

  /**
   * Records that a packet was sent at the given time.
   *
   * @param now timestamp in milliseconds since epoch
   */
  public synchronized void sentPacket(long now) {
    PACKETS_SENT_UPDATER.incrementAndGet(this);
    if (timeFirstSentPacket < 0) timeFirstSentPacket = now;
    timeLastSentPacket = now;
  }

  /**
   * Records that a packet was received at the given time and updates gap history when the
   * inactivity since the last relevant activity exceeds the threshold.
   *
   * <p>Interval start is the maximum of the last send, the {@code no-sent} bound, and, when {@link
   * #INCLUDE_RECEIVED_PACKETS} is true, the last receiving and the {@code no-recv} bound.
   *
   * @param now timestamp in milliseconds since epoch
   */
  public synchronized void receivedPacket(long now) {
    PACKETS_RECEIVED_UPDATER.incrementAndGet(this);
    if (timeFirstReceivedPacket < 0) timeFirstReceivedPacket = now;
    long oldTimeLastReceivedPacket = timeLastReceivedPacket;
    timeLastReceivedPacket = now;
    // Establish the interval start from known lower bounds and recent activity.
    long startTime;
    startTime = timeLastSentPacket;
    startTime = Math.max(startTime, timeDefinitelyNoPacketsSent);
    if (INCLUDE_RECEIVED_PACKETS) {
      startTime = Math.max(startTime, oldTimeLastReceivedPacket);
      startTime = Math.max(startTime, timeDefinitelyNoPacketsReceived);
    }
    // No usable lower bound yet (all unknown/zero) → nothing to record.
    if (startTime <= 0) return;
    if (now - startTime > GAP_THRESHOLD) {
      // This may be a new gap or a refinement of the most recent one.
      // Rotate only if a sending occurred after the previously recorded gap; otherwise overwrite
      // [0].
      if (timeLastSentPacket >= gapLengthRecvTimes[0]) {
        // Shift right to make room at [0]; manual loop avoids overlapping copy concerns.
        for (int i = TRACK_GAPS - 1; i > 0; i--) {
          gapLengths[i] = gapLengths[i - 1];
          gapLengthRecvTimes[i] = gapLengthRecvTimes[i - 1];
        }
      }
      gapLengths[0] = (now - startTime);
      gapLengthRecvTimes[0] = now;
    }
  }

  /**
   * Returns whether the most recent recorded gap ended within the given horizon.
   *
   * <p>This is a coarse signal that a long-running tunnel may have been observed recently.
   *
   * @param horizon look-back window in milliseconds
   * @return {@code true} if the latest gap's receiving time is within {@code horizon} of "now"
   */
  public synchronized boolean hasLongTunnel(long horizon) {
    return gapLengthRecvTimes[0] > System.currentTimeMillis() - horizon;
  }

  /**
   * Returns the maximum gap length among gaps whose end time is within {@code horizon} of {@code
   * now}.
   *
   * <p>Stops scanning once it reaches a gap older than the horizon because entries are ordered most
   * recent first.
   *
   * @param horizon look-back window in milliseconds
   * @param now reference time in milliseconds since epoch
   * @return longest qualifying gap length in milliseconds, or {@code -1} if none
   */
  public long longestGap(long horizon, long now) {
    long longestGap = -1;
    for (int i = 0; i < TRACK_GAPS; i++) {
      if (gapLengthRecvTimes[i] < now - horizon) break;
      longestGap = Math.max(longestGap, gapLengths[i]);
    }
    return longestGap;
  }

  /**
   * Immutable view of a recorded connectivity gap.
   *
   * @param gapLength duration in milliseconds between the derived interval start (see {@link
   *     #receivedPacket(long)}) and the packet that ended the gap
   * @param receivedPacketAt absolute time in milliseconds when the ending packet was received
   */
  public record Gap(long gapLength, long receivedPacketAt) {}

  /**
   * Returns a snapshot of the most recent gaps ordered newest-first.
   *
   * <p>Unpopulated slots contain zeros for both fields.
   *
   * @return fixed-size array of {@link Gap} instances with length {@link #TRACK_GAPS}
   */
  public synchronized Gap[] getGaps() {
    Gap[] gaps = new Gap[TRACK_GAPS];
    for (int i = 0; i < TRACK_GAPS; i++) {
      gaps[i] = new Gap(gapLengths[i], gapLengthRecvTimes[i]);
    }
    return gaps;
  }

  /**
   * Returns the time of the first observed receive, or {@code -1} if none.
   *
   * @return milliseconds since epoch, or {@code -1}
   */
  public synchronized long firstReceivedPacket() {
    return timeFirstReceivedPacket;
  }

  /**
   * Returns the time of the first observed send, or {@code -1} if none.
   *
   * @return milliseconds since epoch, or {@code -1}
   */
  public synchronized long firstSentPacket() {
    return timeFirstSentPacket;
  }

  /**
   * Returns the time of the most recent receiving, or {@code -1} if none.
   *
   * @return milliseconds since epoch, or {@code -1}
   */
  public synchronized long lastReceivedPacket() {
    return timeLastReceivedPacket;
  }

  /**
   * Returns the time of the most recent sending, or {@code -1} if none.
   *
   * @return milliseconds since epoch, or {@code -1}
   */
  public synchronized long lastSentPacket() {
    return timeLastSentPacket;
  }

  /**
   * Returns the earliest time at which sending was definitely not possible.
   *
   * @return milliseconds since epoch
   */
  public synchronized long timeDefinitelyNoPacketsSent() {
    return timeDefinitelyNoPacketsSent;
  }

  /**
   * Returns the earliest time at which receiving was definitely not possible.
   *
   * @return milliseconds since epoch
   */
  public synchronized long timeDefinitelyNoPacketsReceived() {
    return timeDefinitelyNoPacketsReceived;
  }

  /** Returns the total number of packets sent. */
  public synchronized long packetsSent() {
    return packetsSent;
  }

  /** Returns the total number of packets received. */
  public synchronized long packetsReceived() {
    return packetsReceived;
  }

  /**
   * Returns whether the first observed activity was a sending rather than a receiving.
   *
   * <p>Returns {@code true} if there has been no receiving, {@code false} if there has been no
   * send, otherwise compares first-send and first-receive times.
   *
   * @return {@code true} if the first event was a sending
   */
  public synchronized boolean weSentFirst() {
    if (timeFirstReceivedPacket == -1) return true;
    if (timeFirstSentPacket == -1) return false;
    return timeFirstSentPacket < timeFirstReceivedPacket;
  }

  /**
   * Returns the delay from the {@code no-sent} bound to the first sending, or {@code -1} if nothing
   * has been sent.
   *
   * @return milliseconds since the {@code no-sent} bound, or {@code -1}
   */
  public synchronized long timeFromStartupToFirstSentPacket() {
    if (packetsSent == 0) return -1;
    return timeFirstSentPacket - timeDefinitelyNoPacketsSent;
  }

  /**
   * Returns the delay from the {@code no-recv} bound to the first receiving, or {@code -1} if
   * nothing has been received.
   *
   * @return milliseconds since the {@code no-recv} bound, or {@code -1}
   */
  public synchronized long timeFromStartupToFirstReceivedPacket() {
    if (packetsReceived == 0) return -1;
    return timeFirstReceivedPacket - timeDefinitelyNoPacketsReceived;
  }

  /**
   * Serializes this tracker to a {@link SimpleFieldSet} including counters, timestamps, and the
   * {@code Gaps} subset with up to {@link #TRACK_GAPS} entries.
   *
   * @return a field set suitable for persistence and {@link #AddressTrackerItem(SimpleFieldSet)}
   */
  public SimpleFieldSet toFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("TimeFirstReceivedPacket", timeFirstReceivedPacket);
    fs.put("TimeFirstSentPacket", timeFirstSentPacket);
    fs.put("TimeDefinitelyNoPacketsSent", timeDefinitelyNoPacketsSent);
    fs.put("TimeDefinitelyNoPacketsReceived", timeDefinitelyNoPacketsReceived);
    fs.put("TimeLastReceivedPacket", timeLastReceivedPacket);
    fs.put("TimeLastSentPacket", timeLastSentPacket);
    fs.put("PacketsSent", packetsSent);
    fs.put("PacketsReceived", packetsReceived);
    SimpleFieldSet gaps = new SimpleFieldSet(true);
    for (int i = 0; i < TRACK_GAPS; i++) {
      SimpleFieldSet gap = new SimpleFieldSet(true);
      gap.put("Length", gapLengths[i]);
      gap.put("Received", gapLengthRecvTimes[i]);
      gaps.put(Integer.toString(i), gap);
    }
    fs.put("Gaps", gaps);
    return fs;
  }
}
