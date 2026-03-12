package network.crypta.node;

import java.util.Arrays;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.support.SparseBitmap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps a {@link MessageItem} and tracks which byte ranges were sent, acknowledged, or lost.
 *
 * <p>The wrapper supports fragmentation: callers request the next fragment via an upper bound on
 * the available payload size, and this class computes a non-overlapping range that has not been
 * fully acknowledged. Acknowledgments ({@code ack}) and loss notifications ({@code lost}) update
 * the internal state. Some accounting (e.g., resent vs. newly sent bytes) is reported through
 * {@link #onSent(int, int, int, BasePeerNode)}.
 *
 * <p>Concurrency: methods synchronize on internal {@link SparseBitmap} instances. Callers do not
 * need to externally synchronize for single-method calls; do not hold the returned bitmaps. All
 * byte index ranges are inclusive.
 */
public class MessageWrapper {
  private static final Logger LOG = LoggerFactory.getLogger(MessageWrapper.class);

  private final MessageItem item;
  private final boolean isShortMessage;
  private final int messageID;
  private boolean reportedSent;
  private final long created;
  private int resends;

  // Sorted, non-overlapping, inclusive ranges.
  // Locking order: if locking both maps, lock 'sent' before 'acks' to avoid deadlocks.
  private final SparseBitmap acks = new SparseBitmap();
  private final SparseBitmap sent = new SparseBitmap();
  private final SparseBitmap everSent = new SparseBitmap();

  /**
   * Creates a new wrapper for a message.
   *
   * @param item the message payload and metadata; not {@code null}
   * @param messageID unique identifier for logging and on-wire correlation
   */
  public MessageWrapper(MessageItem item, int messageID) {
    this.item = item;
    isShortMessage = item.buf.length <= 255;
    this.messageID = messageID;
    created = System.currentTimeMillis();
  }

  private boolean alreadyAcked = false;

  /**
   * Marks the inclusive range {@code [start, end]} as acknowledged by the peer.
   *
   * @param start first acknowledged byte index (inclusive)
   * @param end last acknowledged byte index (inclusive)
   * @return {@code true} when the entire message is now acknowledged
   */
  public boolean ack(int start, int end) {
    return ack(start, end, null);
  }

  /**
   * Marks the inclusive range {@code [start, end]} as acknowledged by the peer.
   *
   * <p>On the first full acknowledgment of the message, notifies any {@link AsyncMessageCallback}
   * via {@code acknowledged()} and emits a debug log entry.
   *
   * @param start first acknowledged byte index (inclusive)
   * @param end last acknowledged byte index (inclusive)
   * @param pn optional peer for debug logging context
   * @return {@code true} when the entire message is now acknowledged
   */
  public boolean ack(int start, int end, BasePeerNode pn) {
    synchronized (acks) {
      acks.add(start, end);
      if (acks.contains(0, item.buf.length - 1)) {
        if (!alreadyAcked) {
          onFirstFullAck(pn);
        }
        return true;
      }
    }
    return false;
  }

  private void onFirstFullAck(BasePeerNode pn) {
    if (item.cb != null) {
      for (AsyncMessageCallback cb : item.cb) {
        cb.acknowledged();
      }
    }
    alreadyAcked = true;
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Message {} acked; item={}, rtt={} ms, resends={}{}",
          messageID,
          item,
          System.currentTimeMillis() - created,
          resends,
          pn == null ? "" : " for " + pn.shortToString());
    }
  }

  /**
   * Marks the inclusive range {@code [start, end]} as lost and returns the effective lost size.
   *
   * <p>Bytes that overlap already acknowledged ranges are not counted toward the return value and
   * are re-added to the {@code sent} bitmap to preserve invariants.
   *
   * @param start first lost byte index (inclusive)
   * @param end last lost byte index (inclusive)
   * @return number of bytes effectively lost
   */
  public int lost(int start, int end) {
    if (LOG.isTraceEnabled())
      LOG.trace("Mark lost bytes {}..{} (messageId={})", start, end, this.messageID);
    int size = end - start + 1;
    synchronized (sent) {
      synchronized (acks) {
        resends++;
        sent.remove(start, end);

        for (int[] range : acks) {
          boolean outsideLostRange = (range[1] < start) || (range[0] > end);
          if (!outsideLostRange) {
            int toAddStart = Math.max(start, range[0]);
            int toAddEnd = Math.min(end, range[1]);
            if (!(toAddStart == toAddEnd || toAddStart > toAddEnd)) {
              LOG.warn(
                  "Lost range {}->{} overlaps acked {}->{}; add {}->{} to sent",
                  start,
                  end,
                  range[0],
                  range[1],
                  toAddStart,
                  toAddEnd);
              sent.add(toAddStart, toAddEnd);
              size -= (toAddEnd - toAddStart + 1);
            }
          }
        }
      }
    }

    return size;
  }

  public int getMessageID() {
    // Stable identifier used in logs and on-wire metadata.
    return messageID;
  }

  public int getLength() {
    // Payload size in bytes.
    return item.buf.length;
  }

  public boolean isFragmented(int length) {
    if (length < item.buf.length) {
      // Not enough space to send the full payload; fragmentation required.
      return true;
    }

    synchronized (sent) {
      synchronized (acks) {
        if (sent.isEmpty() && acks.isEmpty()) {
          // Nothing sent or acked yet; a single fragment can carry the full payload.
          return false;
        }
      }

      if (sent.contains(0, item.buf.length - 1)) {
        // Single-fragment would fit, and all bytes were already sent once.
        return false;
      }
    }
    return true;
  }

  public int getPriority() {
    return item.getPriority();
  }

  public boolean isFirstFragment() {
    synchronized (sent) {
      synchronized (acks) {
        return sent.isEmpty() && acks.isEmpty();
      }
    }
  }

  /**
   * Returns a {@code MessageFragment} with a length of {@code maxLength} or less, or {@code null}
   * if there is nothing to send. Ranges that have been returned by this function and are not marked
   * as lost, and data that has been acked is never returned.
   *
   * <p>The returned range is inclusive with respect to the source buffer.
   *
   * @param maxLength maximum permitted fragment length in bytes (including protocol overhead)
   * @return a {@code MessageFragment} with a length of {@code maxLength} or less
   */
  MessageFragment getMessageFragment(int maxLength) {
    int start = 0;
    int end = item.buf.length - 1;

    int dataLength;
    byte[] fragmentData;
    synchronized (sent) {
      for (int[] range : sent) {
        if (range[0] == start) {
          start = range[1] + 1;
        } else if (range[0] - start > 0) {
          end = range[0] - 1;
        }
      }

      if (start >= item.buf.length) {
        return null;
      }

      dataLength =
          maxLength
              - 2 // Message id + flags
              - (isShortMessage ? 1 : 2); // Fragment length

      if (isFragmented(dataLength)) {
        dataLength -= (isShortMessage ? 1 : 3); // Message length / fragment offset
      }

      dataLength = Math.min(end - start + 1, dataLength);
      if (dataLength <= 0) return null; // No room for payload after headers.

      fragmentData = Arrays.copyOfRange(item.buf, start, start + dataLength);

      sent.add(start, start + dataLength - 1);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Select range {}..{}; sent={} (messageId={})",
            start,
            start + dataLength - 1,
            sent,
            messageID);
    }

    boolean isFragmented = !((start == 0) && (dataLength == item.buf.length));
    return new MessageFragment(
        new MessageFragmentHeader(isShortMessage, isFragmented, start == 0, messageID),
        new MessageFragmentSizes(dataLength, item.buf.length, start),
        new MessageFragmentPayload(fragmentData, this));
  }

  /**
   * Propagates a disconnect event to the underlying {@link MessageItem}.
   *
   * <p>No state in this wrapper is cleared.
   */
  public void onDisconnect() {
    item.onDisconnect();
  }

  MessageItem getItem() {
    return item;
  }

  /**
   * Returns {@code true} when every byte index has been sent at least once.
   *
   * @return {@code true} if all data was transmitted at least once
   */
  public boolean allSent() {
    synchronized (sent) {
      return sent.contains(0, item.buf.length - 1);
    }
  }

  /**
   * Records that the inclusive range {@code [start, end]} was sent and reports accounting.
   *
   * <p>Bytes are classified as newly sent vs. resent; {@code overhead} is deterministically split
   * between those categories without allocations. When the full message has been sent at least
   * once, triggers {@code onSentAll()} on the underlying item exactly once.
   *
   * @param start first sent byte index (inclusive)
   * @param end last sent byte index (inclusive)
   * @param overhead per-send overhead in bytes
   */
  public void onSent(int start, int end, int overhead, BasePeerNode pn) {
    int report;
    int resent;
    boolean completed;
    synchronized (sent) {
      long rr = computeReportAndResentPacked(start, end, overhead);
      report = (int) (rr >>> 32);
      resent = (int) rr;
      everSent.add(start, end);
      completed = checkAndMarkCompleted();
    }
    if (report != 0) {
      item.onSent(report);
    }
    if (resent != 0 && pn != null) {
      pn.resentBytes(resent);
    }
    if (completed) {
      item.onSentAll();
    }
  }

  private long computeReportAndResentPacked(int start, int end, int overhead) {
    int report;
    int resent;
    if (everSent.contains(start, end)) {
      report = 0;
      resent = end - start + 1 + overhead;
    } else {
      report = everSent.notOverlapping(start, end);
      resent = end - start + 1 - report;
      // Distribute overhead deterministically between the report and resent without allocations
      if (overhead != 0) {
        if (report > 0 && resent == 0) {
          report += overhead;
        } else if (resent > 0 && report == 0) {
          resent += overhead;
        } else {
          int toReport = overhead / 2;
          int toResent = overhead - toReport;
          report += toReport;
          resent += toResent;
        }
      }
    }
    return (((long) report) << 32) | (resent & 0xFFFFFFFFL);
  }

  private boolean checkAndMarkCompleted() {
    if (everSent.contains(0, item.buf.length - 1)) {
      if (reportedSent) {
        return false;
      }
      reportedSent = true;
      return true;
    }
    return false;
  }

  SparseBitmap getSent() {
    return new SparseBitmap(sent);
  }

  SparseBitmap getAcks() {
    return new SparseBitmap(acks);
  }
}
