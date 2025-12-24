package network.crypta.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.SortedSet;
import java.util.TreeSet;
import network.crypta.crypt.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Packet encoder/decoder for the node wire format.
 *
 * <p>Holds parsed state (sequence number, ACKs, message fragments, and per-packet lossy messages),
 * exposes helpers to append content with size accounting, and serializes the packet back to bytes.
 * Parsing sets an internal error flag when the input is malformed or truncated; callers can inspect
 * it via {@link #getError()}.
 *
 * <p>Instances are not thread-safe.
 */
class NPFPacket {
  private static final Logger LOG = LoggerFactory.getLogger(NPFPacket.class);

  private int sequenceNumber;
  private final SortedSet<Integer> acks = new TreeSet<>();
  private final List<MessageFragment> fragments = new ArrayList<>();

  /**
   * Per-packet lossy payloads.
   *
   * <p>Receivers process these before regular fragments and may drop them without affecting
   * correctness. Older peers can emit unexpected data here; callers should validate as needed.
   */
  private final List<byte[]> lossyMessages = new LinkedList<>();

  private boolean error;
  private int length = 5; // Sequence number (4), numAcks(1)
  private int ackRangeCount = 0;
  private int ackBlockByteSize = 0;

  /**
   * Parse a plaintext packet into an {@code NPFPacket}.
   *
   * <p>Decodes the sequence header, ACK ranges, message fragments, and per-packet lossy messages
   * from {@code plaintext}. On malformed or truncated input, this method sets the packet's error
   * flag and returns the partially populated packet.
   *
   * @param plaintext the decoded packet bytes (not encrypted), length in bytes
   * @param pn the peer context used for logging; must be non-null
   * @return a parsed packet instance; never {@code null}
   * @throws IllegalArgumentException if {@code pn} is {@code null}
   */
  public static NPFPacket create(byte[] plaintext, BasePeerNode pn) {
    NPFPacket packet = new NPFPacket();
    if (pn == null)
      throw new IllegalArgumentException("Can't estimate an ack type of received packet");

    int offset = 0;
    offset = parseHeader(plaintext, packet, offset);
    if (offset < 0) return packet; // error already set

    offset = parseFragmentsAndLossyMessages(plaintext, pn, packet, offset);
    if (offset < 0) return packet; // error already set

    packet.length = offset;
    return packet;
  }

  private static int parseHeader(byte[] plaintext, NPFPacket packet, int offset) {
    if (plaintext.length < (offset + 5)) { // Sequence number + the number of acks
      packet.error = true;
      return -1;
    }

    packet.sequenceNumber =
        ((plaintext[offset] & 0xFF) << 24)
            | ((plaintext[offset + 1] & 0xFF) << 16)
            | ((plaintext[offset + 2] & 0xFF) << 8)
            | (plaintext[offset + 3] & 0xFF);
    offset += 4;

    int numAckRanges = plaintext[offset++] & 0xFF;
    if (numAckRanges > 0) {
      try {
        offset = parseAckRanges(plaintext, numAckRanges, packet, offset);
      } catch (ArrayIndexOutOfBoundsException _) {
        packet.error = true;
        return -1;
      }
    }
    return offset;
  }

  /**
   * Parse ACK ranges encoded after the header.
   *
   * <p>Each range is either a full 4-byte sequence number (for the first or a far range) or a
   * 1-byte delta from the previous range start. This method updates {@code packet.acks} and returns
   * the new offset.
   */
  private static int parseAckRanges(
      byte[] plaintext, int numAckRanges, NPFPacket packet, int offset) {
    int ack;
    int prevAck = 0;
    for (int i = 0; i < numAckRanges; i++) {
      if (i == 0) {
        ack =
            ((plaintext[offset] & 0xFF) << 24)
                | ((plaintext[offset + 1] & 0xFF) << 16)
                | ((plaintext[offset + 2] & 0xFF) << 8)
                | (plaintext[offset + 3] & 0xFF);
        offset += 4;
      } else {
        int distanceFromPrevious = (plaintext[offset++] & 0xFF);
        if (distanceFromPrevious != 0) {
          ack = prevAck + distanceFromPrevious;
        } else {
          // Far offset
          ack =
              ((plaintext[offset] & 0xFF) << 24)
                  | ((plaintext[offset + 1] & 0xFF) << 16)
                  | ((plaintext[offset + 2] & 0xFF) << 8)
                  | (plaintext[offset + 3] & 0xFF);
          offset += 4;
        }
      }

      int rangeSize = (plaintext[offset++] & 0xFF);
      for (int j = 1; j <= rangeSize; j++) {
        packet.acks.add(ack++);
      }

      prevAck = ack - 1;
    }
    return offset;
  }

  /**
   * Parse message fragments followed by optional lossy messages.
   *
   * <p>Stops at the end of {@code plaintext} or when it encounters the lossy messages section.
   * Returns the new offset or a negative value when an error is already recorded on the packet.
   */
  private static int parseFragmentsAndLossyMessages(
      byte[] plaintext, BasePeerNode pn, NPFPacket packet, int offset) {
    int prevFragmentID = -1;
    while (offset < plaintext.length) {
      int res = parseFragmentEntry(plaintext, pn, packet, offset, prevFragmentID);
      if (res == PARSE_LOSSY) {
        return tryParseLossyMessages(packet, plaintext, offset);
      }
      if (res < 0) return -1;
      // Update prevFragmentID: the last added fragment's messageID is at the end of the list.
      prevFragmentID = packet.fragments.getLast().messageID;
      offset = res;
    }

    return offset;
  }

  private static final int PARSE_LOSSY = -2;

  private static int parseFragmentEntry(
      byte[] plaintext, BasePeerNode pn, NPFPacket packet, int offset, int prevFragmentID) {
    byte flags = plaintext[offset];
    boolean isFragmented = (flags & 0x40) != 0;
    boolean firstFragment = (flags & 0x20) != 0;

    if (!isFragmented && !firstFragment) {
      return PARSE_LOSSY;
    }

    IdAndOffset idOff = parseMessageId(plaintext, offset, prevFragmentID, packet);
    if (idOff == null) return -1;
    return materializeFragment(plaintext, idOff.offset, flags, idOff.id, pn, packet);
  }

  private static int materializeFragment(
      byte[] plaintext, int offset, byte flags, int messageID, BasePeerNode pn, NPFPacket packet) {
    boolean shortMessage = (flags & 0x80) != 0;
    boolean isFragmented = (flags & 0x40) != 0;
    boolean firstFragment = (flags & 0x20) != 0;

    int headerLen = shortMessage ? 1 : 2;
    int fragMetaLen;
    if (isFragmented) {
      // For fragmented messages, the additional metadata after the fragment length is
      // 1 byte (short) or 2 bytes (long) for total-length/offset.
      fragMetaLen = shortMessage ? 1 : 2;
    } else {
      fragMetaLen = 0;
    }
    int requiredLength = offset + headerLen + fragMetaLen;
    if (plaintext.length < requiredLength) {
      packet.error = true;
      return -1;
    }

    Lengths lens = parseLengths(plaintext, offset, shortMessage, isFragmented);
    offset = lens.offset;

    int msgLengthForCheck;
    if (firstFragment) {
      msgLengthForCheck = lens.messageLength;
    } else {
      msgLengthForCheck = lens.fragmentLength;
    }
    if (!fragmentFits(plaintext, offset, lens.fragmentLength, msgLengthForCheck, messageID, pn)) {
      packet.error = true;
      return -1;
    }

    byte[] fragmentData = Arrays.copyOfRange(plaintext, offset, offset + lens.fragmentLength);
    offset += lens.fragmentLength;

    int outMessageLength;
    int outFragmentOffset;
    if (isFragmented) {
      if (firstFragment) {
        outMessageLength = lens.messageLength;
        outFragmentOffset = 0;
      } else {
        outMessageLength = -1;
        outFragmentOffset = lens.fragmentOffset;
      }
    } else {
      outMessageLength = lens.messageLength;
      outFragmentOffset = 0;
    }

    packet.fragments.add(
        new MessageFragment(
            shortMessage,
            isFragmented,
            firstFragment,
            messageID,
            lens.fragmentLength,
            outMessageLength,
            outFragmentOffset,
            fragmentData,
            null));

    return offset;
  }

  private static IdAndOffset parseMessageId(
      byte[] plaintext, int offset, int prevFragmentID, NPFPacket packet) {
    int messageID;
    if ((plaintext[offset] & 0x10) != 0) {
      if (plaintext.length < (offset + 4)) {
        packet.error = true;
        return null;
      }

      messageID =
          ((plaintext[offset] & 0x0F) << 24)
              | ((plaintext[offset + 1] & 0xFF) << 16)
              | ((plaintext[offset + 2] & 0xFF) << 8)
              | (plaintext[offset + 3] & 0xFF);
      offset += 4;
    } else {
      if (plaintext.length < (offset + 2)) {
        packet.error = true;
        return null;
      }

      if (prevFragmentID == -1) {
        LOG.warn("First fragment lacks full message id");
        packet.error = true;
        return null;
      }
      messageID =
          prevFragmentID + (((plaintext[offset] & 0x0F) << 8) | (plaintext[offset + 1] & 0xFF));
      offset += 2;
    }
    return new IdAndOffset(messageID, offset);
  }

  private static Lengths parseLengths(
      byte[] plaintext, int offset, boolean shortMessage, boolean isFragmented) {
    int fragmentLength;
    if (shortMessage) {
      fragmentLength = plaintext[offset++] & 0xFF;
    } else {
      fragmentLength = ((plaintext[offset] & 0xFF) << 8) | (plaintext[offset + 1] & 0xFF);
      offset += 2;
    }

    int messageLength;
    int fragmentOffset = 0;
    if (isFragmented) {
      int value;
      if (shortMessage) {
        value = plaintext[offset++] & 0xFF;
      } else {
        value = ((plaintext[offset] & 0xFF) << 8) | (plaintext[offset + 1] & 0xFF);
        offset += 2;
      }

      // Caller already decoded flags from the header and knows whether this is the first fragment.
      // Expose both values; the caller uses messageLength for first fragments, and fragmentOffset
      // otherwise.

      // By contract with caller: first fragment uses messageLength=value, otherwise fragmentOffset
      messageLength = value;
      fragmentOffset = value;
    } else {
      messageLength = fragmentLength;
    }
    return new Lengths(fragmentLength, messageLength, fragmentOffset, offset);
  }

  private static boolean fragmentFits(
      byte[] plaintext,
      int offset,
      int fragmentLength,
      int messageLength,
      int messageID,
      BasePeerNode pn) {
    if ((offset + fragmentLength) > plaintext.length) {
      LOG.error(
          "Fragment out of bounds: offset={} fragmentLength={} plaintextLength={} messageLength={}"
              + " messageId={}{}",
          offset,
          fragmentLength,
          plaintext.length,
          messageLength,
          messageID,
          pn == null ? "" : (" from " + pn.shortToString()));
      return false;
    }
    return true;
  }

  private record IdAndOffset(int id, int offset) {}

  private record Lengths(int fragmentLength, int messageLength, int fragmentOffset, int offset) {}

  private static int tryParseLossyMessages(NPFPacket packet, byte[] plaintext, int offset) {
    int origOffset = offset;
    while (true) {
      if (plaintext[offset] != 0x1F) return offset; // Padding
      // Else it might be some per-packet lossy messages
      offset++;
      if (offset >= plaintext.length) {
        packet.lossyMessages.clear();
        return origOffset;
      }
      int len = plaintext[offset] & 0xFF;
      offset++;
      if (len > plaintext.length - offset) {
        packet.lossyMessages.clear();
        return origOffset;
      }
      byte[] fragment = Arrays.copyOfRange(plaintext, offset, offset + len);
      packet.lossyMessages.add(fragment);
      offset += len;
      if (offset == plaintext.length) return offset;
    }
  }

  /**
   * Encode this packet into {@code buf} starting at {@code offset}.
   *
   * <p>Writes the header, ACK blocks, message fragments, and lossy messages. If {@code buf} has
   * remaining capacity after the encoded packet, the method fills the remainder with padding bytes
   * and normalizes the first padding byte to avoid colliding with header or lossy markers.
   *
   * @param buf destination buffer to receive the encoded packet
   * @param offset starting index in {@code buf}
   * @param paddingGen optional RNG for padding; when {@code null}, no padding is generated
   * @return the end offset (first index after the encoded packet)
   */
  @SuppressWarnings("UnusedReturnValue")
  public int toBytes(byte[] buf, int offset, Random paddingGen) {
    int origOffset = offset;
    offset = writeHeader(buf, offset);
    offset = writeAcks(buf, offset);
    offset = writeFragments(buf, offset);
    offset = writeLossyMessages(buf, offset);

    if ((offset - origOffset) != length) {
      throw new IllegalStateException("Encoded length mismatch");
    }

    if (offset < buf.length) {
      writePadding(buf, offset, paddingGen);
    }

    return offset;
  }

  private int writeHeader(byte[] buf, int offset) {
    buf[offset] = (byte) (sequenceNumber >>> 24);
    buf[offset + 1] = (byte) (sequenceNumber >>> 16);
    buf[offset + 2] = (byte) (sequenceNumber >>> 8);
    buf[offset + 3] = (byte) (sequenceNumber);
    return offset + 4;
  }

  private int writeAcks(byte[] buf, int offset) {
    buf[offset++] = (byte) (ackRangeCount);
    List<AckRange> ranges = computeAckRanges();
    if (!ranges.isEmpty()) {
      for (int i = 0; i < ranges.size(); i++) {
        AckRange r = ranges.get(i);
        if (i == 0 || r.deltaFromPrev >= 254) {
          if (i != 0) buf[offset++] = (byte) 0; // Mark a far offset
          offset = writeInt(buf, offset, r.start);
        } else {
          buf[offset++] = (byte) r.deltaFromPrev;
        }
        int rangeSize = r.end - r.start + 1;
        buf[offset++] = (byte) rangeSize;
      }
      // Edge case: if the last ack does not fit into previous range, the algorithm above already
      // created a separate range for it, so no extra handling is required here.
    }
    return offset;
  }

  private List<AckRange> computeAckRanges() {
    // Coalesce contiguous ACKs into ranges; ranges hold start/end and a delta from the previous
    // range to allow compact encoding (or a far-range marker when out of window).
    List<AckRange> out = new ArrayList<>();
    Iterator<Integer> it = acks.iterator();
    if (!it.hasNext()) return out;
    int prevEnd = -1;
    int start = -1;
    int end = -1;
    while (it.hasNext()) {
      int ack = it.next();
      if (start == -1) {
        start = end = ack;
      } else if (ack == end + 1 && (end - start) < 254) {
        end = ack;
      } else {
        int delta = (prevEnd == -1) ? Integer.MAX_VALUE : (start - prevEnd);
        out.add(new AckRange(start, end, delta));
        prevEnd = end;
        start = end = ack;
      }
    }
    if (start != -1) {
      int delta = (prevEnd == -1) ? Integer.MAX_VALUE : (start - prevEnd);
      out.add(new AckRange(start, end, delta));
    }
    return out;
  }

  /**
   * @param deltaFromPrev Integer.MAX_VALUE indicates far offset
   */
  private record AckRange(int start, int end, int deltaFromPrev) {}

  private static int writeInt(byte[] buf, int offset, int value) {
    buf[offset] = (byte) (value >>> 24);
    buf[offset + 1] = (byte) (value >>> 16);
    buf[offset + 2] = (byte) (value >>> 8);
    buf[offset + 3] = (byte) (value);
    return offset + 4;
  }

  private int writeFragments(byte[] buf, int offset) {
    int prevFragmentID = -1;
    for (MessageFragment fragment : fragments) {
      offset = writeSingleFragment(buf, offset, fragment, prevFragmentID);
      prevFragmentID = fragment.messageID;
    }
    return offset;
  }

  private static int writeSingleFragment(
      byte[] buf, int offset, MessageFragment fragment, int prevFragmentID) {
    if (fragment.shortMessage) buf[offset] = (byte) ((buf[offset] & 0xFF) | 0x80);
    if (fragment.isFragmented) buf[offset] = (byte) ((buf[offset] & 0xFF) | 0x40);
    if (fragment.firstFragment) buf[offset] = (byte) ((buf[offset] & 0xFF) | 0x20);

    if (prevFragmentID == -1 || (fragment.messageID - prevFragmentID >= 4096)) {
      buf[offset] = (byte) ((buf[offset] & 0xFF) | 0x10);
      buf[offset] = (byte) ((buf[offset] & 0xFF) | ((fragment.messageID >>> 24) & 0x0F));
      buf[offset + 1] = (byte) (fragment.messageID >>> 16);
      buf[offset + 2] = (byte) (fragment.messageID >>> 8);
      buf[offset + 3] = (byte) (fragment.messageID);
      offset += 4;
    } else {
      int compressedMsgID = fragment.messageID - prevFragmentID;
      buf[offset] = (byte) ((buf[offset] & 0xFF) | ((compressedMsgID >>> 8) & 0x0F));
      buf[offset + 1] = (byte) (compressedMsgID);
      offset += 2;
    }

    if (fragment.shortMessage) {
      buf[offset++] = (byte) (fragment.fragmentLength);
    } else {
      buf[offset] = (byte) (fragment.fragmentLength >>> 8);
      buf[offset + 1] = (byte) (fragment.fragmentLength);
      offset += 2;
    }

    if (fragment.isFragmented) {
      // If firstFragment is true, encode total message length; otherwise encode fragment offset.
      int value;
      if (fragment.firstFragment) {
        value = fragment.messageLength;
      } else {
        value = fragment.fragmentOffset;
      }

      if (fragment.shortMessage) {
        buf[offset++] = (byte) (value);
      } else {
        buf[offset] = (byte) (value >>> 8);
        buf[offset + 1] = (byte) (value);
        offset += 2;
      }
    }

    System.arraycopy(fragment.fragmentData, 0, buf, offset, fragment.fragmentLength);
    offset += fragment.fragmentLength;

    return offset;
  }

  private int writeLossyMessages(byte[] buf, int offset) {
    if (!lossyMessages.isEmpty()) {
      for (byte[] msg : lossyMessages) {
        buf[offset++] = 0x1F;
        assert (msg.length <= 255);
        buf[offset++] = (byte) msg.length;
        System.arraycopy(msg, 0, buf, offset, msg.length);
        offset += msg.length;
      }
    }
    return offset;
  }

  private static void writePadding(byte[] buf, int offset, Random paddingGen) {
    // Fill remaining space with random padding when capacity remains.
    Util.randomBytes(paddingGen, buf, offset, buf.length - offset);

    byte b = (byte) (buf[offset] & 0x9F); // Clear firstFragment/isFragmented bits in padding byte.
    if (b == 0x1F) b = (byte) 0x9F; // Avoid the lossy message marker (0x1F) in padding.
    buf[offset] = b;
  }

  /**
   * Add an ACK for a received packet sequence number.
   *
   * <p>Updates internal ACK ranges and adjusts this packet's encoded length. If adding the ACK
   * would exceed {@code maxPacketSize}, the method reverts the change and returns {@code false}.
   *
   * @param ack sequence number to acknowledge; must be non-negative
   * @param maxPacketSize maximum allowed encoded size in bytes
   * @return {@code true} if the ACK is added; {@code false} if it would exceed {@code
   *     maxPacketSize}
   * @throws IllegalArgumentException if {@code ack} is negative
   */
  public boolean addAck(int ack, int maxPacketSize) {
    if (ack < 0) throw new IllegalArgumentException("Got negative ack: " + ack);
    if (acks.contains(ack)) return true;

    acks.add(ack);
    List<AckRange> ranges = computeAckRanges();
    int nearRangeCount = 0;
    int farRangeCount = 0;
    for (int i = 0; i < ranges.size(); i++) {
      AckRange r = ranges.get(i);
      if (i == 0) {
        nearRangeCount++;
      } else if (r.deltaFromPrev >= 254) {
        farRangeCount++;
      } else {
        nearRangeCount++;
      }
    }
    if (nearRangeCount + farRangeCount > 254) {
      acks.remove(ack);
      return false;
    }
    //              (start + offset) + (rangeCount-1)    *(1 byte deltaFromPrevious + length) +
    // farRangeCount*(flag + 4-byte packetSequenceNumber + length)
    int blockSize = 5 + (nearRangeCount - 1) * 2 + farRangeCount * 6;
    int finalLength = length + blockSize - ackBlockByteSize;
    if (finalLength > maxPacketSize) {
      acks.remove(ack);
      return false;
    }
    length = finalLength;
    ackBlockByteSize = blockSize;
    ackRangeCount = farRangeCount + nearRangeCount;

    return true;
  }

  private int oldMsgIDLength;

  /**
   * Append a message fragment to this packet.
   *
   * <p>Recomputes message ID encoding overhead to keep compressed IDs consistent and updates the
   * encoded packet length accordingly.
   *
   * @param frag the fragment to add; not {@code null}
   * @return the updated encoded packet length in bytes
   */
  @SuppressWarnings("UnusedReturnValue")
  public int addMessageFragment(MessageFragment frag) {
    length += frag.length();
    fragments.add(frag);
    fragments.sort(new MessageFragmentComparator());

    int msgIDLength = 0;
    int prevMessageID = -1;
    for (MessageFragment fragment : fragments) {
      if ((prevMessageID == -1) || (fragment.messageID - prevMessageID >= 4096)) {
        msgIDLength += 2;
      }
      prevMessageID = fragment.messageID;
    }

    length += (msgIDLength - oldMsgIDLength);
    oldMsgIDLength = msgIDLength;

    return length;
  }

  /**
   * Append a lossy message that receivers may drop without affecting correctness.
   *
   * <p>Each lossy message is encoded as a marker ({@code 0x1F}), a 1-byte length, and the payload.
   * Updates the encoded packet length and returns the new total.
   *
   * @param buf payload to append; size must be {@code <= 255}
   * @return the updated encoded packet length in bytes
   * @throws IllegalArgumentException if {@code buf.length > 255}
   */
  public int addLossyMessage(byte[] buf) {
    if (buf.length > 255) throw new IllegalArgumentException();
    lossyMessages.add(buf);
    length += buf.length + 2;
    // Return the updated total encoded packet length (matches getLength()).
    return length;
  }

  /**
   * Try to append a lossy message subject to a maximum packet size.
   *
   * @param buf payload to append; size must be {@code <= 255}
   * @param maxPacketSize maximum allowed encoded size in bytes
   * @return {@code true} if appended; {@code false} if it would exceed {@code maxPacketSize}
   * @throws IllegalArgumentException if {@code buf.length > 255}
   */
  public boolean addLossyMessage(byte[] buf, int maxPacketSize) {
    if (length + buf.length + 2 > maxPacketSize) return false;
    if (buf.length > 255) throw new IllegalArgumentException();
    lossyMessages.add(buf);
    length += buf.length + 2;
    return true;
  }

  /**
   * Remove the first occurrence of the given lossy message payload and update length.
   *
   * @param buf payload to remove; no-op if not present
   */
  public void removeLossyMessage(byte[] buf) {
    if (lossyMessages.remove(buf)) {
      length -= buf.length + 2;
    }
  }

  /**
   * Return the lossy message payloads in insertion order.
   *
   * <p>Receivers process lossy messages before regular fragments. Older peers may emit unexpected
   * content here; callers should validate as needed.
   *
   * @return an internal, mutable list of lossy message payloads
   */
  public List<byte[]> getLossyMessages() {
    return lossyMessages;
  }

  /**
   * Indicate whether parsing detected a malformed or truncated packet.
   *
   * @return {@code true} if an error occurred during parsing
   */
  public boolean getError() {
    return error;
  }

  /**
   * Return parsed message fragments in send order.
   *
   * @return a mutable list of message fragments
   */
  public List<MessageFragment> getFragments() {
    return fragments;
  }

  /**
   * Get the packet sequence number.
   *
   * @return the sequence number as an integer
   */
  public int getSequenceNumber() {
    return sequenceNumber;
  }

  /**
   * Set the packet sequence number.
   *
   * @param sequenceNumber new sequence number
   */
  public void setSequenceNumber(int sequenceNumber) {
    this.sequenceNumber = sequenceNumber;
  }

  /**
   * Return the set of acknowledged sequence numbers.
   *
   * @return a sorted set of ACKed sequence numbers
   */
  public SortedSet<Integer> getAcks() {
    return acks;
  }

  /**
   * Return the current encoded packet length in bytes.
   *
   * @return packet size in bytes
   */
  public int getLength() {
    return length;
  }

  @Override
  public String toString() {
    return "Packet "
        + sequenceNumber
        + ": "
        + length
        + " bytes, "
        + acks.size()
        + " acks, "
        + fragments.size()
        + " fragments";
  }

  private static class MessageFragmentComparator implements Comparator<MessageFragment> {
    @Override
    public int compare(MessageFragment frag1, MessageFragment frag2) {
      return Integer.compare(frag1.messageID, frag2.messageID);
    }
  }

  /**
   * Notify fragments that this packet was sent.
   *
   * <p>Computes per-packet overhead as {@code totalPacketLength - sum(fragmentLength)} and invokes
   * {@code onSent} on each fragment wrapper with a simple fair-share overhead.
   *
   * @param totalPacketLength total size on the wire in bytes
   * @param pn peer that received the packet; used for wrapper callbacks
   */
  public void onSent(int totalPacketLength, BasePeerNode pn) {
    int totalMessageData = 0;
    int size = fragments.size();
    int biggest = 0;
    for (MessageFragment frag : fragments) {
      totalMessageData += frag.fragmentLength;
      size++;
      if (biggest < frag.messageLength) biggest = frag.messageLength;
    }
    int overhead = totalPacketLength - totalMessageData;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Packet overhead {} bytes for {} messages, total message bytes {}, total packet length"
              + " {}, biggest message {}",
          overhead,
          size,
          totalMessageData,
          totalPacketLength,
          biggest);
    for (MessageFragment frag : fragments) {
      // frag.wrapper is always non-null on sending.
      frag.wrapper.onSent(
          frag.fragmentOffset, frag.fragmentOffset + frag.fragmentLength - 1, overhead / size, pn);
    }
  }

  /**
   * Return a string representation of the current fragment list.
   *
   * <p>For diagnostics only.
   */
  @SuppressWarnings("unused")
  String fragmentsAsString() {
    return Arrays.toString(fragments.toArray());
  }

  /**
   * Return the number of ACKed sequence numbers.
   *
   * @return count of ACKs
   */
  public int countAcks() {
    return acks.size();
  }

  /**
   * Indicate whether there are no fragments to send.
   *
   * @return {@code true} if the fragment list is empty
   */
  public boolean noFragments() {
    return fragments.isEmpty();
  }
}
