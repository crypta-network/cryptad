package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.HMAC;
import network.crypta.crypt.PCFBMode;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.node.NewPacketFormatKeyContext.AddedAcks;
import network.crypta.support.Fields;
import network.crypta.support.SparseBitmap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Packet format and transport for encrypted peer communication.
 *
 * <p>This implementation handles packet assembly and parsing including:
 *
 * <ul>
 *   <li>Fragmenting and reassembling messages up to {@link #MAX_MESSAGE_SIZE} bytes.
 *   <li>Per-session sequence numbers used in IV derivation and HMAC validation.
 *   <li>Acknowledgments, retransmission heuristics, and keepalive scheduling.
 *   <li>Send/receive windows and buffer accounting to avoid overruns.
 * </ul>
 *
 * <p>Thread safety: this class uses fine‑grained locks. The send buffer and its counters are
 * protected by {@code sendBufferLock}. The receive buffer usage counter is protected by {@code
 * receiveBufferSizeLock}. Window pointers and some shared structures synchronize on {@code this} or
 * their own monitors as documented. Callers may use an instance from multiple threads.
 *
 * <p>Time units are milliseconds unless stated otherwise.
 */
public class NewPacketFormat implements PacketFormat {
  private static final Logger LOG = LoggerFactory.getLogger(NewPacketFormat.class);

  /** Number of bytes of the truncated HMAC stored in the packet header. */
  private static final int HMAC_LENGTH = 10;

  // Watchlist of encrypted sequence-number probes used to match incoming packets.
  // A larger list increases tolerance for bursts/latency at the cost of memory.
  private static final int NUM_SEQNUMS_TO_WATCH_FOR = 1024;
  // Upper bound for the summed size of all partially received message buffers.
  // On high-bandwidth/latency links with ample memory, a larger value can reduce drops.
  private static final int MAX_RECEIVE_BUFFER_SIZE = 256 * 1024;
  private static final int MSG_WINDOW_SIZE = 65536;
  private static final int NUM_MESSAGE_IDS = 268435456;
  static final long NUM_SEQNUMS = 2147483648L;
  private static final long MAX_MSGID_BLOCK_TIME = MINUTES.toMillis(10);
  private static final int MAX_ACKS = 500;
  static boolean doKeepalives = true;

  private final BasePeerNode pn;

  /**
   * Outgoing messages in progress and not yet fully acknowledged. Guarded by {@code
   * sendBufferLock}.
   */
  private final List<Map<Integer, MessageWrapper>> startedByPrio;

  /** The next message ID for outgoing messages. Guarded by {@code this}. */
  private int nextMessageID;

  /** First message id not yet acked by the receiver. Guarded by {@code this}. */
  private int messageWindowPtrAcked;

  /**
   * Messages that have been acked. Entries outside the window are periodically pruned. Guarded by
   * {@code this}.
   */
  private final SparseBitmap ackedMessages = new SparseBitmap();

  private final HashMap<Integer, PartiallyReceivedBuffer> receiveBuffers = new HashMap<>();
  private final HashMap<Integer, SparseBitmap> receiveMaps = new HashMap<>();

  /** First message id that has not been fully received. */
  private int messageWindowPtrReceived;

  private final SparseBitmap receivedMessages = new SparseBitmap();

  /**
   * Total bytes currently used by partially received buffers. This mirrors how much of the sender's
   * send window we occupy. Guarded by {@code receiveBufferSizeLock}.
   */
  private int receiveBufferUsed = 0;

  /**
   * Bytes we estimate to occupy in the peer's buffer (derived from our started messages). Guarded
   * by {@code sendBufferLock}.
   */
  private int sendBufferUsed = 0;

  /**
   * Lock for the send-side state: both the in-flight map ({@code startedByPrio}) and the accounting
   * counters. Acquire this lock last to avoid deadlocks with other locks protecting connection
   * state. Using one lock ensures we do not enqueue or send while disconnecting.
   */
  private final Object sendBufferLock = new Object();

  /** Lock protecting {@code receiveBufferUsed}. */
  private final Object receiveBufferSizeLock = new Object();

  private long timeLastSentPacket;
  private long timeLastSentPayload;

  NewPacketFormat(BasePeerNode pn, int ourInitialMsgID, int theirInitialMsgID) {
    this.pn = pn;

    startedByPrio = new ArrayList<>(DMT.NUM_PRIORITIES);
    for (int i = 0; i < DMT.NUM_PRIORITIES; i++) {
      startedByPrio.add(new HashMap<>());
    }

    // Make sure the numbers are within the ranges we want
    ourInitialMsgID = (ourInitialMsgID & 0x7FFFFFFF) % NUM_MESSAGE_IDS;
    theirInitialMsgID = (theirInitialMsgID & 0x7FFFFFFF) % NUM_MESSAGE_IDS;

    nextMessageID = ourInitialMsgID;
    messageWindowPtrAcked = ourInitialMsgID;
    messageWindowPtrReceived = theirInitialMsgID;
  }

  /**
   * Processes an incoming encrypted packet.
   *
   * <p>The method attempts decryption with available session keys, validates the truncated HMAC,
   * processes acknowledgments, reassembles message fragments, and delivers completed messages to
   * the peer for further handling. When appropriate, it schedules an acknowledgment for the
   * received sequence number.
   *
   * @param buf the buffer containing the packet bytes.
   * @param offset the start offset in {@code buf}.
   * @param length the number of bytes in the packet.
   * @param now current time in milliseconds; used for deadlines and scheduling.
   * @param replyTo the peer to reply to; may be {@code null} for non-addressable transports.
   * @return {@code true} if the packet was decrypted and processed; {@code false} if no session key
   *     matched or validation failed.
   */
  @Override
  public boolean handleReceivedPacket(byte[] buf, int offset, int length, long now, Peer replyTo) {
    DecryptionResult dec = tryDecryptOnAnyTracker(buf, offset, length);
    if (dec.packet == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Skip packet: cannot decrypt with available keys");
      return false;
    }

    pn.receivedPacket(false, true);
    pn.verified(dec.sessionKey);
    pn.maybeRekey();
    pn.reportIncomingBytes(length);

    List<byte[]> finished = handleDecryptedPacket(dec.packet, dec.sessionKey);
    if (LOG.isDebugEnabled() && !finished.isEmpty())
      LOG.debug("Decoded {} message(s)", finished.size());
    DecodingMessageGroup group = pn.transport().startProcessingDecryptedMessages(finished.size());
    for (byte[] buffer : finished) {
      group.processDecryptedMessage(buffer, 0, buffer.length, 0);
    }
    group.complete();

    return true;
  }

  private record DecryptionResult(NPFPacket packet, SessionKey sessionKey) {}

  private DecryptionResult tryDecryptOnAnyTracker(byte[] buf, int offset, int length) {
    for (int i = 0; i < 3; i++) {
      SessionKey s =
          switch (i) {
            case 0 -> pn.getCurrentKeyTracker();
            case 1 -> pn.getPreviousKeyTracker();
            default -> pn.getUnverifiedKeyTracker();
          };
      if (s == null) continue;
      NPFPacket packet = tryDecipherPacket(buf, offset, length, s);
      if (packet != null) {
        if (LOG.isTraceEnabled()) LOG.trace("Decrypted packet with tracker {}", i);
        return new DecryptionResult(packet, s);
      }
    }
    return new DecryptionResult(null, null);
  }

  List<byte[]> handleDecryptedPacket(NPFPacket packet, SessionKey sessionKey) {
    List<byte[]> fullyReceived = new ArrayList<>();

    NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
    processAcks(packet, keyContext, sessionKey);

    boolean shouldAck = shouldAckPacket(packet);
    handleLossyMessagesIfAny(packet);
    boolean dontAckFromFragments = processFragments(packet, fullyReceived);
    if (shouldAck && !dontAckFromFragments) maybeQueueAck(keyContext, packet);

    return fullyReceived;
  }

  private void processAcks(
      NPFPacket packet, NewPacketFormatKeyContext keyContext, SessionKey sessionKey) {
    for (int ack : packet.getAcks()) {
      keyContext.ack(ack, pn, sessionKey);
    }
  }

  private boolean shouldAckPacket(NPFPacket packet) {
    if (packet.getError() || packet.getFragments().isEmpty()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Skip ack; reason={}", packet.getError() ? "error" : "no fragments");
      return false;
    }
    return true;
  }

  private void handleLossyMessagesIfAny(NPFPacket packet) {
    List<byte[]> l = packet.getLossyMessages();
    if (l == null || l.isEmpty()) return;

    ArrayList<Message> lossyMessages = new ArrayList<>(l.size());
    for (byte[] buf : l) {
      Message msg = Message.decodeMessageLax(buf, pn, 0);
      if (msg == null || !msg.getSpec().isLossyPacketMessage()) {
        lossyMessages.clear();
        break;
      }
      lossyMessages.add(msg);
    }
    if (LOG.isDebugEnabled() && !lossyMessages.isEmpty())
      LOG.debug("Parsed {} lossy packet messages", lossyMessages.size());
    for (Message msg : lossyMessages) pn.transport().handleMessage(msg);
  }

  private boolean processFragments(NPFPacket packet, List<byte[]> fullyReceived) {
    boolean dontAck = false;
    for (MessageFragment fragment : packet.getFragments()) {
      boolean fragmentOk = processSingleFragment(fragment, fullyReceived);
      if (!fragmentOk) dontAck = true;
    }
    return dontAck;
  }

  private boolean processSingleFragment(MessageFragment fragment, List<byte[]> fullyReceived) {
    if (isOutsideReceiveWindow(fragment)) {
      LOG.debug("Message {} outside receive window; sending ack", fragment.messageID);
      return true; // Outside window does not suppress ack
    }
    synchronized (receivedMessages) {
      if (receivedMessages.contains(fragment.messageID, fragment.messageID)) return true;
    }

    BufferMap bm = ensureBufferAndMap(fragment);
    if (bm == null) {
      return false; // Suppress ack on allocation failure
    }

    if (shouldSetMessageLength(fragment, bm)
        && bm.buffer.cannotSetMessageLength(fragment.messageLength)) return false;

    if (!bm.buffer.add(fragment.fragmentData, fragment.fragmentOffset)) {
      return false;
    }
    if (fragment.fragmentLength == 0) {
      LOG.warn("Ignore fragment with length 0");
      return true;
    }
    bm.map.add(fragment.fragmentOffset, fragment.fragmentOffset + fragment.fragmentLength - 1);
    if (isMessageComplete(bm)) {
      onMessageFullyReceived(fragment, bm, fullyReceived);
    } else {
      if (LOG.isTraceEnabled()) LOG.trace("Message {} receive map {}", fragment.messageID, bm.map);
    }
    return true;
  }

  private boolean shouldSetMessageLength(MessageFragment fragment, BufferMap bm) {
    return fragment.firstFragment && bm.buffer.messageLength == -1;
  }

  private boolean isMessageComplete(BufferMap bm) {
    return bm.buffer.messageLength != -1 && bm.map.contains(0, bm.buffer.messageLength - 1);
  }

  private boolean isOutsideReceiveWindow(MessageFragment fragment) {
    if (messageWindowPtrReceived + MSG_WINDOW_SIZE > NUM_MESSAGE_IDS) {
      int upperBound = (messageWindowPtrReceived + MSG_WINDOW_SIZE) % NUM_MESSAGE_IDS;
      return fragment.messageID > upperBound && fragment.messageID < messageWindowPtrReceived;
    } else {
      int upperBound = messageWindowPtrReceived + MSG_WINDOW_SIZE;
      return !(fragment.messageID >= messageWindowPtrReceived && fragment.messageID < upperBound);
    }
  }

  private record BufferMap(PartiallyReceivedBuffer buffer, SparseBitmap map) {}

  private BufferMap ensureBufferAndMap(MessageFragment fragment) {
    PartiallyReceivedBuffer recvBuffer = receiveBuffers.get(fragment.messageID);
    SparseBitmap recvMap = receiveMaps.get(fragment.messageID);

    if (recvBuffer == null) {
      if (LOG.isTraceEnabled()) LOG.trace("Message {}: create receive buffer", fragment.messageID);
      recvBuffer = new PartiallyReceivedBuffer(this);

      if (cannotSetLengthIfFirstFragment(fragment, recvBuffer)) return null;

      if (!fragment.firstFragment && exceedsReceiveBuffer(fragment.fragmentLength)) {
        if (LOG.isDebugEnabled()) LOG.debug("Cannot create buffer; exceeds max size");
        return null;
      }

      recvMap = new SparseBitmap();
      receiveBuffers.put(fragment.messageID, recvBuffer);
      receiveMaps.put(fragment.messageID, recvMap);
    } else {
      if (cannotSetLengthIfFirstFragment(fragment, recvBuffer)) return null;
    }

    return new BufferMap(recvBuffer, recvMap);
  }

  private boolean cannotSetLengthIfFirstFragment(
      MessageFragment fragment, PartiallyReceivedBuffer recvBuffer) {
    return fragment.firstFragment && recvBuffer.cannotSetMessageLength(fragment.messageLength);
  }

  private boolean exceedsReceiveBuffer(int additionalLength) {
    synchronized (receiveBufferSizeLock) {
      return receiveBufferUsed + additionalLength > MAX_RECEIVE_BUFFER_SIZE;
    }
  }

  private void onMessageFullyReceived(
      MessageFragment fragment, BufferMap bm, List<byte[]> fullyReceived) {
    receiveBuffers.remove(fragment.messageID);
    receiveMaps.remove(fragment.messageID);

    synchronized (receivedMessages) {
      if (receivedMessages.contains(fragment.messageID, fragment.messageID)) return;
      receivedMessages.add(fragment.messageID, fragment.messageID);

      int oldWindow = messageWindowPtrReceived;
      while (receivedMessages.contains(messageWindowPtrReceived, messageWindowPtrReceived)) {
        messageWindowPtrReceived++;
        if (messageWindowPtrReceived == NUM_MESSAGE_IDS) messageWindowPtrReceived = 0;
      }

      if (messageWindowPtrReceived < oldWindow) {
        receivedMessages.remove(oldWindow, NUM_MESSAGE_IDS - 1);
        receivedMessages.remove(0, messageWindowPtrReceived);
      } else {
        receivedMessages.remove(oldWindow, messageWindowPtrReceived);
      }
    }

    synchronized (receiveBufferSizeLock) {
      receiveBufferUsed -= bm.buffer.messageLength;
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Removed {} bytes from buffer; total={}", bm.buffer.messageLength, receiveBufferUsed);
    }

    fullyReceived.add(bm.buffer.buffer);

    if (LOG.isTraceEnabled()) LOG.trace("Message {}: receive complete", fragment.messageID);
  }

  private void maybeQueueAck(NewPacketFormatKeyContext keyContext, NPFPacket packet) {
    int seqno = packet.getSequenceNumber();
    int acksQueued = keyContext.queueAck(seqno);
    boolean addedAck = acksQueued >= 0;
    boolean wakeUp = acksQueued > MAX_ACKS;
    if (addedAck) {
      if (!wakeUp) {
        synchronized (receiveBufferSizeLock) {
          if (receiveBufferUsed > MAX_RECEIVE_BUFFER_SIZE / 2) wakeUp = true;
        }
      }
      if (wakeUp) pn.wakeUpSender();
    }
  }

  private NPFPacket tryDecipherPacket(byte[] buf, int offset, int length, SessionKey sessionKey) {
    NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
    initWatchlistIfNeeded(keyContext, sessionKey);

    int highestReceivedSeqNum;
    synchronized (this) {
      highestReceivedSeqNum = keyContext.highestReceivedSeqNum;
    }
    moveWatchlistIfNeeded(keyContext, highestReceivedSeqNum, sessionKey);

    return findMatchingPacket(keyContext, buf, offset, length, sessionKey);
  }

  private void initWatchlistIfNeeded(NewPacketFormatKeyContext keyContext, SessionKey sessionKey) {
    if (keyContext.seqNumWatchList != null) return;
    if (LOG.isDebugEnabled())
      LOG.debug("Create watchlist at offset={}", keyContext.watchListOffset);
    keyContext.seqNumWatchList = new byte[NUM_SEQNUMS_TO_WATCH_FOR][4];
    int seqNum = keyContext.watchListOffset;
    for (int i = 0; i < keyContext.seqNumWatchList.length; i++) {
      keyContext.seqNumWatchList[i] = NewPacketFormat.encryptSequenceNumber(seqNum++, sessionKey);
      if (seqNum < 0) seqNum = 0;
    }
  }

  private void moveWatchlistIfNeeded(
      NewPacketFormatKeyContext keyContext, int highestReceivedSeqNum, SessionKey sessionKey) {
    int oldHighestReceived =
        (int)
            (((long) keyContext.watchListOffset + keyContext.seqNumWatchList.length / 2)
                % NUM_SEQNUMS);
    if (!seqNumGreaterThan(highestReceivedSeqNum, oldHighestReceived, 31)) return;

    int moveBy = computeMoveBy(oldHighestReceived, highestReceivedSeqNum);
    logMoveBy(moveBy, keyContext);

    int seqNum =
        (int)
            (((long) keyContext.watchListOffset + keyContext.seqNumWatchList.length) % NUM_SEQNUMS);
    for (int i = keyContext.watchListPointer; i < keyContext.watchListPointer + moveBy; i++) {
      keyContext.seqNumWatchList[i % keyContext.seqNumWatchList.length] =
          encryptSequenceNumber(seqNum++, sessionKey);
      if (seqNum < 0) seqNum = 0;
    }

    keyContext.watchListPointer =
        (keyContext.watchListPointer + moveBy) % keyContext.seqNumWatchList.length;
    keyContext.watchListOffset = (int) (((long) keyContext.watchListOffset + moveBy) % NUM_SEQNUMS);
  }

  private int computeMoveBy(int oldHighestReceived, int highestReceivedSeqNum) {
    if (highestReceivedSeqNum > oldHighestReceived) {
      return highestReceivedSeqNum - oldHighestReceived;
    } else {
      return (int) (NUM_SEQNUMS - oldHighestReceived) + highestReceivedSeqNum;
    }
  }

  private void logMoveBy(int moveBy, NewPacketFormatKeyContext keyContext) {
    if (moveBy > keyContext.seqNumWatchList.length) {
      LOG.warn("Move watchlist pointer by {}", moveBy);
    } else if (moveBy < 0) {
      LOG.warn("Attempt to move watchlist pointer by {}", moveBy);
    } else {
      if (LOG.isTraceEnabled()) LOG.trace("Moving watchlist pointer by {}", moveBy);
    }
  }

  private NPFPacket findMatchingPacket(
      NewPacketFormatKeyContext keyContext,
      byte[] buf,
      int offset,
      int length,
      SessionKey sessionKey) {
    for (int i = 0; i < keyContext.seqNumWatchList.length; i++) {
      int index = (keyContext.watchListPointer + i) % keyContext.seqNumWatchList.length;
      if (!Fields.byteArrayEqual(
          buf,
          keyContext.seqNumWatchList[index],
          offset + HMAC_LENGTH,
          0,
          keyContext.seqNumWatchList[index].length)) continue;

      int sequenceNumber = (int) (((long) keyContext.watchListOffset + i) % NUM_SEQNUMS);
      if (LOG.isTraceEnabled()) LOG.trace("Packet matches sequenceNumber={}", sequenceNumber);
      NPFPacket p = decipherFromSeqnum(buf, offset, length, sessionKey, sequenceNumber);
      if (p != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Decrypted packet seq={} tracker={}", p.getSequenceNumber(), sessionKey);
        return p;
      }
    }
    return null;
  }

  /** Must NOT modify buf contents. */
  private NPFPacket decipherFromSeqnum(
      byte[] buf, int offset, int length, SessionKey sessionKey, int sequenceNumber) {
    BlockCipher ivCipher = sessionKey.ivCipher;

    byte[] iv = new byte[ivCipher.getBlockSize() / 8];
    System.arraycopy(sessionKey.ivNonce, 0, iv, 0, iv.length);
    iv[iv.length - 4] = (byte) (sequenceNumber >>> 24);
    iv[iv.length - 3] = (byte) (sequenceNumber >>> 16);
    iv[iv.length - 2] = (byte) (sequenceNumber >>> 8);
    iv[iv.length - 1] = (byte) sequenceNumber;

    ivCipher.encipher(iv, iv);

    byte[] payload = Arrays.copyOfRange(buf, offset + HMAC_LENGTH, offset + length);
    byte[] hash = Arrays.copyOfRange(buf, offset, offset + HMAC_LENGTH);
    byte[] localHash = Arrays.copyOf(HMAC.macWithSHA256(sessionKey.hmacKey, payload), HMAC_LENGTH);
    if (!MessageDigest.isEqual(hash, localHash)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("HMAC validation fails (trackerId={})", sessionKey.trackerID);
      }

      return null;
    }

    PCFBMode payloadCipher = PCFBMode.create(sessionKey.incommingCipher, iv);
    payloadCipher.blockDecipher(payload, 0, payload.length);

    NPFPacket p = NPFPacket.create(payload, pn);

    NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
    synchronized (this) {
      if (seqNumGreaterThan(sequenceNumber, keyContext.highestReceivedSeqNum, 31)) {
        keyContext.highestReceivedSeqNum = sequenceNumber;
      }
    }

    return p;
  }

  private boolean seqNumGreaterThan(long i1, long i2, int serialBits) {
    // halfValue is half the window of possible numbers, so this returns true if the distance from
    // i2->i1 is smaller than i1->i2. See RFC1982 for details and limitations.

    long halfValue = 1L << (serialBits - 1);
    return (i1 < i2 && i2 - i1 > halfValue) || (i1 > i2 && i1 - i2 < halfValue);
  }

  static byte[] encryptSequenceNumber(int seqNum, SessionKey sessionKey) {
    byte[] seqNumBytes = new byte[4];
    seqNumBytes[0] = (byte) (seqNum >>> 24);
    seqNumBytes[1] = (byte) (seqNum >>> 16);
    seqNumBytes[2] = (byte) (seqNum >>> 8);
    seqNumBytes[3] = (byte) seqNum;

    BlockCipher ivCipher = sessionKey.ivCipher;

    byte[] iv = new byte[ivCipher.getBlockSize() / 8];
    System.arraycopy(sessionKey.ivNonce, 0, iv, 0, iv.length);
    System.arraycopy(seqNumBytes, 0, iv, iv.length - seqNumBytes.length, seqNumBytes.length);
    ivCipher.encipher(iv, iv);

    PCFBMode cipher = PCFBMode.create(sessionKey.incommingCipher, iv);
    cipher.blockEncipher(seqNumBytes, 0, seqNumBytes.length);

    return seqNumBytes;
  }

  /**
   * Attempts to build and send a single packet.
   *
   * <p>When {@code ackOnly} is {@code true}, the packet contains only acks or keepalive payloads
   * (no message fragments). When {@code false}, the method may coalesce queued message fragments
   * according to priorities and deadlines.
   *
   * @param now current time in milliseconds.
   * @param ackOnly whether to limit the packet to acks/keepalives.
   * @return {@code true} if a packet was sent; {@code false} if nothing was sent.
   * @throws BlockedTooLongException if message ID allocation is blocked beyond the configured
   *     limit.
   */
  @Override
  public boolean maybeSendPacket(long now, boolean ackOnly) throws BlockedTooLongException {
    SessionKey sessionKey = pn.getPreviousKeyTracker();
    if (sessionKey != null && maybeSendPacket(true, sessionKey)) return true;
    sessionKey = pn.getUnverifiedKeyTracker();
    if (sessionKey != null && maybeSendPacket(true, sessionKey)) return true;
    sessionKey = pn.getCurrentKeyTracker();
    if (sessionKey == null) {
      LOG.warn("No session key available to secure packet");
      return false;
    }
    return maybeSendPacket(ackOnly, sessionKey);
  }

  boolean maybeSendPacket(boolean ackOnly, SessionKey sessionKey) throws BlockedTooLongException {
    int maxPacketSize = pn.getMaxPacketSize();
    NewPacketFormatKeyContext keyContext = sessionKey.packetContext;

    NPFPacket packet =
        createPacket(maxPacketSize - HMAC_LENGTH, pn.getMessageQueue(), sessionKey, ackOnly);
    if (packet == null) return false;
    int paddedLen = computePaddedLength(packet, maxPacketSize);

    byte[] data = new byte[paddedLen];
    packet.toBytes(data, HMAC_LENGTH, pn.paddingGen());

    encryptPayloadAndAddHmac(sessionKey, paddedLen, data);

    if (!sendPacketBytes(packet, data)) return false;

    postSendUpdates(packet, data.length, keyContext);

    return true;
  }

  private int computePaddedLength(NPFPacket packet, int maxPacketSize) {
    int paddedLen = packet.getLength() + HMAC_LENGTH;
    if (!pn.shouldPadDataPackets()) return paddedLen;
    if (LOG.isTraceEnabled()) LOG.trace("Pre-padding length: {}", paddedLen);
    if (paddedLen < 64) {
      return 64 + pn.paddingGen().nextInt(32);
    } else {
      int result = (paddedLen + 63) / 64 * 64;
      if (result < maxPacketSize) {
        result += pn.paddingGen().nextInt(Math.min(64, maxPacketSize - result));
      } else if (paddedLen <= maxPacketSize && result > maxPacketSize) {
        result = maxPacketSize;
      }
      return result;
    }
  }

  private void encryptPayloadAndAddHmac(SessionKey sessionKey, int paddedLen, byte[] data) {
    BlockCipher ivCipher = sessionKey.ivCipher;
    byte[] iv = new byte[ivCipher.getBlockSize() / 8];
    System.arraycopy(sessionKey.ivNonce, 0, iv, 0, iv.length);
    System.arraycopy(data, HMAC_LENGTH, iv, iv.length - 4, 4);
    ivCipher.encipher(iv, iv);
    PCFBMode payloadCipher = PCFBMode.create(sessionKey.outgoingCipher, iv);
    payloadCipher.blockEncipher(data, HMAC_LENGTH, paddedLen - HMAC_LENGTH);
    byte[] text = new byte[paddedLen - HMAC_LENGTH];
    System.arraycopy(data, HMAC_LENGTH, text, 0, text.length);
    byte[] hash = HMAC.macWithSHA256(sessionKey.hmacKey, text);
    System.arraycopy(hash, 0, data, 0, HMAC_LENGTH);
  }

  private boolean sendPacketBytes(NPFPacket packet, byte[] data) {
    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Sending packet {} ({} bytes) with fragments {} and {} acks on {}",
            packet.getSequenceNumber(),
            data.length,
            buildFragmentSummary(packet),
            packet.getAcks().size(),
            this);
      }
      pn.sendEncryptedPacket(data);
      return true;
    } catch (LocalAddressException e) {
      LOG.error("Caught exception while sending packet", e);
      return false;
    }
  }

  private String buildFragmentSummary(NPFPacket packet) {
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (MessageFragment frag : packet.getFragments()) {
      if (!first) sb.append(", ");
      first = false;
      sb.append(frag.messageID)
          .append(" (")
          .append(frag.fragmentOffset)
          .append("->")
          .append(frag.fragmentOffset + frag.fragmentLength - 1)
          .append(")");
    }
    return sb.isEmpty() ? null : sb.toString();
  }

  private void postSendUpdates(
      NPFPacket packet, int bytesSent, NewPacketFormatKeyContext keyContext) {
    packet.onSent(bytesSent, pn);
    if (!packet.getFragments().isEmpty()) {
      keyContext.sent(packet.getSequenceNumber(), packet.getLength());
    }
    long now = System.currentTimeMillis();
    pn.sentPacket();
    pn.reportOutgoingBytes(bytesSent);
    if (pn.shouldThrottle()) pn.sentThrottledBytes(bytesSent);
    if (packet.getFragments().isEmpty()) pn.onNotificationOnlyPacketSent(bytesSent);
    synchronized (this) {
      if (timeLastSentPacket < now) timeLastSentPacket = now;
      if (!packet.getFragments().isEmpty() && timeLastSentPayload < now) timeLastSentPayload = now;
    }
  }

  NPFPacket createPacket(
      int maxPacketSize, PeerMessageQueue messageQueue, SessionKey sessionKey, boolean ackOnly)
      throws BlockedTooLongException {

    checkForLostPackets();

    NPFPacket packet = new NPFPacket();
    SentPacket sentPacket = new SentPacket(this, sessionKey);

    boolean mustSend = false;
    long now = System.currentTimeMillis();

    NewPacketFormatKeyContext keyContext = sessionKey.packetContext;

    AddedAcks moved = keyContext.addAcks(packet, maxPacketSize, now);
    mustSend |= updateMustSendForUrgentAcks(moved);

    int numAcks = packet.countAcks();
    if (numAcks > MAX_ACKS) mustSend = true;
    logAddedAcksIfAny(numAcks);

    mustSend |= maybeFinishStartedMessages(ackOnly, packet, sentPacket, maxPacketSize);

    mustSend =
        mustSend
            || shouldSendDueToPacketSizeOrQueue(packet, maxPacketSize, now, messageQueue, ackOnly);

    mustSend = mustSend || shouldSendDueToRemoteBufferWithAcks(numAcks);

    // Keepalive decisions
    mustSend |= shouldForceSendByKeepaliveTimer(now, mustSend);
    boolean mustSendKeepalive = shouldScheduleKeepalivePayload(ackOnly, packet, now);
    if (mustSendKeepalive && canSend(sessionKey)) mustSend = true;

    if (!mustSend) {
      if (moved != null) {
        moved.abort();
      }
      return null;
    }

    if (!canSendAckOnly(numAcks, ackOnly)) return null;

    if (!ackOnly) {
      fillPacketWithFragments(
          packet, sentPacket, maxPacketSize, messageQueue, sessionKey, mustSendKeepalive, now);
    }

    if (!preparePacketForSend(packet, keyContext, ackOnly, sentPacket)) return null;

    return packet;
  }

  private void logAddedAcksIfAny(int numAcks) {
    if (numAcks > 0 && LOG.isTraceEnabled())
      LOG.trace("Added acks for {} for {}", this, pn.shortToString());
  }

  private boolean maybeFinishStartedMessages(
      boolean ackOnly, NPFPacket packet, SentPacket sentPacket, int maxPacketSize) {
    if (ackOnly) return false;
    return finishStartedMessagesAndAddFragments(packet, sentPacket, maxPacketSize);
  }

  private boolean shouldSendDueToRemoteBufferWithAcks(int numAcks) {
    return numAcks > 0 && shouldSendDueToRemoteBuffer();
  }

  private boolean canSendAckOnly(int numAcks, boolean ackOnly) {
    return !(ackOnly && numAcks == 0);
  }

  private boolean preparePacketForSend(
      NPFPacket packet,
      NewPacketFormatKeyContext keyContext,
      boolean ackOnly,
      SentPacket sentPacket) {
    if (packet.getLength() == 5) return false;
    int seqNum = keyContext.allocateSequenceNumber(pn);
    if (seqNum == -1) return false;
    packet.setSequenceNumber(seqNum);
    if (LOG.isTraceEnabled()) {
      if (ackOnly) {
        LOG.trace("Send ack-only packet bytes={} for {}", packet.getLength(), this);
      } else {
        LOG.trace("Send packet bytes={} for {}", packet.getLength(), this);
      }
    }
    if (!packet.getFragments().isEmpty()) {
      keyContext.sent(sentPacket, seqNum, packet.getLength());
    }
    return true;
  }

  private boolean updateMustSendForUrgentAcks(AddedAcks moved) {
    if (moved != null && moved.anyUrgentAcks) {
      if (LOG.isTraceEnabled()) LOG.trace("Must send due to urgent acks");
      return true;
    }
    return false;
  }

  private boolean finishStartedMessagesAndAddFragments(
      NPFPacket packet, SentPacket sentPacket, int maxPacketSize) {
    boolean addedFragments = false;
    synchronized (sendBufferLock) {
      for (Map<Integer, MessageWrapper> started : startedByPrio) {
        Iterator<MessageWrapper> it = started.values().iterator();
        while (it.hasNext() && packet.getLength() < maxPacketSize) {
          MessageWrapper wrapper = it.next();
          while (packet.getLength() < maxPacketSize) {
            MessageFragment frag = wrapper.getMessageFragment(maxPacketSize - packet.getLength());
            if (frag == null) break;
            addedFragments = true;
            packet.addMessageFragment(frag);
            sentPacket.addFragment(frag);
          }
        }
      }
    }
    if (addedFragments && LOG.isTraceEnabled())
      LOG.trace("Added fragments for {}; must send", this);
    return addedFragments;
  }

  private boolean shouldSendDueToPacketSizeOrQueue(
      NPFPacket packet,
      int maxPacketSize,
      long now,
      PeerMessageQueue messageQueue,
      boolean ackOnly) {
    if (packet.getLength() >= maxPacketSize * 4 / 5) {
      if (LOG.isTraceEnabled()) LOG.trace("Must send; ack-only packet size high");
      return true;
    }
    if (!ackOnly
        && (messageQueue.mustSendNow(now)
            || messageQueue.mustSendSize(packet.getLength(), maxPacketSize))) {
      if (LOG.isTraceEnabled()) LOG.trace("Must send due to message queue");
      return true;
    }
    return false;
  }

  private boolean shouldSendDueToRemoteBuffer() {
    int maxSendBufferSize = maxSendBufferSize();
    synchronized (sendBufferLock) {
      if (sendBufferUsed > maxSendBufferSize / 2) {
        if (LOG.isTraceEnabled()) LOG.trace("Must send; remote buffer used={}", sendBufferUsed);
        return true;
      }
    }
    return false;
  }

  private boolean shouldForceSendByKeepaliveTimer(long now, boolean alreadyMustSend) {
    if (!doKeepalives) return false;
    synchronized (this) {
      return !alreadyMustSend && (now - timeLastSentPacket > Node.KEEPALIVE_INTERVAL);
    }
  }

  private boolean shouldScheduleKeepalivePayload(boolean ackOnly, NPFPacket packet, long now) {
    if (!doKeepalives) return false;
    synchronized (this) {
      return !ackOnly
          && now - timeLastSentPayload > Node.KEEPALIVE_INTERVAL
          && packet.getFragments().isEmpty();
    }
  }

  private void fillPacketWithFragments(
      NPFPacket packet,
      SentPacket sentPacket,
      int maxPacketSize,
      PeerMessageQueue messageQueue,
      SessionKey sessionKey,
      boolean mustSendKeepalive,
      long now)
      throws BlockedTooLongException {

    for (int i = 0; i < startedByPrio.size(); i++) {
      while (packet.getLength() + 10 < maxPacketSize && canSend(sessionKey)) {
        FillAction action =
            appendNextFragmentForPriority(
                i, packet, sentPacket, maxPacketSize, messageQueue, mustSendKeepalive, now);
        if (action == FillAction.ABORT) return; // Abort filling entirely
        if (action == FillAction.STOP) break; // Stop this priority level
        // Otherwise CONTINUE
      }
    }
  }

  private enum FillAction {
    CONTINUE,
    STOP,
    ABORT
  }

  private FillAction appendNextFragmentForPriority(
      int priorityIndex,
      NPFPacket packet,
      SentPacket sentPacket,
      int maxPacketSize,
      PeerMessageQueue messageQueue,
      boolean mustSendKeepalive,
      long now)
      throws BlockedTooLongException {
    boolean wasGeneratedPing = false;
    MessageItem item = messageQueue.grabQueuedMessageItem(priorityIndex);
    if (item == null) {
      if (mustSendKeepalive && packet.noFragments()) {
        Message msg;
        synchronized (this) {
          msg = DMT.createFNPPing(pingCounter++);
        }
        item = new MessageItem(msg, null, null);
        item.setDeadline(now + PacketSender.MAX_COALESCING_DELAY);
        wasGeneratedPing = true;
      } else {
        return FillAction.STOP;
      }
    }

    int messageID = getMessageID();
    if (messageID == -1) {
      LOG.error("No available message ID; requeue item and send packet");
      if (!wasGeneratedPing) {
        messageQueue.pushfrontPrioritizedMessageItem(item);
      }
      return FillAction.ABORT;
    }

    if (LOG.isTraceEnabled())
      LOG.trace("Allocated messageId={} item={} peer={}", messageID, item, this);

    MessageWrapper wrapper = new MessageWrapper(item, messageID);
    MessageFragment frag = wrapper.getMessageFragment(maxPacketSize - packet.getLength());
    if (frag == null) {
      messageQueue.pushfrontPrioritizedMessageItem(item);
      return FillAction.STOP;
    } else {
      packet.addMessageFragment(frag);
      sentPacket.addFragment(frag);

      Map<Integer, MessageWrapper> queue = startedByPrio.get(item.getPriority());
      synchronized (sendBufferLock) {
        sendBufferUsed += item.buf.length;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Added {} bytes to remote buffer; total={} for {}",
              item.buf.length,
              sendBufferUsed,
              pn.shortToString());
        queue.put(messageID, wrapper);
      }
      return FillAction.CONTINUE;
    }
  }

  private int pingCounter;

  /** Maximum message size in bytes. */
  public static final int MAX_MESSAGE_SIZE = 4096;

  private int maxSendBufferSize() {
    return MAX_RECEIVE_BUFFER_SIZE;
  }

  /**
   * Computes the next time to run retransmission checks across all active session keys.
   *
   * @return an absolute timestamp (ms since epoch) when a loss check should next occur, or {@link
   *     Long#MAX_VALUE} when there are no in-flight packets.
   */
  @Override
  public long timeCheckForLostPackets() {
    long timeCheck = Long.MAX_VALUE;
    double averageRTT = averageRTT();
    SessionKey key = pn.getCurrentKeyTracker();
    if (key != null)
      timeCheck = Math.min(timeCheck, key.packetContext.timeCheckForLostPackets(averageRTT));
    key = pn.getPreviousKeyTracker();
    if (key != null)
      timeCheck = Math.min(timeCheck, key.packetContext.timeCheckForLostPackets(averageRTT));
    key = pn.getUnverifiedKeyTracker();
    if (key != null)
      timeCheck = Math.min(timeCheck, key.packetContext.timeCheckForLostPackets(averageRTT));
    return timeCheck;
  }

  private long timeCheckForAcks() {
    long timeCheck = Long.MAX_VALUE;
    SessionKey key = pn.getCurrentKeyTracker();
    if (key != null) timeCheck = Math.min(timeCheck, key.packetContext.timeCheckForAcks());
    key = pn.getPreviousKeyTracker();
    if (key != null) timeCheck = Math.min(timeCheck, key.packetContext.timeCheckForAcks());
    key = pn.getUnverifiedKeyTracker();
    if (key != null) timeCheck = Math.min(timeCheck, key.packetContext.timeCheckForAcks());
    return timeCheck;
  }

  /**
   * Scans in-flight packets and marks overdue ones as lost, updating throttling and backoff.
   *
   * <p>Side effects: may notify the {@link PacketThrottle} and peer backoff, and may wake the
   * sender when new capacity becomes available.
   */
  @Override
  public void checkForLostPackets() {
    if (pn == null) return;
    double averageRTT = averageRTT();
    long curTime = System.currentTimeMillis();
    SessionKey key = pn.getCurrentKeyTracker();
    if (key != null) key.packetContext.checkForLostPackets(averageRTT, curTime, pn);
    key = pn.getPreviousKeyTracker();
    if (key != null) key.packetContext.checkForLostPackets(averageRTT, curTime, pn);
    key = pn.getUnverifiedKeyTracker();
    if (key != null) key.packetContext.checkForLostPackets(averageRTT, curTime, pn);
  }

  /**
   * Clears send-side state on disconnect and returns message items to requeue upstream.
   *
   * @return a list of {@link MessageItem} instances that were partially sent and should be
   *     re-enqueued by the caller.
   */
  @Override
  public List<MessageItem> onDisconnect() {
    int messageSize = 0;
    final List<MessageItem> items = new ArrayList<>();
    // LOCKING: No packet may be sent while connected = false.
    // So we guarantee that no more packets are sent by setting this here.
    synchronized (sendBufferLock) {
      for (Map<Integer, MessageWrapper> queue : startedByPrio) {
        for (MessageWrapper wrapper : queue.values()) {
          items.add(wrapper.getItem());
          messageSize += wrapper.getLength();
        }
        queue.clear();
      }
      sendBufferUsed -= messageSize;
      // This is just a check for logging/debugging purposes.
      if (sendBufferUsed != 0) {
        LOG.warn(
            "Possible leak in transport code: Buffer size not empty after disconnecting on {} for"
                + " {} after removing {} total was {}",
            this,
            pn,
            messageSize,
            sendBufferUsed);
        sendBufferUsed = 0;
      }
    }
    return items;
  }

  /**
   * Computes the next time this peer would like to send any packet (acks, keepalive, or data).
   *
   * @param canSend whether {@link #canSend(SessionKey)} currently allows sending data.
   * @param now current time in milliseconds.
   * @return {@code 0} if something is already in flight; otherwise the earliest of the oldest ack
   *     deadline, half the average RTT (capped at 100 ms), or the next keepalive time. Returns
   *     {@link Long#MAX_VALUE} when nothing is pending.
   */
  @Override
  public long timeNextUrgent(boolean canSend, long now) {
    long ret = Long.MAX_VALUE;
    if (canSend) ret = Math.min(ret, earliestUnsentDeadline());
    ret = Math.min(ret, timeCheckForAcks());
    if (ret > now) {
      ret = Math.min(ret, now + Math.min(100, (long) (averageRTT() / 2)));
      if (canSend && doKeepalives) ret = Math.min(ret, nextKeepaliveTime());
    }
    return ret;
  }

  private long earliestUnsentDeadline() {
    long ret = Long.MAX_VALUE;
    synchronized (sendBufferLock) {
      for (Map<Integer, MessageWrapper> started : startedByPrio) {
        for (MessageWrapper wrapper : started.values()) {
          if (wrapper.allSent()) continue;
          long d = wrapper.getItem().getDeadline();
          if (d > 0) ret = Math.min(ret, d);
          else LOG.error("Started sending {}; invalid deadline {}", wrapper.getItem(), d);
        }
      }
    }
    return ret;
  }

  private long nextKeepaliveTime() {
    synchronized (this) {
      return timeLastSentPayload + Node.KEEPALIVE_INTERVAL;
    }
  }

  /**
   * Returns the earliest deadline to flush queued acknowledgments.
   *
   * @return an absolute timestamp (ms since epoch), or {@link Long#MAX_VALUE} if no acks are
   *     queued.
   */
  @Override
  public long timeSendAcks() {
    return timeCheckForAcks();
  }

  /**
   * Returns whether a packet with data can be sent now under current constraints.
   *
   * <p>Checks include message ID availability, sequence-number allocation for the given key, remote
   * buffer usage, and throttle window. When message ID allocation is not possible but there are
   * partially started messages, a send may still be performed to finish them.
   *
   * @param tracker the session key whose sequence numbers will be used; may be {@code null} to
   *     indicate that only throttling and buffering should be considered.
   * @return {@code true} if data can be sent now; {@code false} otherwise.
   */
  @Override
  public boolean canSend(SessionKey tracker) {
    boolean canAllocateID = canAllocateMessageId();
    if (canAllocateID) {
      if (!rekeyCheck(tracker)) return false;
      if (!withinRemoteBuffer()) return false;
    }
    if (!underThrottleLimit(tracker)) return false;
    if (!canAllocateID) {
      if (hasUnsentStartedMessages()) return true;
      if (LOG.isTraceEnabled()) LOG.trace("Cannot send because cannot allocate ID on {}", this);
    }
    return canAllocateID;
  }

  private boolean canAllocateMessageId() {
    synchronized (this) {
      return !seqNumGreaterThan(
          nextMessageID, (messageWindowPtrAcked + MSG_WINDOW_SIZE) % NUM_MESSAGE_IDS, 28);
    }
  }

  private boolean rekeyCheck(SessionKey tracker) {
    if (tracker == null) return false;
    NewPacketFormatKeyContext keyContext = tracker.packetContext;
    if (!keyContext.canAllocateSeqNum()) {
      pn.startRekeying();
      LOG.error("Can't send because we would block on {}", this);
      return false;
    }
    return true;
  }

  private boolean withinRemoteBuffer() {
    int bufferUsage;
    synchronized (sendBufferLock) {
      bufferUsage = sendBufferUsed;
    }
    int maxSendBufferSize = maxSendBufferSize();
    if (bufferUsage + MAX_MESSAGE_SIZE > maxSendBufferSize) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Cannot send; remote buffer used={} max={} on {}",
            bufferUsage,
            maxSendBufferSize,
            this);
      return false;
    }
    return true;
  }

  private boolean underThrottleLimit(SessionKey tracker) {
    if (tracker == null || pn == null) return true;
    PacketThrottle throttle = pn.transport().getThrottle();
    if (throttle == null) return true;
    int maxPackets =
        (int) Math.min(Integer.MAX_VALUE, pn.transport().getThrottle().getWindowSize());
    if (maxPackets < 1) maxPackets = 1;
    NewPacketFormatKeyContext packets = tracker.packetContext;
    if (maxPackets <= packets.countSentPackets()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Cannot send; in-flight={} limit={} on {}",
            packets.countSentPackets(),
            maxPackets,
            this);
      return false;
    }
    return true;
  }

  private boolean hasUnsentStartedMessages() {
    synchronized (sendBufferLock) {
      for (Map<Integer, MessageWrapper> started : startedByPrio) {
        for (MessageWrapper wrapper : started.values()) {
          if (!wrapper.allSent()) return true;
        }
      }
    }
    return false;
  }

  private long blockedSince = -1;

  private int getMessageID() throws BlockedTooLongException {
    int messageID;
    synchronized (this) {
      if (seqNumGreaterThan(
          nextMessageID, (messageWindowPtrAcked + MSG_WINDOW_SIZE) % NUM_MESSAGE_IDS, 28)) {
        if (blockedSince == -1) {
          blockedSince = System.currentTimeMillis();
        } else if (System.currentTimeMillis() - blockedSince > MAX_MSGID_BLOCK_TIME) {
          throw new BlockedTooLongException(System.currentTimeMillis() - blockedSince);
        }
        return -1;
      }
      blockedSince = -1;
      messageID = nextMessageID++;
      if (nextMessageID == NUM_MESSAGE_IDS) nextMessageID = 0;
    }
    return messageID;
  }

  private double averageRTT() {
    if (pn != null) {
      return pn.averagePingTimeCorrected();
    }
    return PeerNode.MIN_RTO;
  }

  static class SentPacket {
    final NewPacketFormat npf;
    final List<MessageWrapper> messages = new ArrayList<>();
    final List<int[]> ranges = new ArrayList<>();
    long sentTime;

    SentPacket(NewPacketFormat npf, SessionKey key) {
      this.npf = npf;
      if (LOG.isTraceEnabled()) LOG.trace("Created SentPacket for {}", key);
    }

    void addFragment(MessageFragment frag) {
      messages.add(frag.wrapper);
      ranges.add(new int[] {frag.fragmentOffset, frag.fragmentOffset + frag.fragmentLength - 1});
    }

    public long acked(SessionKey key) {
      Iterator<MessageWrapper> msgIt = messages.iterator();
      Iterator<int[]> rangeIt = ranges.iterator();
      while (msgIt.hasNext()) {
        MessageWrapper wrapper = msgIt.next();
        int[] range = rangeIt.next();
        processAckForWrapper(key, wrapper, range);
      }
      return System.currentTimeMillis() - sentTime;
    }

    private void processAckForWrapper(SessionKey key, MessageWrapper wrapper, int[] range) {
      if (LOG.isDebugEnabled())
        LOG.debug("Ack range {}-{} for messageId={}", range[0], range[1], wrapper.getMessageID());
      if (!wrapper.ack(range[0], range[1], npf.pn)) return;
      MessageWrapper removed = removeFromStartedAndUpdateBuffer(wrapper);
      if (removed == null && LOG.isDebugEnabled()) {
        LOG.debug(
            "Completed message {} not found in started map ({})", wrapper.getMessageID(), wrapper);
      }
      if (removed != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Completed message {}; removed from {}", wrapper.getMessageID(), wrapper);
        boolean couldSend = npf.canSend(key);
        updateAckedWindow(wrapper.getMessageID());
        if (!couldSend && npf.canSend(key)) {
          npf.pn.wakeUpSender();
        }
      }
    }

    private MessageWrapper removeFromStartedAndUpdateBuffer(MessageWrapper wrapper) {
      Map<Integer, MessageWrapper> started = npf.startedByPrio.get(wrapper.getPriority());
      MessageWrapper removed;
      synchronized (npf.sendBufferLock) {
        removed = started.remove(wrapper.getMessageID());
        if (removed != null) {
          int size = wrapper.getLength();
          npf.sendBufferUsed -= size;
          if (LOG.isDebugEnabled())
            LOG.debug("Removed {} bytes from remote buffer; total={}", size, npf.sendBufferUsed);
        }
      }
      return removed;
    }

    private void updateAckedWindow(int id) {
      synchronized (npf) {
        npf.ackedMessages.add(id, id);
        int oldWindow = npf.messageWindowPtrAcked;
        while (npf.ackedMessages.contains(npf.messageWindowPtrAcked, npf.messageWindowPtrAcked)) {
          npf.messageWindowPtrAcked++;
          if (npf.messageWindowPtrAcked == NUM_MESSAGE_IDS) npf.messageWindowPtrAcked = 0;
        }
        if (npf.messageWindowPtrAcked < oldWindow) {
          npf.ackedMessages.remove(oldWindow, NUM_MESSAGE_IDS - 1);
          npf.ackedMessages.remove(0, npf.messageWindowPtrAcked);
        } else {
          npf.ackedMessages.remove(oldWindow, npf.messageWindowPtrAcked);
        }
      }
    }

    public void lost() {
      Iterator<MessageWrapper> msgIt = messages.iterator();
      Iterator<int[]> rangeIt = ranges.iterator();

      while (msgIt.hasNext()) {
        MessageWrapper wrapper = msgIt.next();
        int[] range = rangeIt.next();

        wrapper.lost(range[0], range[1]);
      }
    }

    public void sent(int length) {
      if (LOG.isTraceEnabled()) LOG.trace("Sent packet bytes {}", length);
      sentTime = System.currentTimeMillis();
    }

    long getSentTime() {
      return sentTime;
    }
  }

  private static class PartiallyReceivedBuffer {
    private int messageLength;
    private byte[] buffer;
    private final NewPacketFormat npf;

    private PartiallyReceivedBuffer(NewPacketFormat npf) {
      messageLength = -1;
      buffer = new byte[0];
      this.npf = npf;
    }

    private boolean add(byte[] data, int dataOffset) {
      if (buffer.length < dataOffset + data.length && !resize(dataOffset + data.length))
        return false;

      System.arraycopy(data, 0, buffer, dataOffset, data.length);
      return true;
    }

    private boolean setMessageLength(int messageLength) {
      if (this.messageLength != -1 && this.messageLength != messageLength) {
        LOG.warn("Message length has already been set to a different length");
      }

      this.messageLength = messageLength;

      if (buffer.length > messageLength) {
        LOG.warn("Buffer larger than message length ({}>{})", buffer.length, messageLength);
      }

      return resize(messageLength);
    }

    private boolean cannotSetMessageLength(int messageLength) {
      return !setMessageLength(messageLength);
    }

    private boolean resize(int length) {
      if (LOG.isTraceEnabled())
        LOG.trace("Resize buffer from {} to {} bytes", buffer.length, length);

      synchronized (npf.receiveBufferSizeLock) {
        if (npf.receiveBufferUsed + length - buffer.length > MAX_RECEIVE_BUFFER_SIZE) {
          if (LOG.isDebugEnabled()) LOG.debug("Cannot resize buffer; exceeds max size");
          return false;
        }

        npf.receiveBufferUsed += length - buffer.length;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Added {} bytes to buffer; total={}", length - buffer.length, npf.receiveBufferUsed);
      }

      buffer = Arrays.copyOf(buffer, length);

      return true;
    }
  }

  @Override
  public String toString() {
    if (pn != null) return super.toString() + " for " + pn.shortToString();
    else return super.toString();
  }

  /**
   * Returns whether enough data is queued to justify sending a packet immediately.
   *
   * @param maxPacketSize the maximum payload size available for this transport.
   * @return {@code true} if queued data meets or exceeds the size threshold; {@code false}
   *     otherwise.
   */
  @Override
  public boolean fullPacketQueued(int maxPacketSize) {
    return pn.getMessageQueue().mustSendSize(HMAC_LENGTH /* header estimate */, maxPacketSize);
  }
}
