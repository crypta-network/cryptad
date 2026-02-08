package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.xfer.PacketThrottle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NewPacketFormatTest {
  @BeforeEach
  void setUp() {
    // Because we don't call maybeSendPacket, the packet sent times are not updated,
    // so let's turn off the keepalives.
    setDoKeepalives(false);
  }

  @Test
  void createPacket_whenQueueEmpty_returnsNull() throws BlockedTooLongException {
    // Arrange
    NewPacketFormat npf = new NewPacketFormat(null, 0, 0);
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1234));
    SessionKey s = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    // Act
    NPFPacket p = npf.createPacket(1400, pmq, s, false);

    // Assert
    if (p != null) fail("Created packet from nothing");
  }

  @Test
  void createPacket_whenAckQueued_addsAck() throws BlockedTooLongException {
    // Arrange
    BasePeerNode pn = new NullBasePeerNode();
    NewPacketFormat npf = new NewPacketFormat(pn, 0, 0);
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1234));
    SessionKey s = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    NPFPacket generated = new NPFPacket();
    generated.addMessageFragment(
        new MessageFragment(
            new MessageFragmentHeader(true, false, true, 0),
            new MessageFragmentSizes(8, 8, 0),
            new MessageFragmentPayload(
                new byte[] {
                  (byte) 0x01,
                  (byte) 0x23,
                  (byte) 0x45,
                  (byte) 0x67,
                  (byte) 0x89,
                  (byte) 0xAB,
                  (byte) 0xCD,
                  (byte) 0xEF
                },
                null)));

    // Act
    assertEquals(1, npf.handleDecryptedPacket(generated, s).size());
    boolean keepalivesOrig = NewPacketFormat.doKeepalives;
    setDoKeepalives(true); // force sending without sleeping
    NPFPacket ackOnly;
    try {
      ackOnly = npf.createPacket(1400, pmq, s, false);
    } finally {
      setDoKeepalives(keepalivesOrig);
    }

    // Assert
    assertNotNull(ackOnly);
    assertEquals(1, ackOnly.getAcks().size());
  }

  @Test
  void resend_whenAckLost_triggersAckOnlyLater() throws BlockedTooLongException {
    // Arrange
    boolean keepalivesOrig = NewPacketFormat.doKeepalives;
    setDoKeepalives(true); // avoid sleeps for ack scheduling
    NullBasePeerNode senderNode = new NullBasePeerNode();
    NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
    PeerMessageQueue senderQueue = new PeerMessageQueue(new DummyRandomSource(1234));
    NullBasePeerNode receiverNode = new NullBasePeerNode();
    NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
    PeerMessageQueue receiverQueue = new PeerMessageQueue(new DummyRandomSource(1234));
    SessionKey senderKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);
    senderNode.currentKey = senderKey;
    SessionKey receiverKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    senderQueue.queueAndEstimateSize(
        new MessageItem(new byte[1024], null, false, null, (short) 0), 1024);

    // Act: send two fragments and ack them
    NPFPacket fragment1 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment1.getFragments().size());
    receiver.handleDecryptedPacket(fragment1, receiverKey);

    NPFPacket fragment2 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment2.getFragments().size());
    receiver.handleDecryptedPacket(fragment2, receiverKey);

    NPFPacket ack1 = receiver.createPacket(512, receiverQueue, receiverKey, false);
    assertEquals(2, ack1.getAcks().size());
    assertEquals(0, (int) ack1.getAcks().getFirst());
    assertEquals(1, (int) ack1.getAcks().getLast());
    sender.handleDecryptedPacket(ack1, senderKey);

    NPFPacket fragment3 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment3.getFragments().size());
    receiver.handleDecryptedPacket(fragment3, receiverKey);
    receiver.createPacket(512, senderQueue, receiverKey, false); // Simulate lost ack-only

    // Force loss detection without sleeping by backdating sent times
    backdateAllSentTimes(senderKey.packetContext);

    NPFPacket resend1 = sender.createPacket(512, senderQueue, senderKey, false);
    if (resend1 == null) fail("No packet to resend");
    assertEquals(0, receiver.handleDecryptedPacket(resend1, receiverKey).size());

    // Assert: receiver sends an ack-only packet for the resend (keepalive path)
    NPFPacket ack2 = receiver.createPacket(512, receiverQueue, receiverKey, false);
    assertNotNull(ack2);
    assertEquals(1, ack2.getAcks().size());
    setDoKeepalives(keepalivesOrig);
  }

  @Test
  void handleDecryptedPacket_whenFragmentsOutOfOrder_completesOnMissingPiece()
      throws BlockedTooLongException {
    // Arrange
    NullBasePeerNode senderNode = new NullBasePeerNode();
    NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
    PeerMessageQueue senderQueue = new PeerMessageQueue(new DummyRandomSource(1234));
    NullBasePeerNode receiverNode = new NullBasePeerNode();
    NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
    SessionKey senderKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);
    SessionKey receiverKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    senderQueue.queueAndEstimateSize(
        new MessageItem(new byte[1024], null, false, null, (short) 0), 1024);

    NPFPacket fragment1 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment1.getFragments().size());

    NPFPacket fragment2 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment2.getFragments().size());

    NPFPacket fragment3 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment3.getFragments().size());

    // Act: deliver 1 and 3, then the missing middle 2
    receiver.handleDecryptedPacket(fragment1, receiverKey);
    receiver.handleDecryptedPacket(fragment3, receiverKey);
    int completed = receiver.handleDecryptedPacket(fragment2, receiverKey).size();

    // Assert
    assertEquals(1, completed);
  }

  @Test
  void handleDecryptedPacket_whenFirstFragmentArrivesLater_completesMessage()
      throws BlockedTooLongException {
    // Arrange
    NullBasePeerNode senderNode = new NullBasePeerNode();
    NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
    PeerMessageQueue senderQueue = new PeerMessageQueue(new DummyRandomSource(1234));
    NullBasePeerNode receiverNode = new NullBasePeerNode();
    NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
    SessionKey senderKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);
    SessionKey receiverKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    senderQueue.queueAndEstimateSize(
        new MessageItem(new byte[1024], null, false, null, (short) 0), 1024);

    NPFPacket fragment1 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment1.getFragments().size());
    NPFPacket fragment2 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment2.getFragments().size());
    NPFPacket fragment3 = sender.createPacket(512, senderQueue, senderKey, false);
    assertEquals(1, fragment3.getFragments().size());

    // Act: receive non-first fragments first, then the first fragment carrying message length
    receiver.handleDecryptedPacket(fragment3, receiverKey);
    receiver.handleDecryptedPacket(fragment2, receiverKey);
    int completed = receiver.handleDecryptedPacket(fragment1, receiverKey).size();

    // Assert
    assertEquals(1, completed);
  }

  @Test
  void handleDecryptedPacket_whenDuplicateOrResend_doesNotReDeliver()
      throws BlockedTooLongException {
    // Arrange
    NullBasePeerNode senderNode = new NullBasePeerNode();
    NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
    PeerMessageQueue senderQueue = new PeerMessageQueue(new DummyRandomSource(1234));
    NullBasePeerNode receiverNode = new NullBasePeerNode();
    NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
    SessionKey senderKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);
    SessionKey receiverKey = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    // Queue two messages so the total queued size exceeds maxPacketSize (512) and triggers
    // immediate
    // send.
    senderQueue.queueAndEstimateSize(
        new MessageItem(new byte[400], null, false, null, (short) 0), 1024);
    senderQueue.queueAndEstimateSize(
        new MessageItem(new byte[200], null, false, null, (short) 0), 1024);

    // Act
    NPFPacket packet1 = sender.createPacket(512, senderQueue, senderKey, false);
    int first = receiver.handleDecryptedPacket(packet1, receiverKey).size();
    int duplicate = receiver.handleDecryptedPacket(packet1, receiverKey).size();
    int resend = receiver.handleDecryptedPacket(packet1, receiverKey).size();

    // Assert
    assertEquals(1, first);
    assertEquals(0, duplicate);
    assertEquals(0, resend);
  }

  /* This checks the output of the sequence number encryption function to
   * make sure it doesn't change accidentally. */
  @Test
  void encryptSequenceNumber_whenFixedInputs_matchesGoldenBytes() {
    // Arrange
    BlockCipher ivCipher = new Rijndael();
    ivCipher.initialize(
        new byte[] {
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00
        });

    byte[] ivNonce = new byte[16];

    BlockCipher incommingCipher = new Rijndael();
    incommingCipher.initialize(
        new byte[] {
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00
        });

    SessionKey sessionKey =
        new SessionKey(
            null,
            new SessionKeyCryptoMaterial(
                null, null, incommingCipher, null, ivCipher, ivNonce, null),
            null,
            -1);

    // Act
    byte[] encrypted = NewPacketFormat.encryptSequenceNumber(0, sessionKey);

    // Assert (golden value)
    byte[] correct = new byte[] {(byte) 0xF7, (byte) 0x95, (byte) 0xBD, (byte) 0x4A};
    assertArrayEquals(correct, encrypted);
  }

  @Test
  void handleReceivedPacket_whenCiphertextValid_deliversOneMessage()
      throws BlockedTooLongException, UnknownHostException {
    // Arrange
    Random random = new Random(120116);
    NullBasePeerNode senderNode = new NullBasePeerNode();
    NullBasePeerNode receiverNode = new NullBasePeerNode();
    byte[] outgoingKey = new byte[32];
    random.nextBytes(outgoingKey);
    BlockCipher outgoingCipher = new Rijndael();
    outgoingCipher.initialize(outgoingKey);
    byte[] incomingKey = new byte[32];
    random.nextBytes(incomingKey);
    BlockCipher incomingCipher = new Rijndael();
    incomingCipher.initialize(incomingKey);
    BlockCipher ivCipher = new Rijndael();
    byte[] ivKey = new byte[32];
    random.nextBytes(ivKey);
    ivCipher.initialize(ivKey);
    byte[] ivNonce = new byte[16];
    random.nextBytes(ivNonce);
    byte[] hmacKey = new byte[32];
    random.nextBytes(hmacKey);
    int senderStartSeq = 1000;
    int receiverStartSeq = 2000;

    NewPacketFormatKeyContext senderContext =
        new NewPacketFormatKeyContext(senderStartSeq, receiverStartSeq);

    NewPacketFormatKeyContext receiverContext =
        new NewPacketFormatKeyContext(receiverStartSeq, senderStartSeq);

    SessionKey senderSessionKey =
        new SessionKey(
            null,
            new SessionKeyCryptoMaterial(
                outgoingCipher,
                outgoingKey,
                incomingCipher,
                incomingKey,
                ivCipher,
                ivNonce,
                hmacKey),
            senderContext,
            0);

    SessionKey receiverSessionKey =
        new SessionKey(
            null,
            new SessionKeyCryptoMaterial(
                incomingCipher,
                incomingKey,
                outgoingCipher,
                outgoingKey,
                ivCipher,
                ivNonce,
                hmacKey),
            receiverContext,
            0);

    senderNode.currentKey = senderSessionKey;
    receiverNode.currentKey = receiverSessionKey;

    NewPacketFormat senderNPF = new NewPacketFormat(senderNode, senderStartSeq, receiverStartSeq);
    NewPacketFormat receiverNPF =
        new NewPacketFormat(receiverNode, receiverStartSeq, senderStartSeq);

    PeerMessageQueue senderQueue = new PeerMessageQueue(new DummyRandomSource(1234));

    byte[] message = new byte[700];
    random.nextBytes(message);
    byte[] copyOfMessage = Arrays.copyOf(message, message.length);

    // Queue two messages so the total exceeds maxPacketSize (1280) and triggers immediate send.
    byte[] other = new byte[700];
    random.nextBytes(other);
    senderQueue.queueAndEstimateSize(new MessageItem(message, null, false, null, (short) 0), 4096);
    senderQueue.queueAndEstimateSize(new MessageItem(other, null, false, null, (short) 0), 4096);

    senderNode.messageQueue = senderQueue;
    senderNPF.maybeSendPacket(false, senderSessionKey);

    FreenetInetAddress localhost = new FreenetInetAddress("127.0.0.1", true);
    Peer peer = new Peer(localhost, 1234);

    byte[] data = senderNode.sentEncryptedPacket;

    // Act
    receiverNode.decryptedMessages = new ArrayList<>();
    receiverNPF.handleReceivedPacket(data, 0, data.length, System.currentTimeMillis(), peer);

    // Assert
    assertEquals(1, receiverNode.decryptedMessages.size());
    assertArrayEquals(message, copyOfMessage);
    assertArrayEquals(receiverNode.decryptedMessages.getFirst(), message);
  }

  @Test
  @DisplayName("onDisconnect returns queued-but-unsent items and clears buffer")
  @Timeout(5)
  void onDisconnect_whenWrappersInFlight_returnsItems() throws BlockedTooLongException {
    NullBasePeerNode pn = new NullBasePeerNode();
    NewPacketFormat npf = new NewPacketFormat(pn, /*ourInitial*/ 123, /*theirInitial*/ 456);
    PeerMessageQueue q = new PeerMessageQueue(new DummyRandomSource(42));
    pn.messageQueue = q;

    // Queue a single small message and build a packet fragment to move it into startedByPrio.
    byte[] payload = new byte[1024];
    q.queueAndEstimateSize(new MessageItem(payload, null, false, null, (short) 0), 1024);
    SessionKey key = new SessionKey(null, null, new NewPacketFormatKeyContext(0, 0), 1);

    NPFPacket p = npf.createPacket(512, q, key, /*ackOnly*/ false);
    assertNotNull(p, "Expected a packet with one fragment before disconnect");
    assertEquals(1, p.getFragments().size());

    // Now disconnect and ensure the caller returns the item for requeue-ing.
    List<MessageItem> returned = npf.onDisconnect();
    assertEquals(1, returned.size());
    assertEquals(payload.length, returned.getFirst().getLength());
  }

  @Test
  @DisplayName("fullPacketQueued reflects message-queue size thresholds")
  void fullPacketQueued_threshold() {
    NullBasePeerNode pn = new NullBasePeerNode();
    pn.messageQueue = new PeerMessageQueue(new DummyRandomSource(7));
    NewPacketFormat npf = new NewPacketFormat(pn, 0, 0);

    int maxPacket = 512;
    // Below threshold: HMAC(10) + 100 < 512 => false
    pn.messageQueue.queueAndEstimateSize(
        new MessageItem(new byte[100], null, false, null, (short) 0), 1024);
    assertFalse(npf.fullPacketQueued(maxPacket));
    // Above threshold: add enough to cross maxPacket
    pn.messageQueue.queueAndEstimateSize(
        new MessageItem(new byte[450], null, false, null, (short) 0), 1024);
    assertTrue(npf.fullPacketQueued(maxPacket));
  }

  @Test
  @DisplayName("handleDecryptedPacket: no fragments => don't ack and no messages")
  void handleDecryptedPacket_whenEmpty_dontAck() {
    NullBasePeerNode pn = new NullBasePeerNode();
    NewPacketFormat npf = new NewPacketFormat(pn, 0, 0);
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    SessionKey key = new SessionKey(null, null, ctx, 1);
    pn.currentKey = key; // So timeSendAcks() can see the same ctx

    NPFPacket empty = new NPFPacket();
    List<byte[]> finished = npf.handleDecryptedPacket(empty, key);
    assertTrue(finished.isEmpty(), "No fragments -> no completed messages");
    assertEquals(Long.MAX_VALUE, npf.timeSendAcks(), "No ack queued for empty packet");
  }

  @Test
  @DisplayName("maybeSendPacket prioritizes previous key for ack-only packets")
  @Timeout(5)
  void maybeSendPacket_ackOnly_usesPreviousKey() throws Exception {
    // Build crypto materials as in testEncryption for deterministic encryption.
    Random rnd = new Random(1337);
    NullBasePeerNode pn = new NullBasePeerNode();
    byte[] keyA = new byte[32];
    rnd.nextBytes(keyA);
    byte[] keyB = new byte[32];
    rnd.nextBytes(keyB);
    byte[] ivKey = new byte[32];
    rnd.nextBytes(ivKey);
    byte[] ivNonce = new byte[16];
    rnd.nextBytes(ivNonce);
    byte[] hmac = new byte[32];
    rnd.nextBytes(hmac);

    BlockCipher out = new Rijndael();
    out.initialize(keyA);
    BlockCipher in = new Rijndael();
    in.initialize(keyB);
    BlockCipher iv = new Rijndael();
    iv.initialize(ivKey);

    NewPacketFormatKeyContext prevCtx = new NewPacketFormatKeyContext(10, 20);
    SessionKey prev =
        new SessionKey(
            null,
            new SessionKeyCryptoMaterial(out, keyA, in, keyB, iv, ivNonce, hmac),
            prevCtx,
            99);
    pn.previousKey = prev;

    // Ack something on the previous key by simulating a decrypted packet with one fragment.
    NewPacketFormat npf = new NewPacketFormat(pn, 0, 0);
    NPFPacket received = new NPFPacket();
    received.setSequenceNumber(123);
    received.addMessageFragment(
        new MessageFragment(
            new MessageFragmentHeader(true, false, true, 1),
            new MessageFragmentSizes(1, 1, 0),
            new MessageFragmentPayload(new byte[] {1}, null)));
    List<byte[]> finished = npf.handleDecryptedPacket(received, prev);
    assertEquals(1, finished.size());

    // Now ask NPF to maybe send an ack-only packet. It should use the previous key.
    // Make the ack urgent by backdating its timestamp instead of sleeping.
    backdateAllAcks(prevCtx);
    boolean sent = npf.maybeSendPacket(System.currentTimeMillis(), /*ackOnly*/ true);
    assertTrue(sent, "Expected an ack-only packet to be sent on the previous key");
    assertNotNull(pn.sentEncryptedPacket, "Encrypted packet bytes should be produced");
  }

  @Test
  @DisplayName("handleReceivedPacket: invalid HMAC -> false")
  @Timeout(5)
  void handleReceivedPacket_whenHmacInvalid_returnsFalse() throws Exception {
    // Prepare a valid encrypted packet as in testEncryption, then corrupt it and expect false.
    Random random = new Random(2024);
    NullBasePeerNode senderNode = new NullBasePeerNode();
    NullBasePeerNode receiverNode = new NullBasePeerNode();

    byte[] outgoingKey = new byte[32];
    random.nextBytes(outgoingKey);
    BlockCipher outgoingCipher = new Rijndael();
    outgoingCipher.initialize(outgoingKey);
    byte[] incomingKey = new byte[32];
    random.nextBytes(incomingKey);
    BlockCipher incomingCipher = new Rijndael();
    incomingCipher.initialize(incomingKey);
    BlockCipher ivCipher = new Rijndael();
    byte[] ivKey = new byte[32];
    random.nextBytes(ivKey);
    ivCipher.initialize(ivKey);
    byte[] ivNonce = new byte[16];
    random.nextBytes(ivNonce);
    byte[] hmacKey = new byte[32];
    random.nextBytes(hmacKey);

    int senderStartSeq = 111;
    int receiverStartSeq = 222;
    NewPacketFormatKeyContext senderCtx =
        new NewPacketFormatKeyContext(senderStartSeq, receiverStartSeq);
    NewPacketFormatKeyContext receiverCtx =
        new NewPacketFormatKeyContext(receiverStartSeq, senderStartSeq);

    SessionKey senderSessionKey =
        new SessionKey(
            null,
            new SessionKeyCryptoMaterial(
                outgoingCipher,
                outgoingKey,
                incomingCipher,
                incomingKey,
                ivCipher,
                ivNonce,
                hmacKey),
            senderCtx,
            0);
    SessionKey receiverSessionKey =
        new SessionKey(
            null,
            new SessionKeyCryptoMaterial(
                incomingCipher,
                incomingKey,
                outgoingCipher,
                outgoingKey,
                ivCipher,
                ivNonce,
                hmacKey),
            receiverCtx,
            0);
    senderNode.currentKey = senderSessionKey;
    receiverNode.currentKey = receiverSessionKey;

    NewPacketFormat senderNPF = new NewPacketFormat(senderNode, senderStartSeq, receiverStartSeq);
    NewPacketFormat receiverNPF =
        new NewPacketFormat(receiverNode, receiverStartSeq, senderStartSeq);

    PeerMessageQueue senderQueue = new PeerMessageQueue(new DummyRandomSource(1234));
    // Queue two messages so the total exceeds maxPacketSize and triggers immediate send.
    byte[] m1 = new byte[700];
    byte[] m2 = new byte[700];
    random.nextBytes(m1);
    random.nextBytes(m2);
    senderQueue.queueAndEstimateSize(new MessageItem(m1, null, false, null, (short) 0), 4096);
    senderQueue.queueAndEstimateSize(new MessageItem(m2, null, false, null, (short) 0), 4096);
    senderNode.messageQueue = senderQueue;

    // Send one packet and capture its ciphertext (first message)
    senderNPF.maybeSendPacket(false, senderSessionKey);
    byte[] data = senderNode.sentEncryptedPacket.clone();
    assertNotNull(data);

    // Corrupt the HMAC so verification fails (flip one bit in the first HMAC byte)
    data[0] ^= 0x01;
    FreenetInetAddress localhost = new FreenetInetAddress("127.0.0.1", true);
    Peer peer = new Peer(localhost, 1234);

    boolean ok =
        receiverNPF.handleReceivedPacket(data, 0, data.length, System.currentTimeMillis(), peer);
    assertFalse(ok, "Invalid HMAC must cause handleReceivedPacket() to return false");
  }

  @Mock private BasePeerNode mockPeer;

  /** Backdates all in-flight sent packets so loss detection triggers without waiting. */
  private static void backdateAllSentTimes(NewPacketFormatKeyContext ctx) {
    try {
      java.lang.reflect.Field f = NewPacketFormatKeyContext.class.getDeclaredField("sentPackets");
      f.setAccessible(true);
      @SuppressWarnings("unchecked")
      java.util.HashMap<Integer, NewPacketFormat.SentPacket> map =
          (java.util.HashMap<Integer, NewPacketFormat.SentPacket>) f.get(ctx);
      long newSent =
          System.currentTimeMillis() - 5000L; // ample to exceed the retransmitting threshold
      for (NewPacketFormat.SentPacket sp : map.values()) {
        java.lang.reflect.Field sf = NewPacketFormat.SentPacket.class.getDeclaredField("sentTime");
        sf.setAccessible(true);
        sf.setLong(sp, newSent);
      }
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to backdate sentTimes via reflection", e);
    }
  }

  /** Backdates all queued ack timestamps so they are considered urgent without waiting. */
  private static void backdateAllAcks(NewPacketFormatKeyContext ctx) {
    try {
      java.lang.reflect.Field f = NewPacketFormatKeyContext.class.getDeclaredField("acks");
      f.setAccessible(true);
      @SuppressWarnings("unchecked")
      java.util.TreeMap<Integer, Long> map = (java.util.TreeMap<Integer, Long>) f.get(ctx);
      java.util.ArrayList<Integer> keys = new java.util.ArrayList<>(map.keySet());
      long newTime = System.currentTimeMillis() - (NewPacketFormatKeyContext.MAX_ACK_DELAY * 2L);
      for (Integer k : keys) {
        map.put(k, newTime);
      }
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to backdate acks via reflection", e);
    }
  }

  private static void setDoKeepalives(boolean enabled) {
    NewPacketFormat.doKeepalives = enabled;
  }

  private static LinkageError linkageError(String message, ReflectiveOperationException e) {
    return new LinkageError(message, e);
  }

  @Test
  @DisplayName("canSend: throttle window exhausted -> false (Mockito)")
  void canSend_whenThrottleWindowExhausted_returnsFalse() {
    // Minimal NPF with mocked peer reporting a tiny window.
    PacketThrottle throttle = Mockito.mock(PacketThrottle.class);
    Mockito.when(throttle.getWindowSize()).thenReturn(1.0);
    PeerTransport transport = Mockito.mock(PeerTransport.class);
    Mockito.when(mockPeer.transport()).thenReturn(transport);
    Mockito.when(transport.getThrottle()).thenReturn(throttle);

    NewPacketFormat npf = new NewPacketFormat(mockPeer, 0, 0);
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    SessionKey key = new SessionKey(null, null, ctx, 1);

    // Simulate one in-flight packet so countSentPackets() == 1 and equals the window size.
    NewPacketFormat.SentPacket sp = new NewPacketFormat.SentPacket(npf, key);
    ctx.sent(sp, /*seq*/ 5, /*len*/ 100);

    boolean can = npf.canSend(key);
    assertFalse(can, "Window fully used (1 in flight of 1) -> cannot send");
  }
}
