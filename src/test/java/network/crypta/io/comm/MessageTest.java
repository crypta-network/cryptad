package network.crypta.io.comm;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import network.crypta.node.PeerTransport;
import network.crypta.support.ShortBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for {@link Message}. */
@ExtendWith(MockitoExtension.class)
class MessageTest {

  // Field keys for a custom test MessageType
  private static final String BOOLEAN = "boolean";
  private static final String BYTE = "byte";
  private static final String SHORT = "short";
  private static final String INT = "int";
  private static final String LONG = "long";
  private static final String DOUBLE = "double";
  private static final String FLOAT = "float";
  private static final String DOUBLE_ARRAY = "double[]";
  private static final String FLOAT_ARRAY = "float[]";
  private static final String STR = "str";
  private static final String LIST = "list";

  // A single message type used across several tests; registered once.
  private static final MessageType SIMPLE_SPEC = createSimpleSpec();
  private static final MessageType SUB_SPEC = createSubSpec();
  // Minimal spec for round-trip encode/decode tests to avoid null fields.
  private static final MessageType ROUNDTRIP_SPEC = createRoundtripSpec();

  private static final MessageType INTERNAL_ONLY_SPEC =
      new MessageType("MessageTest.internalOnly", DMT.PRIORITY_LOW, true, false);

  private static MessageType createSimpleSpec() {
    MessageType spec = new MessageType("MessageTest.simple", DMT.PRIORITY_LOW);
    spec.addField(BOOLEAN, Boolean.class);
    spec.addField(BYTE, Byte.class);
    spec.addField(SHORT, Short.class);
    spec.addField(INT, Integer.class);
    spec.addField(LONG, Long.class);
    spec.addField(DOUBLE, Double.class);
    spec.addField(FLOAT, Float.class);
    spec.addField(DOUBLE_ARRAY, double[].class);
    spec.addField(FLOAT_ARRAY, float[].class);
    spec.addField(STR, String.class);
    spec.addLinkedListField(LIST, Integer.class);
    return spec;
  }

  private static MessageType createSubSpec() {
    MessageType spec = new MessageType("MessageTest.sub", DMT.PRIORITY_UNSPECIFIED);
    spec.addField("subVal", Integer.class);
    return spec;
  }

  private static MessageType createRoundtripSpec() {
    MessageType spec = new MessageType("MessageTest.roundtrip", DMT.PRIORITY_UNSPECIFIED);
    spec.addField(INT, Integer.class);
    spec.addField(STR, String.class);
    return spec;
  }

  // No Mockito mocks needed; use a minimal stub PeerContext below.

  @Test
  @SuppressWarnings("java:S100") // method naming per test naming convention
  void setGet_whenAllSupportedTypes_expectRoundTripViaAccessors() {
    Message msg = new Message(SIMPLE_SPEC);

    final boolean booleanVal = true;
    final byte byteVal = (byte) 123;
    final short shortVal = (short) 456;
    final int intVal = 78912;
    final long longVal = 3_456_789_123L;
    final double doubleVal = Math.PI;
    final float floatVal = 0.12345f;
    final double[] doubleArrayVal = new double[] {Math.PI, Math.E};
    final float[] floatArrayVal =
        new float[] {Float.parseFloat("1234.5678"), Float.parseFloat("912345.6789")};
    final String strVal = "hello";
    final List<Integer> listVal = new ArrayList<>(List.of(1, 2, 3));

    msg.set(BOOLEAN, booleanVal);
    msg.set(BYTE, byteVal);
    msg.set(SHORT, shortVal);
    msg.set(INT, intVal);
    msg.set(LONG, longVal);
    msg.set(DOUBLE, doubleVal);
    msg.set(FLOAT, floatVal);
    msg.set(DOUBLE_ARRAY, doubleArrayVal);
    msg.set(FLOAT_ARRAY, floatArrayVal);
    msg.set(STR, strVal);
    msg.set(LIST, listVal);

    assertEquals(booleanVal, msg.getBoolean(BOOLEAN));
    assertEquals(byteVal, msg.getByte(BYTE));
    assertEquals(shortVal, msg.getShort(SHORT));
    assertEquals(intVal, msg.getInt(INT));
    assertEquals(longVal, msg.getLong(LONG));
    assertEquals(doubleVal, msg.getDouble(DOUBLE), 0.0);
    assertEquals(floatVal, msg.getFloat(FLOAT), 0.0);
    assertArrayEquals(doubleArrayVal, msg.getDoubleArray(DOUBLE_ARRAY), 0.0);
    assertArrayEquals(floatArrayVal, msg.getFloatArray(FLOAT_ARRAY));
    assertEquals(strVal, msg.getString(STR));
    assertEquals(listVal, msg.getObject(LIST));

    // Sanity: isSet and getFromPayload happy path
    assertTrue(msg.isSet(INT));
    assertEquals(intVal, msg.getFromPayload(INT));
  }

  @Test
  @SuppressWarnings("java:S100")
  void set_whenUnknownField_expectIllegalState() {
    Message msg = new Message(SIMPLE_SPEC);
    assertThrows(IllegalStateException.class, () -> msg.set("nope", 1));
  }

  @Test
  @SuppressWarnings("java:S100")
  void set_whenWrongType_expectIncorrectTypeException() {
    Message msg = new Message(SIMPLE_SPEC);
    assertThrows(IncorrectTypeException.class, () -> msg.set(INT, "notAnInt"));
  }

  @Test
  @SuppressWarnings("java:S100")
  void set_whenNull_expectIncorrectTypeException() {
    Message msg = new Message(SIMPLE_SPEC);
    assertThrows(IncorrectTypeException.class, () -> msg.set(INT, null));
  }

  @Test
  @SuppressWarnings("java:S100")
  void getFromPayload_whenNotSet_expectException() {
    Message msg = new Message(SIMPLE_SPEC);
    assertThrows(Message.FieldNotSetException.class, () -> msg.getFromPayload(INT));
  }

  @Test
  @SuppressWarnings("java:S100")
  void encodeDecode_whenSimpleMessage_expectRoundTripFieldsAndPriority() {
    Message orig = new Message(ROUNDTRIP_SPEC);
    orig.set(INT, 42);
    orig.set(STR, "abc");
    byte[] packet = orig.encodeToPacket();

    // Provide a PeerContext so getSource() works on decoded messages.
    PeerContext pc = new TestPeerContext();
    Message decoded = Message.decodeMessageFromPacket(packet, 0, packet.length, pc, 7);
    assertNotNull(decoded);
    assertEquals(ROUNDTRIP_SPEC, decoded.getSpec());
    assertEquals(42, decoded.getInt(INT));
    assertEquals("abc", decoded.getString(STR));
    assertEquals(packet.length + 7, decoded.receivedByteCount());
    assertSame(pc, decoded.getSource());
    assertFalse(decoded.isInternal());

    // Default priority comes from the spec; boostPriority() decrements it.
    short p = decoded.getPriority();
    decoded.boostPriority();
    assertEquals((short) (p - 1), decoded.getPriority());
  }

  @Test
  @SuppressWarnings("java:S100")
  void encodeDecode_whenWithSubMessage_expectRetrievableViaGetAndGrab() {
    Message parent = new Message(ROUNDTRIP_SPEC);
    parent.set(INT, 10);
    parent.set(STR, "x");
    Message child = new Message(SUB_SPEC);
    child.set("subVal", 99);
    parent.addSubMessage(child);

    byte[] packet = parent.encodeToPacket();
    Message decoded =
        Message.decodeMessageFromPacket(packet, 0, packet.length, new TestPeerContext(), 0);
    assertNotNull(decoded);

    Message sub = decoded.getSubMessage(SUB_SPEC);
    assertNotNull(sub);
    assertEquals(99, sub.getInt("subVal"));

    // grabSubMessage removes it on retrieval
    Message grabbed = decoded.grabSubMessage(SUB_SPEC);
    assertNotNull(grabbed);
    assertNull(decoded.getSubMessage(SUB_SPEC));
  }

  @Test
  @SuppressWarnings("java:S100")
  void decode_whenIncompleteSubMessage_present_expectParentReturnedWithoutSubs()
      throws IOException {
    // Build a parent message packet and then append an incomplete submessage length which
    // claims more bytes than remain.
    Message parent = new Message(ROUNDTRIP_SPEC);
    parent.set(INT, 1);
    parent.set(STR, "x");
    byte[] base = parent.encodeToPacket();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    // Copy parent payload bytes.
    dos.write(base);
    // Append a sub-message size that's too large (e.g. 1000) but no payload bytes.
    dos.writeShort(1000);
    dos.flush();

    Message decoded =
        Message.decodeMessageFromPacket(
            baos.toByteArray(), 0, baos.size(), new TestPeerContext(), 0);
    assertNotNull(decoded);
    assertNull(decoded.getSubMessage(SUB_SPEC));
  }

  @Test
  @SuppressWarnings("java:S100")
  void decode_whenInternalOnlyMessage_expectNull() {
    Message internal = new Message(INTERNAL_ONLY_SPEC);
    byte[] packet = internal.encodeToPacket();

    Message decoded =
        Message.decodeMessageFromPacket(packet, 0, packet.length, new TestPeerContext(), 0);
    assertNull(decoded);
  }

  @Test
  @SuppressWarnings("java:S100")
  void decodeLax_whenUnknownType_expectNull() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    // Unknown spec ID
    dos.writeInt(0x1234_5678);
    dos.flush();
    assertNull(Message.decodeMessageLax(baos.toByteArray(), new TestPeerContext(), 0));
  }

  @Test
  @SuppressWarnings("java:S100")
  void getShortBufferBytes_whenWindowedBuffer_expectOnlyWindowReturned() {
    byte[] backing = new byte[] {0, 1, 2, 3, 4, 5, 6};
    ShortBuffer sb = new ShortBuffer(backing, 2, 3); // bytes 2,3,4
    MessageType shortBufferSpec = new MessageType("MessageTest.shortBuffer", DMT.PRIORITY_LOW);
    shortBufferSpec.addField(DMT.NODE_IDENTITY, ShortBuffer.class);
    Message msg = new Message(shortBufferSpec);
    msg.set(DMT.NODE_IDENTITY, sb);
    byte[] got = msg.getShortBufferBytes(DMT.NODE_IDENTITY);
    assertArrayEquals(new byte[] {2, 3, 4}, got);
  }

  @Test
  @SuppressWarnings("java:S100")
  void setRoutedToNodeFields_whenSpecHasRoutedFields_expectValuesSet() {
    MessageType t = new MessageType("MessageTest.routed", DMT.PRIORITY_LOW);
    t.addRoutedToNodeMessageFields();
    Message msg = new Message(t);
    byte[] nid = new byte[] {7, 8, 9};
    msg.setRoutedToNodeFields(123L, 0.75, (short) 7, nid);

    assertEquals(123L, msg.getLong(DMT.UID));
    assertEquals(0.75, msg.getDouble(DMT.TARGET_LOCATION), 0.0);
    assertEquals((short) 7, msg.getShort(DMT.HTL));
    assertArrayEquals(nid, msg.getShortBufferBytes(DMT.NODE_IDENTITY));
  }

  @Test
  @SuppressWarnings("java:S100")
  void cloneAndDropSubMessages_whenCloned_expectNoSubMessagesAndNoSource() {
    Message parent = new Message(ROUNDTRIP_SPEC);
    parent.set(INT, 5);
    parent.set(STR, "x");
    Message child = new Message(SUB_SPEC);
    child.set("subVal", 1);
    parent.addSubMessage(child);
    // Simulate a decoded (external) message
    Message decoded =
        Message.decodeMessageFromPacket(
            parent.encodeToPacket(), 0, parent.encodeToPacket().length, new TestPeerContext(), 0);
    assertNotNull(decoded);

    Message clone = decoded.cloneAndDropSubMessages();
    assertEquals(ROUNDTRIP_SPEC, clone.getSpec());
    assertEquals(5, clone.getInt(INT));
    assertNull(clone.getSubMessage(SUB_SPEC));
    assertNull(clone.getSource()); // originator is self
    // Priority is preserved
    assertEquals(decoded.getPriority(), clone.getPriority());
    // Received byte count resets to 0 on clone
    assertEquals(0, clone.receivedByteCount());
  }

  @Test
  @SuppressWarnings("java:S100")
  void toString_whenCalled_containsNameAndKeyValues() {
    Message msg = new Message(SIMPLE_SPEC);
    msg.set(INT, 77);
    msg.set(STR, "xyz");
    String s = msg.toString();
    assertTrue(s.contains(SIMPLE_SPEC.getName()));
    assertTrue(s.contains("77"));
    assertTrue(s.contains("xyz"));
  }

  // Minimal stub PeerContext for decode paths. Only getWeakRef() is used by Message.
  private static final class TestPeerContext implements PeerContext {
    private final WeakReference<PeerContext> ref = new WeakReference<>(this);
    private final PeerTransport transport = new TestTransport();

    @Override
    public Peer getPeer() {
      return null;
    }

    @Override
    public void forceDisconnect() {
      // Intentionally empty in test stub: decode-only tests never control connection lifecycle.
    }

    @Override
    public boolean isConnected() {
      return true;
    }

    @Override
    public boolean isRoutable() {
      return true;
    }

    @Override
    public int getBuildNumber() {
      return -1;
    }

    @Override
    public long getBootID() {
      return 0;
    }

    @Override
    public network.crypta.node.OutgoingPacketMangler getOutgoingMangler() {
      return null;
    }

    @Override
    public WeakReference<PeerContext> getWeakRef() {
      return ref;
    }

    @Override
    public String shortToString() {
      return "testPeer";
    }

    @Override
    public void transferFailed(String reason, boolean realTime) {
      // Intentionally empty in test stub: no actual send/transfer occurs during unit tests.
    }

    @Override
    public boolean unqueueMessage(network.crypta.node.MessageItem item) {
      return false;
    }

    @Override
    public void reportThrottledPacketSendTime(long time, boolean realTime) {
      // Intentionally empty in test stub: throttling metrics are irrelevant for decode-only tests.
    }

    @Override
    public int getThrottleWindowSize() {
      return 0;
    }

    @Override
    public PeerTransport transport() {
      return transport;
    }

    private static final class TestTransport implements PeerTransport {

      @Override
      public network.crypta.node.MessageItem sendAsync(
          Message msg, AsyncMessageCallback cb, ByteCounter ctr) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void sendSync(Message req, ByteCounter ctr, boolean realTime)
          throws NotConnectedException, network.crypta.node.SyncSendWaitedTooLongException {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean ping(int pingID) throws NotConnectedException {
        throw new UnsupportedOperationException();
      }

      @Override
      public network.crypta.io.xfer.PacketThrottle getThrottle() {
        return null;
      }

      @Override
      public SocketHandler getSocketHandler() {
        return null;
      }

      @Override
      public void handleMessage(Message msg) {
        throw new UnsupportedOperationException();
      }

      @Override
      public network.crypta.node.DecodingMessageGroup startProcessingDecryptedMessages(int count) {
        throw new UnsupportedOperationException();
      }
    }
  }
}
