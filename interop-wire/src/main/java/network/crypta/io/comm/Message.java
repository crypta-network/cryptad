package network.crypta.io.comm;

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serial;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import network.crypta.support.ByteBufferInputStream;
import network.crypta.support.Fields;
import network.crypta.support.Serializer;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Message container for the Crypta wire format.
 *
 * <p>Instances encode to and decode from a compact binary representation used in UDP datagrams. A
 * message carries a {@link MessageType} and a typed payload addressed by field name. Messages may
 * also contain nested “sub-messages” to bundle related information without introducing new
 * top‑level types.
 *
 * <p>Security note: Prefer constructing a fresh {@code Message} when forwarding rather than passing
 * an incoming instance verbatim. Forwarding as‑is preserves any embedded submessages and can
 * inadvertently leak metadata (e.g., labeling, collusion signals along a route) and waste
 * bandwidth. Sub‑messages exist primarily for historical compatibility and should be used
 * judiciously.
 *
 * <p>Thread-safety: {@code Message} is mutable and not thread‑safe. Callers should confine each
 * instance to a single thread or apply external synchronization.
 */
public class Message {
  private static final Logger LOG = LoggerFactory.getLogger(Message.class);

  /** Legacy source control identifier kept for historical compatibility. */
  public static final String VERSION =
      "$Id: Message.java,v 1.11 2005/09/15 18:16:04 amphibian Exp $";

  private final MessageType spec;
  private final WeakReference<? extends MessageSource> sourceRef;
  private final boolean internal;
  private final HashMap<String, Object> payload = HashMap.newHashMap(8);
  private List<Message> subMessages;

  /**
   * Time of local instantiation in milliseconds since the epoch.
   *
   * <p>For decoded messages this reflects when the instance was constructed, not when the packet
   * was received on the network.
   */
  public final long localInstantiationTime;

  private final int receivedByteCount;
  short priority;

  /**
   * Decodes a message from a datagram buffer.
   *
   * <p>On failure (invalid type, internal‑only type, truncated payload, or I/O while reading the
   * buffer), this method returns {@code null} without throwing.
   *
   * @param buf backing array containing the datagram payload
   * @param offset start offset within {@code buf}
   * @param length number of bytes to read starting at {@code offset}
   * @param peer decoding context for the sending peer; may be {@code null}
   * @param overhead additional bytes attributed to the received packet (e.g., link/protocol
   *     overhead) that should be counted for statistics; incorporated into {@link
   *     #receivedByteCount()}
   * @return a decoded {@code Message}, or {@code null} if decoding fails or the type is rejected
   */
  public static Message decodeMessageFromPacket(
      byte[] buf, int offset, int length, MessageSource peer, int overhead) {
    ByteBufferInputStream bb = new ByteBufferInputStream(buf, offset, length);
    return decodeMessage(bb, peer, length + overhead, true, false, false);
  }

  /**
   * Decodes a message using relaxed validation.
   *
   * <p>Compared to {@link #decodeMessageFromPacket(byte[], int, int, MessageSource, int)}, this
   * variant accepts certain legacy or malformed inputs that the strict decoder would reject.
   *
   * @param buf array containing the entire payload
   * @param peer decoding context for the sending peer; may be {@code null}
   * @param overhead additional bytes attributed to the received packet for statistics
   * @return a decoded {@code Message}, or {@code null} when decoding fails
   */
  public static Message decodeMessageLax(byte[] buf, MessageSource peer, int overhead) {
    ByteBufferInputStream bb = new ByteBufferInputStream(buf);
    return decodeMessage(bb, peer, buf.length + overhead, true, false, true);
  }

  private static Message decodeMessage(
      ByteBufferInputStream bb,
      MessageSource peer,
      int recvByteCount,
      boolean mayHaveSubMessages,
      boolean inSubMessage,
      boolean veryLax) {
    MessageType mspec = readMessageType(bb, veryLax);
    if (mspec == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("event=decode-invalid-type message type missing or corrupt");
      return null;
    }
    if (!isAcceptable(mspec)) return null;
    Message m = new Message(mspec, peer, recvByteCount);
    try {
      readMessageFields(mspec, m, bb);
      readAndAttachSubMessagesIfAny(m, bb, peer, veryLax, mayHaveSubMessages);
    } catch (EOFException e) {
      logPrematureEnd(peer, mspec, inSubMessage, e);
      return null;
    } catch (IOException e) {
      LOG.error("event=decode-io-error unexpected I/O reading message payload: {}", e, e);
      return null;
    }
    logReturnMessage(m);
    return m;
  }

  private static MessageType readMessageType(ByteBufferInputStream bb, boolean veryLax) {
    try {
      return MessageType.getSpec(bb.readInt(), veryLax);
    } catch (IOException e1) {
      if (LOG.isDebugEnabled())
        LOG.debug("event=decode-type-read-failed failed to read message type id: {}", e1, e1);
      return null;
    }
  }

  private static boolean isAcceptable(MessageType mspec) {
    if (mspec == null) {
      if (LOG.isDebugEnabled()) LOG.debug("event=accept-null-type rejected null message type");
      return false;
    }
    if (mspec.isInternalOnly()) {
      if (LOG.isDebugEnabled())
        LOG.debug("event=accept-internal-only rejected internal-only message");
      return false; // silently discard internal-only messages
    }
    return true;
  }

  private static void readAndAttachSubMessagesIfAny(
      Message m,
      ByteBufferInputStream bb,
      MessageSource peer,
      boolean veryLax,
      boolean mayHaveSubMessages) {
    if (!mayHaveSubMessages) return;
    readAndAttachSubMessages(m, bb, peer, veryLax);
  }

  private static void logPrematureEnd(
      MessageSource peer, MessageType mspec, boolean inSubMessage, EOFException e) {
    String msg =
        peer.getPeer()
            + " sent a message packet that ends prematurely while deserialising "
            + mspec.getName();
    if (inSubMessage) {
      if (LOG.isDebugEnabled()) LOG.debug("event=submessage-truncated {}", msg, e);
    } else {
      LOG.error(msg, e);
    }
  }

  private static void logReturnMessage(Message m) {
    if (LOG.isDebugEnabled())
      LOG.debug("event=decode-complete decoded message {} from {}", m, m.getSource());
  }

  private static void readMessageFields(MessageType mspec, Message m, ByteBufferInputStream bb)
      throws IOException {
    DataInput dataInput = bb.asDataInput();
    for (String name : mspec.getOrderedFields()) {
      Class<?> type = mspec.getFields().get(name);
      if (type.equals(List.class)) {
        m.set(
            name,
            Serializer.readListFromDataInputStream(
                mspec.getLinkedListTypes().get(name), dataInput));
      } else {
        m.set(name, Serializer.readFromDataInputStream(type, dataInput));
      }
    }
  }

  private static void readAndAttachSubMessages(
      Message m, ByteBufferInputStream bb, MessageSource peer, boolean veryLax) {
    while (bb.remaining() > 2) { // sizeof(unsigned short) == 2
      ByteBufferInputStream bb2 = readSubMessageSlice(bb, m);
      if (bb2 == null) {
        // Not enough data or EOF - stop processing sub-messages gracefully.
        return;
      }
      Message subMessage = decodeSubMessage(bb2, peer, veryLax);
      if (subMessage == null) return; // Stop if decoding failed or returned null
      if (LOG.isDebugEnabled())
        LOG.debug("event=submessage-attach added sub-message: {}", subMessage);
      m.addSubMessage(subMessage);
    }
  }

  private static ByteBufferInputStream readSubMessageSlice(ByteBufferInputStream bb, Message m) {
    try {
      int size = bb.readUnsignedShort();
      if (bb.remaining() < size) return null;
      return bb.slice(size);
    } catch (EOFException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("event=submessage-none no sub-messages to read; stop at {}", m);
      return null;
    } catch (IOException e) {
      LOG.error("event=submessage-slice-io I/O error while reading sub-message slice: {}", e, e);
      return null;
    }
  }

  private static Message decodeSubMessage(
      ByteBufferInputStream bb2, MessageSource peer, boolean veryLax) {
    try {
      return decodeMessage(bb2, peer, 0, false, true, veryLax);
    } catch (Exception e) {
      LOG.error("event=submessage-decode-failed failed to decode sub-message: {}", e, e);
      return null;
    }
  }

  /**
   * Constructs a new, locally originated message with a default priority.
   *
   * @param spec message type descriptor; must not be {@code null}
   */
  public Message(MessageType spec) {
    this(spec, null, 0);
  }

  private Message(MessageType spec, MessageSource source, int recvByteCount) {
    localInstantiationTime = System.currentTimeMillis();
    this.spec = spec;
    if (source == null) {
      internal = true;
      sourceRef = null;
    } else {
      internal = false;
      sourceRef = source.getWeakRef();
    }
    receivedByteCount = recvByteCount;
    priority = spec.getDefaultPriority();
  }

  /** Drops sub-messages and marks the clone as locally originated. */
  private Message(Message m) {
    spec = m.spec;
    sourceRef = null;
    internal = m.internal;
    payload.putAll(m.payload);
    subMessages = null;
    localInstantiationTime = System.currentTimeMillis();
    receivedByteCount = 0;
    priority = m.priority;
  }

  /**
   * Returns the boolean value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code Boolean}
   */
  public boolean getBoolean(String key) {
    return (Boolean) payload.get(key);
  }

  /**
   * Returns the byte value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code Byte}
   */
  public byte getByte(String key) {
    return (Byte) payload.get(key);
  }

  /**
   * Returns the short value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code Short}
   */
  public short getShort(String key) {
    return (Short) payload.get(key);
  }

  /**
   * Returns the int value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not an {@code Integer}
   */
  public int getInt(String key) {
    return (Integer) payload.get(key);
  }

  /**
   * Returns the long value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code Long}
   */
  public long getLong(String key) {
    return (Long) payload.get(key);
  }

  /**
   * Returns the double value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code Double}
   */
  public double getDouble(String key) {
    return (Double) payload.get(key);
  }

  /**
   * Returns the float value for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code Float}
   */
  public float getFloat(String key) {
    return (Float) payload.get(key);
  }

  /**
   * Returns the {@code double[]} for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code double[]}
   */
  public double[] getDoubleArray(String key) {
    return ((double[]) payload.get(key));
  }

  /**
   * Returns the {@code float[]} for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code float[]}
   */
  public float[] getFloatArray(String key) {
    return (float[]) payload.get(key);
  }

  /**
   * Returns the {@link String} for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return field value
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code String}
   */
  public String getString(String key) {
    return (String) payload.get(key);
  }

  /**
   * Returns the raw object for a payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return the stored value, or {@code null} if the field is not set
   */
  public Object getObject(String key) {
    return payload.get(key);
  }

  /**
   * Returns the bytes from a {@link ShortBuffer} payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @return backing byte array of the {@code ShortBuffer}
   * @throws NullPointerException if the field is not set
   * @throws ClassCastException if the stored value is not a {@code ShortBuffer}
   */
  public byte[] getShortBufferBytes(String key) {
    ShortBuffer buffer = (ShortBuffer) getObject(key);
    return buffer.getData();
  }

  /**
   * Sets a boolean payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param b value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept a boolean for {@code
   *     key}
   */
  public void set(String key, boolean b) {
    set(key, Boolean.valueOf(b));
  }

  /**
   * Sets a byte payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param b value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept a byte for {@code
   *     key}
   */
  public void set(String key, byte b) {
    set(key, Byte.valueOf(b));
  }

  /**
   * Sets a short payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param s value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept a short for {@code
   *     key}
   */
  public void set(String key, short s) {
    set(key, Short.valueOf(s));
  }

  /**
   * Sets an int payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param i value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept an int for {@code
   *     key}
   */
  public void set(String key, int i) {
    set(key, Integer.valueOf(i));
  }

  /**
   * Sets a long payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param l value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept a long for {@code
   *     key}
   */
  public void set(String key, long l) {
    set(key, Long.valueOf(l));
  }

  /**
   * Sets a double payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param d value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept a double for {@code
   *     key}
   */
  public void set(String key, double d) {
    set(key, Double.valueOf(d));
  }

  /**
   * Sets a float payload field.
   *
   * @param key field name defined by the {@link MessageType}
   * @param f value to store
   * @throws IncorrectTypeException if the {@code MessageType} does not accept a float for {@code
   *     key}
   */
  public void set(String key, float f) {
    set(key, Float.valueOf(f));
  }

  /**
   * Sets a payload field to an arbitrary object after type checking.
   *
   * <p>The value must be non‑{@code null} and accepted by {@link MessageType#checkType(String,
   * Object)} for the supplied field name.
   *
   * @param key field name defined by the {@link MessageType}
   * @param value non‑{@code null} value to store
   * @throws IncorrectTypeException if {@code value} is {@code null} or not allowed for {@code key}
   */
  public void set(String key, Object value) {
    if (!spec.checkType(key, value)) {
      if (value == null) {
        throw new IncorrectTypeException("Got null for " + key);
      }
      throw new IncorrectTypeException(
          "Got " + value.getClass() + ", expected " + spec.typeOf(key));
    }
    payload.put(key, value);
  }

  /**
   * Encodes this message to its wire representation.
   *
   * <p>The returned array contains the message header, ordered fields, and (when present) any
   * sub‑messages. Encoding does not mutate this instance.
   *
   * @return a new byte array containing the encoded message
   * @throws IllegalStateException if an I/O error occurs while writing to the in‑memory buffer
   */
  public byte[] encodeToPacket() {
    return encodeToPacket(true);
  }

  private byte[] encodeToPacket(boolean includeSubMessages) {

    if (LOG.isTraceEnabled())
      LOG.trace(
          "event=encode-spec-id message type id hash: {} for {}",
          spec.getName().hashCode(),
          spec.getName());
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    try {
      dos.writeInt(spec.getName().hashCode());
      for (String name : spec.getOrderedFields()) {
        Serializer.writeToDataOutputStream(payload.get(name), dos);
      }
      dos.flush();
    } catch (IOException e) {
      throw new IllegalStateException(
          "Failed to encode message header/fields for " + spec.getName(), e);
    }

    if (subMessages != null && includeSubMessages) {
      for (Message _subMessage : subMessages) {
        byte[] temp = _subMessage.encodeToPacket(false);
        try {
          dos.writeShort(temp.length);
          dos.write(temp);
        } catch (IOException e) {
          throw new IllegalStateException("Failed to encode sub-message for " + spec.getName(), e);
        }
      }
    }

    byte[] buf = baos.toByteArray();
    if (LOG.isTraceEnabled())
      LOG.trace("event=encode-complete length: {}, hash: {}", buf.length, Fields.hashCode(buf));
    return buf;
  }

  @Override
  public String toString() {
    StringBuilder ret = new StringBuilder(1000);
    String comma = "";
    ret.append(spec.getName()).append(" {");
    for (String name : spec.getFields().keySet()) {
      ret.append(comma);
      ret.append(name).append('=').append(payload.get(name));
      comma = ", ";
    }
    ret.append('}');
    return ret.toString();
  }

  /**
   * Returns the originating peer context, if still available.
   *
   * <p>For locally constructed messages this is {@code null}. For decoded messages a weak reference
   * is held to the peer context and may have been cleared by the GC.
   *
   * @return {@code null} for local messages, or a possibly {@code null} {@link MessageSource}
   */
  public MessageSource getSource() {
    return sourceRef == null ? null : sourceRef.get();
  }

  /**
   * Indicates whether this message originated locally.
   *
   * @return {@code true} when constructed locally; {@code false} when decoded from the wire
   */
  public boolean isInternal() {
    return internal;
  }

  /**
   * Returns the type descriptor for this message.
   *
   * @return the {@link MessageType} associated with this message
   */
  public MessageType getSpec() {
    return spec;
  }

  /**
   * Returns whether a payload field has been set.
   *
   * @param fieldName field name defined by the {@link MessageType}
   * @return {@code true} if the field exists in the payload map
   */
  public boolean isSet(String fieldName) {
    return payload.containsKey(fieldName);
  }

  /**
   * Retrieves a non‑{@code null} payload value by name.
   *
   * @param fieldName field name defined by the {@link MessageType}
   * @return the stored value
   * @throws FieldNotSetException if the field has not been set
   */
  public Object getFromPayload(String fieldName) throws FieldNotSetException {
    Object r = payload.get(fieldName);
    if (r == null) {
      throw new FieldNotSetException(fieldName + " not set");
    }
    return r;
  }

  public static class FieldNotSetException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

    /**
     * Creates an exception indicating that a required field was not present in the payload.
     *
     * @param message detail message
     */
    public FieldNotSetException(String message) {
      super(message);
    }
  }

  /**
   * Sets the standard fields used when routing to a specific node.
   *
   * <p>This is a convenience for populating {@link DMT#UID}, {@link DMT#TARGET_LOCATION}, {@link
   * DMT#HTL}, and {@link DMT#NODE_IDENTITY}.
   *
   * @param uid unique identifier for the routed request
   * @param targetLocation target location value used by the routing algorithm
   * @param htl routing HTL value
   * @param nodeIdentity node identity bytes; copied into a {@link ShortBuffer}
   */
  public void setRoutedToNodeFields(
      long uid, double targetLocation, short htl, byte[] nodeIdentity) {
    set(DMT.UID, uid);
    set(DMT.TARGET_LOCATION, targetLocation);
    set(DMT.HTL, htl);
    set(DMT.NODE_IDENTITY, new ShortBuffer(nodeIdentity));
  }

  /**
   * Returns the number of bytes attributed to receiving this message.
   *
   * <p>For decoded messages this includes the decoded payload length plus any extra overhead value
   * supplied to the decoder. For locally created messages this is {@code 0}.
   *
   * @return attributed byte count for statistics and accounting
   */
  public int receivedByteCount() {
    return receivedByteCount;
  }

  /**
   * Appends a sub‑message to this message.
   *
   * @param subMessage message to attach; not copied
   */
  public void addSubMessage(Message subMessage) {
    if (subMessages == null) subMessages = new ArrayList<>();
    subMessages.add(subMessage);
  }

  /**
   * Returns the first attached sub‑message of the given type, if present.
   *
   * @param t message type to match
   * @return a sub‑message, or {@code null} if none matches
   */
  public Message getSubMessage(MessageType t) {
    if (subMessages == null) return null;
    for (Message m : subMessages) {
      if (t.equals(m.getSpec())) return m;
    }
    return null;
  }

  /**
   * Removes and returns the first attached sub‑message of the given type.
   *
   * @param t message type to match
   * @return the removed sub‑message, or {@code null} if none matches
   */
  public Message grabSubMessage(MessageType t) {
    if (subMessages == null) return null;
    for (int i = 0; i < subMessages.size(); i++) {
      Message m = subMessages.get(i);
      if (t.equals(m.getSpec())) {
        subMessages.remove(i);
        return m;
      }
    }
    return null;
  }

  /**
   * Returns the age of this message in milliseconds since local instantiation.
   *
   * @return elapsed time in milliseconds
   */
  public long age() {
    return System.currentTimeMillis() - localInstantiationTime;
  }

  /**
   * Returns the current scheduling priority value.
   *
   * @return implementation‑defined priority
   */
  public short getPriority() {
    return priority;
  }

  /**
   * Adjusts the internal priority to favor earlier handling.
   *
   * <p>The exact scale and ordering are implementation‑defined.
   */
  public void boostPriority() {
    priority--;
  }

  /**
   * Creates a shallow copy without sub‑messages and with a local origin.
   *
   * <p>Payload entries and priority are copied; sub‑messages are dropped, and the source reference
   * is cleared.
   *
   * @return a new {@code Message} with no sub‑messages
   */
  public Message cloneAndDropSubMessages() {
    return new Message(this);
  }
}
