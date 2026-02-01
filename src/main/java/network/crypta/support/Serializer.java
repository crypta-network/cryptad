package network.crypta.support;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import network.crypta.io.WritableToDataOutputStream;
import network.crypta.io.comm.Peer;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NewPacketFormat;

/**
 * Utility for serializing and deserializing a constrained set of value types to and from {@link
 * java.io.DataInput} / {@link java.io.DataOutputStream}.
 *
 * <p>This class supports a small, explicit set of types used by the networking and messaging code:
 * boxed primitives ({@link Boolean}, {@link Byte}, {@link Short}, {@link Integer}, {@link Long},
 * {@link Float}, {@link Double}), {@link String}, {@link List}, {@code double[]} and {@code
 * float[]}, several support types ({@link Buffer}, {@link ShortBuffer}, {@link Peer}, {@link
 * BitArray}), and selected key types ({@link NodeCHK}, {@link NodeSSK}, and {@link Key}).
 *
 * <p>Strings are encoded as a 32-bit length followed by that many 16-bit Java {@code char}s written
 * via {@link java.io.DataOutputStream#writeChar(int)} (i.e., not modified UTF-8 and not {@link
 * java.io.DataOutputStream#writeUTF(String)}). Booleans are encoded strictly as a single byte with
 * value {@code 0} (false) or {@code 1} (true); other values are rejected at read time. Arrays use a
 * compact length prefix: one unsigned byte for {@code double[]} (max 255 elements) and a 16-bit
 * signed short for {@code float[]}.
 *
 * <p>The class is stateless and thread-safe. All methods are static; instantiation is prevented.
 */
public class Serializer {
  private Serializer() {
    throw new IllegalStateException("Utility class");
  }

  /** Historical SCM identifier (kept for traceability). */
  public static final String VERSION =
      "$Id: Serializer.java,v 1.5 2005/09/15 18:16:04 amphibian Exp $";

  /**
   * Upper bound, in bits, used when deserializing {@link BitArray} to prevent pathological
   * allocations.
   */
  public static final int MAX_BITARRAY_SIZE = 2048 * 8;

  /**
   * Maximum allowed inbound variable-length payload, in bytes.
   *
   * <p>The limit equals {@link NewPacketFormat#MAX_MESSAGE_SIZE} minus four bytes to account for a
   * leading length integer in the wire format.
   */
  // Max packet format size – 4 to account for starting size integer.
  public static final int MAX_ARRAY_LENGTH = NewPacketFormat.MAX_MESSAGE_SIZE - 4;

  /**
   * Reads a {@link List} whose elements are of {@code elementType} from the given {@link
   * DataInput}.
   *
   * <p>The on-wire representation is a 32-bit element count followed by that many element values,
   * each encoded using {@link #readFromDataInputStream(Class, DataInput)} with the supplied {@code
   * elementType}. The method does not enforce an explicit upper bound on the element count; callers
   * must ensure the producer is trusted or that inputs are reasonably bounded.
   *
   * @param elementType the expected element type. Must be one of the types recognized by {@link
   *     #readFromDataInputStream(Class, DataInput)}.
   * @param dis the input to read from; not closed by this method.
   * @return a new {@link List} containing the decoded elements in order.
   * @throws IOException if an I/O error occurs or an element payload is invalid for the declared
   *     type.
   * @throws IllegalArgumentException if {@code elementType} is unsupported.
   * @see #readFromDataInputStream(Class, DataInput)
   * @see #writeToDataOutputStream(Object, DataOutputStream)
   */
  public static List<Object> readListFromDataInputStream(Class<?> elementType, DataInput dis)
      throws IOException {
    int length = dis.readInt();
    List<Object> ret = new ArrayList<>(Math.max(0, length));
    for (int x = 0; x < length; x++) {
      ret.add(readFromDataInputStream(elementType, dis));
    }
    return ret;
  }

  /**
   * Reads a single value of the requested {@code type} from a {@link DataInput}.
   *
   * <p>Supported types include boxed primitives ({@link Boolean}, {@link Byte}, {@link Short},
   * {@link Integer}, {@link Long}, {@link Float}, {@link Double}); {@link String}; support types
   * ({@link Buffer}, {@link ShortBuffer}, {@link Peer}, {@link BitArray}); selected keys ({@link
   * NodeCHK}, {@link NodeSSK}, {@link Key}); {@code double[]} and {@code float[]}.
   *
   * <p>Booleans are read in a strict form via a single byte: {@code 0} or {@code 1}. Strings are
   * read as a 32-bit length (bounded by {@link #MAX_ARRAY_LENGTH}) plus that many 16-bit
   * characters.
   *
   * @param type the class indicating the type to read. Must be one of the supported types listed
   *     above.
   * @param dis the input to read from; not closed by this method.
   * @return the decoded value; never {@code null}.
   * @throws IOException if an I/O error occurs or the next value is malformed for the requested
   *     type (for example, a boolean byte not equal to {@code 0} or {@code 1}, an invalid string
   *     length, or an oversized array).
   * @throws IllegalArgumentException if {@code type} is unsupported.
   */
  public static Object readFromDataInputStream(Class<?> type, DataInput dis) throws IOException {
    if (type.equals(Boolean.class)) {
      return readStrictBoolean(dis);
    }

    if (isNumericBoxed(type)) {
      return readNumeric(type, dis);
    }

    if (type.equals(String.class)) {
      return readStringWithBounds(dis);
    }

    if (isSpecializedSupportType(type)) {
      return readSpecializedSupportType(type, dis);
    }

    if (isKeyType(type)) {
      // Use Key.read(...) rather than type-specific methods because write(...) writes the TYPE
      // field.
      return Key.read(dis);
    }

    if (type.equals(double[].class)) {
      return readDoubleArray(dis);
    }

    if (type.equals(float[].class)) {
      return readFloatArray(dis);
    }

    throw new IllegalArgumentException("Unrecognised field type: " + type);
  }

  private static Object readStrictBoolean(DataInput dis) throws IOException {
    final byte bool = dis.readByte();
    // Read a single byte, not {@code readBoolean()}, to reject non-0/1 values.
    return switch (bool) {
      case 1 -> Boolean.TRUE;
      case 0 -> Boolean.FALSE;
      default -> throw new IOException("Boolean is non boolean value: " + bool);
    };
  }

  private static boolean isNumericBoxed(Class<?> type) {
    return type.equals(Byte.class)
        || type.equals(Short.class)
        || type.equals(Integer.class)
        || type.equals(Long.class)
        || type.equals(Double.class)
        || type.equals(Float.class);
  }

  private static Object readNumeric(Class<?> type, DataInput dis) throws IOException {
    if (type.equals(Byte.class)) {
      return dis.readByte();
    }
    if (type.equals(Short.class)) {
      return dis.readShort();
    }
    if (type.equals(Integer.class)) {
      return dis.readInt();
    }
    if (type.equals(Long.class)) {
      return dis.readLong();
    }
    if (type.equals(Double.class)) {
      return dis.readDouble();
    }
    // Float.class
    return dis.readFloat();
  }

  private static String readStringWithBounds(DataInput dis) throws IOException {
    final int length = dis.readInt();
    // Limit length to MAX_ARRAY_LENGTH to avoid unreasonable or malicious sizes. Total byte
    // accounting is left to callers because structures around the string are fixed-size.
    if (length < 0 || length > MAX_ARRAY_LENGTH) {
      throw new IOException("Invalid string length: " + length);
    }
    StringBuilder sb = new StringBuilder(length);
    for (int x = 0; x < length; x++) {
      sb.append(dis.readChar());
    }
    return sb.toString();
  }

  private static boolean isSpecializedSupportType(Class<?> type) {
    return type.equals(Buffer.class)
        || type.equals(ShortBuffer.class)
        || type.equals(Peer.class)
        || type.equals(BitArray.class);
  }

  private static Object readSpecializedSupportType(Class<?> type, DataInput dis)
      throws IOException {
    if (type.equals(Buffer.class)) {
      return new Buffer(dis);
    }
    if (type.equals(ShortBuffer.class)) {
      return new ShortBuffer(dis);
    }
    if (type.equals(Peer.class)) {
      return new Peer(dis);
    }
    // BitArray.class
    return new BitArray(dis, MAX_BITARRAY_SIZE);
  }

  private static boolean isKeyType(Class<?> type) {
    return type.equals(NodeCHK.class) || type.equals(NodeSSK.class) || type.equals(Key.class);
  }

  private static double[] readDoubleArray(DataInput dis) throws IOException {
    // Length is stored in one unsigned byte; mask to avoid sign extension.
    double[] array = new double[dis.readByte() & 0xFF];
    for (int i = 0; i < array.length; i++) array[i] = dis.readDouble();
    return array;
  }

  private static float[] readFloatArray(DataInput dis) throws IOException {
    final short length = dis.readShort();
    // Bound by max allowed bytes; each float is 4 bytes.
    if (length < 0 || length > MAX_ARRAY_LENGTH / 4) {
      throw new IOException("Invalid flat array length: " + length);
    }
    float[] array = new float[length];
    for (int i = 0; i < array.length; i++) array[i] = dis.readFloat();
    return array;
  }

  /**
   * Writes a single supported value to a {@link DataOutputStream} using the format recognized by
   * {@link #readFromDataInputStream(Class, DataInput)}.
   *
   * <p>The {@code object} must be non-{@code null} and of a supported type. For lists, see {@link
   * #writeList(List, DataOutputStream)} for details. Strings are written as a 32-bit length
   * followed by UTF-16 {@code char}s via {@link DataOutputStream#writeChar(int)}.
   *
   * @param object the value to serialize; must be non-{@code null}.
   * @param dos the destination stream; not closed by this method.
   * @throws IOException if an I/O error occurs during writing.
   * @throws IllegalArgumentException if {@code object} has an unsupported type or violates a format
   *     constraint (for example, a {@code double[]} longer than 255 elements).
   */
  public static void writeToDataOutputStream(Object object, DataOutputStream dos)
      throws IOException {
    Class<?> type = object.getClass();

    if (isScalarBoxed(type)) {
      writeScalar(object, dos);
      return;
    }

    if (WritableToDataOutputStream.class.isAssignableFrom(type)) {
      ((WritableToDataOutputStream) object).writeToDataOutputStream(dos);
      return;
    }

    if (type.equals(String.class)) {
      writeString((String) object, dos);
      return;
    }

    if (object instanceof List<?> list) {
      writeList(list, dos);
      return;
    }

    if (type.equals(double[].class)) {
      writeDoubleArray((double[]) object, dos);
      return;
    }

    if (type.equals(float[].class)) {
      writeFloatArray((float[]) object, dos);
      return;
    }

    throw new IllegalArgumentException("Unrecognised field type: " + type);
  }

  private static boolean isScalarBoxed(Class<?> type) {
    return type.equals(Long.class)
        || type.equals(Boolean.class)
        || type.equals(Integer.class)
        || type.equals(Short.class)
        || type.equals(Double.class)
        || type.equals(Float.class)
        || type.equals(Byte.class);
  }

  private static void writeScalar(Object object, DataOutputStream dos) throws IOException {
    Class<?> type = object.getClass();
    if (type.equals(Long.class)) {
      dos.writeLong((Long) object);
      return;
    }
    if (type.equals(Boolean.class)) {
      dos.writeBoolean((Boolean) object);
      return;
    }
    if (type.equals(Integer.class)) {
      dos.writeInt((Integer) object);
      return;
    }
    if (type.equals(Short.class)) {
      dos.writeShort((Short) object);
      return;
    }
    if (type.equals(Double.class)) {
      dos.writeDouble((Double) object);
      return;
    }
    if (type.equals(Float.class)) {
      dos.writeFloat((Float) object);
      return;
    }
    // Byte.class
    dos.write((Byte) object);
  }

  private static void writeString(String s, DataOutputStream dos) throws IOException {
    dos.writeInt(s.length());
    for (int x = 0; x < s.length(); x++) {
      dos.writeChar(s.charAt(x));
    }
  }

  /**
   * Serializes a {@link List} using a snapshot-and-write strategy to avoid concurrent modification
   * races.
   *
   * <p>First, the method takes a stable snapshot of the list under synchronization on the list
   * instance itself; then it releases the lock and writes the snapshot to the stream. Synchronizing
   * on the list coordinates with callers that already use {@code synchronized(list)} during
   * mutation and avoids {@link java.util.ConcurrentModificationException} and length/content
   * mismatches while iterating.
   *
   * @param list the list to serialize; elements must be of a type supported by {@link
   *     #writeToDataOutputStream(Object, DataOutputStream)}.
   * @param dos the destination stream; not closed by this method.
   * @throws IOException if an I/O error occurs while writing an element.
   */
  @SuppressWarnings({"java:S2445", "SynchronizationOnLocalVariableOrMethodParameter"})
  private static void writeList(final List<?> list, DataOutputStream dos) throws IOException {
    // Intentionally lock on the list instance so external synchronization on the same
    // object also applies. Snapshot under lock; perform I/O after releasing it to
    // minimize contention.
    final Object[] snapshot;
    synchronized (list) {
      snapshot = list.toArray();
    }
    dos.writeInt(snapshot.length);
    for (Object o : snapshot) {
      writeToDataOutputStream(o, dos);
    }
  }

  private static void writeDoubleArray(double[] array, DataOutputStream dos) throws IOException {
    // {@code writeByte} keeps the lower 8 bits; cap length to 255 elements.
    if (array.length > 255) {
      throw new IllegalArgumentException(
          "Cannot serialize an array of more than 255 doubles; attempted to "
              + "serialize "
              + array.length
              + ".");
    }
    dos.writeByte(array.length);
    for (double element : array) dos.writeDouble(element);
  }

  private static void writeFloatArray(float[] array, DataOutputStream dos) throws IOException {
    dos.writeShort(array.length);
    for (float element : array) dos.writeFloat(element);
  }

  /**
   * Returns the serialized size, in bytes, for fixed-size simple values.
   *
   * <p>For {@link String}, the result is an upper bound computed as {@code 4 + 2 * maxStringLength}
   * (a 32-bit length plus two bytes per character). For types implementing {@link
   * WritableToDataOutputStream} and for {@link List}, the size is unknown and this method throws
   * {@link IllegalArgumentException}.
   *
   * @param type the type to measure.
   * @param maxStringLength maximum characters to assume for strings when computing an upper bound.
   * @return the exact byte size for fixed-size types or an upper bound for strings.
   * @throws IllegalArgumentException if the type is unsupported or variable-length.
   */
  public static int length(Class<?> type, int maxStringLength) {
    if (type.equals(Long.class)) {
      return 8;
    } else if (type.equals(Boolean.class)) {
      return 1;
    } else if (type.equals(Integer.class)) {
      return 4;
    } else if (type.equals(Short.class)) {
      return 2;
    } else if (type.equals(Double.class)) {
      return 8;
    } else if (WritableToDataOutputStream.class.isAssignableFrom(type)) {
      throw new IllegalArgumentException("Unknown length for " + type);
    } else if (type.equals(String.class)) {
      return 4 + maxStringLength * 2; // Written as chars
    } else if (List.class.isAssignableFrom(type)) {
      throw new IllegalArgumentException("Unknown length for List");
    } else if (type.equals(Byte.class)) {
      return 1;
    } else {
      throw new IllegalArgumentException("Unrecognised field type: " + type);
    }
  }
}
