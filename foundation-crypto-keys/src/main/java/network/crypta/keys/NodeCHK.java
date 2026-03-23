package network.crypta.keys;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.support.Base64;
import network.crypta.support.Fields;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Node-level Content Hash Key (CHK) used for routing and integrity verification.
 *
 * <p>This type carries only the 32-byte routing key (hash-derived) and a crypto algorithm
 * identifier. It does not include any decryption material and therefore cannot decode the payload;
 * it can only address the block and validate integrity via the routing key.
 *
 * <p>Binary form written by {@link #write(java.io.DataOutput)} and returned by {@link
 * #getFullKey()} is 34 bytes: a 2-byte packed type ({@link #getType()} — base type in the high 8
 * bits, algorithm in the low 8 bits) followed by the 32-byte routing key.
 *
 * <p>Instances are immutable and thread-safe.
 *
 * @author amphibian
 */
public final class NodeCHK extends Key {
  private static final Logger LOG = LoggerFactory.getLogger(NodeCHK.class);
  // Holder used to return a null reference without an explicit literal.
  private static final byte[][] NULL_ARRAY_HOLDER = new byte[1][];

  /**
   * Total length of the serialized "full key" in bytes.
   *
   * <p>Layout: {@code 2} bytes type header + {@value #KEY_LENGTH} bytes routing key = {@code 34}.
   */
  public static final short FULL_KEY_LENGTH = 34;

  /**
   * Construct a CHK from a routing key and algorithm identifier.
   *
   * @param routingKey2 32-byte routing key. Must be exactly {@link #KEY_LENGTH} bytes.
   * @param cryptoAlgorithm crypto algorithm identifier (low 8 bits of {@link #getType()}); values
   *     are defined in {@link Key}.
   * @throws IllegalArgumentException if {@code routingKey2.length != KEY_LENGTH}.
   */
  public NodeCHK(byte[] routingKey2, byte cryptoAlgorithm) {
    super(routingKey2);
    if (routingKey2.length != KEY_LENGTH)
      throw new IllegalArgumentException(
          "Wrong length: " + routingKey2.length + " should be " + KEY_LENGTH);
    this.cryptoAlgorithm = cryptoAlgorithm;
  }

  private NodeCHK(NodeCHK key) {
    super(key);
    this.cryptoAlgorithm = key.cryptoAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public Key cloneKey() {
    return new NodeCHK(this);
  }

  public static final int KEY_LENGTH = 32;

  // Crypto algorithm (low 8 bits of type); package-private by design.
  final byte cryptoAlgorithm;

  /** Base type tag written in the high 8 bits of {@link #getType()}. */
  public static final byte BASE_TYPE = 1;

  /**
   * Write this key to a {@link DataOutputStream} using the compact binary format.
   *
   * <p>Equivalent to {@link #write(java.io.DataOutput)}; this method exists for callers that have a
   * {@code DataOutputStream} at hand.
   *
   * @param stream destination; not closed by this method.
   * @throws IOException if writing fails.
   */
  @Override
  public final void writeToDataOutputStream(DataOutputStream stream) throws IOException {
    write(stream);
  }

  /**
   * Return a human-readable representation including the Base64 routing key and hash in hex.
   *
   * <p>Format suffix: {@code "@" + Base64(routingKey) + ":" + Integer.toHexString(hash)} appended
   * to the default {@code Object.toString()} prefix.
   */
  @Override
  public String toString() {
    return super.toString() + '@' + Base64.encode(routingKey) + ':' + Integer.toHexString(hash);
  }

  /**
   * Write the packed type header and routing key to the given {@link DataOutput}.
   *
   * <p>Layout:
   *
   * <ul>
   *   <li>2 bytes: {@link #getType()} — base type in high 8 bits, algorithm in low 8 bits
   *   <li>32 bytes: routing key
   * </ul>
   *
   * @param out destination to write to; not closed.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public final void write(DataOutput out) throws IOException {
    out.writeShort(getType());
    out.write(routingKey);
  }

  /**
   * Read a CHK whose header has already been consumed.
   *
   * <p>Called by {@link Key#read(DataInput)} after it reads the 2-byte type header and selects the
   * concrete key reader. This method consumes exactly {@link #KEY_LENGTH} bytes and constructs a
   * {@code NodeCHK} with the provided algorithm.
   *
   * @param raf input positioned at the first routing-key byte.
   * @param algo algorithm identifier (low 8 bits of type) previously parsed by the caller.
   * @return a new {@code NodeCHK} instance.
   * @throws IOException if the input is truncated.
   */
  public static Key readCHK(DataInput raf, byte algo) throws IOException {
    byte[] buf = new byte[KEY_LENGTH];
    raf.readFully(buf);
    return new NodeCHK(buf, algo);
  }

  /** Equality is based on routing key bytes and crypto algorithm. */
  @Override
  public boolean equals(Object key) {
    if (key == this) return true;
    if (key instanceof NodeCHK chk) {
      return Arrays.equals(chk.routingKey, routingKey) && (cryptoAlgorithm == chk.cryptoAlgorithm);
    }
    return false;
  }

  /** Consistent with {@link #equals(Object)}. */
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /** Return the packed key type: base type in the high 8 bits and algorithm in the low 8 bits. */
  @Override
  public short getType() {
    return (short) ((BASE_TYPE << 8) + (cryptoAlgorithm & 0xFF));
  }

  /**
   * Return the 34-byte full key ({@link #FULL_KEY_LENGTH}) consisting of type and routing key.
   *
   * @return newly allocated array; modifications do not affect this instance.
   */
  @Override
  public byte[] getFullKey() {
    byte[] buf = new byte[FULL_KEY_LENGTH];
    short type = getType();
    buf[0] = (byte) (type >> 8);
    buf[1] = (byte) (type & 0xFF);
    System.arraycopy(routingKey, 0, buf, 2, routingKey.length);
    return buf;
  }

  /**
   * Extract the algorithm identifier (low 8 bits of type) from a full key buffer.
   *
   * <p>Assumes {@code fullKey} contains at least two bytes and follows the format produced by
   * {@link #getFullKey()}.
   */
  public static byte cryptoAlgorithmFromFullKey(byte[] fullKey) {
    return fullKey[1];
  }

  /**
   * Extract the 32-byte routing key from either a routing-key buffer or a full key buffer.
   *
   * <p>Accepted inputs:
   *
   * <ul>
   *   <li>{@link #KEY_LENGTH} (32) bytes: treated as a routing key and returned as-is (same
   *       reference).
   *   <li>{@link #FULL_KEY_LENGTH} (34) bytes: if the header looks valid (base type and a known
   *       algorithm), return the bytes after the 2-byte header; otherwise, return a copy of the
   *       first 32 bytes. The method logs at {@code DEBUG} or {@code ERROR} for diagnostic
   *       purposes.
   * </ul>
   *
   * @param keyBuf routing key or full key buffer.
   * @return the routing key bytes, or {@code null} if {@code keyBuf.length} is not 32 or 34.
   */
  public static byte[] routingKeyFromFullKey(byte[] keyBuf) {
    if (keyBuf.length == KEY_LENGTH) return keyBuf;
    if (keyBuf.length != FULL_KEY_LENGTH) {
      LOG.error("routingKeyFromFullKey() on {} bytes", keyBuf.length);
      return returnNull();
    }
    if (keyBuf[0] != 1
        || (keyBuf[1] != Key.ALGO_AES_PCFB_256_SHA256
            && keyBuf[1] != Key.ALGO_AES_CTR_256_SHA256)) {
      if (keyBuf[keyBuf.length - 1] == 0 && keyBuf[keyBuf.length - 2] == 0) {
        // Clear recovery case: buffer likely contains only a routing key (header not present).
        LOG.debug("Recovering routing-key stored wrong as full-key (two nulls at end)");
      } else {
        // Ambiguous recovery: treat the first 32 bytes as the routing key defensively.
        LOG.error("Maybe recovering routing-key stored wrong as full-key");
      }
      return Arrays.copyOf(keyBuf, KEY_LENGTH);
    }
    return Arrays.copyOfRange(keyBuf, 2, 2 + KEY_LENGTH);
  }

  // Returns a null byte[] using the shared holder; callers must null-check.
  private static byte[] returnNull() {
    return NULL_ARRAY_HOLDER[0];
  }

  /**
   * Compare keys for routing order. CHKs sort after SSKs; CHKs are ordered by routing-key bytes.
   */
  @Override
  public int compareTo(@NotNull Key other) {
    if (other instanceof NodeSSK) return 1;
    NodeCHK otherKey = (NodeCHK) other;
    return Fields.compareBytes(routingKey, otherKey.routingKey);
  }

  /**
   * Return an independent copy suitable for archival storage. Equivalent to {@link #cloneKey()}.
   */
  @Override
  public Key archivalCopy() {
    return new NodeCHK(this);
  }
}
