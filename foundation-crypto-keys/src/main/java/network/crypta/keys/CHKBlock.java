package network.crypta.keys;

import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.SHA256;
import network.crypta.support.Fields;

/**
 * Content Hash Key (CHK) block holding raw headers and data.
 *
 * <p>A CHK block pairs an immutable header section with a fixed-size data section. The routing key
 * used by the network is the SHA-256 digest of {@code headers || data}. Constructors either compute
 * the routing key from the provided bytes or verify it against a supplied {@link NodeCHK}. The
 * header format is implementation-defined; only the first two bytes are interpreted here to carry a
 * hash identifier. At present, only SHA-256 is accepted.
 *
 * <p>Instances are logically immutable; however, accessors return the backing byte arrays without
 * copying for performance. Callers must treat the returned arrays as read-only and never modify
 * them. Mutating the arrays will break equality, hashing, and integrity verification assumptions.
 *
 * @author amphibian
 */
public final class CHKBlock implements KeyBlock {

  // Backing arrays; returned by accessors without defensive copies. Treat as read-only.
  final byte[] data;
  final byte[] headers;

  // Parsed from the first two header bytes. Only HASH_SHA256 is considered valid.
  final short hashIdentifier;

  // Computed or verified content key derived from SHA-256(headers || data).
  final NodeCHK chk;

  // Precomputed structural hash for this object (not to be confused with the routing key).
  final int hashCode;

  /**
   * Upper bound for the uncompressed content length prior to any optional compression stage. Units:
   * bytes.
   */
  public static final int MAX_LENGTH_BEFORE_COMPRESSION = Integer.MAX_VALUE;

  /** Total header size in bytes expected by this implementation. */
  public static final int TOTAL_HEADERS_LENGTH = 36;

  /** Fixed payload size in bytes for the data section. */
  public static final int DATA_LENGTH = 32768;

  /**
   * Maximum number of bytes available to a compressed payload within {@link #DATA_LENGTH}.
   *
   * <p>Leaves 4 bytes for per-block framing/metadata used by readers and writers.
   */
  public static final int MAX_COMPRESSED_DATA_LENGTH = DATA_LENGTH - 4;

  /**
   * Returns a diagnostic string containing the object identity and the derived key.
   *
   * @return a concise representation including {@code chk}.
   */
  @Override
  public String toString() {
    return super.toString() + ": chk=" + chk;
  }

  /**
   * Returns the raw header bytes.
   *
   * <p>The returned array is the internal backing storage; callers must treat it as read-only.
   *
   * @return header bytes of length {@link #TOTAL_HEADERS_LENGTH}.
   */
  public byte[] getHeaders() {
    return headers;
  }

  /**
   * Returns the raw data bytes.
   *
   * <p>The returned array is the internal backing storage; callers must treat it as read-only.
   *
   * @return data bytes of length {@link #DATA_LENGTH}.
   */
  public byte[] getData() {
    return data;
  }

  /**
   * Builds a {@code CHKBlock} from raw components and computes/validates the routing key.
   *
   * <p>This convenience method behaves like {@link #CHKBlock(byte[], byte[], NodeCHK, boolean,
   * byte)} with {@code key == null} and {@code verify == true}.
   *
   * @param data payload bytes of length {@link #DATA_LENGTH}.
   * @param header header bytes of length {@link #TOTAL_HEADERS_LENGTH}.
   * @param cryptoAlgorithm crypto algorithm identifier associated with the resulting {@link
   *     NodeCHK}.
   * @return a verified block whose routing key is {@code SHA-256(header || data)}.
   * @throws CHKVerifyException if the header hash identifier is unsupported or verification fails.
   */
  public static CHKBlock construct(byte[] data, byte[] header, byte cryptoAlgorithm)
      throws CHKVerifyException {
    return new CHKBlock(data, header, null, true, cryptoAlgorithm);
  }

  /**
   * Creates a block and verifies the content against the supplied key.
   *
   * <p>Verification recomputes the SHA-256 digest of {@code headers || data} and compares it with
   * {@code key.getRoutingKey()}.
   *
   * @param data2 payload bytes of length {@link #DATA_LENGTH}.
   * @param header2 header bytes of length {@link #TOTAL_HEADERS_LENGTH}.
   * @param key expected content key; must not be {@code null}.
   * @throws CHKVerifyException if the header hash identifier is unsupported or the digest
   *     mismatches the supplied key.
   */
  public CHKBlock(byte[] data2, byte[] header2, NodeCHK key) throws CHKVerifyException {
    this(data2, header2, key, key.cryptoAlgorithm);
  }

  /**
   * Creates a block and verifies content using the given key and algorithm.
   *
   * @param data2 payload bytes of length {@link #DATA_LENGTH}.
   * @param header2 header bytes of length {@link #TOTAL_HEADERS_LENGTH}.
   * @param key expected content key; must not be {@code null}.
   * @param cryptoAlgorithm crypto algorithm identifier to associate with the block.
   * @throws CHKVerifyException if the header hash identifier is unsupported or the digest
   *     mismatches the supplied key.
   */
  public CHKBlock(byte[] data2, byte[] header2, NodeCHK key, byte cryptoAlgorithm)
      throws CHKVerifyException {
    this(data2, header2, key, true, cryptoAlgorithm);
  }

  /**
   * Creates a block, optionally skipping digest verification when a key is provided.
   *
   * <p>When {@code key == null}, the constructor computes the routing key from the bytes and stores
   * it in the resulting {@link NodeCHK}. When {@code key != null} and {@code verify == true}, the
   * constructor recomputes the digest and compares it to {@code key}. When {@code key != null} and
   * {@code verify == false}, no digest is computed and the supplied key is trusted as-is.
   *
   * @param data2 payload bytes of length {@link #DATA_LENGTH}.
   * @param header2 header bytes of length {@link #TOTAL_HEADERS_LENGTH}.
   * @param key optional content key; may be {@code null}.
   * @param verify whether to recompute and validate the digest when {@code key != null}.
   * @param cryptoAlgorithm crypto algorithm identifier to associate with the block.
   * @throws CHKVerifyException if verification is requested and fails, or if the header indicates
   *     an unsupported hash.
   * @throws IllegalArgumentException if {@code header2.length != TOTAL_HEADERS_LENGTH}.
   */
  public CHKBlock(byte[] data2, byte[] header2, NodeCHK key, boolean verify, byte cryptoAlgorithm)
      throws CHKVerifyException {
    data = data2;
    headers = header2;
    if (headers.length != TOTAL_HEADERS_LENGTH)
      throw new IllegalArgumentException(
          "Wrong length: " + headers.length + " should be " + TOTAL_HEADERS_LENGTH);
    hashIdentifier = (short) (((headers[0] & 0xff) << 8) + (headers[1] & 0xff));
    // Header ID parsed above; minimal verification and hashing follow.
    if ((key != null) && !verify) {
      this.chk = key;
      hashCode =
          key.hashCode() ^ Fields.hashCode(data) ^ Fields.hashCode(headers) ^ cryptoAlgorithm;
      return;
    }

    // Minimal verification: accept only SHA-256 and verify digest when required.
    if (hashIdentifier != HASH_SHA256) throw new CHKVerifyException("Hash not SHA-256");
    MessageDigest md = SHA256.getMessageDigest();

    md.update(headers);
    md.update(data);
    byte[] hash = md.digest();
    if (key == null) {
      chk = new NodeCHK(hash, cryptoAlgorithm);
    } else {
      chk = key;
      byte[] check = chk.routingKey;
      if (!Arrays.equals(hash, check)) {
        throw new CHKVerifyException("Hash does not verify");
      }
      // Otherwise the content verifies against the supplied key.
    }
    hashCode = chk.hashCode() ^ Fields.hashCode(data) ^ Fields.hashCode(headers) ^ cryptoAlgorithm;
  }

  /**
   * Returns the derived content key for this block.
   *
   * @return non-null {@link NodeCHK} representing the routing key and algorithm.
   */
  @Override
  public NodeCHK getKey() {
    return chk;
  }

  /**
   * Returns the header bytes as stored, without defensive copying.
   *
   * @return the backing header array; treat as read-only.
   */
  @Override
  public byte[] getRawHeaders() {
    return headers;
  }

  /**
   * Returns the data bytes as stored, without defensive copying.
   *
   * @return the backing data array; treat as read-only.
   */
  @Override
  public byte[] getRawData() {
    return data;
  }

  /**
   * Returns public-key material if present.
   *
   * <p>CHK blocks do not contain public keys; this method always returns {@code null}.
   *
   * @return {@code null} for CHK blocks.
   */
  @Override
  @SuppressWarnings("java:S1168")
  public byte[] getPubkeyBytes() {
    return null;
  }

  /**
   * Returns the serialized full key as defined by {@link NodeCHK}.
   *
   * @return byte array containing the algorithm identifier and routing key.
   */
  @Override
  public byte[] getFullKey() {
    return getKey().getFullKey();
  }

  /**
   * Returns the routing key used for lookup and storage.
   *
   * @return SHA-256 digest of {@code headers || data}.
   */
  @Override
  public byte[] getRoutingKey() {
    return getKey().getRoutingKey();
  }

  /** Returns a hash code consistent with {@link #equals(Object)}. */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Compares this block with another for structural equality.
   *
   * <p>Two blocks are equal when their derived keys, header bytes, data bytes, and parsed hash
   * identifiers are all equal.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof CHKBlock block)) return false;
    if (!chk.equals(block.chk)) return false;
    if (!Arrays.equals(data, block.data)) return false;
    if (!Arrays.equals(headers, block.headers)) return false;
    return hashIdentifier == block.hashIdentifier;
  }
}
