package network.crypta.crypt;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.support.HexUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds a hash type identifier and its corresponding raw hash bytes.
 *
 * <p>This class is a small value object used when a call needs to transport both the hash algorithm
 * identity and the computed digest. It is intentionally lightweight: it stores the {@link HashType}
 * and the byte array as-is, provides serialization-friendly readers/writers, and orders instances
 * by the hash type bitmask so callers can build stable collections and bitmasks. Typical usage is
 * to read a set of hashes from a stream, compare them to expected values, or write them back in the
 * canonical order.
 *
 * <p>Instances are effectively immutable by convention, but the underlying byte array is stored and
 * returned directly. Callers must treat the bytes as read-only to preserve invariants. Because of
 * that shared storage, concurrent reads are safe only if the array is not mutated elsewhere.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Serialization reads and writes hash bytes without a per-hash length prefix.
 *   <li>{@link #write(HashResult[], DataOutputStream)} sorts the input array in place.
 *   <li>{@link #copy(HashResult[])} performs a shallow copy that shares hash bytes.
 * </ul>
 */
public class HashResult implements Comparable<HashResult>, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(HashResult.class);
  private static final HashResult[] EMPTY_HASHES = new HashResult[0];
  private static final byte[] EMPTY_BYTES = new byte[0];
  private static final String RESULT_MESSAGE = "result";

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Identifies the hash algorithm associated with {@link #result}.
   *
   * <p>This value is treated as a stable identifier for ordering and bitmasking. It should be
   * non-null for normal instances and match the byte length of the stored digest. Consumers rely on
   * it to select the correct hash length and to compare or serialize results deterministically.
   */
  public final HashType type;

  /** The result of the hash. Immutable. */
  private final byte[] result;

  /** Cached HashType.values(). Never modify or pass this array to outside code! */
  private static final HashType[] HashType_values = HashType.values();

  /**
   * Creates a hash result with the provided type and raw digest bytes.
   *
   * <p>The bytes are stored directly without copying. Callers should pass a buffer of exactly
   * {@code hashType.hashLength} bytes and must not mutate the array after construction. This
   * constructor does not perform defensive validation beyond the internal assertion used by the
   * delegated constructor, so misuse can surface later during comparisons or serialization.
   *
   * @param hashType identifies the hash algorithm; expected to be non-null and stable
   * @param bs raw digest bytes; expected length matches {@code hashType.hashLength} and non-null
   */
  public HashResult(HashType hashType, byte[] bs) {
    this(hashType, bs, false);
  }

  /**
   * Creates a copy of the provided {@link HashResult}.
   *
   * <p>This constructor preserves the historical shallow-copy behavior of {@code clone()} by
   * reusing the source byte array. As a result, the new instance shares the underlying bytes with
   * {@code source}. Treat the array as read-only and avoid mutating either instance when used
   * across threads or stored in shared collections.
   *
   * @param source source hash result to copy; expected non-null and fully initialized
   */
  public HashResult(HashResult source) {
    this.type = source.type;
    this.result = source.result;
  }

  /**
   * Creates a hash result with optional validation for unit tests.
   *
   * <p>When {@code testing} is {@code true}, callers may bypass the length assertion; otherwise an
   * assertion checks that {@code bs.length} matches the declared hash length. This constructor is
   * protected so tests can create intentionally malformed instances without exposing that behavior
   * to normal callers.
   *
   * @param hashType identifies the hash algorithm; expected non-null for non-test use
   * @param bs raw digest bytes to store directly; may be null only for serialization tests
   * @param testing whether to bypass the length assertion for test-only scenarios
   */
  protected HashResult(HashType hashType, byte[] bs, boolean testing) {
    this.type = hashType;
    this.result = bs;
    assert testing || (bs.length == type.hashLength);
  }

  /**
   * Creates an uninitialized instance for serialization frameworks.
   *
   * <p>This constructor leaves fields null so that the deserialization machinery can populate them.
   * Normal code should use the public constructors instead of this entry point.
   */
  protected HashResult() {
    // For serialization.
    type = null;
    result = null;
  }

  /**
   * Reads a set of hash results from the provided stream.
   *
   * <p>The method consumes a 32-bit bitmask followed by the raw bytes for each hash type present in
   * the bitmask. The order is defined by the current {@link HashType#values()} array, which
   * provides a stable, deterministic sequence in this codebase. When the bitmask is zero, a shared
   * empty array is returned instead of {@code null}.
   *
   * @param dis input stream positioned at the hash bitmask; must be non-null and readable
   * @return an array of hash results in canonical order; never {@code null}
   * @throws IOException if the stream cannot be read or does not contain enough bytes
   */
  public static HashResult[] readHashes(DataInputStream dis) throws IOException {
    int bitmask = dis.readInt();
    if (bitmask == 0) return EMPTY_HASHES;
    int count = 0;
    for (HashType h : HashType_values) {
      if ((bitmask & h.bitmask) == h.bitmask) {
        count++;
      }
    }
    HashResult[] results = new HashResult[count];
    int x = 0;
    for (HashType h : HashType_values) {
      if ((bitmask & h.bitmask) == h.bitmask) {
        results[x++] = HashResult.readFrom(h, dis);
      }
    }
    return results;
  }

  private static HashResult readFrom(HashType h, DataInputStream dis) throws IOException {
    byte[] buf = new byte[h.hashLength];
    dis.readFully(buf);
    return new HashResult(h, buf);
  }

  /**
   * Writes a set of hash results to the provided stream.
   *
   * <p>The method emits a 32-bit bitmask and then the raw bytes for each hash in ascending type
   * order. To enforce that order, the input array is sorted in place. Callers who need to preserve
   * the original ordering must pass a copy. Duplicate hash types are rejected to keep the encoding
   * unambiguous.
   *
   * @param hashes hash results to write; {@code null} is treated as an empty array
   * @param dos output stream that receives the bitmask and digest bytes; must be non-null
   * @throws IOException if the stream cannot be written to
   * @throws IllegalArgumentException if multiple hashes share the same type bitmask
   */
  public static void write(HashResult[] hashes, DataOutputStream dos) throws IOException {
    if (hashes == null) hashes = EMPTY_HASHES;
    int bitmask = 0;
    for (HashResult hash : hashes) bitmask |= hash.type.bitmask;
    dos.writeInt(bitmask);
    Arrays.sort(hashes);
    HashType prev = null;
    for (HashResult h : hashes) {
      if (prev == h.type || (prev != null && prev.bitmask == h.type.bitmask))
        throw new IllegalArgumentException("Multiple hashes of the same type!");
      prev = h.type;
    }
    for (HashResult h : hashes) h.writeTo(dos);
  }

  /**
   * Writes the raw digest bytes for this hash result.
   *
   * <p>No length prefix is written because the hash type already defines the expected length.
   * Callers must ensure the corresponding {@link HashType} is serialized or known separately. The
   * method writes exactly {@code type.hashLength} bytes from the internal buffer.
   *
   * @param dos output stream that receives the digest bytes; must be non-null
   * @throws IOException if the stream cannot be written to
   * @throws NullPointerException if the result bytes are not initialized
   */
  public void writeTo(OutputStream dos) throws IOException {
    // Any given hash type has a fixed hash length, so just push the bytes.
    Objects.requireNonNull(result, RESULT_MESSAGE);
    dos.write(result);
  }

  /**
   * Compares this instance to another by hash type bitmask.
   *
   * <p>The comparison establishes a stable ordering used by serialization and array sorting. It
   * ignores the digest bytes and only inspects the {@link HashType} bitmask. The method requires
   * both instances and their types to be non-null.
   *
   * @param h other hash result to compare; must be non-null and initialized
   * @return a negative, zero, or positive value based on the type bitmask ordering
   * @throws NullPointerException if {@code h} or either hash type is null
   */
  @Override
  public int compareTo(@NotNull HashResult h) {
    Objects.requireNonNull(type, "type");
    Objects.requireNonNull(h, "hashResult");
    Objects.requireNonNull(h.type, "type");
    return Integer.compare(type.bitmask, h.type.bitmask);
  }

  /**
   * Builds a bitmask representing the types present in the array.
   *
   * <p>Each hash type contributes its {@link HashType#bitmask} bit to the returned value. The
   * method performs no validation and assumes each array entry is non-null and initialized. It is
   * intended for compact storage or quick membership checks.
   *
   * @param hashes array of hash results to inspect; expected non-null and fully populated
   * @return bitmask with one bit set for each hash type present
   * @throws NullPointerException if {@code hashes} or any entry is null
   */
  public static long makeBitmask(HashResult[] hashes) {
    long l = 0;
    for (HashResult hash : hashes) l |= hash.type.bitmask;
    return l;
  }

  /**
   * Compares two arrays for strict equality of type ordering and hash bytes.
   *
   * <p>The arrays must have the same length and be ordered identically by hash type. The method
   * compares types by identity and by name to tolerate classloader differences, then compares the
   * raw digest bytes. Any mismatch is logged at error level. This is a diagnostic helper; it does
   * not attempt to reorder or normalize inputs.
   *
   * @param results expected results array; must be non-null and aligned by type
   * @param hashes actual results array; must be non-null and aligned by type
   * @return {@code true} when every type and byte array matches in order; {@code false} otherwise
   * @throws NullPointerException if either array or any entry is null
   */
  public static boolean strictEquals(HashResult[] results, HashResult[] hashes) {
    if (results.length != hashes.length) {
      LOG.error("Hashes not equal: {} hashes vs {} hashes", results.length, hashes.length);
      return false;
    }
    for (int i = 0; i < results.length; i++) {
      if (results[i].type != hashes[i].type
          && HashType.valueOf(results[i].type.name()) != HashType.valueOf(hashes[i].type.name())) {
        LOG.error(
            "Hashes not the same type: {} vs {}", results[i].type.name(), hashes[i].type.name());
        return false;
      }
      if (!Arrays.equals(results[i].result, hashes[i].result)) {
        LOG.error("Hash {} not equal", results[i].type.name());
        return false;
      }
    }
    return true;
  }

  /**
   * Determines whether the provided array contains a hash of the given type.
   *
   * <p>Type matching is performed by identity and by name to accommodate different enum instances
   * from separate classloaders. A {@code null} array yields {@code false}. The method does not
   * validate contents beyond reading the type field.
   *
   * @param hashes array of hash results to scan; {@code null} is treated as empty
   * @param type hash type to locate; expected non-null and stable
   * @return {@code true} if a matching type is present; {@code false} otherwise
   * @throws NullPointerException if {@code type} is null and the array is non-null
   */
  public static boolean contains(HashResult[] hashes, HashType type) {
    if (hashes == null) {
      return false;
    }
    for (HashResult res : hashes)
      if (res.type == type || type.name().equals(res.type.name())) return true;
    return false;
  }

  /**
   * Returns the raw digest bytes for the requested hash type.
   *
   * <p>The returned array is the internal storage of the matching {@link HashResult}, not a copy.
   * Callers must treat it as read-only. When the array is {@code null} or no match is found, a
   * shared empty array is returned.
   *
   * @param hashes array of hash results to scan; {@code null} is treated as empty
   * @param type hash type to locate; expected non-null and stable
   * @return the stored digest bytes for the matching type, or an empty array if absent
   * @throws NullPointerException if {@code type} is null and the array is non-null
   */
  public static byte[] get(HashResult[] hashes, HashType type) {
    if (hashes == null) {
      return EMPTY_BYTES;
    }
    for (HashResult res : hashes)
      if (res.type == type || type.name().equals(res.type.name())) return res.result;
    return EMPTY_BYTES;
  }

  /**
   * Returns a shallow copy of the provided hash result array.
   *
   * <p>Each element is copied using {@link #HashResult(HashResult)}, which preserves the original
   * byte arrays. The returned array is safe to reorder, but the contained {@code HashResult}
   * instances still share their digest storage with the originals. A {@code null} or empty input
   * yields a shared empty array.
   *
   * @param hashes array of hash results to copy; {@code null} is treated as empty
   * @return a new array containing shallow copies, or a shared empty array when no entries exist
   */
  public static HashResult[] copy(HashResult[] hashes) {
    if (hashes == null || hashes.length == 0) return EMPTY_HASHES;
    HashResult[] out = new HashResult[hashes.length];
    for (int i = 0; i < hashes.length; i++) {
      out[i] = new HashResult(hashes[i]);
    }
    return out;
  }

  /**
   * Returns the digest bytes as a lowercase hexadecimal string.
   *
   * <p>The conversion uses {@link HexUtil} and does not alter the stored bytes. This is typically
   * used for logging, debugging, or textual comparisons where a stable encoding is required.
   *
   * @return hex-encoded digest string for this hash result
   * @throws NullPointerException if the result bytes are not initialized
   */
  public String hashAsHex() {
    Objects.requireNonNull(result, RESULT_MESSAGE);
    return HexUtil.bytesToHex(result);
  }

  /**
   * Tests this hash result for equality with another object.
   *
   * <p>Two instances are considered equal when they share the same {@link HashType} reference and
   * their digest bytes compare equal using {@link MessageDigest#isEqual(byte[], byte[])}. The
   * comparison is byte-for-byte and does not normalize or copy arrays. This method is safe for hash
   * comparisons where timing side channels are a concern because the digest comparison uses a
   * constant-time helper.
   *
   * @param otherObject object to compare against; {@code null} or other types return {@code false}
   * @return {@code true} when type and digest bytes match; {@code false} otherwise
   */
  @Override
  public boolean equals(Object otherObject) {
    if (!(otherObject instanceof HashResult otherHash)) {
      return false;
    }

    if (type != otherHash.type) {
      return false;
    }

    return MessageDigest.isEqual(result, otherHash.result);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash code combines the hash type and the digest bytes using {@link Arrays#hashCode}.
   * This is stable for a given byte array content but will change if the underlying digest bytes
   * are mutated. Callers must treat the digest array as read-only to preserve hashing behavior in
   * maps and sets.
   *
   * @return a hash code derived from the type and digest bytes
   * @throws NullPointerException if the type or digest bytes are uninitialized
   */
  @Override
  public int hashCode() {
    int hash = 1;

    Objects.requireNonNull(type, "type");
    Objects.requireNonNull(result, RESULT_MESSAGE);
    hash *= 31 + type.hashCode();
    hash *= 31 + Arrays.hashCode(result);

    return hash;
  }
}
