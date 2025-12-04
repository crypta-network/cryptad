package network.crypta.crypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import network.crypta.support.HexUtil;

/**
 * Incremental hashing helper for multiple algorithms.
 *
 * <p>This class wraps a {@link MessageDigest} obtained from a {@link HashType} and provides a
 * simple streaming API: add input with {@code addByte(..)} / {@code addBytes(..)}, then finalize
 * the current state with {@link #genHash()} or one of its convenience variants. After generating a
 * hash, the internal digest state is reset, so the instance is ready to accept new input.
 *
 * <p>Instances are not thread-safe. Use each {@code Hash} from a single thread or synchronize
 * externally. Inputs must be non-{@code null}. Passing {@code null} will result in a runtime
 * exception from the underlying digest implementation.
 *
 * <p>Provider quirks: some non-standard digests (e.g., {@link HashType#ED2K} and {@link
 * HashType#TTH}) require special handling when resetting after {@link #genHash()}; this class
 * compensates accordingly.
 *
 * <p>For general-purpose use, {@link HashType#SHA256} is a reasonable default.
 *
 * @author unixninja92
 */
public final class Hash {
  private final HashType type;
  private MessageDigest digest;

  /**
   * Creates a new hasher using the specified algorithm.
   *
   * @param type the hashing algorithm to use; must not be {@code null}
   */
  public Hash(HashType type) {
    this.type = type;
    digest = type.get();
  }

  /**
   * Finalizes and returns the hash of the bytes added since the last reset.
   *
   * <p>After computing the digest, this method resets the internal state so that subsequent calls
   * start from a clean slate. For {@link HashType#ED2K} and {@link HashType#TTH}, the underlying
   * providers do not implement reset reliably; the implementation recreates or resets the digest to
   * ensure a clean state.
   *
   * @return a newly allocated array containing the hash bytes
   */
  public byte[] genHash() {
    byte[] result = digest.digest();
    if (type == HashType.ED2K) {
      // ED2K provider does not reset after digest(); explicitly reset.
      digest.reset();
    } else if (type == HashType.TTH) {
      // TTH provider's reset() is unreliable; recreate the digest.
      digest = type.get();
    }
    return result;
  }

  /**
   * Computes the hash of the provided bytes only.
   *
   * <p>This method resets the internal state before processing the provided input to ensure that no
   * previous data is included, then finalizes and resets again via {@link #genHash()}.
   *
   * @param input the byte arrays to hash; each entry must be non-{@code null}
   * @return the hash of {@code input}
   */
  public byte[] genHash(byte[]... input) {
    digest.reset();
    addBytes(input);
    return genHash();
  }

  /**
   * Finalizes and returns the current hash as a {@link HashResult}.
   *
   * <p>Equivalent to {@code new HashResult(type, genHash())}.
   *
   * @return the hash value paired with its {@link HashType}
   */
  public HashResult genHashResult() {
    return new HashResult(type, genHash());
  }

  /**
   * Computes the hash of the provided bytes only and returns it as a {@link HashResult}.
   *
   * <p>Resets the internal state before and after processing the input.
   *
   * @param input the byte arrays to hash; each entry must be non-{@code null}
   * @return the resulting {@link HashResult}
   */
  public HashResult genHashResult(byte[]... input) {
    digest.reset();
    addBytes(input);
    return genHashResult();
  }

  /**
   * Finalizes and returns the current hash as a hexadecimal string.
   *
   * @return a hexadecimal representation of the hash
   */
  public String genHexHash() {
    return HexUtil.bytesToHex(genHash());
  }

  /**
   * Adds a single byte to the current hash input.
   *
   * @param input the byte to add
   */
  public void addByte(byte input) {
    digest.update(input);
  }

  /**
   * Adds one or more byte arrays to the current hash input.
   *
   * @param input the arrays to add; each entry must be non-{@code null}
   */
  public void addBytes(byte[]... input) {
    for (byte[] b : input) {
      digest.update(b);
    }
  }

  /**
   * Adds the remaining bytes from a {@link ByteBuffer} to the current hash input.
   *
   * <p>Bytes are read from {@code input.position()} up to {@code input.limit()}. On return, the
   * buffer's position is advanced to {@code limit} (i.e., all remaining bytes are consumed); the
   * limit is unchanged.
   *
   * @param input the buffer whose remaining bytes are added
   */
  public void addBytes(ByteBuffer input) {
    digest.update(input);
  }

  /**
   * Adds a slice of a byte array to the current hash input.
   *
   * @param input the source array
   * @param offset the index of the first byte to add
   * @param len the number of bytes to add starting at {@code offset}
   */
  public void addBytes(byte[] input, int offset, int len) {
    digest.update(input, offset, len);
  }

  /**
   * Verifies that the hash of the provided data matches the expected value.
   *
   * <p>The internal state is reset before hashing the provided input and reset again after
   * finalization. Comparison uses {@link java.security.MessageDigest#isEqual(byte[], byte[])} to
   * reduce timing side-channel leakage.
   *
   * @param hash the expected hash value
   * @param data the data to hash
   * @return {@code true} if the computed hash equals {@code hash}; otherwise {@code false}
   */
  public boolean verify(byte[] hash, byte[]... data) {
    return MessageDigest.isEqual(hash, genHash(data));
  }

  /**
   * Compares two {@link HashResult} values for equality of type and contents.
   *
   * @param hash1 the first value
   * @param hash2 the second value
   * @return {@code true} if both type and bytes are equal; otherwise {@code false}
   */
  public static boolean verify(HashResult hash1, HashResult hash2) {
    return hash1.equals(hash2);
  }

  /**
   * Verifies that the provided {@link HashResult} equals the hash of the given data.
   *
   * @param hash the expected value
   * @param input the data to hash
   * @return {@code true} if the computed value equals {@code hash}; otherwise {@code false}
   */
  public static boolean verify(HashResult hash, byte[]... input) {
    HashType type = hash.type;
    Hash h = new Hash(type);
    return verify(hash, new HashResult(type, h.genHash(input)));
  }
}
