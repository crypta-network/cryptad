package network.crypta.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import network.crypta.support.io.IOUtils;

/**
 * Utilities for computing SHA-256 message digests.
 *
 * <p>This class provides convenience helpers around the JCA {@link MessageDigest} implementation
 * for the SHA-256 algorithm. All methods are static; the class is not instantiable.
 *
 * <p>Threading: {@link MessageDigest} instances are mutable and not thread-safe. Callers must use a
 * separate instance per thread or task. {@link #getMessageDigest()} returns a new instance on each
 * call.
 *
 * <p>Typical usage:
 *
 * <ul>
 *   <li>{@link #hash(InputStream, MessageDigest)} reads a stream and updates a supplied digest.
 *   <li>{@link #digest(byte[])} computes a one-shot digest of a byte array.
 *   <li>{@link #getDigestLength()} returns the digest length in bytes.
 * </ul>
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class SHA256 {

  private SHA256() {}

  /**
   * Reads all bytes from the given input stream and updates the provided digest.
   *
   * <p>The stream is consumed until end-of-file and is always closed on return (success or error).
   * The supplied {@link MessageDigest} is updated incrementally and is not reset by this method. If
   * an {@link IOException} occurs during reading, the digest state reflects the bytes processed
   * before the exception was thrown.
   *
   * @param is input stream to read; must be readable and non-null. The stream is closed by this
   *     method.
   * @param md digest instance to update; must be non-null. The instance is modified but not reset.
   * @throws IOException if an I/O error occurs while reading the stream
   */
  public static void hash(InputStream is, MessageDigest md) throws IOException {
    try {
      byte[] buf = new byte[4096];
      int readBytes = is.read(buf);
      while (readBytes > -1) {
        md.update(buf, 0, readBytes);
        readBytes = is.read(buf);
      }
    } finally {
      IOUtils.closeQuietly(is);
    }
  }

  /**
   * Returns a new {@link MessageDigest} instance for the SHA-256 algorithm.
   *
   * <p>The instance is created using the preferred provider configured by {@link HashType#SHA256}.
   * The returned digest is mutable and not thread-safe.
   *
   * @return new SHA-256 {@link MessageDigest}
   * @throws IllegalStateException if the algorithm or configured provider is unavailable
   */
  public static MessageDigest getMessageDigest() {
    return HashType.SHA256.get();
  }

  /**
   * Computes the SHA-256 digest of the provided byte array.
   *
   * <p>This is an equivalent to {@code getMessageDigest().digest(data)}.
   *
   * @param data input bytes; must be non-null
   * @return 32-byte SHA-256 digest
   * @throws NullPointerException if {@code data} is {@code null}
   */
  public static byte[] digest(byte[] data) {
    return getMessageDigest().digest(data);
  }

  /**
   * Returns the SHA-256 digest length in bytes.
   *
   * @return 32
   */
  public static int getDigestLength() {
    return HashType.SHA256.hashLength;
  }
}
