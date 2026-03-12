package network.crypta.crypt;

import java.io.Serial;

/**
 * Signals that checksum verification failed.
 *
 * <p>Thrown by operations in {@link ChecksumChecker}, for example:
 *
 * <ul>
 *   <li>{@link ChecksumChecker#copyAndStripChecksum(java.io.InputStream, java.io.OutputStream,
 *       long)} when the trailing checksum of a copied payload does not match.
 *   <li>{@link ChecksumChecker#readAndChecksum(java.io.DataInput, byte[], int, int)} when bytes
 *       read into a buffer do not validate against the following checksum.
 *   <li>{@link ChecksumChecker#checksumReaderWithLength(java.io.InputStream,
 *       network.crypta.support.api.BucketFactory, long)} when a length-prefixed payload fails
 *       verification.
 * </ul>
 *
 * <p>This is a checked exception to ensure callers explicitly handle potential data corruption. In
 * some code paths the read buffer may be cleared before this exception is thrown to avoid exposing
 * untrusted bytes.
 */
public class ChecksumFailedException extends Exception {
  /** Serialization version for binary compatibility. */
  @Serial private static final long serialVersionUID = 6730512270038683931L;
}
