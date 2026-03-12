package network.crypta.crypt;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import network.crypta.client.async.ReadBucketAndFreeInputStream;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.NonClosingOutputStream;
import network.crypta.support.io.PrependLengthOutputStream;

/**
 * Base API for computing, writing, and verifying checksums.
 *
 * <p>Implementations provide a concrete checksum algorithm (for example, CRC-32) and common helpers
 * for streaming use cases:
 *
 * <ul>
 *   <li>Producing an {@link OutputStream} that appends a checksum when the stream is closed.
 *   <li>Writing a self-delimiting "length + payload + checksum" structure and reading it back
 *       safely into temporary storage before exposing the bytes to callers.
 *   <li>Generating or verifying checksums for in-memory byte arrays.
 * </ul>
 *
 * <p>Unless stated otherwise, methods do not accept {@code null} arguments. All lengths are in
 * bytes. This type is not thread-safe.
 */
public abstract class ChecksumChecker {

  /**
   * Returns the checksum length in bytes for this algorithm.
   *
   * @return checksum size in bytes
   */
  public abstract int checksumLength();

  /**
   * Returns an {@link OutputStream} that forwards writes to {@code os} and appends the checksum
   * when the returned stream is closed.
   *
   * <p>The returned stream may close {@code os} when it is closed. Callers should not attempt to
   * continue using {@code os} after closing the wrapper.
   *
   * @param os the destination stream to write to
   * @param skipPrefix number of initial bytes to write through without including in the checksum
   *     (use {@code 0} to include all bytes)
   * @return an output stream that appends a checksum on close
   */
  public abstract OutputStream checksumWriter(OutputStream os, int skipPrefix);

  /**
   * Convenience overload of {@link #checksumWriter(OutputStream, int)} that includes all bytes in
   * the checksum.
   *
   * @param os the destination stream to write to
   * @return an output stream that appends a checksum on close
   */
  public OutputStream checksumWriter(OutputStream os) {
    return checksumWriter(os, 0);
  }

  /**
   * Returns an {@link OutputStream} that buffers into a temporary {@link Bucket}, then on close
   * prepends an 8-byte length header and appends a checksum.
   *
   * <p>The returned stream closes the underlying writer chain on close, which finalizes and writes
   * the checksum.
   *
   * @param dos the ultimate destination stream; must not be {@code null}
   * @param bf factory used to allocate temporary storage; must not be {@code null}
   * @return a stream that writes a length-prefixed, checksummed structure
   * @throws IOException if temporary storage cannot be created or written
   */
  public PrependLengthOutputStream checksumWriterWithLength(
      final OutputStream dos, BucketFactory bf) throws IOException {
    return PrependLengthOutputStream.create(checksumWriter(dos, 8), bf, 0, true);
  }

  /**
   * Like {@link #checksumWriterWithLength(OutputStream, BucketFactory)} but keeps the underlying
   * writer chain open after close.
   *
   * <p>Callers are responsible for eventually closing the checksum-writing stream so that the
   * trailing checksum bytes are emitted.
   *
   * @param dos the ultimate destination stream; must not be {@code null}
   * @param bf factory used to allocate temporary storage; must not be {@code null}
   * @return a stream that writes a length-prefixed, checksummed structure while leaving the
   *     underlying writer chain open
   * @throws IOException if temporary storage cannot be created or written
   */
  public PrependLengthOutputStream checksumWriterWithLengthNoClose(
      final OutputStream dos, BucketFactory bf) throws IOException {
    return PrependLengthOutputStream.create(
        checksumWriter(new NonClosingOutputStream(dos), 8), bf, 0, true);
  }

  /**
   * Returns a new array consisting of {@code data} followed by its checksum.
   *
   * @param data payload to checksum; must not be {@code null}
   * @return a newly allocated array of {@code data.length + checksumLength()} bytes
   */
  public abstract byte[] appendChecksum(byte[] data);

  /**
   * Verifies that {@code checksum} matches the checksum of {@code data[offset..offset+length)}.
   *
   * @param data source bytes; must not be {@code null}
   * @param offset first index to include
   * @param length number of bytes to include
   * @param checksum expected checksum; length must be {@link #checksumLength()}
   * @throws ChecksumFailedException if verification fails
   */
  @SuppressWarnings("unused")
  public void verifyChecksum(byte[] data, int offset, int length, byte[] checksum)
      throws ChecksumFailedException {
    if (!checkChecksum(data, offset, length, checksum)) throw new ChecksumFailedException();
  }

  /**
   * Reports whether {@code checksum} matches the checksum of {@code data[offset..offset+length)}.
   *
   * @param data source bytes; must not be {@code null}
   * @param offset first index to include
   * @param length number of bytes to include
   * @param checksum expected checksum; length must be {@link #checksumLength()}
   * @return {@code true} if verification succeeds; {@code false} otherwise
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  public abstract boolean checkChecksum(byte[] data, int offset, int length, byte[] checksum);

  /**
   * Computes the checksum for {@code bufToChecksum[offset..offset+length)}.
   *
   * @param bufToChecksum source bytes; must not be {@code null}
   * @param offset first index to include
   * @param length number of bytes to include
   * @return a new array of size {@link #checksumLength()} containing the checksum bytes
   */
  public abstract byte[] generateChecksum(byte[] bufToChecksum, int offset, int length);

  /**
   * Computes the checksum for the entire {@code bufToChecksum} array.
   *
   * @param bufToChecksum source bytes; must not be {@code null}
   * @return a new array of size {@link #checksumLength()} containing the checksum bytes
   */
  public byte[] generateChecksum(byte[] bufToChecksum) {
    return generateChecksum(bufToChecksum, 0, bufToChecksum.length);
  }

  /**
   * Returns the numeric identifier for this checksum algorithm.
   *
   * <p>The set of identifiers is defined in this class (for example, {@link #CHECKSUM_CRC}).
   *
   * @return stable, non-negative type identifier
   */
  public abstract int getChecksumTypeID();

  // Checksum IDs.
  /** Identifier for the CRC-based checksum implementation. */
  public static final int CHECKSUM_CRC = 1;

  /**
   * Copies exactly {@code length} bytes from {@code is} to {@code os}, then reads and verifies the
   * trailing checksum, and does not forward it.
   *
   * @param is source stream positioned at the start of the payload
   * @param os destination stream that receives the payload only
   * @param length number of payload bytes to copy (excludes the trailing checksum)
   * @throws IOException if an I/O error occurs while reading or writing
   * @throws ChecksumFailedException if the checksum does not match
   */
  public abstract void copyAndStripChecksum(InputStream is, OutputStream os, long length)
      throws IOException, ChecksumFailedException;

  /**
   * Reads {@code length} bytes into {@code buf} and verifies the checksum that immediately follows.
   * On failure, fills {@code buf[offset..offset+length)} with zeros and throws.
   *
   * @param is data source
   * @param buf destination buffer
   * @param offset first index into {@code buf}
   * @param length number of bytes to read into {@code buf}
   * @throws IOException if an I/O error occurs while reading
   * @throws ChecksumFailedException if verification fails (after zeroing the read region)
   */
  public abstract void readAndChecksum(DataInput is, byte[] buf, int offset, int length)
      throws IOException, ChecksumFailedException;

  /**
   * Reads a self-delimiting structure written by {@link #checksumWriterWithLength(OutputStream,
   * BucketFactory)} or {@link #checksumWriterWithLengthNoClose(OutputStream, BucketFactory)}.
   *
   * <p>The method consumes an 8-byte length, copies that many payload bytes to temporary storage
   * while verifying the trailing checksum, and returns an {@link InputStream} that reads from the
   * temporary storage. The caller is responsible for closing the returned stream.
   *
   * @param dis source stream positioned at the length field
   * @param bf factory used to allocate a temporary {@link Bucket}
   * @param maxLength upper bound for the length field; must be non-negative
   * @return an input stream over the verified payload bytes
   * @throws IOException if the length is negative, exceeds {@code maxLength}, or an I/O error
   *     occurs
   * @throws ChecksumFailedException if checksum verification fails
   */
  public InputStream checksumReaderWithLength(InputStream dis, BucketFactory bf, long maxLength)
      throws IOException, ChecksumFailedException {
    // Copy into a temporary Bucket so callers never see unverified bytes.
    long length = new DataInputStream(dis).readLong();
    if (length < 0 || length > maxLength) {
      throw new IOException("Bad length: " + length + "; maxLength: " + maxLength);
    }
    Bucket bucket = bf.makeBucket(length);
    try (OutputStream os = bucket.getOutputStream()) {
      copyAndStripChecksum(dis, os, length);
    }
    return ReadBucketAndFreeInputStream.create(bucket);
  }

  public void writeAndChecksum(OutputStream os, byte[] buf, int offset, int length)
      throws IOException {
    os.write(buf, offset, length);
    os.write(generateChecksum(buf, offset, length));
  }

  /**
   * Writes {@code buf} followed by its checksum to {@code oos}.
   *
   * @param oos destination stream
   * @param buf payload
   * @throws IOException if writing fails
   */
  public void writeAndChecksum(ObjectOutputStream oos, byte[] buf) throws IOException {
    writeAndChecksum(oos, buf, 0, buf.length);
  }

  /**
   * Returns the overhead, in bytes, for a structure that uses an 8-byte length header followed by a
   * trailing checksum.
   *
   * @return {@code 8 + checksumLength()}
   */
  @SuppressWarnings("unused")
  public int lengthAndChecksumOverhead() {
    return 8 + checksumLength();
  }

  /**
   * Creates a {@code ChecksumChecker} of the specified type.
   *
   * @param checksumID algorithm identifier (for example, {@link #CHECKSUM_CRC})
   * @return a checker for the given {@code checksumID}
   * @throws IllegalArgumentException if no checker exists for {@code checksumID}
   */
  public static ChecksumChecker create(int checksumID) {
    if (checksumID == CHECKSUM_CRC) return new CRCChecksumChecker();
    else throw new IllegalArgumentException("Bad checksum ID");
  }
}
