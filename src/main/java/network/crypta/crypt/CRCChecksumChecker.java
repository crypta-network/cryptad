package network.crypta.crypt;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import network.crypta.support.Fields;

/**
 * {@link ChecksumChecker} implementation that uses CRC-32.
 *
 * <p>The checksum is computed with {@link java.util.zip.CRC32} and encoded as a 4-byte
 * little-endian integer (as returned by {@link Fields#intToBytes(int)}). The class does not keep
 * mutable state; separate method calls create fresh {@link CRC32} instances, making objects of this
 * type effectively thread-safe.
 */
public class CRCChecksumChecker extends ChecksumChecker {
  private static final int BUFFER_SIZE = 32 * 1024;

  /** Returns the size of the CRC-32 trailer in bytes. */
  @Override
  public int checksumLength() {
    return 4;
  }

  /**
   * Returns an {@link OutputStream} that forwards all bytes to {@code os} and maintains a running
   * CRC-32 of the data written, excluding an initial prefix.
   *
   * <p>On {@link OutputStream#close()}, the stream appends the current checksum as a 4-byte
   * little-endian trailer and then closes the underlying stream.
   *
   * @param os destination stream; must not be {@code null}.
   * @param prefix number of initial bytes to exclude from the checksum (useful when a fixed-size
   *     header precedes the checksummed payload); must be {@code >= 0}.
   * @return a wrapping stream that computes and appends the CRC-32 trailer on close.
   */
  @Override
  public OutputStream checksumWriter(OutputStream os, int prefix) {
    return new ChecksumOutputStream(os, new CRC32(), true, prefix);
  }

  /**
   * Verifies a CRC-32 against the provided data range.
   *
   * <p>The {@code checksum} parameter must contain exactly 4 bytes and use the same little-endian
   * encoding produced by {@link #generateChecksum(byte[], int, int)}.
   *
   * @param data source array containing the payload.
   * @param offset start index in {@code data}.
   * @param length number of bytes to include in the CRC.
   * @param checksum expected 4-byte CRC-32 trailer.
   * @return {@code true} if the computed checksum equals the provided one; otherwise {@code false}.
   * @throws IllegalArgumentException if {@code checksum.length != 4}.
   */
  @Override
  public boolean checkChecksum(byte[] data, int offset, int length, byte[] checksum) {
    if (checksum.length != 4) throw new IllegalArgumentException();
    CRC32 crc = new CRC32();
    crc.update(data, offset, length);
    int computed = (int) crc.getValue();
    int stored = Fields.bytesToInt(checksum);
    return computed == stored;
  }

  /**
   * Returns a new array consisting of {@code data} followed by a 4-byte little-endian CRC-32
   * trailer.
   *
   * @param data payload to copy.
   * @return a new array of size {@code data.length + 4} containing the payload and checksum.
   */
  @Override
  public byte[] appendChecksum(byte[] data) {
    byte[] output = new byte[data.length + 4];
    System.arraycopy(data, 0, output, 0, data.length);
    Checksum crc = new CRC32();
    crc.update(data, 0, data.length);
    byte[] checksum = Fields.intToBytes((int) crc.getValue());
    System.arraycopy(checksum, 0, output, data.length, 4);
    return output;
  }

  /**
   * Generates a 4-byte little-endian CRC-32 for a slice of a byte array.
   *
   * @param data source array.
   * @param offset start index in {@code data}.
   * @param length number of bytes to include in the CRC.
   * @return a new 4-byte array containing the checksum.
   */
  @Override
  public byte[] generateChecksum(byte[] data, int offset, int length) {
    Checksum crc = new CRC32();
    crc.update(data, offset, length);
    return Fields.intToBytes((int) crc.getValue());
  }

  /** Returns the identifier for CRC-32 in the {@link ChecksumChecker} type registry. */
  @Override
  public int getChecksumTypeID() {
    return ChecksumChecker.CHECKSUM_CRC;
  }

  /**
   * Copies a payload to {@code destination} and validates a trailing CRC-32 when a positive {@code
   * length} is provided.
   *
   * <p>Behavior depends on {@code length}:
   *
   * <ul>
   *   <li>{@code length >= 0}: reads exactly {@code length} bytes from {@code is}, forwards them to
   *       {@code destination}, then reads 4 checksum bytes and verifies them against the bytes just
   *       written. On mismatch, a {@link ChecksumFailedException} is thrown. Note that the payload
   *       has already been written to {@code destination} before verification completes.
   *   <li>{@code length == -1}: copies until end-of-stream without reading or verifying a trailing
   *       checksum.
   * </ul>
   *
   * @param is source stream.
   * @param destination sink for the payload bytes.
   * @param length number of payload bytes to read, or {@code -1} to copy until EOF.
   * @throws IOException if an I/O error occurs, including premature EOF while reading the payload
   *     or checksum.
   * @throws ChecksumFailedException if the computed checksum does not match the trailer.
   */
  @Override
  public void copyAndStripChecksum(InputStream is, OutputStream destination, long length)
      throws IOException, ChecksumFailedException {
    // Streaming copy that preserves original behavior: payload bytes are forwarded before
    // verification. On mismatch, the destination already contains the payload.
    CRC32 crc = new CRC32();
    if (length == -1) {
      copyUntilEOF(is, destination, crc);
      return; // No trailing checksum in this mode
    }

    long remaining = length;
    byte[] buffer = new byte[BUFFER_SIZE];
    DataInputStream source = new DataInputStream(is);
    while (remaining > 0) {
      int toRead = (int) Math.min(remaining, BUFFER_SIZE);
      int read = source.read(buffer, 0, toRead);
      if (read == -1) {
        throw new EOFException("stream reached eof");
      }
      if (read == 0) {
        throw new IOException("stream returning 0 bytes");
      }
      crc.update(buffer, 0, read);
      destination.write(buffer, 0, read);
      remaining -= read;
    }
    byte[] checksum = new byte[checksumLength()];
    source.readFully(checksum);
    byte[] myChecksum = Fields.intToBytes((int) crc.getValue());
    if (!Arrays.equals(checksum, myChecksum)) {
      throw new ChecksumFailedException();
    }
  }

  /*
   * Copies all available bytes from {@code is} to {@code destination} until EOF.
   * Updates {@code crc} with the bytes seen. No checksum is read or written in this mode.
   */
  private static void copyUntilEOF(InputStream is, OutputStream destination, CRC32 crc)
      throws IOException {
    byte[] buffer = new byte[BUFFER_SIZE];
    for (; ; ) {
      int read = is.read(buffer, 0, BUFFER_SIZE);
      if (read == -1) {
        return;
      }
      if (read == 0) {
        throw new IOException("stream returning 0 bytes");
      }
      crc.update(buffer, 0, read);
      destination.write(buffer, 0, read);
    }
  }

  /**
   * Reads {@code length} bytes into {@code buf} and verifies the next 4 bytes as a CRC-32.
   *
   * <p>On checksum failure, the method zeroes the region {@code [offset, offset + length)} in
   * {@code buf} and throws a {@link ChecksumFailedException}.
   *
   * @param is source of bytes, positioned at the payload start.
   * @param buf destination buffer; must have capacity for the payload at the given offset.
   * @param offset start index in {@code buf}.
   * @param length number of payload bytes to read.
   * @throws IOException if an I/O error occurs (including EOF while reading the checksum).
   * @throws ChecksumFailedException if the provided trailer does not match the computed checksum.
   */
  @Override
  public void readAndChecksum(DataInput is, byte[] buf, int offset, int length)
      throws IOException, ChecksumFailedException {
    is.readFully(buf, offset, length);
    byte[] checksum = new byte[checksumLength()];
    is.readFully(checksum);
    if (!checkChecksum(buf, offset, length, checksum)) {
      Arrays.fill(buf, offset, offset + length, (byte) 0);
      throw new ChecksumFailedException();
    }
  }
}
