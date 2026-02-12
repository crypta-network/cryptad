package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.CountedOutputStream;
import network.crypta.support.io.HeaderStreams;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compressor implementation for BZip2 streams without the standard {@code "BZ"} header.
 *
 * <p>This implementation is compatible with legacy data produced by earlier tooling which omitted
 * the two-byte BZip2 signature. To maintain interoperability, compression writes through a
 * filtering stream that expects and swallows the header, and decompression augments the input with
 * the header so that {@link BZip2CompressorInputStream} sees a standard stream.
 *
 * <p>Behavioral notes
 *
 * <ul>
 *   <li>Compression and decompression operate on byte streams; there is no archive support.
 *   <li>{@code maxReadLength} and {@code maxWriteLength} limit input and output respectively.
 *       Exceeding {@code maxWriteLength} results in {@link CompressionOutputSizeException}.
 *   <li>Decompression enforces {@code maxLength} and can optionally continue reading to estimate
 *       the full uncompressed size when the limit is exceeded.
 *   <li>When enabled, a minimal compression ratio check can abort compression early via {@link
 *       CompressionRatioException}.
 * </ul>
 */
public class Bzip2Compressor extends AbstractCompressor {
  private static final Logger LOG = LoggerFactory.getLogger(Bzip2Compressor.class);

  private static final byte[] BZ_HEADER = "BZ".getBytes(StandardCharsets.ISO_8859_1);

  /**
   * Compresses data from a {@link Bucket} into a new {@link Bucket} produced by the provided
   * factory.
   *
   * <p>This method creates the destination bucket with the supplied maximum length and delegates to
   * the stream-based {@code compress} implementation. Streams are closed by the {@code try} block
   * regardless of success or failure.
   *
   * @param data source bucket to read from
   * @param bf destination bucket factory
   * @param maxReadLength maximum number of bytes to read from {@code data}
   * @param maxWriteLength maximum number of bytes allowed to be written to the compressed output
   * @return the bucket containing the compressed bytes
   * @throws IOException on I/O errors from the buckets
   * @throws CompressionOutputSizeException if the compressed output exceeds {@code maxWriteLength}
   */
  @Override
  public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException {
    Bucket output = bf.makeBucket(maxWriteLength);
    try (InputStream is = data.getInputStream();
        OutputStream os = output.getOutputStream()) {
      compress(is, os, maxReadLength, maxWriteLength);
    }
    return output;
  }

  /**
   * Compresses data from {@link InputStream} to {@link OutputStream}, optionally checking the
   * compression effect after a specified amount of input has been processed.
   *
   * <p>Input is read in chunks (currently 32,768 bytes). If {@code
   * amountOfDataToCheckCompressionRatio} is non-zero, the method checks the compression percentage
   * after approximately {@code amountOfDataToCheckCompressionRatio / 32768} chunks. If the achieved
   * compression is below {@code minimumCompressionPercentage}, a {@link CompressionRatioException}
   * is thrown.
   *
   * <p>Preconditions
   *
   * <ul>
   *   <li>{@code maxReadLength} must be positive; otherwise an {@link IllegalArgumentException} is
   *       thrown.
   * </ul>
   *
   * @param is source stream
   * @param os destination stream
   * @param maxReadLength maximum number of bytes to read from {@code is}
   * @param maxWriteLength maximum number of bytes allowed to be written to {@code os}
   * @param amountOfDataToCheckCompressionRatio input size (in bytes) after which to check the
   *     compression effect; set to {@code 0} to disable checking
   * @param minimumCompressionPercentage minimal required compression percentage (0 disables check)
   * @return number of bytes written to {@code os}
   * @throws IOException on I/O errors or if the source returns a zero-length read
   * @throws CompressionOutputSizeException if the compressed output exceeds {@code maxWriteLength}
   * @throws CompressionRatioException if the compression effect is lower than requested
   */
  @Override
  public long compress(
      InputStream is,
      OutputStream os,
      long maxReadLength,
      long maxWriteLength,
      long amountOfDataToCheckCompressionRatio,
      int minimumCompressionPercentage)
      throws IOException, CompressionRatioException {
    if (maxReadLength <= 0) throw new IllegalArgumentException();
    CountedOutputStream cos = new CountedOutputStream(os);
    try (BZip2CompressorOutputStream bz2os =
        new BZip2CompressorOutputStream(HeaderStreams.dimOutput(BZ_HEADER, cos))) {
      long read = 0;
      // Bigger input buffer, so can compress all at once.
      // Won't hurt on I/O either, although most OSs will only return a page at a time.
      int bufferSize = 32768;
      byte[] buffer = new byte[bufferSize];
      long iterationToCheckCompressionRatio = amountOfDataToCheckCompressionRatio / bufferSize;
      int i = 0;
      while (true) {
        int l = (int) Math.min(buffer.length, maxReadLength - read);
        int x = l == 0 ? -1 : is.read(buffer, 0, buffer.length);
        if (x == -1) break;
        if (x == 0) throw new IOException("Returned zero from read()");
        bz2os.write(buffer, 0, x);
        read += x;
        if (cos.written() > maxWriteLength) throw new CompressionOutputSizeException();

        if (++i == iterationToCheckCompressionRatio && minimumCompressionPercentage != 0) {
          checkCompressionEffect(read, cos.written(), minimumCompressionPercentage);
        }
      }
      bz2os.flush();
      cos.flush();
    }
    if (cos.written() > maxWriteLength) throw new CompressionOutputSizeException();
    return cos.written();
  }

  /**
   * Decompresses BZip2 data from {@link InputStream} to {@link OutputStream}.
   *
   * <p>The method enforces {@code maxLength}. If the next read exceeds that limit, and {@code
   * maxCheckSizeBytes} is positive, it continues reading up to {@code maxLength +
   * maxCheckSizeBytes} to compute an estimated uncompressed size and then throws {@link
   * CompressionOutputSizeException} populated with that estimate. If {@code maxCheckSizeBytes} is
   * non-positive, it throws immediately without an estimate.
   *
   * @param is source stream containing BZip2 data (without the {@code "BZ"} header)
   * @param os destination stream for uncompressed bytes
   * @param maxLength maximum number of bytes allowed to be written to {@code os}
   * @param maxCheckSizeBytes additional number of bytes to read when the limit is exceeded to
   *     estimate the total uncompressed size; non-positive disables estimation
   * @return number of bytes written to {@code os}
   * @throws IOException on I/O errors or if the source returns a zero-length read
   * @throws CompressionOutputSizeException if the uncompressed output would exceed {@code
   *     maxLength}
   */
  @Override
  public long decompress(InputStream is, OutputStream os, long maxLength, long maxCheckSizeBytes)
      throws IOException {
    try (BZip2CompressorInputStream bz2is =
        new BZip2CompressorInputStream(
            HeaderStreams.augInput(BZ_HEADER, new NonClosingInputStream(is)))) {
      long written = 0;
      int bufSize = 32768;
      if (maxLength > 0 && maxLength < bufSize) bufSize = (int) maxLength;
      byte[] buffer = new byte[bufSize];
      // Read in a loop, enforcing the maximum on every iteration. We intentionally allow
      // over-reading by asking for a full buffer and then detecting overflow; this keeps the logic
      // simple while still bounding output via explicit checks.
      while (true) {
        int expectedBytesRead = (int) Math.min(buffer.length, maxLength - written);
        // Over-read is intentional here to detect when the next chunk would exceed the configured
        // maximum. We then either estimate the full size (if requested) or fail immediately.
        int bytesRead = bz2is.read(buffer, 0, buffer.length);
        if (expectedBytesRead < bytesRead) {
          LOG.info(
              "expectedBytesRead={}, bytesRead={}, written={}, maxLength={} throwing a"
                  + " CompressionOutputSizeException",
              expectedBytesRead,
              bytesRead,
              written,
              maxLength);
          if (maxCheckSizeBytes > 0) {
            consumeAndThrowWithEstimate(
                bz2is, buffer, maxLength, maxCheckSizeBytes, written, bytesRead);
          }
          throw new CompressionOutputSizeException();
        }
        if (bytesRead <= -1) return written;
        if (bytesRead == 0) throw new IOException("Returned zero from read()");
        os.write(buffer, 0, bytesRead);
        written += bytesRead;
      }
    }
  }

  /**
   * Continues reading until EOF to compute an estimated uncompressed size, then throws a {@link
   * CompressionOutputSizeException} with that estimate.
   *
   * <p>This is only invoked when the uncompressed output has already exceeded {@code maxLength} and
   * the caller requested an estimate via {@code maxCheckSizeBytes}.
   *
   * @param bz2is BZip2 stream to read from (already positioned past the limit)
   * @param buffer scratch buffer used for reading
   * @param maxLength configured maximum output length
   * @param maxCheckSizeBytes additional bytes to read when estimating
   * @param written number of bytes already written to the destination before this method was called
   * @param bytesRead number of bytes read in the iteration that detected overflow
   * @throws IOException if a zero-length read occurs or the underlying stream throws
   * @throws CompressionOutputSizeException always thrown at EOF with the estimated size
   */
  private static void consumeAndThrowWithEstimate(
      BZip2CompressorInputStream bz2is,
      byte[] buffer,
      long maxLength,
      long maxCheckSizeBytes,
      long written,
      int bytesRead)
      throws IOException {
    long totalWritten = written + bytesRead;
    int r;
    do {
      int expectedBytesRead =
          (int) Math.min(buffer.length, maxLength + maxCheckSizeBytes - totalWritten);
      r = bz2is.read(buffer, 0, expectedBytesRead);
      if (r == 0) throw new IOException("Returned zero from read()");
      if (r > -1) {
        totalWritten += r;
      }
    } while (r > -1);
    throw new CompressionOutputSizeException(totalWritten);
  }

  /**
   * Decompresses a byte array entirely in memory.
   *
   * <p>This convenience method wraps the array in streams and delegates to {@link
   * #decompress(InputStream, OutputStream, long, long)}. If the provided output buffer is too
   * small, {@link CompressionOutputSizeException} is propagated; unexpected I/O errors from the
   * in-memory streams are wrapped in {@link IllegalStateException}.
   *
   * @param dbuf compressed data buffer (without the {@code "BZ"} header)
   * @param i offset within {@code dbuf}
   * @param j number of bytes from {@code dbuf} to read
   * @param output destination buffer for the uncompressed data
   * @return number of bytes written into {@code output}
   * @throws CompressionOutputSizeException if {@code output} is too small for the decompressed data
   */
  @Override
  public int decompress(byte[] dbuf, int i, int j, byte[] output)
      throws CompressionOutputSizeException {
    // BZip2 streams are not compatible with java.util.zip.Inflater; use the BZip2 stream
    // implementation from Apache Commons Compress.
    ByteArrayInputStream bais = new ByteArrayInputStream(dbuf, i, j);
    ByteArrayOutputStream baos = new ByteArrayOutputStream(output.length);
    int bytes;
    try {
      decompress(bais, baos, output.length, -1);
      bytes = baos.size();
    } catch (IOException e) {
      if (e instanceof CompressionOutputSizeException compressionoutputsizeexception) {
        throw compressionoutputsizeexception;
      }
      throw new IllegalStateException("Unexpected I/O during in-memory BZIP2 decompression", e);
    }
    byte[] buf = baos.toByteArray();
    System.arraycopy(buf, 0, output, 0, bytes);
    return bytes;
  }

  @SuppressWarnings("java:S4929")
  private static class NonClosingInputStream extends FilterInputStream {
    NonClosingInputStream(InputStream in) {
      super(in);
    }

    @Override
    public void close() {
      // Keep ownership of the caller-provided stream with the caller.
    }
  }
}
