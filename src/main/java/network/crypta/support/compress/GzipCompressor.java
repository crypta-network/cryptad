package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.CountedOutputStream;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GZIP implementation of {@link Compressor}.
 *
 * <p>This compressor streams data using {@link GZIPOutputStream} and {@link GZIPInputStream}. It
 * enforces caller-provided size limits during both compression and decompression and optionally
 * validates that compression achieves a minimum reduction percentage.
 *
 * <p>When compressing via the {@link #compress(Bucket, BucketFactory, long, long)} overload, the
 * emitted GZIP header's "OS" byte (offset {@code 9}) is forced to {@code 0}. This guarantees stable
 * output across JDK versions (some versions write {@code 255}) and thus preserves hashes computed
 * over the compressed data.
 *
 * <p>Thread safety: Instances are stateless and may be shared across threads, but individual calls
 * are not coordinated. Each call uses only caller-provided streams/buckets.
 */
public class GzipCompressor extends AbstractCompressor {
  private static final Logger LOG = LoggerFactory.getLogger(GzipCompressor.class);

  /**
   * Compresses data from a {@link Bucket} into a new {@link RandomAccessBucket} created by the
   * supplied {@link BucketFactory}.
   *
   * <p>The GZIP header OS byte is forced to {@code 0} for deterministic output across platforms.
   *
   * @param data input data; read from the beginning. The returned bucket contains the compressed
   *     form.
   * @param bf factory used to create the output bucket.
   * @param maxReadLength maximum number of input bytes to read; negative values are invalid.
   * @param maxWriteLength maximum number of compressed bytes allowed to be written to the output
   *     bucket.
   * @return the {@link RandomAccessBucket} that holds the compressed data. The caller owns it and
   *     must free or close it when done.
   * @throws IOException on I/O errors. The specific subclass {@link CompressionOutputSizeException}
   *     (an {@link IOException}) is thrown if the compressed output exceeds {@code maxWriteLength}.
   */
  @Override
  public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException {
    RandomAccessBucket output = bf.makeBucket(maxWriteLength);
    try (InputStream is = data.getInputStream();
        OutputStream os = output.getOutputStream()) {
      // Force the GZIP header OS byte to 0 regardless of JDK behavior; some JDKs use 255.
      // This avoids output drift that would break content hashes stored elsewhere.
      SingleOffsetReplacingOutputStream osByteFixingOs =
          new SingleOffsetReplacingOutputStream(os, 9, 0);
      compress(is, osByteFixingOs, maxReadLength, maxWriteLength);
      // Streams close automatically at the end of this block.
    }
    return output;
  }

  /**
   * Compresses data from an {@link InputStream} to an {@link OutputStream} with optional
   * compression-ratio validation.
   *
   * <p>Data is read and written in 32&nbsp;KiB chunks. The method stops reading at {@code
   * maxReadLength} bytes or when the input reaches EOF, whichever comes first. If, after {@code
   * amountOfDataToCheckCompressionRatio} bytes have been read, the achieved reduction is below
   * {@code minimumCompressionPercentage}, a {@link CompressionRatioException} is thrown.
   *
   * <p>Neither stream is closed by this method.
   *
   * @param is input to compress.
   * @param os destination for compressed bytes.
   * @param maxReadLength maximum number of input bytes to read; must be {@code >= 0}.
   * @param maxWriteLength maximum number of compressed bytes allowed to be produced.
   * @param amountOfDataToCheckCompressionRatio number of raw bytes after which to evaluate the
   *     compression ratio. Set to a very large value to effectively disable the mid-stream check.
   * @param minimumCompressionPercentage minimum acceptable reduction (0–100). A value of {@code 0}
   *     disables the ratio check.
   * @return the number of compressed bytes written to {@code os}.
   * @throws IllegalArgumentException if {@code maxReadLength} is negative.
   * @throws CompressionRatioException if the reduction is below the requested minimum when checked.
   * @throws IOException on I/O errors. The specific subclass {@link CompressionOutputSizeException}
   *     (an {@link IOException}) is thrown if the compressed output exceeds {@code maxWriteLength}.
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
    if (maxReadLength < 0) throw new IllegalArgumentException();
    CountedOutputStream cos = new CountedOutputStream(os);
    // Use a non-closing wrapper so we can close the GZIP stream without closing the caller's
    // OutputStream.
    try (GZIPOutputStream gos = new GZIPOutputStream(new NonClosingOutputStream(cos))) {
      long read = 0;
      // Use a larger buffer to reduce per-call overhead while remaining memory‑friendly.
      int bufferSize = 32768;
      byte[] buffer = new byte[bufferSize];
      long iterationToCheckCompressionRatio = amountOfDataToCheckCompressionRatio / bufferSize;
      int i = 0;
      while (true) {
        int l = (int) Math.min(buffer.length, maxReadLength - read);
        int x = l == 0 ? -1 : is.read(buffer, 0, l);
        if (x == -1) break;
        if (x == 0) throw new IOException("Returned zero from read()");
        gos.write(buffer, 0, x);
        read += x;
        if (cos.written() > maxWriteLength) throw new CompressionOutputSizeException();

        if (++i == iterationToCheckCompressionRatio && minimumCompressionPercentage != 0) {
          checkCompressionEffect(read, cos.written(), minimumCompressionPercentage);
        }
      }
      // try-with-resources will finish() via close() without closing the caller's OutputStream.
    }
    cos.flush();
    if (cos.written() > maxWriteLength) throw new CompressionOutputSizeException();
    return cos.written();
  }

  /**
   * Decompresses GZIP data from an {@link InputStream} to an {@link OutputStream} with strict
   * output size enforcement.
   *
   * <p>The method reads in 32&nbsp;KiB chunks. If a read produces more bytes than allowed by {@code
   * maxLength}, the behavior depends on {@code maxCheckSizeBytes}:
   *
   * <ul>
   *   <li>If {@code > 0}, it continues reading up to that many extra bytes to compute an estimated
   *       uncompressed size and throws {@link CompressionOutputSizeException} with the estimate.
   *   <li>Otherwise, it throws {@link CompressionOutputSizeException} without an estimate.
   * </ul>
   *
   * <p>Neither stream is closed by this method.
   *
   * @param is compressed source.
   * @param os destination for decompressed bytes.
   * @param maxLength maximum number of bytes allowed to be written to {@code os}.
   * @param maxCheckSizeBytes when {@code > 0}, number of additional bytes to read to estimate size
   *     after an overflow is detected.
   * @return number of decompressed bytes written to {@code os}.
   * @throws IOException on I/O errors. The specific subclass {@link CompressionOutputSizeException}
   *     (an {@link IOException}) is thrown if the output would exceed {@code maxLength}.
   */
  @Override
  public long decompress(InputStream is, OutputStream os, long maxLength, long maxCheckSizeBytes)
      throws IOException {
    // Wrap the input to avoid closing the caller-provided stream when we close the GZIP layer.
    try (GZIPInputStream gis = new GZIPInputStream(new NonClosingInputStream(is))) {
      long written = 0;
      int bufSize = 32768;
      if (maxLength > 0 && maxLength < bufSize) bufSize = (int) maxLength;
      byte[] buffer = new byte[bufSize];
      while (true) {
        int expectedBytesRead = (int) Math.min(buffer.length, maxLength - written);
        // Allow over-reading to detect overflow precisely; then handle it below.
        int bytesRead = gis.read(buffer, 0, buffer.length);
        if (expectedBytesRead < bytesRead) {
          LOG.info(
              "expectedBytesRead={}, bytesRead={}, written={}, maxLength={} throwing a"
                  + " CompressionOutputSizeException",
              expectedBytesRead,
              bytesRead,
              written,
              maxLength);
          handleOverRead(gis, buffer, bytesRead, maxLength, maxCheckSizeBytes, written);
        }
        if (bytesRead <= -1) {
          os.flush();
          return written;
        }
        if (bytesRead == 0) throw new IOException("Returned zero from read()");
        os.write(buffer, 0, bytesRead);
        written += bytesRead;
      }
    }
  }

  /**
   * Decompresses a GZIP byte array segment into a caller-provided buffer.
   *
   * <p>This convenience overload delegates to the stream-based {@link #decompress(InputStream,
   * OutputStream, long, long)} using in-memory streams and a maximum output length equal to {@code
   * output.length}.
   *
   * @param dbuf source buffer containing GZIP bytes.
   * @param i offset into {@code dbuf} where the GZIP payload starts.
   * @param j number of bytes to read from {@code dbuf}.
   * @param output destination buffer for uncompressed bytes; the method writes from index 0.
   * @return number of bytes written into {@code output}.
   * @throws CompressionOutputSizeException if the decompressed data would not fit into {@code
   *     output}.
   */
  @Override
  public int decompress(byte[] dbuf, int i, int j, byte[] output)
      throws CompressionOutputSizeException {
    // Using {@link java.util.zip.Inflater} directly proved unreliable for the expected framing;
    // stick to the GZIP streams to match the on-disk format and checks.
    try (ByteArrayInputStream bais = new ByteArrayInputStream(dbuf, i, j);
        ByteArrayOutputStream baos = new ByteArrayOutputStream(output.length)) {
      decompress(bais, baos, output.length, -1);
      int bytes = baos.size();
      byte[] buf = baos.toByteArray();
      System.arraycopy(buf, 0, output, 0, bytes);
      return bytes;
    } catch (IOException e) {
      // ByteArray streams should not throw; rethrow as a dedicated Error type to preserve behavior.
      throw new UnexpectedIOExceptionError("Got IOException: " + e.getMessage(), e);
    }
  }

  /**
   * Handles the case where a read returns more bytes than allowed by {@code maxLength}.
   *
   * <p>If {@code maxCheckSizeBytes} is greater than zero, the method will continue reading to
   * estimate the full uncompressed size and throw {@link CompressionOutputSizeException} with that
   * estimate. Otherwise, it throws the same exception without an estimated size. This method always
   * throws; it never returns normally.
   */
  private static void handleOverRead(
      GZIPInputStream gis,
      byte[] buffer,
      int firstBytesRead,
      long maxLength,
      long maxCheckSizeBytes,
      long previouslyWritten)
      throws IOException {
    long written = previouslyWritten;
    if (maxCheckSizeBytes > 0) {
      written += firstBytesRead;
      int bytesRead;
      // Read until EOF to estimate the uncompressed size; then throw with the estimate.
      while ((bytesRead =
              gis.read(
                  buffer,
                  0,
                  (int) Math.min(buffer.length, maxLength + maxCheckSizeBytes - written)))
          != -1) {
        if (bytesRead == 0) throw new IOException("Returned zero from read()");
        written += bytesRead;
      }
      throw new CompressionOutputSizeException(written);
    }
    throw new CompressionOutputSizeException();
  }

  /** OutputStream wrapper whose {@link #close()} does not close the underlying stream. */
  private static class NonClosingOutputStream extends FilterOutputStream {
    NonClosingOutputStream(OutputStream out) {
      super(out);
    }

    @Override
    public void close() throws IOException {
      flush();
      // do not close the underlying stream
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) throws IOException {
      out.write(b, off, len);
    }
  }

  /** InputStream wrapper whose {@link #close()} is a no-op to keep the underlying stream open. */
  @SuppressWarnings("java:S4929")
  private static class NonClosingInputStream extends FilterInputStream {
    NonClosingInputStream(InputStream in) {
      super(in);
    }

    @Override
    public void close() {
      // no-op: leave the underlying stream open
    }
  }

  /** Dedicated error used to signal unexpected IOExceptions from in-memory streams. */
  static final class UnexpectedIOExceptionError extends Error {
    @Serial private static final long serialVersionUID = 1L;

    UnexpectedIOExceptionError(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
