package network.crypta.support.compress;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Base implementation of {@link Compressor} providing shared utilities and a convenience overload.
 * This class supplies the four-argument {@code compress(...)} method which delegates to the full
 * six-argument variant with compression-ratio checking disabled.
 *
 * <p>Implementations in this package may use {@link #checkCompressionEffect(long, long, int)} to
 * validate that compression achieves a caller-specified minimum percentage.
 *
 * <p>Thread-safety: implementation-specific; callers should not assume concurrent safety unless
 * documented by the concrete compressor.
 */
abstract class AbstractCompressor implements Compressor {

  /**
   * Compresses data from an input stream to an output stream without enforcing a minimum
   * compression ratio.
   *
   * <p>This overload delegates to {@link Compressor#compress(InputStream, OutputStream, long, long,
   * long, int)} with {@code amountOfDataToCheckCompressionRatio = Long.MAX_VALUE} and {@code
   * minimumCompressionPercentage = 0}, which disables ratio checks. Implementations may still
   * enforce size limits via {@code maxWriteLength}.
   *
   * <p>Streams are not closed by this method; the caller remains responsible for closing {@code
   * input} and {@code output}.
   *
   * @param input the stream to read, in bytes; not closed by this method
   * @param output the stream to write the compressed data to; not closed by this method
   * @param maxReadLength maximum number of bytes to read from {@code input}; must be non-negative
   * @param maxWriteLength maximum number of bytes allowed to be written to {@code output}; must be
   *     non-negative
   * @return the number of compressed bytes written to {@code output}
   * @throws IOException on I/O errors; the specific subclass {@link CompressionOutputSizeException}
   *     may be thrown if {@code maxWriteLength} is exceeded
   */
  public long compress(
      InputStream input, OutputStream output, long maxReadLength, long maxWriteLength)
      throws IOException {
    try {
      return compress(input, output, maxReadLength, maxWriteLength, Long.MAX_VALUE, 0);
    } catch (CompressionRatioException e) {
      // Ratio check is disabled (minimumCompressionPercentage = 0), so this should be
      // unreachable per the contract of the 6‑argument compress().
      throw new IllegalStateException(e);
    }
  }

  /**
   * Validates that the achieved compression is at least the requested minimum.
   *
   * <p>The achieved percentage is computed as {@code 100 - (compressed * 100 / raw)} using integer
   * arithmetic (truncating division). The method throws when the computed percentage is strictly
   * less than {@code minimumCompressionPercentage}.
   *
   * <p>Preconditions: {@code rawDataVolume != 0} and {@code minimumCompressionPercentage != 0}.
   * Callers typically skip the check entirely when the requested minimum is {@code 0}.
   *
   * @param rawDataVolume number of input bytes examined for the check; must be non-zero
   * @param compressedDataVolume number of output bytes corresponding to {@code rawDataVolume}
   * @param minimumCompressionPercentage lower bound on acceptable compression, in percent (0–100)
   * @throws CompressionRatioException if the achieved compression is below the requested minimum
   */
  void checkCompressionEffect(
      long rawDataVolume, long compressedDataVolume, int minimumCompressionPercentage)
      throws CompressionRatioException {
    // Guard against divide-by-zero and meaningless checks; enforced by callers in this package.
    assert rawDataVolume != 0;
    assert minimumCompressionPercentage != 0;

    long compressionPercentage = 100 - compressedDataVolume * 100 / rawDataVolume;
    if (compressionPercentage < minimumCompressionPercentage) {
      throw new CompressionRatioException(
          "Compression has no effect. Compression percentage: " + compressionPercentage);
    }
  }
}
