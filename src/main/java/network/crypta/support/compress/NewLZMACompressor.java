package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.CountedInputStream;
import network.crypta.support.io.CountedOutputStream;
import org.jetbrains.annotations.NotNull;
import org.sevenzip.ICodeProgress;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LZMA compressor/decompressor using the 7-Zip reference implementation.
 *
 * <p>This implementation writes the standard 5-byte LZMA coder properties at the beginning of the
 * compressed stream and enables the end-marker mode. During compression, it enforces
 * caller-provided read and write budgets via counting wrappers. The dictionary size is derived from
 * the expected input size and is capped at {@link #MAX_DICTIONARY_SIZE}.
 *
 * <p>Instances are lightweight and reusable. This class keeps no mutable shared state; each call
 * creates fresh encoder/decoder objects.
 */
public class NewLZMACompressor extends AbstractCompressor {
  private static final Logger LOG = LoggerFactory.getLogger(NewLZMACompressor.class);

  // Max dictionary size: 1 MiB (approximately "lzma -4").
  // Rough resource guide: ~16 MiB to compress, ~2 MiB to decompress at this size.
  // The next preset (2 MiB, similar to "-5") increases usage to ~26 MiB / ~3 MiB.
  static final int MAX_DICTIONARY_SIZE = 1 << 20;

  private static final String SIZE_LITERAL = " size ";

  // Compression entry point adapted from historical EncoderThread patterns in this codebase.
  @Override
  public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException {
    Bucket output = bf.makeBucket(maxWriteLength);
    try (InputStream is = data.getInputStream();
        OutputStream os = output.getOutputStream()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Compressing {}" + SIZE_LITERAL + "{} to new bucket {}", data, data.size(), output);
      compress(is, os, maxReadLength, maxWriteLength);
    }
    return output;
  }

  /**
   * Compresses data from a stream to a stream with optional effectiveness checks.
   *
   * <p>The method writes the 5-byte LZMA properties, then the compressed payload, and flushes the
   * output. It enforces the supplied maximum read and write lengths strictly.
   *
   * @param is source of raw data; not closed by this method
   * @param os destination for compressed data; not closed by this method
   * @param maxReadLength hard upper bound in bytes on how much to read; negative values and {@link
   *     Long#MAX_VALUE} imply no bound and select the maximum dictionary size
   * @param maxWriteLength hard upper bound in bytes on how much may be written; negative values and
   *     {@link Long#MAX_VALUE} imply no explicit bound
   * @param amountOfDataToCheckCompressionRatio number of input bytes after which to evaluate the
   *     compression ratio using {@link #checkCompressionEffect(long, long, int)}
   * @param minimumCompressionPercentage minimum acceptable compression percentage; {@code 0}
   *     disables the check
   * @return number of bytes written to {@code os}
   * @throws IOException on I/O errors
   * @throws CompressionRatioException if the compression ratio check fails
   */
  @Override
  public long compress(
      InputStream is,
      OutputStream os,
      long maxReadLength,
      long maxWriteLength,
      final long amountOfDataToCheckCompressionRatio,
      final int minimumCompressionPercentage)
      throws IOException, CompressionRatioException {
    // Enforce caller-provided read/write limits during compression.
    CountedInputStream countedInput = new CountedInputStream(is);
    InputStream encoderInput =
        (maxReadLength >= 0 && maxReadLength != Long.MAX_VALUE)
            ? new BoundedInputStream(countedInput, maxReadLength)
            : countedInput;
    CountedOutputStream cos = createCountedOutputStream(os, maxWriteLength);

    // Configure the encoder. An end-marker allows decoding without a known uncompressed length.
    Encoder encoder = new Encoder();
    encoder.setEndMarkerMode(true);
    encoder.setDictionarySize(selectDictionarySize(maxReadLength));
    // Coder properties must count toward the maxWriteLength; therefore write through the bounded
    // output.
    encoder.writeCoderProperties(cos);

    ICodeProgress progress =
        createProgressChecker(amountOfDataToCheckCompressionRatio, minimumCompressionPercentage);
    runEncoder(encoder, encoderInput, cos, progress);
    if (maxWriteLength >= 0 && cos.written() > maxWriteLength)
      throw new CompressionOutputSizeException(cos.written());
    cos.flush();
    if (LOG.isDebugEnabled()) LOG.debug("Read {} written {}", countedInput.count(), cos.written());
    return cos.written();
  }

  /* Select a counting output wrapper. A bounded variant throws on overflow; a plain
   * {@link CountedOutputStream} is used otherwise. */
  private CountedOutputStream createCountedOutputStream(OutputStream os, long maxWriteLength) {
    return (maxWriteLength >= 0 && maxWriteLength != Long.MAX_VALUE)
        ? new BoundedOutputStream(os, maxWriteLength)
        : new CountedOutputStream(os);
  }

  /*
   * Choose a power-of-two dictionary size based on the expected input length, capped at
   * {@link #MAX_DICTIONARY_SIZE}. When the expected length is unknown, fall back to the maximum
   * size and log (at error level) to surface the inefficiency.
   */
  private int selectDictionarySize(long maxReadLength) {
    int dictionarySize = 1;
    if (maxReadLength == Long.MAX_VALUE || maxReadLength < 0) {
      dictionarySize = MAX_DICTIONARY_SIZE;
      LOG.error(
          "No indication of size, having to use maximum dictionary size", new Exception("debug"));
    } else {
      while (dictionarySize < maxReadLength && dictionarySize < MAX_DICTIONARY_SIZE) {
        dictionarySize <<= 1;
      }
    }
    return dictionarySize;
  }

  /* Create a progress callback that triggers a one-time compression-effect check. The check wraps
   * {@link CompressionRatioException} into a runtime exception so the foreign encoder API can
   * abort. */
  private ICodeProgress createProgressChecker(
      final long amountOfDataToCheckCompressionRatio, final int minimumCompressionPercentage) {
    return new ICodeProgress() {
      boolean compressionEffectShouldBeChecked = minimumCompressionPercentage != 0;

      @Override
      public void setProgress(long processedInSize, long processedOutSize) {
        if (compressionEffectShouldBeChecked
            && processedInSize > amountOfDataToCheckCompressionRatio) {
          try {
            checkCompressionEffect(processedInSize, processedOutSize, minimumCompressionPercentage);
          } catch (CompressionRatioException e) {
            // Wrap to escape through the foreign API with a dedicated unchecked type.
            throw new ProgressAbortException(e);
          }
          compressionEffectShouldBeChecked = false;
        }
      }
    };
  }

  /* Run the encoder and rethrow an underlying {@link CompressionRatioException} if the progress
   * callback aborted the encoding. */
  private void runEncoder(
      Encoder encoder, InputStream input, CountedOutputStream output, ICodeProgress progress)
      throws IOException, CompressionRatioException {
    try {
      encoder.code(input, output, progress);
    } catch (RuntimeException e) {
      if (e.getCause() instanceof CompressionRatioException compressionRatioException) {
        throw compressionRatioException;
      }
      throw e;
    }
  }

  private static final class ProgressAbortException extends RuntimeException {
    ProgressAbortException(Throwable cause) {
      super(cause);
    }
  }

  /**
   * Input stream wrapper that stops reading after the configured number of bytes.
   *
   * <p>When the underlying stream contains more data than {@code max}, the wrapper throws {@link
   * CompressionInputSizeException} as soon as it can determine the overflow (on the first extra
   * byte). If the underlying stream ends exactly at {@code max}, read methods return {@code -1}.
   */
  private static final class BoundedInputStream extends InputStream {
    private final long max;
    private final CountedInputStream delegate;

    // This wrapper does not maintain explicit EOF flags; it probes the delegate as needed.

    BoundedInputStream(CountedInputStream in, long max) {
      if (max < 0) throw new IllegalArgumentException("maxReadLength < 0");
      this.max = max;
      this.delegate = in;
    }

    @Override
    public int read() throws IOException {
      if (delegate.count() < max) return delegate.read();
      // At the limit: probe one extra byte to distinguish true EOF from overflow.
      int next = delegate.read();
      if (next == -1) {
        return -1; // true EOF
      }
      throw new CompressionInputSizeException(max);
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) throws IOException {
      long remaining = max - delegate.count();
      if (remaining > 0) {
        int toRead = (int) Math.min(len, remaining);
        return delegate.read(b, off, toRead);
      }
      // No remaining budget: check whether there is more data beyond the limit.
      int next = delegate.read();
      if (next == -1) {
        return -1;
      }
      throw new CompressionInputSizeException(max);
    }

    @Override
    public int read(byte @NotNull [] b) throws IOException {
      long remaining = max - delegate.count();
      if (remaining > 0) {
        int toRead = (int) Math.min(b.length, remaining);
        return delegate.read(b, 0, toRead);
      }
      int next = delegate.read();
      if (next == -1) {
        return -1;
      }
      throw new CompressionInputSizeException(max);
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }
  }

  /** Output stream wrapper that throws when more than {@code max} bytes are written. */
  private static final class BoundedOutputStream extends CountedOutputStream {
    private final long max;

    BoundedOutputStream(OutputStream out, long max) {
      super(out);
      if (max < 0) throw new IllegalArgumentException("maxWriteLength < 0");
      this.max = max;
    }

    @Override
    public void write(int b) throws IOException {
      if (written() + 1 > max) throw new CompressionOutputSizeException(written() + 1);
      super.write(b);
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) throws IOException {
      if (len < 0) throw new ArrayIndexOutOfBoundsException(len);
      if (written() + len > max) throw new CompressionOutputSizeException(written() + len);
      super.write(b, off, len);
    }
  }

  /**
   * Decompresses data from a bucket into a new or preferred bucket.
   *
   * <p>The method uses a counting input to report the number of bytes consumed for diagnostics. If
   * {@code preferred} is non-{@code null}, decompressed data is written into it; otherwise a new
   * bucket is created via {@code bf}.
   *
   * @param data compressed data source
   * @param bf factory to create the destination when {@code preferred} is {@code null}
   * @param maxLength hard upper bound in bytes on the decompressed size; passed to the decoder
   * @param maxCheckSizeLength not used by LZMA; retained for interface parity
   * @param preferred optional destination bucket to reuse
   * @return the destination bucket that received the decompressed data
   * @throws IOException on I/O errors
   */
  public Bucket decompress(
      Bucket data, BucketFactory bf, long maxLength, long maxCheckSizeLength, Bucket preferred)
      throws IOException {
    Bucket output;
    if (preferred != null) output = preferred;
    else output = bf.makeBucket(maxLength);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Decompressing {}" + SIZE_LITERAL + "{} to new bucket {}", data, data.size(), output);
    try (CountedInputStream is = new CountedInputStream(data.getInputStream());
        OutputStream os = output.getOutputStream()) {
      decompress(is, os, maxLength, maxCheckSizeLength);
      if (LOG.isDebugEnabled())
        LOG.debug("Output: {}" + SIZE_LITERAL + "{} read {}", output, output.size(), is.count());
    }
    return output;
  }

  /**
   * Decompresses LZMA data from a stream to a stream.
   *
   * <p>Expects the first five bytes to be the LZMA properties. Validates the dictionary size and
   * decoder properties prior to decoding. The {@code maxLength} parameter is passed to the decoder
   * to limit the amount of produced data.
   *
   * @param is source stream containing the LZMA frame (properties + payload)
   * @param os destination stream for uncompressed bytes
   * @param maxLength maximum number of bytes the decoder may emit
   * @param maxCheckSizeBytes reserved for future checks; currently unused by this implementation
   * @return number of bytes written to {@code os}
   * @throws IOException on I/O errors
   * @throws InvalidCompressedDataException if properties are malformed or dictionary size is
   *     negative
   * @throws TooBigDictionaryException if the dictionary exceeds {@link #MAX_DICTIONARY_SIZE}
   */
  @Override
  public long decompress(InputStream is, OutputStream os, long maxLength, long maxCheckSizeBytes)
      throws IOException {
    byte[] props = new byte[5];
    DataInputStream dis = new DataInputStream(is);
    dis.readFully(props);
    CountedOutputStream cos = new CountedOutputStream(os);

    int dictionarySize = 0;
    for (int i = 0; i < 4; i++) dictionarySize += (props[1 + i] & 0xFF) << (i * 8);

    if (dictionarySize < 0) throw new InvalidCompressedDataException("Invalid dictionary size");
    if (dictionarySize > MAX_DICTIONARY_SIZE) throw new TooBigDictionaryException();
    Decoder decoder = new Decoder();
    if (!decoder.setDecoderProperties(props))
      throw new InvalidCompressedDataException("Invalid properties");
    decoder.code(is, cos, maxLength);
    return cos.written();
  }

  /**
   * Decompresses an in-memory LZMA buffer into a provided output buffer.
   *
   * <p>This is a convenience wrapper around the streaming {@link #decompress(InputStream,
   * OutputStream, long, long)} method. The method throws {@link UncheckedIOException} when the
   * underlying streaming call fails with an {@link IOException}.
   *
   * @param dbuf input buffer containing the LZMA frame
   * @param i start offset within {@code dbuf}
   * @param j number of bytes to read from {@code dbuf}
   * @param output destination buffer; must be large enough to hold the decompressed data
   * @return number of bytes written into {@code output}
   * @throws CompressionOutputSizeException if the decompressed size would exceed {@code output}
   */
  @Override
  public int decompress(byte[] dbuf, int i, int j, byte[] output)
      throws CompressionOutputSizeException {
    // Note: java.util.zip.Inflater does not apply to LZMA bitstream format.
    ByteArrayInputStream bais = new ByteArrayInputStream(dbuf, i, j);
    ByteArrayOutputStream baos = new ByteArrayOutputStream(output.length);
    int bytes;
    try {
      decompress(bais, baos, output.length, -1);
      bytes = baos.size();
    } catch (IOException e) {
      // Propagate as a more precise unchecked exception for convenience in array-based callers.
      throw new UncheckedIOException("Unexpected I/O during LZMA decompression", e);
    }
    byte[] buf = baos.toByteArray();
    System.arraycopy(buf, 0, output, 0, bytes);
    return bytes;
  }
}
