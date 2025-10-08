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
import org.sevenzip.ICodeProgress;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NewLZMACompressor extends AbstractCompressor {
  private static final Logger LOG = LoggerFactory.getLogger(NewLZMACompressor.class);

  // Dictionary size 1MB, this is equivalent to lzma -4, it uses 16MB to compress and 2MB to
  // decompress.
  // Next one up is 2MB = -5 = 26M compress, 3M decompress.
  static final int MAX_DICTIONARY_SIZE = 1 << 20;

  private static final String SIZE_LITERAL = " size ";

  static {
  }

  // Copied from EncoderThread. See below re licensing.
  @Override
  public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException {
    Bucket output = bf.makeBucket(maxWriteLength);
    try (InputStream is = data.getInputStream();
        OutputStream os = output.getOutputStream()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Compressing " + data + SIZE_LITERAL + data.size() + " to new bucket " + output);
      compress(is, os, maxReadLength, maxWriteLength);
    }
    return output;
  }

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
    CountedInputStream cis = createCountedInputStream(is, maxReadLength);
    CountedOutputStream cos = createCountedOutputStream(os, maxWriteLength);

    Encoder encoder = new Encoder();
    encoder.setEndMarkerMode(true);
    encoder.setDictionarySize(selectDictionarySize(maxReadLength));
    // Coder properties are part of the output stream and must count toward the
    // maxWriteLength constraint; write them through the bounded stream.
    encoder.writeCoderProperties(cos);

    ICodeProgress progress =
        createProgressChecker(amountOfDataToCheckCompressionRatio, minimumCompressionPercentage);
    runEncoder(encoder, cis, cos, progress);
    if (maxWriteLength >= 0 && cos.written() > maxWriteLength)
      throw new CompressionOutputSizeException(cos.written());
    cos.flush();
    if (LOG.isDebugEnabled()) LOG.debug("Read " + cis.count() + " written " + cos.written());
    return cos.written();
  }

  private CountedInputStream createCountedInputStream(InputStream is, long maxReadLength) {
    return (maxReadLength >= 0 && maxReadLength != Long.MAX_VALUE)
        ? new BoundedInputStream(is, maxReadLength)
        : new CountedInputStream(is);
  }

  private CountedOutputStream createCountedOutputStream(OutputStream os, long maxWriteLength) {
    return (maxWriteLength >= 0 && maxWriteLength != Long.MAX_VALUE)
        ? new BoundedOutputStream(os, maxWriteLength)
        : new CountedOutputStream(os);
  }

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
            // Wrap to escape through foreign API with a dedicated unchecked type.
            throw new ProgressAbortException(e);
          }
          compressionEffectShouldBeChecked = false;
        }
      }
    };
  }

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

  /** Input stream wrapper that stops reading after {@code max} bytes have been returned. */
  private static final class BoundedInputStream extends CountedInputStream {
    private final long max;

    // This wrapper does not maintain explicit EOF flags.

    BoundedInputStream(InputStream in, long max) {
      super(in);
      if (max < 0) throw new IllegalArgumentException("maxReadLength < 0");
      this.max = max;
    }

    @Override
    public int read() throws IOException {
      if (count() < max) return super.read();
      // We are at the limit; determine whether the underlying stream has more data.
      int next = in.read();
      if (next == -1) {
        return -1; // true EOF coincides with limit
      }
      throw new CompressionInputSizeException(max);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      long remaining = max - count();
      if (remaining > 0) {
        int toRead = (int) Math.min(len, remaining);
        return super.read(b, off, toRead);
      }
      // No remaining budget: check if there is more data beyond the limit.
      int next = in.read();
      if (next == -1) {
        return -1;
      }
      throw new CompressionInputSizeException(max);
    }

    @Override
    public int read(byte[] b) throws IOException {
      long remaining = max - count();
      if (remaining > 0) {
        int toRead = (int) Math.min(b.length, remaining);
        return super.read(b, 0, toRead);
      }
      int next = in.read();
      if (next == -1) {
        return -1;
      }
      throw new CompressionInputSizeException(max);
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
    public void write(byte[] b, int off, int len) throws IOException {
      if (len < 0) throw new ArrayIndexOutOfBoundsException(len);
      if (written() + len > max) throw new CompressionOutputSizeException(written() + len);
      super.write(b, off, len);
    }
  }

  public Bucket decompress(
      Bucket data, BucketFactory bf, long maxLength, long maxCheckSizeLength, Bucket preferred)
      throws IOException {
    Bucket output;
    if (preferred != null) output = preferred;
    else output = bf.makeBucket(maxLength);
    if (LOG.isDebugEnabled())
      LOG.debug("Decompressing " + data + SIZE_LITERAL + data.size() + " to new bucket " + output);
    try (CountedInputStream is = new CountedInputStream(data.getInputStream());
        OutputStream os = output.getOutputStream()) {
      decompress(is, os, maxLength, maxCheckSizeLength);
      if (LOG.isDebugEnabled())
        LOG.debug("Output: " + output + SIZE_LITERAL + output.size() + " read " + is.count());
    }
    return output;
  }

  @Override
  public long decompress(InputStream is, OutputStream os, long maxLength, long maxCheckSizeBytes)
      throws IOException {
    byte[] props = new byte[5];
    DataInputStream dis = new DataInputStream(is);
    dis.readFully(props);
    CountedOutputStream cos = new CountedOutputStream(os);

    int dictionarySize = 0;
    for (int i = 0; i < 4; i++) dictionarySize += ((props[1 + i]) & 0xFF) << (i * 8);

    if (dictionarySize < 0) throw new InvalidCompressedDataException("Invalid dictionary size");
    if (dictionarySize > MAX_DICTIONARY_SIZE) throw new TooBigDictionaryException();
    Decoder decoder = new Decoder();
    if (!decoder.setDecoderProperties(props))
      throw new InvalidCompressedDataException("Invalid properties");
    decoder.code(is, cos, maxLength);
    return cos.written();
  }

  @Override
  public int decompress(byte[] dbuf, int i, int j, byte[] output)
      throws CompressionOutputSizeException {
    // Note: Using Inflater is not applicable here due to LZMA format specifics.
    ByteArrayInputStream bais = new ByteArrayInputStream(dbuf, i, j);
    ByteArrayOutputStream baos = new ByteArrayOutputStream(output.length);
    int bytes;
    try {
      decompress(bais, baos, output.length, -1);
      bytes = baos.size();
    } catch (IOException e) {
      // Unexpected I/O, wrap in a more specific unchecked exception.
      throw new UncheckedIOException("Unexpected I/O during LZMA decompression", e);
    }
    byte[] buf = baos.toByteArray();
    System.arraycopy(buf, 0, output, 0, bytes);
    return bytes;
  }
}
