package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.io.UnsupportedEncodingException;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.CountedInputStream;
import network.crypta.support.io.CountedOutputStream;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;

public class OldLZMACompressor implements Compressor {
  private static volatile boolean logMINOR;
  private static final String SIZE_SEP = " size ";

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
          }
        });
  }

  // Copied from EncoderThread. See below re licensing.
  /**
   * @deprecated since 2019-11-17: OldLZMA compression is buggy and unsupported; retained only to
   *     allow reinserting existing keys.
   */
  @Deprecated(since = "2019-11-17")
  @Override
  public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException {
    Logger.warning(
        this,
        "OldLZMA compression is buggy and no longer supported. It only exists to allow reinserting"
            + " keys.");
    Bucket output = bf.makeBucket(maxWriteLength);
    try (InputStream is = data.getInputStream();
        OutputStream os = output.getOutputStream()) {
      if (logMINOR)
        Logger.minor(
            this, "Compressing " + data + SIZE_SEP + data.size() + " to new bucket " + output);
      compress(is, os, maxReadLength, maxWriteLength);
    }
    return output;
  }

  /**
   * @deprecated since 2019-11-17: OldLZMA compression is buggy and unsupported; retained only to
   *     allow reinserting existing keys.
   */
  @Deprecated(since = "2019-11-17")
  @Override
  public long compress(InputStream is, OutputStream os, long maxReadLength, long maxWriteLength)
      throws IOException {
    Logger.warning(
        this,
        "OldLZMA compression is buggy and no longer supported. It only exists to allow reinserting"
            + " keys.");
    CountedInputStream cis;
    CountedOutputStream cos;
    cis = new CountedInputStream(is);
    cos = new CountedOutputStream(os);
    Encoder encoder = new Encoder();
    encoder.setEndMarkerMode(true);
    // Dictionary size 1MB, this is equivalent to lzma -4, it uses 16MB to compress and 2MB to
    // decompress.
    // Next one up is 2MB = -5 = 26M compress, 3M decompress.
    encoder.setDictionarySize(1 << 20);
    // Encoder properties corresponding to bytes: 5d 00 00 10 00
    encoder.code(cis, cos, null);
    if (logMINOR) Logger.minor(this, "Read " + cis.count() + " written " + cos.written());
    if (cos.written() > maxWriteLength) throw new CompressionOutputSizeException();
    cos.flush();
    return cos.written();
  }

  @Override
  public long compress(
      InputStream input,
      OutputStream output,
      long maxReadLength,
      long maxWriteLength,
      long amountOfDataToCheckCompressionRatio,
      int minimumCompressionPercentage)
      throws IOException {
    throw new UnsupportedEncodingException();
  }

  public Bucket decompress(
      Bucket data, BucketFactory bf, long maxLength, long maxCheckSizeLength, Bucket preferred)
      throws IOException {
    Bucket output;
    if (preferred != null) output = preferred;
    else output = bf.makeBucket(maxLength);
    if (logMINOR)
      Logger.minor(
          this, "Decompressing " + data + SIZE_SEP + data.size() + " to new bucket " + output);
    try (CountedInputStream is = new CountedInputStream(data.getInputStream());
        OutputStream os = output.getOutputStream()) {
      decompress(is, os, maxLength, maxCheckSizeLength);
      if (logMINOR)
        Logger.minor(this, "Output: " + output + SIZE_SEP + output.size() + " read " + is.count());
    }
    return output;
  }

  // Copied from DecoderThread
  // LICENSING: DecoderThread is LGPL 2.1/CPL according to comments.

  private static final int PROP_SIZE = 5;

  private static final byte[] PROPS = new byte[PROP_SIZE];

  static {
    // Decoder properties for EndMarkerMode=true and DictionarySize=1<<20
    PROPS[0] = 0x5d;
    PROPS[1] = 0x00;
    PROPS[2] = 0x00;
    PROPS[3] = 0x10;
    PROPS[4] = 0x00;
  }

  @Override
  public long decompress(InputStream is, OutputStream os, long maxLength, long maxCheckSizeBytes)
      throws IOException {
    CountedOutputStream cos = new CountedOutputStream(os);
    Decoder decoder = new Decoder();
    decoder.setDecoderProperties(PROPS);
    decoder.code(is, cos, maxLength);
    return cos.written();
  }

  @Override
  public int decompress(byte[] dbuf, int i, int j, byte[] output)
      throws CompressionOutputSizeException {
    // Didn't work with Inflater.
    // Note: previous attempt to use Inflater failed due to format compatibility.
    ByteArrayInputStream bais = new ByteArrayInputStream(dbuf, i, j);
    ByteArrayOutputStream baos = new ByteArrayOutputStream(output.length);
    int bytes;
    try {
      decompress(bais, baos, output.length, -1);
      bytes = baos.size();
    } catch (IOException e) {
      // Unexpected I/O in memory-only operation; propagate as a specific unchecked exception.
      throw new OldLZMADecompressionException(
          "I/O during LZMA decompression: " + e.getMessage(), e);
    }
    byte[] buf = baos.toByteArray();
    System.arraycopy(buf, 0, output, 0, bytes);
    return bytes;
  }

  private static final class OldLZMADecompressionException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

    OldLZMADecompressionException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
