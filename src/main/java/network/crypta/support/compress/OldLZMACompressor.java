package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.io.UnsupportedEncodingException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.CountedInputStream;
import network.crypta.support.io.CountedOutputStream;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Legacy LZMA compressor retained solely for reinserting historical data.
 *
 * <p>This implementation mirrors the old “LZMA” behavior used in earlier versions of the node. It
 * is intentionally marked as deprecated and kept only for compatibility with already-published
 * content. New code should use {@link NewLZMACompressor} (a.k.a. {@code LZMA_NEW}).
 *
 * <h2>Behavioral notes</h2>
 *
 * <ul>
 *   <li>Compression uses a fixed dictionary size of {@code 1 << 20} (approximately 1 MiB), which
 *       corresponds to the legacy “lzma -4” setting. This class does not write Coder properties to
 *       the output stream.
 *   <li>The {@code maxReadLength} parameter of the stream-based {@code compress} overload is not
 *       enforced; input is read until the end of stream.
 *   <li>{@code maxWriteLength} is enforced only after compression completes (a post-writing check).
 *       If it is exceeded, a {@link CompressionOutputSizeException} is thrown and the output stream
 *       may already contain more data than the configured limit.
 *   <li>Decompression uses a fixed property array equivalent to the legacy encoder properties bytes
 *       {@code 5d 00 00 10 00}. The reader does not expect coder properties in the stream itself.
 *   <li>Instances are stateless and safe to use from multiple threads as long as the caller does
 *       not share the provided streams/buckets unsafely.
 *   <li>Unless otherwise documented, these methods do not close the caller-provided streams.
 *       Bucket-based methods manage their own bucket I/O streams via try-with-resources.
 * </ul>
 */
public class OldLZMACompressor implements Compressor {
  private static final Logger LOG = LoggerFactory.getLogger(OldLZMACompressor.class);

  private static final String SIZE_SEP = " size ";

  // Copied from the historical EncoderThread implementation (licensing noted below).
  /**
   * Compresses a bucket using the legacy LZMA settings.
   *
   * <p>This overload creates an output bucket via the supplied {@link BucketFactory} and writes the
   * compressed data into it. It logs a compatibility warning on each call.
   *
   * @param data input bucket; must not be {@code null}
   * @param bf factory used to construct the output bucket; must not be {@code null}
   * @param maxReadLength upper bound on the number of bytes to read from {@code data} (bytes). This
   *     implementation does not enforce the bound and will read until EOF.
   * @param maxWriteLength upper bound on the number of bytes to write (bytes). The check is applied
   *     after compression finishes; if exceeded, an exception is thrown and the output may already
   *     contain more than {@code maxWriteLength} bytes.
   * @return a bucket containing the compressed output
   * @throws IOException if reading or writing fails
   * @throws CompressionOutputSizeException if the post-write size check detects an overflow
   */
  @Override
  public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException {
    LOG.warn(
        "OldLZMA compression is buggy and no longer supported. It only exists to allow reinserting"
            + " keys.");
    Bucket output = bf.makeBucket(maxWriteLength);
    try (InputStream is = data.getInputStream();
        OutputStream os = output.getOutputStream()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Compressing {}" + SIZE_SEP + "{} to new bucket {}", data, data.size(), output);
      compress(is, os, maxReadLength, maxWriteLength);
    }
    return output;
  }

  /**
   * Compresses data from an input stream to an output stream using the legacy LZMA settings.
   *
   * <p>Dictionary size is fixed to {@code 1 << 20}. This class does not write encoder properties to
   * the output. The caller remains responsible for closing the provided streams.
   *
   * @param is input stream; must not be {@code null}
   * @param os output stream; must not be {@code null}
   * @param maxReadLength upper bound on bytes to read (bytes). This implementation does not enforce
   *     the bound and will read until EOF.
   * @param maxWriteLength upper bound on bytes to write (bytes). The limit is checked only after
   *     compression completes.
   * @return number of bytes written to {@code os}
   * @throws IOException if I/O fails
   * @throws CompressionOutputSizeException if the post-write size check detects an overflow
   */
  @Override
  public long compress(InputStream is, OutputStream os, long maxReadLength, long maxWriteLength)
      throws IOException {
    LOG.warn(
        "OldLZMA compression is buggy and no longer supported. It only exists to allow reinserting"
            + " keys.");
    CountedInputStream cis;
    CountedOutputStream cos;
    cis = new CountedInputStream(is);
    cos = new CountedOutputStream(os);
    Encoder encoder = new Encoder();
    encoder.setEndMarkerMode(true);
    /*
     * Use a 1 MiB dictionary (legacy “lzma -4”): roughly ~16 MiB memory to compress and ~2 MiB to
     * decompress. The next step (2 MiB, “-5”) would increase memory to ~26 MiB / ~3 MiB.
     */
    encoder.setDictionarySize(1 << 20);
    // Historical encoder properties equivalent to the decoder's fixed PROPS: 5d 00 00 10 00
    encoder.code(cis, cos, null);
    if (LOG.isDebugEnabled()) LOG.debug("Read {} written {}", cis.count(), cos.written());
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
    // This legacy compressor does not implement ratio checking.
    throw new UnsupportedEncodingException();
  }

  /**
   * Decompresses from a bucket into a (possibly provided) output bucket.
   *
   * <p>If {@code preferred} is not {@code null}, it is used as the destination; otherwise, a new
   * bucket is created via {@code bf}. This method manages bucket I/O streams internally and closes
   * them via try-with-resources.
   *
   * @param data input bucket containing legacy LZMA data
   * @param bf bucket factory used when {@code preferred} is {@code null}
   * @param maxLength maximum decompressed size to request from the decoder (bytes)
   * @param maxCheckSizeLength reserved parameter for legacy callers; see historical code
   * @param preferred optional destination bucket
   * @return the output bucket (either {@code preferred} or a newly created one)
   * @throws IOException if I/O fails
   */
  public Bucket decompress(
      Bucket data, BucketFactory bf, long maxLength, long maxCheckSizeLength, Bucket preferred)
      throws IOException {
    Bucket output;
    if (preferred != null) output = preferred;
    else output = bf.makeBucket(maxLength);
    if (LOG.isDebugEnabled())
      LOG.debug("Decompressing {}" + SIZE_SEP + "{} to new bucket {}", data, data.size(), output);
    try (CountedInputStream is = new CountedInputStream(data.getInputStream());
        OutputStream os = output.getOutputStream()) {
      decompress(is, os, maxLength, maxCheckSizeLength);
      if (LOG.isDebugEnabled())
        LOG.debug("Output: {}" + SIZE_SEP + "{} read {}", output, output.size(), is.count());
    }
    return output;
  }

  // Copied from the historical DecoderThread.
  // LICENSING NOTE: DecoderThread was distributed under LGPL 2.1 / CPL, according to its header.

  private static final int PROP_SIZE = 5;

  private static final byte[] PROPS = new byte[PROP_SIZE];

  static {
    // Decoder properties for EndMarkerMode=true and DictionarySize=1<<20.
    // These constants mirror the legacy encoder configuration and are not read from the stream.
    PROPS[0] = 0x5d;
    PROPS[1] = 0x00;
    PROPS[2] = 0x00;
    PROPS[3] = 0x10;
    PROPS[4] = 0x00;
  }

  @Override
  public long decompress(InputStream is, OutputStream os, long maxLength, long maxCheckSizeBytes)
      throws IOException {
    // Wrap the output to count bytes for the caller; the wrapper does not close {@code os}.
    CountedOutputStream cos = new CountedOutputStream(os);
    Decoder decoder = new Decoder();
    decoder.setDecoderProperties(PROPS);
    decoder.code(is, cos, maxLength);
    return cos.written();
  }

  @Override
  public int decompress(byte[] dbuf, int i, int j, byte[] output)
      throws CompressionOutputSizeException {
    // Historical note: using {@code java.util.zip.Inflater} is not applicable to the LZMA format.
    ByteArrayInputStream bais = new ByteArrayInputStream(dbuf, i, j);
    ByteArrayOutputStream baos = new ByteArrayOutputStream(output.length);
    int bytes;
    try {
      decompress(bais, baos, output.length, -1);
      bytes = baos.size();
    } catch (IOException e) {
      // Propagate an unexpected I/O failure from a memory-only operation using a dedicated type.
      throw new OldLZMADecompressionException(
          "I/O during LZMA decompression: " + e.getMessage(), e);
    }
    byte[] buf = baos.toByteArray();
    /*
     * Copy the decompressed bytes into the caller-provided buffer. If {@code bytes} exceeds
     * {@code output.length}, the array copy will throw {@link ArrayIndexOutOfBoundsException}.
     * Callers should size the buffer conservatively.
     */
    System.arraycopy(buf, 0, output, 0, bytes);
    return bytes;
  }

  /**
   * Unchecked exception signaling an unexpected I/O failure during in‑memory decompression.
   *
   * <p>Used by {@link #decompress(byte[], int, int, byte[])} to wrap {@link IOException} thrown by
   * the stream-based decompressor.
   */
  private static final class OldLZMADecompressionException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

    OldLZMADecompressionException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
