package network.crypta.support.compress;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstraction for single-file compression and decompression.
 *
 * <p>Implementations provide streaming compression algorithms such as GZIP, BZIP2, and LZMA
 * variants. This interface is intentionally scoped to single-file compression (e.g., gzip or bzip2)
 * and not to archive formats (e.g., zip, tar).
 *
 * <p>Unless specified otherwise, byte counts are in bytes and limits are inclusive. Implementations
 * may buffer internally. Input/output stream ownership and closing behavior is
 * implementation-specific. Stream closing/flush behavior is implementation-specific and should be
 * documented by concrete implementations; callers must not assume streams are closed.
 */
public interface Compressor {

  /**
   * Sentinel descriptor indicating the default compressor selection.
   *
   * <p>When passed to parsing utilities in {@link COMPRESSOR_TYPE}, a {@code null} descriptor (this
   * constant) means: use the default set of compressors in their preferred order. The default set
   * excludes the legacy {@code LZMA} codec, which is only accepted when explicitly requested as the
   * sole codec.
   */
  String DEFAULT_COMPRESSORDESCRIPTOR = null;

  /**
   * Supported compressor kinds and related utilities.
   *
   * <p>Each enum constant wraps a concrete {@link Compressor} and delegates all operations to it.
   * The enumeration also provides parsing helpers for user-provided descriptors.
   *
   * <p>Codecs are tried in declaration order; lighter-weight codecs should come first.
   *
   * <p><strong>Serialization note:</strong> Changing non-transient members of serializable classes
   * may restart downloads or invalidate previously stored uploads.
   */
  enum COMPRESSOR_TYPE implements Compressor {
    // Codecs will be tried in order; put the less resource-consuming first
    GZIP("GZIP", new GzipCompressor(), (short) 0),
    BZIP2("BZIP2", new Bzip2Compressor(), (short) 1),
    LZMA("LZMA", new OldLZMACompressor(), (short) 2),
    LZMA_NEW("LZMA_NEW", new NewLZMACompressor(), (short) 3);

    /**
     * Human-readable codec name used in descriptors. Distinct from {@link #name()}, the Java enum
     * identifier.
     */
    public final String codecName;

    /** Underlying implementation that performs the actual compression/decompression. */
    public final Compressor compressor;

    /** Short, stable identifier written to metadata and used on the wire. */
    public final short metadataID;

    /** Cached {@link #values()} array. Do not modify or expose outside this class. */
    private static final COMPRESSOR_TYPE[] values = values();

    private static final Logger LOG = LoggerFactory.getLogger(COMPRESSOR_TYPE.class);

    COMPRESSOR_TYPE(String name, Compressor c, short metadataID) {
      this.codecName = name;
      this.compressor = c;
      this.metadataID = metadataID;
    }

    /**
     * Look up a compressor by its {@link #metadataID}.
     *
     * @param id the short codec identifier
     * @return the matching compressor type, or {@code null} if none matches
     */
    public static COMPRESSOR_TYPE getCompressorByMetadataID(short id) {
      for (COMPRESSOR_TYPE current : values) if (current.metadataID == id) return current;
      return null;
    }

    /**
     * Look up a compressor by its {@link #codecName}.
     *
     * <p>Matching is case-sensitive.
     *
     * @param name codec name as it appears in descriptors (for example, {@code "GZIP"})
     * @return the matching compressor type, or {@code null} if none matches
     */
    public static COMPRESSOR_TYPE getCompressorByName(String name) {
      for (COMPRESSOR_TYPE current : values) {
        if (current.codecName.equals(name)) {
          return current;
        }
      }
      return null;
    }

    /**
     * Build a brief string describing available codecs for greeting/banner output.
     *
     * <p>Format: {@code <count> - <descriptor>}, where {@code <descriptor>} is the same string
     * produced by {@link #getCompressorDescriptor()}.
     *
     * @return human-readable description including the codec count
     */
    public static String getHelloCompressorDescriptor() {
      StringBuilder sb = new StringBuilder();
      sb.append(values.length);
      sb.append(" - ");
      getCompressorDescriptor(sb);
      return sb.toString();
    }

    /**
     * Build a descriptor listing all codecs.
     *
     * <p>Format: comma-separated {@code NAME(id)} entries in declaration order.
     *
     * @return human-readable descriptor of the available codecs
     */
    public static String getCompressorDescriptor() {
      StringBuilder sb = new StringBuilder();
      getCompressorDescriptor(sb);
      return sb.toString();
    }

    /**
     * Append the codec descriptor into the provided buffer.
     *
     * <p>Format: comma-separated {@code NAME(id)} entries in declaration order. The buffer is
     * appended to and not cleared.
     *
     * @param sb destination buffer; must not be {@code null}
     */
    public static void getCompressorDescriptor(StringBuilder sb) {
      boolean isfirst = true;
      for (COMPRESSOR_TYPE current : values) {
        if (isfirst) {
          isfirst = false;
        } else {
          sb.append(", ");
        }
        sb.append(current.codecName);
        sb.append('(');
        sb.append(current.metadataID);
        sb.append(')');
      }
    }

    /**
     * Parse a list of codecs from a descriptor string, falling back to defaults if necessary.
     *
     * <p>The descriptor is a comma-separated list whose entries are either codec names (as in
     * {@link #codecName}) or numeric {@link #metadataID} values. Duplicates are rejected. The
     * legacy {@code LZMA} codec is only accepted when it is the sole entry; otherwise it is ignored
     * with a warning.
     *
     * <p>If the input is {@code null} or blank, the default list is returned: all codecs except the
     * legacy {@code LZMA}, in declaration order.
     *
     * @param compressordescriptor descriptor string, or {@code null} for defaults
     * @return non-empty array of codecs to try, in order
     * @throws InvalidCompressionCodecException if an identifier is unknown or duplicated
     */
    public static COMPRESSOR_TYPE[] getCompressorsArray(String compressordescriptor)
        throws InvalidCompressionCodecException {
      COMPRESSOR_TYPE[] result = getCompressorsArrayNoDefault(compressordescriptor);
      if (result.length == 0) {
        // Build default list: exclude legacy LZMA silently; warn only when explicitly requested
        // via a non-default descriptor.
        COMPRESSOR_TYPE[] ret = new COMPRESSOR_TYPE[values.length - 1];
        int x = 0;
        for (COMPRESSOR_TYPE v : values) {
          if (v == LZMA) continue;
          ret[x++] = v;
        }
        result = ret;
      }
      return result;
    }

    /**
     * Parse a list of codecs from a descriptor string without applying defaults.
     *
     * <p>The descriptor is a comma-separated list whose entries are either codec names (as in
     * {@link #codecName}) or numeric {@link #metadataID} values. Duplicates are rejected. The
     * legacy {@code LZMA} codec is only accepted when it is the sole entry; otherwise it is ignored
     * with a warning.
     *
     * <p>If the input is {@code null} or blank, this method returns an empty array. Callers that
     * want the default list should use {@link #getCompressorsArray(String)}.
     *
     * @param compressordescriptor descriptor string, or {@code null}
     * @return array of codecs to try, possibly empty, preserving input order without duplicates
     * @throws InvalidCompressionCodecException if an identifier is unknown or duplicated
     */
    public static COMPRESSOR_TYPE[] getCompressorsArrayNoDefault(String compressordescriptor)
        throws InvalidCompressionCodecException {
      if (compressordescriptor == null || compressordescriptor.trim().isEmpty()) {
        // Return an empty array to comply with SL rule S1168; callers treat empty as default.
        return new COMPRESSOR_TYPE[0];
      }
      List<String> codecs = new ArrayList<>();
      int start = 0;
      for (int i = 0; i < compressordescriptor.length(); i++) {
        if (compressordescriptor.charAt(i) == ',') {
          codecs.add(compressordescriptor.substring(start, i));
          start = i + 1;
        }
      }
      if (start < compressordescriptor.length()) {
        codecs.add(compressordescriptor.substring(start));
      }
      java.util.LinkedHashSet<COMPRESSOR_TYPE> result =
          java.util.LinkedHashSet.newLinkedHashSet(codecs.size());
      for (String raw : codecs) {
        final String codec = raw.trim();
        final COMPRESSOR_TYPE ct = resolveCodec(codec);
        if (!result.add(ct)) {
          throw new InvalidCompressionCodecException(
              "Duplicate compression codec identifier: '" + codec + "'");
        }
        if (result.contains(COMPRESSOR_TYPE.LZMA)) {
          // OldLZMA should no longer be used. Only accept it if it is the only codec in the list.
          LOG.warn(
              "OldLZMA compression is buggy and no longer supported. It only exists to allow"
                  + " reinserting old keys.");
          if (result.size() > 1) {
            logLzmaOldRemovedWarning();
            result.remove(COMPRESSOR_TYPE.LZMA);
          }
        }
      }
      return result.toArray(new COMPRESSOR_TYPE[0]);
    }

    /**
     * Resolve a descriptor token to a codec type.
     *
     * <p>Tries name matching first, then parses a numeric {@code short} {@link #metadataID}. Logs
     * at debug level when the token is not numeric.
     *
     * @param token codec name or numeric identifier
     * @return resolved codec type
     * @throws InvalidCompressionCodecException if the token cannot be resolved
     */
    private static COMPRESSOR_TYPE resolveCodec(String token)
        throws InvalidCompressionCodecException {
      COMPRESSOR_TYPE ct = getCompressorByName(token);
      if (ct == null) {
        try {
          ct = getCompressorByMetadataID(Short.parseShort(token));
        } catch (NumberFormatException _) {
          // Not a numeric identifier; proceed to error below.
          LOG.debug("Not a numeric codec identifier: {}", token);
        }
      }
      if (ct == null) {
        throw new InvalidCompressionCodecException(
            "Unknown compression codec identifier: '" + token + "'");
      }
      return ct;
    }

    /** Log a specific warning when legacy {@code LZMA} is ignored in a mixed list. */
    private static void logLzmaOldRemovedWarning() {
      LOG.warn("Legacy 'LZMA' requested with other codecs; ignoring it. Use {}.", "LZMA_NEW");
    }

    @Override
    public Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
        throws IOException {
      return compressor.compress(data, bf, maxReadLength, maxWriteLength);
    }

    /** {@inheritDoc} */
    @Override
    public long compress(InputStream is, OutputStream os, long maxReadLength, long maxWriteLength)
        throws IOException {
      return compressor.compress(is, os, maxReadLength, maxWriteLength);
    }

    /** {@inheritDoc} */
    @Override
    public long compress(
        InputStream is,
        OutputStream os,
        long maxReadLength,
        long maxWriteLength,
        long amountOfDataToCheckCompressionRatio,
        int minimumCompressionPercentage)
        throws IOException, CompressionRatioException {
      return compressor.compress(
          is,
          os,
          maxReadLength,
          maxWriteLength,
          amountOfDataToCheckCompressionRatio,
          minimumCompressionPercentage);
    }

    /** {@inheritDoc} */
    @Override
    public long decompress(
        InputStream input, OutputStream output, long maxLength, long maxEstimateSizeLength)
        throws IOException {
      return compressor.decompress(input, output, maxLength, maxEstimateSizeLength);
    }

    /** {@inheritDoc} */
    @Override
    public int decompress(byte[] dbuf, int i, int j, byte[] output)
        throws CompressionOutputSizeException {
      return compressor.decompress(dbuf, i, j, output);
    }
  }

  /**
   * Compress data from a bucket into a newly created bucket.
   *
   * @param data The bucket to read from.
   * @param bf The factory used to create the output bucket.
   * @param maxReadLength The maximum number of bytes to read from the input bucket (bytes).
   * @param maxWriteLength The maximum number of bytes to write to the output bucket (bytes). If the
   *     limit is exceeded, an exception is thrown.
   * @return A bucket containing the compressed data, created via {@code bf}.
   * @throws IOException If an error occurs while reading or writing.
   * @throws CompressionOutputSizeException If the compressed data exceeds {@code maxWriteLength}.
   * @since 1
   */
  Bucket compress(Bucket data, BucketFactory bf, long maxReadLength, long maxWriteLength)
      throws IOException;

  /**
   * Compress data from an input stream to an output stream.
   *
   * @param input The stream to read from.
   * @param output The stream to write to.
   * @param maxReadLength The maximum number of bytes to read (bytes).
   * @param maxWriteLength The maximum number of bytes to write (bytes). If the limit is exceeded,
   *     an exception is thrown.
   * @return The number of bytes written to {@code output}.
   * @throws IOException If an error occurs while reading or writing.
   * @throws CompressionOutputSizeException If the compressed data exceeds {@code maxWriteLength}.
   *     Stream closing/flush behavior is implementation-specific.
   * @since 1
   */
  long compress(InputStream input, OutputStream output, long maxReadLength, long maxWriteLength)
      throws IOException;

  /**
   * Compress data with an optional minimum compression effectiveness check.
   *
   * <p>Equivalent to {@link #compress(InputStream, OutputStream, long, long)} with additional
   * parameters that validate the compression ratio after a given amount of input has been
   * processed.
   *
   * @param amountOfDataToCheckCompressionRatio The data amount after compression of which we will
   *     check whether the desired effect has been achieved (bytes processed).
   * @param minimumCompressionPercentage The minimal desired compression effect, %. A value of 0
   *     means that the compression effect will not be checked.
   * @return The number of bytes written to {@code output}.
   * @throws IOException If an error occurs while reading or writing.
   * @throws CompressionRatioException If the desired effectiveness is not achieved. The exact ratio
   *     computation is implementation-specific.
   * @since 1
   */
  long compress(
      InputStream input,
      OutputStream output,
      long maxReadLength,
      long maxWriteLength,
      long amountOfDataToCheckCompressionRatio,
      int minimumCompressionPercentage)
      throws IOException, CompressionRatioException;

  /**
   * Decompress data from an input stream to an output stream.
   *
   * @param input Where to read the data to decompress from.
   * @param output Where to write the final product to.
   * @param maxLength The maximum length to decompress; exceeding it causes an exception.
   * @param maxEstimateSizeLength If the data is too big and this is {@code > 0}, read up to this
   *     many bytes in order to try to get the data size.
   * @return Number of bytes written to {@code output}.
   * @throws IOException If an error occurs while reading or writing.
   * @throws CompressionOutputSizeException If the output exceeded a hard limit. Stream
   *     closing/flush behavior is implementation-specific.
   * @since 1
   */
  long decompress(
      InputStream input, OutputStream output, long maxLength, long maxEstimateSizeLength)
      throws IOException;

  /**
   * Decompress from a byte array into another byte array.
   *
   * @param dbuf Input buffer.
   * @param i Offset to start reading from.
   * @param j Number of bytes to read.
   * @param output Output buffer.
   * @return The number of bytes actually written to {@code output}.
   * @throws CompressionOutputSizeException If the decompressed size would exceed the output buffer
   *     capacity or another hard limit.
   * @since 1
   */
  int decompress(byte[] dbuf, int i, int j, byte[] output) throws CompressionOutputSizeException;
}
