package network.crypta.keys;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.CryptFormatException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.Util;
import network.crypta.io.WritableToDataOutputStream;
import network.crypta.support.Fields;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.compress.CompressionOutputSizeException;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base for node-level keys used for routing and addressing in the Crypta network.
 *
 * <p>Concrete subclasses (for example, {@link NodeCHK} and {@link NodeSSK}) define the key material
 * and the exact on-disk/binary representation used by {@link #write(DataOutput)} and the
 * corresponding {@code read*} methods.
 *
 * <p>Compatibility note: The bytes written by {@link #write(DataOutput)} are persisted and
 * exchanged across nodes. Changing the binary format is a breaking change and must be coordinated
 * with the corresponding {@code read*} methods and any on-disk structures that store keys.
 *
 * <p>Thread-safety: Instances are immutable except a lazily computed cache used by {@link
 * #toNormalizedDouble()}. That cache is updated under synchronization and read-only usage is safe
 * across threads.
 *
 * @author amphibian
 */
public abstract class Key implements WritableToDataOutputStream, Comparable<Key> {
  private static final Logger LOG = LoggerFactory.getLogger(Key.class);

  final int hash;
  double cachedNormalizedDouble;

  /**
   * Routing key used for placement and equality. Subclasses derive or provide this value; it is a
   * 32-byte SHA-256 based value for both CHK and SSK.
   */
  final byte[] routingKey;

  /**
   * Algorithm identifier used in the low 8 bits of {@link #getType()} for AES‑256 in PCFB mode with
   * SHA‑256. The high 8 bits carry the base key type (CHK/SSK).
   */
  public static final byte ALGO_AES_PCFB_256_SHA256 = 2;

  public static final byte ALGO_AES_CTR_256_SHA256 = 3;

  // No static initialization required.

  /**
   * Create a key with the given routing key.
   *
   * @param routingKey Derived routing key bytes; must not be {@code null}. Subclasses validate
   *     length.
   */
  protected Key(byte[] routingKey) {
    this.routingKey = routingKey;
    hash = Fields.hashCode(routingKey);
    cachedNormalizedDouble = -1;
  }

  /**
   * Copy constructor that clones the routing key and copies cached values.
   *
   * @param key Source key to copy from.
   */
  protected Key(Key key) {
    this.hash = key.hash;
    this.cachedNormalizedDouble = key.cachedNormalizedDouble;
    this.routingKey = new byte[key.routingKey.length];
    System.arraycopy(key.routingKey, 0, routingKey, 0, routingKey.length);
  }

  /**
   * Return a new key equal to this one. The returned instance has the same concrete type and
   * content. Implementations may share immutable internal objects.
   *
   * @return a new {@code Key} representing the same value.
   */
  public abstract Key cloneKey();

  /**
   * Write this key in its compact binary representation.
   *
   * <p>The format is defined by the concrete subclass and must match the corresponding {@code
   * read*} method. As a convention, both {@link NodeCHK} and {@link NodeSSK} write a 2-byte type
   * header followed by type-specific key bytes (34 bytes for CHK and 66 bytes for SSK, see {@link
   * NodeCHK#FULL_KEY_LENGTH} and {@link NodeSSK#FULL_KEY_LENGTH}).
   *
   * @param out destination to write to; not closed by this method.
   * @throws IOException if an I/O error occurs while writing.
   */
  public abstract void write(DataOutput out) throws IOException;

  /**
   * Read a key from a {@link DataInput} previously written by {@link #write(DataOutput)}.
   *
   * <p>This method reads a 2-byte header (base type and subtype/algorithm) and dispatches to the
   * appropriate concrete reader.
   *
   * @param raf the input to read from.
   * @return a parsed {@code Key} instance.
   * @throws IOException if the input is truncated or the type is unrecognized.
   */
  public static Key read(DataInput raf) throws IOException {
    byte type = raf.readByte();
    byte subtype = raf.readByte();
    if (type == NodeCHK.BASE_TYPE) {
      return NodeCHK.readCHK(raf, subtype);
    } else if (type == NodeSSK.BASE_TYPE) return NodeSSK.readSSK(raf, subtype);

    throw new IOException("Unrecognized format: " + type);
  }

  /**
   * Construct a typed {@link KeyBlock} from raw pieces.
   *
   * <p>The {@code keyType} packs the base type in the high 8 bits and the crypto algorithm in the
   * low 8 bits (see {@link #getType()}). For CHK, {@code keyBytes} is unused; for SSK it carries
   * the type-specific key material (encrypted hashed docname). {@code headersBytes} and {@code
   * dataBytes} are the serialized block header and payload.
   *
   * @param keyType packed base type and algorithm.
   * @param keyBytes type-specific key material; see concrete key type.
   * @param headersBytes serialized block headers.
   * @param dataBytes serialized block payload.
   * @param pubkeyBytes serialized DSA public key, required for SSK blocks.
   * @return a {@link CHKBlock} or {@link SSKBlock} wrapped as {@link KeyBlock} depending on type.
   * @throws KeyVerifyException if inputs are invalid or the public key cannot be constructed.
   */
  public static KeyBlock createBlock(
      short keyType, byte[] keyBytes, byte[] headersBytes, byte[] dataBytes, byte[] pubkeyBytes)
      throws KeyVerifyException {
    byte type = (byte) (keyType >> 8);
    byte subtype = (byte) (keyType & 0xFF);
    switch (type) {
      case NodeCHK.BASE_TYPE -> {
        // For CHKs, the subtype is the crypto algorithm.
        return CHKBlock.construct(dataBytes, headersBytes, subtype);
      }
      case NodeSSK.BASE_TYPE -> {
        DSAPublicKey pubKey;
        try {
          pubKey = new DSAPublicKey(pubkeyBytes);
        } catch (IOException | CryptFormatException e) {
          throw new KeyVerifyException("Failed to construct pubkey: " + e, e);
        }
        NodeSSK key = new NodeSSK(pubKey.asBytesHash(), keyBytes, pubKey, subtype);
        return new SSKBlock(dataBytes, headersBytes, key, false);
      }
      default -> throw new KeyVerifyException("No such key type " + Integer.toHexString(type));
    }
  }

  /**
   * Return a stable hash-derived position in the half-open interval {@code [0.0, 1.0)}.
   *
   * <p>The routing key and type are hashed with SHA‑256 and mapped uniformly to a double. The value
   * is computed once and cached; subsequent calls return the cached value.
   */
  public synchronized double toNormalizedDouble() {
    if (cachedNormalizedDouble > 0) return cachedNormalizedDouble;
    MessageDigest md = SHA256.getMessageDigest();
    if (routingKey == null) throw new NullPointerException();
    md.update(routingKey);
    int type = getType();
    md.update((byte) (type >> 8));
    md.update((byte) type);
    byte[] digest = md.digest();
    cachedNormalizedDouble = Util.keyDigestAsNormalizedDouble(digest);
    return cachedNormalizedDouble;
  }

  /**
   * Return the packed key type.
   *
   * <ul>
   *   <li>High 8 bits ({@code (type >> 8) & 0xFF}) carry the base type ({@link NodeCHK#BASE_TYPE}
   *       or {@link NodeSSK#BASE_TYPE}).
   *   <li>Low 8 bits ({@code type & 0xFF}) carry the crypto algorithm (for example, {@link
   *       #ALGO_AES_PCFB_256_SHA256}).
   * </ul>
   */
  public abstract short getType();

  @Override
  public int hashCode() {
    return hash;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Key)) return false;
    return Arrays.equals(routingKey, ((Key) o).routingKey);
  }

  /**
   * Decompress a block into a {@link Bucket} when {@code isCompressed} is {@code true}; otherwise
   * return an immutable bucket view over the input bytes.
   *
   * <p>When compressed, the input is expected to start with a precompressed-length header of 2 or 4
   * bytes as selected by {@code shortLength}. The method enforces {@code maxLength} and the
   * codec-specific maximum to protect against resource exhaustion.
   */
  static Bucket decompress(
      boolean isCompressed,
      byte[] input,
      int inputLength,
      BucketFactory bf,
      long maxLength,
      short compressionAlgorithm,
      boolean shortLength)
      throws CHKDecodeException, IOException {
    if (maxLength < 0) throw new IllegalArgumentException("maxlength=" + maxLength);
    if (input.length < inputLength)
      throw new IndexOutOfBoundsException(input.length + "<" + inputLength);

    // Fast path when data is not compressed.
    if (!isCompressed) return BucketTools.makeImmutableBucket(bf, input, inputLength);

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Decompressing {} bytes in decode with codec {}", inputLength, compressionAlgorithm);
    }

    // Skip the precompressed-length header (2 bytes when short, otherwise 4).
    final int inputOffset = (shortLength ? 2 : 4);
    if (inputLength < inputOffset + 1) throw new CHKDecodeException("No bytes to decompress");

    int len = readPrecompressedLength(input, shortLength);
    if (len > maxLength)
      throw new TooBigException("Invalid precompressed size: " + len + " maxlength=" + maxLength);

    COMPRESSOR_TYPE decompressor = requireDecompressor(compressionAlgorithm);

    Bucket outputBucket = bf.makeBucket(maxLength);
    try (BucketResource inputResource =
            new BucketResource(
                new SimpleReadOnlyArrayBucket(input, inputOffset, inputLength - inputOffset));
        InputStream inputStream = inputResource.bucket().getInputStream();
        OutputStream outputStream = outputBucket.getOutputStream()) {
      decompressor.decompress(inputStream, outputStream, maxLength, -1);
    } catch (CompressionOutputSizeException _) {
      throw new TooBigException("Too big");
    }
    return outputBucket;
  }

  private static int readPrecompressedLength(byte[] input, boolean shortLength) {
    if (shortLength) {
      return ((input[0] & 0xff) << 8) + (input[1] & 0xff);
    }
    return ((((((input[0] & 0xff) << 8) + (input[1] & 0xff)) << 8) + (input[2] & 0xff)) << 8)
        + (input[3] & 0xff);
  }

  private static COMPRESSOR_TYPE requireDecompressor(short compressionAlgorithm)
      throws CHKDecodeException {
    COMPRESSOR_TYPE decompressor = COMPRESSOR_TYPE.getCompressorByMetadataID(compressionAlgorithm);
    if (decompressor == null)
      throw new CHKDecodeException("Unknown compression algorithm: " + compressionAlgorithm);
    return decompressor;
  }

  /**
   * Minimal {@link AutoCloseable} wrapper that calls {@link Bucket#free()} in {@link #close()}.
   * Buckets use {@code free()} rather than {@code close()} and do not declare checked exceptions.
   */
  private record BucketResource(Bucket bucket) implements AutoCloseable {
    @Override
    public void close() {
      // Buckets use free() instead of close(); no exception is declared.
      bucket.free();
    }
  }

  /**
   * Holder for compressed output and the algorithm that produced it.
   *
   * <p>When the data was not compressed (either because a codec was already applied or compression
   * was disabled/ineffective), {@code compressionAlgorithm} is negative.
   */
  public static final class Compressed {
    /**
     * Create a {@code Compressed} result.
     *
     * @param finalData bytes to persist or transmit; may be the original data if no compression was
     *     applied.
     * @param compressionAlgorithm2 codec identifier; negative when uncompressed.
     */
    public Compressed(byte[] finalData, short compressionAlgorithm2) {
      this.compressedData = finalData;
      this.compressionAlgorithm = compressionAlgorithm2;
    }

    byte[] compressedData;
    short compressionAlgorithm;
  }

  /**
   * Compress {@code sourceData} when allowed and beneficial.
   *
   * <p>If compression is applied, the returned byte array is prefixed with the original
   * uncompressed length encoded in 2 or 4 bytes depending on {@code shortLength}. If compression is
   * not applied, the returned bytes contain the original data without a length header.
   *
   * @param sourceData input bucket to read from.
   * @param dontCompress when {@code true}, skip trying compressors unless {@code
   *     alreadyCompressedCodec} is provided.
   * @param alreadyCompressedCodec when non-negative, treat {@code sourceData} as already compressed
   *     with the given codec and only add the length header.
   * @param sourceLength logical uncompressed length to record in the header when compression is
   *     used.
   * @param maxLengthBeforeCompression upper bound on {@code sourceData.size()} before any
   *     compression attempt; larger inputs fail fast.
   * @param maxCompressedLengthLimit hard limit on the size of the byte array returned by this
   *     method.
   * @param shortLength if {@code true}, use a 2-byte length header; otherwise use 4 bytes.
   * @param compressorDescriptor descriptor string used to select candidate compressors.
   * @return a {@link Compressed} result containing the bytes to persist and the codec id (negative
   *     when uncompressed).
   * @throws KeyEncodeException if the input is larger than permitted after considering limits.
   * @throws IOException on I/O failure while materializing bucket contents.
   * @throws InvalidCompressionCodecException if {@code compressorDescriptor} is invalid.
   */
  public static Compressed compress(
      Bucket sourceData,
      boolean dontCompress,
      short alreadyCompressedCodec,
      long sourceLength,
      long maxLengthBeforeCompression,
      int maxCompressedLengthLimit,
      boolean shortLength,
      String compressorDescriptor)
      throws KeyEncodeException, IOException, InvalidCompressionCodecException {
    byte[] finalData = null;
    short compressionAlgorithm = -1;
    int maxCompressedDataLength =
        adjustedMaxCompressedLength(maxCompressedLengthLimit, shortLength);
    if (sourceData.size() > maxLengthBeforeCompression) throw new KeyEncodeException("Too big");

    CompressionPrep prep =
        prepareCompressionData(
            sourceData,
            dontCompress,
            alreadyCompressedCodec,
            sourceLength,
            maxLengthBeforeCompression,
            maxCompressedDataLength,
            compressorDescriptor);
    if (prep != null) {
      finalData = addLengthHeader(prep.cbuf(), prep.headerSourceLength(), shortLength);
      compressionAlgorithm = prep.algorithm();
    }
    if (finalData == null) {
      // Not compressed or not compressible; no size header is added.
      if (sourceData.size() > maxCompressedLengthLimit) {
        throw new CHKEncodeException(
            "Too big: " + sourceData.size() + " should be " + maxCompressedLengthLimit);
      }
      finalData = BucketTools.toByteArray(sourceData);
    }

    return new Compressed(finalData, compressionAlgorithm);
  }

  private record CompressionPrep(byte[] cbuf, short algorithm, long headerSourceLength) {
    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof CompressionPrep(var otherCbuf, var otherAlgorithm, var otherHeader)))
        return false;
      return algorithm == otherAlgorithm
          && headerSourceLength == otherHeader
          && Arrays.equals(cbuf, otherCbuf);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(cbuf);
      result = 31 * result + Short.hashCode(algorithm);
      result = 31 * result + Long.hashCode(headerSourceLength);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "CompressionPrep[cbuf="
          + Arrays.toString(cbuf)
          + ", algorithm="
          + algorithm
          + ", headerSourceLength="
          + headerSourceLength
          + "]";
    }
  }

  private static CompressionPrep prepareCompressionData(
      Bucket sourceData,
      boolean dontCompress,
      short alreadyCompressedCodec,
      long sourceLength,
      long maxLengthBeforeCompression,
      int maxCompressedDataLength,
      String compressorDescriptor)
      throws IOException, InvalidCompressionCodecException {
    if (dontCompress && alreadyCompressedCodec < 0) {
      return null;
    }
    if (alreadyCompressedCodec >= 0) {
      if (sourceData.size() > maxCompressedDataLength) {
        throw new TooBigException("Too big (precompressed)");
      }
      if (sourceLength > maxLengthBeforeCompression) throw new TooBigException("Too big");
      byte[] cbuf = BucketTools.toByteArray(sourceData);
      return new CompressionPrep(cbuf, alreadyCompressedCodec, sourceLength);
    }
    if (sourceData.size() <= maxCompressedDataLength) {
      return null;
    }
    CompressedChoice choice =
        chooseCompression(sourceData, maxCompressedDataLength, compressorDescriptor);
    if (choice == null) return null;
    return new CompressionPrep(choice.data, choice.algorithm, choice.sourceLength);
  }

  private static int adjustedMaxCompressedLength(
      int maxCompressedLengthLimit, boolean shortLength) {
    int maxCompressedDataLength = maxCompressedLengthLimit;
    if (shortLength) maxCompressedDataLength -= 2;
    else maxCompressedDataLength -= 4;
    return maxCompressedDataLength;
  }

  private static byte[] addLengthHeader(byte[] cbuf, long sourceLength, boolean shortLength) {
    int compressedLength = cbuf.length;
    byte[] finalData = new byte[compressedLength + (shortLength ? 2 : 4)];
    System.arraycopy(cbuf, 0, finalData, shortLength ? 2 : 4, compressedLength);
    if (!shortLength) {
      finalData[0] = (byte) ((sourceLength >> 24) & 0xff);
      finalData[1] = (byte) ((sourceLength >> 16) & 0xff);
      finalData[2] = (byte) ((sourceLength >> 8) & 0xff);
      finalData[3] = (byte) ((sourceLength) & 0xff);
    } else {
      finalData[0] = (byte) ((sourceLength >> 8) & 0xff);
      finalData[1] = (byte) ((sourceLength) & 0xff);
    }
    return finalData;
  }

  private record CompressedChoice(byte[] data, short algorithm, long sourceLength) {
    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof CompressedChoice(var otherData, var otherAlgorithm, var otherLen)))
        return false;
      return algorithm == otherAlgorithm
          && sourceLength == otherLen
          && Arrays.equals(data, otherData);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(data);
      result = 31 * result + Short.hashCode(algorithm);
      result = 31 * result + Long.hashCode(sourceLength);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "CompressedChoice[data="
          + Arrays.toString(data)
          + ", algorithm="
          + algorithm
          + ", sourceLength="
          + sourceLength
          + "]";
    }
  }

  /**
   * Try candidate compressors (as specified by {@code compressorDescriptor}) and pick the first
   * that produces output within {@code maxCompressedDataLength}. Returns {@code null} when no
   * compressor fits or when compression is not beneficial.
   */
  private static CompressedChoice chooseCompression(
      Bucket sourceData, int maxCompressedDataLength, String compressorDescriptor)
      throws InvalidCompressionCodecException {
    COMPRESSOR_TYPE[] comps = COMPRESSOR_TYPE.getCompressorsArray(compressorDescriptor);
    for (COMPRESSOR_TYPE comp : comps) {
      ArrayBucket compressedData = null;
      try {
        compressedData =
            (ArrayBucket)
                comp.compress(
                    sourceData, new ArrayBucketFactory(), Long.MAX_VALUE, maxCompressedDataLength);
      } catch (IOException _) {
        // Ignore and try next compressor.
      }
      if (compressedData != null && compressedData.size() <= maxCompressedDataLength) {
        try {
          byte[] cbuf = BucketTools.toByteArray(compressedData);
          return new CompressedChoice(cbuf, comp.metadataID, sourceData.size());
        } catch (IOException e) {
          throw new UncheckedIOException(e);
        }
      }
    }
    return null;
  }

  /**
   * Return the routing key bytes. The returned array is the internal array; callers must not modify
   * it.
   */
  public byte[] getRoutingKey() {
    return routingKey;
  }

  /**
   * Return the minimal type-specific bytes required to reconstruct this key, excluding any
   * auxiliary material such as a public key.
   */
  public byte[] getKeyBytes() {
    return routingKey;
  }

  /**
   * Create a client-level block wrapper that corresponds to the provided key and node-level block.
   * The pair must be type-consistent (CHK with {@link CHKBlock}, SSK with {@link SSKBlock}).
   *
   * @param key client key of matching type.
   * @param block node-level block of matching type.
   * @return a {@link ClientCHKBlock} or {@link ClientSSKBlock} as appropriate.
   * @throws KeyVerifyException if construction fails (for example, due to a bad public key).
   */
  public static ClientKeyBlock createKeyBlock(ClientKey key, KeyBlock block)
      throws KeyVerifyException {
    if (key instanceof ClientSSK sK) {
      return ClientSSKBlock.construct((SSKBlock) block, sK);
    } else {
      return new ClientCHKBlock((CHKBlock) block, (ClientCHK) key);
    }
  }

  /**
   * Return the full, self-contained key bytes including the 2-byte type header and all
   * type-specific material needed to reconstruct the key instance.
   */
  public abstract byte[] getFullKey();

  /**
   * Return a key suitable for long-term in-memory storage by stripping optional or redundant
   * information. For example, {@link NodeSSK} omits the {@link network.crypta.crypt.DSAPublicKey}.
   * The returned instance does not pick up additional data after creation.
   */
  public abstract Key archivalCopy();

  /**
   * Return whether the provided algorithm identifier is recognized by this implementation.
   *
   * @param cryptoAlgorithm low 8-bit algorithm identifier as used in {@link #getType()}.
   * @return {@code true} if supported; {@code false} otherwise.
   */
  public static boolean isValidCryptoAlgorithm(byte cryptoAlgorithm) {
    return cryptoAlgorithm == ALGO_AES_PCFB_256_SHA256
        || cryptoAlgorithm == ALGO_AES_CTR_256_SHA256;
  }
}
