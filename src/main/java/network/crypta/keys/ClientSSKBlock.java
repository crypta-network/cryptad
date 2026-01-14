package network.crypta.keys;

import java.io.IOException;
import java.util.Arrays;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client-side view of a Signed Subspace Key (SSK) block.
 *
 * <p>This type decrypts and optionally decompresses the payload of an {@link SSKBlock} using the
 * material contained in a {@link ClientSSK}. A successful decoding exposes whether the block
 * carries metadata (see {@link #isMetadata()}) and which compression codec was indicated in the
 * encrypted headers (see {@link #getCompressionCodec()}).
 *
 * <p>Thread-safety: instances are not thread-safe. Use one instance per decoding or externally
 * synchronize access.
 */
public class ClientSSKBlock implements ClientKeyBlock {
  private static final Logger LOG = LoggerFactory.getLogger(ClientSSKBlock.class);

  static final int DATA_DECRYPT_KEY_LENGTH = 32;

  public static final int MAX_DECOMPRESSED_DATA_LENGTH = 32768;

  /** Underlying encoded SSK block (immutable). */
  private final SSKBlock block;

  /** True, when the high-bit metadata flag is set; value becomes known after decoding. */
  private boolean isMetadata;

  /** True, after a successful decoding; guards access to decode-dependent properties. */
  private boolean decoded;

  /** Client key holding the decryption material and (optionally) the public key. */
  private final ClientSSK key;

  /** Compression code read from headers on last decoding; {@code -1} means "none/unknown". */
  private short compressionAlgorithm = -1;

  /**
   * Creates a client wrapper around an encoded SSK block.
   *
   * <p>Verification is delegated to {@link SSKBlock}; when {@code dontVerify} is {@code false}, the
   * signature and header invariants are checked during construction of the underlying block.
   *
   * @param data the encrypted payload of the block; not modified
   * @param headers the encrypted header bytes; not modified
   * @param key the client SSK containing decryption material; its node key is used to create the
   *     {@link NodeSSK}
   * @param dontVerify when {@code true}, skips signature verification in the {@link SSKBlock}
   * @throws SSKVerifyException if signature or header verification fails
   */
  public ClientSSKBlock(byte[] data, byte[] headers, ClientSSK key, boolean dontVerify)
      throws SSKVerifyException {
    block = new SSKBlock(data, headers, (NodeSSK) key.getNodeKey(true), dontVerify);
    this.key = key;
  }

  /**
   * Builds a {@code ClientSSKBlock} from an existing {@link SSKBlock} and client key.
   *
   * <p>If {@code key} does not yet carry a public key, this method copies it from {@code block} so
   * later verification and URI materialization succeed.
   *
   * @param block the source block providing headers and payload
   * @param key the client key used for decryption; updated with a public key if missing
   * @return a new client block bound to {@code block} and {@code key}
   * @throws SSKVerifyException if the new {@link SSKBlock} wrapper fails verification
   */
  public static ClientSSKBlock construct(SSKBlock block, ClientSSK key) throws SSKVerifyException {
    // Ensure the client key has a public key; fall back to the one carried by the block.
    if (key.getPubKey() == null) key.setPublicKey(block.getPubKey());
    return new ClientSSKBlock(block.data, block.headers, key, false);
  }

  /**
   * Decrypts the block and optionally decompresses the result.
   *
   * <p>The method derives a per-block data key from the encrypted headers, decrypts the payload,
   * records the metadata flag and compression code, and returns the decoded content in a bucket
   * created by {@code factory}. When {@code dontDecompress} is {@code true}, the returned bucket
   * contains the raw decrypted bytes; if a compression code is present, the result skips the
   * two-byte compression metadata prefix.
   *
   * @param factory the destination {@link BucketFactory}
   * @param maxLength upper bound for decompressed size in bytes; the effective bound is the minimum
   *     of this value and {@value #MAX_DECOMPRESSED_DATA_LENGTH}
   * @param dontDecompress when {@code true}, returns decrypted bytes without decompression
   * @return a {@link Bucket} containing the decoded payload
   * @throws KeyDecodeException if decryption or header parsing fails
   * @throws IOException if creating or writing the result bucket fails
   */
  @Override
  public Bucket decode(BucketFactory factory, int maxLength, boolean dontDecompress)
      throws KeyDecodeException, IOException {
    /*
     * Signature and basic header checks are performed by SSKBlock during construction.
     * The encrypted headers also carry the value used to seed the PCFB stream.
     */
    byte[] decryptedHeaders = new byte[SSKBlock.ENCRYPTED_HEADERS_LENGTH];
    System.arraycopy(
        block.headers, block.headersOffset, decryptedHeaders, 0, SSKBlock.ENCRYPTED_HEADERS_LENGTH);
    Rijndael aes;
    try {
      LOG.debug("cryptoAlgorithm={} for {}", key.cryptoAlgorithm, getClientKey().getURI());
      aes = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      // Surface cipher supporting problems as a decoding failure rather than a generic error.
      throw new KeyDecodeException(e);
    }
    aes.initialize(key.cryptoKey);
    // Initialize PCFB stream using E(H(docname)) as the initial vector/seed.
    PCFBMode pcfb = PCFBMode.create(aes, key.ehDocname);
    pcfb.blockDecipher(decryptedHeaders, 0, decryptedHeaders.length);
    // The first 32 bytes of decrypted headers form the per-block data key.
    byte[] dataDecryptKey = Arrays.copyOf(decryptedHeaders, DATA_DECRYPT_KEY_LENGTH);
    aes.initialize(dataDecryptKey);
    byte[] dataOutput = block.data.clone();
    // Use the derived data key as the PCFB IV for the data section; it is unique per block.
    pcfb.reset(dataDecryptKey);
    pcfb.blockDecipher(dataOutput, 0, dataOutput.length);
    // The next two header bytes encode the data length; the high bit indicates "metadata".
    int dataLength =
        ((decryptedHeaders[DATA_DECRYPT_KEY_LENGTH] & 0xff) << 8)
            + (decryptedHeaders[DATA_DECRYPT_KEY_LENGTH + 1] & 0xff);
    // Clear the metadata flag and remember it for callers once decoding completes.
    if ((dataLength & 32768) != 0) {
      dataLength = dataLength & ~32768;
      isMetadata = true;
    }
    if (dataLength > dataOutput.length) {
      throw new SSKDecodeException(
          "Data length: " + dataLength + " but data.length=" + dataOutput.length);
    }

    compressionAlgorithm =
        (short)
            (((decryptedHeaders[DATA_DECRYPT_KEY_LENGTH + 2] & 0xff) << 8)
                + (decryptedHeaders[DATA_DECRYPT_KEY_LENGTH + 3] & 0xff));
    decoded = true;

    if (dontDecompress) {
      if (compressionAlgorithm == (short) -1)
        return BucketTools.makeImmutableBucket(factory, dataOutput, dataLength);
      else if (dataLength < 2)
        throw new SSKDecodeException("Data length is less than 2 yet compressed!");
      else
        // The compressed form carries a two-byte metadata prefix; skip it when returning raw bytes.
        return BucketTools.makeImmutableBucket(factory, dataOutput, 2, dataLength - 2);
    }

    return Key.decompress(
        new DecompressionParams(
            compressionAlgorithm >= 0,
            dataOutput,
            dataLength,
            factory,
            Math.min(MAX_DECOMPRESSED_DATA_LENGTH, maxLength),
            compressionAlgorithm,
            true));
  }

  /**
   * Returns whether the decoded payload is marked as metadata.
   *
   * @return {@code true} if the metadata flag was set in the headers
   * @throws IllegalStateException if invoked before a successful decoding
   */
  @Override
  public boolean isMetadata() {
    if (!decoded) throw new IllegalStateException("Cannot read isMetadata before decoded");
    return isMetadata;
  }

  /**
   * Returns the client key used to decode this block.
   *
   * @return the associated {@link ClientSSK}
   */
  @Override
  public ClientSSK getClientKey() {
    return key;
  }

  /**
   * Returns the compression code extracted from the headers during decoding.
   *
   * @return a non-negative codec identifier when present; a negative value indicates no codec, or
   *     that decoding has not yet been attempted
   */
  public short getCompressionCodec() {
    return compressionAlgorithm;
  }

  /**
   * Convenience overload that decodes into memory with decompression enabled.
   *
   * <p>Equivalent to {@link #memoryDecode(boolean)} with {@code dontDecompress == false}.
   *
   * @return the decoded byte array
   * @throws KeyDecodeException if decryption or decompression fails
   */
  @Override
  public byte[] memoryDecode() throws KeyDecodeException {
    return memoryDecode(false);
  }

  /**
   * Decodes the payload into memory, optionally skipping decompression.
   *
   * <p>The decompressed size is capped at 32 KiB. This is a convenience over {@link #decode} that
   * uses an in-memory bucket.
   *
   * @param dontDecompress when {@code true}, returns decrypted bytes without decompression
   * @return the decoded byte array
   * @throws KeyDecodeException if decryption or I/O fails
   */
  public byte[] memoryDecode(boolean dontDecompress) throws KeyDecodeException {
    try {
      ArrayBucket a = (ArrayBucket) decode(new ArrayBucketFactory(), 32 * 1024, dontDecompress);
      // Extract the decoded content as a byte array for in-memory use.
      return BucketTools.toByteArray(a);
    } catch (IOException e) {
      // Propagate I/O problems as a decoding failure consistent with the method contract.
      throw new KeyDecodeException(e);
    }
  }

  @Override
  public int hashCode() {
    return block.hashCode() ^ key.hashCode();
  }

  /**
   * Equality is based on both the underlying block and the client key.
   *
   * <p>Two instances are equal if their {@link #getBlock()} and {@link #getClientKey()} are equal.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ClientSSKBlock other)) return false;
    if (!key.equals(other.key)) return false;
    return this.block.equals(other.block);
  }

  /**
   * Returns the underlying encoded block.
   *
   * @return the {@link KeyBlock} view of the SSK block
   */
  @Override
  public KeyBlock getBlock() {
    return block;
  }

  /**
   * Returns the key identifying the block.
   *
   * @return the key associated with the underlying block
   */
  @Override
  public Key getKey() {
    return block.getKey();
  }
}
