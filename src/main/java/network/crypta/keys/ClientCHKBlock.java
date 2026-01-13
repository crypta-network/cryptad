package network.crypta.keys;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.CTRBlockCipher;
import network.crypta.crypt.JceLoader;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.Util;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.keys.Key.Compressed;
import network.crypta.node.Node;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds a client-side CHK block and provides encode/decode helpers for CHK content.
 *
 * <p>This class wraps a {@link CHKBlock} together with the corresponding {@link ClientCHK} and
 * exposes decoding into a {@link Bucket} or in-memory, plus static encoders for both the legacy
 * AES/PCFB and the current AES/CTR variants. Instances reference the underlying encoded data and
 * headers; no I/O is performed until a decode method is invoked. Decoding performs integrity checks
 * and optional decompression depending on the key metadata.
 *
 * <p>For AES/CTR, the 16-byte counter-nonce is derived deterministically from an HMAC of the
 * plaintext (plus length bytes) under the encryption key. This preserves CHK determinism: identical
 * plaintext with the same key yields identical ciphertext and key material.
 *
 * @author amphibian
 */
public class ClientCHKBlock implements ClientKeyBlock {
  private static final Logger LOG = LoggerFactory.getLogger(ClientCHKBlock.class);
  private static final String HMAC_SHA256 = "HmacSHA256";

  private static Mac selectPreferredHmac(Mac base, Provider sun, SecretKeySpec dummyKey)
      throws GeneralSecurityException {
    if (sun == null) return base;
    final String algo = base.getAlgorithm();
    Mac sunHmac = Mac.getInstance(algo, sun);
    sunHmac.init(dummyKey);
    if (base.getProvider() == sunHmac.getProvider()) return base;
    long timeDef = benchmark(base);
    long timeSun = benchmark(sunHmac);
    LOG.debug("{}/{}: {}ns", algo, base.getProvider(), timeDef);
    LOG.debug("{}/{}: {}ns", algo, sunHmac.getProvider(), timeSun);
    return (timeSun < timeDef) ? sunHmac : base;
  }

  private static Mac safeSelectPreferredHmac(Mac base, Provider sun, SecretKeySpec dummyKey) {
    try {
      return selectPreferredHmac(base, sun, dummyKey);
    } catch (GeneralSecurityException | RuntimeException e) {
      String algo = base.getAlgorithm();
      LOG.warn("{}@{} benchmark failed", algo, sun, e);
      return base;
    }
  }

  private static ClientCHKBlock newClientCHKBlockUnchecked(
      byte[] data, byte[] header, ClientCHK key) {
    // Helper that asserts construction-time verification never fails when called from trusted
    // encode paths. Throws an unchecked exception if it ever does.
    try {
      return new ClientCHKBlock(data, header, key, false);
    } catch (CHKVerifyException e) {
      throw new IllegalStateException("Verification failed unexpectedly", e);
    }
  }

  private static Rijndael newRijndael256x128ForEncode() throws CHKEncodeException {
    // Creates a Rijndael instance with a 256-bit key and 128-bit block size for CTR mode.
    try {
      return new Rijndael(256, 128);
    } catch (UnsupportedCipherException e) {
      throw new CHKEncodeException("Unsupported cipher", e);
    }
  }

  private static Rijndael newRijndael256x256ForEncode() {
    // Creates a Rijndael instance with a 256-bit key and 256-bit block size for PCFB mode.
    try {
      return new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException("Unsupported cipher", e);
    }
  }

  final ClientCHK key;
  private final CHKBlock block;

  /**
   * Returns a concise representation for debugging that includes the associated client key.
   *
   * @return a string containing the implementation identity and key summary.
   */
  @Override
  public String toString() {
    return super.toString() + ",key=" + key;
  }

  /**
   * Constructs an instance from raw block bytes and a client key.
   *
   * <p>When {@code verify} is {@code true}, lightweight integrity checks are performed by {@link
   * CHKBlock} without fully decoding the content.
   *
   * @param data the encrypted payload as stored on disk or received over the network.
   * @param header the block header bytes (algorithm marker, HMAC, and length encoding).
   * @param key2 the client key associated with the block.
   * @param verify whether to verify invariants available without a full decoding.
   * @throws CHKVerifyException if the header or overall hash check fails during verification.
   */
  public ClientCHKBlock(byte[] data, byte[] header, ClientCHK key2, boolean verify)
      throws CHKVerifyException {
    block = new CHKBlock(data, header, key2.getNodeCHK(), verify, key2.cryptoAlgorithm);
    this.key = key2;
  }

  /**
   * Constructs an instance from an existing {@link CHKBlock} and client key.
   *
   * <p>Performs the same verification as the raw-bytes constructor with {@code verify=true}.
   *
   * @param block the encoded block (data plus headers).
   * @param key2 the client key associated with the block.
   * @throws CHKVerifyException if verification fails.
   */
  public ClientCHKBlock(CHKBlock block, ClientCHK key2) throws CHKVerifyException {
    this(block.getData(), block.getHeaders(), key2, true);
  }

  /**
   * Decodes the block entirely into memory.
   *
   * <p>Intended for small payloads (up to a single CHK block). Applies decompression when the key
   * indicates that the content was compressed.
   *
   * @return the decoded bytes.
   * @throws CHKDecodeException if decryption, integrity validation, or decompression fails.
   */
  @Override
  public byte[] memoryDecode() throws CHKDecodeException {
    try {
      ArrayBucket a = (ArrayBucket) decode(new ArrayBucketFactory(), 32 * 1024, false);
      return BucketTools.toByteArray(a);
    } catch (IOException e) {
      throw new CHKDecodeException("I/O error during decode", e);
    }
  }

  /**
   * Decodes the CHK and writes the original data to a {@link Bucket}.
   *
   * @param bf factory used to allocate the destination bucket.
   * @param maxLength maximum number of bytes allowed in the decoded output.
   * @param dontCompress when {@code true}, skips decompression even if the key marks the data as
   *     compressed.
   * @return a bucket containing the decoded bytes. The caller is responsible for closing it.
   * @throws CHKDecodeException if integrity checks fail, decryption fails, or the output would
   *     exceed {@code maxLength}.
   * @throws IOException if allocating or writing the output bucket fails.
   */
  @Override
  public Bucket decode(BucketFactory bf, int maxLength, boolean dontCompress)
      throws CHKDecodeException, IOException {
    return decode(bf, maxLength, dontCompress, false);
  }

  // forceNoJCA for unit tests.
  Bucket decode(BucketFactory bf, int maxLength, boolean dontCompress, boolean forceNoJCA)
      throws CHKDecodeException, IOException {
    if (key.cryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256)
      return decodeOld(bf, maxLength, dontCompress);
    else if (key.cryptoAlgorithm == Key.ALGO_AES_CTR_256_SHA256) {
      if (Rijndael.getAesCtrProvider() == null || forceNoJCA)
        return decodeNewNoJCA(bf, maxLength, dontCompress);
      else return decodeNew(bf, maxLength, dontCompress);
    } else throw new UnsupportedOperationException();
  }

  /**
   * Decodes a block that uses the legacy AES/PCFB + SHA-256 format.
   *
   * <p>Only valid when {@link ClientCHK#cryptoAlgorithm} is {@link Key#ALGO_AES_PCFB_256_SHA256}.
   * The method decrypts the header (which functions as an IV), validates that the decrypted IV
   * equals {@code SHA-256(cryptokey)}, and then decrypts the data.
   *
   * @param bf factory used to allocate the destination bucket.
   * @param maxLength maximum number of bytes allowed in the decoded output.
   * @param dontCompress when {@code true}, skips decompression even if the key marks the data as
   *     compressed.
   * @return a bucket containing the decoded bytes.
   * @throws CHKDecodeException if the crypto key is invalid, integrity checks fail, or the output
   *     would exceed {@code maxLength}.
   * @throws IOException if allocating or writing the output bucket fails.
   * @throws UnsupportedOperationException if the block does not use the legacy algorithm.
   */
  public Bucket decodeOld(BucketFactory bf, int maxLength, boolean dontCompress)
      throws CHKDecodeException, IOException {
    // Overall hash already verified, so the first job is to decrypt.
    if (key.cryptoAlgorithm != Key.ALGO_AES_PCFB_256_SHA256)
      throw new UnsupportedOperationException();
    BlockCipher cipher;
    try {
      cipher = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      // Should be impossible with bundled cipher
      throw new CHKDecodeException("Unsupported cipher", e);
    }
    byte[] cryptoKey = key.cryptoKey;
    if (cryptoKey.length < Node.SYMMETRIC_KEY_LENGTH)
      throw new CHKDecodeException("Crypto key too short");
    cipher.initialize(key.cryptoKey);
    byte[] zeroIv = new byte[PCFBMode.lengthIV(cipher)];
    PCFBMode pcfb = PCFBMode.create(cipher, zeroIv);
    byte[] headers = block.headers;
    byte[] data = block.data;
    byte[] hbuf = Arrays.copyOfRange(headers, 2, headers.length);
    byte[] dbuf = Arrays.copyOf(data, data.length);
    // Decrypt the header first: it acts as the IV for PCFB.
    pcfb.blockDecipher(hbuf, 0, hbuf.length);
    pcfb.blockDecipher(dbuf, 0, dbuf.length);
    MessageDigest md256 = SHA256.getMessageDigest();
    byte[] dkey = key.cryptoKey;
    // Invariant: IV must equal SHA-256 of the decryption key.
    byte[] predIV = md256.digest(dkey);
    // Extract the IV
    byte[] iv = Arrays.copyOf(hbuf, 32);
    if (!Arrays.equals(iv, predIV))
      throw new CHKDecodeException("Check failed: Decrypted IV == H(decryption key)");
    // Checks complete
    int size = ((hbuf[32] & 0xff) << 8) + (hbuf[33] & 0xff);
    if (size > 32768) {
      throw new CHKDecodeException("Invalid size: " + size);
    }
    return Key.decompress(
        !dontCompress && key.isCompressed(),
        dbuf,
        size,
        bf,
        maxLength,
        key.compressionAlgorithm,
        false);
  }

  private static final Provider hmacProvider;

  private static long benchmark(Mac hmac) throws GeneralSecurityException {
    long times = Long.MAX_VALUE;
    byte[] input = new byte[1024];
    byte[] output = new byte[hmac.getMacLength()];
    byte[] key = new byte[Node.SYMMETRIC_KEY_LENGTH];
    final String algo = hmac.getAlgorithm();
    hmac.init(new SecretKeySpec(key, algo));
    // warm-up
    for (int i = 0; i < 32; i++) {
      hmac.update(input, 0, input.length);
      hmac.doFinal(output, 0);
      System.arraycopy(
          output, 0, input, (i * output.length) % (input.length - output.length), output.length);
    }
    System.arraycopy(output, 0, key, 0, Math.min(key.length, output.length));
    for (int i = 0; i < 1024; i++) {
      long startTime = System.nanoTime();
      hmac.init(new SecretKeySpec(key, algo));
      for (int j = 0; j < 8; j++) {
        for (int k = 0; k < 32; k++) {
          hmac.update(input, 0, input.length);
        }
        hmac.doFinal(output, 0);
      }
      long endTime = System.nanoTime();
      times = Math.min(endTime - startTime, times);
      System.arraycopy(output, 0, input, 0, output.length);
      System.arraycopy(output, 0, key, 0, Math.min(key.length, output.length));
    }
    return times;
  }

  static {
    // Resolve and cache the preferred HMAC provider at class initialization for consistent
    // performance across decode/encode operations. Falls back to the default provider on error.
    try {
      final String algo = HMAC_SHA256;
      final Provider sun = JceLoader.getSunJCE();
      SecretKeySpec dummyKey = new SecretKeySpec(new byte[Node.SYMMETRIC_KEY_LENGTH], algo);
      Mac hmac = Mac.getInstance(algo);
      hmac.init(dummyKey); // resolve provider
      hmac = safeSelectPreferredHmac(hmac, sun, dummyKey);
      hmacProvider = hmac.getProvider();
      LOG.info("{}: using {}", algo, hmacProvider);
    } catch (GeneralSecurityException e) {
      // impossible
      throw new ExceptionInInitializerError(e);
    }
  }

  /**
   * Decodes a block that uses the AES/CTR + HMAC-SHA-256 format via JCA/JCE.
   *
   * <p>The 16-byte CTR nonce (IV) is derived from the first 16 bytes of {@code
   * HMAC-SHA-256(cryptokey, plaintext || lengthBytes)}, which is deterministic per content to
   * preserve CHK determinism. The HMAC of the plaintext (including the 2 length bytes) is stored in
   * the header and verified during decoding.
   *
   * @param bf factory used to allocate the destination bucket.
   * @param maxLength maximum number of bytes allowed in the decoded output.
   * @param dontCompress when {@code true}, skips decompression even if the key marks the data as
   *     compressed.
   * @return a bucket containing the decoded bytes.
   * @throws CHKDecodeException if integrity checks fail, the crypto key is invalid, or the output
   *     would exceed {@code maxLength}.
   * @throws IOException if allocating or writing the output bucket fails.
   * @throws UnsupportedOperationException if the block does not use the AES/CTR algorithm.
   */
  public Bucket decodeNew(BucketFactory bf, int maxLength, boolean dontCompress)
      throws CHKDecodeException, IOException {
    if (key.cryptoAlgorithm != Key.ALGO_AES_CTR_256_SHA256)
      throw new UnsupportedOperationException();
    if (Rijndael.getAesCtrProvider() == null) {
      // Fallback for direct calls when no JCA provider is available.
      return decodeNewNoJCA(bf, maxLength, dontCompress);
    }
    byte[] headers = block.headers;
    byte[] data = block.data;
    byte[] hash = Arrays.copyOfRange(headers, 2, 2 + 32);
    byte[] cryptoKey = key.cryptoKey;
    if (cryptoKey.length < Node.SYMMETRIC_KEY_LENGTH)
      throw new CHKDecodeException("Crypto key too short");
    try {
      Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING", Rijndael.getAesCtrProvider());
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(cryptoKey, "AES"),
          new IvParameterSpec(hash, 0, 16)); // NOSONAR: CTR requires a unique nonce; we derive
      // it deterministically from HMAC(cryptokey, plaintext||len) to preserve CHK determinism.
      byte[] plaintext = new byte[data.length + 2];
      int moved = cipher.update(data, 0, data.length, plaintext);
      cipher.doFinal(headers, hash.length + 2, 2, plaintext, moved);
      int size = ((plaintext[data.length] & 0xff) << 8) + (plaintext[data.length + 1] & 0xff);
      if (size > 32768) {
        throw new CHKDecodeException("Invalid size: " + size);
      }
      // Check the HMAC of plaintext || lengthBytes.
      Mac hmac = Mac.getInstance(HMAC_SHA256, hmacProvider);
      hmac.init(new SecretKeySpec(cryptoKey, HMAC_SHA256));
      hmac.update(plaintext); // plaintext includes lengthBytes
      byte[] hashCheck = hmac.doFinal();
      if (!Arrays.equals(hash, hashCheck)) {
        throw new CHKDecodeException("HMAC is wrong, wrong decryption key?");
      }
      return Key.decompress(
          !dontCompress && key.isCompressed(),
          plaintext,
          size,
          bf,
          maxLength,
          key.compressionAlgorithm,
          false);
    } catch (GeneralSecurityException e) {
      throw new CHKDecodeException("Problem with JCA, should be impossible!", e);
    }
  }

  /**
   * Decodes a block using the built-in AES/CTR implementation when no JCA provider is available.
   *
   * <p>Semantics are equivalent to {@link #decodeNew(BucketFactory, int, boolean)}. HMAC-SHA-256 is
   * used for integrity, and AES uses a 128-bit block size in this pure-Java path.
   *
   * @param bf factory used to allocate the destination bucket.
   * @param maxLength maximum number of bytes allowed in the decoded output.
   * @param dontCompress when {@code true}, skips decompression even if the key marks the data as
   *     compressed.
   * @return a bucket containing the decoded bytes.
   * @throws CHKDecodeException if integrity checks fail, the crypto key is invalid, or the output
   *     would exceed {@code maxLength}.
   * @throws IOException if allocating or writing the output bucket fails.
   * @throws UnsupportedOperationException if the block does not use the AES/CTR algorithm.
   */
  public Bucket decodeNewNoJCA(BucketFactory bf, int maxLength, boolean dontCompress)
      throws CHKDecodeException, IOException {
    if (key.cryptoAlgorithm != Key.ALGO_AES_CTR_256_SHA256)
      throw new UnsupportedOperationException();
    byte[] headers = block.headers;
    byte[] data = block.data;
    byte[] hash = Arrays.copyOfRange(headers, 2, 2 + 32);
    byte[] cryptoKey = key.cryptoKey;
    if (cryptoKey.length < Node.SYMMETRIC_KEY_LENGTH)
      throw new CHKDecodeException("Crypto key too short");
    Rijndael aes;
    try {
      aes = new Rijndael(256, 128);
    } catch (UnsupportedCipherException e) {
      // Should be impossible with bundled cipher
      throw new CHKDecodeException("Unsupported cipher", e);
    }
    aes.initialize(cryptoKey);
    CTRBlockCipher cipher = new CTRBlockCipher(aes);
    cipher.init(hash, 0, 16); // NOSONAR: deterministic per-content nonce by design (see above).
    byte[] plaintext = new byte[data.length];
    cipher.processBytes(data, 0, data.length, plaintext, 0);
    byte[] lengthBytes = new byte[2];
    cipher.processBytes(headers, hash.length + 2, 2, lengthBytes, 0);
    int size = ((lengthBytes[0] & 0xff) << 8) + (lengthBytes[1] & 0xff);
    if (size > 32768) {
      throw new CHKDecodeException("Invalid size: " + size);
    }
    try {
      // Check the HMAC of plaintext || lengthBytes.
      Mac hmac = Mac.getInstance(HMAC_SHA256, hmacProvider);
      hmac.init(new SecretKeySpec(cryptoKey, HMAC_SHA256));
      hmac.update(plaintext);
      hmac.update(lengthBytes);
      byte[] hashCheck = hmac.doFinal();
      if (!Arrays.equals(hash, hashCheck)) {
        throw new CHKDecodeException("HMAC is wrong, wrong decryption key?");
      }
    } catch (GeneralSecurityException e) {
      throw new CHKDecodeException("Problem with JCA, should be impossible!", e);
    }
    return Key.decompress(
        !dontCompress && key.isCompressed(),
        plaintext,
        size,
        bf,
        maxLength,
        key.compressionAlgorithm,
        false);
  }

  /**
   * Encodes a single splitfile block.
   *
   * <p>The input must be exactly {@link CHKBlock#DATA_LENGTH} bytes. If {@code cryptoKey} is {@code
   * null}, the key is derived as {@code SHA-256(data)}. The {@code cryptoAlgorithm} selects between
   * the legacy AES/PCFB and the current AES/CTR variants.
   *
   * @param data the block payload, exactly {@link CHKBlock#DATA_LENGTH} bytes.
   * @param cryptoKey optional encryption key; when non-null it must be {@link
   *     Node#SYMMETRIC_KEY_LENGTH} bytes.
   * @param cryptoAlgorithm algorithm selector; one of {@link Key#ALGO_AES_PCFB_256_SHA256} or
   *     {@link Key#ALGO_AES_CTR_256_SHA256}.
   * @return the encoded client block.
   * @throws CHKEncodeException if encoding fails.
   * @throws IllegalArgumentException if input sizes or {@code cryptoAlgorithm} are invalid.
   */
  public static ClientCHKBlock encodeSplitfileBlock(
      byte[] data, byte[] cryptoKey, byte cryptoAlgorithm) throws CHKEncodeException {
    if (data.length != CHKBlock.DATA_LENGTH) throw new IllegalArgumentException();
    if (cryptoKey != null && cryptoKey.length != 32) throw new IllegalArgumentException();
    MessageDigest md256 = SHA256.getMessageDigest();
    // No need to pad
    if (cryptoKey == null) {
      cryptoKey = md256.digest(data);
    }
    ClientCHKEncodeParams encodeParams =
        new ClientCHKEncodeParams(
            data,
            CHKBlock.DATA_LENGTH,
            md256,
            cryptoKey,
            false,
            (short) -1,
            cryptoAlgorithm,
            KeyBlock.HASH_SHA256);
    if (cryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256) return innerEncode(encodeParams);
    else if (cryptoAlgorithm != Key.ALGO_AES_CTR_256_SHA256)
      throw new IllegalArgumentException("Unknown crypto algorithm: " + cryptoAlgorithm);
    if (Rijndael.getAesCtrProvider() == null) {
      return encodeNewNoJCA(encodeParams);
    } else {
      return encodeNew(encodeParams);
    }
  }

  /**
   * Encodes data from a {@link Bucket} to a {@link ClientCHKBlock}.
   *
   * <p>Optionally compresses the input before encrypting, then pads to {@link
   * CHKBlock#DATA_LENGTH}. The {@code cryptoKey} may be {@code null} to derive a key from the
   * padded data. The {@code cryptoAlgorithm} selects AES/PCFB or AES/CTR.
   *
   * @param params bundle containing the compression inputs
   * @param cryptoKey optional encryption key (may be {@code null}).
   * @param cryptoAlgorithm algorithm selector; one of {@link Key#ALGO_AES_PCFB_256_SHA256} or
   *     {@link Key#ALGO_AES_CTR_256_SHA256}.
   * @return the encoded client block.
   * @throws CHKEncodeException on encode failures.
   * @throws IOException if reading from the bucket fails.
   */
  public static ClientCHKBlock encode(
      BlockEncodeParams params, byte[] cryptoKey, byte cryptoAlgorithm)
      throws CHKEncodeException, IOException {
    return encode(params, cryptoKey, cryptoAlgorithm, false);
  }

  // Unit-test hook: forces use of the pure-Java AES/CTR path.
  static ClientCHKBlock encode(
      BlockEncodeParams params, byte[] cryptoKey, byte cryptoAlgorithm, boolean forceNoJCA)
      throws CHKEncodeException, IOException {
    Bucket sourceData = params.sourceData();
    boolean asMetadata = params.asMetadata();
    boolean dontCompress = params.dontCompress();
    short alreadyCompressedCodec = params.alreadyCompressedCodec();
    long sourceLength = params.sourceLength();
    String compressorDescriptor = params.compressorDescriptor();
    byte[] finalData;
    byte[] data;
    short compressionAlgorithm;
    try {
      Compressed comp =
          Key.compress(
              sourceData,
              dontCompress,
              alreadyCompressedCodec,
              sourceLength,
              CHKBlock.MAX_LENGTH_BEFORE_COMPRESSION,
              CHKBlock.DATA_LENGTH,
              false,
              compressorDescriptor);
      finalData = comp.compressedData;
      compressionAlgorithm = comp.compressionAlgorithm;
    } catch (KeyEncodeException | InvalidCompressionCodecException e2) {
      throw new CHKEncodeException(e2.getMessage(), e2);
    }
    // Now do the actual encoding

    MessageDigest md256 = SHA256.getMessageDigest();
    // First pad it
    int dataLength = finalData.length;
    if (finalData.length != 32768) {
      // Hash the data
      if (finalData.length != 0) md256.update(finalData);
      byte[] digest = md256.digest();
      MersenneTwister mt = MersenneTwister.createUnsynchronized(digest);
      data = Arrays.copyOf(finalData, 32768);
      Util.randomBytes(mt, data, finalData.length, 32768 - finalData.length);
    } else {
      data = finalData;
    }
    // Now make the header
    byte[] encKey;
    if (cryptoKey != null) encKey = cryptoKey;
    else encKey = md256.digest(data);
    if (cryptoAlgorithm == 0) {
      // Default to legacy algorithm for backward compatibility.
      LOG.warn("Passed in 0 crypto algorithm");
      cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
    }
    ClientCHKEncodeParams encodeParams =
        new ClientCHKEncodeParams(
            data,
            dataLength,
            md256,
            encKey,
            asMetadata,
            compressionAlgorithm,
            cryptoAlgorithm,
            KeyBlock.HASH_SHA256);
    if (cryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256) return innerEncode(encodeParams);
    if (Rijndael.getAesCtrProvider() == null || forceNoJCA) return encodeNewNoJCA(encodeParams);
    return encodeNew(encodeParams);
  }

  /**
   * Encodes one block using the AES/CTR + HMAC-SHA-256 format via JCA/JCE.
   *
   * <p>Header layout: {@code [0..1]=blockHashAlg, [2..33]=HMAC(cryptokey, plaintext||len),
   * [34..35]=lengthBytes}. The CTR IV is the first 16 bytes of the HMAC value, making it
   * deterministic for identical content and key (required for CHK determinism).
   *
   * @param params bundle containing the encoding inputs
   * @return the encoded client block.
   * @throws CHKEncodeException if encoding fails.
   * @throws IllegalArgumentException if an unsupported algorithm is requested.
   */
  @SuppressWarnings("java:S3329")
  public static ClientCHKBlock encodeNew(ClientCHKEncodeParams params) throws CHKEncodeException {
    byte cryptoAlgorithm = params.cryptoAlgorithm();
    if (cryptoAlgorithm != Key.ALGO_AES_CTR_256_SHA256)
      throw new IllegalArgumentException("Unsupported crypto algorithm " + cryptoAlgorithm);
    if (Rijndael.getAesCtrProvider() == null) {
      // Fallback when no provider is available.
      return encodeNewNoJCA(params);
    }
    byte[] data = params.data();
    int dataLength = params.dataLength();
    MessageDigest md256 = params.md256();
    byte[] encKey = params.encKey();
    boolean asMetadata = params.asMetadata();
    short compressionAlgorithm = params.compressionAlgorithm();
    int blockHashAlgorithm = params.blockHashAlgorithm();
    try {
      // IV = HMAC<cryptokey>(plaintext || lengthBytes).
      // Deterministic IV preserves CHK determinism across identical content and key.
      Mac hmac = Mac.getInstance(HMAC_SHA256, hmacProvider);
      hmac.init(new SecretKeySpec(encKey, HMAC_SHA256));
      byte[] tmpLen = new byte[] {(byte) (dataLength >> 8), (byte) (dataLength & 0xff)};
      hmac.update(data);
      hmac.update(tmpLen);
      byte[] hash = hmac.doFinal();

      if (blockHashAlgorithm == 0) blockHashAlgorithm = KeyBlock.HASH_SHA256;
      if (blockHashAlgorithm != KeyBlock.HASH_SHA256)
        throw new IllegalArgumentException(
            "Unsupported block hash algorithm " + blockHashAlgorithm);

      byte[] header = new byte[hash.length + 2 + 2];
      header[0] = 0;
      header[1] = (byte) blockHashAlgorithm;
      System.arraycopy(hash, 0, header, 2, hash.length);
      SecretKeySpec ckey = new SecretKeySpec(encKey, "AES");
      // CTR mode IV is 16 bytes; we derive it deterministically from the HMAC above.
      Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING", Rijndael.getAesCtrProvider());
      cipher.init(Cipher.ENCRYPT_MODE, ckey, new IvParameterSpec(hash, 0, 16));
      byte[] cdata = new byte[data.length];
      // Some providers (e.g., certain SunPKCS11 backends) may defer producing output until
      // doFinal(). Handle a short write from update() by collecting the remainder from doFinal()
      // before writing the encrypted length bytes into the header tail.
      int moved = cipher.update(data, 0, data.length, cdata, 0);
      if (moved < data.length) {
        int remaining = data.length - moved;
        byte[] tail = new byte[remaining + 2];
        int written = cipher.doFinal(tmpLen, 0, 2, tail, 0);
        if (written < remaining + 2) {
          throw new CHKEncodeException(
              "Cipher produced insufficient output: expected "
                  + (remaining + 2)
                  + ", got "
                  + written);
        }
        System.arraycopy(tail, 0, cdata, moved, remaining);
        header[hash.length + 2] = tail[remaining];
        header[hash.length + 3] = tail[remaining + 1];
      } else {
        // Encrypt length bytes directly into the header tail when no remainder is pending.
        cipher.doFinal(tmpLen, 0, 2, header, hash.length + 2);
      }

      // Overall hash covers header then ciphertext bytes.
      md256.update(header);
      byte[] finalHash = md256.digest(cdata);

      ClientCHK finalKey =
          new ClientCHK(finalHash, encKey, asMetadata, cryptoAlgorithm, compressionAlgorithm);
      return newClientCHKBlockUnchecked(cdata, header, finalKey);
    } catch (GeneralSecurityException e) {
      throw new CHKEncodeException("Problem with JCA, should be impossible!", e);
    }
  }

  /**
   * Encodes one block using the built-in AES/CTR implementation (no external provider).
   *
   * <p>Semantics and header format match {@link #encodeNew(ClientCHKEncodeParams)}. AES uses a
   * 128-bit block size in this path.
   *
   * @param params bundle containing the encoding inputs
   * @return the encoded client block.
   * @throws CHKEncodeException if encoding fails.
   * @throws IllegalArgumentException if an unsupported algorithm is requested.
   */
  public static ClientCHKBlock encodeNewNoJCA(ClientCHKEncodeParams params)
      throws CHKEncodeException {
    byte cryptoAlgorithm = params.cryptoAlgorithm();
    if (cryptoAlgorithm != Key.ALGO_AES_CTR_256_SHA256)
      throw new IllegalArgumentException("Unsupported crypto algorithm " + cryptoAlgorithm);
    byte[] data = params.data();
    int dataLength = params.dataLength();
    MessageDigest md256 = params.md256();
    byte[] encKey = params.encKey();
    boolean asMetadata = params.asMetadata();
    short compressionAlgorithm = params.compressionAlgorithm();
    int blockHashAlgorithm = params.blockHashAlgorithm();
    try {
      // IV = HMAC<cryptokey>(plaintext).
      // It's okay that this is the same for 2 blocks with the same key and the same content.
      // In fact, that's the point; this is still a Content Hash Key.
      // Note: identical content with the same key yields identical IV by design.
      Mac hmac = Mac.getInstance(HMAC_SHA256, hmacProvider);
      hmac.init(new SecretKeySpec(encKey, HMAC_SHA256));
      byte[] tmpLen = new byte[] {(byte) (dataLength >> 8), (byte) (dataLength & 0xff)};
      hmac.update(data);
      hmac.update(tmpLen);
      byte[] hash = hmac.doFinal();
      byte[] header = new byte[hash.length + 2 + 2];
      if (blockHashAlgorithm == 0) blockHashAlgorithm = KeyBlock.HASH_SHA256;
      if (blockHashAlgorithm != KeyBlock.HASH_SHA256)
        throw new IllegalArgumentException(
            "Unsupported block hash algorithm " + blockHashAlgorithm);
      header[0] = 0;
      header[1] = (byte) blockHashAlgorithm;
      Rijndael aes = newRijndael256x128ForEncode();
      aes.initialize(encKey);
      CTRBlockCipher ctr = new CTRBlockCipher(aes);
      // CTR mode uses a 16-byte IV.
      ctr.init(hash, 0, 16); // NOSONAR: deterministic per-content nonce by design (see above).
      System.arraycopy(hash, 0, header, 2, hash.length);
      byte[] cdata = new byte[data.length];
      ctr.processBytes(data, 0, data.length, cdata, 0);
      ctr.processBytes(tmpLen, 0, 2, header, hash.length + 2);

      // Now calculate the final hash
      md256.update(header);
      byte[] finalHash = md256.digest(cdata);

      // Now convert it into a ClientCHK
      ClientCHK finalKey =
          new ClientCHK(finalHash, encKey, asMetadata, cryptoAlgorithm, compressionAlgorithm);

      return newClientCHKBlockUnchecked(cdata, header, finalKey);
    } catch (GeneralSecurityException e) {
      throw new CHKEncodeException("Problem with JCA, should be impossible!", e);
    }
  }

  /**
   * Encodes one block using the legacy AES/PCFB + SHA-256 format.
   *
   * <p>Primarily retained for compatibility with historical content. Callers must pass padded data
   * and the original content length. The resulting key records the compression and crypto
   * algorithms used.
   *
   * @param params bundle containing the encoding inputs
   * @return the encoded client block.
   * @throws IllegalArgumentException if an unsupported algorithm is requested.
   */
  public static ClientCHKBlock innerEncode(ClientCHKEncodeParams params) {
    byte[] data =
        params.data().clone(); // Will overwrite otherwise. Callers expect data not to be clobbered.
    int dataLength = params.dataLength();
    MessageDigest md256 = params.md256();
    byte[] encKey = params.encKey();
    boolean asMetadata = params.asMetadata();
    short compressionAlgorithm = params.compressionAlgorithm();
    byte cryptoAlgorithm = params.cryptoAlgorithm();
    if (cryptoAlgorithm != Key.ALGO_AES_PCFB_256_SHA256)
      throw new IllegalArgumentException("Unsupported crypto algorithm " + cryptoAlgorithm);
    byte[] header;
    ClientCHK key;
    // IV = E(H(crypto key))
    byte[] plainIV = md256.digest(encKey);
    header = new byte[plainIV.length + 2 + 2];
    header[0] = 0;
    header[1] = (byte) (KeyBlock.HASH_SHA256);
    System.arraycopy(plainIV, 0, header, 2, plainIV.length);
    header[plainIV.length + 2] = (byte) (dataLength >> 8);
    header[plainIV.length + 3] = (byte) (dataLength & 0xff);
    // Encrypt the header and then the data using the same PCFB instance.
    BlockCipher cipher = newRijndael256x256ForEncode();
    cipher.initialize(encKey);

    /*
     * plainIV (SHA-256 of the crypto key) is enciphered with a null IV, i.e. XORed with E(0).
     * For splitfiles the same decryption key may be reused across blocks (derived from an overall
     * hash or set randomly). Consequently, the plaintext and ciphertext IVs are constant for that
     * key, and the next 32 bytes (length[2] + first 30 bytes of data) are XORed with the same
     * keystream segment on every block.
     */

    byte[] zeroIv = new byte[PCFBMode.lengthIV(cipher)];
    PCFBMode pcfb = PCFBMode.create(cipher, zeroIv);
    pcfb.blockEncipher(header, 2, header.length - 2);
    pcfb.blockEncipher(data, 0, data.length);

    // Compute the final block hash over header || ciphertext.
    md256.update(header);
    byte[] finalHash = md256.digest(data);

    // Construct the final client key and block wrapper.
    key = new ClientCHK(finalHash, encKey, asMetadata, cryptoAlgorithm, compressionAlgorithm);

    try {
      return new ClientCHKBlock(data, header, key, false);
    } catch (CHKVerifyException e3) {
      throw new IllegalStateException("Verification failed unexpectedly", e3);
    }
  }

  /**
   * Convenience overload to encode a byte array as a {@link ClientCHKBlock}.
   *
   * <p>Behavior matches {@link #encode(BlockEncodeParams, byte[], byte)}, using the AES/CTR
   * algorithm and deriving the encryption key from the padded data.
   *
   * @param sourceData the input bytes.
   * @param asMetadata whether the resulting key should be flagged as metadata.
   * @param dontCompress when {@code true}, disables compression regardless of {@code
   *     alreadyCompressedCodec}.
   * @param alreadyCompressedCodec when {@code dontCompress} is {@code false} and this value is
   *     {@code >= 0}, signals that {@code sourceData} is already compressed using the given codec.
   * @param sourceLength number of bytes from {@code sourceData} to encode.
   * @param compressorDescriptor optional compressor selection/hint; implementation specific.
   * @return the encoded client block.
   * @throws CHKEncodeException on encode failures.
   */
  public static ClientCHKBlock encode(
      byte[] sourceData,
      boolean asMetadata,
      boolean dontCompress,
      short alreadyCompressedCodec,
      int sourceLength,
      String compressorDescriptor)
      throws CHKEncodeException {
    try {
      return encode(
          new BlockEncodeParams(
              new ArrayBucket(sourceData),
              asMetadata,
              dontCompress,
              alreadyCompressedCodec,
              sourceLength,
              compressorDescriptor),
          null,
          Key.ALGO_AES_CTR_256_SHA256);
    } catch (IOException e) {
      // Can't happen
      throw new CHKEncodeException("Unexpected I/O", e);
    }
  }

  /**
   * Returns the client key associated with this block.
   *
   * @return the {@link ClientCHK} for this block.
   */
  @Override
  public ClientCHK getClientKey() {
    return key;
  }

  /**
   * Indicates whether the key is marked as metadata.
   *
   * @return {@code true} when the {@link ClientCHK} represents metadata; otherwise {@code false}.
   */
  @Override
  public boolean isMetadata() {
    return key.isMetadata();
  }

  /**
   * Returns a hash code consistent with {@link #equals(Object)}.
   *
   * <p>Delegates to the associated {@link ClientCHK} hash, which uniquely identifies the block in
   * typical usage.
   */
  @Override
  public int hashCode() {
    return key.hashCode;
  }

  /**
   * Compares two {@code ClientCHKBlock} instances for structural equality.
   *
   * <p>Equality requires both the {@link ClientCHK} and the underlying {@link CHKBlock} to be
   * equal. This ensures callers do not accidentally conflate different ciphertext or header bytes
   * that happen to map to the same client key.
   *
   * @param o the object to compare.
   * @return {@code true} if both key and block match; otherwise {@code false}.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ClientCHKBlock other)) return false;
    if (!key.equals(other.key)) return false;
    return other.block.equals(this.block);
  }

  /**
   * Returns the underlying encoded {@link CHKBlock} (headers and ciphertext).
   *
   * @return the stored block.
   */
  @Override
  public CHKBlock getBlock() {
    return block;
  }

  /**
   * Returns the {@link Key} view that corresponds to this block's node-visible key material.
   *
   * @return the key derived from this block.
   */
  @Override
  public Key getKey() {
    return block.getKey();
  }
}
