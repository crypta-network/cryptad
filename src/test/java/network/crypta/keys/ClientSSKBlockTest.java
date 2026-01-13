package network.crypta.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.Global;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ClientSSKBlockTest {

  private RandomSource rng;

  @BeforeEach
  void setUp() {
    // Fixed seed for determinism across runs
    rng = new DummyRandomSource(1337L);
  }

  @Test
  @DisplayName("decode: uncompressed payload round-trips and flags are correct")
  void decode_whenUncompressed_expectOriginalBytesAndFlags() throws Exception {
    String docName = "doc-plain";
    String text = "Hello SSK!";

    InsertableClientSSK key = InsertableClientSSK.createRandom(rng, docName);
    Bucket src = new SimpleReadOnlyArrayBucket(text.getBytes(StandardCharsets.UTF_8));

    ClientSSKBlock block =
        key.encode(
            new BlockEncodeParams(
                src, false, true, (short) -1, src.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

    assertThrows(IllegalStateException.class, block::isMetadata);
  }

  @Test
  @DisplayName("equals/hashCode: identical content and key are equal; different content not equal")
  void equalsHashCode_whenSameAndDifferent_expectConsistent() throws Exception {
    InsertableClientSSK key = InsertableClientSSK.createRandom(rng, "doc-eq");
    Bucket src = new SimpleReadOnlyArrayBucket("abc".getBytes(StandardCharsets.UTF_8));

    ClientSSKBlock a =
        key.encode(
            new BlockEncodeParams(
                src, false, true, (short) -1, src.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
    // Re-encode the same source with the same key → deterministic block
    ClientSSKBlock b =
        key.encode(
            new BlockEncodeParams(
                src, false, true, (short) -1, src.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

    assertNotSame(a, b);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());

    // Different source → not equal
    Bucket src2 = new SimpleReadOnlyArrayBucket("abcd".getBytes(StandardCharsets.UTF_8));
    ClientSSKBlock c =
        key.encode(
            new BlockEncodeParams(
                src2,
                false,
                true,
                (short) -1,
                src2.size(),
                Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
    assertNotEquals(a, c);
  }

  @Test
  @DisplayName("decode error: data length claims more than available bytes")
  void decode_whenDataLengthExceedsBuffer_expectSSKDecodeException() throws Exception {
    // Build a synthetic block that decrypts headers with dataLength = 1025 (> 1024)
    InsertableClientSSK key = InsertableClientSSK.createRandom(rng, "doc-too-long");
    byte[] plaintext = "z".getBytes(StandardCharsets.UTF_8);
    ClientSSKBlock block = buildSyntheticBlock(key, plaintext, 1025, false, (short) -1);

    assertThrows(
        SSKDecodeException.class,
        () -> {
          try (Bucket ignored = block.decode(new ArrayBucketFactory(), 32768, true)) {
            ignored.size();
          }
        });
  }

  @Test
  @DisplayName("decode error: compressed flag set but length < 2")
  void decode_whenCompressedButLengthTooShort_expectSSKDecodeException() throws Exception {
    InsertableClientSSK key = InsertableClientSSK.createRandom(rng, "doc-bad-len");
    byte[] plaintext = {42};
    // compressionAlgorithm >= 0 and dataLength = 1 triggers the guard when dontDecompress=true
    ClientSSKBlock block = buildSyntheticBlock(key, plaintext, 1, true, (short) 0);
    assertThrows(
        SSKDecodeException.class,
        () -> {
          try (Bucket ignored = block.decode(new ArrayBucketFactory(), 32768, true)) {
            ignored.size();
          }
        });
  }

  @Test
  @DisplayName("decode: dontDecompress=false matches dontDecompress=true for uncompressed data")
  void decode_whenDontDecompressFalse_expectSameAsRaw() throws Exception {
    InsertableClientSSK key = InsertableClientSSK.createRandom(rng, "doc-nodecomp");
    String text = "RAW";
    Bucket src = new SimpleReadOnlyArrayBucket(text.getBytes(StandardCharsets.UTF_8));
    ClientSSKBlock block =
        key.encode(
            new BlockEncodeParams(
                src, false, true, (short) -1, src.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

    byte[] raw;
    try (Bucket b = block.decode(new ArrayBucketFactory(), 32768, true)) {
      raw = BucketTools.toByteArray(b);
    }
    byte[] decomp;
    try (Bucket b = block.decode(new ArrayBucketFactory(), 32768, false)) {
      decomp = BucketTools.toByteArray(b);
    }
    assertArrayEquals(raw, decomp);
  }

  // --- helpers ---

  /**
   * Constructs a {@link ClientSSKBlock} with caller-specified decrypted header fields and payload
   * content. The block is built in a way that {@link ClientSSKBlock#decode} can successfully
   * decrypt headers and data; signature verification is skipped by constructing the underlying
   * {@link SSKBlock} with {@code dontVerify=true}.
   */
  private static ClientSSKBlock buildSyntheticBlock(
      InsertableClientSSK key,
      byte[] plaintext,
      int dataLength,
      boolean asMetadata,
      short compressionAlg)
      throws Exception {
    // Prepare decrypted header segment: dataDecryptKey, length+meta, codec.
    byte[] decryptedHeader = new byte[SSKBlock.ENCRYPTED_HEADERS_LENGTH];
    byte[] dataDecryptKey = new byte[ClientSSKBlock.DATA_DECRYPT_KEY_LENGTH];
    Arrays.fill(dataDecryptKey, (byte) 0x42);
    System.arraycopy(dataDecryptKey, 0, decryptedHeader, 0, dataDecryptKey.length);

    int len = dataLength & 0x7FFF;
    if (asMetadata) len |= 0x8000;
    decryptedHeader[ClientSSKBlock.DATA_DECRYPT_KEY_LENGTH] = (byte) ((len >> 8) & 0xFF);
    decryptedHeader[ClientSSKBlock.DATA_DECRYPT_KEY_LENGTH + 1] = (byte) (len & 0xFF);
    decryptedHeader[ClientSSKBlock.DATA_DECRYPT_KEY_LENGTH + 2] =
        (byte) ((compressionAlg >> 8) & 0xFF);
    decryptedHeader[ClientSSKBlock.DATA_DECRYPT_KEY_LENGTH + 3] = (byte) (compressionAlg & 0xFF);

    // Build full headers with hash ID, cipher ID, E(H(docname)), and encrypted header segment
    byte[] headers = new byte[SSKBlock.TOTAL_HEADERS_LENGTH];
    int x = 0;
    headers[x++] = 0; // hash id MSB
    headers[x++] = (byte) KeyBlock.HASH_SHA256; // hash id LSB
    headers[x++] = 0; // cipher id MSB
    headers[x++] = Key.ALGO_AES_PCFB_256_SHA256; // cipher id LSB
    System.arraycopy(key.ehDocname, 0, headers, x, key.ehDocname.length);
    x += key.ehDocname.length;

    // Encrypt the header segment using AES-256/PCFB with IV = E(H(docname)) and key = cryptoKey
    Rijndael aes = new Rijndael(256, 256);
    aes.initialize(key.cryptoKey);
    PCFBMode pcfb = PCFBMode.create(aes, key.ehDocname);
    byte[] encHeader = Arrays.copyOf(decryptedHeader, decryptedHeader.length);
    pcfb.blockEncipher(encHeader, 0, encHeader.length);
    System.arraycopy(encHeader, 0, headers, x, encHeader.length);
    x += encHeader.length;

    // Construct the ciphertext payload: encrypt 1024 bytes using dataDecryptKey as the key and IV
    byte[] data = new byte[SSKBlock.DATA_LENGTH];
    if (plaintext.length > data.length) throw new IllegalArgumentException("plaintext too long");
    System.arraycopy(plaintext, 0, data, 0, Math.min(plaintext.length, Math.max(0, dataLength)));

    aes.initialize(dataDecryptKey);
    pcfb.reset(dataDecryptKey);
    pcfb.blockEncipher(data, 0, data.length);

    // Compute encrypted data hash and overall hash, then sign deterministically
    java.security.MessageDigest md256 = SHA256.getMessageDigest();
    byte[] encryptedDataHash = md256.digest(Arrays.copyOf(data, data.length));
    md256.reset();
    md256.update(headers, 0, x);
    md256.update(encryptedDataHash);
    byte[] overallHash = md256.digest();

    DSASigner dsa = new DSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    DSAPrivateKeyParameters privParams =
        new DSAPrivateKeyParameters(key.privKey.getX(), Global.getDSAgroupBigAParameters());
    dsa.init(true, privParams);
    java.math.BigInteger[] sig = dsa.generateSignature(Global.truncateHash(overallHash));
    byte[] rBuf = toFixed(sig[0], SSKBlock.SIG_R_LENGTH);
    byte[] sBuf = toFixed(sig[1], SSKBlock.SIG_S_LENGTH);
    System.arraycopy(rBuf, 0, headers, x, rBuf.length);
    x += rBuf.length;
    System.arraycopy(sBuf, 0, headers, x, sBuf.length);
    x += sBuf.length;
    // Sanity: we should have filled the full header buffer
    assertEquals(SSKBlock.TOTAL_HEADERS_LENGTH, x);

    // Build final ClientSSKBlock (verifier in SSKBlock is skipped via dontVerify=true)
    return new ClientSSKBlock(data, headers, key, /* dontVerify= */ true);
  }

  private static byte[] toFixed(java.math.BigInteger v, int len) {
    byte[] bs = v.toByteArray();
    if (bs.length == len) return bs;
    if (bs.length < len) {
      byte[] out = new byte[len];
      System.arraycopy(bs, 0, out, len - bs.length, bs.length);
      return out;
    }
    for (int i = 0; i < bs.length - len; i++) {
      if (bs[i] != 0) throw new IllegalStateException("Cannot truncate non-zero-leading MPI");
    }
    return Arrays.copyOfRange(bs, bs.length - len, bs.length);
  }
}
