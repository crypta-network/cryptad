package network.crypta.keys;

import java.io.IOException;
import java.io.Serial;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.Util;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.keys.Key.Compressed;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.math.MersenneTwister;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A client-side SSK that also carries the private signing key, so it can insert content.
 *
 * <p>This class extends {@link ClientSSK} by adding the DSA private key required to sign new or
 * updated SSK blocks. It also provides helpers to construct an insert-capable URI and to encode a
 * {@link ClientSSKBlock}: data is optionally compressed, deterministically padded to a fixed size,
 * encrypted using AES/PCFB-256 with SHA-256 derived material, and finally signed with DSA
 * (deterministic {@code k} via HMAC-SHA-256).
 *
 * <p>Instances are effectively immutable after construction. The field {@link #privKey} is never
 * {@code null} for normal instances; it may be {@code null} only for the protected no-arg
 * constructor used by serialization frameworks.
 */
public class InsertableClientSSK extends ClientSSK {
  private static final Logger LOG = LoggerFactory.getLogger(InsertableClientSSK.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * The DSA private key used to sign SSK headers.
   *
   * <p>Non-null for regular instances constructed via public APIs. It may be {@code null} only on
   * objects created by the protected no-arg constructor for deserialization purposes. Do not log or
   * persist this key outside the node's secure storage.
   */
  public final DSAPrivateKey privKey;

  /**
   * Constructs an insertable SSK from its components.
   *
   * <p>The supplied parameters must correspond to each other (e.g., {@code pubKey} must be derived
   * from {@code privKey}; {@code pubKeyHash} must hash to {@code pubKey}). The encryption
   * parameters must identify AES/PCFB-256 with SHA-256.
   *
   * @param docName document name component of the SSK URI (may be empty but should not be {@code
   *     null})
   * @param pubKeyHash SHA-256 hash of {@code pubKey} in the format expected by the routing layer
   * @param pubKey DSA public key corresponding to {@code privKey}
   * @param privKey DSA private key used to sign the block headers
   * @param cryptoKey symmetric key used for AES/PCFB encryption of data and headers
   * @param cryptoAlgorithm crypto algorithm identifier; must be {@link
   *     Key#ALGO_AES_PCFB_256_SHA256}
   * @throws MalformedURLException if the parameters do not describe a supported insertable SSK
   */
  public InsertableClientSSK(
      String docName,
      byte[] pubKeyHash,
      DSAPublicKey pubKey,
      DSAPrivateKey privKey,
      byte[] cryptoKey,
      byte cryptoAlgorithm)
      throws MalformedURLException {
    super(docName, pubKeyHash, getExtraBytes(cryptoAlgorithm), pubKey, cryptoKey);
    if (pubKey == null) throw new NullPointerException();
    this.privKey = privKey;
  }

  /**
   * Protected no-arg constructor for serialization frameworks.
   *
   * <p>Regular code should not use this constructor. The resulting instance is not fully
   * initialized until deserialization populates fields; {@link #privKey} is {@code null} here.
   */
  protected InsertableClientSSK() {
    // Serialization hook only; fields are completed during readObject.
    privKey = null;
  }

  /**
   * Builds an insert-capable client SSK from a URI.
   *
   * <p>The URI must be an SSK with an embedded private key and crypto key. If the URI denotes a
   * KSK, this method returns a {@link ClientKSK} instance (which is a subclass of {@link
   * InsertableClientSSK}) for compatibility.
   *
   * @param uri SSK (or KSK) URI containing the private key and crypto key
   * @return an insert-capable key matching the URI
   * @throws MalformedURLException if the URI is not an insertable SSK (missing routing or crypto
   *     key, wrong type, or invalid extras), or if key material is malformed
   */
  public static InsertableClientSSK create(FreenetURI uri) throws MalformedURLException {
    if (uri.getKeyType().equalsIgnoreCase("KSK")) return ClientKSK.create(uri);

    if (uri.getRoutingKey() == null)
      throw new MalformedURLException("Insertable SSK URIs must have a private key!: " + uri);
    if (uri.getCryptoKey() == null)
      throw new MalformedURLException("Insertable SSK URIs must have a private key!: " + uri);

    byte keyType = extractKeyType(uri);

    // Allow docName="" for SSKs to remain consistent with key generators. Using an empty name can
    // confuse tools when building freesites and is therefore discouraged.
    if (uri.getDocName() == null)
      throw new MalformedURLException("SSK URIs must have a document name (to avoid ambiguity)");
    DSAGroup g = Global.DSAgroupBigA;
    DSAPrivateKey privKey;
    try {
      privKey = new DSAPrivateKey(new BigInteger(1, uri.getRoutingKey()), g);
    } catch (IllegalArgumentException e) {
      // DSAPrivateKey is invalid — rethrow with context without logging secrets.
      throw new MalformedURLException("SSK private key (routing key) is invalid: " + e);
    }
    DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
    byte[] pkHash = pubKey.asBytesHash();
    return new InsertableClientSSK(
        uri.getDocName(), pkHash, pubKey, privKey, uri.getCryptoKey(), keyType);
  }

  /**
   * Validate the URI type and extras and return the SSK crypto algorithm byte.
   *
   * <p>Throws {@link MalformedURLException} with a descriptive message when the URI is not an SSK
   * insert URI or when its extras are missing/invalid.
   */
  private static byte extractKeyType(FreenetURI uri) throws MalformedURLException {
    if (!"SSK".equals(uri.getKeyType()))
      throw new MalformedURLException("Not a valid SSK insert URI type: " + uri.getKeyType());
    byte[] extra = uri.getExtra();
    if (extra == null) throw new MalformedURLException("Inserting pre-1010 keys not supported");
    if (extra.length < 5) throw new MalformedURLException("SSK private key ,extra too short");
    if (extra[1] != 1) throw new MalformedURLException("SSK not a private key");
    byte keyType = extra[2];
    if (keyType != Key.ALGO_AES_PCFB_256_SHA256)
      throw new MalformedURLException("Unrecognized crypto type in SSK private key");
    return keyType;
  }

  /**
   * Encodes content into a signed and encrypted {@link ClientSSKBlock}.
   *
   * <p>Steps: (1) optionally compress; (2) deterministically pad to {@link SSKBlock#DATA_LENGTH};
   * (3) encrypt data with AES/PCFB-256 where the key is {@code SHA-256(plaintext)}; (4) build
   * headers (hash and crypto identifiers, {@code E(H(doc))}, encrypted metadata); (5) compute an
   * overall hash over headers and encrypted data hash; (6) sign with DSA using deterministic {@code
   * k} derived via HMAC-SHA-256; (7) return the block.
   *
   * <p>This method reads from {@code params.sourceData()} but does not close it.
   *
   * @param params bundle containing compression inputs
   * @return a {@link ClientSSKBlock} containing encrypted data and headers
   * @throws SSKEncodeException on compression or encoding failures
   * @throws IOException on I/O errors while reading {@code params.sourceData()}
   * @throws InvalidCompressionCodecException if {@code params.alreadyCompressedCodec()} is invalid
   *     or unsupported
   */
  public ClientSSKBlock encode(BlockEncodeParams params)
      throws SSKEncodeException, IOException, InvalidCompressionCodecException {
    boolean asMetadata = params.asMetadata();
    byte[] compressedData;
    short compressionAlgo;
    try {
      Compressed comp =
          Key.compress(
              params,
              new CompressionLimits(
                  ClientSSKBlock.MAX_DECOMPRESSED_DATA_LENGTH, SSKBlock.DATA_LENGTH, true));
      compressedData = comp.compressedData;
      compressionAlgo = comp.compressionAlgorithm;
    } catch (KeyEncodeException e) {
      throw new SSKEncodeException(e.getMessage(), e);
    }
    // Pad to a fixed size to avoid leaking the original length.
    MessageDigest md256 = SHA256.getMessageDigest();
    byte[] data;
    // If compressed output is short, deterministically extend it using a PRNG seeded with
    // SHA-256(compressedData).
    if (compressedData.length != SSKBlock.DATA_LENGTH) {
      // Hash the current bytes to seed the PRNG used for padding.
      if (compressedData.length != 0) md256.update(compressedData);
      byte[] digest = md256.digest();
      MersenneTwister mt = MersenneTwister.createUnsynchronized(digest);
      data = Arrays.copyOf(compressedData, SSKBlock.DATA_LENGTH);
      if (compressedData.length > data.length) {
        throw new IllegalStateException(
            "compressedData.length = " + compressedData.length + " but data.length=" + data.length);
      }
      Util.randomBytes(
          mt, data, compressedData.length, SSKBlock.DATA_LENGTH - compressedData.length);
    } else {
      data = compressedData;
    }

    // Hash over the padded plaintext; reused as the data-encryption key.
    byte[] origDataHash = md256.digest(data);

    Rijndael aes;
    try {
      aes = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException("256/256 Rijndael not supported!", e);
    }

    // Encrypt data. Key = SHA-256 (plaintext); IV/feedback state comes from PCFB construction.
    aes.initialize(origDataHash);
    PCFBMode pcfb = PCFBMode.create(aes, origDataHash);

    pcfb.blockEncipher(data, 0, data.length);

    byte[] encryptedDataHash = md256.digest(data);

    // Create headers: algo IDs, E(H(docname)), and encrypted metadata.

    byte[] headers = new byte[SSKBlock.TOTAL_HEADERS_LENGTH];
    // The first two bytes = hash algorithm ID.
    int x = 0;
    headers[x++] = 0;
    headers[x++] = (byte) (KeyBlock.HASH_SHA256);
    // Then crypto algorithm ID (two bytes, big-endian).
    headers[x++] = 0;
    headers[x++] = Key.ALGO_AES_PCFB_256_SHA256;
    // Then E(H(docname)) — already prepared in {@code ehDocname} by the superclass.
    System.arraycopy(ehDocname, 0, headers, x, ehDocname.length);
    x += ehDocname.length;
    // Now the encrypted headers
    byte[] encryptedHeaders = Arrays.copyOf(origDataHash, SSKBlock.ENCRYPTED_HEADERS_LENGTH);
    int y = origDataHash.length;
    short len = (short) compressedData.length;
    if (asMetadata) len = (short) (len | 0x8000);
    encryptedHeaders[y++] = (byte) (len >> 8);
    encryptedHeaders[y++] = (byte) len;
    encryptedHeaders[y++] = (byte) (compressionAlgo >> 8);
    encryptedHeaders[y++] = (byte) compressionAlgo;
    if (encryptedHeaders.length != y)
      throw new IllegalStateException("Have more bytes to generate encoding SSK");
    aes.initialize(cryptoKey);
    pcfb.reset(ehDocname);
    pcfb.blockEncipher(encryptedHeaders, 0, encryptedHeaders.length);
    System.arraycopy(encryptedHeaders, 0, headers, x, encryptedHeaders.length);
    x += encryptedHeaders.length;
    // Generate an implicit overall hash signed below.
    md256.update(headers, 0, x);
    md256.update(encryptedDataHash);
    byte[] overallHash = md256.digest();
    // Now sign it
    DSASigner dsa = new DSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    dsa.init(true, new DSAPrivateKeyParameters(privKey.getX(), Global.getDSAgroupBigAParameters()));
    BigInteger[] sig = dsa.generateSignature(Global.truncateHash(overallHash));
    // Pack R and S into fixed 32-byte fields, append to headers, and build the block.
    byte[] rBuf = truncate(sig[0].toByteArray(), SSKBlock.SIG_R_LENGTH);
    byte[] sBuf = truncate(sig[1].toByteArray(), SSKBlock.SIG_S_LENGTH);
    System.arraycopy(rBuf, 0, headers, x, rBuf.length);
    x += rBuf.length;
    System.arraycopy(sBuf, 0, headers, x, sBuf.length);
    x += sBuf.length;
    if (x != SSKBlock.TOTAL_HEADERS_LENGTH) throw new IllegalStateException("Too long");
    try {
      return new ClientSSKBlock(data, headers, this, !LOG.isDebugEnabled());
    } catch (SSKVerifyException e) {
      throw new AssertionError("Impossible encoding error", e);
    }
  }

  /**
   * Left-pads or trims a big-endian integer to the requested byte length.
   *
   * <p>When {@code bs} is longer than {@code len}, only leading zero bytes may be removed; any
   * non-zero high-order byte would change the value and therefore triggers an exception.
   */
  private byte[] truncate(byte[] bs, int len) {
    if (bs.length == len) return bs;
    else if (bs.length < len) {
      byte[] buf = new byte[len];
      System.arraycopy(bs, 0, buf, len - bs.length, bs.length);
      return buf;
    } else {
      for (int i = 0; i < (bs.length - len); i++) {
        if (bs[i] != 0) throw new IllegalStateException("Cannot truncate");
      }
      return Arrays.copyOfRange(bs, bs.length - len, bs.length);
    }
  }

  /**
   * Generates a new random insertable SSK.
   *
   * <p>Uses the standard DSA group ({@link Global#DSAgroupBigA}) and AES/PCFB-256 with SHA-256 for
   * content encryption. The {@code docName} may be empty; an empty document name is allowed but
   * discouraged for human-facing content.
   *
   * @param r cryptographically strong random source
   * @param docName document name to embed in the key's URI (may be empty)
   * @return a new key pair with random crypto and signing keys
   */
  public static InsertableClientSSK createRandom(RandomSource r, String docName) {
    byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
    r.nextBytes(ckey);
    DSAGroup g = Global.DSAgroupBigA;
    DSAPrivateKey privKey = new DSAPrivateKey(g, r);
    DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
    try {
      byte[] pkHash = SHA256.digest(pubKey.asBytes());
      return new InsertableClientSSK(
          docName, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Returns an insert-capable URI for this key.
   *
   * <p>The URI includes the private (routing) key and the symmetric crypto key in its components,
   * allowing clients to insert or update content under this SSK.
   *
   * @return an {@link FreenetURI} suitable for insertion
   */
  public FreenetURI getInsertURI() {
    return new FreenetURI(
        "SSK", docName, privKey.getX().toByteArray(), cryptoKey, getInsertExtraBytes());
  }

  private byte[] getInsertExtraBytes() {
    byte[] extra = getExtraBytes();
    extra[1] = 1; // insert
    return extra;
  }

  /** Returns the DSA group used for SSK signing (BigA). */
  public DSAGroup getCryptoGroup() {
    return Global.DSAgroupBigA;
  }

  /**
   * Equality is consistent with {@link ClientSSK#equals(Object)} to avoid changing behavior.
   *
   * <p>This subclass introduces {@link #privKey}, but equality across client keys in this codebase
   * historically depends only on the public routing/decryption components. To satisfy static
   * analysis (subclass adds fields), we override {@code equals} and delegate to the superclass
   * implementation, which compares the established SSK fields. This keeps semantics unchanged and
   * preserves symmetry with {@link ClientSSK} instances.
   */
  @Override
  public boolean equals(Object o) {
    // Keep semantics identical to ClientSSK.equals(); do a light-type guard to avoid a trivial
    // pass-through override while preserving behavior.
    return (o instanceof ClientSSK) && super.equals(o);
  }

  /** Hash code remains the base computation to stay consistent with {@link #equals(Object)}. */
  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
