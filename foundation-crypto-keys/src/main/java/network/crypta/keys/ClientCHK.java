package network.crypta.keys;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.security.SecureRandom;
import java.util.Arrays;
import network.crypta.support.Base64;
import network.crypta.support.Fields;

/**
 * Client-facing Content Hash Key (CHK).
 *
 * <p>This type encapsulates both the routing hash (used for store/route) and the decryption key
 * (kept client-side). It can be serialized to and from {@link FreenetURI}, written/read in a
 * compact binary form, used to decrypt a {@link CHKBlock}, and produced by a {@link CHKBlock}.
 *
 * <p>Instances are effectively immutable. A cached {@link NodeCHK} is created lazily on first
 * access by {@link #getNodeCHK()} and reused thereafter.
 *
 * <p>"Extra" bytes format (length {@link #EXTRA_LENGTH}):
 *
 * <ul>
 *   <li>byte[0]: reserved
 *   <li>byte[1]: crypto algorithm (see {@link Key#ALGO_AES_PCFB_256_SHA256} and {@link
 *       Key#ALGO_AES_CTR_256_SHA256})
 *   <li>byte[2]: flags (bit 1 set means control document)
 *   <li>byte[3..4]: compression algorithm (big-endian {@code short}; negative means uncompressed)
 * </ul>
 */
public final class ClientCHK extends ClientKey implements Serializable {
  @Serial private static final long serialVersionUID = 1L;

  /** Lazily constructed cached {@link NodeCHK}. */
  transient NodeCHK nodeKey;

  /** Routing hash used for lookup and storage. */
  final byte[] routingKey;

  /** Symmetric decryption key (client-side secret). */
  final byte[] cryptoKey;

  /** Whether the CHK refers to a control/metadata document. */
  final boolean controlDocument;

  /** Identifier of the encryption algorithm used. */
  final byte cryptoAlgorithm;

  /** Compression algorithm; negative value means "uncompressed". */
  final short compressionAlgorithm;

  final int hashCode;

  /*
   * We intentionally read/write exactly EXTRA_LENGTH bytes for the "extra" field to keep callers
   * that rely on the precise size consistent. If the format changes, update those call sites first.
   */
  /** The length of the "extra" bytes carried by a CHK. */
  public static final short EXTRA_LENGTH = 5;

  /** The length of the decryption key */
  public static final short CRYPTO_KEY_LENGTH = 32;

  /** A sample key instance useful for length checks and test scaffolding. */
  public static final ClientCHK TEST_KEY;

  static {
    try {
      TEST_KEY = new ClientCHK(FreenetURI.generateRandomCHK(new SecureRandom()));
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }

  private ClientCHK(ClientCHK key) {
    this.routingKey = key.routingKey.clone();
    this.nodeKey = null;
    this.cryptoKey = key.cryptoKey.clone();
    this.controlDocument = key.controlDocument;
    this.cryptoAlgorithm = key.cryptoAlgorithm;
    this.compressionAlgorithm = key.compressionAlgorithm;
    hashCode = key.hashCode;
  }

  /**
   * Construct a CHK from its components.
   *
   * @param routingKey overall routing hash for the block content and header; must not be {@code
   *     null}.
   * @param encKey decryption key extracted from the URI; not shared with other nodes.
   * @param isControlDocument whether the key addresses a control/metadata document.
   * @param algo encryption algorithm identifier (see {@link Key#ALGO_AES_PCFB_256_SHA256} and
   *     {@link Key#ALGO_AES_CTR_256_SHA256}).
   * @param compressionAlgorithm compression algorithm; negative means "uncompressed".
   */
  public ClientCHK(
      byte[] routingKey,
      byte[] encKey,
      boolean isControlDocument,
      byte algo,
      short compressionAlgorithm) {
    this.routingKey = routingKey;
    this.cryptoKey = encKey;
    this.controlDocument = isControlDocument;
    this.cryptoAlgorithm = algo;
    this.compressionAlgorithm = compressionAlgorithm;
    if (routingKey == null) throw new NullPointerException();
    hashCode = Fields.hashCode(routingKey) ^ Fields.hashCode(encKey) ^ compressionAlgorithm;
  }

  /**
   * Construct a CHK from raw parts and an {@code extra} descriptor.
   *
   * @param routingKey overall routing hash; must not be {@code null}.
   * @param encKey decryption key bytes.
   * @param extra 5-byte descriptor; index 1 holds the crypto algorithm, index 2 the control flag,
   *     and indices 3–4 the compression algorithm (big-endian {@code short}). Byte 0 is reserved.
   * @throws MalformedURLException if {@code extra} is missing/short or the crypto algorithm is not
   *     supported.
   */
  public ClientCHK(byte[] routingKey, byte[] encKey, byte[] extra) throws MalformedURLException {
    this.routingKey = routingKey;
    this.cryptoKey = encKey;
    if ((extra == null) || (extra.length < 5))
      throw new MalformedURLException("No extra bytes in CHK - maybe a 0.5 key?");
    // byte 0 is reserved, for now
    cryptoAlgorithm = extra[1];
    if (!(cryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256
        || cryptoAlgorithm == Key.ALGO_AES_CTR_256_SHA256))
      throw new MalformedURLException("Invalid crypto algorithm");
    controlDocument = (extra[2] & 0x02) != 0;
    compressionAlgorithm = (short) (((extra[3] & 0xff) << 8) + (extra[4] & 0xff));
    hashCode = Fields.hashCode(routingKey) ^ Fields.hashCode(cryptoKey) ^ compressionAlgorithm;
  }

  /**
   * Construct a CHK from a {@link FreenetURI}.
   *
   * @param uri a CHK-form {@link FreenetURI}.
   * @throws MalformedURLException if the URI is not of type {@code CHK}, if the {@code extra}
   *     component is missing/short, or if the contained crypto algorithm is unsupported.
   */
  public ClientCHK(FreenetURI uri) throws MalformedURLException {
    if (!uri.getKeyType().equals("CHK")) throw new MalformedURLException("Not CHK");
    routingKey = uri.getRoutingKey();
    cryptoKey = uri.getCryptoKey();
    byte[] extra = uri.getExtra();
    if ((extra == null) || (extra.length < 5))
      throw new MalformedURLException("No extra bytes in CHK - maybe a 0.5 key?");
    // byte 0 is reserved, for now
    cryptoAlgorithm = extra[1];
    if (!(cryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256
        || cryptoAlgorithm == Key.ALGO_AES_CTR_256_SHA256))
      throw new MalformedURLException("Invalid crypto algorithm");
    controlDocument = (extra[2] & 0x02) != 0;
    compressionAlgorithm = (short) (((extra[3] & 0xff) << 8) + (extra[4] & 0xff));
    hashCode = Fields.hashCode(routingKey) ^ Fields.hashCode(cryptoKey) ^ compressionAlgorithm;
  }

  /**
   * Construct a CHK by reading its compact binary form.
   *
   * <p>The binary layout is: {@code extra[5]}, {@code routingKey[NodeCHK.KEY_LENGTH]}, then {@code
   * cryptoKey[CRYPTO_KEY_LENGTH]}.
   *
   * @param dis input to read from; the method blocks until all bytes are read.
   * @throws IOException on I/O errors or premature end of stream.
   * @throws MalformedURLException if the embedded crypto algorithm is unsupported.
   */
  public ClientCHK(DataInputStream dis) throws IOException {
    byte[] extra = new byte[EXTRA_LENGTH];
    dis.readFully(extra);
    // byte 0 is reserved, for now
    cryptoAlgorithm = extra[1];
    if (!(cryptoAlgorithm == Key.ALGO_AES_PCFB_256_SHA256
        || cryptoAlgorithm == Key.ALGO_AES_CTR_256_SHA256))
      throw new MalformedURLException("Invalid crypto algorithm");
    compressionAlgorithm = (short) (((extra[3] & 0xff) << 8) + (extra[4] & 0xff));
    controlDocument = (extra[2] & 0x02) != 0;
    routingKey = new byte[NodeCHK.KEY_LENGTH];
    dis.readFully(routingKey);
    cryptoKey = new byte[CRYPTO_KEY_LENGTH];
    dis.readFully(cryptoKey);
    hashCode = Fields.hashCode(routingKey) ^ Fields.hashCode(cryptoKey) ^ compressionAlgorithm;
  }

  ClientCHK() {
    // For serialization frameworks only.
    routingKey = null;
    cryptoKey = null;
    controlDocument = false;
    cryptoAlgorithm = 0;
    compressionAlgorithm = 0;
    hashCode = 0;
  }

  /**
   * Write the compact binary representation of this key.
   *
   * <p>The layout is identical to the one read by {@link #ClientCHK(DataInputStream)}: {@code
   * extra[5]}, {@code routingKey[NodeCHK.KEY_LENGTH]}, then {@code cryptoKey[CRYPTO_KEY_LENGTH]}.
   *
   * @param dos destination to write to.
   * @throws IOException if writing fails.
   */
  public void writeRawBinaryKey(DataOutputStream dos) throws IOException {
    dos.write(getExtra());
    dos.write(routingKey);
    dos.write(cryptoKey);
  }

  /**
   * Return the "extra" descriptor for this key.
   *
   * @return a 5-byte array encoding algorithm, flags, and compression as defined for {@link
   *     #getExtra(byte, short, boolean)}.
   */
  public byte[] getExtra() {
    return getExtra(cryptoAlgorithm, compressionAlgorithm, controlDocument);
  }

  /**
   * Build the 5-byte {@code extra} descriptor.
   *
   * @param cryptoAlgorithm algorithm identifier (stored in {@code extra[1]}).
   * @param compressionAlgorithm compression identifier; negative means "uncompressed" (stored in
   *     {@code extra[3..4]} big-endian).
   * @param controlDocument when {@code true}, sets the control-document flag (bit 1 in {@code
   *     extra[2]}).
   * @return the constructed 5-byte descriptor.
   */
  public static byte[] getExtra(
      byte cryptoAlgorithm, short compressionAlgorithm, boolean controlDocument) {
    byte[] extra = new byte[EXTRA_LENGTH];
    extra[0] = 0;
    extra[1] = cryptoAlgorithm;
    extra[2] = (byte) (controlDocument ? 2 : 0);
    extra[3] = (byte) (compressionAlgorithm >> 8);
    extra[4] = (byte) compressionAlgorithm;
    return extra;
  }

  /**
   * Extract the crypto algorithm identifier from an {@code extra} descriptor.
   *
   * @param extra 5-byte descriptor as produced by {@link #getExtra(byte, short, boolean)}.
   * @return the value stored in {@code extra[1]}.
   */
  public static byte getCryptoAlgorithmFromExtra(byte[] extra) {
    return extra[1];
  }

  /**
   * Human-readable representation for diagnostics.
   *
   * <p>Includes Base64 encodings of the routing and crypto keys and other parameters. The format is
   * not part of any public API and may change.
   *
   * @return a string representation useful for debugging.
   */
  @Override
  public String toString() {
    return super.toString()
        + ':'
        + Base64.encode(routingKey)
        + ','
        + Base64.encode(cryptoKey)
        + ','
        + compressionAlgorithm
        + ','
        + controlDocument
        + ','
        + cryptoAlgorithm;
  }

  @Override
  public Key getNodeKey(boolean cloneKey) {
    return cloneKey ? getNodeCHK().cloneKey() : getNodeCHK();
  }

  /**
   * Return the corresponding {@link NodeCHK}, caching the instance.
   *
   * <p>The first call creates the {@link NodeCHK} from the routing key and algorithm; subsequent
   * calls return the cached instance.
   *
   * @return a {@link NodeCHK} view of this client key.
   */
  public synchronized NodeCHK getNodeCHK() {
    // Cache the NodeCHK; it is frequently requested and cheaper to retain directly than via a
    // reference wrapper.
    if (nodeKey == null) nodeKey = new NodeCHK(routingKey, cryptoAlgorithm);
    return nodeKey;
  }

  /**
   * Convert this key to a {@link FreenetURI} of type {@code CHK}.
   *
   * @return the URI form of this key.
   */
  @Override
  public FreenetURI getURI() {
    byte[] extra = getExtra();
    return new FreenetURI("CHK", null, routingKey, cryptoKey, extra);
  }

  /**
   * Read a CHK from its compact binary form.
   *
   * @param dis source stream; the method blocks until the full key is read.
   * @return the parsed {@link ClientCHK}.
   * @throws IOException on I/O errors or premature end of stream.
   */
  public static ClientCHK readRawBinaryKey(DataInputStream dis) throws IOException {
    return new ClientCHK(dis);
  }

  /**
   * Whether this key refers to a control/metadata document.
   *
   * @return {@code true} if the control-document flag is set.
   */
  public boolean isMetadata() {
    return controlDocument;
  }

  /**
   * Whether the content is marked as compressed.
   *
   * @return {@code true} if {@link #compressionAlgorithm} is non-negative.
   */
  public boolean isCompressed() {
    return compressionAlgorithm >= 0;
  }

  /**
   * Create a deep copy of this key.
   *
   * @return a logically equivalent {@code ClientCHK} with independent arrays.
   */
  @Override
  public ClientCHK cloneKey() {
    return new ClientCHK(this);
  }

  /** Precomputed hash based on the routing key, crypto key, and compression algorithm. */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Equality is defined by routing key, crypto key, control flag, crypto algorithm, and compression
   * algorithm.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ClientCHK key)) return false;
    if (controlDocument != key.controlDocument) return false;
    if (cryptoAlgorithm != key.cryptoAlgorithm) return false;
    if (compressionAlgorithm != key.compressionAlgorithm) return false;
    if (!Arrays.equals(routingKey, key.routingKey)) return false;
    return Arrays.equals(cryptoKey, key.cryptoKey);
  }

  /**
   * Access the routing hash.
   *
   * <p>Returns the internal array; callers must not modify it.
   *
   * @return the routing key bytes.
   */
  public byte[] getRoutingKey() {
    return routingKey;
  }

  /**
   * Access the decryption key.
   *
   * <p>Returns the internal array; callers must not modify it.
   *
   * @return the crypto key bytes.
   */
  public byte[] getCryptoKey() {
    return cryptoKey;
  }

  /**
   * Return the encryption algorithm identifier.
   *
   * @return the algorithm code used for this key.
   */
  public byte getCryptoAlgorithm() {
    return cryptoAlgorithm;
  }
}
