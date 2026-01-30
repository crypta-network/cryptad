package network.crypta.keys;

import java.io.Serial;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;

/**
 * Client-side Subspace Key (SSK) used to fetch and decrypt SSK content.
 *
 * <p>An instance carries the routing information (public key hash), the decryption key, and the
 * encrypted hash of the document name. It does <strong>not</strong> contain the private key
 * required to sign new content. Use {@link InsertableClientSSK} to construct insert-capable keys.
 *
 * <p>Thread-safety: All state other than the optional {@link #pubKey} and the cached node key is
 * effectively immutable. {@link #setPublicKey(DSAPublicKey)} may be called at most once to attach a
 * matching public key. {@link #getNodeKey(boolean)} caches a derived {@link NodeSSK} and
 * synchronizes on {@code this} while (re)computing it.
 */
public class ClientSSK extends ClientKey {
  // No logger required; this class does not log.

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Encryption algorithm identifier used by this key. The current implementation expects {@link
   * Key#ALGO_AES_PCFB_256_SHA256}.
   */
  public final byte cryptoAlgorithm;

  /**
   * Document name component of the URI. Encoded as UTF-8 when computing the hashed/encrypted
   * document name.
   */
  public final String docName;

  /**
   * DSA public key associated with the keypair; may be {@code null} until provided via {@link
   * #setPublicKey(DSAPublicKey)}. Transient to avoid redundant serialization.
   */
  protected transient DSAPublicKey pubKey;

  /**
   * Hash of the serialized DSA public key, length {@link NodeSSK#PUBKEY_HASH_SIZE} bytes. This is
   * used for routing and must match any later {@link #pubKey} supplied.
   */
  public final byte[] pubKeyHash;

  /**
   * Decryption key used for SSK content and for encrypting the hashed document name. Length is
   * {@link #CRYPTO_KEY_LENGTH} bytes. Callers must not mutate the array contents.
   */
  public final byte[] cryptoKey;

  /**
   * Encrypted hash of the document name: {@code AES256( SHA-256(docName UTF-8) )} using {@link
   * #cryptoKey}. Used as part of the node-level key derivation.
   */
  public final byte[] ehDocname;

  private final int hashCode;

  /** Length of the decryption key in bytes (32). */
  public static final int CRYPTO_KEY_LENGTH = 32;

  /** Length of the {@code extra} field in SSK URIs (5). */
  public static final int EXTRA_LENGTH = 5;

  private ClientSSK(ClientSSK key) {
    this.cryptoAlgorithm = key.cryptoAlgorithm;
    this.docName = key.docName;
    if (key.pubKey != null) this.pubKey = key.pubKey.cloneKey();
    else this.pubKey = null;
    pubKeyHash = key.pubKeyHash.clone();
    cryptoKey = key.cryptoKey.clone();
    ehDocname = key.ehDocname.clone();
    hashCode =
        Fields.hashCode(pubKeyHash)
            ^ Fields.hashCode(cryptoKey)
            ^ Fields.hashCode(ehDocname)
            ^ docName.hashCode();
  }

  /**
   * Construct a client SSK from individual components.
   *
   * @param docName document name (non-{@code null}); encoded as UTF-8 for hashing
   * @param pubKeyHash hash of the serialized DSA public key; length {@link
   *     NodeSSK#PUBKEY_HASH_SIZE}
   * @param extras SSK {@code extras} bytes; must equal {@link #getExtraBytes()} for this instance
   * @param pubKey optional DSA public key; if non-{@code null} its hash must equal {@code
   *     pubKeyHash}
   * @param cryptoKey decryption key; length {@link #CRYPTO_KEY_LENGTH}
   * @throws MalformedURLException if {@code docName} is {@code null}; {@code extras} are missing,
   *     malformed, or specify an unknown algorithm; the {@code pubKeyHash} or {@code cryptoKey}
   *     length is incorrect
   * @throws IllegalArgumentException if {@code pubKey} is non-{@code null} and its hash does not
   *     equal {@code pubKeyHash}
   * @throws IllegalStateException if the AES cipher implementation is unavailable
   */
  public ClientSSK(
      String docName, byte[] pubKeyHash, byte[] extras, DSAPublicKey pubKey, byte[] cryptoKey)
      throws MalformedURLException {
    // Validate arguments and compute the encrypted docname used by the node-level key.
    this.docName = docName;
    this.pubKey = pubKey;
    this.pubKeyHash = pubKeyHash;
    if (docName == null) throw new MalformedURLException("No document name.");
    if (extras == null) throw new MalformedURLException("No extra bytes in SSK - maybe a 0.5 key?");
    if (extras.length < 5)
      throw new MalformedURLException("Extra bytes too short: " + extras.length + " bytes");
    this.cryptoAlgorithm = extras[2];
    if (cryptoAlgorithm != Key.ALGO_AES_PCFB_256_SHA256)
      throw new MalformedURLException("Unknown encryption algorithm " + cryptoAlgorithm);
    if (!Arrays.equals(extras, getExtraBytes()))
      throw new MalformedURLException("Wrong extra bytes");
    if (pubKeyHash.length != NodeSSK.PUBKEY_HASH_SIZE)
      throw new MalformedURLException(
          "Pubkey hash wrong length: "
              + pubKeyHash.length
              + " should be "
              + NodeSSK.PUBKEY_HASH_SIZE);
    if (cryptoKey.length != CRYPTO_KEY_LENGTH)
      throw new MalformedURLException(
          "Decryption key wrong length: " + cryptoKey.length + " should be " + CRYPTO_KEY_LENGTH);
    MessageDigest md = SHA256.getMessageDigest();
    if (pubKey != null) {
      byte[] pubKeyAsBytes = pubKey.asBytes();
      md.update(pubKeyAsBytes);
      byte[] otherPubKeyHash = md.digest();
      if (!Arrays.equals(otherPubKeyHash, pubKeyHash)) throw new IllegalArgumentException();
    }
    this.cryptoKey = cryptoKey;
    md.update(docName.getBytes(StandardCharsets.UTF_8));
    byte[] buf = md.digest();
    try {
      Rijndael aes = new Rijndael(256, 256);
      aes.initialize(cryptoKey);
      aes.encipher(buf, buf);
      ehDocname = buf;
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException("AES cipher unavailable", e);
    }
    hashCode =
        Fields.hashCode(pubKeyHash)
            ^ Fields.hashCode(cryptoKey)
            ^ Fields.hashCode(ehDocname)
            ^ docName.hashCode();
  }

  /**
   * Build a client SSK from a {@link FreenetURI}.
   *
   * @param origURI URI whose type must be {@code "SSK"}; the routing key, extra bytes, and crypto
   *     key are extracted; the public key is optional and may be absent.
   * @throws MalformedURLException if the URI is not an SSK URI or any component fails validation.
   */
  public ClientSSK(FreenetURI origURI) throws MalformedURLException {
    this(
        origURI.getDocName(),
        origURI.getRoutingKey(),
        origURI.getExtra(),
        null,
        origURI.getCryptoKey());
    if (!origURI.getKeyType().equalsIgnoreCase("SSK")) throw new MalformedURLException();
  }

  /** No-arg constructor for serialization frameworks. Not intended for general use. */
  protected ClientSSK() {
    // For serialization frameworks only.
    this.cryptoAlgorithm = 0;
    this.docName = null;
    this.pubKeyHash = null;
    this.cryptoKey = null;
    this.ehDocname = null;
    this.hashCode = 0;
  }

  /**
   * Attach the DSA public key for signature verification.
   *
   * <p>If a key was previously attached, it must be the same logical key; attempts to change it to
   * a different key are rejected. The supplied key's hash must match {@link #pubKeyHash}.
   *
   * @param pubKey public key to associate with this SSK
   * @throws IllegalArgumentException if attempting to reassign to a different key or if the
   *     computed hash of {@code pubKey} does not equal {@link #pubKeyHash}
   */
  public synchronized void setPublicKey(DSAPublicKey pubKey) {
    if (this.pubKey != null && !this.pubKey.equals(pubKey))
      throw new IllegalArgumentException("Cannot reassign: was " + this.pubKey + " now " + pubKey);
    byte[] newKeyHash = pubKey.asBytesHash();
    if (!Arrays.equals(newKeyHash, pubKeyHash))
      throw new IllegalArgumentException(
          "New pubKey hash does not match pubKeyHash: "
              + HexUtil.bytesToHex(newKeyHash)
              + " ( "
              + HexUtil.bytesToHex(pubKey.asBytesHash())
              + " != "
              + HexUtil.bytesToHex(pubKeyHash)
              + " for "
              + pubKey);
    this.pubKey = pubKey;
    this.cachedNodeKey = null;
  }

  /**
   * Return the canonical client fetch URI for this key.
   *
   * @return a {@link FreenetURI} with type {@code "SSK"}, the document name, the routing key, the
   *     crypto key, and the correct {@code extra} bytes for this algorithm
   */
  @Override
  public FreenetURI getURI() {
    return new FreenetURI("SSK", docName, pubKeyHash, cryptoKey, getExtraBytes());
  }

  /** Extra bytes for this instance's algorithm. See {@link #getExtraBytes(byte)} for layout. */
  protected final byte[] getExtraBytes() {
    return getExtraBytes(cryptoAlgorithm);
  }

  /**
   * Construct the 5-byte SSK {@code extra} field used in URIs and for key derivation.
   *
   * <p>Layout: <br>
   * [0] {@link NodeSSK#SSK_VERSION} <br>
   * [1] {@code 0} = fetch (public) URI; {@code 1} = insert (private) URI <br>
   * [2] {@code cryptoAlgorithm} <br>
   * [3] high byte of {@link KeyBlock#HASH_SHA256} <br>
   * [4] low byte of {@link KeyBlock#HASH_SHA256}
   *
   * @param cryptoAlgorithm algorithm identifier to encode
   * @return a new 5-byte array containing the encoded extras
   */
  protected static byte[] getExtraBytes(byte cryptoAlgorithm) {
    // Allocate the fixed-size buffer for the extras.
    byte[] extra = new byte[5];

    extra[0] = NodeSSK.SSK_VERSION;
    extra[1] = 0; // 0 = fetch (public) URI; 1 = insert (private) URI
    extra[2] = cryptoAlgorithm;
    extra[3] = 0;
    extra[4] = (byte) KeyBlock.HASH_SHA256;
    return extra;
  }

  private transient Key cachedNodeKey;

  /**
   * Derive the node-level key ({@link NodeSSK}) corresponding to this client key.
   *
   * <p>The result is cached. When {@code cloneKey} is {@code true}, a defensive clone of the
   * underlying node key is returned.
   *
   * @param cloneKey whether to return a cloned copy of the derived node key
   * @return the derived {@link Key} (specifically a {@link NodeSSK})
   * @throws AssertionError if an internal verification error occurs after prior successful
   *     validation; indicates an unexpected inconsistency
   */
  @Override
  public Key getNodeKey(boolean cloneKey) {
    try {
      Key nodeKey;
      synchronized (this) {
        // Guard against partially deserialized objects.
        if (ehDocname == null) throw new NullPointerException();
        if (pubKeyHash == null) throw new NullPointerException();
        if (cachedNodeKey == null
            || cachedNodeKey.getKeyBytes() == null
            || cachedNodeKey.getRoutingKey() == null)
          cachedNodeKey = new NodeSSK(pubKeyHash, ehDocname, pubKey, cryptoAlgorithm);
        nodeKey = cachedNodeKey;
      }
      return cloneKey ? nodeKey.cloneKey() : nodeKey;
    } catch (SSKVerifyException e) {
      throw new AssertionError("Have already verified and yet it fails!", e);
    }
  }

  /**
   * Return the attached public key, or {@code null} if not set.
   *
   * @return the DSA public key, possibly {@code null}
   */
  public DSAPublicKey getPubKey() {
    return pubKey;
  }

  /** Human-readable representation containing the canonical URI. */
  @Override
  public String toString() {
    return "ClientSSK:" + getURI().toString();
  }

  /**
   * Return a deep copy of this key. Array fields and the optional {@link #pubKey} are cloned as
   * needed.
   */
  @Override
  public ClientKey cloneKey() {
    return new ClientSSK(this);
  }

  /**
   * Precomputed hash code consistent with {@link #equals(Object)}. Includes the document name,
   * public key hash, decryption key, and encrypted document name.
   */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Equality based on algorithm, document name, public key hash, decryption key, and encrypted
   * document name. Does not consider the cached node key.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ClientSSK key)) return false;
    if (cryptoAlgorithm != key.cryptoAlgorithm) return false;
    if (!docName.equals(key.docName)) return false;
    if (!Arrays.equals(pubKeyHash, key.pubKeyHash)) return false;
    if (!Arrays.equals(cryptoKey, key.cryptoKey)) return false;
    return Arrays.equals(ehDocname, key.ehDocname);
  }
}
