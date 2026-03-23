package network.crypta.keys;

import java.io.Serial;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.support.math.MersenneTwister;

/**
 * Client-side Key Subspace Key (KSK).
 *
 * <p>A {@code ClientKSK} deterministically derives an SSK key pair and related hashes from a
 * human-readable keyword. The derivation uses {@link SHA256} of the UTF-8 bytes of the keyword as a
 * seed for a {@link MersenneTwister} PRNG, from which a DSA private key is generated in the {@link
 * Global#DSAgroupBigA} group. The resulting public key, keyword hash, and algorithm parameters are
 * wired into the base {@link InsertableClientSSK}.
 *
 * <p>Instances are immutable and thread-safe.
 */
public class ClientKSK extends InsertableClientSSK {

  @Serial private static final long serialVersionUID = 1L;
  final String keyword;

  /**
   * Constructs a KSK instance from fully specified components.
   *
   * <p>This is used internally by factory methods after deriving the components. Callers should
   * prefer {@link #create(String)} or {@link #create(FreenetURI)}.
   *
   * @param keyword source keyword used to derive the key pair (must not be {@code null})
   * @param pubKeyHash SHA-256 of the public key bytes
   * @param pubKey derived DSA public key
   * @param privKey derived DSA private key
   * @param keywordHash SHA-256 of the UTF-8 bytes of {@code keyword}
   * @throws MalformedURLException if component validation in the superclass fails
   */
  private ClientKSK(
      String keyword,
      byte[] pubKeyHash,
      DSAPublicKey pubKey,
      DSAPrivateKey privKey,
      byte[] keywordHash)
      throws MalformedURLException {
    super(keyword, pubKeyHash, pubKey, privKey, keywordHash, Key.ALGO_AES_PCFB_256_SHA256);
    this.keyword = keyword;
  }

  /**
   * No-arg constructor for Java serialization frameworks.
   *
   * <p>Not intended for direct use. The instance is incomplete until the deserializer assigns
   * fields.
   */
  @SuppressWarnings("unused")
  protected ClientKSK() {
    // Required by serialization mechanisms.
    keyword = null;
  }

  /**
   * Returns the canonical KSK {@link FreenetURI} for this key.
   *
   * <p>The URI has key type {@code "KSK"} and the document name set to the original keyword.
   *
   * @return a URI that identifies this KSK
   */
  @Override
  public FreenetURI getURI() {
    return new FreenetURI("KSK", keyword);
  }

  /**
   * Compares this key to another for equality.
   *
   * <p>Equality is consistent with {@link ClientSSK}: if the superclass deems two instances equal,
   * this method preserves symmetry even when the other instance is a {@code ClientSSK} but not a
   * {@code ClientKSK}. When both are {@code ClientKSK}, the keywords must also match.
   *
   * @param o the object to compare
   * @return {@code true} when the keys are considered equal
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ClientSSK)) return false;
    if (!super.equals(o)) return false;
    if (o instanceof ClientKSK other) {
      return Objects.equals(this.keyword, other.keyword);
    }
    // Preserve symmetry with ClientSSK: when super.equals(o) is true for a non-ClientKSK
    // (e.g., a ClientSSK), treat the instances as equal.
    return true;
  }

  /**
   * Returns a hash code consistent with {@link #equals(Object)} and {@link ClientSSK}.
   *
   * @return the hash code
   */
  @Override
  public int hashCode() {
    // Must remain consistent with ClientSSK to preserve the equals/hashCode contract when
    // cross-comparing with ClientSSK.
    return super.hashCode();
  }

  /**
   * Creates a {@code ClientKSK} from a {@link FreenetURI}.
   *
   * <p>The URI must have key type {@code "KSK"}; the document name is treated as the keyword. The
   * keyword is used as-is (byte-wise, UTF-8) with no normalization; callers should ensure any
   * required normalization upstream.
   *
   * @param uri the input URI whose doc name provides the keyword
   * @return a new {@code ClientKSK} derived from {@code uri}
   * @throws IllegalArgumentException if {@code uri} does not have key type {@code "KSK"}
   */
  public static InsertableClientSSK fromUri(FreenetURI uri) {
    if (!uri.getKeyType().equals("KSK")) throw new IllegalArgumentException();
    return create(uri.getDocName());
  }

  /**
   * Creates a {@code ClientKSK} from a keyword.
   *
   * <p>Derivation uses {@link SHA256} over the UTF-8 bytes of {@code keyword} as a PRNG seed for a
   * {@link MersenneTwister}, then generates a DSA key pair in {@link Global#DSAgroupBigA}. The
   * result is deterministic for the same keyword. The keyword is case-sensitive and is not trimmed
   * or otherwise normalized.
   *
   * @param keyword the human-readable token (must not be {@code null})
   * @return a new {@code ClientKSK}
   * @throws NullPointerException if {@code keyword} is {@code null}
   */
  public static ClientKSK create(String keyword) {
    MessageDigest md256 = SHA256.getMessageDigest();
    byte[] keywordHash = md256.digest(keyword.getBytes(StandardCharsets.UTF_8));
    MersenneTwister mt = MersenneTwister.createUnsynchronized(keywordHash);
    DSAPrivateKey privKey = new DSAPrivateKey(Global.DSAgroupBigA, mt);
    DSAPublicKey pubKey = new DSAPublicKey(Global.DSAgroupBigA, privKey);
    byte[] pubKeyHash = md256.digest(pubKey.asBytes());
    try {
      return new ClientKSK(keyword, pubKeyHash, pubKey, privKey, keywordHash);
    } catch (MalformedURLException e) {
      // Construction uses validated, internally derived values; reaching here indicates an
      // unexpected invariant violation in the superclass validation.
      throw new IllegalStateException(e);
    }
  }
}
