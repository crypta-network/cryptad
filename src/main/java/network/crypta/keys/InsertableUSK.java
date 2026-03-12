package network.crypta.keys;

import java.io.Serial;
import java.net.MalformedURLException;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Updatable Subspace Key (USK) that can perform inserts.
 *
 * <p>This variant extends {@link USK} by carrying the DSA private key so callers can derive
 * insert-capable SSKs and sign new editions. It preserves the public USK semantics for equality,
 * ordering, and URIs; the private key is intentionally ignored in {@link #equals(Object)} and
 * {@link #hashCode()}.
 *
 * <p>Notable differences from {@link USK}:
 *
 * <ul>
 *   <li>Holds a {@link DSAPrivateKey} for signing derived SSK blocks.
 *   <li>Provides {@link #getUSK()} to obtain a public-only view without the private key.
 *   <li>Exposes {@link #getInsertableSSK(long)} and {@link #getInsertableSSK(String)} helpers to
 *       produce {@link InsertableClientSSK} instances.
 * </ul>
 */
public final class InsertableUSK extends USK {
  private static final Logger LOG = LoggerFactory.getLogger(InsertableUSK.class);

  @Serial private static final long serialVersionUID = 1L;
  public final DSAPrivateKey privKey;

  /**
   * Dedicated error used when a supposedly-impossible {@link MalformedURLException} occurs while
   * deriving keys. Keeps historical behavior (an {@link Error}) but avoids throwing the generic
   * base class directly to satisfy static analysis.
   */
  private static final class UnexpectedKeyFormatError extends Error {
    @Serial private static final long serialVersionUID = 1L;

    UnexpectedKeyFormatError(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Builds an insert-capable USK from a {@link FreenetURI} of key type {@code USK}.
   *
   * <p>The {@code persistent} flag is accepted for historical compatibility and is currently
   * ignored. Callers should not rely on it affecting behavior.
   *
   * @param uri USK URI that identifies the namespace and suggested edition.
   * @param persistent Ignored; retained for compatibility with legacy call sites.
   * @return A new {@code InsertableUSK} bound to the same namespace and edition.
   * @throws MalformedURLException if {@code uri} is not a USK or contains invalid fields.
   */
  public static InsertableUSK createInsertable(FreenetURI uri, boolean persistent)
      throws MalformedURLException {
    if (LOG.isDebugEnabled()) {
      // Parameter is intentionally ignored by behavior; log for traceability to avoid "unused"
      // parameter and document call sites during migrations.
      LOG.debug("InsertableUSK.createInsertable(persistent={})", persistent);
    }
    if (!uri.getKeyType().equalsIgnoreCase("USK")) throw new MalformedURLException();
    InsertableClientSSK ssk = InsertableClientSSK.create(uri.setKeyType("SSK"));
    return new InsertableUSK(
        ssk.docName,
        ssk.pubKeyHash,
        ssk.cryptoKey,
        ssk.privKey,
        uri.getSuggestedEdition(),
        ssk.cryptoAlgorithm);
  }

  /**
   * Constructs an insertable USK from raw components when the algorithm is already known.
   *
   * @param docName Site name (doc name prefix) without an edition suffix.
   * @param pubKeyHash SSK public key hash, length {@link NodeSSK#PUBKEY_HASH_SIZE}.
   * @param cryptoKey SSK crypto key, length {@link ClientSSK#CRYPTO_KEY_LENGTH}.
   * @param key DSA private key corresponding to the namespace's public key.
   * @param suggestedEdition Edition to store on the instance; used by helpers as a default.
   * @param cryptoAlgorithm Algorithm identifier compatible with {@link ClientSSK}.
   * @throws MalformedURLException if any length is incorrect or parameters are inconsistent.
   */
  InsertableUSK(
      String docName,
      byte[] pubKeyHash,
      byte[] cryptoKey,
      DSAPrivateKey key,
      long suggestedEdition,
      byte cryptoAlgorithm)
      throws MalformedURLException {
    super(pubKeyHash, cryptoKey, docName, suggestedEdition, cryptoAlgorithm);
    if (cryptoKey.length != ClientSSK.CRYPTO_KEY_LENGTH)
      throw new MalformedURLException(
          "Decryption key wrong length: "
              + cryptoKey.length
              + " should be "
              + ClientSSK.CRYPTO_KEY_LENGTH);
    this.privKey = key;
  }

  /**
   * Returns the public-only USK view of this key.
   *
   * <p>The returned instance contains no private material and compares equal to this instance when
   * using {@link USK#equals(Object)} semantics (which ignore the private key).
   *
   * @return A {@link USK} with identical public fields.
   */
  public USK getUSK() {
    return new USK(pubKeyHash, cryptoKey, siteName, suggestedEdition, cryptoAlgorithm);
  }

  /**
   * Derives an {@link InsertableClientSSK} for the given edition.
   *
   * @param ver Edition number to append to the site name.
   * @return An insert-capable SSK for {@code ver}.
   */
  public InsertableClientSSK getInsertableSSK(long ver) {
    return getInsertableSSK(siteName + SEPARATOR + ver);
  }

  /**
   * Derives an {@link InsertableClientSSK} from an explicit document name.
   *
   * <p>The {@code string} is typically {@code <siteName>-<ver>} but may be any valid SSK doc name
   * for this namespace.
   *
   * @param string Doc name to embed in the SSK.
   * @return An insert-capable SSK bound to {@code string}.
   * @throws UnexpectedKeyFormatError if the derived SSK would be malformed.
   */
  public InsertableClientSSK getInsertableSSK(String string) {
    try {
      return new InsertableClientSSK(
          string,
          pubKeyHash,
          new DSAPublicKey(getCryptoGroup(), privKey),
          privKey,
          cryptoKey,
          cryptoAlgorithm);
    } catch (MalformedURLException e) {
      // Rethrow with context but without logging to avoid duplicate log entries when callers log
      // the failure. This preserves historical behavior (Error with MUE cause).
      throw new UnexpectedKeyFormatError(
          "USK.getInsertableSSK failed to build InsertableClientSSK: docName=" + string, e);
    }
  }

  /**
   * Returns a copy with the given edition, retaining the private key.
   *
   * @param edition New edition value.
   * @return A key with {@code edition}; may return {@code this} if unchanged.
   * @throws IllegalStateException if the copy cannot be constructed.
   */
  public InsertableUSK privCopy(long edition) {
    if (edition == suggestedEdition) return this;
    try {
      return new InsertableUSK(siteName, pubKeyHash, cryptoKey, privKey, edition, cryptoAlgorithm);
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Returns the DSA group used for this namespace's keys.
   *
   * @return The group parameters (currently {@link Global#DSAgroupBigA}).
   */
  public final DSAGroup getCryptoGroup() {
    return Global.DSAgroupBigA;
  }

  /**
   * Equality consistent with {@link USK}: compares only public fields and ignores the private key.
   * This preserves historical behavior and symmetry with {@link USK}.
   *
   * @param o Other object.
   * @return {@code true} if public fields match per {@link USK#equals(Object)}.
   */
  @Override
  public boolean equals(Object o) {
    // Accept comparison to any USK instance to keep symmetry: USK.equals(InsertableUSK) may be
    // true, so InsertableUSK.equals(USK) must also consult the same fields.
    return (o instanceof USK) && super.equals(o);
  }

  /**
   * Hash code unchanged from {@link USK} to remain consistent with {@link #equals(Object)}.
   *
   * @return Hash code computed from the public fields only.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
