package network.crypta.keys;

import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Comparator;
import network.crypta.support.Fields;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Updatable Subspace Key (USK).
 *
 * <p>A USK identifies a mutable namespace whose concrete content lives at versioned {@link
 * ClientSSK} locations. A USK itself cannot be fetched directly; callers must derive an SSK for a
 * specific edition.
 *
 * <p>It carries enough information to derive a concrete SSK (public key hash, encryption key and
 * algorithm), plus the site name and a suggested edition number. Equality and ordering can include
 * the edition (see {@link #equals(Object, boolean)} and {@link #compareTo(USK)}).
 *
 * <p>WARNING: This type is {@link java.io.Serializable}. Changing non-transient fields breaks
 * on-disk compatibility and may cause nodes to restart downloads or lose uploads.
 */
public class USK extends BaseClientKey implements Comparable<USK>, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(USK.class);

  @Serial private static final long serialVersionUID = 1L;
  /* Separator between site name and edition in the derived SSK doc name.
   * Chosen as "-" to keep USK → SSK conversion trivial; conversion in the other
   * direction is handled by heuristics in {@link #turnMySSKIntoUSK(FreenetURI)}.
   */
  protected static final String SEPARATOR = "-";

  /**
   * Algorithm identifier used to derive {@code extra} bytes for the underlying SSK. The value
   * matches the {@link ClientSSK} crypto algorithm for this key material.
   */
  public final byte cryptoAlgorithm;

  /** Hash of the SSK public key used by this namespace. */
  protected final byte[] pubKeyHash;

  /** Symmetric encryption key for the SSK namespace. */
  protected final byte[] cryptoKey;

  // Extra must be verified on creation and is fixed for now. If the on-disk format ever
  // allows changing the extra bytes post-construction, persist and validate the chosen
  // value here to keep equality stable.

  /** Human-readable site name component of the doc name. */
  public final String siteName;

  /** Suggested (latest known) edition for convenience when deriving SSKs. */
  public final long suggestedEdition;

  private final int hashCode;

  /**
   * Constructs a USK from raw key material.
   *
   * @param pubKeyHash SSK public key hash, length {@link NodeSSK#PUBKEY_HASH_SIZE}.
   * @param cryptoKey SSK crypto key, length {@link ClientSSK#CRYPTO_KEY_LENGTH}.
   * @param extra Extra bytes identifying the crypto algorithm (validated via {@link ClientSSK}).
   * @param siteName Site name (doc name prefix) without an edition suffix.
   * @param suggestedEdition Edition to suggest when callers do not specify one.
   * @throws MalformedURLException if {@code extra} is missing/invalid or any length is incorrect.
   */
  public USK(
      byte[] pubKeyHash, byte[] cryptoKey, byte[] extra, String siteName, long suggestedEdition)
      throws MalformedURLException {
    this.pubKeyHash = pubKeyHash;
    this.cryptoKey = cryptoKey;
    this.siteName = siteName;
    this.suggestedEdition = suggestedEdition;
    if (extra == null) throw new MalformedURLException("No extra bytes (third bit) in USK");
    if (pubKeyHash == null) throw new MalformedURLException("No pubkey hash (first bit) in USK");
    if (cryptoKey == null) throw new MalformedURLException("No crypto key (second bit) in USK");
    // Verify extra bytes and derive the cryptoAlgorithm. We validate via a temporary ClientSSK
    // to keep the derivation consistent with existing rules.
    ClientSSK tmp = new ClientSSK(siteName, pubKeyHash, extra, null, cryptoKey);
    cryptoAlgorithm = tmp.cryptoAlgorithm;
    if (pubKeyHash.length != NodeSSK.PUBKEY_HASH_SIZE)
      throw new MalformedURLException(
          "Pubkey hash wrong length: "
              + pubKeyHash.length
              + " should be "
              + NodeSSK.PUBKEY_HASH_SIZE);
    if (cryptoKey.length != ClientSSK.CRYPTO_KEY_LENGTH)
      throw new MalformedURLException(
          "Decryption key wrong length: "
              + cryptoKey.length
              + " should be "
              + ClientSSK.CRYPTO_KEY_LENGTH);
    hashCode =
        Fields.hashCode(pubKeyHash)
            ^ Fields.hashCode(cryptoKey)
            ^ siteName.hashCode()
            ^ (int) suggestedEdition
            ^ (int) (suggestedEdition >> 32);
  }

  /**
   * Builds a USK from a {@link FreenetURI} of key type {@code USK}.
   *
   * @param uri A USK URI.
   * @return A new {@code USK} representing the same namespace and edition.
   * @throws MalformedURLException if {@code uri} is not a USK or contains invalid fields.
   */
  public static USK create(FreenetURI uri) throws MalformedURLException {
    if (!uri.isUSK()) throw new MalformedURLException("Not a USK");
    return new USK(
        uri.getRoutingKey(),
        uri.getCryptoKey(),
        uri.getExtra(),
        uri.getDocName(),
        uri.getSuggestedEdition());
  }

  /**
   * Constructs a USK when the algorithm is already known.
   *
   * @param pubKeyHash2 Public key hash.
   * @param cryptoKey2 Crypto key.
   * @param siteName2 Site name without edition.
   * @param suggestedEdition2 Edition to store on the instance.
   * @param cryptoAlgorithm Algorithm identifier compatible with {@link ClientSSK}.
   */
  protected USK(
      byte[] pubKeyHash2,
      byte[] cryptoKey2,
      String siteName2,
      long suggestedEdition2,
      byte cryptoAlgorithm) {
    this.pubKeyHash = pubKeyHash2;
    this.cryptoKey = cryptoKey2;
    this.siteName = siteName2;
    this.suggestedEdition = suggestedEdition2;
    this.cryptoAlgorithm = cryptoAlgorithm;
    hashCode =
        Fields.hashCode(pubKeyHash)
            ^ Fields.hashCode(cryptoKey)
            ^ siteName.hashCode()
            ^ (int) suggestedEdition
            ^ (int) (suggestedEdition >> 32);
  }

  /** For deserialization frameworks only. Fields are initialized to defaults. */
  protected USK() {
    // For serialization frameworks.
    pubKeyHash = null;
    cryptoKey = null;
    siteName = null;
    suggestedEdition = 0;
    cryptoAlgorithm = 0;
    hashCode = 0;
  }

  // No regex: see hasEditionSuffix(String) for a linear, allocation-free detector.

  // Constructor expects a ClientSSK whose docName has no edition suffix; otherwise we would
  // double-encode the edition.
  public USK(ClientSSK ssk, long myARKNumber) {
    this.pubKeyHash = ssk.pubKeyHash;
    this.cryptoKey = ssk.cryptoKey;
    this.siteName = ssk.docName;
    this.suggestedEdition = myARKNumber;
    this.cryptoAlgorithm = ssk.cryptoAlgorithm;

    if (hasEditionSuffix(siteName)) { // not error -- just "possible" bug
      LOG.info("POSSIBLE BUG: edition in ClientSSK {}", ssk);
    }

    hashCode =
        Fields.hashCode(pubKeyHash)
            ^ Fields.hashCode(cryptoKey)
            ^ siteName.hashCode()
            ^ (int) suggestedEdition
            ^ (int) (suggestedEdition >> 32);
  }

  /**
   * Returns {@code true} if the given document name appears to include an edition suffix, i.e., it
   * ends with "-<digits>" or "-<digits>/<...>".
   *
   * <p>Implementation is linear and avoids regex backtracking. It scans for a hyphen followed by at
   * least one digit; the digit run must be followed by either end-of-string or '/'. If a hyphen is
   * followed by a digit run that is immediately followed by a non-'/' non-terminating character,
   * the scan continues after the digit run rather than bailing out, so later "-<digits>" segments
   * are still detected (e.g., {@code foo-1a-23} → {@code true}).
   */
  private static boolean hasEditionSuffix(String name) {
    if (name == null || name.isEmpty()) return false;
    final int len = name.length();
    int from = 0;
    while (from < len) {
      int hy = name.indexOf('-', from);
      if (hy < 0) return false; // no more hyphens
      if (hy + 1 >= len) return false; // trailing '-' cannot start a suffix

      char c = name.charAt(hy + 1);
      if (c < '0' || c > '9') {
        // Not a digit right after '-', keep scanning from the next character.
        from = hy + 1;
        continue;
      }

      int j = skipDigits(name, hy + 1); // first non-digit after the run
      if (j == len || name.charAt(j) == '/') {
        return true; // "-<digits>" at end or before '/'
      }

      // Not a valid suffix at this hyphen; continue scanning from the end of this digit run
      // to allow later segments like "...-1a-23" to be detected.
      from = j;
    }
    return false;
  }

  private static int skipDigits(String s, int start) {
    int i = start;
    final int n = s.length();
    while (i < n) {
      char ch = s.charAt(i);
      if (ch < '0' || ch > '9') break;
      i++;
    }
    return i;
  }

  public USK(USK usk) {
    // Copy the public key hash to avoid sharing mutable arrays across instances.
    // If we can guarantee that neither USK nor anything getting it without copying will change it,
    // we could reuse the original array.
    // db4o treats byte[] as individual byte members, so there are no issues with deactivation.
    this.pubKeyHash = usk.pubKeyHash.clone();
    this.cryptoAlgorithm = usk.cryptoAlgorithm;
    // cryptoKey is reused; the caller retains ownership and must treat it as immutable.
    this.cryptoKey = usk.cryptoKey;
    this.siteName = usk.siteName;
    this.suggestedEdition = usk.suggestedEdition;
    hashCode =
        Fields.hashCode(pubKeyHash)
            ^ Fields.hashCode(cryptoKey)
            ^ siteName.hashCode()
            ^ (int) suggestedEdition
            ^ (int) (suggestedEdition >> 32);
  }

  /**
   * Returns a {@link FreenetURI} representing this USK, including the suggested edition.
   *
   * @return A USK URI equivalent to this instance.
   */
  @Override
  public FreenetURI getURI() {
    return new FreenetURI(
        pubKeyHash,
        cryptoKey,
        ClientSSK.getExtraBytes(cryptoAlgorithm),
        siteName,
        suggestedEdition);
  }

  /**
   * Derives a {@link ClientSSK} for the given edition.
   *
   * @param ver Edition number to append to the site name.
   * @return The corresponding {@code ClientSSK}.
   */
  public ClientSSK getSSK(long ver) {
    return getSSK(getName(ver));
  }

  /**
   * Derives a {@link ClientSSK} using an explicit doc name.
   *
   * @param string Doc name to embed in the SSK (usually {@code siteName + "-" + ver}).
   * @return The corresponding {@code ClientSSK}.
   * @throws IllegalStateException if the constructed SSK would be malformed.
   */
  public ClientSSK getSSK(String string) {
    try {
      return new ClientSSK(
          string, pubKeyHash, ClientSSK.getExtraBytes(cryptoAlgorithm), null, cryptoKey);
    } catch (MalformedURLException e) {
      // Rethrow with context; do not log to avoid double-reporting when callers log the failure.
      throw new IllegalStateException(
          "USK.getSSK failed to build ClientSSK: docName=" + string + ", algo=" + cryptoAlgorithm,
          e);
    }
  }

  /**
   * Returns the doc name for an edition: {@code <siteName>-<ver>}.
   *
   * @param ver Edition number.
   * @return Doc name used in derived SSKs.
   */
  public String getName(long ver) {
    return siteName + SEPARATOR + ver;
  }

  /**
   * Derives a {@link ClientKey} for {@link #suggestedEdition}.
   *
   * @return A {@code ClientSSK} using the stored suggested edition.
   */
  public ClientKey getSSK() {
    return getSSK(suggestedEdition);
  }

  /**
   * Returns a copy with the given edition. May return {@code this} if unchanged.
   *
   * @param edition New edition value.
   * @return A USK with the requested edition.
   */
  public USK copy(long edition) {
    if (suggestedEdition == edition) return this;
    return new USK(pubKeyHash, cryptoKey, siteName, edition, cryptoAlgorithm);
  }

  /** Returns a copy with the edition cleared to {@code 0}. */
  public USK clearCopy() {
    return copy(0);
  }

  /**
   * Returns a structural copy of this instance.
   *
   * <p>The public key hash array is cloned; other immutable fields are reused. This preserves
   * isolation for {@code pubKeyHash} without deep-copying the entire object graph.
   */
  public final USK copy() {
    // We need our own constructor to make sure we copy pubKeyHash.
    // So clone() doesn't work for this.
    // If we can guarantee that no mutable arrays escape, Object.clone() would be safe and we could
    // drop the manual copying.
    return new USK(this);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof USK)) return false;
    return equals(o, true);
  }

  /**
   * Equality test with optional version sensitivity.
   *
   * @param o Other object.
   * @param includeVersion When {@code true}, editions must match; otherwise editions are ignored.
   * @return {@code true} if keys match per the requested semantics.
   */
  public boolean equals(Object o, boolean includeVersion) {
    if (o instanceof USK u) {
      if (!Arrays.equals(pubKeyHash, u.pubKeyHash)) return false;
      if (!Arrays.equals(cryptoKey, u.cryptoKey)) return false;
      if (!siteName.equals(u.siteName)) return false;
      return !includeVersion || (suggestedEdition == u.suggestedEdition);
    }
    return false;
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Returns a base {@link FreenetURI} of type {@code SSK} that omits any edition suffix in the doc
   * name. This is useful for constructing concrete edition URIs externally.
   */
  public FreenetURI getBaseSSK() {
    return new FreenetURI(
        "SSK", siteName, pubKeyHash, cryptoKey, ClientSSK.getExtraBytes(cryptoAlgorithm));
  }

  @Override
  public String toString() {
    return super.toString() + ':' + getURI();
  }

  /**
   * Converts a matching {@code SSK} URI back into a {@code USK} URI using this instance as the
   * reference, when possible.
   *
   * <p>The input must match this key's material and have a doc name of the form {@code
   * <siteName>-<digits>}. If parsing succeeds, the returned URI has key type {@code USK} and
   * carries the parsed edition; otherwise the original URI is returned unchanged.
   *
   * @param uri Candidate SSK URI.
   * @return A USK URI if convertible; otherwise {@code uri}.
   */
  public FreenetURI turnMySSKIntoUSK(FreenetURI uri) {
    if (uri.getKeyType().equals("SSK")
        && Arrays.equals(uri.getRoutingKey(), pubKeyHash)
        && Arrays.equals(uri.getCryptoKey(), cryptoKey)
        && Arrays.equals(uri.getExtra(), ClientSSK.getExtraBytes(cryptoAlgorithm))
        && uri.getDocName() != null
        && uri.getDocName().startsWith(siteName)) {
      String doc = uri.getDocName();
      doc = doc.substring(siteName.length());
      if (doc.length() < 2 || doc.charAt(0) != '-') return uri;
      doc = doc.substring(1);
      long edition;
      try {
        edition = Long.parseLong(doc);
      } catch (NumberFormatException e) {
        LOG.info("Trying to turn SSK back into USK: {} doc={} caught {}", uri, doc, e, e);
        return uri;
      }
      if (!doc.equals(Long.toString(edition))) return uri;
      return new FreenetURI(
          "USK",
          siteName,
          uri.getAllMetaStrings(),
          pubKeyHash,
          cryptoKey,
          ClientSSK.getExtraBytes(cryptoAlgorithm),
          edition);
    }
    return uri;
  }

  /** Natural ordering: algorithm, public key hash, crypto key, site name, then edition. */
  @Override
  public int compareTo(@NotNull USK o) {
    if (this == o) return 0;
    if (cryptoAlgorithm < o.cryptoAlgorithm) return -1;
    if (cryptoAlgorithm > o.cryptoAlgorithm) return 1;
    int cmp = Fields.compareBytes(pubKeyHash, o.pubKeyHash);
    if (cmp != 0) return cmp;
    cmp = Fields.compareBytes(cryptoKey, o.cryptoKey);
    if (cmp != 0) return cmp;
    cmp = siteName.compareTo(o.siteName);
    if (cmp != 0) return cmp;
    return Long.compare(suggestedEdition, o.suggestedEdition);
  }

  /**
   * Comparator that compares {@link #hashCode()} first to short-circuit obviously different keys,
   * and falls back to {@link #compareTo(USK)} for a total order.
   */
  public static final Comparator<USK> FAST_COMPARATOR =
      (o1, o2) -> {
        if (o1.hashCode > o2.hashCode) {
          return 1;
        } else if (o1.hashCode < o2.hashCode) {
          return -1;
        }
        return o1.compareTo(o2);
      };

  /**
   * Returns a defensive copy of the public key hash.
   *
   * @return New array containing the public key hash.
   */
  public byte[] getPubKeyHash() {
    return Arrays.copyOf(pubKeyHash, pubKeyHash.length);
  }

  /**
   * Tests whether another SSK shares the same public key hash.
   *
   * @param k Node SSK to compare with.
   * @return {@code true} if the public key hashes are identical.
   */
  public boolean samePubKeyHash(NodeSSK k) {
    return Arrays.equals(k.getPubKeyHash(), pubKeyHash);
  }
}
