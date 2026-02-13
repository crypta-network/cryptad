/* -*- Mode: java; c-basic-indent: 4; tab-width: 4 -*- */
package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.math.BigInteger;
import java.util.Arrays;
import network.crypta.node.FSParseException;
import network.crypta.store.StorableBlock;
import network.crypta.support.Base64;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;

/**
 * DSA public key backed by a parameter {@link DSAGroup} and the public value {@code y}.
 *
 * <p>The instance is immutable with respect to its mathematical value; a lazily computed
 * fingerprint is cached in a transient field for performance and serialization safety. When the
 * constructor receives the canonical group {@link Global#DSAgroupBigA}, the field is stored as
 * {@code null} to minimize the encoded size. {@link #getGroup()} always returns a non-null
 * instance, resolving {@code null} to the canonical group.
 */
public final class DSAPublicKey extends CryptoKey implements StorableBlock {

  @Serial private static final long serialVersionUID = -1;
  private final BigInteger y;

  /**
   * Fixed padded serialization length in bytes used by {@link #asPaddedBytes()}. Callers that
   * persist padded keys can rely on this value to pre-allocate buffers and to validate input.
   */
  public static final int PADDED_SIZE = 1024;

  /** Number of bytes in the SHA-256 hash returned by {@link #asBytesHash()}. */
  public static final int HASH_LENGTH = 32;

  // When null, {@link #getGroup()} resolves to Global.DSAgroupBigA. This reduces persisted size.
  private final DSAGroup group;

  private transient byte[] fingerprint;

  /**
   * Constructs a key from a parameter group and public value.
   *
   * @param g parameter set; when equal to {@link Global#DSAgroupBigA} it is stored as {@code null}
   *     to reduce encoding size. {@link #getGroup()} always returns a non-null value.
   * @param y public value; must be positive and strictly less than {@code p} of the group.
   * @throws IllegalArgumentException if {@code y} is non-positive or {@code y >= p}.
   */
  public DSAPublicKey(DSAGroup g, BigInteger y) {
    if (y.signum() != 1) throw new IllegalArgumentException();
    this.y = y;
    if (Global.DSAgroupBigA.equals(g)) g = null;
    this.group = g;
    if (y.compareTo(getGroup().getP()) > 0)
      throw new IllegalArgumentException("y must be < p but y=" + y + " p=" + getGroup().getP());
  }

  /**
   * Constructs a key from a parameter group and a hexadecimal representation of {@code y}.
   *
   * <p>Prefer this when a hex string is already available to avoid intermediate allocations.
   *
   * @param g parameter set; when equal to {@link Global#DSAgroupBigA} it is stored as {@code null}.
   * @param yAsHexString unsigned hexadecimal representation of {@code y} (base 16).
   * @throws NumberFormatException if the string is not a valid hexadecimal integer.
   * @throws IllegalArgumentException if {@code y} is non-positive.
   */
  public DSAPublicKey(DSAGroup g, String yAsHexString) throws NumberFormatException {
    this.y = new BigInteger(yAsHexString, 16);
    if (y.signum() != 1) throw new IllegalArgumentException();
    if (Global.DSAgroupBigA.equals(g)) g = null;
    this.group = g;
  }

  /**
   * Derives the public key from a private key using {@code y = g^x mod p}.
   *
   * @param g parameter set.
   * @param p private key holding {@code x}.
   */
  public DSAPublicKey(DSAGroup g, DSAPrivateKey p) {
    this(g, g.getG().modPow(p.getX(), g.getP()));
  }

  /**
   * Reads a key from the binary format produced by {@link #asBytes()}.
   *
   * <p>Format: {@code DSAGroup.asBytes()} followed by {@code y} encoded as an MPI (see {@link
   * Util#readMPI(InputStream)}).
   *
   * @param is source stream.
   * @throws IOException on I/O errors.
   * @throws CryptFormatException if the input is malformed.
   * @throws IllegalArgumentException if the parsed {@code y} is not in {@code [1, p)}.
   */
  public DSAPublicKey(InputStream is) throws IOException, CryptFormatException {
    DSAGroup g = (DSAGroup) DSAGroup.readKey(is);
    if (Global.DSAgroupBigA.equals(g)) g = null;
    group = g;
    y = Util.readMPI(is);
    if (y.compareTo(getGroup().getP()) > 0)
      throw new IllegalArgumentException("y must be < p but y=" + y + " p=" + getGroup().getP());
  }

  /**
   * Convenience constructor reading from a byte array in the same format as {@link #asBytes()}.
   *
   * @param pubkeyBytes encoded key material.
   * @throws IOException on I/O errors while parsing.
   * @throws CryptFormatException if the input is malformed.
   */
  public DSAPublicKey(byte[] pubkeyBytes) throws IOException, CryptFormatException {
    this(new ByteArrayInputStream(pubkeyBytes));
  }

  private DSAPublicKey(DSAPublicKey key) {
    fingerprint = null; // Recomputed lazily on first access.
    this.y = new BigInteger(1, key.y.toByteArray());
    DSAGroup g = key.group;
    if (g != null) g = g.cloneKey();
    this.group = g;
  }

  /**
   * Parses a key from a byte array.
   *
   * @param pubkeyAsBytes encoded key as produced by {@link #asBytes()}.
   * @return a new {@code DSAPublicKey} instance.
   * @throws CryptFormatException if parsing fails.
   */
  public static DSAPublicKey create(byte[] pubkeyAsBytes) throws CryptFormatException {
    try {
      return new DSAPublicKey(new ByteArrayInputStream(pubkeyAsBytes));
    } catch (IOException e) {
      throw new CryptFormatException(e);
    }
  }

  /** For use by serialization frameworks only. Do not call directly. */
  protected DSAPublicKey() {
    // For serialization.
    y = null;
    group = null;
  }

  /**
   * Returns the public value {@code y}.
   *
   * @return immutable {@link BigInteger} representing {@code y}.
   */
  public BigInteger getY() {
    return y;
  }

  /**
   * Returns the prime {@code p} from the associated group.
   *
   * @return group prime {@code p}.
   */
  public BigInteger getP() {
    return getGroup().getP();
  }

  /**
   * Returns the subgroup order {@code q} from the associated group.
   *
   * @return group order {@code q}.
   */
  public BigInteger getQ() {
    return getGroup().getQ();
  }

  /**
   * Returns the generator {@code g} from the associated group.
   *
   * @return group generator {@code g}.
   */
  public BigInteger getG() {
    return getGroup().getG();
  }

  /**
   * Returns the key type identifier used in serialized formats.
   *
   * @return the literal {@code "DSA.p"}.
   */
  @Override
  public String keyType() {
    return "DSA.p";
  }

  /**
   * Returns the parameter group. When the internal field is {@code null}, this resolves to {@link
   * Global#DSAgroupBigA}.
   *
   * @return non-null parameter group.
   */
  public final DSAGroup getGroup() {
    if (group == null) return Global.DSAgroupBigA;
    else return group;
  }

  /**
   * Reads a {@code DSAPublicKey} from a stream.
   *
   * @param i source stream positioned at the start of an encoded key.
   * @return the parsed key.
   * @throws IOException on I/O errors.
   * @throws CryptFormatException if the input is malformed.
   */
  public static CryptoKey readKey(InputStream i) throws IOException, CryptFormatException {
    return new DSAPublicKey(i);
  }

  /**
   * Returns a non-cryptographic 32-bit identifier derived from {@code y}.
   *
   * <p>Primarily intended for logging or lightweight maps. Do not rely on uniqueness.
   *
   * @return {@code y.intValue()}.
   */
  public int keyId() {
    return y.intValue();
  }

  /**
   * Returns a human-readable representation containing {@code y} in hexadecimal.
   *
   * @return descriptive string for diagnostics.
   */
  @Override
  public String toLongString() {
    return "y=" + HexUtil.biToHex(y);
  }

  /**
   * Serializes the key to bytes: {@code DSAGroup.asBytes()} followed by {@code y} as an MPI.
   *
   * @return a newly allocated byte array.
   */
  @Override
  public byte[] asBytes() {
    byte[] groupBytes = getGroup().asBytes();
    byte[] ybytes = Util.mpiBytes(y);
    byte[] bytes = new byte[groupBytes.length + ybytes.length];
    System.arraycopy(groupBytes, 0, bytes, 0, groupBytes.length);
    System.arraycopy(ybytes, 0, bytes, groupBytes.length, ybytes.length);
    return bytes;
  }

  /**
   * Returns the SHA-256 digest of {@link #asBytes()}.
   *
   * @return 32-byte hash of the serialized key.
   */
  public byte[] asBytesHash() {
    return SHA256.digest(asBytes());
  }

  /**
   * Returns the serialized form padded with trailing zeros to {@link #PADDED_SIZE} bytes.
   *
   * @return a byte array of length {@link #PADDED_SIZE}.
   * @throws TooLargeError if the unpadded serialized size exceeds {@link #PADDED_SIZE}.
   */
  public byte[] asPaddedBytes() {
    byte[] asBytes = asBytes();
    if (asBytes.length == PADDED_SIZE) return asBytes;
    if (asBytes.length > PADDED_SIZE)
      throw new TooLargeError(
          "Cannot fit key in " + PADDED_SIZE + " - real size is " + asBytes.length);
    return Arrays.copyOf(asBytes, PADDED_SIZE);
  }

  /**
   * Returns a stable fingerprint derived from the key material.
   *
   * <p>The value is computed lazily and cached. The returned array is the internal cache; callers
   * must treat it as read-only.
   *
   * @return fingerprint bytes.
   */
  @Override
  public synchronized byte[] fingerprint() {
    byte[] fp = this.fingerprint;
    if (fp == null) {
      fp = fingerprint(new BigInteger[] {y});
      this.fingerprint = fp;
    }
    return fp;
  }

  /**
   * Type-specific equality check equivalent to {@link #equals(Object)} for convenience.
   *
   * @param o other key.
   * @return {@code true} if both {@code y} and the group are equal.
   */
  @SuppressWarnings("NonOverridingEquals")
  public boolean equals(DSAPublicKey o) {
    if (o == null) {
      return false;
    }
    return y.compareTo(o.y) == 0 && getGroup().equals(o.getGroup());
  }

  /** Hash code consistent with {@link #equals(Object)} using {@code y} and the group. */
  @Override
  public int hashCode() {
    return y.hashCode() ^ getGroup().hashCode();
  }

  /** Equality based on {@code y} and the parameter group. */
  @Override
  public boolean equals(Object o) {
    if (this == o) { // Not necessary, but a very cheap optimization
      return true;
    }
    if (!(o instanceof DSAPublicKey other)) {
      return false;
    }
    return y.compareTo(other.y) == 0 && getGroup().equals(other.getGroup());
  }

  /**
   * Compares two {@code DSAPublicKey} instances by their {@code y} value.
   *
   * <p>If {@code other} is not a {@code DSAPublicKey}, this method returns {@code -1}.
   *
   * @param other object to compare with.
   * @return negative, zero, or positive as this key's {@code y} is less than, equal to, or greater
   *     than the other's.
   */
  public int compareTo(Object other) {
    if (other instanceof DSAPublicKey key) return getY().compareTo(key.getY());
    else return -1;
  }

  /**
   * Returns a {@link SimpleFieldSet} containing the base64-encoded {@code y} value.
   *
   * <p>The group is not included in this representation and must be supplied by the caller when
   * reconstructing via {@link #create(SimpleFieldSet, DSAGroup)}.
   *
   * @return field set with a single entry {@code "y"}.
   */
  public SimpleFieldSet asFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("y", Base64.encode(y.toByteArray()));
    return fs;
  }

  /**
   * Reconstructs a key from a field set and an explicit parameter group.
   *
   * @param set field set containing base64-encoded {@code y} under the key {@code "y"}.
   * @param group parameter set to associate with the reconstructed key.
   * @return a new {@code DSAPublicKey} instance.
   * @throws FSParseException if decoding fails or the value is out of range.
   */
  public static DSAPublicKey create(SimpleFieldSet set, DSAGroup group) throws FSParseException {
    BigInteger yValue;
    try {
      yValue = new BigInteger(1, Base64.decode(set.get("y")));
    } catch (IllegalBase64Exception e) {
      throw new FSParseException(e);
    }
    try {
      return new DSAPublicKey(group, yValue);
    } catch (IllegalArgumentException e) {
      throw new FSParseException(e);
    }
  }

  /**
   * Returns the full key identifier used for storage systems.
   *
   * @return {@link #asBytesHash()}.
   */
  @Override
  public byte[] getFullKey() {
    return asBytesHash();
  }

  /**
   * Returns the routing key derived from the public key material.
   *
   * @return {@link #asBytesHash()}.
   */
  @Override
  public byte[] getRoutingKey() {
    return asBytesHash();
  }

  /**
   * Returns a deep copy of this key. The fingerprint cache is not copied and is recomputed on first
   * access.
   *
   * @return a new {@code DSAPublicKey} instance with the same value.
   */
  public DSAPublicKey cloneKey() {
    return new DSAPublicKey(this);
  }

  /**
   * Error thrown when a public key cannot be represented within the configured {@link
   * #PADDED_SIZE}.
   */
  static final class TooLargeError extends Error {
    @Serial private static final long serialVersionUID = 1L;

    TooLargeError(String message) {
      super(message);
    }
  }
}
