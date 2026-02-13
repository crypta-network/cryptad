package network.crypta.keys;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.SHA256;
import network.crypta.store.BlockMetadata;
import network.crypta.store.GetPubkey;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signed Subspace Key (SSK) identifier and helpers.
 *
 * <p>An {@code NodeSSK} represents the immutable identifier portion of an SSK: the 32-byte hash of
 * the DSA public key and the 32-byte encrypted hash of the document name. It also carries the
 * crypto algorithm selector in the two-byte type header used by the serialized form. The optional
 * {@link DSAPublicKey} may be attached when available and is verified to match the stored hash.
 *
 * <p>Serialization formats:
 *
 * <ul>
 *   <li><b>Full key</b> ({@link #getFullKey()} / {@link #construct(byte[])}): 66 bytes. Layout:
 *       {@code [type_hi, type_lo, E(H(docname)) (32), pubKeyHash (32)]}.
 *   <li><b>SSK payload</b> ({@link #readSSK(DataInput, byte)}): 64 bytes (no two-byte type header).
 *       Layout: {@code [E(H(docname)) (32), pubKeyHash (32)]}.
 * </ul>
 *
 * <p>Routing key semantics: the routing key is {@code SHA-256(E(H(docname)) || pubKeyHash)}, i.e.,
 * the SHA‑256 digest of the payload bytes in that order. See {@link #routingKey} in the {@link Key}
 * base class and {@link #routingKeyFromFullKey(byte[])}.
 */
public class NodeSSK extends Key {
  private static final Logger LOG = LoggerFactory.getLogger(NodeSSK.class);

  /** Crypto algorithm (encoded in the low byte of {@link #getType()}). */
  final byte cryptoAlgorithm;

  /** 32-byte SHA‑256 hash of the public key. */
  final byte[] pubKeyHash;

  /** 32-byte {@code E(H(docname))} where {@code E} is the client-side encryption used for SSKs. */
  final byte[] encryptedHashedDocname;

  /** The public signature key if known; otherwise {@code null}. */
  DSAPublicKey pubKey;

  final int hashCode;

  /**
   * Version marker for SSK format used by this implementation.
   *
   * @since 1
   */
  public static final int SSK_VERSION = 1;

  /** Size in bytes of {@link #pubKeyHash}. */
  public static final int PUBKEY_HASH_SIZE = 32;

  /** Size in bytes of {@link #encryptedHashedDocname}. */
  public static final int E_H_DOCNAME_SIZE = 32;

  /** Base type discriminator for SSKs used in the serialized header. */
  public static final byte BASE_TYPE = 2;

  /** Total length in bytes of the full serialized SSK ({@link #getFullKey()}). */
  public static final int FULL_KEY_LENGTH = 66;

  /** Length in bytes of the routing key ({@link #routingKey}). */
  public static final int ROUTING_KEY_LENGTH = 32;

  /**
   * Returns a string for diagnostics containing hex-encoded components.
   *
   * <p>The format includes the superclass information plus {@code pkh=<hex(pubKeyHash)>} and {@code
   * ehd=<hex(E(H(docname))>}. The exact format is subject to change and should not be parsed.
   */
  @Override
  public String toString() {
    return super.toString()
        + ":pkh="
        + HexUtil.bytesToHex(pubKeyHash)
        + ":ehd="
        + HexUtil.bytesToHex(encryptedHashedDocname);
  }

  /**
   * Returns an archival, non-mutable copy of this key.
   *
   * <p>The returned instance is an {@link ArchiveNodeSSK} that forbids mutation paths related to
   * the public key (e.g., {@link #setPubKey(DSAPublicKey)} and {@link #grabPubkey(GetPubkey,
   * boolean, boolean, network.crypta.store.BlockMetadata)} throw {@link
   * UnsupportedOperationException}).
   *
   * @return a copy suitable for storage in archival contexts.
   */
  @Override
  public Key archivalCopy() {
    return new ArchiveNodeSSK(pubKeyHash, encryptedHashedDocname, cryptoAlgorithm);
  }

  /**
   * Creates an SSK identifier with the given payload and algorithm.
   *
   * <p>The constructor copies neither argument for routing key calculation; however, both are
   * validated for expected lengths and stored internally. The attached public key is left unset.
   *
   * @param pkHash 32-byte SHA‑256 of the public key.
   * @param ehDocname 32-byte encrypted hash of the document name.
   * @param cryptoAlgorithm algorithm selector encoded in the low byte of {@link #getType()}.
   * @throws IllegalArgumentException if either array has an unexpected length.
   */
  public NodeSSK(byte[] pkHash, byte[] ehDocname, byte cryptoAlgorithm) {
    this(validateState(pkHash, ehDocname, cryptoAlgorithm));
  }

  /**
   * Creates an SSK identifier and attaches a public key after verifying its hash.
   *
   * <p>If {@code pubKey} is non-null, its {@code asBytes()} is hashed with SHA‑256 and compared to
   * {@code pkHash}. A mismatch results in an exception.
   *
   * @param pkHash 32-byte SHA‑256 of the public key.
   * @param ehDocname 32-byte encrypted hash of the document name.
   * @param pubKey optional public key; may be {@code null}.
   * @param cryptoAlgorithm algorithm selector encoded in the low byte of {@link #getType()}.
   * @throws SSKVerifyException if {@code pubKey} is provided and its hash does not match {@code
   *     pkHash}.
   * @throws IllegalArgumentException if either array has an unexpected length.
   */
  public NodeSSK(byte[] pkHash, byte[] ehDocname, DSAPublicKey pubKey, byte cryptoAlgorithm)
      throws SSKVerifyException {
    this(validateState(pkHash, ehDocname, pubKey, cryptoAlgorithm));
  }

  private NodeSSK(ValidatedState state) {
    super(makeRoutingKey(state.pkHash, state.ehDocname));
    this.encryptedHashedDocname = state.ehDocname;
    this.pubKeyHash = state.pkHash;
    this.cryptoAlgorithm = state.cryptoAlgorithm;
    this.pubKey = state.pubKey;
    this.hashCode = state.hashCodeValue;
  }

  private static ValidatedState validateState(
      byte[] pkHash, byte[] ehDocname, byte cryptoAlgorithm) {
    if (ehDocname.length != E_H_DOCNAME_SIZE)
      throw new IllegalArgumentException("ehDocname must be " + E_H_DOCNAME_SIZE + " bytes");
    if (pkHash.length != PUBKEY_HASH_SIZE)
      throw new IllegalArgumentException("pubKeyHash must be " + PUBKEY_HASH_SIZE + " bytes");
    return new ValidatedState(
        pkHash,
        ehDocname,
        null,
        cryptoAlgorithm,
        Fields.hashCode(pkHash) ^ Fields.hashCode(ehDocname));
  }

  private static ValidatedState validateState(
      byte[] pkHash, byte[] ehDocname, DSAPublicKey pubKey, byte cryptoAlgorithm)
      throws SSKVerifyException {
    if (pubKey != null) {
      byte[] hash = SHA256.digest(pubKey.asBytes());
      if (!Arrays.equals(hash, pkHash)) throw new SSKVerifyException("Invalid pubKey: wrong hash");
    }
    if (ehDocname.length != E_H_DOCNAME_SIZE)
      throw new IllegalArgumentException("ehDocname must be " + E_H_DOCNAME_SIZE + " bytes");
    if (pkHash.length != PUBKEY_HASH_SIZE)
      throw new IllegalArgumentException("pubKeyHash must be " + PUBKEY_HASH_SIZE + " bytes");
    return new ValidatedState(
        pkHash,
        ehDocname,
        pubKey,
        cryptoAlgorithm,
        Fields.hashCode(pkHash) ^ Fields.hashCode(ehDocname));
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class ValidatedState {
    final byte[] pkHash;
    final byte[] ehDocname;
    final DSAPublicKey pubKey;
    final byte cryptoAlgorithm;
    final int hashCodeValue;

    ValidatedState(
        byte[] pkHash,
        byte[] ehDocname,
        DSAPublicKey pubKey,
        byte cryptoAlgorithm,
        int hashCodeValue) {
      this.pkHash = pkHash;
      this.ehDocname = ehDocname;
      this.pubKey = pubKey;
      this.cryptoAlgorithm = cryptoAlgorithm;
      this.hashCodeValue = hashCodeValue;
    }
  }

  private NodeSSK(NodeSSK key) {
    super(key);
    this.cryptoAlgorithm = key.cryptoAlgorithm;
    this.pubKey = key.pubKey;
    this.pubKeyHash = key.pubKeyHash.clone();
    this.encryptedHashedDocname = key.encryptedHashedDocname.clone();
    this.hashCode = key.hashCode;
  }

  /**
   * Returns a copy of this key.
   *
   * <p>Arrays are cloned; the {@link DSAPublicKey} reference is shared.
   *
   * @return a new {@code NodeSSK} with the same values.
   */
  @Override
  public Key cloneKey() {
    return new NodeSSK(this);
  }

  // Routing key is SHA‑256(E(H(docname)) || pubKeyHash).
  private static byte[] makeRoutingKey(byte[] pkHash, byte[] ehDocname) {
    MessageDigest md256 = SHA256.getMessageDigest();
    md256.update(ehDocname);
    md256.update(pkHash);
    return md256.digest();
  }

  /**
   * Writes the full SSK to a {@link DataOutput}.
   *
   * <p>Order: two-byte type header ({@link #getType()}), then 32 bytes of {@code E(H(docname))},
   * then 32 bytes of {@code pubKeyHash}.
   *
   * @param out destination to write to; not closed.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void write(DataOutput out) throws IOException {
    out.writeShort(getType());
    out.write(encryptedHashedDocname);
    out.write(pubKeyHash);
  }

  /**
   * Reads the SSK payload (64 bytes) from a {@link DataInput} and returns a {@code NodeSSK}.
   *
   * <p>This reads only the payload without the two-byte type header. The resulting instance uses
   * the {@code cryptoAlgorithm} provided by the caller.
   *
   * @param raf source to read from; exactly 64 bytes are consumed.
   * @param cryptoAlgorithm algorithm selector encoded in the low byte of {@link #getType()}.
   * @return a {@code NodeSSK} with no attached public key.
   * @throws IOException if the input cannot supply the required bytes.
   */
  public static Key readSSK(DataInput raf, byte cryptoAlgorithm) throws IOException {
    byte[] buf = new byte[E_H_DOCNAME_SIZE];
    raf.readFully(buf);
    byte[] buf2 = new byte[PUBKEY_HASH_SIZE];
    raf.readFully(buf2);
    try {
      return new NodeSSK(buf2, buf, null, cryptoAlgorithm);
    } catch (SSKVerifyException e) {
      throw new AssertionError("Impossible", e);
    }
  }

  /**
   * Returns the two-byte type header combining base type and algorithm.
   *
   * <p>High byte is {@link #BASE_TYPE}; low byte is {@link #cryptoAlgorithm} treated as unsigned.
   *
   * @return type header as an unsigned 16-bit value in a Java {@code short}.
   */
  @Override
  public short getType() {
    return (short) ((BASE_TYPE << 8) + (cryptoAlgorithm & 0xff));
  }

  /**
   * Writes the full SSK to a {@link DataOutputStream}.
   *
   * <p>Delegates to {@link #write(DataOutput)}.
   *
   * @param stream destination to write to; not closed.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void writeToDataOutputStream(DataOutputStream stream) throws IOException {
    write(stream);
  }

  /**
   * Returns whether a public key is attached.
   *
   * @return {@code true} if {@link #getPubKey()} is non-null.
   */
  public boolean hasPubKey() {
    return pubKey != null;
  }

  /**
   * Returns the attached public key if present.
   *
   * @return the public key, or {@code null} if unknown.
   */
  public DSAPublicKey getPubKey() {
    return pubKey;
  }

  /**
   * Returns the 32-byte SHA‑256 hash of the public key.
   *
   * @return a non-null, 32-byte array.
   */
  public byte[] getPubKeyHash() {
    return pubKeyHash;
  }

  /**
   * Attaches a verified public key.
   *
   * <p>If a key is already present and the new key has the same hash but is not reference-equal, a
   * collision is reported via {@code SSKVerifyException}. Passing {@code null} is a no-op. When the
   * key is accepted, it replaces the previous value.
   *
   * @param pubKey2 key to attach; may be {@code null}.
   * @throws SSKVerifyException if the key's hash does not match {@link #pubKeyHash} or if a hash
   *     collision is detected with an existing different key.
   */
  public void setPubKey(DSAPublicKey pubKey2) throws SSKVerifyException {
    if (pubKey2 == null) return;
    if (pubKey2.equals(pubKey)) return;
    byte[] newPubKeyHash = SHA256.digest(pubKey2.asBytes());
    if (Arrays.equals(pubKeyHash, newPubKeyHash)) {
      if (pubKey != null) {
        // Same hash yet a different key instance: treat as a collision.
        LOG.error("Found SHA-256 collision or something... WTF?");
        throw new SSKVerifyException("Invalid new pubkey: " + pubKey2 + " old pubkey: " + pubKey);
      }
      // Hash matches and no previous key: accept.
    } else {
      throw new SSKVerifyException("New pubkey has invalid hash");
    }
    pubKey = pubKey2;
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof NodeSSK key)) return false;
    if (!Arrays.equals(key.encryptedHashedDocname, encryptedHashedDocname)) return false;
    if (!Arrays.equals(key.pubKeyHash, pubKeyHash)) return false;
    return Arrays.equals(key.routingKey, routingKey);
    // cachedNormalizedDouble and pubKey could be negative/null.
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  // Returns the payload portion only; exclude header and any attached pubKey.
  @Override
  public byte[] getKeyBytes() {
    return encryptedHashedDocname;
  }

  @Override
  public byte[] getFullKey() {
    byte[] buf = new byte[FULL_KEY_LENGTH];
    short type = getType();
    buf[0] = (byte) (type >> 8);
    buf[1] = (byte) (type & 0xFF);
    System.arraycopy(encryptedHashedDocname, 0, buf, 2, E_H_DOCNAME_SIZE);
    System.arraycopy(pubKeyHash, 0, buf, 2 + E_H_DOCNAME_SIZE, PUBKEY_HASH_SIZE);
    return buf;
  }

  /**
   * Parses a full 66-byte SSK buffer into a {@code NodeSSK}.
   *
   * <p>Validates the base type byte ({@link #BASE_TYPE}) and the supported algorithm ({@link
   * Key#ALGO_AES_PCFB_256_SHA256}). The returned instance has no attached public key.
   *
   * @param buf serialized full key; must be {@link #FULL_KEY_LENGTH} bytes.
   * @return a parsed {@code NodeSSK}.
   * @throws SSKVerifyException if the type or algorithm are not recognized.
   */
  public static NodeSSK construct(byte[] buf) throws SSKVerifyException {
    if (buf[0] != 2) throw new SSKVerifyException("Unknown type byte " + buf[0]);
    byte cryptoAlgorithm = buf[1];
    if (cryptoAlgorithm != Key.ALGO_AES_PCFB_256_SHA256)
      throw new SSKVerifyException("Unknown crypto algorithm " + buf[1]);
    byte[] encryptedHashedDocname = Arrays.copyOfRange(buf, 2, 2 + E_H_DOCNAME_SIZE);
    byte[] pubkeyHash =
        Arrays.copyOfRange(buf, 2 + E_H_DOCNAME_SIZE, 2 + E_H_DOCNAME_SIZE + PUBKEY_HASH_SIZE);
    return new NodeSSK(pubkeyHash, encryptedHashedDocname, null, cryptoAlgorithm);
  }

  /**
   * Attempts to resolve and attach the public key from a cache.
   *
   * <p>If the public key is already present, this method returns {@code false} and does not invoke
   * the cache. Otherwise, it calls {@link GetPubkey#getKey(byte[], boolean, boolean,
   * network.crypta.store.BlockMetadata)} and, on success, attaches the result.
   *
   * @param pubkeyCache provider used to retrieve the key.
   * @param canReadClientCache whether the client cache may be consulted.
   * @param forULPR hint used by the caller for request routing.
   * @param meta optional block metadata; may be {@code null}.
   * @return {@code true} if a key was fetched and attached; {@code false} otherwise.
   */
  public boolean grabPubkey(
      GetPubkey pubkeyCache, boolean canReadClientCache, boolean forULPR, BlockMetadata meta) {
    if (pubKey != null) return false;
    pubKey = pubkeyCache.getKey(pubKeyHash, canReadClientCache, forULPR, meta);
    return pubKey != null;
  }

  /**
   * Computes the routing key from a serialized full key buffer.
   *
   * <p>The computation hashes {@code E(H(docname))} followed by {@code pubKeyHash} using SHA‑256.
   * If the buffer length differs from {@link #FULL_KEY_LENGTH}, an error is logged but the method
   * proceeds to use the available bytes at the expected offsets.
   *
   * @param keyBuf full-key buffer; expected to be {@link #FULL_KEY_LENGTH} bytes.
   * @return 32-byte routing key.
   */
  public static byte[] routingKeyFromFullKey(byte[] keyBuf) {
    if (keyBuf.length != FULL_KEY_LENGTH) {
      LOG.error("routingKeyFromFullKey() on buffer length {}", keyBuf.length);
    }
    byte[] encryptedHashedDocname = Arrays.copyOfRange(keyBuf, 2, 2 + E_H_DOCNAME_SIZE);
    byte[] pubKeyHash =
        Arrays.copyOfRange(keyBuf, 2 + E_H_DOCNAME_SIZE, 2 + E_H_DOCNAME_SIZE + PUBKEY_HASH_SIZE);
    return makeRoutingKey(pubKeyHash, encryptedHashedDocname);
  }

  /**
   * Orders keys for deterministic maps and indexes.
   *
   * <p>{@code NodeSSK} compares before {@link NodeCHK} (returns {@code -1}). Two SSKs are ordered
   * lexicographically by {@code E(H(docname))}, then by {@code pubKeyHash}.
   *
   * @param arg0 other key.
   * @return negative, zero, or positive as per {@link Comparable}.
   */
  @Override
  public int compareTo(@NotNull Key arg0) {
    if (arg0 instanceof NodeCHK) return -1;
    NodeSSK key = (NodeSSK) arg0;
    int result = Fields.compareBytes(encryptedHashedDocname, key.encryptedHashedDocname);
    if (result != 0) return result;
    return Fields.compareBytes(pubKeyHash, key.pubKeyHash);
  }
}

/**
 * Archival variant of {@link NodeSSK} that forbids mutation of the attached public key.
 *
 * <p>Used by {@link NodeSSK#archivalCopy()} to provide a representation suitable for storage in
 * contexts where key resolution is not performed.
 */
final class ArchiveNodeSSK extends NodeSSK {

  /** Creates an archival SSK. Arguments mirror {@link NodeSSK#NodeSSK(byte[], byte[], byte)}. */
  public ArchiveNodeSSK(byte[] pubKeyHash, byte[] encryptedHashedDocname, byte cryptoAlgorithm) {
    super(pubKeyHash, encryptedHashedDocname, cryptoAlgorithm);
  }

  /**
   * Not supported for archival keys.
   *
   * @throws UnsupportedOperationException always.
   */
  @Override
  public void setPubKey(DSAPublicKey pubKey2) {
    throw new UnsupportedOperationException();
  }

  /**
   * Not supported for archival keys.
   *
   * @throws UnsupportedOperationException always.
   */
  @Override
  public boolean grabPubkey(
      GetPubkey pubkeyCache, boolean canReadClientCache, boolean forULPR, BlockMetadata meta) {
    throw new UnsupportedOperationException();
  }
}
