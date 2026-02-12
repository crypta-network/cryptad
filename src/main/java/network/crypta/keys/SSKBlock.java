package network.crypta.keys;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a Signed Subspace Key (SSK) block fetched from the network.
 *
 * <p>An instance encapsulates the fixed-size payload ({@link #DATA_LENGTH}) and its headers and can
 * perform node-level signature verification using the public key contained in the provided {@link
 * NodeSSK}. The actual payload decryption is handled elsewhere (e.g., by client-level code) using
 * the data-decrypt key that is stored in the encrypted portion of the headers.
 *
 * <p>Equality intentionally ignores the trailing signature bytes in the header (see {@link
 * #HEADER_COMPARE_TO}) because legacy blocks may be signed over different digests (truncated vs.
 * full) while remaining semantically equivalent.
 */
public final class SSKBlock implements KeyBlock {
  private static final Logger LOG = LoggerFactory.getLogger(SSKBlock.class);

  // Number of initial header bytes compared for equality.
  // The final 64 bytes hold the DSA (r,s) signature and may legitimately differ for
  // semantically identical blocks; see class Javadoc and the verification logic below.
  private static final int HEADER_COMPARE_TO = 71;
  final byte[] data;
  final byte[] headers;

  /**
   * Index of the first byte of the encrypted header segment, immediately after {@code
   * E(H(docname))}.
   */
  final int headersOffset;

  /*
   * Header layout (big-endian where applicable):
   *
   *  - 2 bytes  : hash identifier
   *  - 2 bytes  : symmetric cipher identifier
   *  - 32 bytes : E(H(docname)) — encrypted hash of the document name
   *  - 36 bytes : encrypted header segment, using E(H(docname)) as IV
   *               (32) H(decrypted data) — also used as the data-decrypt key
   *               ( 2) data length with an embedded metadata flag
   *               ( 2) compression algorithm id or -1
   *  - implicit : SHA-256 of the {@code data} (not stored directly in the header array)
   *  - implicit : overall header hash that also includes the implicit data hash
   *  - 32 bytes : DSA signature component R (unsigned)
   *  - 32 bytes : DSA signature component S (unsigned)
   *
   * Notes:
   *  - The header byte array validated by this class does not contain the public key. The public
   *    key is supplied out-of-band via {@link NodeSSK}.
   *  - The DSA signature may have been generated over either the truncated overall hash or the
   *    full hash for historical reasons; verification accepts both forms.
   */
  final NodeSSK nodeKey;
  final DSAPublicKey pubKey;
  final short hashIdentifier;
  final short symCipherIdentifier;
  final int hashCode;

  /** Size in bytes of the fixed payload area carried by an SSK block. */
  public static final short DATA_LENGTH = 1024;

  /**
   * Maximum number of bytes available for the compressed payload. Two bytes are reserved in the
   * encrypted header segment for the payload length and a metadata flag.
   */
  public static final int MAX_COMPRESSED_DATA_LENGTH = DATA_LENGTH - 2;

  static final short SIG_R_LENGTH = 32;
  static final short SIG_S_LENGTH = 32;
  static final short E_H_DOCNAME_LENGTH = 32;
  public static final short TOTAL_HEADERS_LENGTH =
      2
          + SIG_R_LENGTH
          + SIG_S_LENGTH
          + 2
          + E_H_DOCNAME_LENGTH
          + ClientSSKBlock.DATA_DECRYPT_KEY_LENGTH
          + 2
          + 2;

  static final short ENCRYPTED_HEADERS_LENGTH = 36;

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof SSKBlock block)) return false;

    if (!block.pubKey.equals(pubKey)) return false;
    if (!block.nodeKey.equals(nodeKey)) return false;
    if (block.headersOffset != headersOffset) return false;
    if (block.hashIdentifier != hashIdentifier) return false;
    if (block.symCipherIdentifier != symCipherIdentifier) return false;
    // Compare only the leading portion of the header to ignore the signature bytes.
    for (int i = 0; i < HEADER_COMPARE_TO; i++) {
      if (block.headers[i] != headers[i]) return false;
    }
    return Arrays.equals(block.data, data);
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Creates a block and optionally verifies its signature and header bindings.
   *
   * <p>Preconditions: - {@code headers.length == TOTAL_HEADERS_LENGTH} - {@code data.length ==
   * DATA_LENGTH} - {@code nodeKey} provides a non-null public key
   *
   * <p>Verification computes the legacy overall hash (data hash plus selected header bytes) and
   * checks the DSA signature against the public key from {@code nodeKey}. For compatibility, the
   * signature is validated against both the truncated and full digest forms. It also verifies that
   * the {@code E(H(docname))} field in the header matches the corresponding value in {@code
   * nodeKey}.
   *
   * @param data the fixed-size payload; treated as opaque by this class
   * @param headers the block headers in the format described above
   * @param nodeKey the node-level SSK that supplies the public key and {@code E(H(docname))}
   * @param dontVerify when {@code true}, skips signature verification (still performs basic
   *     structural checks); validation always runs when debug logging is enabled
   * @throws IllegalArgumentException if {@code headers.length != TOTAL_HEADERS_LENGTH}
   * @throws SSKVerifyException if the payload length is wrong, the public key is missing, the
   *     signature does not verify, or the header is not bound to {@code nodeKey}
   */
  public SSKBlock(byte[] data, byte[] headers, NodeSSK nodeKey, boolean dontVerify)
      throws SSKVerifyException {
    if (headers.length != TOTAL_HEADERS_LENGTH)
      throw new IllegalArgumentException(
          "Headers.length=" + headers.length + " should be " + TOTAL_HEADERS_LENGTH);
    this.data = data;
    this.headers = headers;
    this.nodeKey = nodeKey;
    if (data.length != DATA_LENGTH)
      throw new SSKVerifyException(
          "Data length wrong: " + data.length + " should be " + DATA_LENGTH);
    this.pubKey = nodeKey.getPubKey();
    if (pubKey == null) throw new SSKVerifyException("PubKey was null from " + nodeKey);
    // Now verify it
    hashIdentifier = (short) (((headers[0] & 0xff) << 8) + (headers[1] & 0xff));
    if (hashIdentifier != HASH_SHA256) throw new SSKVerifyException("Hash not SHA-256");
    int x = 2;
    symCipherIdentifier = (short) (((headers[x] & 0xff) << 8) + (headers[x + 1] & 0xff));
    x += 2;
    // Read E(H(docname)) and determine the start of the encrypted header segment.
    byte[] ehDocname = new byte[E_H_DOCNAME_LENGTH];
    System.arraycopy(headers, x, ehDocname, 0, ehDocname.length);
    x += E_H_DOCNAME_LENGTH;
    headersOffset = x; // index of the first byte of the encrypted header segment
    x += ENCRYPTED_HEADERS_LENGTH;
    // Extract the signature (safe due to TOTAL_HEADERS_LENGTH pre-check) and compute the legacy
    // overall hash used by the signature.
    if (!dontVerify || LOG.isDebugEnabled()) { // force verify on debug
      byte[] bufR = new byte[SIG_R_LENGTH];
      byte[] bufS = new byte[SIG_S_LENGTH];

      System.arraycopy(headers, x, bufR, 0, SIG_R_LENGTH);
      System.arraycopy(headers, x + SIG_R_LENGTH, bufS, 0, SIG_S_LENGTH);

      byte[] overallHash;
      MessageDigest md = SHA256.getMessageDigest();
      md.update(data);
      byte[] dataHash = md.digest();
      // Include all header bytes up to (but not including) the signature.
      md.update(headers, 0, headersOffset + ENCRYPTED_HEADERS_LENGTH);
      // Then incorporate the implicit data hash.
      md.update(dataHash);
      // Finalize the overall hash.
      overallHash = md.digest();

      // Now verify it
      BigInteger r = new BigInteger(1, bufR);
      BigInteger s = new BigInteger(1, bufS);
      DSASigner dsa = new DSASigner();
      dsa.init(
          false, new DSAPublicKeyParameters(pubKey.getY(), Global.getDSAgroupBigAParameters()));

      // Legacy blocks may be signed over the truncated digest; accept both truncated and full
      // forms for backward compatibility. See Global.truncateHash(...).
      if (!(dsa.verifySignature(Global.truncateHash(overallHash), r, s)
          || dsa.verifySignature(overallHash, r, s))) {
        if (dontVerify) LOG.error("DSA verification failed with dontVerify!!!!");
        throw new SSKVerifyException("Signature verification failed for node-level SSK");
      }
    } // No further parsing beyond the signature is required here.
    // Ensure the header is bound to the supplied nodeKey by comparing E(H(docname)).
    if (!Arrays.equals(ehDocname, nodeKey.encryptedHashedDocname))
      throw new SSKVerifyException(
          "E(H(docname)) wrong - wrong key?? \nfrom headers: "
              + HexUtil.bytesToHex(ehDocname)
              + "\nfrom key:     "
              + HexUtil.bytesToHex(nodeKey.encryptedHashedDocname));
    hashCode =
        Fields.hashCode(data)
            ^ Fields.hashCode(headers)
            ^ nodeKey.hashCode()
            ^ pubKey.hashCode()
            ^ hashIdentifier;
  }

  /**
   * Returns the node-level SSK used for verification and routing. Never {@code null}.
   *
   * @return the associated {@link NodeSSK}
   */
  @Override
  public NodeSSK getKey() {
    return nodeKey;
  }

  /**
   * Exposes the raw header bytes as stored in this instance. The returned array is the backing
   * storage; callers must treat it as immutable.
   *
   * @return the header byte array of length {@link #TOTAL_HEADERS_LENGTH}
   */
  @Override
  public byte[] getRawHeaders() {
    return headers;
  }

  /**
   * Exposes the raw payload bytes. The returned array is the backing storage; callers must not
   * modify it.
   *
   * @return the payload byte array of length {@link #DATA_LENGTH}
   */
  @Override
  public byte[] getRawData() {
    return data;
  }

  /**
   * Returns the DSA public key extracted from {@link #getKey()}.
   *
   * @return the public key used to verify the block signature
   */
  public DSAPublicKey getPubKey() {
    return pubKey;
  }

  /**
   * Returns the encoded form of the DSA public key.
   *
   * @return public key bytes in the format produced by {@link DSAPublicKey#asBytes()}
   */
  @Override
  public byte[] getPubkeyBytes() {
    return pubKey.asBytes();
  }

  /**
   * Returns the full routing key bytes for this block as defined by {@link NodeSSK}.
   *
   * @return the full routing key
   */
  @Override
  public byte[] getFullKey() {
    return getKey().getFullKey();
  }

  /**
   * Returns the routing key used for DHT placement.
   *
   * @return the routing key
   */
  @Override
  public byte[] getRoutingKey() {
    return getKey().getRoutingKey();
  }
}
