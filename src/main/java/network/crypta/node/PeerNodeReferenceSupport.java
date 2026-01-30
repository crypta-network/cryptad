package network.crypta.node;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.PeerNode.IdentityValues;
import network.crypta.support.Base64;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper that owns noderef parsing, identity validation, and setup key derivation for {@link
 * PeerNode}.
 *
 * <p>This support type centralizes the low-level parsing and validation steps used when a {@link
 * PeerNode} ingests a node reference. Typical call paths read the peer's ECDSA key, validate
 * identity consistency, verify reference signatures, and derive setup keys before any handshake or
 * persisted peer state is finalized. The class intentionally bundles these behaviors to keep
 * peer-reference handling cohesive and to avoid duplicating parsing rules across the node.
 *
 * <p>State is derived from the owning {@link PeerNode} and from the input {@link SimpleFieldSet}
 * instances; no internal caching is performed beyond direct field access. The implementation
 * assumes callers coordinate concurrency as needed, because no explicit synchronization is
 * performed and some methods mutate the owning peer's flags and stored field set.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Parse and validate ECDSA identity material in noderefs.
 *   <li>Verify reference signatures and record verification outcomes.
 *   <li>Translate reference metadata into peer-ready values and setup keys.
 * </ul>
 *
 * @see PeerNode
 */
final class PeerNodeReferenceSupport {

  /**
   * Logger used for peer-reference parsing and validation diagnostics.
   *
   * <p>Messages emitted here distinguish local versus remote references and are intended for
   * operator visibility when a noderef is malformed or unverifiable. The logger is private to this
   * helper and shares the class name for consistent filtering.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeReferenceSupport.class);

  /**
   * Owning peer whose reference state is parsed and validated by this helper.
   *
   * <p>The reference support delegates identity and signature outcomes to this peer and may update
   * flags or cached field sets on it. Callers are expected to pass a stable, non-null instance for
   * the lifetime of this helper.
   */
  private final PeerNode peer;

  /**
   * Creates a support helper bound to a specific peer.
   *
   * <p>The helper does not copy any state; it retains the provided peer and uses it for validation
   * decisions and side effects such as recording signature verification results. Callers should
   * provide a fully initialized peer instance and ensure any required synchronization around its
   * state changes.
   *
   * @param peer owning peer instance used for identity, flags, and side effects; expected non-null
   */
  PeerNodeReferenceSupport(PeerNode peer) {
    this.peer = peer;
  }

  /**
   * Reads and validates the peer's ECDSA public key from a noderef field set.
   *
   * <p>The method expects an {@code ecdsa.P256} subset containing a {@code pub} field encoded in
   * Base64. It validates the modulus size and rejects malformed or missing data. When the subset is
   * absent, the peer is treated as too old to support ECC and a {@link PeerTooOldException} is
   * raised.
   *
   * @param fs field set that should contain {@code ecdsa.P256} key material; must be non-null
   * @return decoded and validated ECDSA public key for the peer
   * @throws FSParseException if the subset or key material is malformed or invalid
   * @throws PeerTooOldException if the noderef predates required ECC support
   */
  ECPublicKey readPeerEcdsaKeyReturn(SimpleFieldSet fs)
      throws FSParseException, PeerTooOldException {
    SimpleFieldSet sfs = fs.subset("ecdsa.P256");
    if (sfs == null) {
      GregorianCalendar gc = new GregorianCalendar(2013, Calendar.JULY, 20);
      gc.setTimeZone(TimeZone.getTimeZone("GMT"));
      throw new PeerTooOldException("No ECC support", 1449, gc.getTime());
    }
    byte[] pub;
    try {
      pub = Base64.decode(sfs.get("pub"));
    } catch (IllegalBase64Exception e) {
      throw new FSParseException("Invalid base64 in ecdsa.P256.pub", e);
    }
    if (pub.length > Curves.P256.modulusSize)
      throw new FSParseException("ecdsa.P256.pub is not the right size!");
    ECPublicKey key = ECDSA.getPublicKey(pub, Curves.P256);
    if (key == null) throw new FSParseException("ecdsa.P256.pub is invalid!");
    return key;
  }

  /**
   * Verifies a reference signature unless signature checks are explicitly disabled.
   *
   * <p>When {@code noSig} is {@code true}, the peer is marked as having passed verification without
   * inspecting the field set. Otherwise, signature validation is delegated to {@link
   * #verifyReferenceSignature(SimpleFieldSet)} which updates the peer's verification flag and may
   * throw if validation fails.
   *
   * @param fs field set containing signature fields when verification is required
   * @param noSig {@code true} to skip verification and mark success immediately
   * @throws ReferenceSignatureVerificationException if a required signature is missing or invalid
   */
  void verifySignatureIfPresent(SimpleFieldSet fs, boolean noSig)
      throws ReferenceSignatureVerificationException {
    if (noSig) {
      peer.setSignatureVerificationSuccessfull(true);
      return;
    }
    // When present, verifyReferenceSignature() sets the flag and may throw on failure.
    verifyReferenceSignature(fs);
  }

  /**
   * Reads identity data from a noderef and derives stable identity values.
   *
   * <p>If the identity field is present, it is decoded from Base64. Otherwise, for non-darknet
   * peers the identity is derived from the DSA public key for legacy compatibility. The returned
   * values include the identity in multiple forms and precomputed hashes used by the peer for swap
   * identifiers and setup key calculations.
   *
   * @param fs field set that may contain identity or legacy DSA key material
   * @return computed identity values derived from the noderef contents
   * @throws FSParseException if base64 or hash inputs are malformed or inconsistent
   * @throws PeerParseException if identity is required for a darknet peer but missing
   */
  IdentityValues readIdentityValues(SimpleFieldSet fs) throws FSParseException, PeerParseException {
    String identityString = fs.get(PeerNode.SFS_KEY_IDENTITY);
    if (identityString == null && peer.isDarknet()) throw new PeerParseException("No identity!");
    try {
      byte[] id;
      if (identityString != null) {
        id = Base64.decode(identityString);
      } else {
        // We might be talking to a pre-1471 node
        // We need to generate it from the DSA key
        SimpleFieldSet sfs = fs.subset("dsaPubKey");
        id = SHA256.digest(DSAPublicKey.create(sfs, Global.DSAgroupBigA).asBytes());
      }
      if (id == null) throw new FSParseException("No identity");
      String b64 = Base64.encode(id);
      byte[] idHash = SHA256.digest(id);
      byte[] idHashHash = SHA256.digest(idHash);
      long swapId = Fields.bytesToLong(idHashHash);
      int hc = Fields.hashCode(peer.peerECDSAPubKeyHash);
      return new IdentityValues(id, b64, idHash, idHashHash, swapId, hc);
    } catch (NumberFormatException | IllegalBase64Exception e) {
      throw new FSParseException(e);
    }
  }

  /**
   * Computes the incoming setup key by XORing the node identity hash with a peer hash.
   *
   * <p>The method allocates a new array with the SHA-256 digest length and performs a byte-wise XOR
   * between the local node's identity hash and the provided peer hash. Callers must provide arrays
   * that match the digest length.
   *
   * @param crypto node crypto provider that supplies the local identity hash
   * @param identityHashHash peer identity hash-of-hash bytes to combine with the node hash
   * @return new byte array containing the derived incoming setup key
   */
  byte[] computeIncomingSetupKey(NodeCrypto crypto, byte[] identityHashHash) {
    byte[] nodeKey = crypto.getIdentityHash();
    int digestLength = SHA256.getDigestLength();
    byte[] key = new byte[digestLength];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (nodeKey[i] ^ identityHashHash[i]);
    return key;
  }

  /**
   * Computes the outgoing setup key by XORing the node identity hash-of-hash with a peer hash.
   *
   * <p>The method allocates a new array with the SHA-256 digest length and performs a byte-wise XOR
   * between the local node's identity hash-of-hash and the provided peer identity hash. Callers
   * must provide arrays that match the digest length.
   *
   * @param crypto node crypto provider that supplies the local identity hash-of-hash
   * @param identityHash peer identity hash bytes to combine with the node hash-of-hash
   * @return new byte array containing the derived outgoing setup key
   */
  byte[] computeOutgoingSetupKey(NodeCrypto crypto, byte[] identityHash) {
    byte[] nodeKeyHash = crypto.getIdentityHashHash();
    int digestLength = SHA256.getDigestLength();
    byte[] key = new byte[digestLength];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (nodeKeyHash[i] ^ identityHash[i]);
    return key;
  }

  /**
   * Builds and initializes a Rijndael 256-bit block cipher for setup key use.
   *
   * <p>The cipher is created with a 256-bit block size and key size and then initialized with the
   * provided key bytes. Invalid key material or cipher initialization failures are wrapped in an
   * {@link IllegalStateException} because callers do not expect recoverable errors here.
   *
   * @param keyBytes raw key material for a 256-bit Rijndael cipher; must be a valid length
   * @return initialized Rijndael block cipher instance ready for use
   * @throws IllegalStateException if the cipher cannot be initialized with the given key
   */
  BlockCipher buildRijndaelCipher(byte[] keyBytes) {
    try {
      BlockCipher c = new Rijndael(256, 256);
      c.initialize(keyBytes);
      return c;
    } catch (UnsupportedCipherException e1) {
      throw new IllegalStateException("Failed to initialize Rijndael(256,256)", e1);
    }
  }

  /**
   * Computes the SHA-256 hash of the encoded peer ECDSA public key.
   *
   * <p>The returned digest is used for identity verification and swap identifier derivation. The
   * method does not cache results and always hashes the encoded key bytes.
   *
   * @param key ECDSA public key to encode and hash; must be non-null
   * @return SHA-256 digest of the encoded key bytes
   */
  byte[] computePeerPublicKeyHash(ECPublicKey key) {
    return SHA256.digest(key.getEncoded());
  }

  /**
   * Parses a physical address entry, accepting compatibility comma-separated formats.
   *
   * <p>The preferred format is {@code host:port}. For compatibility, the method also accepts a
   * comma-separated host list with a shared trailing port (for example {@code A,B:1234}) and a
   * comma-separated list of full entries (for example {@code A:1234,B:2345}). Parsed peers are
   * accumulated into a list; duplicates from the full-entry form are filtered.
   *
   * @param phys raw physical entry string as read from a noderef; must be non-null
   * @param fromLocal {@code true} if the entry originated from a local peers list
   * @return list of parsed peers, possibly empty when no candidate could be parsed
   */
  List<Peer> parsePeerEntryCompat(String phys, boolean fromLocal) {
    ArrayList<Peer> out = new ArrayList<>(2);
    Peer direct = tryParsePeerOrNull(phys);
    if (direct != null) {
      out.add(direct);
      return out;
    }

    // Try compatibility forms only if a comma appears.
    if (phys.indexOf(',') >= 0) {
      // Pattern: A,B,C:port -> apply trailing port to each host
      addPeersWithSharedPortSuffix(phys, out);
      // Additionally try: split by comma and parse each token as-is (covers A:port,B:port)
      addPeersFromCommaSeparatedTokens(phys, out);
      if (!out.isEmpty()) {
        LOG.info("Parsed {} into {} peer(s) via compatibility split", phys, out.size());
        return out;
      }
    }

    logInvalidPeerReference(phys, fromLocal);
    return out;
  }

  /**
   * Attempts to parse a single {@code host:port} peer without logging on failure.
   *
   * <p>This helper is used for the fast path when no compatibility parsing is required; it returns
   * {@code null} on syntax or resolution failures so the caller can fall back to other formats.
   *
   * @param phys raw physical entry in {@code host:port} form
   * @return parsed peer instance, or {@code null} when parsing fails
   */
  private static Peer tryParsePeerOrNull(String phys) {
    try {
      return new Peer(phys, true, true);
    } catch (HostnameSyntaxException | PeerParseException | UnknownHostException _) {
      return null;
    }
  }

  /**
   * Parses a comma-separated host list with a shared port suffix.
   *
   * <p>The input is expected to contain a trailing {@code :port}. Each host before the port is
   * trimmed and combined with the port to form a candidate peer. Any invalid candidates are skipped
   * without logging to allow other forms to succeed.
   *
   * @param phys raw physical entry string that may contain {@code A,B,C:port}
   * @param out destination list to append parsed peers to
   */
  private static void addPeersWithSharedPortSuffix(String phys, List<Peer> out) {
    int lastColon = phys.lastIndexOf(':');
    if (lastColon <= 0 || lastColon >= phys.length() - 1) {
      return;
    }

    String portStr = phys.substring(lastColon + 1);
    if (!isValidPortNumber(portStr)) {
      return;
    }

    String hostList = phys.substring(0, lastColon);
    StringTokenizer tokenizer = new StringTokenizer(hostList, ",");
    while (tokenizer.hasMoreTokens()) {
      String host = tokenizer.nextToken();
      addPeerIfParsable(host.trim() + ":" + portStr, out);
    }
  }

  /**
   * Parses a comma-separated list of full {@code host:port} tokens.
   *
   * <p>Each token is trimmed and parsed independently. Empty tokens are ignored, and any peers that
   * are already present in the output list are skipped to avoid duplicates.
   *
   * @param phys raw physical entry string that may contain {@code A:port,B:port}
   * @param out destination list to append parsed peers to
   */
  private static void addPeersFromCommaSeparatedTokens(String phys, List<Peer> out) {
    StringTokenizer tokenizer = new StringTokenizer(phys, ",");
    while (tokenizer.hasMoreTokens()) {
      String token = tokenizer.nextToken();
      String cand = token.trim();
      if (cand.isEmpty()) {
        continue;
      }
      addPeerIfParsableAndNotDuplicate(cand, out);
    }
  }

  /**
   * Validates that a port string is a decimal integer in the TCP/UDP range.
   *
   * <p>The method accepts {@code 0} through {@code 65535} and rejects any non-numeric or out-of-
   * range values.
   *
   * @param portStr port substring to parse and validate
   * @return {@code true} when the port is numeric and within the valid range
   */
  private static boolean isValidPortNumber(String portStr) {
    try {
      int port = Integer.parseInt(portStr);
      return port >= 0 && port <= 65535;
    } catch (NumberFormatException _) {
      return false;
    }
  }

  /**
   * Adds a parsed peer to the output list when the candidate is valid.
   *
   * <p>Parsing errors are intentionally ignored because the compatibility parser may try multiple
   * candidates and only wants to record successful parses.
   *
   * @param cand candidate {@code host:port} string to parse
   * @param out destination list to append a parsed peer to
   */
  private static void addPeerIfParsable(String cand, List<Peer> out) {
    try {
      out.add(new Peer(cand, true, true));
    } catch (Exception _) {
      // ignore; we will try other candidates
    }
  }

  /**
   * Adds a parsed peer to the output list if it is valid and not already present.
   *
   * <p>This helper is used for comma-separated full entries to avoid duplicates that might already
   * exist from the shared-port parsing path. Parsing errors are ignored.
   *
   * @param cand candidate {@code host:port} string to parse
   * @param out destination list to append a parsed peer to if unique
   */
  private static void addPeerIfParsableAndNotDuplicate(String cand, List<Peer> out) {
    try {
      Peer parsed = new Peer(cand, true, true);
      if (!out.contains(parsed)) {
        out.add(parsed);
      }
    } catch (Exception _) {
      // ignore; we will try other candidates
    }
  }

  /**
   * Logs a parse failure for a physical entry with context-specific severity.
   *
   * <p>Local peer lists are treated as configuration errors and logged at error level; remote
   * references are logged as warnings to reduce noise during peer exchange.
   *
   * @param phys raw physical entry that could not be parsed
   * @param fromLocal {@code true} when the entry comes from local configuration
   */
  private static void logInvalidPeerReference(String phys, boolean fromLocal) {
    if (fromLocal) {
      LOG.error(
          "Invalid hostname or IP Address syntax error while parsing peer reference in local peers"
              + " list: {}",
          phys);
    } else {
      LOG.warn(
          "Invalid hostname or IP Address syntax error while parsing peer reference: {}", phys);
    }
  }

  /**
   * Attempts to parse a {@code host:port} peer with logging on failure.
   *
   * <p>Unresolvable hostnames are logged at INFO to avoid excessive noise for transient or
   * host-local names; syntax errors are logged at ERROR to highlight malformed noderefs.
   *
   * @param phys raw physical entry to parse; must include a port suffix
   * @return parsed peer, or {@code null} when parsing fails
   */
  Peer tryParsePeer(String phys) {
    try {
      return new Peer(phys, true, true);
    } catch (UnknownHostException _) {
      // Host appears syntactically valid but cannot be resolved here (e.g., link-local scope name
      // not present on this host). Lower severity to INFO to avoid noisy logs.
      LOG.info(
          PeerNode.STR_INVALID_HOST_OR_IP_WHILE_PARSING
              + "{} (unresolvable here; likely host-local scope or transient DNS)",
          phys);
      return null;
    } catch (HostnameSyntaxException | PeerParseException _) {
      // True syntax issues: keep ERROR to surface malformed noderefs.
      LOG.error(PeerNode.STR_INVALID_HOST_OR_IP_WHILE_PARSING + "{}", phys);
      return null;
    }
  }

  /**
   * Validates testnet and opennet flags for a noderef.
   *
   * <p>The method rejects testnet peers when they are not explicitly allowed and checks that the
   * opennet flag matches the peer's expected configuration. Missing opennet information is only
   * allowed for differential noderefs.
   *
   * @param fs field set containing {@code testnet} and {@code opennet} fields
   * @param forDiffNodeRef {@code true} if the noderef is a differential update
   * @param forFullNodeRef {@code true} if the noderef is expected to be complete
   * @throws FSParseException if the noderef violates testnet or opennet expectations
   */
  void checkTestnetAndOpennet(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    if (!forDiffNodeRef && fs.getBoolean(PeerNode.SFS_KEY_TESTNET, false)) {
      String err = "Preventing connection to node " + peer.getPeer() + " - testnet is enabled!";
      LOG.error(err);
      throw new FSParseException(err);
    }
    String s = fs.get(PeerNode.SFS_KEY_OPENNET);
    if (s == null && forFullNodeRef) throw new FSParseException("No opennet ref");
    else if (s != null) {
      try {
        boolean b = Fields.stringToBool(s);
        if (b != peer.isOpennetForNoderef())
          throw new FSParseException(
              "Changed opennet status?!?!?!? expected="
                  + peer.isOpennetForNoderef()
                  + " but got "
                  + b
                  + " ("
                  + s
                  + PeerNode.STR_ON
                  + peer);
      } catch (NumberFormatException e) {
        throw new FSParseException("Cannot parse opennet=\"" + s + "\"", e);
      }
    }
  }

  /**
   * Validates that the identity in the noderef matches the peer's stored identity.
   *
   * <p>If the identity field is present, it must match the peer's existing identity bytes. When it
   * is absent, differential or partial noderefs may omit it, but full noderefs for darknet peers
   * must include it or a parse exception is raised.
   *
   * @param fs field set that may contain {@code identity} data
   * @param forDiffNodeRef {@code true} when validating a differential noderef
   * @param forFullNodeRef {@code true} when validating a full noderef
   * @throws FSParseException if identity is missing when required or does not match
   */
  void validateIdentity(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    String identityString = fs.get(PeerNode.SFS_KEY_IDENTITY);
    if (identityString != null) {
      try {
        byte[] id = Base64.decode(identityString);
        if (!Arrays.equals(id, peer.identity)) throw new FSParseException("Changing the identity");
      } catch (NumberFormatException | IllegalBase64Exception e) {
        throw new FSParseException(e);
      }
      return;
    }
    // Missing identity is allowed for differential or partial noderefs (e.g., during handshake).
    // Only full noderefs must include identity.
    if (forFullNodeRef && !forDiffNodeRef) {
      if (peer.isDarknet()) throw new FSParseException("No identity!");
      else if (LOG.isDebugEnabled())
        LOG.debug("didn't send an identity; let's assume it's pre-1471");
    }
  }

  /**
   * Parses ECDSA fields and validates that the peer key does not change.
   *
   * <p>The method reads the {@code ecdsa.P256.pub} field when present, validates its size, and
   * compares it against the existing peer key. Any attempt to change the key results in a parse
   * failure and an error log entry.
   *
   * @param fs field set that may contain {@code ecdsa.P256} key data
   * @throws FSParseException if key data is malformed or attempts to change the key
   */
  void parseEcdsaFields(SimpleFieldSet fs) throws FSParseException {
    /* Read the ECDSA key material for the peer */
    SimpleFieldSet sfs = fs.subset("ecdsa.P256");
    if (sfs != null) {
      byte[] pub;
      try {
        pub = Base64.decode(sfs.get("pub"));
      } catch (IllegalBase64Exception e) {
        throw new FSParseException("Invalid base64 in ecdsa.P256.pub", e);
      }
      if (pub.length > ECDSA.Curves.P256.modulusSize)
        throw new FSParseException("ecdsa.P256.pub is not the right size!");
      ECPublicKey key = ECDSA.getPublicKey(pub, ECDSA.Curves.P256);
      if (key == null) throw new FSParseException("ecdsa.P256.pub is invalid!");
      if (!key.equals(peer.peerECDSAPubKey)) {
        LOG.atError()
            .addArgument(peer::userToString)
            .log("Tried to change ECDSA key on {} - did neighbour try to downgrade? Rejecting...");
        throw new FSParseException("Changing ECDSA key not allowed!");
      }
    }
  }

  /**
   * Writes the ECDSA public key material into the provided field set.
   *
   * <p>The method stores a P-256 public key under the {@code ecdsa} subset using the canonical
   * serialization format expected by peers.
   *
   * @param fs destination field set to receive the ECDSA key data
   * @param key ECDSA public key to serialize into the field set
   */
  void putEcdsaFields(SimpleFieldSet fs, ECPublicKey key) {
    fs.put("ecdsa", Curves.P256.getSFS(key));
  }

  /**
   * Verifies the ECDSA signature embedded in the provided noderef field set.
   *
   * <p>The method removes signature fields to build the canonical bytes to verify, then restores
   * the signature field for verification. It records verification success or failure on the peer
   * and, when configured, stores the full field set. An exception is thrown for invalid or missing
   * signatures.
   *
   * @param fs field set containing signature fields and other noderef data
   * @return {@code true} when verification succeeds without errors
   * @throws ReferenceSignatureVerificationException if the signature is missing or invalid
   */
  @SuppressWarnings("UnusedReturnValue")
  boolean verifyReferenceSignature(SimpleFieldSet fs)
      throws ReferenceSignatureVerificationException {
    // Assume we failed at validating
    boolean failed;
    String signatureP256 = fs.get(PeerNode.SFS_KEY_SIG_P256);
    try {
      // If we have:
      // - the new P256 signature AND the P256 pubkey
      // OR
      // - the old DSA signature the pubkey and the groups
      // THEN
      // verify the signatures
      fs.removeValue("sig");
      fs.removeValue(PeerNode.SFS_KEY_SIG_P256);
      byte[] toVerifyECDSA = fs.toOrderedString().getBytes(StandardCharsets.UTF_8);

      boolean isECDSAsigPresent = (signatureP256 != null && peer.peerECDSAPubKey != null);
      boolean verifyECDSA = false; // assume it failed.

      // Is there a new ECDSA sig?
      if (isECDSAsigPresent) {
        fs.putSingle(PeerNode.SFS_KEY_SIG_P256, signatureP256);
        verifyECDSA =
            ECDSA.verify(
                Curves.P256, peer.peerECDSAPubKey, Base64.decode(signatureP256), toVerifyECDSA);
      }

      // If there is no signature, FAIL
      // If there is an ECDSA signature, and it doesn't verify, FAIL
      boolean hasNoSignature = !isECDSAsigPresent;
      boolean isECDSAsigInvalid = (isECDSAsigPresent && !verifyECDSA);
      failed = hasNoSignature || isECDSAsigInvalid;
      if (failed) {
        String errCause = "";
        if (hasNoSignature) errCause += " (No signature)";
        if (isECDSAsigInvalid) errCause += " (ECDSA signature is invalid)";
        errCause += " (VERIFICATION FAILED)";
        LOG.atError()
            .addArgument(errCause)
            .addArgument(fs::toOrderedString)
            .log("The integrity of the reference has been compromised!{} fs was\n{}");
        peer.setSignatureVerificationSuccessfull(false);
        throw new ReferenceSignatureVerificationException(
            "The integrity of the reference has been compromised!" + errCause);
      } else {
        peer.setSignatureVerificationSuccessfull(true);
        if (!peer.dontKeepFullFieldSet()) peer.fullFieldSet = fs;
      }
    } catch (IllegalBase64Exception e) {
      LOG.error("Invalid reference: {}", e, e);
      throw new ReferenceSignatureVerificationException(
          "The node reference you added is invalid: It does not have a valid ECDSA signature.");
    }
    return true;
  }

  /**
   * Formats a peer public key hash as a hex string.
   *
   * <p>The formatting uses lower-case hexadecimal output as provided by {@link HexUtil} and does
   * not perform any validation on the input length.
   *
   * @param hash raw hash bytes to format as hexadecimal
   * @return hex string representation of the provided hash
   */
  String formatPeerKeyHash(byte[] hash) {
    return HexUtil.bytesToHex(hash);
  }

  /**
   * Formats a duration in milliseconds as a human-friendly string.
   *
   * <p>The output is delegated to {@link TimeUtil} and preserves its formatting conventions for
   * seconds, minutes, and larger units.
   *
   * @param millis duration in milliseconds to format
   * @return formatted duration string suitable for logs or UI
   */
  String formatDuration(long millis) {
    return TimeUtil.formatTime(millis);
  }

  /**
   * Decodes a compressed or uncompressed noderef payload into a field set.
   *
   * <p>The payload format begins with a flag byte that may indicate compression and an optional
   * legacy DSA-compressed group. If compressed, the data is inflated into a temporary buffer of up
   * to 4096 bytes before being parsed as UTF-8 into a {@link SimpleFieldSet}.
   *
   * @param data raw byte array containing the noderef payload
   * @param offset starting offset into {@code data} where the payload begins
   * @param length length of the payload in bytes starting at {@code offset}
   * @return parsed {@link SimpleFieldSet} representing the noderef contents
   * @throws FSParseException if the payload is too short or decompression fails
   */
  static SimpleFieldSet compressedNoderefToFieldSet(byte[] data, int offset, int length)
      throws FSParseException {
    if (length <= 5) throw new FSParseException("Too short");
    int firstByte = data[offset];
    offset++;
    length--;
    if ((firstByte & 0x2) == 2) { // DSAcompressed group; legacy
      offset++;
      length--;
    }
    // Is it compressed?
    if ((firstByte & 1) == 1) {
      try (Inflater inflater = new Inflater()) {
        inflater.setInput(data, offset, length);
        // We shouldn't ever need 4096 bytes long ref!
        byte[] output = new byte[4096];
        length = inflater.inflate(output, 0, output.length);
        // Finished
        data = output;
        offset = 0;
        if (LOG.isDebugEnabled())
          LOG.debug("We have decompressed a {} bytes big reference.", length);
      } catch (DataFormatException _) {
        throw new FSParseException("Invalid compressed data");
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reference: {}({})", HexUtil.bytesToHex(data, offset, length), length);

    // Now decode it
    ByteArrayInputStream bais = new ByteArrayInputStream(data, offset, length);
    InputStreamReader isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
    try (BufferedReader br = new BufferedReader(isr)) {
      return new SimpleFieldSet(br, false, true);
    } catch (IOException e) {
      throw new FSParseException("Impossible: " + e, e);
    }
  }

  /**
   * Checks whether an address is a valid public address for peer communication.
   *
   * <p>The validation delegates to {@link IPUtil} and rejects loopback or otherwise unusable
   * addresses according to the project's IP filtering rules.
   *
   * @param addr address to validate; must be non-null
   * @return {@code true} when the address is acceptable for peer connections
   */
  static boolean isValidAddress(InetAddress addr) {
    return IPUtil.isValidAddress(addr, false);
  }

  /**
   * Splits a version string into trimmed, non-empty components.
   *
   * <p>The input is split on commas, with whitespace trimmed from each token and empty tokens
   * discarded. A {@code null} input yields an empty array.
   *
   * @param versionStr raw version string, possibly {@code null}
   * @return array of trimmed version components, possibly empty
   */
  static String[] splitVersionComponents(String versionStr) {
    if (versionStr == null) {
      return new String[0];
    }
    StringTokenizer tokenizer = new StringTokenizer(versionStr, ",");
    ArrayList<String> components = new ArrayList<>();
    while (tokenizer.hasMoreTokens()) {
      String trimmed = tokenizer.nextToken().trim();
      if (!trimmed.isEmpty()) {
        components.add(trimmed);
      }
    }
    return components.toArray(new String[0]);
  }

  /**
   * Computes the ARK {@link USK} for a peer from noderef fields.
   *
   * <p>The method reads the ARK public key URI and edition number from the field set. When both are
   * present, it constructs a {@link USK} and optionally increments the edition on startup. For
   * differential noderefs, it can reuse an existing {@code currentArk} when only the edition is
   * provided. Parsing errors are logged and result in {@code null}.
   *
   * @param peer peer associated with the noderef, used only for log context
   * @param fs field set that may contain ARK-related fields
   * @param onStartup {@code true} to increment the edition for startup handling
   * @param forDiffNodeRef {@code true} when processing a differential noderef
   * @param currentArk existing ARK to reuse for differential updates, or {@code null}
   * @return constructed {@link USK} when ARK data is valid, otherwise {@code null}
   */
  static USK computeArk(
      PeerNode peer, SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef, USK currentArk) {
    try {
      String arkPubKey = fs.get(PeerNode.SFS_KEY_ARK_PUBURI);
      long arkNo = fs.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1);
      if (arkPubKey == null && arkNo <= -1) return null; // pair is optional
      if (arkPubKey != null && arkNo > -1) {
        if (onStartup) arkNo++;
        FreenetURI uri = new FreenetURI(arkPubKey);
        ClientSSK ssk = new ClientSSK(uri);
        return new USK(ssk, arkNo);
      }
      if (forDiffNodeRef && arkPubKey == null && currentArk != null) {
        return currentArk.copy(arkNo);
      }
      if (forDiffNodeRef && arkPubKey != null && currentArk != null) {
        LOG.error(
            "Got a differential node reference from {} with an arkPubKey but no ARK edition", peer);
        return null;
      }
    } catch (MalformedURLException | NumberFormatException e) {
      LOG.error("Couldn't parse ARK info for {}: {}", peer, e, e);
    }
    return null;
  }
}
