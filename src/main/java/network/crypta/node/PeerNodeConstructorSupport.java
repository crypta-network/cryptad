package network.crypta.node;

import java.security.interfaces.ECPublicKey;
import java.util.Objects;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds validated constructor inputs for {@link PeerNode} instances from a peer noderef.
 *
 * <p>This type centralizes noderef parsing and constructor preconditions so {@link PeerNode}
 * construction can stay focused on runtime behavior. The helper consumes the raw field set,
 * enforces consistency checks between parsed values and constructor profile flags, and transforms
 * low-level parse errors into {@link FSParseException} instances that the caller can handle
 * uniformly.
 *
 * <p>The workflow performs version handling, network-mode validation, cryptographic identity
 * loading, and signature verification before it returns immutable constructor values.
 *
 * <ul>
 *   <li>All required inputs are validated as non-null before processing starts.
 *   <li>Profile-dependent defaults are applied only when explicitly allowed by the profile.
 *   <li>Returned values are ready to be passed directly to {@link PeerNode.ConstructorInit}.
 * </ul>
 */
final class PeerNodeConstructorSupport {
  /** Logger for constructor preparation failures and incompatible noderef diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeConstructorSupport.class);

  /** Field-set key for the peer version string that includes a build number suffix. */
  private static final String SFS_KEY_VERSION = "version";

  /** Field-set key for the most recent known-good version identifier. */
  private static final String SFS_KEY_LAST_GOOD_VERSION = "lastGoodVersion";

  /** Field-set key indicating whether the remote node advertises testnet mode. */
  private static final String SFS_KEY_TESTNET = "testnet";

  /** Field-set key listing supported authentication negotiation types. */
  private static final String SFS_KEY_NEG_TYPES = "auth.negTypes";

  /** Field-set key indicating whether the noderef is for opennet traffic. */
  private static final String SFS_KEY_OPENNET = "opennet";

  /** Utility type; instantiation is intentionally blocked. */
  private PeerNodeConstructorSupport() {}

  /**
   * Parses and validates constructor values derived from a peer noderef.
   *
   * <p>The method enforces profile and crypto compatibility, validates version and network mode
   * fields, loads and hashes the peer ECDSA key, verifies the optional noderef signature, and
   * parses identity values. All successful outputs are grouped into a {@link
   * PeerNode.ConstructorInit} instance so callers can build a {@link PeerNode} without repeating
   * parse and validation logic.
   *
   * @param fs raw noderef fields received from storage or the network.
   * @param node2 owning node context used for constructor initialization.
   * @param crypto node cryptography context expected for the noderef type.
   * @param fromLocal whether the noderef originated locally and may omit signature validation.
   * @param peers peer manager that will own the constructed peer instance.
   * @param profile constructor profile flags that define parse and validation behavior.
   * @return fully validated constructor values grouped by runtime, version, and identity concerns.
   * @throws FSParseException if any noderef field is invalid, inconsistent, or cryptographically
   *     unusable for constructor initialization.
   */
  static PeerNode.ConstructorInit prepareConstructorInit(
      SimpleFieldSet fs,
      Node node2,
      NodeCrypto crypto,
      boolean fromLocal,
      PeerManager peers,
      PeerNode.ConstructorProfile profile)
      throws FSParseException {
    ResolvedInputs resolved = resolveInputs(fs, node2, crypto, peers, profile);
    OutgoingPacketMangler resolvedOutgoingMangler = resolved.crypto.getPacketMangler();
    PeerNode.ConstructorInit.VersionValues versionValues =
        buildVersionValues(resolved.fs, profile, resolvedOutgoingMangler);
    ECPublicKey parsedPeerEcdsaKey = parsePeerEcdsaKey(resolved.fs);
    byte[] parsedPeerEcdsaHash =
        PeerNodeReferenceSupport.computePeerPublicKeyHash(parsedPeerEcdsaKey);
    PeerNodeReferenceSupport.SignatureVerificationResult signatureResult =
        verifySignatureForConstruction(resolved.fs, fromLocal, profile, parsedPeerEcdsaKey);
    PeerNode.IdentityValues parsedIdentityValues =
        parseIdentityValues(resolved.fs, profile, parsedPeerEcdsaHash);
    PeerNode.ConstructorInit.CoreValues coreValues =
        new PeerNode.ConstructorInit.CoreValues(
            resolved.fs,
            resolved.node,
            resolved.crypto,
            fromLocal,
            resolved.peers,
            resolvedOutgoingMangler);
    PeerNode.ConstructorInit.IdentityAndSignatureValues identityAndSignatureValues =
        new PeerNode.ConstructorInit.IdentityAndSignatureValues(
            parsedPeerEcdsaKey,
            parsedPeerEcdsaHash,
            signatureResult.signatureVerificationSuccessful(),
            signatureResult.fullFieldSet(),
            parsedIdentityValues);

    return new PeerNode.ConstructorInit(coreValues, versionValues, identityAndSignatureValues);
  }

  /**
   * Non-null constructor inputs normalized before derived values are computed.
   *
   * @param fs noderef field set used during constructor parsing.
   * @param node owning node instance associated with the new peer.
   * @param crypto cryptography context validated against noderef mode.
   * @param peers peer manager that will host the constructed peer.
   */
  private record ResolvedInputs(
      SimpleFieldSet fs, Node node, NodeCrypto crypto, PeerManager peers) {}

  /**
   * Normalizes external constructor arguments and validates noderef type compatibility.
   *
   * @param fs raw noderef field set.
   * @param node2 local node instance associated with the constructor flow.
   * @param crypto cryptography context expected for this noderef.
   * @param peers peer manager that will receive the resulting peer.
   * @param profile constructor profile flags controlling noderef expectations.
   * @return grouped non-null inputs that can be used for downstream parsing steps.
   * @throws NullPointerException if any required argument is {@code null}.
   * @throws IllegalArgumentException if crypto mode and noderef profile mode are inconsistent.
   */
  private static ResolvedInputs resolveInputs(
      SimpleFieldSet fs,
      Node node2,
      NodeCrypto crypto,
      PeerManager peers,
      PeerNode.ConstructorProfile profile) {
    SimpleFieldSet resolvedFs = Objects.requireNonNull(fs, "fs");
    Node resolvedNode = Objects.requireNonNull(node2, "node2");
    NodeCrypto resolvedCrypto = Objects.requireNonNull(crypto, "crypto");
    PeerManager resolvedPeers = Objects.requireNonNull(peers, "peers");
    Objects.requireNonNull(profile, "profile");
    validateNoderefType(resolvedCrypto, profile);
    return new ResolvedInputs(resolvedFs, resolvedNode, resolvedCrypto, resolvedPeers);
  }

  /**
   * Verifies that the provided crypto context matches the noderef mode expected by the profile.
   *
   * @param resolvedCrypto crypto context supplied for constructor setup.
   * @param profile constructor profile that declares expected opennet or darknet mode.
   * @throws IllegalArgumentException if the crypto mode does not match profile expectations.
   */
  private static void validateNoderefType(
      NodeCrypto resolvedCrypto, PeerNode.ConstructorProfile profile) {
    if (resolvedCrypto.isOpennet() != profile.opennetForNoderef) {
      throw new IllegalArgumentException("Mismatched NodeCrypto for noderef type");
    }
  }

  /**
   * Parses and validates version-related constructor values from the noderef field set.
   *
   * @param fs noderef field set containing version, testnet, and negotiation metadata.
   * @param profile constructor profile controlling fallback behavior and mode checks.
   * @param outgoingMangler packet mangler used to derive default negotiation types when allowed.
   * @return immutable version value group suitable for {@link PeerNode.ConstructorInit}.
   * @throws FSParseException if required version fields are missing or internally inconsistent.
   */
  private static PeerNode.ConstructorInit.VersionValues buildVersionValues(
      SimpleFieldSet fs, PeerNode.ConstructorProfile profile, OutgoingPacketMangler outgoingMangler)
      throws FSParseException {
    String parsedVersion = fs.get(SFS_KEY_VERSION);
    int parsedSimpleVersion = parseSimpleVersion(parsedVersion);
    boolean parsedTestnetEnabled = parseAndValidateTestnet(fs);
    int[] parsedNegTypes = parseNegTypes(fs, profile, outgoingMangler);
    validateOpennetFlag(fs, profile);
    return new PeerNode.ConstructorInit.VersionValues(
        parsedVersion,
        parsedSimpleVersion,
        fs.get(SFS_KEY_LAST_GOOD_VERSION),
        parsedTestnetEnabled,
        parsedNegTypes);
  }

  /**
   * Parses the numeric build component from a peer version string.
   *
   * @param parsedVersion version string read from the noderef.
   * @return parsed build number encoded by the version string.
   * @throws FSParseException if the version string cannot be parsed as a valid build identifier.
   */
  private static int parseSimpleVersion(String parsedVersion) throws FSParseException {
    Version.seenVersion(parsedVersion);
    try {
      return Version.parseBuildNumberFromVersionStr(parsedVersion);
    } catch (VersionParseException e2) {
      throw new FSParseException("Invalid version " + parsedVersion + " : " + e2);
    }
  }

  /**
   * Rejects noderefs that advertise testnet mode in this runtime.
   *
   * @param fs noderef field set containing the testnet flag.
   * @return {@code false} when testnet is disabled in the noderef.
   * @throws FSParseException if the noderef announces testnet mode and must be rejected.
   */
  private static boolean parseAndValidateTestnet(SimpleFieldSet fs) throws FSParseException {
    boolean parsedTestnetEnabled = fs.getBoolean(SFS_KEY_TESTNET, false);
    if (!parsedTestnetEnabled) {
      return false;
    }
    String err = "Ignoring incompatible testnet node " + fs.toOrderedString();
    LOG.error(err);
    throw new FSParseException(err);
  }

  /**
   * Resolves supported negotiation types from the noderef or an anonymous-initiator fallback.
   *
   * @param fs noderef field set containing optional negotiation types.
   * @param profile constructor profile that controls fallback eligibility.
   * @param outgoingMangler packet mangler used to provide default negotiation types.
   * @return non-empty negotiation type identifiers for authentication setup.
   * @throws FSParseException if no negotiation types are available for the active profile.
   */
  private static int[] parseNegTypes(
      SimpleFieldSet fs, PeerNode.ConstructorProfile profile, OutgoingPacketMangler outgoingMangler)
      throws FSParseException {
    int[] parsedNegTypes = fs.getIntArray(SFS_KEY_NEG_TYPES);
    if (parsedNegTypes != null && parsedNegTypes.length != 0) {
      return parsedNegTypes;
    }
    if (profile.anonymousInitiator) {
      return outgoingMangler.supportedNegTypes(false);
    }
    throw new FSParseException("No negTypes!");
  }

  /**
   * Confirms that the noderef opennet flag matches the expected constructor profile mode.
   *
   * @param fs noderef field set containing the opennet flag.
   * @param profile constructor profile defining the expected noderef mode.
   * @throws FSParseException if the noderef mode does not match the requested profile mode.
   */
  private static void validateOpennetFlag(SimpleFieldSet fs, PeerNode.ConstructorProfile profile)
      throws FSParseException {
    boolean parsedOpennet = fs.getBoolean(SFS_KEY_OPENNET, false);
    if (parsedOpennet == profile.opennetForNoderef) {
      return;
    }
    throw new FSParseException(
        "Trying to parse a darknet peer as opennet or an opennet peer as darknet isOpennet="
            + profile.opennetForNoderef
            + " boolean = "
            + parsedOpennet
            + " string = \""
            + fs.get(SFS_KEY_OPENNET)
            + "\"");
  }

  /**
   * Parses the peer ECDSA public key from the noderef.
   *
   * @param fs noderef field set containing key material.
   * @return parsed peer ECDSA public key.
   * @throws FSParseException if key material is missing, malformed, or otherwise invalid.
   */
  private static ECPublicKey parsePeerEcdsaKey(SimpleFieldSet fs) throws FSParseException {
    try {
      return PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs);
    } catch (Exception e) {
      if (e instanceof FSParseException fsParseException) {
        throw fsParseException;
      }
      throw new FSParseException("Invalid peer ECDSA key", e);
    }
  }

  /**
   * Verifies the noderef signature according to constructor profile and source.
   *
   * @param fs noderef field set containing signature-related fields.
   * @param fromLocal whether the noderef was loaded locally and can skip strict signature checks.
   * @param profile constructor profile that controls anonymous and full-field-set behavior.
   * @param parsedPeerEcdsaKey parsed peer ECDSA key used for signature verification.
   * @return signature verification result including the validity flag and optional full field set.
   * @throws FSParseException if signature verification fails or signature data is malformed.
   */
  private static PeerNodeReferenceSupport.SignatureVerificationResult
      verifySignatureForConstruction(
          SimpleFieldSet fs,
          boolean fromLocal,
          PeerNode.ConstructorProfile profile,
          ECPublicKey parsedPeerEcdsaKey)
          throws FSParseException {
    boolean noSig = fromLocal || profile.anonymousInitiator;
    try {
      return PeerNodeReferenceSupport.verifySignatureForConstruction(
          fs, noSig, parsedPeerEcdsaKey, profile.keepFullFieldSet);
    } catch (Exception e) {
      throw new FSParseException("Invalid peer noderef signature", e);
    }
  }

  /**
   * Parses peer identity values from the noderef using the constructor profile mode.
   *
   * @param fs noderef field set containing identity attributes.
   * @param profile constructor profile that defines whether identity is parsed as darknet.
   * @param parsedPeerEcdsaHash hash of the parsed peer ECDSA public key.
   * @return parsed peer identity values for constructor initialization.
   * @throws FSParseException if identity fields are missing or semantically invalid.
   */
  private static PeerNode.IdentityValues parseIdentityValues(
      SimpleFieldSet fs, PeerNode.ConstructorProfile profile, byte[] parsedPeerEcdsaHash)
      throws FSParseException {
    try {
      return PeerNodeReferenceSupport.readIdentityValues(
          fs, profile.isDarknet, parsedPeerEcdsaHash);
    } catch (Exception e) {
      if (e instanceof FSParseException fsParseException) {
        throw fsParseException;
      }
      throw new FSParseException("Invalid peer identity", e);
    }
  }
}
