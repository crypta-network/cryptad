package network.crypta.node;

import java.security.interfaces.ECPublicKey;
import java.util.Objects;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds validated constructor inputs for {@link PeerNode} instances from a peer noderef.
 *
 * <p>This helper keeps parsing and validation logic out of {@link PeerNode} so the node class can
 * focus on runtime behavior once construction inputs have been validated.
 */
final class PeerNodeConstructorSupport {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeConstructorSupport.class);

  private static final String SFS_KEY_VERSION = "version";
  private static final String SFS_KEY_LAST_GOOD_VERSION = "lastGoodVersion";
  private static final String SFS_KEY_TESTNET = "testnet";
  private static final String SFS_KEY_NEG_TYPES = "auth.negTypes";
  private static final String SFS_KEY_OPENNET = "opennet";

  private PeerNodeConstructorSupport() {}

  static PeerNode.ConstructorInit prepareConstructorInit(
      SimpleFieldSet fs,
      Node node2,
      NodeCrypto crypto,
      boolean fromLocal,
      PeerManager peers,
      PeerNode.ConstructorProfile profile)
      throws FSParseException {
    SimpleFieldSet resolvedFs = Objects.requireNonNull(fs, "fs");
    Node resolvedNode = Objects.requireNonNull(node2, "node2");
    NodeCrypto resolvedCrypto = Objects.requireNonNull(crypto, "crypto");
    PeerManager resolvedPeers = Objects.requireNonNull(peers, "peers");
    Objects.requireNonNull(profile, "profile");

    if (resolvedCrypto.isOpennet() != profile.opennetForNoderef) {
      throw new IllegalArgumentException("Mismatched NodeCrypto for noderef type");
    }

    OutgoingPacketMangler resolvedOutgoingMangler = resolvedCrypto.getPacketMangler();
    String parsedVersion = resolvedFs.get(SFS_KEY_VERSION);
    Version.seenVersion(parsedVersion);
    int parsedSimpleVersion;
    try {
      parsedSimpleVersion = Version.parseBuildNumberFromVersionStr(parsedVersion);
    } catch (VersionParseException e2) {
      throw new FSParseException("Invalid version " + parsedVersion + " : " + e2);
    }

    boolean parsedTestnetEnabled = resolvedFs.getBoolean(SFS_KEY_TESTNET, false);
    if (parsedTestnetEnabled) {
      String err = "Ignoring incompatible testnet node " + resolvedFs.toOrderedString();
      LOG.error(err);
      throw new FSParseException(err);
    }

    int[] parsedNegTypes = resolvedFs.getIntArray(SFS_KEY_NEG_TYPES);
    if (parsedNegTypes == null || parsedNegTypes.length == 0) {
      if (profile.anonymousInitiator) {
        parsedNegTypes = resolvedOutgoingMangler.supportedNegTypes(false);
      } else {
        throw new FSParseException("No negTypes!");
      }
    }

    boolean parsedOpennet = resolvedFs.getBoolean(SFS_KEY_OPENNET, false);
    if (parsedOpennet != profile.opennetForNoderef) {
      throw new FSParseException(
          "Trying to parse a darknet peer as opennet or an opennet peer as darknet isOpennet="
              + profile.opennetForNoderef
              + " boolean = "
              + parsedOpennet
              + " string = \""
              + resolvedFs.get(SFS_KEY_OPENNET)
              + "\"");
    }

    ECPublicKey parsedPeerEcdsaKey;
    try {
      parsedPeerEcdsaKey = PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(resolvedFs);
    } catch (Exception e) {
      if (e instanceof FSParseException fsParseException) {
        throw fsParseException;
      }
      throw new FSParseException("Invalid peer ECDSA key", e);
    }
    byte[] parsedPeerEcdsaHash =
        PeerNodeReferenceSupport.computePeerPublicKeyHash(parsedPeerEcdsaKey);

    boolean noSig = fromLocal || profile.anonymousInitiator;
    PeerNodeReferenceSupport.SignatureVerificationResult signatureResult;
    try {
      signatureResult =
          PeerNodeReferenceSupport.verifySignatureForConstruction(
              resolvedFs, noSig, parsedPeerEcdsaKey, profile.keepFullFieldSet);
    } catch (Exception e) {
      throw new FSParseException("Invalid peer noderef signature", e);
    }

    PeerNode.IdentityValues parsedIdentityValues;
    try {
      parsedIdentityValues =
          PeerNodeReferenceSupport.readIdentityValues(
              resolvedFs, profile.isDarknet, parsedPeerEcdsaHash);
    } catch (Exception e) {
      if (e instanceof FSParseException fsParseException) {
        throw fsParseException;
      }
      throw new FSParseException("Invalid peer identity", e);
    }

    return new PeerNode.ConstructorInit(
        resolvedFs,
        resolvedNode,
        resolvedCrypto,
        fromLocal,
        resolvedPeers,
        resolvedOutgoingMangler,
        parsedVersion,
        parsedSimpleVersion,
        resolvedFs.get(SFS_KEY_LAST_GOOD_VERSION),
        parsedTestnetEnabled,
        parsedNegTypes,
        parsedPeerEcdsaKey,
        parsedPeerEcdsaHash,
        signatureResult.signatureVerificationSuccessful,
        signatureResult.fullFieldSet,
        parsedIdentityValues);
  }
}
