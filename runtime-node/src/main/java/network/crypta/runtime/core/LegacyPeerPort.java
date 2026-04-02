package network.crypta.runtime.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.PeerAddFailureReason;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.RemovedPeerSnapshot;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapts the daemon's legacy peer-management logic to the runtime SPI's {@link PeerPort}.
 *
 * <p>This bridge keeps knowledge of {@link Node}, {@link PeerNode}, {@link DarknetPeerNode}, and
 * {@link SimpleFieldSet} inside the daemon root module while exposing only SPI-local DTOs to
 * management-facing code. It preserves the current peer-management behavior by delegating directly
 * to the daemon's existing peer lookup, export, add, remove, and mutation paths.
 *
 * <p>The adapter is intentionally narrow. It exists to keep the peer-management slice migrated in
 * this PR behind a JDK-only SPI without redesigning the daemon's internal peer model. It converts
 * legacy field-set exports into detached snapshot trees, translates legacy peer-add failures into
 * SPI-local exceptions, and applies the small set of darknet-only mutations that the current FCP
 * message family already supports.
 */
final class LegacyPeerPort implements PeerPort {
  /** Logger used for add-peer events that were already visible through the legacy path. */
  private static final Logger LOG = LoggerFactory.getLogger(LegacyPeerPort.class);

  /** Subset key used when attaching exported peer metadata to detached snapshots. */
  private static final String METADATA_SUBSET = "metadata";

  /** Subset key used when attaching exported volatile peer state to detached snapshots. */
  private static final String VOLATILE_SUBSET = "volatile";

  /** Live daemon node whose legacy network subsystem performs the actual peer operations. */
  private final Node node;

  /**
   * Creates a legacy-backed peer-management port for the current daemon runtime.
   *
   * @param node daemon node that exposes the legacy peer-management subsystem
   */
  LegacyPeerPort(Node node) {
    this.node = Objects.requireNonNull(node);
  }

  /** {@inheritDoc} */
  @Override
  public List<PeerSnapshot> list(boolean includeMetadata, boolean includeVolatile) {
    PeerNode[] peers = node.network().peerNodes();
    List<PeerSnapshot> snapshots = new ArrayList<>(peers.length);
    for (PeerNode peer : peers) {
      snapshots.add(toPeerSnapshot(peer, includeMetadata, includeVolatile));
    }
    return List.copyOf(snapshots);
  }

  /** {@inheritDoc} */
  @Override
  public PeerSnapshot get(String nodeIdentifier, boolean includeMetadata, boolean includeVolatile)
      throws UnknownPeerException {
    return toPeerSnapshot(resolvePeer(nodeIdentifier), includeMetadata, includeVolatile);
  }

  /** {@inheritDoc} */
  @Override
  public PeerSnapshot add(PeerFieldSet reference, PeerTrust trust, PeerVisibility visibility)
      throws PeerAddRejectedException {
    Objects.requireNonNull(reference, "reference");
    Objects.requireNonNull(trust, "trust");
    Objects.requireNonNull(visibility, "visibility");

    SimpleFieldSet fieldSet = toSimpleFieldSet(reference);
    boolean isOpennetRef = fieldSet.getBoolean("opennet", false);
    PeerNode peer =
        isOpennetRef ? createOpennetPeer(fieldSet) : createDarknetPeer(fieldSet, trust, visibility);
    ensureNotSelfPeer(peer, isOpennetRef);
    if (!node.network().addPeerConnection(peer)) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.DUPLICATE_PEER_REF, "Node already has a peer with that identity");
    }
    if (isOpennetRef) {
      LOG.info("Added opennet peer: {}", peer);
    } else {
      LOG.info("Added darknet peer: {}", peer);
    }
    return toPeerSnapshot(peer, true, true);
  }

  /** {@inheritDoc} */
  @Override
  public PeerSnapshot updateDarknetPeer(String nodeIdentifier, DarknetPeerSettingsUpdate update)
      throws UnknownPeerException, DarknetPeerRequiredException {
    Objects.requireNonNull(update, "update");
    DarknetPeerNode peer = resolveDarknetPeer(nodeIdentifier);
    return applyDarknetPeerUpdate(peer, update);
  }

  /** {@inheritDoc} */
  @Override
  public PeerSnapshot updateDarknetPeerByIdentity(
      String peerIdentity, DarknetPeerSettingsUpdate update)
      throws UnknownPeerException, DarknetPeerRequiredException {
    Objects.requireNonNull(update, "update");
    DarknetPeerNode peer = resolveDarknetPeerByIdentity(peerIdentity);
    return applyDarknetPeerUpdate(peer, update);
  }

  private PeerSnapshot applyDarknetPeerUpdate(
      DarknetPeerNode peer, DarknetPeerSettingsUpdate update) {
    applyDisableFlag(peer, update.disabled());
    applyBooleanFlag(update.listenOnly(), peer::setListenOnly);
    applyBooleanFlag(update.burstOnly(), peer::setBurstOnly);
    applyBooleanFlag(update.ignoreSourcePort(), peer::setIgnoreSourcePort);
    applyBooleanFlag(update.allowLocalAddresses(), peer::setAllowLocalAddresses);
    applyRoutingFlag(peer, update.routingEnabled());
    applyTrust(peer, update.trust());
    applyVisibility(peer, update.visibility());
    return toPeerSnapshot(peer, true, true);
  }

  /** {@inheritDoc} */
  @Override
  public RemovedPeerSnapshot remove(String nodeIdentifier) throws UnknownPeerException {
    PeerNode peer = resolvePeer(nodeIdentifier);
    String identity = peer.getIdentityString();
    node.network().removePeerConnection(peer);
    return new RemovedPeerSnapshot(identity, nodeIdentifier);
  }

  /** {@inheritDoc} */
  @Override
  public RemovedPeerSnapshot removeByIdentity(String peerIdentity) throws UnknownPeerException {
    PeerNode peer = resolvePeerByIdentity(peerIdentity);
    if (peer == null) {
      throw new UnknownPeerException(peerIdentity);
    }
    String identity = peer.getIdentityString();
    node.network().removePeerConnection(peer);
    return new RemovedPeerSnapshot(identity, peerIdentity);
  }

  /** {@inheritDoc} */
  @Override
  public String readPrivateDarknetComment(String nodeIdentifier)
      throws UnknownPeerException, DarknetPeerRequiredException {
    return resolveDarknetPeer(nodeIdentifier).getPrivateDarknetCommentNote();
  }

  /** {@inheritDoc} */
  @Override
  public String writePrivateDarknetComment(String nodeIdentifier, String noteText)
      throws UnknownPeerException, DarknetPeerRequiredException {
    DarknetPeerNode peer = resolveDarknetPeer(nodeIdentifier);
    peer.setPrivateDarknetCommentNote(noteText);
    return peer.getPrivateDarknetCommentNote();
  }

  /** {@inheritDoc} */
  @Override
  public String writePrivateDarknetCommentByIdentity(String peerIdentity, String noteText)
      throws UnknownPeerException, DarknetPeerRequiredException {
    DarknetPeerNode peer = resolveDarknetPeerByIdentity(peerIdentity);
    peer.setPrivateDarknetCommentNote(noteText);
    return peer.getPrivateDarknetCommentNote();
  }

  /**
   * Resolves one peer by the daemon's existing node-identifier lookup path.
   *
   * @param nodeIdentifier peer identifier to resolve through the legacy network subsystem
   * @return resolved live peer instance from the daemon
   * @throws UnknownPeerException if the identifier does not match any known peer
   */
  private PeerNode resolvePeer(String nodeIdentifier) throws UnknownPeerException {
    Objects.requireNonNull(nodeIdentifier, "nodeIdentifier");
    PeerNode peer = node.network().getPeerNode(nodeIdentifier);
    if (peer == null) {
      throw new UnknownPeerException(nodeIdentifier);
    }
    return peer;
  }

  private PeerNode resolvePeerByIdentity(String identity) {
    Objects.requireNonNull(identity, "identity");
    for (PeerNode peer : node.network().peerNodes()) {
      if (identity.equals(peer.getIdentityString())) {
        return peer;
      }
    }
    return null;
  }

  /**
   * Resolves one peer and verifies that it is a darknet peer.
   *
   * @param nodeIdentifier peer identifier to resolve through the legacy network subsystem
   * @return resolved darknet peer instance from the daemon
   * @throws UnknownPeerException if the identifier does not match any known peer
   * @throws DarknetPeerRequiredException if the resolved peer is not a darknet peer
   */
  private DarknetPeerNode resolveDarknetPeer(String nodeIdentifier)
      throws UnknownPeerException, DarknetPeerRequiredException {
    PeerNode peer = resolvePeer(nodeIdentifier);
    if (!(peer instanceof DarknetPeerNode darknetPeer)) {
      throw new DarknetPeerRequiredException(nodeIdentifier);
    }
    return darknetPeer;
  }

  private DarknetPeerNode resolveDarknetPeerByIdentity(String peerIdentity)
      throws UnknownPeerException, DarknetPeerRequiredException {
    PeerNode peer = resolvePeerByIdentity(peerIdentity);
    if (peer == null) {
      throw new UnknownPeerException(peerIdentity);
    }
    if (!(peer instanceof DarknetPeerNode darknetPeer)) {
      throw new DarknetPeerRequiredException(peerIdentity);
    }
    return darknetPeer;
  }

  /**
   * Creates one opennet peer from a legacy field-set reference.
   *
   * @param fieldSet detached peer reference converted back into the legacy field-set format
   * @return live opennet peer instance created by the daemon
   * @throws PeerAddRejectedException if legacy peer creation rejects the reference
   */
  private PeerNode createOpennetPeer(SimpleFieldSet fieldSet) throws PeerAddRejectedException {
    try {
      return node.network().createNewOpennetNode(fieldSet);
    } catch (FSParseException | PeerParseException | PeerTooOldException e) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.REF_PARSE_ERROR, "Error parsing ref: " + e.getMessage());
    } catch (OpennetDisabledException e) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.OPENNET_DISABLED, "Error adding ref: " + e.getMessage());
    } catch (ReferenceSignatureVerificationException e) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.REF_SIGNATURE_INVALID, "Error adding ref: " + e.getMessage());
    }
  }

  /**
   * Creates one darknet peer from a legacy field-set reference and SPI-local defaults.
   *
   * @param fieldSet detached peer reference converted back into the legacy field-set format
   * @param trust SPI-local trust level supplied by the caller
   * @param visibility SPI-local visibility level supplied by the caller
   * @return live darknet peer instance created by the daemon
   * @throws PeerAddRejectedException if legacy peer creation rejects the reference
   */
  private PeerNode createDarknetPeer(
      SimpleFieldSet fieldSet, PeerTrust trust, PeerVisibility visibility)
      throws PeerAddRejectedException {
    try {
      return node.network()
          .createNewDarknetNode(fieldSet, toLegacyTrust(trust), toLegacyVisibility(visibility));
    } catch (FSParseException | PeerParseException | PeerTooOldException e) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.REF_PARSE_ERROR, "Error parsing ref: " + e.getMessage());
    } catch (ReferenceSignatureVerificationException e) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.REF_SIGNATURE_INVALID, "Error adding ref: " + e.getMessage());
    }
  }

  /**
   * Rejects peer references that resolve to the local node's own public-key hash.
   *
   * @param peer candidate peer created by the legacy daemon path
   * @param isOpennetRef whether the reference was classified as opennet
   * @throws PeerAddRejectedException if the peer resolves to the local node
   */
  private void ensureNotSelfPeer(PeerNode peer, boolean isOpennetRef)
      throws PeerAddRejectedException {
    byte[] nodePubKeyHash =
        isOpennetRef ? node.network().opennetPubKeyHash() : node.network().darknetPubKeyHash();
    if (Arrays.equals(peer.peerECDSAPubKeyHash, nodePubKeyHash)) {
      throw new PeerAddRejectedException(
          PeerAddFailureReason.CANNOT_PEER_WITH_SELF, "Node cannot peer with itself");
    }
  }

  /**
   * Maps the SPI-local trust enum onto the daemon's legacy darknet trust enum.
   *
   * @param trust SPI-local trust value supplied to the runtime port
   * @return equivalent legacy trust value expected by the daemon
   */
  private static FRIEND_TRUST toLegacyTrust(PeerTrust trust) {
    return switch (trust) {
      case LOW -> FRIEND_TRUST.LOW;
      case NORMAL -> FRIEND_TRUST.NORMAL;
      case HIGH -> FRIEND_TRUST.HIGH;
    };
  }

  /**
   * Maps the SPI-local visibility enum onto the daemon's legacy darknet visibility enum.
   *
   * @param visibility SPI-local visibility value supplied to the runtime port
   * @return equivalent legacy visibility value expected by the daemon
   */
  private static FRIEND_VISIBILITY toLegacyVisibility(PeerVisibility visibility) {
    return switch (visibility) {
      case YES -> FRIEND_VISIBILITY.YES;
      case NAME_ONLY -> FRIEND_VISIBILITY.NAME_ONLY;
      case NO -> FRIEND_VISIBILITY.NO;
    };
  }

  /**
   * Applies the nullable disabled flag using the legacy enable and disable methods.
   *
   * @param peer darknet peer to update
   * @param disabled nullable disabled flag from the detached update DTO
   */
  private static void applyDisableFlag(DarknetPeerNode peer, Boolean disabled) {
    if (disabled == null) {
      return;
    }
    if (disabled) {
      peer.disablePeer();
    } else {
      peer.enablePeer();
    }
  }

  /**
   * Applies one nullable boolean flag through the supplied legacy setter.
   *
   * @param flagValue nullable flag value from the detached update DTO
   * @param setter legacy setter to invoke only when a value is present
   */
  private static void applyBooleanFlag(
      Boolean flagValue, java.util.function.Consumer<Boolean> setter) {
    if (flagValue != null) {
      setter.accept(flagValue);
    }
  }

  /**
   * Applies the nullable routing-enabled flag using the legacy routing-status setter.
   *
   * @param peer darknet peer to update
   * @param routingEnabled nullable routing-enabled flag from the detached update DTO
   */
  private static void applyRoutingFlag(DarknetPeerNode peer, Boolean routingEnabled) {
    if (routingEnabled != null) {
      peer.setRoutingStatus(routingEnabled, true);
    }
  }

  /**
   * Applies the nullable trust update using the legacy darknet trust setter.
   *
   * @param peer darknet peer to update
   * @param trust nullable runtime-spi trust value from the detached update DTO
   */
  private static void applyTrust(DarknetPeerNode peer, PeerTrust trust) {
    if (trust != null) {
      peer.setTrustLevel(toLegacyTrust(trust));
    }
  }

  /**
   * Applies the nullable visibility update using the legacy darknet visibility setter.
   *
   * @param peer darknet peer to update
   * @param visibility nullable runtime-spi visibility value from the detached update DTO
   */
  private static void applyVisibility(DarknetPeerNode peer, PeerVisibility visibility) {
    if (visibility != null) {
      peer.setVisibility(toLegacyVisibility(visibility));
    }
  }

  /**
   * Exports one live peer into a detached snapshot tree with optional subsets attached.
   *
   * @param peer live peer instance supplied by the daemon
   * @param includeMetadata whether exported metadata should be attached under the metadata subset
   * @param includeVolatile whether exported volatile state should be attached under the volatile
   *     subset
   * @return detached snapshot for the supplied peer
   */
  private PeerSnapshot toPeerSnapshot(
      PeerNode peer, boolean includeMetadata, boolean includeVolatile) {
    PeerFieldSet root = toPeerFieldSet(peer.exportFieldSet());
    if (!includeMetadata && !includeVolatile) {
      return new PeerSnapshot(root);
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(root.directValues());
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>(root.directSubsets());
    if (includeMetadata) {
      PeerFieldSet metadata =
          toPeerFieldSet(peer.exportMetadataFieldSet(System.currentTimeMillis()));
      if (!metadata.isEmpty()) {
        directSubsets.put(METADATA_SUBSET, metadata);
      }
    }
    if (includeVolatile) {
      PeerFieldSet volatileFieldSet = toPeerFieldSet(peer.exportVolatileFieldSet());
      if (!volatileFieldSet.isEmpty()) {
        directSubsets.put(VOLATILE_SUBSET, volatileFieldSet);
      }
    }
    return new PeerSnapshot(new PeerFieldSet(directValues, directSubsets));
  }

  /**
   * Converts one legacy {@link SimpleFieldSet} tree into the detached SPI tree representation.
   *
   * @param fieldSet legacy field-set tree exported by the daemon
   * @return detached peer field-set tree with empty child subsets omitted
   */
  private static PeerFieldSet toPeerFieldSet(SimpleFieldSet fieldSet) {
    if (fieldSet.isEmpty()) {
      return PeerFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(fieldSet.directKeyValues());
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : fieldSet.directSubsets().entrySet()) {
      PeerFieldSet subset = toPeerFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new PeerFieldSet(directValues, directSubsets);
  }

  /**
   * Converts one detached SPI peer tree back into a legacy {@link SimpleFieldSet}.
   *
   * @param fieldSet detached peer tree supplied through the runtime SPI
   * @return legacy field-set tree suitable for daemon peer creation
   */
  private static SimpleFieldSet toSimpleFieldSet(PeerFieldSet fieldSet) {
    SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
    for (Map.Entry<String, String> entry : fieldSet.directValues().entrySet()) {
      simpleFieldSet.putSingle(entry.getKey(), entry.getValue());
    }
    for (Map.Entry<String, PeerFieldSet> entry : fieldSet.directSubsets().entrySet()) {
      simpleFieldSet.tput(entry.getKey(), toSimpleFieldSet(entry.getValue()));
    }
    return simpleFieldSet;
  }
}
