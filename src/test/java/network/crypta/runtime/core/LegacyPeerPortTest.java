package network.crypta.runtime.core;

import java.util.List;
import java.util.Map;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.OpennetPeerNode;
import network.crypta.node.PeerNode;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.PeerAddFailureReason;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.RemovedPeerSnapshot;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyPeerPortTest {

  @Mock private Node node;

  @Mock private NodeNetworkSubsystem network;

  @Mock private PeerNode peerOne;

  @Mock private PeerNode peerTwo;

  @Mock private DarknetPeerNode darknetPeer;

  @Mock private OpennetPeerNode opennetPeer;

  @Test
  void list_whenMetadataAndVolatileRequested_mapsPeerSnapshotsInEncounterOrder() {
    LegacyPeerPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {peerOne, peerTwo});
    stubPeerExports(peerOne, "peer-one", "trustLevel", "NORMAL", "CONNECTED");
    stubPeerExports(peerTwo, "peer-two", null, null, "BACKED_OFF");

    List<PeerSnapshot> snapshots = port.list(true, true);

    assertEquals(2, snapshots.size());
    assertEquals("peer-one", snapshots.getFirst().root().directValues().get("identity"));
    assertEquals(
        "NORMAL",
        snapshots
            .getFirst()
            .root()
            .directSubsets()
            .get("metadata")
            .directValues()
            .get("trustLevel"));
    assertEquals(
        "CONNECTED",
        snapshots.getFirst().root().directSubsets().get("volatile").directValues().get("status"));
    assertEquals("peer-two", snapshots.get(1).root().directValues().get("identity"));
    assertNull(snapshots.get(1).root().directSubsets().get("metadata"));
    assertEquals(
        "BACKED_OFF",
        snapshots.get(1).root().directSubsets().get("volatile").directValues().get("status"));
    verify(peerOne).exportMetadataFieldSet(anyLong());
    verify(peerOne).exportVolatileFieldSet();
    verify(peerTwo).exportMetadataFieldSet(anyLong());
    verify(peerTwo).exportVolatileFieldSet();
  }

  @Test
  void list_whenOptionalExportsDisabled_omitsMetadataAndVolatileSubsets() {
    LegacyPeerPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {peerOne});
    stubPeerExports(peerOne, "peer-one", "trustLevel", "NORMAL", "CONNECTED");

    List<PeerSnapshot> snapshots = port.list(false, false);

    assertEquals(1, snapshots.size());
    assertTrue(snapshots.getFirst().root().directSubsets().isEmpty());
    verify(peerOne, never()).exportMetadataFieldSet(anyLong());
    verify(peerOne, never()).exportVolatileFieldSet();
  }

  @Test
  void get_whenPeerExists_returnsRequestedSnapshot() throws UnknownPeerException {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("peer-one")).thenReturn(peerOne);
    stubPeerExports(peerOne, "peer-one", "trustLevel", "NORMAL", "CONNECTED");

    PeerSnapshot snapshot = port.get("peer-one", false, true);

    assertEquals("peer-one", snapshot.root().directValues().get("identity"));
    assertNull(snapshot.root().directSubsets().get("metadata"));
    assertEquals(
        "CONNECTED", snapshot.root().directSubsets().get("volatile").directValues().get("status"));
  }

  @Test
  void add_whenOpennetReferenceAccepted_returnsSnapshot() throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewOpennetNode(any(SimpleFieldSet.class))).thenReturn(opennetPeer);
    when(network.opennetPubKeyHash()).thenReturn(new byte[] {1});
    when(network.addPeerConnection(opennetPeer)).thenReturn(true);
    stubPeerExports(opennetPeer, "opennet-peer", "trustLevel", "NORMAL", "CONNECTED");

    PeerSnapshot snapshot = port.add(opennetReference(), PeerTrust.NORMAL, PeerVisibility.YES);

    ArgumentCaptor<SimpleFieldSet> captor = ArgumentCaptor.forClass(SimpleFieldSet.class);
    verify(network).createNewOpennetNode(captor.capture());
    assertEquals("true", captor.getValue().get("opennet"));
    assertEquals("peer-identity", captor.getValue().get("identity"));
    assertEquals("opennet-peer", snapshot.root().directValues().get("identity"));
  }

  @Test
  void add_whenDarknetReferenceAccepted_mapsTrustAndVisibilityAndReturnsSnapshot()
      throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewDarknetNode(
            any(SimpleFieldSet.class), any(FRIEND_TRUST.class), any(FRIEND_VISIBILITY.class)))
        .thenReturn(darknetPeer);
    when(network.darknetPubKeyHash()).thenReturn(new byte[] {1});
    when(network.addPeerConnection(darknetPeer)).thenReturn(true);
    stubPeerExports(darknetPeer, "darknet-peer", "trustLevel", "HIGH", "CONNECTED");

    PeerSnapshot snapshot = port.add(darknetReference(), PeerTrust.HIGH, PeerVisibility.NAME_ONLY);

    ArgumentCaptor<FRIEND_TRUST> trustCaptor = ArgumentCaptor.forClass(FRIEND_TRUST.class);
    ArgumentCaptor<FRIEND_VISIBILITY> visibilityCaptor =
        ArgumentCaptor.forClass(FRIEND_VISIBILITY.class);
    verify(network)
        .createNewDarknetNode(
            any(SimpleFieldSet.class), trustCaptor.capture(), visibilityCaptor.capture());
    assertEquals(FRIEND_TRUST.HIGH, trustCaptor.getValue());
    assertEquals(FRIEND_VISIBILITY.NAME_ONLY, visibilityCaptor.getValue());
    assertEquals("darknet-peer", snapshot.root().directValues().get("identity"));
  }

  @Test
  void add_whenLegacyParseFails_mapsToRefParseError() throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewOpennetNode(any(SimpleFieldSet.class)))
        .thenThrow(new FSParseException("bad-ref"));

    PeerAddRejectedException exception =
        assertThrows(
            PeerAddRejectedException.class,
            () -> port.add(opennetReference(), PeerTrust.NORMAL, PeerVisibility.YES));

    assertEquals(PeerAddFailureReason.REF_PARSE_ERROR, exception.reason());
    assertEquals("Error parsing ref: bad-ref", exception.getMessage());
  }

  @Test
  void add_whenOpennetDisabled_mapsToOpennetDisabled() throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewOpennetNode(any(SimpleFieldSet.class)))
        .thenThrow(new OpennetDisabledException("disabled"));

    PeerAddRejectedException exception =
        assertThrows(
            PeerAddRejectedException.class,
            () -> port.add(opennetReference(), PeerTrust.NORMAL, PeerVisibility.YES));

    assertEquals(PeerAddFailureReason.OPENNET_DISABLED, exception.reason());
    assertEquals("Error adding ref: disabled", exception.getMessage());
  }

  @Test
  void add_whenSignatureVerificationFails_mapsToSignatureInvalid() throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewDarknetNode(
            any(SimpleFieldSet.class), any(FRIEND_TRUST.class), any(FRIEND_VISIBILITY.class)))
        .thenThrow(new ReferenceSignatureVerificationException("bad-sig"));

    PeerAddRejectedException exception =
        assertThrows(
            PeerAddRejectedException.class,
            () -> port.add(darknetReference(), PeerTrust.NORMAL, PeerVisibility.YES));

    assertEquals(PeerAddFailureReason.REF_SIGNATURE_INVALID, exception.reason());
    assertEquals("Error adding ref: bad-sig", exception.getMessage());
  }

  @Test
  void add_whenReferenceTargetsSelf_mapsToCannotPeerWithSelf() throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewOpennetNode(any(SimpleFieldSet.class))).thenReturn(opennetPeer);
    when(network.opennetPubKeyHash()).thenReturn(null);

    PeerAddRejectedException exception =
        assertThrows(
            PeerAddRejectedException.class,
            () -> port.add(opennetReference(), PeerTrust.NORMAL, PeerVisibility.YES));

    assertEquals(PeerAddFailureReason.CANNOT_PEER_WITH_SELF, exception.reason());
    assertEquals("Node cannot peer with itself", exception.getMessage());
  }

  @Test
  void add_whenPeerAlreadyExists_mapsToDuplicatePeerRef() throws Exception {
    LegacyPeerPort port = newPort();
    when(network.createNewDarknetNode(
            any(SimpleFieldSet.class), any(FRIEND_TRUST.class), any(FRIEND_VISIBILITY.class)))
        .thenReturn(darknetPeer);
    when(network.darknetPubKeyHash()).thenReturn(new byte[] {1});
    when(network.addPeerConnection(darknetPeer)).thenReturn(false);

    PeerAddRejectedException exception =
        assertThrows(
            PeerAddRejectedException.class,
            () -> port.add(darknetReference(), PeerTrust.NORMAL, PeerVisibility.YES));

    assertEquals(PeerAddFailureReason.DUPLICATE_PEER_REF, exception.reason());
    assertEquals("Node already has a peer with that identity", exception.getMessage());
  }

  @Test
  void
      updateDarknetPeer_whenFlagsTrustAndVisibilityPresent_appliesRequestedMutationsAndReturnsSnapshot()
          throws Exception {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("peer-123")).thenReturn(darknetPeer);
    stubPeerExports(darknetPeer, "peer-123", "trustLevel", "NORMAL", "CONNECTED");

    PeerSnapshot snapshot =
        port.updateDarknetPeer(
            "peer-123",
            new DarknetPeerSettingsUpdate(
                Boolean.TRUE,
                Boolean.FALSE,
                Boolean.TRUE,
                Boolean.FALSE,
                Boolean.TRUE,
                Boolean.TRUE,
                PeerTrust.HIGH,
                PeerVisibility.NO));

    verify(darknetPeer).disablePeer();
    verify(darknetPeer).setListenOnly(false);
    verify(darknetPeer).setBurstOnly(true);
    verify(darknetPeer).setIgnoreSourcePort(false);
    verify(darknetPeer).setAllowLocalAddresses(true);
    verify(darknetPeer).setRoutingStatus(true, true);
    verify(darknetPeer).setTrustLevel(FRIEND_TRUST.HIGH);
    verify(darknetPeer).setVisibility(FRIEND_VISIBILITY.NO);
    assertEquals("peer-123", snapshot.root().directValues().get("identity"));
  }

  @Test
  void updateDarknetPeer_whenIdentifierUsesIdentityPrefix_usesLegacyLookupSemantics()
      throws Exception {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("identity:peer-123")).thenReturn(darknetPeer);
    stubPeerExports(darknetPeer, "peer-123", "trustLevel", "NORMAL", "CONNECTED");

    port.updateDarknetPeer(
        "identity:peer-123",
        new DarknetPeerSettingsUpdate(
            Boolean.TRUE, null, null, null, null, null, null, PeerVisibility.NAME_ONLY));

    verify(network).getPeerNode("identity:peer-123");
    verify(darknetPeer).disablePeer();
    verify(darknetPeer).setVisibility(FRIEND_VISIBILITY.NAME_ONLY);
  }

  @Test
  void updateDarknetPeerByIdentity_whenIdentityMatchesPeer_resolvesByIdentityOnly()
      throws Exception {
    LegacyPeerPort port = newPort();
    DarknetPeerNode collidingNamePeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    when(network.peerNodes()).thenReturn(new PeerNode[] {collidingNamePeer, darknetPeer});
    when(collidingNamePeer.getIdentityString()).thenReturn("other-peer");
    when(darknetPeer.getIdentityString()).thenReturn("peer-123");
    stubPeerExports(darknetPeer, "peer-123", "trustLevel", "NORMAL", "CONNECTED");

    port.updateDarknetPeerByIdentity(
        "peer-123",
        new DarknetPeerSettingsUpdate(
            Boolean.TRUE, null, null, null, null, null, null, PeerVisibility.NAME_ONLY));

    verify(darknetPeer).disablePeer();
    verify(darknetPeer).setVisibility(FRIEND_VISIBILITY.NAME_ONLY);
    verify(collidingNamePeer, never()).disablePeer();
    verify(network, never()).getPeerNode(any());
  }

  @Test
  void updateDarknetPeerByIdentity_whenPeerMissing_throwsUnknownPeerException() {
    LegacyPeerPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {peerOne});
    when(peerOne.getIdentityString()).thenReturn("other-peer");

    assertThrows(
        UnknownPeerException.class,
        () ->
            port.updateDarknetPeerByIdentity(
                "peer-123",
                new DarknetPeerSettingsUpdate(
                    Boolean.TRUE, null, null, null, null, null, null, null)));
  }

  @Test
  void remove_whenPeerExists_removesAndReturnsDetachedResult() throws UnknownPeerException {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("peer-123")).thenReturn(peerOne);
    when(peerOne.getIdentityString()).thenReturn("identity-xyz");

    RemovedPeerSnapshot removedPeer = port.remove("peer-123");

    assertEquals("identity-xyz", removedPeer.identity());
    assertEquals("peer-123", removedPeer.nodeIdentifier());
    verify(network).removePeerConnection(peerOne);
  }

  @Test
  void removeByIdentity_whenIdentityMatchesPeer_resolvesByIdentityOnly()
      throws UnknownPeerException {
    LegacyPeerPort port = newPort();
    DarknetPeerNode collidingNamePeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    when(network.peerNodes()).thenReturn(new PeerNode[] {collidingNamePeer, peerOne});
    when(collidingNamePeer.getIdentityString()).thenReturn("other-peer");
    when(peerOne.getIdentityString()).thenReturn("peer-123");

    RemovedPeerSnapshot removedPeer = port.removeByIdentity("peer-123");

    assertEquals("peer-123", removedPeer.identity());
    assertEquals("peer-123", removedPeer.nodeIdentifier());
    verify(network).removePeerConnection(peerOne);
    verify(network, never()).getPeerNode(any());
  }

  @Test
  void removeByIdentity_whenPeerMissing_throwsUnknownPeerException() {
    LegacyPeerPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {peerOne});
    when(peerOne.getIdentityString()).thenReturn("other-peer");

    assertThrows(UnknownPeerException.class, () -> port.removeByIdentity("peer-123"));
  }

  @Test
  void remove_whenPeerMissing_throwsUnknownPeerException() {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("missing-peer")).thenReturn(null);

    assertThrows(UnknownPeerException.class, () -> port.remove("missing-peer"));
  }

  @Test
  void readPrivateDarknetComment_whenPeerExists_returnsStoredNote()
      throws UnknownPeerException, DarknetPeerRequiredException {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("peer-123")).thenReturn(darknetPeer);
    when(darknetPeer.getPrivateDarknetCommentNote()).thenReturn("stored-note");

    assertEquals("stored-note", port.readPrivateDarknetComment("peer-123"));
  }

  @Test
  void writePrivateDarknetComment_whenPeerExists_storesAndReturnsUpdatedNote()
      throws UnknownPeerException, DarknetPeerRequiredException {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("peer-123")).thenReturn(darknetPeer);
    when(darknetPeer.getPrivateDarknetCommentNote()).thenReturn("stored-note");

    String storedNote = port.writePrivateDarknetComment("peer-123", "updated-note");

    verify(darknetPeer).setPrivateDarknetCommentNote("updated-note");
    assertEquals("stored-note", storedNote);
  }

  @Test
  void writePrivateDarknetCommentByIdentity_whenIdentityMatchesPeer_resolvesByIdentityOnly()
      throws UnknownPeerException, DarknetPeerRequiredException {
    LegacyPeerPort port = newPort();
    DarknetPeerNode collidingNamePeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    when(network.peerNodes()).thenReturn(new PeerNode[] {collidingNamePeer, darknetPeer});
    when(collidingNamePeer.getIdentityString()).thenReturn("other-peer");
    when(darknetPeer.getIdentityString()).thenReturn("peer-123");
    when(darknetPeer.getPrivateDarknetCommentNote()).thenReturn("stored-note");

    String storedNote = port.writePrivateDarknetCommentByIdentity("peer-123", "updated-note");

    verify(darknetPeer).setPrivateDarknetCommentNote("updated-note");
    verify(collidingNamePeer, never()).setPrivateDarknetCommentNote(any());
    verify(network, never()).getPeerNode(any());
    assertEquals("stored-note", storedNote);
  }

  @Test
  void readPrivateDarknetComment_whenPeerMissing_throwsUnknownPeerException() {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("missing-peer")).thenReturn(null);

    assertThrows(UnknownPeerException.class, () -> port.readPrivateDarknetComment("missing-peer"));
  }

  @Test
  void writePrivateDarknetComment_whenPeerIsNotDarknet_throwsDarknetPeerRequiredException() {
    LegacyPeerPort port = newPort();
    when(network.getPeerNode("peer-123")).thenReturn(peerOne);

    assertThrows(
        DarknetPeerRequiredException.class,
        () -> port.writePrivateDarknetComment("peer-123", "updated-note"));
  }

  private LegacyPeerPort newPort() {
    when(node.network()).thenReturn(network);
    return new LegacyPeerPort(node);
  }

  private void stubPeerExports(
      PeerNode peer,
      String identity,
      String metadataKey,
      String metadataValue,
      String volatileValue) {
    when(peer.exportFieldSet()).thenReturn(fieldSet("identity", identity));
    lenient()
        .when(peer.exportMetadataFieldSet(anyLong()))
        .thenReturn(
            metadataKey == null ? new SimpleFieldSet(true) : fieldSet(metadataKey, metadataValue));
    lenient()
        .when(peer.exportVolatileFieldSet())
        .thenReturn(
            volatileValue == null ? new SimpleFieldSet(true) : fieldSet("status", volatileValue));
  }

  private static PeerFieldSet opennetReference() {
    return new PeerFieldSet(Map.of("opennet", "true", "identity", "peer-identity"), Map.of());
  }

  private static PeerFieldSet darknetReference() {
    return new PeerFieldSet(Map.of("identity", "peer-identity"), Map.of());
  }

  private static SimpleFieldSet fieldSet(String key, String value) {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle(key, value);
    return fieldSet;
  }
}
