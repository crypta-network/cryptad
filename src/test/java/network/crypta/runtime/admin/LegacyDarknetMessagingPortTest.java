package network.crypta.runtime.admin;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.spi.DarknetMessageSendStatus;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetUploadedFile;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.io.BucketTools;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyDarknetMessagingPortTest {

  @Mock private Node node;

  @Mock private NodeNetworkSubsystem network;

  @Mock private DarknetPeerNode darknetPeer;

  @Mock private PeerNode nonDarknetPeer;

  @Test
  void sendText_whenLegacyStatusConnected_returnsSent() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");
    when(darknetPeer.sendTextFeed("hello")).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);

    DarknetMessageSendStatus result = port.sendText("peer-1", "hello");

    assertEquals(DarknetMessageSendStatus.SENT, result);
  }

  @Test
  void sendText_whenLegacyStatusRoutingBackedOff_returnsDelayed() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");
    when(darknetPeer.sendTextFeed("hello"))
        .thenReturn(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);

    DarknetMessageSendStatus result = port.sendText("peer-1", "hello");

    assertEquals(DarknetMessageSendStatus.DELAYED, result);
  }

  @Test
  void sendText_whenLegacyStatusIsOther_returnsQueued() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");
    when(darknetPeer.sendTextFeed("hello")).thenReturn(PeerManager.PEER_NODE_STATUS_DISCONNECTED);

    DarknetMessageSendStatus result = port.sendText("peer-1", "hello");

    assertEquals(DarknetMessageSendStatus.QUEUED, result);
  }

  @Test
  void sendFileOffer_whenIdentityResolves_delegatesToPeer() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    File file = new File("shared/path/example.txt");
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");

    port.sendFileOffer("peer-1", file, "message-head");

    verify(darknetPeer).sendFileOffer(file, "message-head");
  }

  @Test
  void sendUploadedFileOffer_whenIdentityResolves_adaptsDetachedUpload() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8);
    DarknetUploadedFile upload =
        new DarknetUploadedFile(
            "hello.txt", "text/plain", bytes.length, () -> new ByteArrayInputStream(bytes));
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");
    ArgumentCaptor<HTTPUploadedFile> uploadCaptor = ArgumentCaptor.forClass(HTTPUploadedFile.class);

    port.sendUploadedFileOffer("peer-1", upload, "message-head");

    verify(darknetPeer).sendFileOffer(uploadCaptor.capture(), eq("message-head"));
    HTTPUploadedFile delegatedUpload = uploadCaptor.getValue();
    assertEquals("hello.txt", delegatedUpload.getFilename());
    assertEquals("text/plain", delegatedUpload.getContentType());
    assertArrayEquals(bytes, BucketTools.toByteArray(delegatedUpload.getData()));
  }

  @Test
  void recommendDownloads_whenIdentityResolves_sendsEveryUriInOrderWithDescription()
      throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    FreenetURI firstUri = new FreenetURI("CHK@");
    FreenetURI secondUri = new FreenetURI("SSK@");
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");

    port.recommendDownloads("peer-1", List.of("CHK@", "SSK@"), "check these out");

    InOrder sendOrder = inOrder(darknetPeer);
    sendOrder.verify(darknetPeer).sendDownloadFeed(firstUri, "check these out");
    sendOrder.verify(darknetPeer).sendDownloadFeed(secondUri, "check these out");
    verify(darknetPeer, never()).sendDownloadFeed(any(FreenetURI.class), eq(null));
  }

  @Test
  void recommendDownloads_whenDescriptionIsNull_preservesNullDescription() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");
    ArgumentCaptor<String> descriptionCaptor = ArgumentCaptor.forClass(String.class);

    port.recommendDownloads("peer-1", List.of("CHK@"), null);

    verify(darknetPeer).sendDownloadFeed(any(FreenetURI.class), descriptionCaptor.capture());
    assertNull(descriptionCaptor.getValue());
  }

  @Test
  void shareBookmark_whenIdentityResolves_delegatesToLegacyBookmarkFeed() throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");

    port.shareBookmark("peer-1", "KSK@bookmark", "bookmark-name", "public description", true);

    verify(darknetPeer)
        .sendBookmarkFeed(
            new FreenetURI("KSK@bookmark"), "bookmark-name", "public description", true);
  }

  @Test
  void shareBookmark_whenPeerIdentityIsUnknown_throwsUnknownPeerException() {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[0]);

    assertThrows(
        UnknownPeerException.class,
        () -> port.shareBookmark("missing-peer", "KSK@bookmark", "bookmark-name", null, false));
  }

  @Test
  void shareBookmark_whenResolvedPeerIsNotDarknet_throwsDarknetPeerRequiredException() {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {nonDarknetPeer});
    when(nonDarknetPeer.getIdentityString()).thenReturn("peer-1");

    assertThrows(
        DarknetPeerRequiredException.class,
        () -> port.shareBookmark("peer-1", "KSK@bookmark", "bookmark-name", null, false));
  }

  @Test
  void sendComposedMessage_whenLocalFilePresent_usesOnePeerResolutionForOfferAndText()
      throws Exception {
    LegacyDarknetMessagingPort port = newPort();
    File file = new File("shared/path/example.txt");
    when(network.peerNodes()).thenReturn(new PeerNode[] {darknetPeer});
    when(darknetPeer.getIdentityString()).thenReturn("peer-1");
    when(darknetPeer.sendTextFeed("hello")).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);

    DarknetMessageSendStatus result =
        port.sendComposedMessage("peer-1", "hello", file, null, "message-head");

    assertEquals(DarknetMessageSendStatus.SENT, result);
    InOrder sendOrder = inOrder(darknetPeer);
    sendOrder.verify(darknetPeer).sendFileOffer(file, "message-head");
    sendOrder.verify(darknetPeer).sendTextFeed("hello");
  }

  @Test
  void recommendDownloads_whenPeerIdentityIsUnknown_throwsUnknownPeerException() {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[0]);

    assertThrows(
        UnknownPeerException.class,
        () -> port.recommendDownloads("missing-peer", List.of("CHK@"), "hello"));
  }

  @Test
  void recommendDownloads_whenResolvedPeerIsNotDarknet_throwsDarknetPeerRequiredException() {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {nonDarknetPeer});
    when(nonDarknetPeer.getIdentityString()).thenReturn("peer-1");

    assertThrows(
        DarknetPeerRequiredException.class,
        () -> port.recommendDownloads("peer-1", List.of("CHK@"), "hello"));
  }

  @Test
  void sendText_whenPeerIdentityIsUnknown_throwsUnknownPeerException() {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[0]);

    assertThrows(UnknownPeerException.class, () -> port.sendText("missing-peer", "hello"));
  }

  @Test
  void sendText_whenResolvedPeerIsNotDarknet_throwsDarknetPeerRequiredException() {
    LegacyDarknetMessagingPort port = newPort();
    when(network.peerNodes()).thenReturn(new PeerNode[] {nonDarknetPeer});
    when(nonDarknetPeer.getIdentityString()).thenReturn("peer-1");

    assertThrows(DarknetPeerRequiredException.class, () -> port.sendText("peer-1", "hello"));
  }

  private LegacyDarknetMessagingPort newPort() {
    when(node.network()).thenReturn(network);
    return new LegacyDarknetMessagingPort(node);
  }
}
