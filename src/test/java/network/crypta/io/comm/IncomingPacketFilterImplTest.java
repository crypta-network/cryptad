package network.crypta.io.comm;

import java.net.InetAddress;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.IncomingPacketFilter.DECODED;
import network.crypta.node.FNPPacketMangler;
import network.crypta.node.Node;
import network.crypta.node.NodeCrypto;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerRoster;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class IncomingPacketFilterImplTest {

  @Mock private FNPPacketMangler mangler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeCrypto crypto;
  @Mock private PeerManager peerManager;
  @Mock private PeerRoster roster;
  @Mock private RandomSource randomSource;

  private IncomingPacketFilterImpl filter;

  private byte[] buf;
  private Peer peer;
  private long now;

  @BeforeEach
  void setUp() {
    // Common buffer and time
    buf = new byte[64];
    now = 123_456_789L;
    peer = new Peer(InetAddress.getLoopbackAddress(), 4242);

    filter = new IncomingPacketFilterImpl(mangler, node, crypto);
  }

  // --- isDisconnected() ----------------------------------------------------

  @Test
  void isDisconnected_nullContext_returnsFalse() {
    assertFalse(filter.isDisconnected(null));
  }

  @Test
  void isDisconnected_whenConnected_returnsFalse() {
    PeerContext ctx = Mockito.mock(PeerContext.class);
    when(ctx.isConnected()).thenReturn(true);
    assertFalse(filter.isDisconnected(ctx));
  }

  @Test
  void isDisconnected_whenNotConnected_returnsTrue() {
    PeerContext ctx = Mockito.mock(PeerContext.class);
    when(ctx.isConnected()).thenReturn(false);
    assertTrue(filter.isDisconnected(ctx));
  }

  // --- process() happy paths -----------------------------------------------

  @Test
  void process_whenOpnHandlesPacket_returnsDecoded_andSkipsMangler() {
    // Node wiring used by the filter
    when(node.bootstrap().random()).thenReturn(randomSource);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.roster()).thenReturn(roster);
    PeerNode opn = Mockito.mock(PeerNode.class);
    when(roster.getByPeer(peer, mangler)).thenReturn(opn);
    when(opn.handleReceivedPacket(buf, 0, buf.length, now, peer)).thenReturn(true);

    DECODED result = filter.process(buf, 0, buf.length, peer, now);

    assertSame(DECODED.SUCCESS, result);
    // Should gather timer entropy with the expected bias
    verify(randomSource, times(1)).acceptTimerEntropy(any(), eq(0.25d));
    // Mangler should not be invoked if the owning PeerNode handled the packet
    verify(mangler, never()).process(any(), anyInt(), anyInt(), eq(peer), eq(opn));
  }

  @Test
  void process_whenUnknownAddress_callsManglerWithNullPeerNode_andReturnsManglerResult() {
    when(node.bootstrap().random()).thenReturn(randomSource);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.roster()).thenReturn(roster);
    when(roster.getByPeer(peer, mangler)).thenReturn(null);
    when(mangler.process(buf, 0, buf.length, peer, null)).thenReturn(DECODED.SUCCESS);

    DECODED result = filter.process(buf, 0, buf.length, peer, now);

    assertSame(DECODED.SUCCESS, result);
    verify(randomSource, times(1)).acceptTimerEntropy(any(), eq(0.25d));
    verify(mangler, times(1)).process(buf, 0, buf.length, peer, null);
  }

  // --- process() fallback paths --------------------------------------------

  @Test
  void process_whenManglerNotDecoded_thenFallbackPeersHandle_returnsDecoded() {
    when(node.bootstrap().random()).thenReturn(randomSource);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.roster()).thenReturn(roster);
    when(roster.getByPeer(peer, mangler)).thenReturn(null);
    when(mangler.process(buf, 0, buf.length, peer, null)).thenReturn(DECODED.NOT_DECODED);

    PeerNode pn1 = Mockito.mock(PeerNode.class);
    PeerNode pn2 = Mockito.mock(PeerNode.class);
    when(crypto.getPeerNodes()).thenReturn(new PeerNode[] {pn1, pn2});

    when(pn1.handleReceivedPacket(buf, 0, buf.length, now, peer)).thenReturn(false);
    when(pn2.handleReceivedPacket(buf, 0, buf.length, now, peer)).thenReturn(true);

    DECODED result = filter.process(buf, 0, buf.length, peer, now);

    assertSame(DECODED.SUCCESS, result);
    verify(pn1, times(1)).handleReceivedPacket(buf, 0, buf.length, now, peer);
    verify(pn2, times(1)).handleReceivedPacket(buf, 0, buf.length, now, peer);
  }

  @Test
  void process_whenManglerNotDecoded_andNoPeerHandles_returnsNotDecoded() {
    when(node.bootstrap().random()).thenReturn(randomSource);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.roster()).thenReturn(roster);
    when(roster.getByPeer(peer, mangler)).thenReturn(null);
    when(mangler.process(buf, 0, buf.length, peer, null)).thenReturn(DECODED.NOT_DECODED);

    PeerNode pn1 = Mockito.mock(PeerNode.class);
    PeerNode pn2 = Mockito.mock(PeerNode.class);
    when(crypto.getPeerNodes()).thenReturn(new PeerNode[] {pn1, pn2});

    when(pn1.handleReceivedPacket(buf, 0, buf.length, now, peer)).thenReturn(false);
    when(pn2.handleReceivedPacket(buf, 0, buf.length, now, peer)).thenReturn(false);

    DECODED result = filter.process(buf, 0, buf.length, peer, now);

    assertSame(DECODED.NOT_DECODED, result);
    verify(pn1, times(1)).handleReceivedPacket(buf, 0, buf.length, now, peer);
    verify(pn2, times(1)).handleReceivedPacket(buf, 0, buf.length, now, peer);
  }

  @Test
  void process_whenManglerReturnsShuttingDown_returnsShuttingDown_withoutFallback() {
    when(node.bootstrap().random()).thenReturn(randomSource);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.roster()).thenReturn(roster);
    when(roster.getByPeer(peer, mangler)).thenReturn(null);
    when(mangler.process(buf, 0, buf.length, peer, null)).thenReturn(DECODED.SHUTTING_DOWN);

    DECODED result = filter.process(buf, 0, buf.length, peer, now);

    assertSame(DECODED.SHUTTING_DOWN, result);
    // Fallback peers should not be queried on non-NOT_DECODED results
    verifyNoInteractions(crypto);
  }
}
