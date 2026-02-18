package network.crypta.node;

import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DarknetPeerNodeStatusTest {

  // Creates a minimally‑stubbed peer suitable for constructing PeerNodeStatus deterministically.
  private DarknetPeerNode basePeerMock() {
    DarknetPeerNode peer = mock(DarknetPeerNode.class);

    // Keep address and port null/-1 to make toString deterministic.
    when(peer.getPeer()).thenReturn(null);

    // Fields used by PeerNodeStatus#toString(); keep values stable.
    when(peer.getPeerNodeStatusString()).thenReturn("CONNECTED");
    when(peer.getLocation()).thenReturn(0.0);
    when(peer.getVersion()).thenReturn("1");
    when(peer.getRoutingBackoffLength(true)).thenReturn(0L);
    when(peer.getRoutingBackoffLength(false)).thenReturn(0L);
    when(peer.getRoutingBackedOffUntil(true)).thenReturn(0L);
    when(peer.getRoutingBackedOffUntil(false)).thenReturn(0L);
    when(peer.getBackedOffPercentRT()).thenReturn(0.0);
    when(peer.getBackedOffPercentBulk()).thenReturn(0.0);

    // Defaults for other primitive reads invoked by the constructor.
    when(peer.isConnected()).thenReturn(false);
    when(peer.isRoutable()).thenReturn(false);
    when(peer.isFetchingARK()).thenReturn(false);
    when(peer.isOpennet()).thenReturn(false);
    when(peer.averagePingTime()).thenReturn(0.0);
    when(peer.averagePingTimeCorrected()).thenReturn(0.0);
    when(peer.publicInvalidVersion()).thenReturn(false);
    when(peer.publicReverseInvalidVersion()).thenReturn(false);
    when(peer.timeLastRoutable()).thenReturn(0L);
    when(peer.timeLastConnectionCompleted()).thenReturn(0L);
    when(peer.getPeerAddedTime()).thenReturn(0L);
    when(peer.getPRejected()).thenReturn(0.0);
    when(peer.getTotalInputBytes()).thenReturn(0L);
    when(peer.getTotalOutputBytes()).thenReturn(0L);
    when(peer.getTotalInputSinceStartup()).thenReturn(0L);
    when(peer.getTotalOutputSinceStartup()).thenReturn(0L);
    when(peer.getPercentTimeRoutableConnection()).thenReturn(0.0);
    PeerTransport transport = mock(PeerTransport.class);
    when(transport.getThrottle()).thenReturn(null);
    when(peer.transport()).thenReturn(transport);
    when(peer.getClockDelta()).thenReturn(0L);
    when(peer.recordStatus()).thenReturn(false);
    when(peer.isRealConnection()).thenReturn(false);
    when(peer.getResendBytesSent()).thenReturn(0L);
    when(peer.getUptime()).thenReturn((short) 0);
    when(peer.getMessageQueueLengthBytes()).thenReturn(0L);
    when(peer.getProbableSendQueueTime()).thenReturn(0L);
    when(peer.getIncomingLoadStats(true)).thenReturn(null);
    when(peer.getIncomingLoadStats(false)).thenReturn(null);
    when(peer.hasFullNoderef()).thenReturn(false);

    return peer;
  }

  @Test
  void constructor_copiesBasicFields_expectValues() {
    DarknetPeerNode peer = basePeerMock();
    when(peer.getName()).thenReturn("Alice");
    when(peer.isBurstOnly()).thenReturn(true);
    when(peer.isListenOnly()).thenReturn(true);
    when(peer.isDisabled()).thenReturn(false);
    when(peer.getPrivateDarknetCommentNote()).thenReturn("note-1");
    when(peer.getTrustLevel()).thenReturn(FRIEND_TRUST.HIGH);
    when(peer.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.NAME_ONLY);
    when(peer.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);

    DarknetPeerNodeStatus status = new DarknetPeerNodeStatus(peer, true);

    assertEquals("Alice", status.getName());
    assertTrue(status.isBurstOnly());
    assertTrue(status.isListening());
    assertFalse(status.isDisabled());
    assertEquals("note-1", status.getPrivateDarknetCommentNote());
    assertSame(FRIEND_TRUST.HIGH, status.getTrustLevel());
    assertSame(FRIEND_VISIBILITY.NAME_ONLY, status.getOurVisibility());
    assertSame(FRIEND_VISIBILITY.YES, status.getTheirVisibility());
    // NAME_ONLY is stricter than YES → overall NAME_ONLY
    assertSame(FRIEND_VISIBILITY.NAME_ONLY, status.getOverallVisibility());
  }

  @Test
  void getOverallVisibility_whenTheirMoreStrict_expectTheir() {
    DarknetPeerNode peer = basePeerMock();
    when(peer.getName()).thenReturn("Carol");
    when(peer.isBurstOnly()).thenReturn(false);
    when(peer.isListenOnly()).thenReturn(false);
    when(peer.isDisabled()).thenReturn(false);
    when(peer.getPrivateDarknetCommentNote()).thenReturn("");
    when(peer.getTrustLevel()).thenReturn(FRIEND_TRUST.NORMAL);
    when(peer.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(peer.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.NO);

    DarknetPeerNodeStatus status = new DarknetPeerNodeStatus(peer, true);

    assertSame(FRIEND_VISIBILITY.NO, status.getOverallVisibility());
    assertSame(FRIEND_VISIBILITY.NO, status.getTheirVisibility());
    assertSame(FRIEND_VISIBILITY.YES, status.getOurVisibility());
  }

  @Test
  void getTheirVisibility_whenNullStored_expectNOAndOverallFromOur() {
    DarknetPeerNode peer = basePeerMock();
    when(peer.getName()).thenReturn("Dave");
    when(peer.isBurstOnly()).thenReturn(false);
    when(peer.isListenOnly()).thenReturn(false);
    when(peer.isDisabled()).thenReturn(true);
    when(peer.getPrivateDarknetCommentNote()).thenReturn("pvt");
    when(peer.getTrustLevel()).thenReturn(FRIEND_TRUST.LOW);
    when(peer.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    // Simulate a legacy/mock path where their visibility is unknown (null)
    when(peer.getTheirVisibility()).thenReturn(null);

    DarknetPeerNodeStatus status = new DarknetPeerNodeStatus(peer, true);

    // Getter maps null to NO.
    assertSame(FRIEND_VISIBILITY.NO, status.getTheirVisibility());
    // During construction, overall = stricter(our=YES, their=null) → our
    assertSame(FRIEND_VISIBILITY.YES, status.getOverallVisibility());
    assertTrue(status.isDisabled());
  }

  @Test
  void toString_includesNameAndParentFields_deterministic() {
    DarknetPeerNode peer = basePeerMock();
    when(peer.getName()).thenReturn("Bob");
    when(peer.isBurstOnly()).thenReturn(false);
    when(peer.isListenOnly()).thenReturn(false);
    when(peer.isDisabled()).thenReturn(false);
    when(peer.getPrivateDarknetCommentNote()).thenReturn("");
    when(peer.getTrustLevel()).thenReturn(FRIEND_TRUST.NORMAL);
    when(peer.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(peer.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);

    DarknetPeerNodeStatus status = new DarknetPeerNodeStatus(peer, true);

    String expected = "Bob " + "CONNECTED null:-1 0.0 1 RT backoff: 0 (0 ) bulk backoff: 0 (0)";

    String actual = status.toString();
    assertNotNull(actual);
    assertEquals(expected, actual);
  }

  @Test
  void equals_whenSamePubKeyHash_expectEqual() {
    byte[] pkh = new byte[] {1, 2, 3};

    DarknetPeerNode p1 = basePeerMock();
    when(p1.getName()).thenReturn("P1");
    when(p1.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(p1.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(p1.getTrustLevel()).thenReturn(FRIEND_TRUST.NORMAL);
    when(p1.getPrivateDarknetCommentNote()).thenReturn("");
    when(p1.getPubKeyHash()).thenReturn(pkh);

    DarknetPeerNode p2 = basePeerMock();
    when(p2.getName()).thenReturn("P2");
    when(p2.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.NO);
    when(p2.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.NO);
    when(p2.getTrustLevel()).thenReturn(FRIEND_TRUST.HIGH);
    when(p2.getPrivateDarknetCommentNote()).thenReturn("x");
    when(p2.getPubKeyHash()).thenReturn(pkh.clone());

    DarknetPeerNodeStatus s1 = new DarknetPeerNodeStatus(p1, true);
    DarknetPeerNodeStatus s2 = new DarknetPeerNodeStatus(p2, true);

    assertEquals(s1, s2);
    assertEquals(s2, s1);
  }

  @Test
  void equals_whenDifferentPubKeyHash_expectNotEqual() {
    DarknetPeerNode p1 = basePeerMock();
    when(p1.getName()).thenReturn("X");
    when(p1.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(p1.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(p1.getTrustLevel()).thenReturn(FRIEND_TRUST.NORMAL);
    when(p1.getPrivateDarknetCommentNote()).thenReturn("");
    when(p1.getPubKeyHash()).thenReturn(new byte[] {9, 9, 9});

    DarknetPeerNode p2 = basePeerMock();
    when(p2.getName()).thenReturn("Y");
    when(p2.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(p2.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(p2.getTrustLevel()).thenReturn(FRIEND_TRUST.NORMAL);
    when(p2.getPrivateDarknetCommentNote()).thenReturn("");
    when(p2.getPubKeyHash()).thenReturn(new byte[] {8, 8, 8});

    DarknetPeerNodeStatus s1 = new DarknetPeerNodeStatus(p1, true);
    DarknetPeerNodeStatus s2 = new DarknetPeerNodeStatus(p2, true);

    assertNotEquals(s1, s2);
    assertNotEquals(s2, s1);
  }
}
