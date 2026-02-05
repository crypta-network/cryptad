package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RequestTagTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private RequestTracker tracker;

  private static final long UID = 1234L;

  @BeforeEach
  void setup() {
    when(node.routing().tracker()).thenReturn(tracker);
  }

  private static RequestTag newLocalTag(Node node) {
    return new RequestTag(
        /* isSSK= */ false, RequestTag.START.LOCAL, /* source= */ null, /* rt= */ true, UID, node);
  }

  private static RequestTag newRemoteTag(Node node, PeerNode source) {
    return new RequestTag(
        /* isSSK= */ true,
        RequestTag.START.REMOTE,
        /* source= */ source,
        /* rt= */ false,
        UID,
        node);
  }

  @Test
  void setRequestSenderFinished_whenNotFinished_throws() {
    RequestTag tag = newLocalTag(node);
    assertThrows(
        IllegalArgumentException.class,
        () -> tag.setRequestSenderFinished(RequestSender.NOT_FINISHED));
  }

  @Test
  void unlockHandler_whenCoalescedSender_allowsUnlock() {
    RequestTag tag = newLocalTag(node);

    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);
    // Coalesced: we won't wait for sender completion (the "sent" flag remains false)
    tag.setSender(rs, /* coalesced= */ true);

    // Expect innerUnlock to delegate to tracker.unlockUID exactly once
    doNothing()
        .when(tracker)
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    tag.unlockHandler();

    verify(tracker, times(1)).unlockUID(tag, false, false);
  }

  @Test
  void setRequestSenderFinished_afterUnlockHandlerPreviouslyBlockedByPendingSender_unlocksUID() {
    RequestTag tag = newLocalTag(node);
    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);

    // Non-coalesced: mark as sent so mustUnlock() blocks until sender finishes
    tag.setSender(rs, /* coalesced= */ false);

    tag.unlockHandler(); // should be deferred due to a pending sender

    verify(tracker, never())
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    doNothing()
        .when(tracker)
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    // Now mark sender finished with a valid terminal status
    tag.setRequestSenderFinished(RequestSender.SUCCESS);

    verify(tracker, times(1)).unlockUID(tag, false, false);
  }

  @Test
  void expectedTransfersIn_whenAcceptanceVaries_behavesAsSpecified() {
    PeerNode source = org.mockito.Mockito.mock(PeerNode.class);
    RequestTag tag = newRemoteTag(node, source);

    // Not accepted yet
    assertEquals(0, tag.expectedTransfersIn(false, 0, false));

    tag.setAccepted();
    assertEquals(1, tag.expectedTransfersIn(false, 0, false));

    tag.setNotRoutedOnwards();
    assertEquals(0, tag.expectedTransfersIn(false, 0, false));
  }

  @Test
  void expectedTransfersOut_variousScenarios_matchContract() {
    // Remote request (not local)
    PeerNode remote = org.mockito.Mockito.mock(PeerNode.class);
    RequestTag remoteTag = newRemoteTag(node, remote);

    // a) Not accepted
    assertEquals(0, remoteTag.expectedTransfersOut(false, 0, false));

    // b) Accepted, remote, forAccept=false, ignoreLocal=false -> 1
    remoteTag.setAccepted();
    assertEquals(1, remoteTag.expectedTransfersOut(false, 0, false));

    // c) Accepted, local, ignoreLocal=false -> 0
    RequestTag localTag = newLocalTag(node);
    localTag.setAccepted(); // Already true, but explicit for clarity
    assertEquals(0, localTag.expectedTransfersOut(false, 0, false));

    // d) Accepted, local, ignoreLocal=true -> 1
    assertEquals(1, localTag.expectedTransfersOut(true, 0, false));

    // e) Accepted, remote, completedDownstreamTransfers -> 0
    remoteTag.completedDownstreamTransfers();
    assertEquals(0, remoteTag.expectedTransfersOut(false, 0, false));

    // f) forAccept=true and unlockedHandler=true -> 0 regardless of locality
    RequestTag acceptTag = newRemoteTag(node, remote);
    acceptTag.setAccepted();
    acceptTag.unlockHandler(); // sets unlockedHandler=true (may defer full unlock)
    assertEquals(0, acceptTag.expectedTransfersOut(false, 0, true));
  }

  @Test
  void waitingForOpennet_thenFinished_allowsUnlock() throws Exception {
    RequestTag tag = newLocalTag(node);
    PeerNode pn = org.mockito.Mockito.mock(PeerNode.class);

    // Block unlock via waitingForOpennet != null && get() != null
    setPrivateWaitingForOpennet(tag, new WeakReference<>(pn));

    // Should defer unlocking because waitingForOpennet is non-null
    tag.unlockHandler();
    verify(tracker, never())
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    doNothing()
        .when(tracker)
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    // Now clear the wait with the same peer and expect unlocking
    tag.finishedWaitingForOpennet(pn);

    verify(tracker, times(1)).unlockUID(tag, false, false);
  }

  @Test
  void hardTimeout_whenWaitingForOpennet_triggersFatalTimeout() throws Exception {
    RequestTag tag = newLocalTag(node);
    PeerNode pn = org.mockito.Mockito.mock(PeerNode.class);

    setPrivateWaitingForOpennet(tag, new WeakReference<>(pn));

    tag.timedOutToHandlerButContinued();
    tag.unlockHandler();

    long now = System.currentTimeMillis() + RequestTracker.TIMEOUT + 1_000;
    tag.maybeLogStillPresent(now, UID);

    verify(pn, times(1)).fatalTimeout(tag, false);
  }

  @Test
  void hardTimeout_whenSenderLostAndNoRouting_forcesSenderFinishAndUnlocks() throws Exception {
    RequestTag tag = newLocalTag(node);
    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);

    tag.setSender(rs, /* coalesced= */ false);
    setPrivateSender(tag, new WeakReference<>(null));

    tag.timedOutToHandlerButContinued();
    tag.unlockHandler();

    verify(tracker, never())
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    long now = System.currentTimeMillis() + RequestTracker.TIMEOUT + 1_000;
    tag.maybeLogStillPresent(now, UID);

    verify(tracker, times(1)).unlockUID(tag, false, false);
    assertEquals(RequestSender.TIMED_OUT, getPrivateRequestSenderFinishedCode(tag));
  }

  @Test
  void hardTimeout_afterPeerTimeout_stillAllowsSenderFallback() throws Exception {
    RequestTag tag = newLocalTag(node);
    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);

    tag.setSender(rs, /* coalesced= */ false);
    setPrivateSender(tag, new WeakReference<>(null));
    tag.addRoutedTo(peer, /* offeredKey= */ false);

    tag.timedOutToHandlerButContinued();
    tag.unlockHandler();

    long now = System.currentTimeMillis() + RequestTracker.TIMEOUT + 1_000;
    tag.maybeLogStillPresent(now, UID);

    verify(peer, times(1)).fatalTimeout(tag, false);

    tag.removeRoutingTo(peer);

    long later = now + 61_000;
    tag.maybeLogStillPresent(later, UID);

    verify(tracker, times(1)).unlockUID(tag, false, false);
    assertEquals(RequestSender.TIMED_OUT, getPrivateRequestSenderFinishedCode(tag));
  }

  @Test
  void handlerTransferBegins_thenUnlock_removesFromTracker() {
    RequestTag tag = newLocalTag(node);

    // Register the transferring state and then fully unlock
    tag.handlerTransferBegins();
    verify(tracker, times(1)).addTransferringRequestHandler(UID);

    doNothing()
        .when(tracker)
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    tag.unlockHandler();

    // innerUnlock should clear the transferring handler state
    verify(tracker, times(1)).removeTransferringRequestHandler(UID);
    verify(tracker, times(1)).unlockUID(tag, false, false);
  }

  @Test
  void senderTransferBegins_withoutSenderSet_throws() {
    RequestTag tag = newLocalTag(node);
    NodeCHK key = randomNodeChk();
    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);

    assertThrows(IllegalStateException.class, () -> tag.senderTransferBegins(key, rs));
  }

  @Test
  void senderTransferBegins_andEnds_registersAndUnregisters() {
    RequestTag tag = newLocalTag(node);
    NodeCHK key = randomNodeChk();
    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);

    tag.setSender(rs, /* coalesced= */ false);

    tag.senderTransferBegins(key, rs);
    verify(tracker, times(1)).addTransferringSender(key, rs);

    // Should assert and then remove the sender from the tracker
    tag.senderTransferEnds(key, rs);
    verify(tracker, times(1)).removeTransferringSender(key, rs);
  }

  @Test
  void senderTransferEnds_whenNotTransferring_doesNothing() {
    RequestTag tag = newLocalTag(node);
    NodeCHK key = randomNodeChk();
    RequestSender rs = org.mockito.Mockito.mock(RequestSender.class);

    tag.senderTransferEnds(key, rs);
    verify(tracker, never()).removeTransferringSender(key, rs);
  }

  @Test
  void currentlyRoutingTo_whenNoOpennetWait_delegatesToSuper() {
    RequestTag tag = newLocalTag(node);
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);

    boolean added = tag.addRoutedTo(peer, /* offeredKey= */ false);
    assertTrue(added, "Peer should be added to routing set");

    assertTrue(
        tag.currentlyRoutingTo(peer), "Should delegate to UIDTag when not waiting for opennet");
  }

  @Test
  void basicFlags_areReportedCorrectly() {
    RequestTag tag = newLocalTag(node);
    assertFalse(tag.isSSK());
    assertFalse(tag.isInsert());
    assertFalse(tag.isOfferReply());

    RequestTag sskTag = new RequestTag(true, RequestTag.START.LOCAL, null, true, 42L, node);
    assertTrue(sskTag.isSSK());
  }

  @Test
  void handlerThrew_unlocksWhenPossible() {
    RequestTag tag = newLocalTag(node);

    doNothing()
        .when(tracker)
        .unlockUID(
            org.mockito.Mockito.any(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean());

    assertDoesNotThrow(() -> tag.handlerThrew(new RuntimeException("boom")));

    verify(tracker, times(1)).unlockUID(tag, false, false);
  }

  private static NodeCHK randomNodeChk() {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    new SecureRandom(new byte[] {1, 2, 3, 4}).nextBytes(rk);
    return new NodeCHK(rk, network.crypta.keys.Key.ALGO_AES_PCFB_256_SHA256);
  }

  private static void setPrivateWaitingForOpennet(RequestTag tag, WeakReference<PeerNode> ref)
      throws Exception {
    Field f = RequestTag.class.getDeclaredField("waitingForOpennet");
    f.setAccessible(true);
    f.set(tag, ref);
  }

  private static void setPrivateSender(RequestTag tag, WeakReference<RequestSender> ref)
      throws Exception {
    Field f = RequestTag.class.getDeclaredField("sender");
    f.setAccessible(true);
    f.set(tag, ref);
  }

  private static int getPrivateRequestSenderFinishedCode(RequestTag tag) throws Exception {
    Field f = RequestTag.class.getDeclaredField("requestSenderFinishedCode");
    f.setAccessible(true);
    return (int) f.get(tag);
  }
}
