package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.RequestTag.START;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RequestTrackerTest {

  @Mock private PeerManager peerManager;
  @Mock private Ticker ticker;

  private RequestTracker tracker;
  private Node node;

  @BeforeEach
  void setup() {
    tracker = new RequestTracker(peerManager, ticker);
    node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    org.mockito.Mockito.lenient().when(node.routing().tracker()).thenReturn(tracker);
  }

  @Test
  void lockUID_whenLocalAndRemoteCHKRequests_expectCountsUpdated() {
    // Arrange
    RequestTag localChkRt = new RequestTag(false, START.LOCAL, null, true, 1L, node);
    RequestTag remoteChkBulk =
        new RequestTag(
            false, START.REMOTE, org.mockito.Mockito.mock(PeerNode.class), false, 2L, node);
    // Remote tags need to be marked accepted explicitly (local are accepted in constructor)
    remoteChkBulk.setAccepted();

    // Act
    assertTrue(tracker.lockUID(localChkRt));
    assertTrue(tracker.lockUID(remoteChkBulk));

    // Assert
    assertEquals(2, tracker.getNumCHKRequests());
    assertEquals(1, tracker.getNumLocalCHKRequests());
    assertEquals(1, tracker.getNumRemoteCHKRequests());
    assertEquals(0, tracker.getNumSSKRequests());
    assertEquals(0, tracker.getNumCHKInserts());
    assertEquals(0, tracker.getNumSSKInserts());
  }

  @Test
  void lockUID_whenSameTagTwice_expectIdempotentTrue() {
    // Arrange
    RequestTag remoteChk = new RequestTag(false, START.REMOTE, null, false, 10L, node);
    remoteChk.setAccepted();

    // Act + Assert
    assertTrue(tracker.lockUID(remoteChk));
    assertTrue(tracker.lockUID(remoteChk)); // idempotent
    assertEquals(1, tracker.getNumCHKRequests());
  }

  @Test
  void unlockUID_whenCanFailTrueOnMissingEntry_expectNoThrowAndNoChange() {
    // Arrange: a tag that was never locked
    RequestTag tag = new RequestTag(false, START.LOCAL, null, true, 200L, node);

    // Act: unlock against empty tracker (canFail = true)
    tracker.unlockUID(
        200L, /*ssk*/
        false, /*insert*/
        false, /*canFail*/
        true,
        /*offerReply*/ false, /*local*/
        true, /*realTime*/
        true,
        tag, /*noRecord*/
        true);

    // Assert: counts remain zero
    assertEquals(0, tracker.getNumCHKRequests());
    assertEquals(0, tracker.getNumTransferringRequestHandlers());
  }

  @Test
  void completed_whenThresholdReached_flushesToRoutingCompatiblePeers() {
    // Arrange
    PeerNode routable = org.mockito.Mockito.mock(PeerNode.class);
    PeerNode unroutable = org.mockito.Mockito.mock(PeerNode.class);
    when(routable.isRoutingCompatible()).thenReturn(true);
    when(unroutable.isRoutingCompatible()).thenReturn(false);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {routable, unroutable});

    // Act: push exactly COMPLETED_THRESHOLD items
    for (int i = 1; i <= RequestTracker.COMPLETED_THRESHOLD; i++) {
      tracker.completed(i);
    }

    // Assert: only routable peer is notified once, with all ids
    ArgumentCaptor<Long[]> idsCaptor = ArgumentCaptor.forClass(Long[].class);
    verify(routable, times(1)).removeUIDsFromMessageQueues(idsCaptor.capture());
    verify(unroutable, never()).removeUIDsFromMessageQueues(any());
    Long[] flushed = idsCaptor.getValue();
    assertEquals(RequestTracker.COMPLETED_THRESHOLD, flushed.length);
    assertEquals(1L, flushed[0].longValue());
    assertEquals(RequestTracker.COMPLETED_THRESHOLD, flushed[flushed.length - 1].longValue());
  }

  @Test
  void startDeadUIDChecker_schedulesAndReschedules_andInvokesMaybeLog() {
    // Arrange
    ArgumentCaptor<Runnable> runCaptor = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<Long> delayCaptor = ArgumentCaptor.forClass(Long.class);

    // Add a spied tag so we can verify maybeLogStillPresent is invoked
    RequestTag tag = spy(new RequestTag(false, START.LOCAL, null, false, 777L, node));
    doNothing().when(tag).maybeLogStillPresent(anyLong(), any());
    assertTrue(tracker.lockUID(tag));

    // Act: schedule
    tracker.startDeadUIDChecker();

    // Assert: initial schedule with TIMEOUT
    verify(ticker, times(1)).queueTimedJob(runCaptor.capture(), delayCaptor.capture());
    assertEquals(RequestTracker.TIMEOUT, delayCaptor.getValue().longValue());

    // Run the checker and expect a reschedule with ~60s
    Runnable checker = runCaptor.getValue();
    assertNotNull(checker);
    checker.run();

    // maybeLogStillPresent called for the locked tag
    verify(tag, times(1)).maybeLogStillPresent(anyLong(), org.mockito.Mockito.eq(777L));
    // Rescheduled
    verify(ticker, times(2)).queueTimedJob(runCaptor.capture(), delayCaptor.capture());
    assertEquals(60_000L, delayCaptor.getValue().longValue());
  }

  @Test
  void countRequests_whenLocalVsRemoteRequests_expectAggregates() {
    // Arrange: one local CHK, one remote CHK, one local SSK insert
    RequestTag localChk = new RequestTag(false, START.LOCAL, null, false, 21L, node);
    RequestTag remoteChk =
        new RequestTag(
            false, START.REMOTE, org.mockito.Mockito.mock(PeerNode.class), false, 22L, node);
    remoteChk.setAccepted();
    InsertTag localSskInsert = new InsertTag(true, InsertTag.START.LOCAL, null, false, 23L, node);
    localSskInsert.setAccepted();

    assertTrue(tracker.lockUID(localChk));
    assertTrue(tracker.lockUID(remoteChk));
    assertTrue(tracker.lockUID(localSskInsert));

    RequestTracker.CountedRequests allNonLocal = new RequestTracker.CountedRequests();
    RequestTracker.CountedRequests locals = new RequestTracker.CountedRequests();

    // Act: Count remote (local=false) CHK gets
    tracker.countRequests(
        /*local*/ false,
        /*ssk*/ false,
        /*insert*/ false,
        /*offer*/ false,
        /*rt*/ false,
        /*transfersPerInsert*/ 3,
        /*ignoreLocalVsRemote*/ false,
        allNonLocal,
        /*counterSR*/ null);

    // Act: Count local (local=true) CHK gets
    tracker.countRequests(
        /*local*/ true,
        /*ssk*/ false,
        /*insert*/ false,
        /*offer*/ false,
        /*rt*/ false,
        /*transfersPerInsert*/ 3,
        /*ignoreLocalVsRemote*/ false,
        locals,
        /*counterSR*/ null);

    // Assert
    assertEquals(1, allNonLocal.total());
    assertEquals(1, allNonLocal.expectedTransfersIn());
    assertEquals(1, allNonLocal.expectedTransfersOut());

    assertEquals(1, locals.total());
    assertEquals(1, locals.expectedTransfersIn());
    assertEquals(0, locals.expectedTransfersOut());
  }

  @Test
  void countRequestsWaitingForSlots_whenMixedLocalAndRemote_expectSeparatedTotals() {
    // Arrange: one local waiting, one remote waiting
    RequestTag localTag = new RequestTag(false, START.LOCAL, null, false, 31L, node);
    localTag.setWaitingForSlot();
    RequestTag remoteTag =
        new RequestTag(
            false, START.REMOTE, org.mockito.Mockito.mock(PeerNode.class), false, 32L, node);
    remoteTag.setAccepted();
    remoteTag.setWaitingForSlot();
    assertTrue(tracker.lockUID(localTag));
    assertTrue(tracker.lockUID(remoteTag));

    // Act
    RequestTracker.WaitingForSlots slots = tracker.countRequestsWaitingForSlots();

    // Assert
    assertEquals(1, slots.local);
    assertEquals(1, slots.remote);
  }

  @Test
  void reassignTagToSelf_whenRemoteTag_expectIsLocalAfterwards() {
    // Arrange
    RequestTag remote =
        new RequestTag(
            false, START.REMOTE, org.mockito.Mockito.mock(PeerNode.class), false, 41L, node);
    remote.setAccepted();
    assertTrue(tracker.lockUID(remote));

    // Act
    tracker.reassignTagToSelf(remote);

    // Assert
    assertTrue(remote.isLocal());
  }

  @Test
  void transferringRequestHandlers_addAndRemove_expectCountsUpdated() {
    // Arrange + Act
    tracker.addTransferringRequestHandler(1001L);
    assertEquals(1, tracker.getNumTransferringRequestHandlers());

    tracker.removeTransferringRequestHandler(1001L);
    assertEquals(0, tracker.getNumTransferringRequestHandlers());
  }

  @Test
  void transferringRequestSenders_addGetRemove_expectBehaviorByKeyAndSender() {
    // Arrange
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    rk[0] = 1;
    NodeCHK key = new NodeCHK(rk, Key.ALGO_AES_PCFB_256_SHA256);

    // Use a mock RequestSender; inline mock maker allows final-class mocking.
    RequestSender sender1 = org.mockito.Mockito.mock(RequestSender.class);
    // Default realTimeFlag=false for mocks; sender will be tracked in bulk map.

    // Act: add and get
    tracker.addTransferringSender(key, sender1);
    assertEquals(1, tracker.getNumTransferringRequestSenders());
    RequestSender got = tracker.getTransferringRequestSenderByKey(key, /*rt*/ false);
    assertNotNull(got);

    // Remove with mismatched sender: should not remove
    RequestSender sender2 = org.mockito.Mockito.mock(RequestSender.class);
    tracker.removeTransferringSender(key, sender2);
    assertEquals(1, tracker.getNumTransferringRequestSenders());

    // Remove with the matching sender: should remove
    tracker.removeTransferringSender(key, sender1);
    assertEquals(0, tracker.getNumTransferringRequestSenders());
    assertNull(tracker.getTransferringRequestSenderByKey(key, /*rt*/ false));
  }

  @Test
  void addRunningUIDs_and_getTotalRunningUIDsAlt_expectConsistency() {
    // Arrange: add several tags across categories
    RequestTag r1 = new RequestTag(false, START.LOCAL, null, true, 501L, node);
    RequestTag r2 = new RequestTag(true, START.LOCAL, null, false, 502L, node);
    InsertTag ins = new InsertTag(false, InsertTag.START.LOCAL, null, true, 503L, node);
    OfferReplyTag off = new OfferReplyTag(true, null, false, 504L, node);
    r2.setAccepted();
    ins.setAccepted();
    assertTrue(tracker.lockUID(r1));
    assertTrue(tracker.lockUID(r2));
    assertTrue(tracker.lockUID(ins));
    assertTrue(tracker.lockUID(off));

    // Act
    List<Long> ids = new ArrayList<>();
    tracker.addRunningUIDs(ids);

    // Assert: cardinality matches alternative counter
    assertEquals(tracker.getTotalRunningUIDsAlt(), ids.size());
  }
}
