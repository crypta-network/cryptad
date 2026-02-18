package network.crypta.node;

import java.lang.reflect.Field;
import java.util.List;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.node.NodeStats.RequestType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeLoadTrackerTest {

  @Test
  void proportionTimingOutFatallyInWait_whenFirstFatalNoAllocated_returnsHalf() throws Exception {
    TestContext ctx = newTestContext();
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);

    tracker.reportFatalTimeoutInWait(false);

    assertEquals(0.5, tracker.proportionTimingOutFatallyInWait(), 0.0001);
    verify(ctx.nodeStats).reportFatalTimeoutInWait(false);
  }

  @Test
  void proportionTimingOutFatallyInWait_whenFatalAndAllocated_returnsRatio() throws Exception {
    TestContext ctx = newTestContext();
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);

    tracker.reportFatalTimeoutInWait(false);
    tracker.reportFatalTimeoutInWait(false);
    tracker.reportAllocated(false);

    assertEquals(2.0 / 3.0, tracker.proportionTimingOutFatallyInWait(), 0.0001);
  }

  @Test
  void tryRouteTo_whenNoLoadStatsAndTagNew_returnsUnknownAndAddsRoute() throws Exception {
    TestContext ctx = newTestContext();
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    when(ctx.nodeStats.ignoreLocalVsRemoteBandwidthLiability()).thenReturn(false);
    when(ctx.peer.isRoutable()).thenReturn(true);
    when(ctx.peer.isInMandatoryBackoff(anyLong(), eq(true))).thenReturn(false);
    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);
    UIDTag tag = mock(UIDTag.class);
    when(tag.addRoutedTo(ctx.peer, false)).thenReturn(true);

    PeerNodeLoadTracker.RequestLikelyAcceptedState state =
        tracker.tryRouteTo(tag, PeerNodeLoadTracker.RequestLikelyAcceptedState.LIKELY);

    assertEquals(PeerNodeLoadTracker.RequestLikelyAcceptedState.UNKNOWN, state);
    verify(tag).addRoutedTo(ctx.peer, false);
  }

  @Test
  void tryRouteTo_whenPeerNotRoutable_returnsNull() throws Exception {
    TestContext ctx = newTestContext();
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    when(ctx.nodeStats.ignoreLocalVsRemoteBandwidthLiability()).thenReturn(false);
    when(ctx.peer.isRoutable()).thenReturn(false);
    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);
    UIDTag tag = mock(UIDTag.class);

    PeerNodeLoadTracker.RequestLikelyAcceptedState state =
        tracker.tryRouteTo(tag, PeerNodeLoadTracker.RequestLikelyAcceptedState.LIKELY);

    assertNull(state);
    verify(tag, never()).addRoutedTo(ctx.peer, false);
  }

  @Test
  void tryRouteTo_whenGuaranteedAndTagNew_returnsGuaranteed() throws Exception {
    TestContext ctx = newTestContext();
    when(ctx.peer.isRoutable()).thenReturn(true);
    when(ctx.peer.isInMandatoryBackoff(anyLong(), eq(true))).thenReturn(false);
    PeerLoadStats loadStats = createLoadStats(ctx.peer, 100, 100, 300, 300, 1000, 1200, 10, 20);
    RunningRequestsSnapshot runningRequests = mock(RunningRequestsSnapshot.class);
    RunningRequestsSnapshot otherRunningRequests = mock(RunningRequestsSnapshot.class);
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    when(ctx.nodeStats.getRunningRequestsTo(ctx.peer, true)).thenReturn(runningRequests);
    when(ctx.nodeStats.ignoreLocalVsRemoteBandwidthLiability()).thenReturn(false);
    when(runningRequests.calculate(false, false)).thenReturn(50.0);
    when(runningRequests.calculate(false, true)).thenReturn(50.0);
    when(runningRequests.totalOutTransfers()).thenReturn(1);

    PeerLoadStats loadStatsSpy = spy(loadStats);
    doReturn(otherRunningRequests).when(loadStatsSpy).getOtherRunningRequests();

    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);
    tracker.reportLoadStatus(loadStatsSpy);

    UIDTag tag = mock(UIDTag.class);
    when(tag.addRoutedTo(ctx.peer, false)).thenReturn(true);

    PeerNodeLoadTracker.RequestLikelyAcceptedState state =
        tracker.tryRouteTo(tag, PeerNodeLoadTracker.RequestLikelyAcceptedState.LIKELY);

    assertEquals(PeerNodeLoadTracker.RequestLikelyAcceptedState.GUARANTEED, state);
    verify(tag).addRoutedTo(ctx.peer, false);
  }

  @Test
  void tryRouteTo_whenDontSendUnlessGuaranteed_blocksLikely() throws Exception {
    TestContext ctx = newTestContext();
    when(ctx.peer.isRoutable()).thenReturn(true);
    when(ctx.peer.isInMandatoryBackoff(anyLong(), eq(true))).thenReturn(false);
    PeerLoadStats loadStats = createLoadStats(ctx.peer, 100, 100, 300, 300, 1000, 1200, 5, 30);
    RunningRequestsSnapshot runningRequests = mock(RunningRequestsSnapshot.class);
    RunningRequestsSnapshot otherRunningRequests = mock(RunningRequestsSnapshot.class);
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    when(ctx.nodeStats.getRunningRequestsTo(ctx.peer, true)).thenReturn(runningRequests);
    when(ctx.nodeStats.ignoreLocalVsRemoteBandwidthLiability()).thenReturn(false);
    when(runningRequests.calculate(false, false)).thenReturn(120.0);
    when(runningRequests.calculate(false, true)).thenReturn(120.0);
    when(runningRequests.totalOutTransfers()).thenReturn(10);
    when(otherRunningRequests.calculate(false, false)).thenReturn(0.0);
    when(otherRunningRequests.calculate(false, true)).thenReturn(0.0);
    when(otherRunningRequests.totalOutTransfers()).thenReturn(0);

    PeerLoadStats loadStatsSpy = spy(loadStats);
    doReturn(otherRunningRequests).when(loadStatsSpy).getOtherRunningRequests();

    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);
    tracker.reportLoadStatus(loadStatsSpy);
    tracker.setDontSendUnlessGuaranteed();

    UIDTag tag = mock(UIDTag.class);

    PeerNodeLoadTracker.RequestLikelyAcceptedState state =
        tracker.tryRouteTo(tag, PeerNodeLoadTracker.RequestLikelyAcceptedState.LIKELY);

    assertNull(state);
    verify(tag, never()).addRoutedTo(ctx.peer, false);
  }

  @Test
  void getIncomingLoadStats_whenNoLastStats_returnsNull() throws Exception {
    TestContext ctx = newTestContext();
    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);

    assertNull(tracker.getIncomingLoadStats());
  }

  @Test
  void getIncomingLoadStats_whenStatsPresent_returnsSummary() throws Exception {
    TestContext ctx = newTestContext();
    PeerLoadStats loadStats = createLoadStats(ctx.peer, 1000, 2000, 5000, 6000, 5000, 6000, 10, 20);
    RunningRequestsSnapshot runningRequests = mock(RunningRequestsSnapshot.class);
    RunningRequestsSnapshot otherRunningRequests = mock(RunningRequestsSnapshot.class);
    when(ctx.node.network().stats()).thenReturn(ctx.nodeStats);
    when(ctx.nodeStats.getRunningRequestsTo(ctx.peer, true)).thenReturn(runningRequests);
    when(ctx.nodeStats.ignoreLocalVsRemoteBandwidthLiability()).thenReturn(false);
    when(runningRequests.calculate(false, false)).thenReturn(111.0);
    when(runningRequests.calculate(false, true)).thenReturn(222.0);
    when(runningRequests.totalRequests()).thenReturn(7);
    when(otherRunningRequests.calculate(false, false)).thenReturn(333.0);
    when(otherRunningRequests.calculate(false, true)).thenReturn(444.0);

    PeerLoadStats loadStatsSpy = spy(loadStats);
    doReturn(otherRunningRequests).when(loadStatsSpy).getOtherRunningRequests();

    PeerNodeLoadTracker.OutputLoadTracker tracker = ctx.tracker.outputLoadTracker(true);
    tracker.reportLoadStatus(loadStatsSpy);

    PeerNodeLoadTracker.IncomingLoadSummaryStats summary = tracker.getIncomingLoadStats();

    assertNotNull(summary);
    assertEquals(7, summary.runningRequestsTotal);
    assertEquals(1000, summary.peerCapacityOutputBytes);
    assertEquals(2000, summary.peerCapacityInputBytes);
    assertEquals(5000, summary.totalCapacityOutputBytes);
    assertEquals(6000, summary.totalCapacityInputBytes);
    assertEquals(111, summary.usedCapacityOutputBytes);
    assertEquals(222, summary.usedCapacityInputBytes);
    assertEquals(333, summary.othersUsedCapacityOutputBytes);
    assertEquals(444, summary.othersUsedCapacityInputBytes);
  }

  @Test
  void slotWaiterList_whenAddingAndRemoving_preservesOrder() {
    PeerNode source = mock(PeerNode.class);
    UIDTag tag = mock(UIDTag.class);
    PeerNodeLoadTracker.SlotWaiterList list = new PeerNodeLoadTracker.SlotWaiterList();
    PeerNodeLoadTracker.SlotWaiter first =
        new PeerNodeLoadTracker.SlotWaiter(tag, RequestType.CHK_REQUEST, true, source);
    PeerNodeLoadTracker.SlotWaiter second =
        new PeerNodeLoadTracker.SlotWaiter(tag, RequestType.CHK_REQUEST, true, source);

    list.put(first);
    list.put(second);

    PeerNodeLoadTracker.SlotWaiter removed = list.removeFirst();
    List<PeerNodeLoadTracker.SlotWaiter> remaining = list.values();

    assertEquals(first, removed);
    assertEquals(1, remaining.size());
    assertEquals(second, remaining.getFirst());
  }

  @Test
  void addWaitingFor_whenPeerInBackoff_returnsFalse() {
    PeerNode peer = mock(PeerNode.class);
    UIDTag tag = mock(UIDTag.class);
    PeerNodeLoadTracker.SlotWaiter waiter =
        new PeerNodeLoadTracker.SlotWaiter(tag, RequestType.CHK_REQUEST, true, null);
    when(peer.isRoutable()).thenReturn(true);
    when(peer.isInMandatoryBackoff(anyLong(), eq(true))).thenReturn(true);

    boolean queued = waiter.addWaitingFor(peer);

    assertFalse(queued);
    verify(tag, never()).setWaitingForSlot();
  }

  @Test
  void addWaitingFor_whenQueued_addsAndMarksWaiting() {
    PeerNode peer = mock(PeerNode.class);
    UIDTag tag = mock(UIDTag.class);
    PeerNodeLoadTracker.SlotWaiter waiter =
        new PeerNodeLoadTracker.SlotWaiter(tag, RequestType.CHK_REQUEST, true, null);
    PeerNodeLoadTracker.OutputLoadTracker outputLoadTracker =
        mock(PeerNodeLoadTracker.OutputLoadTracker.class);

    when(peer.isRoutable()).thenReturn(true);
    when(peer.isInMandatoryBackoff(anyLong(), eq(true))).thenReturn(false);
    when(peer.outputLoadTracker(true)).thenReturn(outputLoadTracker);
    when(outputLoadTracker.queueSlotWaiter(waiter)).thenReturn(true);

    boolean queued = waiter.addWaitingFor(peer);

    assertTrue(queued);
    assertEquals(1, waiter.waitingForCount());
    verify(tag).setWaitingForSlot();
  }

  @Test
  void noLongerRoutingTo_whenTagIsNotUidTag_throwsIllegalArgument() throws Exception {
    TestContext ctx = newTestContext();
    Object tag = new Object();

    assertThrows(IllegalArgumentException.class, () -> callNoLongerRoutingTo(ctx.tracker, tag));
  }

  private static TestContext newTestContext() throws Exception {
    PeerNode peer = mock(PeerNode.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeStats nodeStats = mock(NodeStats.class);
    setPeerNodeField(peer, node);
    PeerNodeLoadTracker tracker = new PeerNodeLoadTracker(peer);
    return new TestContext(peer, node, nodeStats, tracker);
  }

  private static PeerLoadStats createLoadStats(
      PeerNode peer,
      int outputPeerLimit,
      int inputPeerLimit,
      int outputLowerLimit,
      int inputLowerLimit,
      int outputUpperLimit,
      int inputUpperLimit,
      int maxTransfersOutPeerLimit,
      int maxTransfersOutLowerLimit) {
    Message message = mock(Message.class);
    when(message.getSpec()).thenReturn(DMT.FNPPeerLoadStatusInt);
    when(message.getInt(anyString())).thenReturn(0);
    when(message.getBoolean(DMT.REAL_TIME_FLAG)).thenReturn(true);
    when(message.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT)).thenReturn(outputPeerLimit);
    when(message.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT)).thenReturn(inputPeerLimit);
    when(message.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT)).thenReturn(outputLowerLimit);
    when(message.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT)).thenReturn(inputLowerLimit);
    when(message.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT)).thenReturn(outputUpperLimit);
    when(message.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT)).thenReturn(inputUpperLimit);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT)).thenReturn(1000);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT)).thenReturn(maxTransfersOutPeerLimit);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT)).thenReturn(maxTransfersOutLowerLimit);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT)).thenReturn(2000);
    when(message.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT)).thenReturn(1);
    return new PeerLoadStats(peer, message);
  }

  private static void setPeerNodeField(PeerNode target, Node node) throws Exception {
    Field field = PeerNode.class.getDeclaredField("node");
    field.setAccessible(true);
    field.set(target, node);
  }

  private static void callNoLongerRoutingTo(PeerNodeLoadTracker tracker, Object tag) {
    tracker.noLongerRoutingTo(tag, false);
  }

  private record TestContext(
      PeerNode peer, Node node, NodeStats nodeStats, PeerNodeLoadTracker tracker) {}
}
