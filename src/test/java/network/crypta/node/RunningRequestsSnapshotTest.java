package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.node.RequestTracker.CountedRequests;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests for RunningRequestsSnapshot. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "java:S3011"})
class RunningRequestsSnapshotTest {

  private static final double CHK_TRANSFER_BYTES = 32768d + 256d;
  private static final double SSK_TRANSFER_BYTES = 2048d + 256d;
  private static final int TRANSFER_IN_OUT_OVERHEAD = 256;
  private static final int TRANSFER_OUT_IN_OVERHEAD = 256;

  private static final CounterValues CHK_MAIN = new CounterValues(7, 30, 50);
  private static final CounterValues SSK_MAIN = new CounterValues(5, 10, 20);
  private static final CounterValues CHK_SR = new CounterValues(2, 6, 8);
  private static final CounterValues SSK_SR = new CounterValues(1, 4, 6);

  private static final Field TOTAL_FIELD = getField("total");
  private static final Field EXPECTED_OUT_FIELD = getField("expectedTransfersOut");
  private static final Field EXPECTED_IN_FIELD = getField("expectedTransfersIn");

  @Test
  void constructor_withPeerLoadStats_copiesFieldsAndZerosSourceRestarted() {
    // Arrange
    PeerLoadStats stats = peerLoadStats(3, 5, 7, 11, 9, true);

    // Act
    RunningRequestsSnapshot snapshot = new RunningRequestsSnapshot(stats);

    // Assert
    assertEquals(3, snapshot.expectedTransfersInCHK);
    assertEquals(5, snapshot.expectedTransfersInSSK);
    assertEquals(7, snapshot.expectedTransfersOutCHK);
    assertEquals(11, snapshot.expectedTransfersOutSSK);
    assertEquals(-1, snapshot.totalRequests());
    assertEquals(9, snapshot.averageTransfersPerInsert);
    assertEquals(0, snapshot.expectedTransfersInCHKSR);
    assertEquals(0, snapshot.expectedTransfersInSSKSR);
    assertEquals(0, snapshot.expectedTransfersOutCHKSR);
    assertEquals(0, snapshot.expectedTransfersOutSSKSR);
    assertEquals(0, snapshot.totalRequestsSR);
    assertEquals(18, snapshot.totalOutTransfers());
  }

  @ParameterizedTest
  @CsvSource({"true", "false"})
  void calculate_whenInputFlag_expectTransferEstimate(boolean input) {
    // Arrange
    PeerLoadStats stats = peerLoadStats(2, 1, 3, 4, 6, false);
    RunningRequestsSnapshot snapshot = new RunningRequestsSnapshot(stats);
    double expected =
        input
            ? expectedInputBytes(new CounterValues(0, 2, 3), new CounterValues(0, 1, 4))
            : expectedOutputBytes(new CounterValues(0, 2, 3), new CounterValues(0, 1, 4));

    // Act
    double resultIgnoreFalse = snapshot.calculate(false, input);
    double resultIgnoreTrue = snapshot.calculate(true, input);

    // Assert
    assertEquals(expected, resultIgnoreFalse, 0.0);
    assertEquals(expected, resultIgnoreTrue, 0.0);
  }

  @ParameterizedTest
  @CsvSource({"true", "false"})
  void calculateSR_whenInputFlag_expectTransferEstimateFromSourceRestarted(boolean input) {
    // Arrange
    RunningRequestsSnapshot snapshot = snapshotFromPeerTracker(false, true);
    double expected =
        input ? expectedInputBytes(CHK_SR, SSK_SR) : expectedOutputBytes(CHK_SR, SSK_SR);

    // Act
    double resultIgnoreFalse = snapshot.calculateSR(false, input);
    double resultIgnoreTrue = snapshot.calculateSR(true, input);

    // Assert
    assertEquals(expected, resultIgnoreFalse, 0.0);
    assertEquals(expected, resultIgnoreTrue, 0.0);
  }

  @Test
  void constructor_withPeerNodeAndRequestsFromPeer_subtractsSourceRestartedCounts() {
    // Arrange
    RunningRequestsSnapshot snapshot = snapshotFromPeerTracker(false, false);

    // Act
    int totalRequests = snapshot.totalRequests();

    // Assert
    assertEquals(24, snapshot.expectedTransfersInCHK);
    assertEquals(6, snapshot.expectedTransfersInSSK);
    assertEquals(42, snapshot.expectedTransfersOutCHK);
    assertEquals(14, snapshot.expectedTransfersOutSSK);
    assertEquals(9, totalRequests);
    assertEquals(6, snapshot.expectedTransfersInCHKSR);
    assertEquals(4, snapshot.expectedTransfersInSSKSR);
    assertEquals(8, snapshot.expectedTransfersOutCHKSR);
    assertEquals(6, snapshot.expectedTransfersOutSSKSR);
    assertEquals(3, snapshot.totalRequestsSR);
    assertEquals(56, snapshot.totalOutTransfers());
  }

  @Test
  void constructor_withPeerNodeAndRequestsToPeer_keepsTotalsAndZerosSourceRestarted() {
    // Arrange
    RunningRequestsSnapshot snapshot = snapshotFromPeerTracker(true, false);

    // Act
    int totalRequests = snapshot.totalRequests();

    // Assert
    assertEquals(30, snapshot.expectedTransfersInCHK);
    assertEquals(10, snapshot.expectedTransfersInSSK);
    assertEquals(50, snapshot.expectedTransfersOutCHK);
    assertEquals(20, snapshot.expectedTransfersOutSSK);
    assertEquals(12, totalRequests);
    assertEquals(0, snapshot.expectedTransfersInCHKSR);
    assertEquals(0, snapshot.expectedTransfersInSSKSR);
    assertEquals(0, snapshot.expectedTransfersOutCHKSR);
    assertEquals(0, snapshot.expectedTransfersOutSSKSR);
    assertEquals(0, snapshot.totalRequestsSR);
  }

  @Test
  void constructor_withTrackerSnapshot_includesSourceRestartedInTotals() {
    // Arrange
    RequestTracker tracker = mock(RequestTracker.class);
    stubCountRequestsWithoutPeer(tracker);

    // Act
    RunningRequestsSnapshot snapshot = new RunningRequestsSnapshot(tracker, false, 7, true);

    // Assert
    assertEquals(30, snapshot.expectedTransfersInCHK);
    assertEquals(10, snapshot.expectedTransfersInSSK);
    assertEquals(50, snapshot.expectedTransfersOutCHK);
    assertEquals(20, snapshot.expectedTransfersOutSSK);
    assertEquals(12, snapshot.totalRequests());
    assertEquals(6, snapshot.expectedTransfersInCHKSR);
    assertEquals(4, snapshot.expectedTransfersInSSKSR);
    assertEquals(8, snapshot.expectedTransfersOutCHKSR);
    assertEquals(6, snapshot.expectedTransfersOutSSKSR);
    assertEquals(3, snapshot.totalRequestsSR);
  }

  private static RunningRequestsSnapshot snapshotFromPeerTracker(
      boolean requestsToNode, boolean realTimeFlag) {
    RequestTracker tracker = mock(RequestTracker.class);
    stubCountRequestsWithPeer(tracker);
    PeerNode peer = mock(PeerNode.class);
    return new RunningRequestsSnapshot(tracker, peer, requestsToNode, false, 5, realTimeFlag);
  }

  private static PeerLoadStats peerLoadStats(
      int inChk,
      int inSsk,
      int outChk,
      int outSsk,
      int avgTransfersOutPerInsert,
      boolean realTime) {
    PeerNode peer = mock(PeerNode.class);
    Message message = mock(Message.class);
    when(message.getSpec()).thenReturn(DMT.FNPPeerLoadStatusInt);
    when(message.getInt(DMT.OTHER_TRANSFERS_IN_CHK)).thenReturn(inChk);
    when(message.getInt(DMT.OTHER_TRANSFERS_IN_SSK)).thenReturn(inSsk);
    when(message.getInt(DMT.OTHER_TRANSFERS_OUT_CHK)).thenReturn(outChk);
    when(message.getInt(DMT.OTHER_TRANSFERS_OUT_SSK)).thenReturn(outSsk);
    when(message.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT)).thenReturn(avgTransfersOutPerInsert);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT)).thenReturn(0);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT)).thenReturn(0);
    when(message.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT)).thenReturn(0);
    when(message.getBoolean(DMT.REAL_TIME_FLAG)).thenReturn(realTime);
    return new PeerLoadStats(peer, message);
  }

  private static void stubCountRequestsWithoutPeer(RequestTracker tracker) {
    doAnswer(
            invocation -> {
              RequestAdmissionMode mode = invocation.getArgument(0);
              boolean sskFlag = mode.isSSK();
              CountedRequests counter = invocation.getArgument(2);
              CountedRequests counterSr = invocation.getArgument(3);
              setCounter(counter, sskFlag ? SSK_MAIN : CHK_MAIN);
              setCounter(counterSr, sskFlag ? SSK_SR : CHK_SR);
              return null;
            })
        .when(tracker)
        .countRequests(
            any(RequestAdmissionMode.class),
            any(RequestTransferOptions.class),
            any(CountedRequests.class),
            any(CountedRequests.class));
  }

  private static void stubCountRequestsWithPeer(RequestTracker tracker) {
    doAnswer(
            invocation -> {
              RequestAdmissionMode mode = invocation.getArgument(2);
              boolean sskFlag = mode.isSSK();
              CountedRequests counter = invocation.getArgument(4);
              CountedRequests counterSr = invocation.getArgument(5);
              setCounter(counter, sskFlag ? SSK_MAIN : CHK_MAIN);
              if (counterSr != null) {
                setCounter(counterSr, sskFlag ? SSK_SR : CHK_SR);
              }
              return null;
            })
        .when(tracker)
        .countRequests(
            any(PeerNode.class),
            anyBoolean(),
            any(RequestAdmissionMode.class),
            any(RequestTransferOptions.class),
            any(CountedRequests.class),
            nullable(CountedRequests.class));
  }

  private static void setCounter(CountedRequests counter, CounterValues values) {
    try {
      TOTAL_FIELD.setInt(counter, values.total());
      EXPECTED_IN_FIELD.setInt(counter, values.in());
      EXPECTED_OUT_FIELD.setInt(counter, values.out());
    } catch (IllegalAccessException e) {
      throw new AssertionError("Failed to set counter values", e);
    }
  }

  private static double expectedInputBytes(CounterValues chk, CounterValues ssk) {
    return chk.in() * CHK_TRANSFER_BYTES
        + ssk.in() * SSK_TRANSFER_BYTES
        + chk.out() * (double) TRANSFER_OUT_IN_OVERHEAD
        + ssk.out() * (double) TRANSFER_OUT_IN_OVERHEAD;
  }

  private static double expectedOutputBytes(CounterValues chk, CounterValues ssk) {
    return chk.out() * CHK_TRANSFER_BYTES
        + ssk.out() * SSK_TRANSFER_BYTES
        + chk.in() * (double) TRANSFER_IN_OUT_OVERHEAD
        + ssk.in() * (double) TRANSFER_IN_OUT_OVERHEAD;
  }

  private static Field getField(String name) {
    try {
      Field field = CountedRequests.class.getDeclaredField(name);
      field.setAccessible(true);
      return field;
    } catch (ReflectiveOperationException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private record CounterValues(int total, int in, int out) {}
}
