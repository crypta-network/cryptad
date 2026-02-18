package network.crypta.io.xfer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Allow underscore-separated test names
class PacketThrottleTestPacketThrottleTest {

  private static final int PACKET_SIZE = 1024; // match Node.PACKET_SIZE

  @Test
  @DisplayName("setRoundTripTime clamps to >= 10 ms and returns via getter")
  void setRoundTripTime_whenBelowMinimum_expectClampedToTen() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    t.setRoundTripTime(5);
    assertEquals(10, t.getRoundTripTime(), "RTT must be clamped to 10 ms minimum");

    t.setRoundTripTime(123);
    assertEquals(123, t.getRoundTripTime(), "RTT should be set exactly when >= 10 ms");
  }

  @Test
  void notifyOfPacketsLost_whenZeroOrNegative_expectIllegalArgument() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);
    assertThrows(IllegalArgumentException.class, () -> t.notifyOfPacketsLost(0));
    assertThrows(IllegalArgumentException.class, () -> t.notifyOfPacketsLost(-1));
  }

  @Test
  void notifyOfPacketsLost_whenPositive_expectWindowShrinksAndSlowStartStops() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    double initial = t.getWindowSize(); // default 2.0
    t.notifyOfPacketsLost(1);

    double expectedAfterLoss = initial * Math.pow(PacketThrottle.PACKET_DROP_DECREASE_MULTIPLE, 1);
    assertEquals(
        expectedAfterLoss, t.getWindowSize(), 1e-6, "Window should decrease by loss factor");

    // Next ACK should use non-slow-start increment: + PACKET_TRANSMIT_INCREMENT / window
    double beforeAck = t.getWindowSize();
    t.notifyOfPacketAcknowledged(1000.0);
    double expectedAfterAck = beforeAck + (PacketThrottle.PACKET_TRANSMIT_INCREMENT / beforeAck);
    assertEquals(expectedAfterAck, t.getWindowSize(), 1e-6, "Non-slow-start additive increase");
  }

  @Test
  void notifyOfPacketAcknowledged_inSlowStart_expectIncreaseByOneThird() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    // Very large maxWindow so we stay in slow start and do not clamp
    t.notifyOfPacketAcknowledged(1_000_000.0);
    double expected = 2.0 + (2.0 / PacketThrottle.SLOW_START_DIVISOR); // 2 + 2/3
    assertEquals(expected, t.getWindowSize(), 1e-6, "Slow-start multiplicative growth by +1/3");
  }

  @Test
  void notifyOfPacketAcknowledged_whenExceedsMax_expectClampedAndSlowStartDisabled() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    // Choose a small max so first slow-start step would exceed it
    double maxWindow = 2.2;
    t.notifyOfPacketAcknowledged(maxWindow);
    assertEquals(maxWindow, t.getWindowSize(), 1e-6, "Window must be clamped to maxWindow");

    // Next ACK should be additive (non-slow-start)
    double before = t.getWindowSize();
    t.notifyOfPacketAcknowledged(1_000_000.0);
    double expected = before + (PacketThrottle.PACKET_TRANSMIT_INCREMENT / before);
    assertEquals(expected, t.getWindowSize(), 1e-6);
  }

  @Test
  void getWindowSize_afterHeavyLoss_expectNotBelowOneAndThenGrowsAdditively() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    t.notifyOfPacketsLost(1000); // drive internal window well below 1, then clamp to 1
    assertEquals(1.0, t.getWindowSize(), 0.0, "Window must be clamped to minimum of 1");

    t.notifyOfPacketAcknowledged(1_000_000.0);
    double expected = 1.0 + PacketThrottle.PACKET_TRANSMIT_INCREMENT; // 1 + 0.3125
    assertEquals(expected, t.getWindowSize(), 1e-6, "Additive increase from minimum window");
  }

  @Test
  void getDelay_whenDefaultAndAfterGrowth_expectFloorAndMinClamp() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    // Default: RTT=500ms, window=2 -> delay=floor(500/2)=250
    assertEquals(250, t.getDelay(), "Initial delay derived from RTT/window");

    // Grow window enough so rtt/window < 1, delay should clamp to MIN_DELAY=1
    for (int i = 0; i < 20; i++) {
      t.notifyOfPacketAcknowledged(1_000_000.0);
    }
    assertEquals(1L, t.getDelay(), "Delay must be clamped to MIN_DELAY when very large window");
  }

  @Test
  void getBandwidth_whenBasedOnDelay_expectConsistentComputation() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    // With delay=250 (from previous test’s initial state), bandwidth = 1024*1000/250 = 4096
    assertEquals(4096.0, t.getBandwidth(), 1e-9);

    // Force delay to clamp at 1 and verify bandwidth becomes PACKET_SIZE * 1000
    for (int i = 0; i < 20; i++) {
      t.notifyOfPacketAcknowledged(1_000_000.0);
    }
    assertEquals(PACKET_SIZE * 1000.0, t.getBandwidth(), 1e-9);
  }

  @Test
  void toString_whenNoPackets_thenContainsNaNAndZeroTotal() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);
    String s = t.toString();
    assertTrue(s.contains("k/sec, (w:"), "String should include bandwidth and window token");
    assertTrue(s.contains("d:NaN"), "No packets implies NaN drop ratio");
    assertTrue(s.contains("total=0"), "Totals should show zero initially");
  }

  @Test
  void toString_afterAckAndLoss_expectUpdatedTotalsAndRatio() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);

    t.notifyOfPacketAcknowledged(1000.0); // total=1
    t.notifyOfPacketAcknowledged(1000.0); // total=2
    t.notifyOfPacketsLost(3); // total=5, dropped=3

    String s = t.toString();
    // total should be 5
    int idxTotal = s.indexOf("total=");
    int idxAfterTotal = s.indexOf(" : ", idxTotal);
    long total = Long.parseLong(s.substring(idxTotal + 6, idxAfterTotal));
    assertEquals(5L, total);

    // ratio should be approximately 0.6 (float formatting)
    int idxD = s.indexOf("d:");
    int idxClose = s.indexOf(") total=", idxD);
    double ratio = Double.parseDouble(s.substring(idxD + 2, idxClose));
    assertEquals(0.6, ratio, 1e-6);
  }

  @Test
  void maybeDisconnected_doesNotThrowAndIsCallable() {
    PacketThrottle t = new PacketThrottle(PACKET_SIZE);
    long delayBefore = t.getDelay();
    double winBefore = t.getWindowSize();
    // Coverage: ensure method is callable; behavioral verification would require concurrency.
    t.maybeDisconnected();
    // Assertion to avoid no-assert test: no state change expected
    assertEquals(delayBefore, t.getDelay(), "maybeDisconnected should not change delay");
    assertEquals(winBefore, t.getWindowSize(), 1e-9, "maybeDisconnected should not change window");
  }
}
