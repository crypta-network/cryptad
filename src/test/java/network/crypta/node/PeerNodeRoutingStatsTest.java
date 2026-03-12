package network.crypta.node;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerNodeRoutingStatsTest {
  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  private PeerNodeRoutingStats newStats() {
    return new PeerNodeRoutingStats(node);
  }

  @Test
  void averageSwapInterval_whenNoReports_expectDefaultMinInterval() {
    PeerNodeRoutingStats stats = newStats();

    double average = stats.averageSwapInterval();

    assertEquals(Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS, average, 0.0);
  }

  @Test
  void averageSwapInterval_whenReportsProvided_expectWindowMean() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportSwapInterval(100);
    stats.reportSwapInterval(200);

    assertEquals(150.0, stats.averageSwapInterval(), 0.0);
  }

  @Test
  void averageProbeInterval_whenNoReports_expectDefaultMinInterval() {
    PeerNodeRoutingStats stats = newStats();

    double average = stats.averageProbeInterval();

    assertEquals(Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS, average, 0.0);
  }

  @Test
  void averageProbeInterval_whenReportsProvided_expectWindowMean() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportProbeInterval(300);
    stats.reportProbeInterval(700);

    assertEquals(500.0, stats.averageProbeInterval(), 0.0);
  }

  @Test
  void averagePingTime_whenNoReports_expectDefaultValue() {
    PeerNodeRoutingStats stats = newStats();

    double average = stats.averagePingTime();

    assertEquals(1.0, average, 0.0);
  }

  @Test
  void averagePingTime_whenFirstReportProvided_expectReportedValue() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportPing(123L);

    assertEquals(123.0, stats.averagePingTime(), 0.0);
  }

  @Test
  void pRejected_whenReportNotRejectedFirst_expectZero() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportNotRejectedOverload();

    assertEquals(0.0, stats.pRejected(), 0.0);
  }

  @Test
  void pRejected_whenReportRejectedFirst_expectOne() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportRejectedOverload();

    assertEquals(1.0, stats.pRejected(), 0.0);
  }

  @Test
  void reportBackoffStatus_whenFirstCallBeforeLastSample_expectNoUpdate() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportBackoffStatus(1000, 2000, 2000);

    assertEquals(0.0, stats.backedOffPercentRT(), 0.0);
    assertEquals(0.0, stats.backedOffPercentBulk(), 0.0);
    assertEquals(0.0, stats.backedOffPercent(), 0.0);
  }

  @Test
  void reportBackoffStatus_whenBackedOff_expectOne() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportBackoffStatus(1000, 0, 0);
    stats.reportBackoffStatus(2000, 2500, 2500);

    assertEquals(1.0, stats.backedOffPercentRT(), 0.0);
    assertEquals(1.0, stats.backedOffPercentBulk(), 0.0);
    assertEquals(1.0, stats.backedOffPercent(), 0.0);
  }

  @Test
  void reportBackoffStatus_whenBackoffEndsDuringInterval_expectFractionAndMin() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportBackoffStatus(1000, 0, 0);
    stats.reportBackoffStatus(2000, 1500, 2500);

    assertEquals(0.5, stats.backedOffPercentRT(), 0.000001);
    assertEquals(1.0, stats.backedOffPercentBulk(), 0.0);
    assertEquals(0.5, stats.backedOffPercent(), 0.000001);
  }

  @Test
  void reportBackoffStatus_whenCalledSameMillisecond_expectNoSecondUpdate() {
    PeerNodeRoutingStats stats = newStats();

    stats.reportBackoffStatus(1000, 0, 0);
    stats.reportBackoffStatus(2000, 2500, 2500);
    stats.reportBackoffStatus(2000, 1000, 1000);

    assertEquals(1.0, stats.backedOffPercentRT(), 0.0);
    assertEquals(1.0, stats.backedOffPercentBulk(), 0.0);
    assertEquals(1.0, stats.backedOffPercent(), 0.0);
  }
}
