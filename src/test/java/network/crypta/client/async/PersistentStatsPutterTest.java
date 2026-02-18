package network.crypta.client.async;

import network.crypta.io.comm.IOStatisticCollector;
import network.crypta.node.Node;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.UptimeContainer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class PersistentStatsPutterTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private IOStatisticCollector collector;

  @Test
  @DisplayName("getters_returnSameInstances_andAreMutable")
  void getters_returnSameInstances_andAreMutable() {
    // Arrange
    PersistentStatsPutter putter = new PersistentStatsPutter();

    // Act
    BandwidthStatsContainer bw1 = putter.getLatestBWData();
    BandwidthStatsContainer bw2 = putter.getLatestBWData();
    UptimeContainer up1 = putter.getLatestUptimeData();
    UptimeContainer up2 = putter.getLatestUptimeData();

    // Mutate via returned references
    bw1.setTotalBytesIn(123L);
    bw1.setTotalBytesOut(456L);
    up1.setTotalUptime(789L);

    // Assert
    assertNotNull(bw1);
    assertNotNull(up1);
    assertSame(bw1, bw2, "BW getters must return the same instance");
    assertSame(up1, up2, "Uptime getters must return the same instance");
    assertEquals(123L, bw2.getTotalBytesIn());
    assertEquals(456L, bw2.getTotalBytesOut());
    assertEquals(789L, up2.getTotalUptime());
  }

  @Test
  @DisplayName("updateData_whenFirstCall_setsTotalsAndTimestamps")
  void updateData_whenFirstCall_setsTotalsAndTimestamps() {
    // Arrange
    when(node.network().collector()).thenReturn(collector);
    when(collector.getTotalIO()).thenReturn(new long[] {1000L, 2000L});
    when(node.network().uptime()).thenReturn(5000L);

    PersistentStatsPutter putter = new PersistentStatsPutter();

    long t0 = System.currentTimeMillis();
    // Act
    putter.updateData(node);
    long t1 = System.currentTimeMillis();

    // Assert
    BandwidthStatsContainer bw = putter.getLatestBWData();
    UptimeContainer up = putter.getLatestUptimeData();

    assertEquals(1000L, bw.getTotalBytesOut());
    assertEquals(2000L, bw.getTotalBytesIn());
    assertEquals(5000L, up.getTotalUptime());

    assertTrue(
        bw.getCreationTime() >= t0 && bw.getCreationTime() <= t1,
        "BW creation time should be set within call window");
    assertTrue(
        up.getCreationTime() >= t0 && up.getCreationTime() <= t1,
        "Uptime creation time should be set within call window");
  }

  @Test
  @DisplayName("updateData_whenSubsequentCall_accumulatesDeltaAndUpdatesTimestamps")
  void updateData_whenSubsequentCall_accumulatesDeltaAndUpdatesTimestamps() {
    // Arrange
    when(node.network().collector()).thenReturn(collector);
    when(collector.getTotalIO())
        .thenReturn(new long[] {1000L, 2000L})
        .thenReturn(new long[] {1400L, 2600L}); // +400 out, +600 in
    when(node.network().uptime()).thenReturn(5000L).thenReturn(8000L); // +3000

    PersistentStatsPutter putter = new PersistentStatsPutter();

    // First update establishes baseline
    putter.updateData(node);
    long bwTime1 = putter.getLatestBWData().getCreationTime();
    long upTime1 = putter.getLatestUptimeData().getCreationTime();

    // Act: second update applies deltas
    long t0 = System.currentTimeMillis();
    putter.updateData(node);
    long t1 = System.currentTimeMillis();

    // Assert: totals should now equal the second absolute snapshot
    BandwidthStatsContainer bw = putter.getLatestBWData();
    UptimeContainer up = putter.getLatestUptimeData();

    assertEquals(1400L, bw.getTotalBytesOut());
    assertEquals(2600L, bw.getTotalBytesIn());
    assertEquals(8000L, up.getTotalUptime());

    assertTrue(bw.getCreationTime() >= bwTime1, "BW creation time should be monotonic");
    assertTrue(up.getCreationTime() >= upTime1, "Uptime creation time should be monotonic");
    assertTrue(
        bw.getCreationTime() >= t0 && bw.getCreationTime() <= t1,
        "BW creation time should be updated within call window");
    assertTrue(
        up.getCreationTime() >= t0 && up.getCreationTime() <= t1,
        "Uptime creation time should be updated within call window");
  }

  @Test
  @DisplayName("updateData_whenCountersDecrease_handlesNegativeDelta")
  void updateData_whenCountersDecrease_handlesNegativeDelta() {
    // Arrange
    when(node.network().collector()).thenReturn(collector);
    when(collector.getTotalIO())
        .thenReturn(new long[] {1000L, 2000L})
        .thenReturn(new long[] {900L, 1500L}); // -100 out, -500 in
    when(node.network().uptime()).thenReturn(5000L).thenReturn(4500L); // -500

    PersistentStatsPutter putter = new PersistentStatsPutter();

    // First update establishes baseline
    putter.updateData(node);

    // Act: counters decreased; putter adds negative deltas
    putter.updateData(node);

    // Assert: totals should follow the latest absolute snapshot
    BandwidthStatsContainer bw = putter.getLatestBWData();
    UptimeContainer up = putter.getLatestUptimeData();
    assertEquals(900L, bw.getTotalBytesOut());
    assertEquals(1500L, bw.getTotalBytesIn());
    assertEquals(4500L, up.getTotalUptime());
  }

  @Test
  @DisplayName("addFrom_whenMerging_addsBandwidth_sumsUptimeAndAdoptsCreationTime")
  void addFrom_whenMerging_addsBandwidth_sumsUptimeAndAdoptsCreationTime() {
    // Arrange: target
    PersistentStatsPutter target = new PersistentStatsPutter();
    target.getLatestBWData().setTotalBytesOut(10L);
    target.getLatestBWData().setTotalBytesIn(20L);
    target.getLatestBWData().setCreationTime(999L);
    target.getLatestUptimeData().setTotalUptime(5L);
    target.getLatestUptimeData().setCreationTime(444L);

    // Arrange: source
    PersistentStatsPutter source = new PersistentStatsPutter();
    source.getLatestBWData().setTotalBytesOut(100L);
    source.getLatestBWData().setTotalBytesIn(200L);
    source.getLatestBWData().setCreationTime(111L);
    source.getLatestUptimeData().setTotalUptime(50L);
    source.getLatestUptimeData().setCreationTime(333L);

    // Act
    target.addFrom(source);

    // Assert
    BandwidthStatsContainer bw = target.getLatestBWData();
    UptimeContainer up = target.getLatestUptimeData();

    // Bandwidth: totals added; creationTime unchanged
    assertEquals(110L, bw.getTotalBytesOut());
    assertEquals(220L, bw.getTotalBytesIn());
    assertEquals(999L, bw.getCreationTime());

    // Uptime: total added; creationTime adopted from source
    assertEquals(55L, up.getTotalUptime());
    assertEquals(333L, up.getCreationTime());
  }

  @Test
  @DisplayName("updateData_whenNodeNull_throwsNullPointerException")
  void updateData_whenNodeNull_throwsNullPointerException() {
    // Arrange
    PersistentStatsPutter putter = new PersistentStatsPutter();

    // Act + Assert
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> putter.updateData(null));
  }
}
