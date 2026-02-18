package network.crypta.node;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Test method naming uses when/expect convention
class ThrottleWindowManagerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerManager peerManager;

  @Test
  @DisplayName("currentValue_whenNoPeers_usesMultiplierOneAndReturnsSimulated")
  void currentValue_whenNoPeers_usesMultiplierOneAndReturnsSimulated() {
    // Arrange
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(0);
    double def = 2.5;
    ThrottleWindowManager mgr = new ThrottleWindowManager(def, null, node);

    // Act
    double value = mgr.currentValue(false);

    // Assert
    assertEquals(def, value, 1e-9);
    assertEquals(def, mgr.realCurrentValue(), 1e-9);
    verify(peerManager).countNonBackedOffPeers(false);
  }

  @Test
  @DisplayName("currentValue_whenPeersPresent_multipliesByCount")
  void currentValue_whenPeersPresent_multipliesByCount() {
    // Arrange
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(true)).thenReturn(5);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(2);
    ThrottleWindowManager mgr = new ThrottleWindowManager(2.0, null, node);

    // Act
    double vRealTime = mgr.currentValue(true);
    double vBulk = mgr.currentValue(false);

    // Assert
    assertEquals(10.0, vRealTime, 1e-9);
    assertEquals(4.0, vBulk, 1e-9);
    verify(peerManager).countNonBackedOffPeers(true);
    verify(peerManager).countNonBackedOffPeers(false);
  }

  @Test
  @DisplayName("currentValue_whenBelowOne_clampsAndUpdatesState")
  void currentValue_whenBelowOne_clampsAndUpdatesState() {
    // Arrange
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(0);
    ThrottleWindowManager mgr = new ThrottleWindowManager(0.25, null, node);

    // Act
    double value = mgr.currentValue(false);

    // Assert
    assertEquals(1.0, value, 1e-9);
    assertEquals(1.0, mgr.realCurrentValue(), 1e-9); // internal state clamped
  }

  @Test
  @DisplayName("rejectedOverload_whenCalled_incrementsDroppedAndTotalAndMultipliesWindow")
  void rejectedOverload_whenCalled_incrementsDroppedAndTotalAndMultipliesWindow() {
    // Arrange
    ThrottleWindowManager mgr = new ThrottleWindowManager(2.0, null, node);

    // Act
    mgr.rejectedOverload();

    // Assert
    double expected = 2.0 * ThrottleWindowManager.PACKET_DROP_DECREASE_MULTIPLE;
    assertEquals(expected, mgr.realCurrentValue(), 1e-9);
    SimpleFieldSet fs = mgr.exportFieldSet(true);
    assertEquals(1, fs.getInt("TotalPackets", -1));
    assertEquals(1, fs.getInt("DroppedPackets", -1));
  }

  @Test
  @DisplayName("requestCompleted_whenCalled_incrementsTotalAndAdditivelyIncreasesWindow")
  void requestCompleted_whenCalled_incrementsTotalAndAdditivelyIncreasesWindow() {
    // Arrange
    ThrottleWindowManager mgr = new ThrottleWindowManager(1.0, null, node);

    // Act
    mgr.requestCompleted();

    // Assert
    @SuppressWarnings("PointlessArithmeticExpression")
    double expected = 1.0 + (ThrottleWindowManager.PACKET_TRANSMIT_INCREMENT / 1.0);
    assertEquals(expected, mgr.realCurrentValue(), 1e-9);
    SimpleFieldSet fs = mgr.exportFieldSet(false);
    assertEquals(1, fs.getInt("TotalPackets", -1));
    assertEquals(0, fs.getInt("DroppedPackets", -1));
  }

  @Test
  @DisplayName("constructor_withFieldSet_loadsValues")
  void constructor_withFieldSet_loadsValues() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.put("TotalPackets", 10);
    sfs.put("DroppedPackets", 3);
    sfs.put("SimulatedWindowSize", 1.5);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.countNonBackedOffPeers(true)).thenReturn(4);
    when(peerManager.countNonBackedOffPeers(false)).thenReturn(0);

    // Act
    ThrottleWindowManager mgr = new ThrottleWindowManager(2.0, sfs, node);

    // Assert
    assertEquals(1.5, mgr.realCurrentValue(), 1e-9);
    SimpleFieldSet out = mgr.exportFieldSet(false);
    assertEquals(10, out.getInt("TotalPackets", -1));
    assertEquals(3, out.getInt("DroppedPackets", -1));
    assertEquals(1.5, out.getDouble("SimulatedWindowSize", -1), 1e-9);

    // And currentValue respects peer multiplier
    assertEquals(1.5, mgr.currentValue(false), 1e-9);
    assertEquals(6.0, mgr.currentValue(true), 1e-9);
  }

  @Test
  @DisplayName("toString_whenZeroTotals_containsWindowAndNoDivisionError")
  void toString_whenZeroTotals_containsWindowAndNoDivisionError() {
    // Arrange
    ThrottleWindowManager mgr = new ThrottleWindowManager(2.0, null, node);

    // Act
    String s = mgr.toString();

    // Assert
    assertTrue(s.contains("w: 2.0"));
    assertTrue(s.contains("=0/0")); // format includes "=<dropped>/<total>"
  }
}
