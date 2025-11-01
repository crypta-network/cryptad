package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.io.comm.TrafficClass;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.objenesis.ObjenesisStd;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeTest {

  private static Node newNodeInstance() {
    // Allocate without running the heavy constructor
    return new ObjenesisStd().newInstance(Node.class);
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field f = Node.class.getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed setting field '" + fieldName + "'", e);
    }
  }

  @Test
  @DisplayName("getMinimumBandwidth_returns_expected_constant")
  void getMinimumBandwidth_returns_expected_constant() {
    assertEquals(10 * 1024, Node.getMinimumBandwidth());
  }

  @Test
  @DisplayName("maxHTL_whenFieldSet_returnsSameValue")
  void maxHTL_whenFieldSet_returnsSameValue() {
    Node node = newNodeInstance();
    short expected = 18;
    setField(node, "maxHTL", expected);
    assertEquals(expected, node.maxHTL());
  }

  @Test
  @DisplayName("getTrafficClass_whenSet_returnsSameValue")
  void getTrafficClass_whenSet_returnsSameValue() {
    Node node = newNodeInstance();
    setField(node, "trafficClass", TrafficClass.DSCP_CS1);
    assertEquals(TrafficClass.DSCP_CS1, node.getTrafficClass());
  }

  @Test
  @DisplayName("getMinimumMTU_whenIpDetectorNull_returnsConfiguredMtu")
  void getMinimumMTU_whenIpDetectorNull_returnsConfiguredMtu() {
    Node node = newNodeInstance();
    setField(node, "maxPacketSize", 1500);
    setField(node, "ipDetector", null);
    assertEquals(1500, node.getMinimumMTU());
  }

  @Test
  @DisplayName("getMinimumMTU_whenDetectorLower_returnsDetectorValue")
  void getMinimumMTU_whenDetectorLower_returnsDetectorValue() {
    Node node = newNodeInstance();
    setField(node, "maxPacketSize", 1500);
    NodeIPDetector detector = mock(NodeIPDetector.class);
    when(detector.getMinimumDetectedMTU()).thenReturn(1200);
    setField(node, "ipDetector", detector);
    assertEquals(1200, node.getMinimumMTU());
  }

  @Test
  @DisplayName("getMinimumMTU_whenDetectorHigher_returnsConfiguredMtu")
  void getMinimumMTU_whenDetectorHigher_returnsConfiguredMtu() {
    Node node = newNodeInstance();
    setField(node, "maxPacketSize", 1400);
    NodeIPDetector detector = mock(NodeIPDetector.class);
    when(detector.getMinimumDetectedMTU()).thenReturn(9000);
    setField(node, "ipDetector", detector);
    assertEquals(1400, node.getMinimumMTU());
  }

  @Test
  @DisplayName("getDarknetPortNumber_delegatesToNodeCrypto")
  void getDarknetPortNumber_delegatesToNodeCrypto() {
    Node node = newNodeInstance();
    NodeCrypto crypto = mock(NodeCrypto.class);
    when(crypto.getPortNumber()).thenReturn(4545);
    setField(node, "darknetCrypto", crypto);
    assertEquals(4545, node.getDarknetPortNumber());
  }

  @Test
  @DisplayName("exportVolatileFieldSet_delegatesToNodeStats")
  void exportVolatileFieldSet_delegatesToNodeStats() {
    Node node = newNodeInstance();
    NodeStats stats = mock(NodeStats.class);
    SimpleFieldSet expected = new SimpleFieldSet(true);
    when(stats.exportVolatileFieldSet()).thenReturn(expected);
    setField(node, "nodeStats", stats);
    assertEquals(expected, node.exportVolatileFieldSet());
  }

  @Test
  @DisplayName("isUsingWrapper_whenNoNodeStarter_returnsFalse")
  void isUsingWrapper_whenNoNodeStarter_returnsFalse() {
    Node node = newNodeInstance();
    // nodeStarter is null by default; short-circuits WrapperManager static call
    assertFalse(node.isUsingWrapper());
  }
}
