package network.crypta.node;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import network.crypta.fs.readiness.LauncherReadinessFiles;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.io.comm.TrafficClass;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;
import org.objenesis.ObjenesisStd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeTest {

  private static Node newNodeInstance() {
    // Allocate without running the heavy constructor
    return new ObjenesisStd().newInstance(Node.class);
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field f = target.getClass().getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed setting field '" + fieldName + "'", e);
    }
  }

  private static void invokeFinishToadletsIfEnabled(Node node) {
    try {
      Method method = node.getClass().getDeclaredMethod("finishToadletsIfEnabled");
      method.setAccessible(true);
      method.invoke(node);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed invoking method 'finishToadletsIfEnabled'", e);
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
    NodeNetworkSubsystem network = new NodeNetworkSubsystem(node);
    setField(node, "network", network);
    setField(network, "trafficClass", TrafficClass.DSCP_CS1);
    assertEquals(TrafficClass.DSCP_CS1, node.network().trafficClass());
  }

  @Test
  @DisplayName("getMinimumMTU_whenIpDetectorNull_returnsConfiguredMtu")
  void getMinimumMTU_whenIpDetectorNull_returnsConfiguredMtu() {
    Node node = newNodeInstance();
    NodeNetworkSubsystem network = new NodeNetworkSubsystem(node);
    setField(node, "network", network);
    setField(node, "maxPacketSize", 1500);
    assertEquals(1500, node.getMinimumMTU());
  }

  @Test
  @DisplayName("getMinimumMTU_whenDetectorLower_returnsDetectorValue")
  void getMinimumMTU_whenDetectorLower_returnsDetectorValue() {
    Node node = newNodeInstance();
    NodeNetworkSubsystem network = new NodeNetworkSubsystem(node);
    setField(node, "network", network);
    setField(node, "maxPacketSize", 1500);
    NodeIPDetector detector = mock(NodeIPDetector.class);
    when(detector.getMinimumDetectedMTU()).thenReturn(1200);
    setField(network, "ipDetector", detector);
    assertEquals(1200, node.getMinimumMTU());
  }

  @Test
  @DisplayName("getMinimumMTU_whenDetectorHigher_returnsConfiguredMtu")
  void getMinimumMTU_whenDetectorHigher_returnsConfiguredMtu() {
    Node node = newNodeInstance();
    NodeNetworkSubsystem network = new NodeNetworkSubsystem(node);
    setField(node, "network", network);
    setField(node, "maxPacketSize", 1400);
    NodeIPDetector detector = mock(NodeIPDetector.class);
    when(detector.getMinimumDetectedMTU()).thenReturn(9000);
    setField(network, "ipDetector", detector);
    assertEquals(1400, node.getMinimumMTU());
  }

  @Test
  @DisplayName("getDarknetPortNumber_delegatesToNodeCrypto")
  void getDarknetPortNumber_delegatesToNodeCrypto() {
    Node node = newNodeInstance();
    NodeNetworkSubsystem network = new NodeNetworkSubsystem(node);
    setField(node, "network", network);
    NodeCrypto crypto = mock(NodeCrypto.class);
    when(crypto.getPortNumber()).thenReturn(4545);
    setField(network, "darknetCrypto", crypto);
    assertEquals(4545, node.network().darknetPortNumber());
  }

  @Test
  @DisplayName("exportVolatileFieldSet_delegatesToNodeStats")
  void exportVolatileFieldSet_delegatesToNodeStats() {
    Node node = newNodeInstance();
    NodeNetworkSubsystem network = new NodeNetworkSubsystem(node);
    setField(node, "network", network);
    NodeStats stats = mock(NodeStats.class);
    SimpleFieldSet expected = new SimpleFieldSet(true);
    when(stats.exportVolatileFieldSet()).thenReturn(expected);
    setField(network, "nodeStats", stats);
    assertEquals(expected, node.network().exportVolatileFieldSet());
  }

  @Test
  @DisplayName("isUsingWrapper_whenNoNodeStarter_returnsFalse")
  void isUsingWrapper_whenNoNodeStarter_returnsFalse() {
    Node node = newNodeInstance();
    // nodeStarter is null by default; short-circuits WrapperManager static call
    assertFalse(node.isUsingWrapper());
  }

  @Test
  @DisplayName(
      "finishToadletsIfEnabled_whenShellEnabled_publishesLauncherReadinessAfterStartupHooks")
  void finishToadletsIfEnabled_whenShellEnabled_publishesLauncherReadinessAfterStartupHooks(
      @TempDir Path tempDir) throws Exception {
    Node node = newNodeInstance();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    HttpShellContainer toadlets = mock(HttpShellContainer.class);
    ProgramDirectory runDir = new ProgramDirectory();
    runDir.move(tempDir.toString());
    when(services.toadlets()).thenReturn(toadlets);
    when(toadlets.isEnabled()).thenReturn(true);
    when(toadlets.listenPort()).thenReturn(8888);

    setField(node, "services", services);
    setField(node, "runDir", runDir);

    invokeFinishToadletsIfEnabled(node);

    var order = inOrder(toadlets);
    order.verify(toadlets).isEnabled();
    order.verify(toadlets).finishStart();
    order.verify(toadlets).createFproxy();
    order.verify(toadlets).removeStartupToadlet();
    order.verify(toadlets).listenPort();

    Path readinessFile = LauncherReadinessFiles.resolve(tempDir);
    LauncherReadinessInfo actual = LauncherReadinessFiles.read(readinessFile).orElseThrow();
    assertEquals(LauncherReadinessInfo.ready(8888), actual);
    assertTrue(actual.isReady());
  }

  @Test
  @DisplayName("finishToadletsIfEnabled_whenReadinessPortInvalid_keepsStartupNonFatal")
  void finishToadletsIfEnabled_whenReadinessPortInvalid_keepsStartupNonFatal(@TempDir Path tempDir)
      throws Exception {
    Node node = newNodeInstance();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    HttpShellContainer toadlets = mock(HttpShellContainer.class);
    ProgramDirectory runDir = new ProgramDirectory();
    runDir.move(tempDir.toString());
    when(services.toadlets()).thenReturn(toadlets);
    when(toadlets.isEnabled()).thenReturn(true);
    when(toadlets.listenPort()).thenReturn(0);

    setField(node, "services", services);
    setField(node, "runDir", runDir);

    invokeFinishToadletsIfEnabled(node);

    var order = inOrder(toadlets);
    order.verify(toadlets).isEnabled();
    order.verify(toadlets).finishStart();
    order.verify(toadlets).createFproxy();
    order.verify(toadlets).removeStartupToadlet();
    order.verify(toadlets).listenPort();
    assertTrue(LauncherReadinessFiles.read(LauncherReadinessFiles.resolve(tempDir)).isEmpty());
  }
}
