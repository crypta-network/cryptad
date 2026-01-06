package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.Properties;
import network.crypta.config.PersistentConfig;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.slf4j.event.Level;
import org.tanukisoftware.wrapper.WrapperManager;

@SuppressWarnings({"java:S100", "java:S3011"})
class NodeStarterTest {

  private static final String WRAPPER_BITS_KEY = "wrapper.java.additional.auto_bits";

  @BeforeEach
  void resetStatics_before() throws ReflectiveOperationException {
    resetNodeStarterStatics();
    DNSRequester.disable = false;
  }

  @AfterEach
  void resetStatics_after() throws ReflectiveOperationException {
    // Delegate to the setup method to avoid duplicate implementation
    resetStatics_before();
  }

  @Test
  void isTestingVM_whenNotStarted_throws() {
    assertThrows(IllegalStateException.class, NodeStarter::isTestingVM);
  }

  @Test
  void globalTestInit_whenCalled_setsFlagsAndDnsAndReturnsProvidedRandom(@TempDir File tmpDir) {
    // Arrange
    DummyRandomSource rnd = new DummyRandomSource(42L);

    // Act
    RandomSource returned =
        NodeStarter.globalTestInit(tmpDir, /*enablePlug*/ false, Level.WARN, "test", true, rnd);

    // Assert
    assertSame(rnd, returned, "Should return the same RandomSource instance when provided");
    // isTestingVM requires NodeStarter to be started by globalTestInit
    assertTrue(NodeStarter.isTestingVM(), "Test VM flag should be true after init");
    assertTrue(DNSRequester.disable, "DNS should be disabled when noDNS is true");
  }

  @Test
  void createTestNode_whenCalled_constructsNodeWithPersistentConfigAndCleansPeers(
      @TempDir File tmpDir) throws Exception {
    // Arrange: initialize test VM state
    DummyRandomSource rnd = new DummyRandomSource(7L);
    NodeStarter.globalTestInit(tmpDir, false, Level.ERROR, "", true, rnd);

    NodeStarter.TestNodeParameters params = new NodeStarter.TestNodeParameters();
    params.setBaseDirectory(tmpDir);
    params.setPort(12345);
    params.setOpennetPort(0);
    params.setRandom(rnd);
    params.setExecutor(mock(network.crypta.support.PriorityAwareExecutor.class));

    // Capture constructor arguments and provide a mock PeerManager for getPeers()
    java.util.concurrent.atomic.AtomicReference<PersistentConfig> capturedCfg =
        new java.util.concurrent.atomic.AtomicReference<>();

    try (MockedConstruction<Node> mocked =
        Mockito.mockConstruction(
            Node.class,
            (mock, context) -> {
              // Capture the first constructor argument for inspection
              Object arg0 = context.arguments().getFirst();
              if (arg0 instanceof PersistentConfig pc) {
                capturedCfg.set(pc);
              }
              // getPeers() must not return null because createTestNode() calls removeAllPeers()
              PeerManager peerManager = mock(PeerManager.class);
              NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
              Mockito.doReturn(network).when(mock).network();
              Mockito.doReturn(peerManager).when(network).peers();
            })) {
      // Act
      Node node = NodeStarter.createTestNode(params);

      // Assert: one Node instance constructed
      assertEquals(1, mocked.constructed().size());
      Node constructed = mocked.constructed().getFirst();
      assertSame(constructed, node, "createTestNode should return the constructed Node instance");

      // Verify the first constructor argument is a PersistentConfig carrying our values
      PersistentConfig cfg = capturedCfg.get();
      SimpleFieldSet sfs = cfg.getSimpleFieldSet();
      // A few representative keys written by createTestNode()
      // Port and feature toggles
      assertEquals("12345", sfs.get("node.listenPort"));
      assertEquals("false", sfs.get("fproxy.enabled"));
      assertEquals("false", sfs.get("console.enabled"));
      // Per-port derived paths exist under base/port
      File portDir = new File(tmpDir, "12345");
      assertEquals(new File(portDir, "throttle.dat").toString(), sfs.get("node.throttleFile"));

      // And ensure peers list is cleared on the returned node
      verify(node.network().peers(), times(1)).removeAllPeers();
    }
  }

  @Test
  void getGlobalSecureRandom_whenCalledTwice_returnsSameInstance() {
    // Arrange & Act
    SecureRandom r1 = NodeStarter.getGlobalSecureRandom();
    SecureRandom r2 = NodeStarter.getGlobalSecureRandom();

    // Assert
    assertNotNull(r1);
    assertSame(r1, r2, "Global SecureRandom should be a singleton");
  }

  @Test
  void getMemoryLimitMB_whenUnlimitedBytes_returnsMinusTwo() {
    try (MockedStatic<NodeStarter> mocked =
        Mockito.mockStatic(NodeStarter.class, CALLS_REAL_METHODS)) {
      mocked.when(NodeStarter::getMemoryLimitBytes).thenReturn(Long.MAX_VALUE);
      assertEquals(-2L, NodeStarter.getMemoryLimitMB());
    }
  }

  @Test
  void getMemoryLimitMB_whenNegativeBytes_returnsNegativeOne() {
    try (MockedStatic<NodeStarter> mocked =
        Mockito.mockStatic(NodeStarter.class, CALLS_REAL_METHODS)) {
      mocked.when(NodeStarter::getMemoryLimitBytes).thenReturn(-1L);
      assertEquals(-1L, NodeStarter.getMemoryLimitMB());
    }
  }

  @Test
  void getMemoryLimitMB_whenExceedsIntegerMax_returnsMinusOne() {
    long bytes = ((long) Integer.MAX_VALUE + 1) * 1024L * 1024L; // just over Integer.MAX_VALUE MB
    try (MockedStatic<NodeStarter> mocked =
        Mockito.mockStatic(NodeStarter.class, CALLS_REAL_METHODS)) {
      mocked.when(NodeStarter::getMemoryLimitBytes).thenReturn(bytes);
      assertEquals(-1L, NodeStarter.getMemoryLimitMB());
    }
  }

  @Test
  void isSomething32bits_variousCombinations_matchExpectation() {
    Properties props = new Properties();
    props.setProperty(WRAPPER_BITS_KEY, "64");

    try (MockedStatic<WrapperManager> wm = Mockito.mockStatic(WrapperManager.class);
        MockedStatic<network.crypta.support.JVMVersion> jvm =
            Mockito.mockStatic(network.crypta.support.JVMVersion.class)) {
      wm.when(WrapperManager::getProperties).thenReturn(props);

      // 64-bit JVM and wrapper reports 64 -> expect true per current implementation
      jvm.when(network.crypta.support.JVMVersion::is32Bit).thenReturn(false);
      assertTrue(NodeStarter.isSomething32bits());

      // Wrapper indicates 32 -> expect false regardless of JVM size
      props.setProperty(WRAPPER_BITS_KEY, "32");
      assertFalse(NodeStarter.isSomething32bits());

      // 32-bit JVM -> expect false even if wrapper says 64
      props.setProperty(WRAPPER_BITS_KEY, "64");
      jvm.when(network.crypta.support.JVMVersion::is32Bit).thenReturn(true);
      assertFalse(NodeStarter.isSomething32bits());
    }
  }

  @Test
  void stop_whenCalled_parksNode_andSignalsStopping_andReturnsExitCode()
      throws ReflectiveOperationException {
    // Arrange
    NodeStarter ns = newNodeStarterViaReflection();
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    setNodeField(ns, node);

    try (MockedStatic<WrapperManager> wm = Mockito.mockStatic(WrapperManager.class)) {
      // Act
      int ret = ns.stop(123);

      // Assert
      assertEquals(123, ret);
      verify(node, times(1)).park();
      wm.verify(() -> WrapperManager.signalStopping(120000), times(1));
    }
  }

  @Test
  void restart_whenCalled_invokesWrapperRestart() throws ReflectiveOperationException {
    NodeStarter ns = newNodeStarterViaReflection();
    try (MockedStatic<WrapperManager> wm = Mockito.mockStatic(WrapperManager.class)) {
      ns.restart();
      wm.verify(WrapperManager::restart, times(1));
    }
  }

  @Test
  void controlEvent_whenNotControlledAndCtrlC_stopsViaWrapper()
      throws ReflectiveOperationException {
    NodeStarter ns = newNodeStarterViaReflection();
    try (MockedStatic<WrapperManager> wm = Mockito.mockStatic(WrapperManager.class)) {
      wm.when(WrapperManager::isControlledByNativeWrapper).thenReturn(false);
      ns.controlEvent(WrapperManager.WRAPPER_CTRL_C_EVENT);
      wm.verify(() -> WrapperManager.stop(0), times(1));
    }
  }

  // --- helpers ---

  private static void resetNodeStarterStatics() throws ReflectiveOperationException {
    clearStaticBoolean("isStarted");
    clearStaticBoolean("isTestingVM");
    clearStaticObject("globalSecureRandom");
    clearStaticObject("nodestarter_osgi");
  }

  private static void clearStaticBoolean(String field)
      throws NoSuchFieldException, IllegalAccessException {
    Field f = NodeStarter.class.getDeclaredField(field);
    f.setAccessible(true);
    f.setBoolean(null, false);
  }

  private static void clearStaticObject(String field)
      throws NoSuchFieldException, IllegalAccessException {
    Field f = NodeStarter.class.getDeclaredField(field);
    f.setAccessible(true);
    f.set(null, null);
  }

  private static void setNodeField(Object target, Object value)
      throws NoSuchFieldException, IllegalAccessException {
    Field f = NodeStarter.class.getDeclaredField("node");
    f.setAccessible(true);
    f.set(target, value);
  }

  private static NodeStarter newNodeStarterViaReflection() throws ReflectiveOperationException {
    var ctor = NodeStarter.class.getDeclaredConstructor();
    ctor.setAccessible(true);
    return ctor.newInstance();
  }
}
