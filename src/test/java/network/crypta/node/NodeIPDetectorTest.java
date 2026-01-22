package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.useralerts.InvalidAddressOverrideUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.pluginmanager.DetectedIP;
import network.crypta.pluginmanager.FredPluginIPDetector;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeIPDetectorTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PriorityAwareExecutor executor;
  @Mock private NodeNetworkSubsystem network;
  @Mock private PeerManager peers;

  @BeforeEach
  void setUpNodeBasics() {
    lenient().when(node.network()).thenReturn(network);
    lenient().when(network.executor()).thenReturn(executor);
    lenient().when(network.peers()).thenReturn(peers);
    lenient().when(peers.myPeers()).thenReturn(new PeerNode[0]);
  }

  // Helper: prime the internal IPAddressDetector snapshot to avoid real network enumeration
  private static void primeIpDetector(NodeIPDetector detector, InetAddress... addrs)
      throws Exception {
    Field f = NodeIPDetector.class.getDeclaredField("ipDetector");
    f.setAccessible(true);
    Object ipd = f.get(detector);

    Field last = ipd.getClass().getDeclaredField("lastAddressList");
    last.setAccessible(true);
    last.set(ipd, addrs);

    Field ts = ipd.getClass().getDeclaredField("lastDetectedTime");
    ts.setAccessible(true);
    // Far in the future so no checkpoint() is triggered by getAddress*()
    ts.setLong(ipd, System.currentTimeMillis() + 86_400_000L);
  }

  private static InetAddress ip(String s) throws UnknownHostException {
    return InetAddress.getByName(s);
  }

  @Test
  @DisplayName("hasDirectlyDetectedIP returns true for routable and false for local-only addresses")
  void hasDirectlyDetectedIP_whenAddressesProvided_expectCorrectClassification() throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);

    // Routable IPv4 (TEST-NET-3; treated as public by IPUtil rules)
    primeIpDetector(det, ip("203.0.113.10"));
    assertTrue(det.hasDirectlyDetectedIP());

    // Only loopback
    primeIpDetector(det, ip("127.0.0.1"));
    assertFalse(det.hasDirectlyDetectedIP());
  }

  @Test
  @DisplayName("redetectAddress writes node file only when address set changes")
  void redetectAddress_whenNoChange_doesNotRewriteNodeFile() throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);
    when(network.dontDetect()).thenReturn(false);

    InetAddress a = ip("203.0.113.10");
    primeIpDetector(det, a);

    // First detection writes a file
    det.redetectAddress();
    verify(node).writeNodeFile();

    // Same addresses -> early return, no write
    reset(node);
    when(node.network()).thenReturn(network);
    when(node.services().clientCore()).thenReturn(null);
    when(network.dontDetect()).thenReturn(false);

    primeIpDetector(det, a);
    det.redetectAddress();
    verify(node, never()).writeNodeFile();
  }

  @Test
  @DisplayName("processDetectedIPs reports MTU and triggers re-detect + write")
  void processDetectedIPs_whenPluginReports_expectMtuUpdateAndWrite() throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);
    when(node.services().clientCore()).thenReturn(null);
    when(network.peers()).thenReturn(null);
    when(network.dontDetect()).thenReturn(false);

    // No direct-detected addresses; plugin IPs should be considered
    primeIpDetector(det /* none */);

    DetectedIP v4 = new DetectedIP(ip("203.0.113.7"), DetectedIP.FULL_INTERNET);
    v4.setMtu(1480);
    DetectedIP v6 = new DetectedIP(ip("2001:db8::1"), DetectedIP.FULL_INTERNET);
    v6.setMtu(1280);

    det.processDetectedIPs(new DetectedIP[] {v4, v6});

    // Two MTU reports (v4 and v6) -> two updates
    verify(network, org.mockito.Mockito.times(2)).updateMTU();
    verify(node).writeNodeFile();

    // Verify the tracked minimum MTUs reflect reports
    assertEquals(1480, det.getMinimumDetectedMTU(false));
    assertEquals(1280, det.getMinimumDetectedMTU(true));
    assertEquals(1280, det.getMinimumDetectedMTU());
  }

  @Test
  @DisplayName("getMinimumDetectedMTU tracks per-family minimums and overall minimum")
  void getMinimumDetectedMTU_whenReporting_expectPerFamilyAndOverallMinimums() {
    NodeIPDetector det = new NodeIPDetector(node);

    // Defaults (no reports yet) return the internal initial sentinel (Integer.MAX_VALUE)
    assertEquals(Integer.MAX_VALUE, det.getMinimumDetectedMTU(false));
    assertEquals(Integer.MAX_VALUE, det.getMinimumDetectedMTU(true));
    assertEquals(Integer.MAX_VALUE, det.getMinimumDetectedMTU());

    // The first valid report lowers the minima and triggers node.network().updateMTU()
    det.reportMTU(1400, false);
    verify(network).updateMTU();
    assertEquals(1400, det.getMinimumDetectedMTU(false));
    assertEquals(1400, det.getMinimumDetectedMTU());

    // Zero/negative are ignored and do not trigger updates
    clearInvocations(network);
    det.reportMTU(0, false);
    det.reportMTU(-1, true);
    verify(network, never()).updateMTU();

    // IPv6 report lowers overall minimum and triggers update
    det.reportMTU(1300, true);
    verify(network).updateMTU();
    assertEquals(1300, det.getMinimumDetectedMTU(true));
    assertEquals(1300, det.getMinimumDetectedMTU());
  }

  @Test
  @DisplayName("isDetecting flips to false after plugin manager and local detection complete")
  void isDetecting_whenPMAndIADComplete_expectFalse() throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);
    when(network.dontDetect()).thenReturn(false);
    assertTrue(det.isDetecting()); // neither PM nor IAD completed

    // Complete IPAddressDetector path by redetecting once
    primeIpDetector(det, ip("203.0.113.20"));
    det.redetectAddress();
    assertTrue(det.isDetecting()); // PM isn't yet signaled

    // Signal plugin manager completion
    det.hasDetectedPM();
    assertFalse(det.isDetecting());
  }

  @Test
  @DisplayName("registerConfigs: allowBindToLocalhost change throws restart; override validates")
  void registerConfigs_whenChangingOptions_expectValidationAndRestart() throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);

    // Real SubConfig via Config factory
    Config cfg = new Config();
    SubConfig nodeCfg = cfg.createSubConfig("node");

    int ret = det.registerConfigs(nodeCfg, 0);
    assertEquals(3, ret); // three options registered

    // allowBindToLocalhost: change triggers NodeNeedRestartException
    Option<?> allowLocal = nodeCfg.getOption("allowBindToLocalhost");
    assertThrows(NodeNeedRestartException.class, () -> allowLocal.setValue("true"));

    // ipAddressOverride: invalid syntax
    Option<?> override = nodeCfg.getOption("ipAddressOverride");
    assertThrows(InvalidConfigValueException.class, () -> override.setValue("bad host$"));

    // ipAddressOverride: a valid hostname triggers redetect and keeps hostname-only entry
    // Force detector to avoid direct detection so only the override is considered
    when(network.dontDetect()).thenReturn(true);
    when(node.services().clientCore()).thenReturn(null);
    override.setValue("example.com");
    verify(node).writeNodeFile();
    FreenetInetAddress[] addrs = det.getPrimaryIPAddress(true);
    assertEquals(1, addrs.length);
    assertTrue(addrs[0].hasHostnameNoIP());
  }

  @Test
  @DisplayName("Clearing ipAddressOverride resets validity and unregisters invalid-override alert")
  void ipAddressOverride_whenCleared_restoresValidityAndUnregistersAlert() throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);

    // Wire a real SubConfig so the override callback is active
    Config cfg = new Config();
    SubConfig nodeCfg = cfg.createSubConfig("node");
    det.registerConfigs(nodeCfg, 0);

    // Provide client core + alerts so unregister() is observable
    NodeClientCore clientCore = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.services().clientCore()).thenReturn(clientCore);

    // Simulate a prior invalid override state so clearing should flip the flag and unregister
    Field f = NodeIPDetector.class.getDeclaredField("hasValidAddressOverride");
    f.setAccessible(true);
    f.setBoolean(det, false);
    assertFalse(det.hasValidAddressOverride());

    // Clear the override via the config API
    Option<?> override = nodeCfg.getOption("ipAddressOverride");
    override.setValue("");

    // Validity restored and alert unregistered
    assertTrue(det.hasValidAddressOverride());
    verify(alerts)
        .unregister(
            ArgumentMatchers.<UserAlert>argThat(InvalidAddressOverrideUserAlert.class::isInstance));
  }

  @Test
  @DisplayName("Clearing override before client core init does not throw and resets validity")
  void ipAddressOverride_whenClearedBeforeClientCore_expectNoNPEAndValidityRestored()
      throws Exception {
    NodeIPDetector det = new NodeIPDetector(node);

    // Wire a real SubConfig so the override callback is active
    Config cfg = new Config();
    SubConfig nodeCfg = cfg.createSubConfig("node");
    det.registerConfigs(nodeCfg, 0);

    // Simulate startup: no client core yet
    when(node.services().clientCore()).thenReturn(null);

    // Pretend we were in an invalid-override state
    Field f = NodeIPDetector.class.getDeclaredField("hasValidAddressOverride");
    f.setAccessible(true);
    f.setBoolean(det, false);
    assertFalse(det.hasValidAddressOverride());

    // Clear via config API; should not throw
    Option<?> override = nodeCfg.getOption("ipAddressOverride");
    override.setValue("");

    // Validity restored
    assertTrue(det.hasValidAddressOverride());
  }

  @Test
  @DisplayName("setMaybeSymmetric registers or unregisters alert based on plugin presence")
  void setMaybeSymmetric_whenPluginsChange_expectAlertToggle() {
    NodeIPDetector det = new NodeIPDetector(node);

    // Provide a client core + alerts to observe registrations
    NodeClientCore clientCore = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.services().clientCore()).thenReturn(clientCore);

    // With no plugins, the method registers the alert
    det.setMaybeSymmetric();
    verify(alerts).register(any(UserAlert.class));

    // Register a detector plugin; the method should now unregister the alert
    FredPluginIPDetector plugin = mock(FredPluginIPDetector.class);
    det.registerIPDetectorPlugin(plugin);
    det.setMaybeSymmetric();
    verify(alerts).unregister(any(UserAlert.class));
  }
}
