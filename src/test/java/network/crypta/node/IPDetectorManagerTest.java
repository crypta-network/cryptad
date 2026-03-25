package network.crypta.node;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import network.crypta.compat.DetectedIP;
import network.crypta.compat.ExternalIpDetector;
import network.crypta.compat.ForwardPort;
import network.crypta.compat.ForwardPortCallback;
import network.crypta.compat.ForwardPortStatus;
import network.crypta.compat.PortForwardProvider;
import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.Peer;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IPDetectorManagerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeIPDetector detector;
  @Mock private PeerManager peerManager;
  @Mock private NodeCrypto darknetCrypto;
  @Mock private OpennetManager opennetManager;
  @Mock private NodeCrypto opennetCrypto;
  @Mock private PriorityAwareExecutor executor;
  @Mock private Ticker ticker;
  @Mock private NodeNetworkSubsystem network;
  @Mock private NodeServicesSubsystem services;

  private IPDetectorManager newManager() {
    return new IPDetectorManager(node, detector);
  }

  @BeforeEach
  void setUp() {
    when(node.network()).thenReturn(network);
    when(node.services()).thenReturn(services);
    when(network.peers()).thenReturn(peerManager);
    when(network.darknetCrypto()).thenReturn(darknetCrypto);
    when(network.executor()).thenReturn(executor);
    when(network.ticker()).thenReturn(ticker);
    when(network.peerNodes()).thenReturn(new PeerNode[0]);
    when(network.connectedPeers()).thenReturn(new PeerNode[0]);
    when(detector.getPrimaryIPAddress(true))
        .thenReturn(new network.crypta.io.comm.FreenetInetAddress[0]);
    when(detector.hasDirectlyDetectedIP()).thenReturn(false);

    // Run submitted jobs inline for determinism
    doAnswer(
            inv -> {
              Runnable job = inv.getArgument(0);
              job.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));
    doAnswer(
            inv -> {
              Runnable job = inv.getArgument(0);
              job.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), any(String.class));
  }

  @Test
  void getUDPPortsNotForwarded_whenNoOpennetAndDarknetUnknown_expectEmpty() {
    IPDetectorManager mgr = newManager();

    when(node.network().opennet()).thenReturn(null);
    when(peerManager.anyDarknetPeers()).thenReturn(false); // -> darknet status DONT_KNOW

    int[] ports = mgr.getUDPPortsNotForwarded();
    assertEquals(0, ports.length);
  }

  @Test
  void getUDPPortsNotForwarded_whenNoOpennetAndDarknetDefinitelyNAT_expectNegativeDarknetPort() {
    IPDetectorManager mgr = newManager();

    when(node.network().opennet()).thenReturn(null);
    when(peerManager.anyDarknetPeers()).thenReturn(true);
    when(darknetCrypto.getDetectedConnectivityStatus()).thenReturn(Status.DEFINITELY_NATED);
    when(node.network().darknetPortNumber()).thenReturn(9486);

    assertArrayEquals(new int[] {-9486}, mgr.getUDPPortsNotForwarded());
  }

  @Test
  void getUDPPortsNotForwarded_whenOpennetNatAndDarknetUnknown_expectNegativeOpennetPort() {
    IPDetectorManager mgr = newManager();

    when(node.network().opennet()).thenReturn(opennetManager);
    when(opennetManager.getCrypto()).thenReturn(opennetCrypto);
    when(opennetCrypto.getDetectedConnectivityStatus()).thenReturn(Status.DEFINITELY_NATED);

    when(peerManager.anyDarknetPeers()).thenReturn(false); // DONT_KNOW on darknet
    when(opennetCrypto.getPortNumber()).thenReturn(12345);

    assertArrayEquals(new int[] {-12345}, mgr.getUDPPortsNotForwarded());
  }

  @Test
  void getUDPPortsNotForwarded_whenBothNat_expectBothPortsNegative() {
    IPDetectorManager mgr = newManager();

    when(node.network().opennet()).thenReturn(opennetManager);
    when(opennetManager.getCrypto()).thenReturn(opennetCrypto);
    when(opennetCrypto.getDetectedConnectivityStatus()).thenReturn(Status.DEFINITELY_NATED);
    when(opennetCrypto.getPortNumber()).thenReturn(56789);

    when(peerManager.anyDarknetPeers()).thenReturn(true);
    when(darknetCrypto.getDetectedConnectivityStatus()).thenReturn(Status.DEFINITELY_NATED);
    when(node.network().darknetPortNumber()).thenReturn(24680);

    assertArrayEquals(new int[] {-24680, -56789}, mgr.getUDPPortsNotForwarded());
  }

  @Test
  void getUDPPortsNotForwarded_whenBothMaybeNated_expectBothPortsPositive() {
    IPDetectorManager mgr = newManager();

    when(node.network().opennet()).thenReturn(opennetManager);
    when(opennetManager.getCrypto()).thenReturn(opennetCrypto);
    when(opennetCrypto.getDetectedConnectivityStatus()).thenReturn(Status.MAYBE_NATED);
    when(opennetCrypto.getPortNumber()).thenReturn(30000);

    when(peerManager.anyDarknetPeers()).thenReturn(true);
    when(darknetCrypto.getDetectedConnectivityStatus()).thenReturn(Status.MAYBE_NATED);
    when(node.network().darknetPortNumber()).thenReturn(40000);

    assertArrayEquals(new int[] {40000, 30000}, mgr.getUDPPortsNotForwarded());
  }

  @Test
  void registerExternalDetector_whenNull_expectNpe() {
    IPDetectorManager mgr = newManager();
    assertThrows(NullPointerException.class, () -> mgr.registerExternalDetector(null));
  }

  @Test
  void registerAndUnregisterExternalDetector_updatesState() {
    IPDetectorManager mgr = newManager();
    assertTrue(mgr.isEmpty());
    assertFalse(mgr.hasDetectors());

    ExternalIpDetector plugin = mock(ExternalIpDetector.class);
    when(plugin.getAddress()).thenReturn(new DetectedIP[0]);

    mgr.registerExternalDetector(plugin);
    assertFalse(mgr.isEmpty());
    assertTrue(mgr.hasDetectors());

    // Unregister removes it and remains stable if called again
    mgr.unregisterExternalDetector(plugin);
    assertTrue(mgr.isEmpty());
    assertFalse(mgr.hasDetectors());
    mgr.unregisterExternalDetector(plugin); // idempotent
    assertTrue(mgr.isEmpty());
  }

  @Test
  void registerPortForwardProvider_callsOnChangeWithCurrentPorts() {
    IPDetectorManager mgr = newManager();

    Set<ForwardPort> current = new HashSet<>();
    current.add(new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, 11111));
    when(node.network().publicInterfacePorts()).thenReturn(current);

    PortForwardProvider pf = mock(PortForwardProvider.class);
    mgr.registerPortForwardProvider(pf);
    verify(pf, times(1)).onChangePublicPorts(current, mgr);
  }

  @Test
  void unregisterPortForwardProvider_thenNotify_callsOnlyRemainingProviders() {
    IPDetectorManager mgr = newManager();

    PortForwardProvider pf1 = mock(PortForwardProvider.class);
    PortForwardProvider pf2 = mock(PortForwardProvider.class);

    Set<ForwardPort> initial = new HashSet<>();
    initial.add(new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, 22222));
    when(node.network().publicInterfacePorts()).thenReturn(initial);

    mgr.registerPortForwardProvider(pf1);
    mgr.registerPortForwardProvider(pf2);

    // Remove the first plugin
    reset(pf1);
    reset(pf2);
    mgr.unregisterPortForwardProvider(pf1);

    // Send a change and ensure only pf2 is invoked
    Set<ForwardPort> changed = new HashSet<>();
    changed.add(new ForwardPort("opennet", false, ForwardPort.PROTOCOL_UDP_IPV4, 33333));
    mgr.notifyPortChange(changed);
    verify(pf2, times(1)).onChangePublicPorts(changed, mgr);
    verify(pf1, times(0)).onChangePublicPorts(anySet(), any(ForwardPortCallback.class));
  }

  @Test
  void portForwardStatus_schedulesRedetect() {
    IPDetectorManager mgrReal = newManager();
    IPDetectorManager mgr = spy(mgrReal);

    Set<ForwardPort> current = new HashSet<>();
    ForwardPort fp = new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, 44444);
    current.add(fp);
    when(node.network().publicInterfacePorts()).thenReturn(current);

    Map<ForwardPort, ForwardPortStatus> statuses = new HashMap<>();
    statuses.put(
        fp, new ForwardPortStatus(ForwardPortStatus.PROBABLE_SUCCESS, "ok", fp.portNumber()));

    // maybeRun() should be invoked via executor runnable
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              r.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), any(String.class));

    mgr.portForwardStatus(statuses);
    verify(mgr, times(1)).maybeRun();
  }

  @Test
  void hasStunDetector_whenPluginRuntimeRemoved_returnsFalse() {
    IPDetectorManager mgr = newManager();
    assertFalse(mgr.hasStunDetector());
  }

  @Test
  void addConnectionTypeBox_whenNotStarted_doesNothing() {
    IPDetectorManager mgr = newManager();
    HTMLNode root = new HTMLNode("div");
    // getClientCore() is null by default -> early return
    assertDoesNotThrow(() -> mgr.addConnectionTypeBox(root));
    assertEquals(0, root.getChildren().size());
  }

  @Test
  void addConnectionTypeBox_whenProxyAlertValid_renders() throws Exception {
    IPDetectorManager mgr = newManager();

    // Provide a client core + alerts that can render
    NodeClientCore core = mock(NodeClientCore.class);
    network.crypta.runtime.alerts.UserAlertManager alerts =
        mock(network.crypta.runtime.alerts.UserAlertManager.class);
    when(core.getAlerts()).thenReturn(alerts);
    when(node.services().clientCore()).thenReturn(core);
    when(alerts.renderAlert(any())).thenReturn(new HTMLNode("div"));

    // Install a ProxyUserAlert with an underlying always-valid alert via reflection
    network.crypta.runtime.alerts.ProxyUserAlert proxy =
        new network.crypta.runtime.alerts.ProxyUserAlert(alerts, false);
    proxy.setAlert(
        new network.crypta.runtime.alerts.UserAlert() {
          @Override
          public boolean userCanDismiss() {
            return true;
          }

          @Override
          public String getTitle() {
            return "t";
          }

          @Override
          public String getText() {
            return "x";
          }

          @Override
          public HTMLNode getHTMLText() {
            return new HTMLNode("div");
          }

          @Override
          public short getPriorityClass() {
            return 0;
          }

          @Override
          public boolean isValid() {
            return true;
          }

          @Override
          public void isValid(boolean validity) {
            // Intentionally empty: this test stub does not track the alert lifecycle state.
          }

          @Override
          public String dismissButtonText() {
            return "d";
          }

          @Override
          public boolean shouldUnregisterOnDismiss() {
            return false;
          }

          @Override
          public void onDismiss() {
            // Intentionally empty: no side effects are needed for dismissal in this test.
          }

          @Override
          public String anchor() {
            return "a";
          }

          @Override
          public String getShortText() {
            return "s";
          }

          @Override
          public boolean isEventNotification() {
            return false;
          }

          @Override
          public network.crypta.clients.fcp.FCPMessage getFCPMessage() {
            return null;
          }

          @Override
          public long getUpdatedTime() {
            return System.currentTimeMillis();
          }
        });

    Field f = IPDetectorManager.class.getDeclaredField("proxyAlert");
    f.setAccessible(true);
    f.set(mgr, proxy);

    HTMLNode root = new HTMLNode("div");
    mgr.addConnectionTypeBox(root);
    assertFalse(root.getChildren().isEmpty());
  }

  @Test
  void computePeerStats_ignoresPeersWithNullAddress() throws Exception {
    IPDetectorManager mgr = newManager();

    // Prepare a peer whose FreenetInetAddress returns null for getAddress(false)
    PeerNode p = mock(PeerNode.class);
    when(p.isDisabled()).thenReturn(false);
    when(p.isConnected()).thenReturn(true);

    Peer peer = mock(Peer.class);
    when(p.getPeer()).thenReturn(peer);

    network.crypta.io.comm.FreenetInetAddress fna =
        mock(network.crypta.io.comm.FreenetInetAddress.class);
    when(peer.getFreenetAddress()).thenReturn(fna);
    when(fna.getAddress(false)).thenReturn(null);

    PeerNode[] peers = new PeerNode[] {p};
    network.crypta.io.comm.FreenetInetAddress[] nodeAddrs =
        new network.crypta.io.comm.FreenetInetAddress[0];

    // Reflectively invoke private computePeerStats(...)
    var m =
        IPDetectorManager.class.getDeclaredMethod(
            "computePeerStats",
            PeerNode[].class,
            network.crypta.io.comm.FreenetInetAddress[].class,
            long.class);
    m.setAccessible(true);
    Object stats = m.invoke(mgr, peers, nodeAddrs, System.currentTimeMillis());

    // Access record accessors reflectively: realConnections() and realDisconnected()
    int realConnections = (int) stats.getClass().getDeclaredMethod("realConnections").invoke(stats);
    int realDisconnected =
        (int) stats.getClass().getDeclaredMethod("realDisconnected").invoke(stats);

    // With a null InetAddress the peer must not be counted as usable/eligible.
    assertEquals(0, realConnections);
    assertEquals(0, realDisconnected);
  }

  @Test
  void massDisconnectsAfterSixMinutes_bypassesHourlyThrottle_andStartsDetect() throws Exception {
    IPDetectorManager mgr = newManager();

    // Ensure we have a plugin so startDetect() schedules a runner.
    ExternalIpDetector plugin = mock(ExternalIpDetector.class);
    when(plugin.getAddress()).thenReturn(new DetectedIP[0]);
    mgr.registerExternalDetector(plugin);

    // Peer manager reports some peers overall (none currently connected).
    when(peerManager.countValidPeers()).thenReturn(3);

    // Build three eligible, recently disconnected peers to trigger the override.
    long now = System.currentTimeMillis();
    PeerNode p1 = mock(PeerNode.class);
    PeerNode p2 = mock(PeerNode.class);
    PeerNode p3 = mock(PeerNode.class);
    for (PeerNode p : new PeerNode[] {p1, p2, p3}) {
      when(p.isDisabled()).thenReturn(false);
      when(p.isConnected()).thenReturn(false);
      when(p.lastReceivedPacketTime()).thenReturn(now - 60_000L); // recently connected

      Peer peer = mock(Peer.class);
      when(p.getPeer()).thenReturn(peer);
      network.crypta.io.comm.FreenetInetAddress fna =
          mock(network.crypta.io.comm.FreenetInetAddress.class);
      when(peer.getFreenetAddress()).thenReturn(fna);
      // Valid InetAddress to pass eligibility check
      when(fna.getAddress(false)).thenReturn(java.net.InetAddress.getAllByName("198.51.100.10")[0]);
    }
    when(node.network().peerNodes()).thenReturn(new PeerNode[] {p1, p2, p3});
    when(node.network().connectedPeers()).thenReturn(new PeerNode[0]);

    // Set last detect attempt to 7 minutes ago: hourly throttle active, but 6-minute override
    // applies.
    var f = IPDetectorManager.class.getDeclaredField("lastDetectAttemptEndedTime");
    f.setAccessible(true);
    f.setLong(mgr, now - 7 * 60_000L);

    // Mark manager as started so maybeRun() is effective without wiring alerts
    var fs = IPDetectorManager.class.getDeclaredField("started");
    fs.setAccessible(true);
    fs.setBoolean(mgr, true);

    // Capture startDetect via executor scheduling.
    reset(executor);
    doAnswer(_ -> null).when(executor).execute(any(Runnable.class), any(String.class));

    mgr.maybeRun();

    // Expect a detection run to be scheduled despite the hourly throttle.
    verify(executor, times(1)).execute(any(Runnable.class), any(String.class));
  }
}
