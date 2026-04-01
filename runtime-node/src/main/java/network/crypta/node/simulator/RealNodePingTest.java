package network.crypta.node.simulator;

import java.io.File;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import network.crypta.node.PeerTransport;
import network.crypta.runtime.bootstrap.NodeStarter.TestNodeParameters;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Invokes a standalone ping test that creates two nodes, connects them, and repeatedly sends ping
 * requests while logging send/receive events and sequence numbers.
 *
 * <p>This class is a manual simulation harness for exercising end-to-end ping traffic between two
 * local darknet nodes. The {@link #main()} method sets up a temporary basis directory, initializes
 * test randomness, and configures two nodes with RAM-backed stores and high thread limits. After
 * connecting the nodes with fixed trust and visibility settings, it starts them and schedules
 * periodic {@link PeerTransport#ping(int)} calls. The scheduler runs on a single thread while the
 * nodes operate asynchronously, so the ping cadence is approximate and influenced by node activity
 * and network timing.
 *
 * <p>The test runs until interrupted and does not attempt cleanup beyond the process shutdown. It
 * is intended for local diagnostics rather than production deployments, and the hard-coded ports
 * must be free on the host.
 *
 * <ul>
 *   <li>Responsibility: create two test nodes with deterministic test configuration.
 *   <li>Responsibility: connect and start nodes, then drive a periodic ping loop.
 *   <li>Notable behavior: logs ping send/receive status using error-level messages.
 * </ul>
 *
 * @see NodeStarter
 * @see PeerTransport#ping(int)
 */
public class RealNodePingTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodePingTest.class);

  /**
   * Creates an instance of the ping test harness without additional initialization.
   *
   * <p>The class is designed to be driven through {@link #main()}, so constructing it directly is
   * rarely needed. This explicit constructor exists to provide a documented public entry point for
   * tools that inspect Javadoc, and it performs no work or side effects beyond creating the
   * instance.
   */
  private RealNodePingTest() {
    // Intentionally empty: this harness is driven via static main entry points only.
  }

  /**
   * First darknet port used by the ping test's initial node instance.
   *
   * <p>The value is derived from {@link RealNodeBusyNetworkTest#DARKNET_PORT_END} to avoid
   * collisions with other simulator tests. It represents a TCP port number and remains constant for
   * the lifetime of the process, so callers must ensure the port is available.
   */
  public static final int DARKNET_PORT1 = RealNodeBusyNetworkTest.DARKNET_PORT_END;

  /**
   * Second darknet port used by the ping test's peer node instance.
   *
   * <p>This port is one greater than {@link #DARKNET_PORT1} and is intended to be adjacent for ease
   * of inspection during local runs. It is a TCP port number and must be free on the host.
   */
  public static final int DARKNET_PORT2 = RealNodeBusyNetworkTest.DARKNET_PORT_END + 1;

  /**
   * Upper bound marker for the port range reserved by this ping test.
   *
   * <p>This constant is one greater than {@link #DARKNET_PORT2} and is provided for consistency
   * with other simulator tests that reserve a contiguous port window. It is not bound to a socket
   * directly but documents the exclusive upper limit of the chosen ports.
   */
  public static final int DARKNET_PORT_END = DARKNET_PORT2 + 1;

  static final FRIEND_TRUST trust = FRIEND_TRUST.LOW;
  static final FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NO;

  /**
   * Runs the ping simulation by creating two test nodes and scheduling periodic ping requests.
   *
   * <p>The method initializes a temporary base directory, configures two nodes with RAM-backed
   * stores and fixed resource limits, and connects them using the configured trust and visibility
   * levels. After starting both nodes, it schedules a fixed-delay task that increments a ping
   * sequence number, sends the ping, and logs success or failure. The process blocks on a latch
   * until interrupted, so it is expected to be stopped externally.
   *
   * <pre>{@code
   * // Example: run from the command line in the project root.
   * RealNodePingTest.main(new String[0]);
   * }</pre>
   *
   * @throws FSParseException if node configuration parsing fails for the local test setup.
   * @throws PeerParseException if peer references cannot be parsed during node creation.
   * @throws InterruptedException if the calling thread is interrupted during setup or wait.
   * @throws ReferenceSignatureVerificationException if a peer reference signature is invalid.
   * @throws NodeInitException if a test node fails to initialize required components.
   * @throws PeerTooOldException if the peer build is too old to establish a connection.
   */
  static void main()
      throws FSParseException,
          PeerParseException,
          InterruptedException,
          ReferenceSignatureVerificationException,
          NodeInitException,
          PeerTooOldException {
    File baseDirectory = new File("pingtest");
    RandomSource random =
        NodeStarter.globalTestInit(baseDirectory, false, Level.ERROR, "", true, null);
    // Create 2 nodes
    PriorityAwareExecutor executor = new PooledExecutor();
    TestNodeParameters node1Params =
        TestNodeParameterFactory.create(
            baseDirectory,
            random,
            executor,
            params -> {
              params.setPort(DARKNET_PORT1);
              params.setOpennetPort(0);
              params.setDisableProbabilisticHTLs(true);
              params.setMaxHTL(Node.DEFAULT_MAX_HTL);
              params.setThreadLimit(1000);
              params.setStoreSize(65536);
              params.setRamStore(true);
              params.setEnablePacketCoalescing(true);
              params.setOutputBandwidthLimit(0);
              params.setLongPingTimes(true);
            });
    Node node1 = NodeStarter.createTestNode(node1Params);
    TestNodeParameters node2Params =
        TestNodeParameterFactory.create(
            baseDirectory,
            random,
            executor,
            params -> {
              params.setPort(DARKNET_PORT2);
              params.setOpennetPort(0);
              params.setDisableProbabilisticHTLs(true);
              params.setMaxHTL(Node.DEFAULT_MAX_HTL);
              params.setThreadLimit(1000);
              params.setStoreSize(65536);
              params.setRamStore(true);
              params.setEnablePacketCoalescing(true);
              params.setOutputBandwidthLimit(0);
              params.setLongPingTimes(true);
            });
    Node node2 = NodeStarter.createTestNode(node2Params);
    // Connect
    node1.network().connect(node2, trust, visibility);
    node2.network().connect(node1, trust, visibility);
    // No swapping
    node1.start(true);
    node2.start(true);
    // Ping
    PeerNode pn = node1.network().peerNodes()[0];
    AtomicInteger pingID = new AtomicInteger();
    try (ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor()) {
      java.util.Objects.requireNonNull(
          scheduler.scheduleWithFixedDelay(
              () -> {
                int ping = pingID.getAndIncrement();
                LOG.error("Sending PING {}", ping);
                boolean success;
                boolean connected = true;
                try {
                  success = pn.transport().ping(ping);
                } catch (NotConnectedException _) {
                  LOG.error("Not connected");
                  connected = false;
                  success = false;
                }
                if (connected) {
                  if (success) LOG.error("PING {} successful", ping);
                  else LOG.error("PING FAILED: {}", ping);
                }
              },
              20,
              2,
              TimeUnit.SECONDS));
      CountDownLatch done = new CountDownLatch(1);
      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
    }
  }
}
