package network.crypta.node.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import network.crypta.crypt.RandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Standalone bootstrap smoke-test for the simulator node.
 *
 * <p>This class starts a single node configured to connect to a local {@code seednodes.fref} file,
 * then waits until the node reports that it has reached the OpenNet announcement threshold (i.e.,
 * the number of connected OpenNet peers required for the node to consider itself bootstrapped).
 * Progress is reported once per second via log messages so the run can be monitored from a console
 * or CI log.
 *
 * <p>The entry point is {@link #main(String[])}, which sets up an isolated data directory, copies
 * the seednodes file into the per-port node directory, starts the node, and exits with a
 * deterministic status code for success and common failure modes. This is intended for developer
 * troubleshooting and for validating that bootstrapping still works end-to-end against a known
 * seednodes list.
 *
 * <ul>
 *   <li><b>Inputs:</b> a readable {@code seednodes.fref} in the working directory; optional IP
 *       override as {@code args[0]}.
 *   <li><b>Outputs:</b> creates/overwrites {@code bootstrap-test/} and exits the JVM with a status
 *       code indicating the observed outcome.
 *   <li><b>Threading:</b> the node runs background threads; this class itself performs
 *       orchestration from the main thread and waits using {@link Thread#sleep(long)}.
 * </ul>
 */
public class BootstrapSeedTest {
  private static final Logger LOG = LoggerFactory.getLogger(BootstrapSeedTest.class);

  /**
   * Creates a new bootstrap test runner instance.
   *
   * <p>This type is primarily used as a standalone tool via {@link #main(String[])}, which performs
   * all setup and execution using static orchestration. The constructor is intentionally trivial
   * and exists to document the implicitly-available public no-argument constructor so that doclint
   * can validate this file without warnings.
   */
  public BootstrapSeedTest() {
    /* Intentionally empty: this is a static entry-point utility. */
  }

  static final int EXIT_NO_SEEDNODES = 257;
  static final int EXIT_FAILED_TARGET = 258;
  static final int EXIT_THREW_SOMETHING = 259;

  static final int DARKNET_PORT = 5006;
  static final int OPENNET_PORT = 5007;

  private static boolean waitUntilBootstrapped(Node node, int targetPeers, long startTime)
      throws InterruptedException {
    int seconds = 0;
    while (seconds < 600) {
      Thread.sleep(1000);
      int seeds = node.network().peers().countSeednodes();
      int seedConns =
          node.network().peers().seedPeers().getConnectedSeedServerPeersVector(null).size();
      int opennetPeers = node.network().peers().countValidPeers();
      int opennetConns = node.network().peers().countConnectedOpennetPeers();
      LOG.error(
          "{} : seeds: {}, connected: {} opennet: peers: {}, connected: {}",
          seconds,
          seeds,
          seedConns,
          opennetPeers,
          opennetConns);
      seconds++;

      if (opennetConns >= targetPeers) {
        long timeTaken = System.currentTimeMillis() - startTime;
        if (LOG.isErrorEnabled()) {
          LOG.error(
              "Completed bootstrap ({} peers) in {}ms ({})",
              targetPeers,
              timeTaken,
              TimeUtil.formatTime(timeTaken));
        }
        node.park();
        return true;
      }
    }

    LOG.error("Failed to reach target peers count {} in 5 minutes.", targetPeers);
    node.park();
    return false;
  }

  /**
   * Runs the bootstrap test from a fresh local data directory.
   *
   * <p>This method deletes any prior {@code bootstrap-test} directory, initializes the global test
   * environment, copies {@code seednodes.fref} into the node's per-port directory, and starts a
   * single node configured to connect to seednodes. It then waits for up to five minutes for the
   * node to reach the OpenNet announcement threshold, parking the node before exiting.
   *
   * <p>Progress is logged once per second and the process exits with one of the {@code EXIT_*}
   * constants to make failures easy to triage in scripts.
   *
   * @param args command-line arguments; if present, {@code args[0]} is used as an IP address
   *     override for the node's external address and may be {@code null} or empty to disable the
   *     override
   * @throws NodeInitException if creating or starting the test node fails during initialization
   * @throws InterruptedException if the current thread is interrupted while waiting for bootstrap
   *     to complete; the interrupt flag is preserved on exit
   * @throws IOException if required filesystem operations fail, such as creating the data directory
   *     or copying {@code seednodes.fref}
   */
  public static void main(String[] args)
      throws NodeInitException, InterruptedException, IOException {
    Node node = null;
    try {
      String ipOverride = null;
      if (args.length > 0) ipOverride = args[0];
      final String ipOverrideFinal = ipOverride;
      File dir = new File("bootstrap-test");
      FileUtil.removeAll(dir);
      RandomSource random = NodeStarter.globalTestInit(dir, false, Level.ERROR, "", false, null);
      File seednodes = new File("seednodes.fref");
      if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        LOG.error("Unable to read seednodes.fref, it doesn't exist, or is empty");
        System.exit(EXIT_NO_SEEDNODES);
      }
      File innerDir = new File(dir, Integer.toString(DARKNET_PORT));
      if (!innerDir.mkdirs() && !innerDir.isDirectory()) {
        throw new IOException("Failed to create directory: " + innerDir.getAbsolutePath());
      }
      try (FileInputStream fis = new FileInputStream(seednodes)) {
        FileUtil.writeTo(fis, new File(innerDir, "seednodes.fref"));
      }
      // Create one node
      PriorityAwareExecutor executor = new PooledExecutor();
      TestNodeParameters params =
          TestNodeParameterFactory.create(
              dir,
              random,
              executor,
              p -> {
                p.setPort(DARKNET_PORT);
                p.setOpennetPort(OPENNET_PORT);
                p.setMaxHTL(Node.DEFAULT_MAX_HTL);
                p.setThreadLimit(1000);
                p.setStoreSize(5L * 1024 * 1024);
                p.setRamStore(true);
                p.setEnableSwapping(true);
                p.setEnableARKs(true);
                p.setEnableULPRs(true);
                p.setEnablePerNodeFailureTables(true);
                p.setEnableSwapQueueing(true);
                p.setEnablePacketCoalescing(true);
                p.setOutputBandwidthLimit(12 * 1024);
                p.setConnectToSeednodes(true);
                p.setIpAddressOverride(ipOverrideFinal);
              });
      node = NodeStarter.createTestNode(params);
      Logging.setRootLevel(Level.ERROR); // kill logging
      long startTime = System.currentTimeMillis();
      // Start it
      node.start(true);
      // Wait until we have 10 connected nodes...
      int targetPeers = node.network().opennet().getAnnouncementThreshold();
      if (waitUntilBootstrapped(node, targetPeers, startTime)) {
        System.exit(0);
      }
      System.exit(EXIT_FAILED_TARGET);
    } catch (Exception e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      LOG.error("CAUGHT: {}", e, e);
      try {
        if (node != null) node.park();
      } catch (Exception e1) {
        LOG.error("Failed to park node during cleanup after failure.", e1);
      }
      System.exit(EXIT_THREW_SOMETHING);
    }
  }
}
