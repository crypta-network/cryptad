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

public class BootstrapSeedTest {
  private static final Logger LOG = LoggerFactory.getLogger(BootstrapSeedTest.class);

  public static int EXIT_NO_SEEDNODES = 257;
  public static int EXIT_FAILED_TARGET = 258;
  public static int EXIT_THREW_SOMETHING = 259;

  public static int DARKNET_PORT = 5006;
  public static int OPENNET_PORT = 5007;

  /**
   * @param args
   * @throws NodeInitException
   * @throws InterruptedException
   * @throws IOException
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
        System.err.println("Unable to read seednodes.fref, it doesn't exist, or is empty");
        System.exit(EXIT_NO_SEEDNODES);
      }
      File innerDir = new File(dir, Integer.toString(DARKNET_PORT));
      innerDir.mkdir();
      FileInputStream fis = new FileInputStream(seednodes);
      FileUtil.writeTo(fis, new File(innerDir, "seednodes.fref"));
      fis.close();
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
                p.setStoreSize(5 * 1024 * 1024);
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
      // NodeCrypto.DISABLE_GROUP_STRIP = true;
      // Logging.bootstrap(Level.DEBUG,
      // "freenet:NORMAL,freenet.node.NodeDispatcher:MINOR,freenet.node.FNPPacketMangler:MINOR");
      Logging.setRootLevel(Level.ERROR); // kill logging
      long startTime = System.currentTimeMillis();
      // Start it
      node.start(true);
      // Wait until we have 10 connected nodes...
      int seconds = 0;
      int targetPeers = node.getOpennet().getAnnouncementThreshold();
      while (seconds < 600) {
        Thread.sleep(1000);
        int seeds = node.getPeers().countSeednodes();
        int seedConns = node.getPeers().getConnectedSeedServerPeersVector(null).size();
        int opennetPeers = node.getPeers().countValidPeers();
        int opennetConns = node.getPeers().countConnectedOpennetPeers();
        System.err.println(
            seconds
                + " : seeds: "
                + seeds
                + ", connected: "
                + seedConns
                + " opennet: peers: "
                + opennetPeers
                + ", connected: "
                + opennetConns);
        seconds++;
        if (opennetConns >= targetPeers) {
          long timeTaken = System.currentTimeMillis() - startTime;
          System.out.println(
              "Completed bootstrap ("
                  + targetPeers
                  + " peers) in "
                  + timeTaken
                  + "ms ("
                  + TimeUtil.formatTime(timeTaken)
                  + ")");
          node.park();
          System.exit(0);
        }
      }
      System.err.println("Failed to reach target peers count " + targetPeers + " in 5 minutes.");
      node.park();
      System.exit(EXIT_FAILED_TARGET);
    } catch (Throwable t) {
      System.err.println("CAUGHT: " + t);
      t.printStackTrace();
      try {
        if (node != null) node.park();
      } catch (Throwable t1) {
      }
      System.exit(EXIT_THREW_SOMETHING);
    }
  }
}
