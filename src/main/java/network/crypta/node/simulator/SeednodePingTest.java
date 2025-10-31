package network.crypta.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.Announcer;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.SeedServerPeerNode;
import network.crypta.node.SeedServerTestPeerNode;
import network.crypta.node.SeedServerTestPeerNode.FATE;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import org.slf4j.event.Level;

/**
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class SeednodePingTest extends RealNodeTest {

  static File STATUS_DIR = new File("/var/www/freenet/tests/seednodes/status/");
  static final long COUNT_SUCCESSES_PERIOD = DAYS.toMillis(7);

  static final int DARKNET_PORT = RealNodeULPRTest.DARKNET_PORT_END;
  static final int OPENNET_PORT = DARKNET_PORT + 1;

  public static void main(String[] args)
      throws FSParseException,
          IOException,
          OpennetDisabledException,
          PeerParseException,
          InterruptedException,
          ReferenceSignatureVerificationException,
          NodeInitException {
    Node node = null;
    try {
      if (args.length == 1) STATUS_DIR = new File(args[0]);
      File baseDir = new File("seednode-pingtest");
      RandomSource random =
          NodeStarter.globalTestInit(baseDir, false, Level.ERROR, "", false, null);
      // Create one node
      PriorityAwareExecutor executor = new PooledExecutor();
      TestNodeParameters params = new TestNodeParameters();
      params.setBaseDirectory(baseDir);
      params.setPort(DARKNET_PORT);
      params.setOpennetPort(OPENNET_PORT);
      params.setMaxHTL(Node.DEFAULT_MAX_HTL);
      params.setRandom(random);
      params.setExecutor(executor);
      params.setThreadLimit(1000);
      params.setStoreSize(5 * 1024 * 1024);
      params.setRamStore(true);
      params.setOutputBandwidthLimit(0);
      node = NodeStarter.createTestNode(params);
      // Connect & ping
      List<SeedServerTestPeerNode> seedNodes = new ArrayList<>();
      List<SimpleFieldSet> seedNodesAsSFS =
          Announcer.readSeednodes(new File("/tmp/", NodeFile.SEEDNODES.getFilename()));
      int numberOfNodesInTheFile = 0;
      for (SimpleFieldSet sfs : seedNodesAsSFS) {
        numberOfNodesInTheFile++;
        SeedServerTestPeerNode seednode = node.createNewSeedServerTestPeerNode(sfs);
        try {
          node.connectToSeednode(seednode);
          seedNodes.add(seednode);
        } catch (Exception fse) {
          System.err.println("ERROR adding " + seednode.toString() + " " + fse.getMessage());
        }
      }
      // Start it
      node.start(true);
      // Logging.bootstrap(Level.DEBUG,
      // "freenet:NORMAL,freenet.node.NodeDispatcher:MINOR,freenet.node.FNPPacketMangler:MINOR");
      Logging.setRootLevel(Level.ERROR); // kill logging
      Thread.sleep(SECONDS.toMillis(2));
      if (seedNodes.size() != numberOfNodesInTheFile)
        System.out.println("ERROR ADDING SOME OF THE SEEDNODES!!");
      System.out.println("Let some time for the " + seedNodes.size() + " nodes to connect...");
      Thread.sleep(SECONDS.toMillis(8));

      int pingID = 0;
      long deadline = System.currentTimeMillis() + MINUTES.toMillis(2);
      while (System.currentTimeMillis() < deadline) {
        int countConnectedSeednodes = 0;
        for (SeedServerPeerNode seednode :
            node.getPeers().getConnectedSeedServerPeersVector(null)) {
          try {
            double pingTime = seednode.averagePingTime();
            int uptime = seednode.getUptime();
            long timeDelta = seednode.getClockDelta();
            if (seednode.isRealConnection()) continue;
            countConnectedSeednodes++;
            boolean ping = seednode.ping(pingID++);
            if (ping)
              System.out.println(
                  seednode.getIdentityString()
                      + " uptime="
                      + uptime
                      + " ping="
                      + ping
                      + " pingTime="
                      + pingTime
                      + " uptime="
                      + seednode.getUptime()
                      + " timeDelta="
                      + TimeUtil.formatTime(timeDelta));
            // sanity check
            if (seednode.isRoutable()) System.out.println(seednode + " is routable!");
          } catch (NotConnectedException e) {
            System.out.println(
                seednode.getIdentityString() + " is not connected " + seednode.getHandshakeCount());
          }
        }
        Map<FATE, Integer> totals = new EnumMap<>(SeedServerTestPeerNode.FATE.class);
        for (SeedServerTestPeerNode seednode : seedNodes) {
          FATE fate = seednode.getFate();
          Integer x = totals.get(fate);
          if (x == null) totals.put(fate, 1);
          else totals.put(fate, x + 1);
          System.out.println(
              seednode.getIdentityString()
                  + " : "
                  + fate
                  + " : "
                  + seednode.getPeerNodeStatusString());
        }
        System.out.println("TOTALS:");
        for (Entry<FATE, Integer> fateEntry : totals.entrySet()) {
          System.out.println(fateEntry.getKey() + " : " + fateEntry.getValue());
        }
        System.out.println(
            "################## ("
                + node.getPeers().countConnectedPeers()
                + ") "
                + countConnectedSeednodes
                + '/'
                + node.getPeers().countSeednodes());
        Thread.sleep(SECONDS.toMillis(5));
      }
      Map<FATE, Integer> totals = new EnumMap<>(SeedServerTestPeerNode.FATE.class);
      for (SeedServerTestPeerNode seednode : seedNodes) {
        FATE fate = seednode.getFate();
        Integer x = totals.get(fate);
        if (x == null) totals.put(fate, 1);
        else totals.put(fate, x + 1);
        System.out.println(
            seednode.getIdentityString()
                + " : "
                + fate
                + " : "
                + seednode.getPeerNodeStatusString());
      }
      System.out.println("RESULT:TOTALS:");
      for (FATE fate : totals.keySet()) {
        System.out.println("RESULT:" + fate + " : " + totals.get(fate));
      }
      System.out.println("Completed seednodes scan.");
      // Record statuses.
      System.out.println("FINAL STATUS:");
      long writeTime = System.currentTimeMillis();
      for (SeedServerTestPeerNode peer : seedNodes) {
        String status = writeTime + " : " + peer.getIdentityString() + " : " + peer.getFate();
        System.out.println(status);
        File logFile = new File(STATUS_DIR, peer.getIdentityString());
        FileOutputStream fos = new FileOutputStream(logFile, true);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        osw.write(status + "\n");
        osw.close();
        FileInputStream fis = new FileInputStream(logFile);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr);
        String line;
        int successes = 0;
        int failures = 0;
        long lastSuccess = 0;
        long firstSample = 0;
        long countSince = writeTime - COUNT_SUCCESSES_PERIOD;
        do {
          line = br.readLine();
          if (line == null) break;
          String[] results = line.split(" : ");
          if (results.length != 3) {
            System.err.println(
                "Unable to parse line in "
                    + logFile
                    + " : wrong number of fields : "
                    + results.length
                    + " : "
                    + line);
            continue;
          }
          long time = Long.parseLong(results[0]);
          FATE fate = FATE.valueOf(results[2]);
          if (firstSample == 0) firstSample = time;
          if (fate == FATE.CONNECTED_SUCCESS) {
            if (time >= countSince) successes++;
            lastSuccess = time;
          } else {
            if (time >= countSince) failures++;
          }
        } while (line != null);
        br.close();
        if (firstSample < countSince && successes == 0)
          System.err.println(
              "RESULT:"
                  + peer.getIdentityString()
                  + " NOT CONNECTED IN LAST WEEK! LAST CONNECTED: "
                  + (lastSuccess > 0 ? TimeUtil.formatTime(writeTime - lastSuccess) : "NEVER"));
        System.out.println(
            peer.getIdentityString()
                + " : last success "
                + (lastSuccess > 0 ? TimeUtil.formatTime(writeTime - lastSuccess) : "NEVER")
                + " failures in last week: "
                + failures
                + " successes in last week: "
                + successes);
      }
      node.park();
      System.exit(0);
    } catch (Throwable t) {
      System.err.println("CAUGHT: " + t);
      t.printStackTrace();
      try {
        if (node != null) node.park();
      } catch (Throwable t1) {
      }
      System.exit(1);
    }
  }
}
