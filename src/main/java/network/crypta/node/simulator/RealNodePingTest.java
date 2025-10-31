package network.crypta.node.simulator;

import java.io.File;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * @author amphibian
 *     <p>When the code is invoked via this class, it: - Creates two nodes. - Connects them to each
 *     other - Sends pings from the first node to the second node. - Prints on the logger when
 *     packets are sent, when they are received, (by both sides), and their sequence numbers.
 */
public class RealNodePingTest {
  private static final Logger LOG = LoggerFactory.getLogger(RealNodePingTest.class);

  public static final int DARKNET_PORT1 = RealNodeBusyNetworkTest.DARKNET_PORT_END;
  public static final int DARKNET_PORT2 = RealNodeBusyNetworkTest.DARKNET_PORT_END + 1;
  public static final int DARKNET_PORT_END = DARKNET_PORT2 + 1;

  static final FRIEND_TRUST trust = FRIEND_TRUST.LOW;
  static final FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NO;

  public static void main(String[] args)
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
    node1.connect(node2, trust, visibility);
    node2.connect(node1, trust, visibility);
    // No swapping
    node1.start(true);
    node2.start(true);
    // Ping
    PeerNode pn = node1.getPeerNodes()[0];
    int pingID = 0;
    Thread.sleep(20000);
    // node1.usm.setDropProbability(4);
    while (true) {
      LOG.error("Sending PING " + pingID);
      boolean success;
      try {
        success = pn.ping(pingID);
      } catch (NotConnectedException e1) {
        LOG.error("Not connected");
        continue;
      }
      if (success) LOG.error("PING " + pingID + " successful");
      else LOG.error("PING FAILED: " + pingID);
      try {
        Thread.sleep(2000);
      } catch (InterruptedException e) {
        // Shouldn't happen
      }
      pingID++;
    }
  }
}
