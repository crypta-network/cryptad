package network.crypta.node;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.TestProperty;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

/**
 * Creates a node, inserts data to it, and fetches the data back. Note that we need one JUnit class
 * per node because we need to actually exit the JVM to get rid of all the node threads.
 *
 * @author toad
 */
class NodeAndClientLayerTest extends NodeAndClientLayerTestBase {

  @Test
  void testFetchPullSingleNodeSsk()
      throws NodeInitException, InsertException, FetchException, IOException {
    if (!TestProperty.EXTENSIVE) {
      return;
    }
    DummyRandomSource random = new DummyRandomSource(25312);
    InsertBlock block = generateBlock(random, false);
    FetchResult result = insertAndRetrieveBlock(random, block);
    assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
  }

  @Test
  void testFetchPullSingleNodeUskEditionZero()
      throws NodeInitException, InsertException, FetchException, IOException {
    if (!TestProperty.EXTENSIVE) {
      return;
    }
    DummyRandomSource random = new DummyRandomSource(25312);
    InsertBlock block = generateBlock(random, true);
    FetchResult result = insertAndRetrieveBlock(random, block);
    assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
  }

  @AfterEach
  void cleanUp() {
    FileUtil.removeAll(dir);
  }

  private static FetchResult insertAndRetrieveBlock(DummyRandomSource random, InsertBlock block)
      throws NodeInitException, InsertException, FetchException {
    final PriorityAwareExecutor executor = new PooledExecutor();
    FileUtil.removeAll(dir);
    dir.mkdir();
    NodeStarter.globalTestInit(dir, false, Level.ERROR, "", true, random);
    TestNodeParameters params = new TestNodeParameters();
    params.setRandom(new DummyRandomSource(253121));
    params.setRamStore(true);
    params.setStoreSize(FILE_SIZE * 3);
    params.setBaseDirectory(dir);
    params.setExecutor(executor);
    Node node = NodeStarter.createTestNode(params);
    node.start(false);
    HighLevelSimpleClient client = node.getClientCore().makeClient((short) 0, false, false);
    InsertContext ictx = client.getInsertContext(true);
    ictx.setLocalRequestOnly(true);
    FreenetURI uri = client.insert(block, "", (short) 0, ictx);
    assertEquals(uri.getKeyType(), "SSK");
    FetchContext ctx = client.getFetchContext(FILE_SIZE * 2);
    ctx.setLocalRequestOnly(true);
    FetchWaiter fw = new FetchWaiter(rc);
    client.fetch(uri, FILE_SIZE * 2, fw, ctx, (short) 0);
    return fw.waitForCompletion();
  }

  private static final File dir = new File("test-fetch-pull-single-node");
}
